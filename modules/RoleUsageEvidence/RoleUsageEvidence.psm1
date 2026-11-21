<#
    RoleUsageEvidence.psm1 - extra read-only usage signals that no role module collects:
      SqlUsage  (remote client connections to SQL Server ports, point in time)
      RdsUsage  (session logon/reconnect events, TerminalServices-LocalSessionManager)
      AdUsage   (Kerberos TGT requests on a domain controller, Security log)
    Counts and dates only - never user, host or client names. Each block runs only when its role is present.
    Verdicts are derived later by the RoleUsage synthesis module.
#>
function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='RoleUsageEvidence'; DisplayName='Role Usage Evidence (SQL, RDS, AD)'; Category='RoleUsage'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('SqlUsage','RdsUsage','AdUsage')
        ProducesRisks=$false; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}
function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='RoleUsageEvidence'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

# Pure: a list of events (TimeCreated) -> count, last, and coverage (how far back the log actually reaches, capped at the window).
function Get-EventUsageSummary {
    param($Times, $OldestAvailable, [int]$WindowDays, [datetime]$Now = (Get-Date))
    $t = @($Times | Sort-Object -Descending)
    [pscustomobject]@{
        Count = $t.Count
        Last = $(if ($t.Count) { ([datetime]$t[0]).ToString('yyyy-MM-dd HH:mm') } else { '' })
        CoverageDays = $(if ($OldestAvailable) { [math]::Round([math]::Min($WindowDays, ($Now - [datetime]$OldestAvailable).TotalDays), 1) } else { 0 })
    }
}

function Read-EventUsage {
    param([string]$LogName, [int[]]$Ids, [int]$Days, [int]$Max = 20000)
    $ev = @()
    try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$Ids; StartTime=(Get-Date).AddDays(-$Days) } -MaxEvents $Max -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
    $oldest = (Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated
    Get-EventUsageSummary -Times @($ev | ForEach-Object { $_.TimeCreated }) -OldestAvailable $oldest -WindowDays $Days
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $days = [int]$Context.Parameters['EventLogDays']; if ($days -le 0) { $days = 14 }
    $sql = [System.Collections.Generic.List[object]]::new(); $rds = [System.Collections.Generic.List[object]]::new(); $ad = [System.Collections.Generic.List[object]]::new()

    # ---- SQL Server: remote clients connected to the SQL TCP ports right now (point in time) ----
    $sqlSvc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^MSSQL(\$.+)?$' -and $_.Status -eq 'Running' })
    if ($sqlSvc.Count -gt 0) {
        $row = [ordered]@{ Status='Unavailable'; RunningInstances=$sqlSvc.Count; RemoteClients=$null; ObservedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm'); Reason='' }
        try {
            $ports = [System.Collections.Generic.List[int]]::new(); $ports.Add(1433)
            foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^MSSQL\d+\.' })) {
                $p = [string](Get-RegistryValueSafe -Path ($k.PSPath + '\MSSQLServer\SuperSocketNetLib\Tcp\IPAll') -Name 'TcpPort')
                foreach ($x in ($p -split ',')) { if ($x -match '^\d+$' -and -not $ports.Contains([int]$x)) { $ports.Add([int]$x) } }
            }
            $own = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })
            $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $ports.Contains([int]$_.LocalPort) -and $_.RemoteAddress -notin $own -and $_.RemoteAddress -notin @('127.0.0.1','::1') })
            $row.RemoteClients = @($conns | ForEach-Object { $_.RemoteAddress } | Select-Object -Unique).Count; $row.Status = 'Queried'
        } catch { $row.Reason = $_.Exception.Message; Add-Limitation -Context $Context -Module 'RoleUsageEvidence' -Message 'SQL client connections could not be read; SQL usage is unknown.' -Reason $row.Reason | Out-Null }
        $sql.Add([pscustomobject]$row)
    }

    # ---- RDS session host: session logon (21) / reconnect (25) events ----
    if (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)^RDS-RD-Server$') {
        $row = [ordered]@{ Status='Unavailable'; WindowDays=$days; SessionEvents=$null; LastSession=''; CoverageDays=$null; Reason='' }
        try {
            $s = Read-EventUsage -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Ids 21,25 -Days $days
            $row.Status='Queried'; $row.SessionEvents=$s.Count; $row.LastSession=$s.Last; $row.CoverageDays=$s.CoverageDays
        } catch { $row.Reason = $_.Exception.Message; Add-Limitation -Context $Context -Module 'RoleUsageEvidence' -Message 'RDS session events could not be read; session host usage is unknown.' -Reason $row.Reason | Out-Null }
        $rds.Add([pscustomobject]$row)
    }

    # ---- Domain controller: Kerberos TGT requests (4768) ----
    # The feature name alone misses a DC whose AD DS feature state is InstallPending, so also trust the DomainContext flag.
    if ((Test-RoleFeaturePresent -Context $Context -Pattern '(?i)^AD-Domain-Services$') -or (Test-DatasetFieldTrue -Context $Context -Dataset 'DomainContext' -Field 'IsDomainController')) {
        $row = [ordered]@{ Status='Unavailable'; WindowDays=$days; TgtRequests=$null; LastTgt=''; CoverageDays=$null; Reason='' }
        try {
            $s = Read-EventUsage -LogName 'Security' -Ids 4768 -Days $days -Max 5000   # ponytail: capped at 5000; a capped count still means "busy"
            $row.Status='Queried'; $row.TgtRequests=$s.Count; $row.LastTgt=$s.Last; $row.CoverageDays=$s.CoverageDays
        } catch { $row.Reason = $_.Exception.Message; Add-Limitation -Context $Context -Module 'RoleUsageEvidence' -Message 'Domain controller authentication events could not be read; DC usage is unknown.' -Reason $row.Reason | Out-Null }
        $ad.Add([pscustomobject]$row)
    }
    return ,@{ SqlUsage=@($sql); RdsUsage=@($rds); AdUsage=@($ad) }
}
function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'SqlUsage' -Description 'Remote clients connected to SQL Server ports at collection time (counts only).' -Rows (& $get 'SqlUsage') -Visibility 'Internal' -SourceModule 'RoleUsageEvidence' | Out-Null
    Add-DataSet -Context $Context -Name 'RdsUsage' -Description 'RDS session logon/reconnect event counts (counts and dates only).' -Rows (& $get 'RdsUsage') -Visibility 'Internal' -SourceModule 'RoleUsageEvidence' | Out-Null
    Add-DataSet -Context $Context -Name 'AdUsage'  -Description 'Domain controller Kerberos TGT request counts (counts and dates only).' -Rows (& $get 'AdUsage') -Visibility 'Internal' -SourceModule 'RoleUsageEvidence' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-EventUsageSummary'
