<#
    PrintServer.psm1 - printers, drivers, ports, print activity and per-user connections (read-only).
    Produces: Printers, PrinterDrivers, PrintPorts, PrintActivity, PrinterConnections, PrintServerSummary.
    SNMP community strings are never read (only whether SNMP is enabled). Print-log activity is
    counted per queue; document names and user names are never kept. Scan-to-email/folder is NEVER
    reported as discovered - multifunction devices only raise a verification item.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='PrintServer'; DisplayName='Print Server & Printers'; Category='File'; Version='1.1.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('Printers','PrinterDrivers','PrintPorts','PrintActivity','PrinterConnections','PrintServerSummary')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='PrintServer'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

# Multifunction-device model families (copier/scan capable). A match means "ask about scan-to
# workflows", never "scan-to-email is configured".
$script:MfpPattern = '(?i)\bMFP\b|multifunction|all-in-one|workcentre|versalink|altalink|imagerunner|\biR[- ]?(ADV|C?\d{3,4})|bizhub|taskalfa|ecosys m|\bMX-\d|\bMP ?C?\d{3,4}|\bIM ?C?\d{3,4}|aficio|e-studio|laserjet.*(mfp|flow)|pagewide.*mfp|color ?qube|apeosport|docucentre'
$script:LabelPattern = '(?i)zebra|dymo|brother\s*ql|bartender|godex|intermec|sato|toshiba tec|label'

function Get-PrinterAssessment {
    <# Pure: per-queue flags from driver/port/name text. #>
    param([string]$Name, [string]$DriverName, [string]$PortName, [string]$PortHostAddress, [object]$DriverMajorVersion)
    [pscustomobject]@{
        IsLabelPrinter      = [bool](($Name -match $script:LabelPattern) -or ($DriverName -match $script:LabelPattern))
        IsMultifunctionLikely = [bool](($Name -match $script:MfpPattern) -or ($DriverName -match $script:MfpPattern))
        IsDirectIp          = [bool]($PortHostAddress -or $PortName -match '^(IP_)?\d{1,3}(\.\d{1,3}){3}(_\d+)?$|^WSD-')
        IsUniversalDriver   = [bool]($DriverName -match '(?i)universal|\bUPD\b|generic|global|PCL ?6 class|class driver')
        IsLegacyDriver      = [bool](($null -ne $DriverMajorVersion -and [string]$DriverMajorVersion -ne '' -and [int]$DriverMajorVersion -lt 3))
    }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $printers=[System.Collections.Generic.List[object]]::new(); $drivers=[System.Collections.Generic.List[object]]::new(); $ports=[System.Collections.Generic.List[object]]::new()
    $activity=[System.Collections.Generic.List[object]]::new(); $connections=[System.Collections.Generic.List[object]]::new()
    $sensitive = ([bool]$Context.Parameters['IncludeSensitiveEvidence'])

    # ---- Ports first, so each queue can carry its device address ----
    $portMap = @{}
    try {
        # Win32_TCPIPPrinterPort works on every supported OS; only safe properties are selected (never SNMPCommunity).
        foreach ($tp in (Invoke-CimSafe -ClassName 'Win32_TCPIPPrinterPort')) {
            $portMap[[string]$tp.Name] = [pscustomobject]@{ Name=[string]$tp.Name; PrinterHostAddress=[string]$tp.HostAddress; PortNumber=$tp.PortNumber; Protocol=$(switch ([int]$tp.Protocol) { 1 {'RAW'} 2 {'LPR'} default {[string]$tp.Protocol} }); SnmpEnabled=[bool]$tp.SNMPEnabled; PortMonitor='Standard TCP/IP Port'; Description='' }
        }
    } catch { }
    try {
        if (Get-CommandAvailable -Name 'Get-PrinterPort') {
            foreach ($pt in (Get-PrinterPort -ErrorAction SilentlyContinue)) {
                if (-not $portMap.ContainsKey([string]$pt.Name)) {
                    $portMap[[string]$pt.Name] = [pscustomobject]@{ Name=[string]$pt.Name; PrinterHostAddress=[string]$pt.PrinterHostAddress; PortNumber=$null; Protocol=''; SnmpEnabled=$null; PortMonitor=[string]$pt.PortMonitor; Description=[string]$pt.Description }
                } else { $portMap[[string]$pt.Name].PortMonitor = [string]$pt.PortMonitor; $portMap[[string]$pt.Name].Description = [string]$pt.Description }
            }
        }
    } catch { }
    foreach ($k in $portMap.Keys) { $ports.Add($portMap[$k]) }

    $driverMap = @{}
    try {
        if (Get-CommandAvailable -Name 'Get-PrinterDriver') {
            foreach ($d in (Get-PrinterDriver -ErrorAction SilentlyContinue)) {
                $row = [pscustomobject]@{ Name=$d.Name; Manufacturer=$d.Manufacturer; DriverVersion=[string]$d.DriverVersion; Environment=$d.PrinterEnvironment; MajorVersion=$d.MajorVersion; InfPath=[string]$d.InfPath; IsLegacyDriver=[bool]($null -ne $d.MajorVersion -and [int]$d.MajorVersion -lt 3) }
                $drivers.Add($row); $driverMap[[string]$d.Name] = $row
            }
        }
    } catch { }

    try {
        $source = @()
        $useCmdlet = (Get-CommandAvailable -Name 'Get-Printer')
        if ($useCmdlet) { $source = @(Get-Printer -ErrorAction SilentlyContinue) } else { $source = @(Invoke-CimSafe -ClassName 'Win32_Printer') }
        foreach ($p in $source) {
            $port = $portMap[[string]$p.PortName]
            $drv = $driverMap[[string]$p.DriverName]
            $hostAddr = if ($port) { $port.PrinterHostAddress } else { '' }
            $as = Get-PrinterAssessment -Name $p.Name -DriverName $p.DriverName -PortName $p.PortName -PortHostAddress $hostAddr -DriverMajorVersion $(if ($drv) { $drv.MajorVersion } else { $null })
            $printers.Add([pscustomobject]@{
                Name=$p.Name; DriverName=$p.DriverName; PortName=$p.PortName; Shared=([bool]$p.Shared); ShareName=$p.ShareName; Location=$p.Location; Comment=$p.Comment
                Published=([bool]$p.Published); PrinterStatus=[string]$p.PrinterStatus; IsLabelPrinter=$as.IsLabelPrinter
                PrinterHostAddress=$hostAddr; PortNumber=$(if ($port) { $port.PortNumber } else { $null }); SnmpEnabled=$(if ($port) { $port.SnmpEnabled } else { $null })
                PrintProcessor=[string]$p.PrintProcessor
                DriverEnvironment=$(if ($drv) { [string]$drv.Environment } else { '' }); DriverInfPath=$(if ($drv) { $drv.InfPath } else { '' })
                IsConnection=[bool]([string]$p.Type -eq 'Connection' -or $p.Name -match '^\\\\')
                IsDirectIp=$as.IsDirectIp; IsMultifunctionLikely=$as.IsMultifunctionLikely; IsUniversalDriver=$as.IsUniversalDriver; IsLegacyDriver=$as.IsLegacyDriver
            })
            if ($p.Shared) { Add-DependencyEdge -Context $Context -SourceType 'Printer' -SourceName $p.Name -DependencyType 'UsesPort' -Target $p.PortName -Evidence 'Shared printer' -Confidence 'Confirmed' -SourceDataset 'Printers' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Do users map to this printer by server name?' | Out-Null }
        }
    } catch { Add-Limitation -Context $Context -Module 'PrintServer' -Message 'Printer enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    if ($printers.Count -eq 0) { Add-Limitation -Context $Context -Module 'PrintServer' -Message 'No printers detected (print server role may be absent).' | Out-Null }

    # ---- Print activity from the PrintService operational log (event 307 = job printed) ----
    $logStatus = 'Unavailable'
    $days = [int]$Context.Parameters['EventLogDays']; if ($days -le 0) { $days = 14 }
    if ($printers.Count -gt 0) {
        try {
            $log = Get-WinEvent -ListLog 'Microsoft-Windows-PrintService/Operational' -ErrorAction Stop
            if (-not $log.IsEnabled) { $logStatus = 'Disabled' }
            else {
                $logStatus = 'Enabled'
                $events = @()
                try { $events = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PrintService/Operational'; Id=307; StartTime=(Get-Date).AddDays(-$days) } -MaxEvents 20000 -ErrorAction Stop) }
                catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
                # Event 307 properties: 0 job id, 1 document, 2 user, 3 client, 4 printer, 5 port, 6 bytes, 7 pages.
                foreach ($g in ($events | Group-Object { [string]$_.Properties[4].Value })) {
                    $clients = @($g.Group | ForEach-Object { [string]$_.Properties[3].Value } | Select-Object -Unique)
                    $activity.Add([pscustomobject]@{ Printer=$g.Name; JobsInWindow=$g.Count; DistinctClients=$clients.Count; LastJob=(Normalize-DateTime (($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated)); WindowDays=$days })
                }
            }
        } catch { $logStatus = 'Unavailable'; Add-Limitation -Context $Context -Module 'PrintServer' -Message 'PrintService operational log could not be read; queue usage is unknown.' -Reason $_.Exception.Message | Out-Null }
        if ($logStatus -eq 'Disabled') { Add-Unknown -Context $Context -Unknown 'The PrintService operational log is disabled, so which queues are actually used is unknown.' -WhyItMatters 'Without usage evidence every queue has to be treated as in use during migration planning.' -Module 'PrintServer' -RecommendedValidationQuestion 'Which printers are still used, and can print logging be enabled for an observation window (a change the client approves, not this tool)?' | Out-Null }
    }

    # ---- Per-user printer connections + default printer, for the collection context only ----
    try {
        $default = [string](Get-RegistryValueSafe -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'Device')
        $defaultName = ($default -split ',')[0]
        $who = if ($sensitive) { "$env:USERDOMAIN\$env:USERNAME" } else { '(collection account)' }
        if (Test-RegistryPathSafe 'HKCU:\Printers\Connections') {
            foreach ($k in (Get-ChildItem -LiteralPath 'HKCU:\Printers\Connections' -ErrorAction SilentlyContinue)) {
                $conn = ([string]$k.PSChildName) -replace ',', '\'
                $connections.Add([pscustomobject]@{ Account=$who; Connection=$conn; IsDefault=[bool]($conn -ieq $defaultName) })
            }
        }
        if ($defaultName -and -not @($connections | Where-Object { $_.IsDefault }).Count) { $connections.Add([pscustomobject]@{ Account=$who; Connection=$defaultName; IsDefault=$true }) }
    } catch { }

    $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
    $mgmt = @($svcRows | Where-Object { $_.DisplayName -match '(?i)PrinterLogic|PrinterCloud|Vasion|PaperCut|Universal Print|PrintFleet|Pharos|Equitrac|uniFLOW' } | ForEach-Object { [string]$_.DisplayName } | Select-Object -Unique)
    $summary = @([pscustomobject]@{
        PrinterCount=$printers.Count
        SharedQueueCount=@($printers | Where-Object { $_.Shared }).Count
        DirectIpQueueCount=@($printers | Where-Object { $_.IsDirectIp }).Count
        MultifunctionLikelyCount=@($printers | Where-Object { $_.IsMultifunctionLikely }).Count
        LegacyDriverCount=@($drivers | Where-Object { $_.IsLegacyDriver }).Count
        PrintLogStatus=$logStatus; PrintLogWindowDays=$days
        QueuesWithActivity=$activity.Count
        PrintManagementAgents=($mgmt -join '; ')
        HostsRdsSessions=[bool]($Context.DataSets.Contains('RdsDiscovery') -and @($Context.DataSets['RdsDiscovery'].Rows).Count -gt 0)
        ScanWorkflowVerificationNeeded=[bool](@($printers | Where-Object { $_.IsMultifunctionLikely }).Count -gt 0)
        ScanToEmailDiscovered='Not determinable from the server - verify on the devices'
    })
    return ,@{ Printers=@($printers); PrinterDrivers=@($drivers); PrintPorts=@($ports); PrintActivity=@($activity); PrinterConnections=@($connections); PrintServerSummary=$summary }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'Printers'       -Description 'Printers (shared, direct-IP, MFP, driver flags).' -Rows (& $get 'Printers')       -Visibility 'Both'     -SourceModule 'PrintServer' | Out-Null
    Add-DataSet -Context $Context -Name 'PrinterDrivers' -Description 'Installed printer drivers (type/version, INF).'   -Rows (& $get 'PrinterDrivers') -Visibility 'Internal' -SourceModule 'PrintServer' | Out-Null
    Add-DataSet -Context $Context -Name 'PrintPorts'     -Description 'Printer ports (host, port number, SNMP enabled - never the community).' -Rows (& $get 'PrintPorts') -Visibility 'Internal' -SourceModule 'PrintServer' | Out-Null
    Add-DataSet -Context $Context -Name 'PrintActivity'  -Description 'Jobs per queue from the PrintService log (counts only).' -Rows (& $get 'PrintActivity') -Visibility 'Internal' -SourceModule 'PrintServer' | Out-Null
    Add-DataSet -Context $Context -Name 'PrinterConnections' -Description 'Printer connections/default printer visible to the collection account.' -Rows (& $get 'PrinterConnections') -Visibility 'Internal' -SourceModule 'PrintServer' | Out-Null
    Add-DataSet -Context $Context -Name 'PrintServerSummary' -Description 'Print migration summary (queues, drivers, log status, verification items).' -Rows (& $get 'PrintServerSummary') -Visibility 'Internal' -SourceModule 'PrintServer' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('PrintServerSummary')) {
            $s = @($Context.DataSets['PrintServerSummary'].Rows)[0]
            if ($s -and $s.ScanWorkflowVerificationNeeded) {
                Add-FollowUpQuestion -Context $Context -Category 'Printing' -Module 'PrintServer' -Audience 'Both' -Question 'Some printers look like multifunction devices. Do any of them scan to email or to a folder on this server? Those settings live on the device and must be checked there before anything changes.' | Out-Null
            }
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-PrinterAssessment'
