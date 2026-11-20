<#
    DHCP.psm1 - DHCP Server role discovery (read-only). Role-gated.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='DHCP'; DisplayName='DHCP Server'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole='DHCP'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('DhcpScopes','DhcpReservations','DhcpOptions','DhcpFailover','DhcpServerSummary','DhcpLeaseActivity')
        # ProducesRisks is $false, not a placeholder: this module's own datasets (scope/
        # reservation lists) are informational, not risk-scored, and no risk-rules.json rule
        # references them. The real "server hosts the DHCP role" risk finding already exists
        # (RULE-DHCP-001) and is deliberately sourced from RolesFeatures instead, since that
        # module runs on every server (this one is role-gated and simply never runs on the
        # other 90%+ of a fleet).
        ProducesRisks=$false; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DhcpPresent {
    if (Get-CommandAvailable -Name 'Get-DhcpServerv4Scope') { return $true }
    if (Get-Service -Name 'DHCPServer' -ErrorAction SilentlyContinue) { return $true }
    return $false
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    if (Test-DhcpPresent) { return [pscustomobject]@{ ModuleName='DHCP'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='DHCP'; CanRun=$false; Status='NotApplicable'; Reason='DHCP Server role not present.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    # Default cmdlets resolve $env:COMPUTERNAME through DNS on every call (~1 s each; 20-30x slower than 'localhost'), and a resolution failure is swallowed by -ErrorAction SilentlyContinue as an empty result.
    $PSDefaultParameterValues = @{ 'Get-Dhcp*:ComputerName' = 'localhost' }
    $scopes=[System.Collections.Generic.List[object]]::new(); $res=[System.Collections.Generic.List[object]]::new()
    $opts=[System.Collections.Generic.List[object]]::new(); $fo=[System.Collections.Generic.List[object]]::new(); $srv=[System.Collections.Generic.List[object]]::new()
    if (-not (Get-CommandAvailable -Name 'Get-DhcpServerv4Scope')) { Add-Limitation -Context $Context -Module 'DHCP' -Message 'DhcpServer module not available; DHCP present but not enumerable.' | Out-Null; return ,@{ DhcpScopes=@(); DhcpReservations=@(); DhcpOptions=@(); DhcpFailover=@(); DhcpServerSummary=@(); DhcpLeaseActivity=@() } }
    $svc = Get-Service -Name 'DHCPServer' -ErrorAction SilentlyContinue
    try {
        foreach ($s in (Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) {
            # Lease COUNTS only: individual leases carry client host names and MAC addresses.
            $st = $null; try { $st = Get-DhcpServerv4ScopeStatistics -ScopeId $s.ScopeId -ErrorAction Stop } catch { }
            $scopes.Add([pscustomobject]@{ ScopeId=[string]$s.ScopeId; Name=$s.Name; StartRange=[string]$s.StartRange; EndRange=[string]$s.EndRange; SubnetMask=[string]$s.SubnetMask; State=[string]$s.State; LeaseDuration=[string]$s.LeaseDuration
                LeasesInUse=$(if ($st) { [int]$st.InUse } else { $null }); AddressesFree=$(if ($st) { [int]$st.Free } else { $null }); PercentInUse=$(if ($st) { [double]$st.PercentageInUse } else { $null }) })
            try { foreach ($o in (Get-DhcpServerv4OptionValue -ScopeId $s.ScopeId -ErrorAction Stop)) { $opts.Add([pscustomobject]@{ Level='Scope'; ScopeId=[string]$s.ScopeId; OptionId=$o.OptionId; Name=$o.Name; Value=((@($o.Value)) -join ', ') }) } } catch { }
            try { foreach ($r in (Get-DhcpServerv4Reservation -ScopeId $s.ScopeId -ErrorAction SilentlyContinue)) { $res.Add([pscustomobject]@{ ScopeId=[string]$s.ScopeId; IPAddress=[string]$r.IPAddress; ClientId=[string]$r.ClientId; Name=$r.Name; Description=$r.Description }) } } catch { }
        }
    } catch { Add-Limitation -Context $Context -Module 'DHCP' -Message 'DHCP scope enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    try { foreach ($o in (Get-DhcpServerv4OptionValue -ErrorAction Stop)) { $opts.Add([pscustomobject]@{ Level='Server'; ScopeId=''; OptionId=$o.OptionId; Name=$o.Name; Value=((@($o.Value)) -join ', ') }) } } catch { }
    try { foreach ($f in (Get-DhcpServerv4Failover -ErrorAction Stop)) { $fo.Add([pscustomobject]@{ Name=$f.Name; PartnerServer=$f.PartnerServer; Mode=[string]$f.Mode; State=[string]$f.State; ScopeIds=((@($f.ScopeId) | ForEach-Object { [string]$_ }) -join ', ') }) } } catch { }
    $authorized = $null
    try { $authorized = [bool](@(Get-DhcpServerInDC -ErrorAction Stop | Where-Object { [string]$_.DnsName -match ('(?i)^' + [regex]::Escape($env:COMPUTERNAME) + '(\.|$)') }).Count -gt 0) } catch { }
    $srv.Add([pscustomobject]@{ ServiceState=$(if ($svc) { [string]$svc.Status } else { '' }); ScopeCount=$scopes.Count; ActiveScopeCount=@($scopes | Where-Object { $_.State -eq 'Active' }).Count
        ReservationCount=$res.Count; FailoverRelationships=$fo.Count; HasFailover=[bool]($fo.Count -gt 0); AuthorizedInAd=$authorized
        HostsActiveDhcp=[bool](@($scopes | Where-Object { $_.State -eq 'Active' }).Count -gt 0) })
    # Lease activity from the DHCP audit log (read-only; the log keeps one file per weekday, so ~7 days at most).
    $leaseAct = [System.Collections.Generic.List[object]]::new()
    $row = [ordered]@{ Status='Unavailable'; AuditLogEnabled=$null; NewLeases=$null; Renewals=$null; Releases=$null; LastLeaseEvent=''; CoverageDays=$null; Reason='' }
    try {
        $dir = Join-Path $env:windir 'System32\dhcp'
        try { $al = Get-DhcpServerAuditLog -ErrorAction Stop; $row.AuditLogEnabled = [bool]$al.Enable; if ($al.Path) { $dir = [Environment]::ExpandEnvironmentVariables([string]$al.Path) } } catch { }
        if ($row.AuditLogEnabled -eq $false) { $row.Reason = 'DHCP audit logging is disabled; lease activity unknown.' }
        else {
            $files = @(Get-ChildItem -LiteralPath $dir -Filter 'DhcpSrvLog-*.log' -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-8) })
            if ($files.Count -eq 0) { $row.Reason = 'No recent DHCP audit log files found.' }
            else {
                $sum = ConvertTo-DhcpLeaseSummary -Lines @($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -ErrorAction Stop })
                $row.Status='Queried'; $row.NewLeases=$sum.NewLeases; $row.Renewals=$sum.Renewals; $row.Releases=$sum.Releases; $row.LastLeaseEvent=$sum.LastLeaseEvent; $row.CoverageDays=$sum.CoverageDays
            }
        }
    } catch { $row.Reason = $_.Exception.Message }
    if ($row.Status -ne 'Queried') { Add-Limitation -Context $Context -Module 'DHCP' -Message 'DHCP lease activity could not be read; whether leases are being handed out is unknown.' -Reason $row.Reason | Out-Null }
    $leaseAct.Add([pscustomobject]$row)
    return ,@{ DhcpScopes=@($scopes); DhcpReservations=@($res); DhcpOptions=@($opts); DhcpFailover=@($fo); DhcpServerSummary=@($srv); DhcpLeaseActivity=@($leaseAct) }
}

# Pure: counts lease events from DHCP audit-log lines. Only the ID/date/time fields are read -
# host names, MACs and user names in later columns are never touched.
# Event IDs: 10 = new lease, 11 = renew, 12 = release. CoverageDays = span of every dated row.
function ConvertTo-DhcpLeaseSummary {
    param([string[]]$Lines)
    $new = 0; $ren = 0; $rel = 0; $last = $null; $min = $null; $max = $null
    foreach ($l in $Lines) {
        if ($l -notmatch '^(\d+),([^,]+),([^,]+),') { continue }
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParse(($Matches[2] + ' ' + $Matches[3]), [ref]$d)) { continue }
        if ($null -eq $min -or $d -lt $min) { $min = $d }; if ($null -eq $max -or $d -gt $max) { $max = $d }
        $id = [int]$Matches[1]
        if     ($id -eq 10) { $new++ } elseif ($id -eq 11) { $ren++ } elseif ($id -eq 12) { $rel++ } else { continue }
        if ($null -eq $last -or $d -gt $last) { $last = $d }
    }
    [pscustomobject]@{
        NewLeases=$new; Renewals=$ren; Releases=$rel
        LastLeaseEvent=$(if ($last) { $last.ToString('yyyy-MM-dd HH:mm') } else { '' })
        CoverageDays=$(if ($min) { [math]::Round(($max - $min).TotalDays, 1) } else { 0 })
    }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'DhcpScopes'       -Description 'DHCP scopes.'       -Rows (& $get 'DhcpScopes')       -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
    Add-DataSet -Context $Context -Name 'DhcpReservations' -Description 'DHCP reservations.' -Rows (& $get 'DhcpReservations') -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
    Add-DataSet -Context $Context -Name 'DhcpOptions'      -Description 'DHCP server- and scope-level options.' -Rows (& $get 'DhcpOptions') -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
    Add-DataSet -Context $Context -Name 'DhcpFailover'     -Description 'DHCP failover relationships.' -Rows (& $get 'DhcpFailover') -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
    Add-DataSet -Context $Context -Name 'DhcpServerSummary' -Description 'DHCP cutover summary (active scopes, failover, AD authorization).' -Rows (& $get 'DhcpServerSummary') -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
    Add-DataSet -Context $Context -Name 'DhcpLeaseActivity' -Description 'Lease event counts from the DHCP audit log (counts and dates only).' -Rows (& $get 'DhcpLeaseActivity') -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Test-DhcpPresent','ConvertTo-DhcpLeaseSummary'
