<#
    RoleUsage.psm1
    Synthesis module. Answers "is this installed role actually in use?" from datasets other
    modules already collected. Produces the RoleUsage dataset (one row per assessed role).
    Doctrine (same as SmtpRelayAssessment): activity evidence can show use, never prove
    absence, so the verdict vocabulary has no "unused": Active | No activity in window | Unknown.
#>
function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'RoleUsage'
        DisplayName               = 'Role Usage Evidence'
        Category                  = 'Synthesis'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Minimal'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('RoleUsage','RoleUsageSummary')
        ProducesRisks             = $false
        ProducesFollowUpQuestions = $false
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $false
        IsSynthesis               = $true
    }
}
function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='RoleUsage'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}
# Pure: $Count = $null means "no usable evidence source" (log off, unreadable, not collected).
# -Recent/-ActiveAt: optional Light/Occasional band. Some activity overall but fewer than ActiveAt
# events in the recent slice is "Light/Occasional" (only roles that pass -Recent get the band).
# ponytail: one flat threshold per role (CA: 5 per 90 days); tune per role if clients disagree.
function Get-RoleUsageVerdict {
    param($Count, [int]$WindowDays = 0, $Recent = $null, [int]$ActiveAt = 5)
    if ($null -eq $Count) { return 'Unknown' }
    if ([int]$Count -gt 0) {
        if ($null -ne $Recent -and [int]$Recent -lt $ActiveAt) { return 'Light/Occasional' }
        return 'Active'
    }
    if ($WindowDays -gt 0) { return 'No activity in window' }
    return 'Unknown'
}
function New-RoleUsageRow {
    param([string]$Role, [string]$Verdict, [string]$Evidence, [string]$Source, $LastActivity = '', [int]$WindowDays = 0, [string]$Confidence = 'Possible')
    [pscustomobject]@{ Role=$Role; Verdict=$Verdict; Evidence=$Evidence; EvidenceSource=$Source; LastActivity=[string]$LastActivity; WindowDays=$WindowDays; Confidence=$Confidence }
}
function Build-RoleUsage {
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()
    $get = { param($n) if ($Context.DataSets.Contains($n)) { @($Context.DataSets[$n].Rows) } else { @() } }

    # ---- Print: PrintService event 307 counts (PrintServer module) ----
    if (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)Print-Services|Print-Server') {
        $sum = @(& $get 'PrintServerSummary') | Select-Object -First 1
        $act = @(& $get 'PrintActivity')
        $status = if ($sum) { [string]$sum.PrintLogStatus } else { 'Unavailable' }
        $win = if ($act.Count -gt 0) { [int]$act[0].WindowDays } else { [int]$Context.Parameters['EventLogDays'] }
        $count = if ($status -eq 'Enabled') { [int](($act | Measure-Object JobsInWindow -Sum).Sum) } else { $null }
        $last = ($act | Where-Object { $_.LastJob } | Sort-Object LastJob -Descending | Select-Object -First 1).LastJob
        $ev = if ($status -eq 'Enabled') { "$count print jobs in $win days across $($act.Count) queue(s)." } else { "PrintService operational log is $status; usage unknown." }
        $rows.Add((New-RoleUsageRow 'Print Server' (Get-RoleUsageVerdict $count $win) $ev 'PrintActivity' $last $win $(if ($status -eq 'Enabled') { 'Likely' } else { 'Unknown' })))
    }

    # ---- ADCS: issued-certificate counts from the CA database (Certificates module) ----
    $cau = @(& $get 'CertificateAuthorityUsage') | Select-Object -First 1
    if ($cau) {
        $q = ($cau.Status -eq 'Queried'); $win = [int]$cau.LookbackDays
        $count = if ($q) { [int]$cau.IssuedInLookback } else { $null }
        $ev = if ($q) { "$($cau.IssuedInLookback) cert(s) issued in $win days ($($cau.Issued30d) in 30d, $($cau.Issued90d) in 90d). Templates: $($cau.TopTemplates)" } else { "CA database not queried: $($cau.Reason)" }
        $rows.Add((New-RoleUsageRow 'Certification Authority' (Get-RoleUsageVerdict $count $win $(if ($q) { [int]$cau.Issued90d } else { $null }) 5) $ev 'CertificateAuthorityUsage' $cau.LastIssued $win $(if ($q) { 'Likely' } else { 'Unknown' })))
    }

    # ---- IIS: request counts from W3C logs, summed over the sites whose logs were readable ----
    $iis = @(& $get 'IisUsage')
    if ($iis.Count -gt 0) {
        $okSites = @($iis | Where-Object { $_.Status -eq 'Queried' }); $win = [int]$iis[0].WindowDays
        if ($okSites.Count -eq 0) { $rows.Add((New-RoleUsageRow 'Web Server (IIS)' 'Unknown' "W3C logs unreadable for all $($iis.Count) site(s): $($iis[0].Reason)" 'IisUsage' '' $win 'Unknown')) }
        else {
            $req = [int](($okSites | Measure-Object Requests -Sum).Sum); $cov = [int][math]::Floor([math]::Min($win, [double](($okSites | Measure-Object CoverageDays -Maximum).Maximum)))
            $last = ($okSites | Where-Object { $_.LastRequest } | Sort-Object LastRequest -Descending | Select-Object -First 1).LastRequest
            $v = Get-RoleUsageVerdict $req $cov $req 100
            if ($v -eq 'No activity in window' -and $okSites.Count -lt $iis.Count) { $v = 'Unknown' }   # unreadable sites could be the busy ones
            $rows.Add((New-RoleUsageRow 'Web Server (IIS)' $v "$req request(s) in $win days across $($okSites.Count) of $($iis.Count) site(s) with readable logs." 'IisUsage' $last $cov 'Likely'))
        }
    }

    # ---- DNS: query counters since service start ----
    $dns = @(& $get 'DnsUsage') | Select-Object -First 1
    if ($dns) {
        if ($dns.Status -eq 'Queried') { $win = [int][math]::Floor([double]$dns.CoverageDays); $rows.Add((New-RoleUsageRow 'DNS Server' (Get-RoleUsageVerdict ([int]$dns.TotalQueries) $win ([int]$dns.QueriesPerDay) 100) "$($dns.TotalQueries) queries since DNS service start $($dns.ServerStartTime) (~$($dns.QueriesPerDay)/day)." 'DnsUsage' '' $win 'Likely')) }
        else { $rows.Add((New-RoleUsageRow 'DNS Server' 'Unknown' "DNS statistics unavailable: $($dns.Reason)" 'DnsUsage' '' 0 'Unknown')) }
    }

    # ---- NPS: RADIUS authentications in the Security log ----
    $nps = @(& $get 'NpsUsage') | Select-Object -First 1
    if ($nps) {
        if ($nps.Status -eq 'Queried') { $n = [int]$nps.Granted + [int]$nps.Denied; $win = [int][math]::Floor([double]$nps.CoverageDays)
            $v = Get-RoleUsageVerdict $n $win $n 5
            if ($v -eq 'No activity in window' -and $nps.AuditEnabled -ne $true) { $v = 'Unknown' }   # events are only written when NPS auditing is on
            $rows.Add((New-RoleUsageRow 'NPS / RADIUS' $v "$($nps.Granted) granted, $($nps.Denied) denied authentication(s) in the Security log ($($nps.CoverageDays) days of coverage). NPS auditing enabled: $($nps.AuditEnabled)." 'NpsUsage' $nps.LastAuth $win 'Likely')) }
        else { $rows.Add((New-RoleUsageRow 'NPS / RADIUS' 'Unknown' "Security log not readable: $($nps.Reason)" 'NpsUsage' '' 0 'Unknown')) }
    }

    # ---- SQL Server: remote clients connected at collection time (point in time only, so never "No activity") ----
    $sqlu = @(& $get 'SqlUsage') | Select-Object -First 1
    if ($sqlu) {
        if ($sqlu.Status -eq 'Queried' -and [int]$sqlu.RemoteClients -gt 0) { $rows.Add((New-RoleUsageRow 'SQL Server' 'Active' "$($sqlu.RemoteClients) remote client(s) connected at collection time ($($sqlu.RunningInstances) running instance(s))." 'SqlUsage' $sqlu.ObservedAt 0 'Likely')) }
        elseif ($sqlu.Status -eq 'Queried') { $rows.Add((New-RoleUsageRow 'SQL Server' 'Unknown' 'No remote clients connected at collection time. Point-in-time only: SQL connection history needs an observation window.' 'SqlUsage' '' 0 'Possible')) }
        else { $rows.Add((New-RoleUsageRow 'SQL Server' 'Unknown' "SQL connections unreadable: $($sqlu.Reason)" 'SqlUsage' '' 0 'Unknown')) }
    }

    # ---- RDS session host: session logon/reconnect events ----
    $rdsu = @(& $get 'RdsUsage') | Select-Object -First 1
    if ($rdsu) {
        if ($rdsu.Status -eq 'Queried') { $win = [int][math]::Floor([double]$rdsu.CoverageDays); $rows.Add((New-RoleUsageRow 'RDS Session Host' (Get-RoleUsageVerdict ([int]$rdsu.SessionEvents) $win ([int]$rdsu.SessionEvents) 5) "$($rdsu.SessionEvents) session logon/reconnect event(s) ($($rdsu.CoverageDays) days of coverage)." 'RdsUsage' $rdsu.LastSession $win 'Likely')) }
        else { $rows.Add((New-RoleUsageRow 'RDS Session Host' 'Unknown' "Session log unreadable: $($rdsu.Reason)" 'RdsUsage' '' 0 'Unknown')) }
    }

    # ---- Domain controller: Kerberos TGT requests ----
    $adu = @(& $get 'AdUsage') | Select-Object -First 1
    if ($adu) {
        if ($adu.Status -eq 'Queried') { $win = [int][math]::Floor([double]$adu.CoverageDays); $rows.Add((New-RoleUsageRow 'Domain Controller' (Get-RoleUsageVerdict ([int]$adu.TgtRequests) $win ([int]$adu.TgtRequests) 50) "$($adu.TgtRequests) Kerberos TGT request(s) in the Security log ($($adu.CoverageDays) days of coverage). Other DCs also serve clients; this is this DC only." 'AdUsage' $adu.LastTgt $win 'Likely')) }
        else { $rows.Add((New-RoleUsageRow 'Domain Controller' 'Unknown' "Security log unreadable: $($adu.Reason)" 'AdUsage' '' 0 'Unknown')) }
    }

    # ---- Hyper-V: VMs running at collection time (state, not history) ----
    $vms = @(& $get 'HyperVVMs')
    if (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)^Hyper-V$') {
        $run = @($vms | Where-Object { $_.State -eq 'Running' }).Count
        if ($run -gt 0) { $rows.Add((New-RoleUsageRow 'Hyper-V Host' 'Active' "$run of $($vms.Count) VM(s) running at collection time." 'HyperVVMs' '' 0 'Likely')) }
        else { $rows.Add((New-RoleUsageRow 'Hyper-V Host' 'Unknown' "No VMs running at collection time ($($vms.Count) defined). State, not history." 'HyperVVMs' '' 0 'Possible')) }
    }

    # ---- WSUS: requests to the WSUS web site (client check-ins and console), from the IIS W3C logs ----
    if (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)^UpdateServices') {
        $w = @($iis | Where-Object { $_.Site -match '(?i)WSUS' }) | Select-Object -First 1
        if ($w -and $w.Status -eq 'Queried') { $win = [int][math]::Floor([double]$w.CoverageDays); $rows.Add((New-RoleUsageRow 'WSUS' (Get-RoleUsageVerdict ([int]$w.Requests) $win ([int]$w.Requests) 100) "$($w.Requests) request(s) to the WSUS web site in $($w.WindowDays) days (includes console traffic)." 'IisUsage' $w.LastRequest $win 'Possible')) }
        else { $rows.Add((New-RoleUsageRow 'WSUS' 'Unknown' 'WSUS web site logs not readable; client check-ins unknown.' 'IisUsage' '' 0 'Unknown')) }
    }

    # ---- DHCP: active scopes + lease counts (point-in-time; lease event history is a later phase) ----
    $dhcp = @(& $get 'DhcpServerSummary') | Select-Object -First 1
    if ($dhcp) {
        if (-not $dhcp.HostsActiveDhcp) {
            $rows.Add((New-RoleUsageRow 'DHCP Server' 'No activity in window' 'No active scopes: role is installed but not serving leases.' 'DhcpServerSummary' '' 0 'Likely'))
        } else {
            $leases = [int](@(& $get 'DhcpScopes' | Where-Object { $_.State -eq 'Active' }) | Measure-Object LeasesInUse -Sum).Sum
            $la = @(& $get 'DhcpLeaseActivity') | Select-Object -First 1
            if ($la -and $la.Status -eq 'Queried') {
                $n = [int]$la.NewLeases + [int]$la.Renewals + [int]$la.Releases; $win = [int][math]::Floor([double]$la.CoverageDays)
                $rows.Add((New-RoleUsageRow 'DHCP Server' (Get-RoleUsageVerdict $n $win $n 5) "$($la.NewLeases) new, $($la.Renewals) renewed, $($la.Releases) released lease(s) in the audit log ($($la.CoverageDays) days of coverage); $leases lease(s) in use now." 'DhcpLeaseActivity' $la.LastLeaseEvent $win 'Likely'))
            } else {
                $v = if ($leases -gt 0) { 'Active' } else { 'Unknown' }
                $rows.Add((New-RoleUsageRow 'DHCP Server' $v "$leases lease(s) in use across active scopes (point in time). Audit log not readable." 'DhcpScopes' '' 0 'Possible'))
            }
        }
    }

    # ---- File shares: open files at collection only (point-in-time) ----
    $sh = @(& $get 'ShareActivity')
    if ($sh.Count -gt 0) {
        $open = @($sh | Where-Object { $_.InUseDuringCollection -eq $true }).Count
        $v = if ($open -gt 0) { 'Active' } else { 'Unknown' }
        $rows.Add((New-RoleUsageRow 'File Server' $v "$open of $($sh.Count) user share(s) had open files at collection time. Point-in-time only; no history." 'ShareActivity' '' 0 'Possible'))
    }

    # ---- Exchange SMTP relay: reuse the existing assessment status ----
    $smtp = @(& $get 'SmtpRelayAssessment') | Select-Object -First 1
    if ($smtp) {
        $v = switch -Wildcard ([string]$smtp.Status) {
            'Confirmed active*' { 'Active' }
            'Possible*'         { 'Unknown' }   # an unidentified client is not confirmed use; the Evidence column keeps the status
            'No SMTP usage*'    { 'No activity in window' }
            default             { 'Unknown' }
        }
        $rows.Add((New-RoleUsageRow 'SMTP Relay' $v ([string]$smtp.Status) 'SmtpRelayAssessment' '' ([int]$smtp.LookbackDays) $(if ($v -eq 'Unknown') { 'Unknown' } elseif ([string]$smtp.Status -like 'Possible*') { 'Possible' } else { 'Likely' })))
    }

    Add-DataSet -Context $Context -Name 'RoleUsage' -Description 'Per-role usage evidence (Active / No activity in window / Unknown). Activity can show use, never prove absence.' -Rows @($rows) -Visibility 'Internal' -SourceModule 'RoleUsage' | Out-Null
    # Client-safe view: role + plain-language reading + window only. No counts, templates, or evidence text.
    $summary = @($rows | ForEach-Object { [pscustomobject]@{ Role=$_.Role; Verdict=$_.Verdict; WindowDays=$_.WindowDays } })
    Add-DataSet -Context $Context -Name 'RoleUsageSummary' -Description 'Client-safe per-role usage reading (role, verdict, window).' -Rows $summary -Visibility 'Both' -SourceModule 'RoleUsage' | Out-Null
}
function Invoke-DiscoverySynthesis {
    param([object]$Context)
    Write-SectionStatus -Title 'Role Usage' -Status 'Analyzing' -Context $Context
    try { Build-RoleUsage -Context $Context } catch { Write-Log -Level WARN -Message 'Role usage build failed.' -Module 'RoleUsage' -Exception $_ -Context $Context }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis','Build-RoleUsage','Get-RoleUsageVerdict'
