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
        ProducesDatasets          = @('RoleUsage')
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
            'Possible*'         { 'Active' }
            'No SMTP usage*'    { 'No activity in window' }
            default             { 'Unknown' }
        }
        $rows.Add((New-RoleUsageRow 'SMTP Relay' $v ([string]$smtp.Status) 'SmtpRelayAssessment' '' ([int]$smtp.LookbackDays) $(if ($v -eq 'Unknown') { 'Unknown' } else { 'Likely' })))
    }

    Add-DataSet -Context $Context -Name 'RoleUsage' -Description 'Per-role usage evidence (Active / No activity in window / Unknown). Activity can show use, never prove absence.' -Rows @($rows) -Visibility 'Internal' -SourceModule 'RoleUsage' | Out-Null
}
function Invoke-DiscoverySynthesis {
    param([object]$Context)
    Write-SectionStatus -Title 'Role Usage' -Status 'Analyzing' -Context $Context
    try { Build-RoleUsage -Context $Context } catch { Write-Log -Level WARN -Message 'Role usage build failed.' -Module 'RoleUsage' -Exception $_ -Context $Context }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis','Build-RoleUsage','Get-RoleUsageVerdict'
