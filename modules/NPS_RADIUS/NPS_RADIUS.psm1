<#
    NPS_RADIUS.psm1 - NPS / RADIUS / VPN / MFA discovery (read-only). Role-gated.
    NEVER collects RADIUS shared secrets.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='NPS_RADIUS'; DisplayName='NPS / RADIUS / VPN / MFA'; Category='Security'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$true; RequiresDomainContext=$false
        RequiresRole='NPAS'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('NpsRadiusDiscovery')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-NpsPresent {
    if (Get-Service -Name 'IAS' -ErrorAction SilentlyContinue) { return $true }
    if (Test-RegistryPathSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\IAS') { return $true }
    return $false
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $rolePresent = $false
    if ($Context.DataSets.Contains('RolesFeatures')) { $rolePresent = (@($Context.DataSets['RolesFeatures'].Rows | Where-Object { $_.Name -match '(?i)NPAS|Policy-Server' }).Count -gt 0) }
    if ($rolePresent -or (Test-NpsPresent)) { return [pscustomobject]@{ ModuleName='NPS_RADIUS'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='NPS_RADIUS'; CanRun=$false; Status='NotApplicable'; Reason='NPS/RADIUS role not detected.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $rows=[System.Collections.Generic.List[object]]::new()
    $rows.Add([pscustomobject]@{ Item='NPS'; Type='Role'; Detail='NPS/RADIUS indicators present on this server.' })
    # Shared secrets are intentionally NOT collected.
    Add-Unknown -Context $Context -Unknown 'RADIUS shared secrets are intentionally not collected.' -WhyItMatters 'Secrets must be re-coordinated with network devices during migration.' -Module 'NPS_RADIUS' -RecommendedValidationQuestion 'Who holds the RADIUS shared secrets for each client device?' | Out-Null
    # Config summary via netsh nps show config (READ-ONLY show)
    try {
        $r = Invoke-CommandLineSafe -FilePath 'netsh.exe' -Arguments @('nps','show','config') -TimeoutSeconds 45
        if ($r.Succeeded -and $r.StdOut) {
            # Real output is "<Section> configuration:" headers, each object opened by "Name = X"
            # followed by "Key = value" lines. Only allow-listed keys are read, so the
            # "Shared secret" line is never captured.
            $type = ''; $cur = $null
            foreach ($ln in ($r.StdOut -split "`r?`n")) {
                if ($ln -match '(?i)^\s*(Client|Connection request policy|Network policy|Remote RADIUS server group)\s+configuration\s*:') {
                    $type = switch -Regex ($Matches[1]) { '(?i)^client' { 'RadiusClient' } '(?i)^connection' { 'ConnectionRequestPolicy' } '(?i)^network' { 'NetworkPolicy' } default { 'RemoteRadiusServerGroup' } }
                    $cur = $null; continue
                }
                if (-not $type) { continue }
                if ($ln -match '^\s*Name\s*=\s*(.+?)\s*$') { $cur = [pscustomobject]@{ Item=$Matches[1]; Type=$type; Detail='' }; $rows.Add($cur); continue }
                if ($cur -and $ln -match '^\s*(Address|State|Processing order|Vendor)\s*=\s*(.+?)\s*$') {
                    $kv = '{0}={1}' -f $Matches[1], $Matches[2]
                    $cur.Detail = if ($cur.Detail) { $cur.Detail + '; ' + $kv } else { $kv }
                }
            }
        } else { Add-Limitation -Context $Context -Module 'NPS_RADIUS' -Message 'netsh nps show config unavailable; NPS present but detail limited.' | Out-Null }
    } catch { Add-Limitation -Context $Context -Module 'NPS_RADIUS' -Message 'NPS config query failed.' -Reason $_.Exception.Message | Out-Null }
    # Azure MFA NPS extension indicator
    try { if (Test-RegistryPathSafe 'HKLM:\SOFTWARE\Microsoft\AzureMfa') { $rows.Add([pscustomobject]@{ Item='Azure MFA NPS Extension'; Type='MFA'; Detail='Registry indicator present' }) } } catch { }
    return ,@{ NpsRadiusDiscovery=@($rows) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    $rows = @(if ($RawData -and $RawData.NpsRadiusDiscovery) { @($RawData.NpsRadiusDiscovery) } else { @() })
    Add-DataSet -Context $Context -Name 'NpsRadiusDiscovery' -Description 'NPS/RADIUS indicators (no shared secrets).' -Rows $rows -Visibility 'Internal' -SourceModule 'NPS_RADIUS' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try { if ($Context.DataSets.Contains('NpsRadiusDiscovery') -and @($Context.DataSets['NpsRadiusDiscovery'].Rows).Count -gt 0) { Add-FollowUpQuestion -Context $Context -Category 'Security / compliance' -Module 'NPS_RADIUS' -Audience 'Both' -Question 'Which devices (VPN/Wi-Fi/switches) authenticate through this NPS/RADIUS server, and who manages the shared secrets and certificates?' | Out-Null } } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Test-NpsPresent'
