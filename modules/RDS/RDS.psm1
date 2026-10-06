<#
    RDS.psm1 - Remote Desktop Services discovery (read-only). Role-gated.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='RDS'; DisplayName='Remote Desktop Services'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole='RDS-RD-Server'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('RdsDiscovery')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-RdsPresent {
    # The Terminal Server registry keys, the licensing key and TermService exist on EVERY Windows
    # Server (plain RDP administration), so their mere presence says nothing. A file server was
    # reported as an RDS host on that basis. Require evidence of actual RDS use instead.
    $mode = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core' -Name 'LicensingMode'
    if ($mode -in 2, 4) { return $true }                      # Per Device / Per User CAL mode was actually chosen
    if (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers' -Name 'SpecifiedLicenseServers') { return $true }
    try { if (Get-CommandAvailable -Name 'Get-RDServer') { if (@(Get-RDServer -ErrorAction SilentlyContinue).Count -gt 0) { return $true } } } catch { }
    return $false
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $rolePresent = $false
    if ($Context.DataSets.Contains('RolesFeatures')) { $rolePresent = (@($Context.DataSets['RolesFeatures'].Rows | Where-Object { $_.Name -match '(?i)^RDS-' -and $_.InstallState -match '(?i)Installed' }).Count -gt 0) }
    if ($rolePresent -or (Test-RdsPresent)) { return [pscustomobject]@{ ModuleName='RDS'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='RDS'; CanRun=$false; Status='NotApplicable'; Reason='RDS roles not detected.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $rows=[System.Collections.Generic.List[object]]::new()
    # Licensing mode/server (read-only registry)
    try {
        $lic = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core'
        $mode = Get-RegistryValueSafe -Path $lic -Name 'LicensingMode'
        # Modes 1 (Remote Administration, the default on every server) and 5 (not configured) are not RDS licensing.
        if ($mode -in 2, 4) { $modeName = switch ($mode) { 2 {'Per Device'} 4 {'Per User'} }; $rows.Add([pscustomobject]@{ Item='RDS Licensing'; Type='Licensing'; Detail=$modeName }) }
        $ls = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers' -Name 'SpecifiedLicenseServers'
        if ($ls) { $rows.Add([pscustomobject]@{ Item='RDS License Servers'; Type='Licensing'; Detail=($ls -join ', ') }) }
    } catch { }
    # Role services from RolesFeatures
    try {
        if ($Context.DataSets.Contains('RolesFeatures')) {
            foreach ($r in @($Context.DataSets['RolesFeatures'].Rows | Where-Object { $_.Name -match '(?i)^RDS-' -and $_.InstallState -match '(?i)Installed' })) {
                $rows.Add([pscustomobject]@{ Item=$r.DisplayName; Type='RoleService'; Detail=$r.Name })
            }
        }
    } catch { }
    # FSLogix / UPD indicators
    try { if (Get-Service -Name 'frxsvc' -ErrorAction SilentlyContinue) { $rows.Add([pscustomobject]@{ Item='FSLogix'; Type='ProfileContainer'; Detail='FSLogix service present' }) } } catch { }
    # Collections (best-effort)
    try { if (Get-CommandAvailable -Name 'Get-RDSessionCollection') { foreach ($c in (Get-RDSessionCollection -ErrorAction SilentlyContinue)) { $rows.Add([pscustomobject]@{ Item=$c.CollectionName; Type='Collection'; Detail=$c.CollectionDescription }) } } } catch { }
    if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ Item='RDS'; Type='Detected'; Detail='RDS indicators present; detailed configuration unavailable.' }) }
    return ,@{ RdsDiscovery=@($rows) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    $rows = @(if ($RawData -and $RawData.RdsDiscovery) { @($RawData.RdsDiscovery) } else { @() })
    Add-DataSet -Context $Context -Name 'RdsDiscovery' -Description 'Remote Desktop Services indicators.' -Rows $rows -Visibility 'Internal' -SourceModule 'RDS' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try { if ($Context.DataSets.Contains('RdsDiscovery') -and @($Context.DataSets['RdsDiscovery'].Rows).Count -gt 0) { Add-FollowUpQuestion -Context $Context -Category 'Critical systems' -Module 'RDS' -Audience 'Both' -Question 'How is RDS licensing configured (per-user/per-device, license server), and who validates user sessions and published apps after a change?' | Out-Null } } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Test-RdsPresent'
