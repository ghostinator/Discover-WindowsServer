<#
    Licensing.psm1 - licensing indicators for validation (read-only).
    Produces: Licensing. Makes NO legal licensing determinations - flags for validation.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='Licensing'; DisplayName='Licensing'; Category='Licensing'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('Licensing')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='Licensing'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $rows=[System.Collections.Generic.List[object]]::new()

    # ---- Windows activation / edition (CIM; avoids slow slmgr) ----
    try {
        foreach ($p in (Invoke-CimSafe -ClassName 'SoftwareLicensingProduct' -Filter 'PartialProductKey IS NOT NULL')) {
            $status = switch ([int]$p.LicenseStatus) { 0 {'Unlicensed'} 1 {'Licensed'} 2 {'OOB Grace'} 3 {'OOT Grace'} 4 {'Non-Genuine Grace'} 5 {'Notification'} 6 {'Extended Grace'} default {"Status $($p.LicenseStatus)"} }
            $rows.Add([pscustomobject]@{ Item=$p.Name; Type='OS/Product'; Detail=$status; Evidence='SoftwareLicensingProduct'; ValidationNeeded='Confirm entitlement transfers on server replacement (OEM licenses often do not).' })
        }
    } catch { Add-Limitation -Context $Context -Module 'Licensing' -Message 'Windows activation query failed.' -Reason $_.Exception.Message | Out-Null }
    try {
        $svc = Invoke-CimSafe -ClassName 'SoftwareLicensingService' | Select-Object -First 1
        if ($svc) { $rows.Add([pscustomobject]@{ Item='Windows Activation'; Type='OS'; Detail=("KMS/MAK channel indicators; ProductKeyChannel=" + $svc.OA3xOriginalProductKeyDescription); Evidence='SoftwareLicensingService'; ValidationNeeded='Confirm OEM vs Volume vs Retail.' }) }
    } catch { }

    # ---- RDS licensing (from registry) ----
    try {
        $mode = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core' -Name 'LicensingMode'
        # Only a chosen CAL mode (2 Per Device, 4 Per User) is an RDS licensing dependency. 1 (Remote
        # Administration) is the default on every server and 5 means not configured.
        if ($mode -in 2, 4) { $rows.Add([pscustomobject]@{ Item='RDS Licensing'; Type='RDS'; Detail=("LicensingMode=$mode"); Evidence='Registry'; ValidationNeeded='Confirm RDS CAL type and license server.' }) }
    } catch { }

    # ---- SQL edition (from SqlInstances dataset) ----
    try {
        if ($Context.DataSets.Contains('SqlInstances')) {
            foreach ($s in @($Context.DataSets['SqlInstances'].Rows)) {
                $rows.Add([pscustomobject]@{ Item=("SQL: " + $s.InstanceName); Type='SQL'; Detail=("Edition=" + $s.Edition + "; Version=" + $s.Version); Evidence='SqlInstances'; ValidationNeeded='Confirm SQL licensing (core vs CAL) and edition entitlement.' })
            }
        }
    } catch { }

    # ---- License managers (from Services / InstalledApplications) ----
    try {
        $lmPattern = '(?i)flex(net|lm)|lmgrd|sentinel (ldk|hasp|license)|codemeter|reprise|\bRLM\b|LMTOOLS|license server'
        $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
        $appRows = @(if ($Context.DataSets.Contains('InstalledApplications')) { @($Context.DataSets['InstalledApplications'].Rows) } else { @() })
        foreach ($s in @($svcRows | Where-Object { $_.DisplayName -match $lmPattern -or $_.Name -match $lmPattern })) { $rows.Add([pscustomobject]@{ Item=$s.DisplayName; Type='LicenseManager'; Detail=('Service ' + $s.Name); Evidence='Services'; ValidationNeeded='Which app depends on this, and does licensing rebind to a new host?' }) }
        foreach ($a in @($appRows | Where-Object { $_.DisplayName -match $lmPattern })) { $rows.Add([pscustomobject]@{ Item=$a.DisplayName; Type='LicenseManager'; Detail='Installed application'; Evidence='InstalledApplications'; ValidationNeeded='Vendor license validation required.' }) }
        # Office/Visio/Project
        foreach ($a in @($appRows | Where-Object { $_.DisplayName -match '(?i)Microsoft (Office|Visio|Project)\b' })) { $rows.Add([pscustomobject]@{ Item=$a.DisplayName; Type='App'; Detail=$a.DisplayVersion; Evidence='InstalledApplications'; ValidationNeeded='Confirm licensing model (volume/365/OEM).' }) }
    } catch { }

    return ,@{ Licensing=@($rows) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    $rows = @(if ($RawData -and $RawData.Licensing) { @($RawData.Licensing) } else { @() })
    Add-DataSet -Context $Context -Name 'Licensing' -Description 'Licensing indicators for validation (no legal determinations).' -Rows $rows -Visibility 'Both' -SourceModule 'Licensing' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try { if ($Context.DataSets.Contains('Licensing') -and @($Context.DataSets['Licensing'].Rows | Where-Object { $_.Type -eq 'LicenseManager' }).Count -gt 0) { Add-FollowUpQuestion -Context $Context -Category 'Licensing' -Module 'Licensing' -Audience 'Both' -Question 'A license manager/dongle was detected. Which application depends on it, and is vendor support available to reactivate licensing on a new server?' | Out-Null } } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions'
