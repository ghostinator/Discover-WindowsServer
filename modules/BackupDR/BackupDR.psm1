<#
    BackupDR.psm1 - backup/DR solution detection and VSS writer status (read-only).
    Produces: BackupDiscovery, VssWriters. Never runs or modifies backups.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='BackupDR'; DisplayName='Backup & DR'; Category='Backup'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('BackupDiscovery','VssWriters')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='BackupDR'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $backup=[System.Collections.Generic.List[object]]::new(); $vss=[System.Collections.Generic.List[object]]::new()
    $patterns = @(
        @{ Product='Veeam'; Pattern='(?i)veeam' }, @{ Product='Datto'; Pattern='(?i)datto' },
        @{ Product='Acronis'; Pattern='(?i)acronis' }, @{ Product='StorageCraft/ShadowProtect'; Pattern='(?i)storagecraft|shadowprotect' },
        @{ Product='Azure Backup (MARS)'; Pattern='(?i)Microsoft Azure Recovery Services|OBEngine' },
        @{ Product='Cove/N-able'; Pattern='(?i)\bcove\b|N-able|SolarWinds Backup' }, @{ Product='Carbonite'; Pattern='(?i)carbonite' },
        @{ Product='Windows Server Backup'; Pattern='(?i)Windows Server Backup|wbengine' }, @{ Product='Commvault'; Pattern='(?i)commvault' },
        @{ Product='Unitrends'; Pattern='(?i)unitrends' }, @{ Product='Barracuda'; Pattern='(?i)barracuda' }, @{ Product='Rubrik'; Pattern='(?i)rubrik' }
    )
    try {
        $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
        $appRows = @(if ($Context.DataSets.Contains('InstalledApplications')) { @($Context.DataSets['InstalledApplications'].Rows) } else { @() })
        foreach ($p in $patterns) {
            $ev=@()
            $sh = @($svcRows | Where-Object { $_.DisplayName -match $p.Pattern -or $_.Name -match $p.Pattern })
            $ah = @($appRows | Where-Object { $_.DisplayName -match $p.Pattern })
            if ($sh.Count) { $ev += ('service:' + $sh[0].Name) }
            if ($ah.Count) { $ev += ('app:' + $ah[0].DisplayName) }
            if ($ev.Count) { $backup.Add([pscustomobject]@{ Product=$p.Product; Evidence=($ev -join '; '); Confidence='Likely' }) }
        }
    } catch { Add-Limitation -Context $Context -Module 'BackupDR' -Message 'Backup product detection failed.' -Reason $_.Exception.Message | Out-Null }

    if ($backup.Count -gt 0) { Add-Unknown -Context $Context -Unknown 'Backup software detected but recent success/restore not confirmed.' -WhyItMatters 'A backup agent does not prove backups are current or restorable.' -Module 'BackupDR' -RecommendedValidationQuestion 'When was the last successful backup and last tested restore?' | Out-Null }

    # ---- VSS writers (read-only) ----
    try {
        $r = Invoke-CommandLineSafe -FilePath 'vssadmin.exe' -Arguments @('list','writers') -TimeoutSeconds 45
        if ($r.Succeeded -and $r.StdOut) {
            $name=''; $state=''; $lastErr=''
            foreach ($ln in ($r.StdOut -split "`r?`n")) {
                if ($ln -match "Writer name:\s*'([^']+)'") { if ($name) { $vss.Add([pscustomobject]@{ Writer=$name; State=$state; LastError=$lastErr }) }; $name=$Matches[1]; $state=''; $lastErr='' }
                elseif ($ln -match 'State:\s*(.+)$') { $state=$Matches[1].Trim() }
                elseif ($ln -match 'Last error:\s*(.+)$') { $lastErr=$Matches[1].Trim() }
            }
            if ($name) { $vss.Add([pscustomobject]@{ Writer=$name; State=$state; LastError=$lastErr }) }
        } else { Add-Limitation -Context $Context -Module 'BackupDR' -Message 'vssadmin list writers unavailable (may require elevation).' | Out-Null }
    } catch { Add-Limitation -Context $Context -Module 'BackupDR' -Message 'VSS writer query failed.' -Reason $_.Exception.Message | Out-Null }

    return ,@{ BackupDiscovery=@($backup); VssWriters=@($vss) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'BackupDiscovery' -Description 'Detected backup/DR solutions.' -Rows (& $get 'BackupDiscovery') -Visibility 'Both'     -SourceModule 'BackupDR' | Out-Null
    Add-DataSet -Context $Context -Name 'VssWriters'      -Description 'VSS writer status.'            -Rows (& $get 'VssWriters')      -Visibility 'Internal' -SourceModule 'BackupDR' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    Add-FollowUpQuestion -Context $Context -Category 'Backup / restore' -Module 'BackupDR' -Audience 'Both' -Question 'How is this server backed up, where are the backups stored, and when was a restore last successfully tested?' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions'
