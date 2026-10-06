<#
    WindowsUpdate.psm1 - patch / update posture (read-only).

    Produces: UpdatePosture, InstalledHotfixes, UpdateSources, WsusServerRole.

    NEVER installs, downloads, approves, or declines an update. Every call here is
    a read: Win32_QuickFixEngineering, the Windows Update policy/registry keys, the
    Automatic Update service state, and (where the COM API is present and the caller
    allows it) a LOCAL-ONLY search of already-cached update metadata.

    Why this module exists: patch currency is the single most common scoping question
    an MSP is asked to answer about a server it has just been handed, and it feeds
    directly into migration urgency, CMMC evidence, and whether a maintenance window
    needs to allow for a large catch-up patch run. Before this module the toolkit
    reported the OS build and a pending reboot and nothing else.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='WindowsUpdate'; DisplayName='Windows Update / Patch Posture'; Category='System'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('UpdatePosture','InstalledHotfixes','UpdateSources','WsusServerRole')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $lim = @()
    if (-not $Context.IsAdmin) { $lim = @('Not elevated: the Windows Update agent COM interface and some policy keys may be unreadable.') }
    [pscustomobject]@{ ModuleName='WindowsUpdate'; CanRun=$true; Status='Ready'; Reason=''; Limitations=$lim }
}

function Get-WuAutoUpdateModeLabel {
    <# Maps the AUOptions policy value to a friendly label. #>
    param($Value)
    switch ([string]$Value) {
        '1' { 'Never check for updates (not recommended)' }
        '2' { 'Notify before download' }
        '3' { 'Auto download, notify before install' }
        '4' { 'Auto download and schedule install' }
        '5' { 'Local administrator chooses' }
        default { if ($null -eq $Value) { 'Not configured by policy' } else { "AUOptions=$Value" } }
    }
}

function Get-WuLastActionTime {
    <#
        Reads the Windows Update agent's own last-search / last-install timestamps from
        the registry rather than the COM API, so this works non-elevated and never
        triggers a live detection pass against WSUS or Microsoft Update.
    #>
    param([string]$Action)
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\$Action"
    $v = Get-RegistryValueSafe -Path $path -Name 'LastSuccessTime'
    if ($null -eq $v) { return $null }
    return (Normalize-DateTime $v)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)

    $hotfixes = [System.Collections.Generic.List[object]]::new()
    $sources  = [System.Collections.Generic.List[object]]::new()
    $wsusRole = [System.Collections.Generic.List[object]]::new()

    # ---- Installed hotfixes -------------------------------------------------
    # Win32_QuickFixEngineering only ever reports servicing-stack-visible updates
    # (it misses in-box cumulative rollups on some builds), so the absence of a
    # recent KB here is an indicator, never proof. That caveat is carried into the
    # dataset itself rather than left to the reader.
    $newestDate = $null
    try {
        foreach ($h in (Invoke-CimSafe -ClassName 'Win32_QuickFixEngineering')) {
            try {
                $installed = $null
                if ($h.InstalledOn) { $installed = Normalize-DateTime $h.InstalledOn }
                $hotfixes.Add([pscustomobject]@{
                    HotFixId    = [string]$h.HotFixID
                    Description = [string]$h.Description
                    InstalledOn = $installed
                    InstalledBy = [string]$h.InstalledBy
                })
                if ($installed) {
                    $dt = $null
                    if ([datetime]::TryParse($installed, [ref]$dt)) {
                        if (($null -eq $newestDate) -or ($dt -gt $newestDate)) { $newestDate = $dt }
                    }
                }
            } catch { }
        }
    } catch {
        Add-Limitation -Context $Context -Module 'WindowsUpdate' -Message 'Hotfix enumeration failed.' -Reason $_.Exception.Message | Out-Null
    }

    if ($hotfixes.Count -eq 0) {
        Add-Limitation -Context $Context -Module 'WindowsUpdate' `
            -Message 'Win32_QuickFixEngineering returned no rows; patch history could not be established from this host.' `
            -Impact 'Patch currency unknown' | Out-Null
    }

    # ---- Update source / policy --------------------------------------------
    $auPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wuPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

    $wsusServer   = Get-RegistryValueSafe -Path $wuPath -Name 'WUServer'
    $wsusStatus   = Get-RegistryValueSafe -Path $wuPath -Name 'WUStatusServer'
    $useWsus      = Get-RegistryValueSafe -Path $auPath -Name 'UseWUServer'
    $auOptions    = Get-RegistryValueSafe -Path $auPath -Name 'AUOptions'
    $noAutoUpdate = Get-RegistryValueSafe -Path $auPath -Name 'NoAutoUpdate'
    $targetGroup  = Get-RegistryValueSafe -Path $wuPath -Name 'TargetGroup'

    $sourceKind = if ([bool]($useWsus -eq 1) -and $wsusServer) { 'WSUS / update server' } else { 'Microsoft Update (or managed by a third-party patching tool)' }

    $sources.Add([pscustomobject]@{
        Setting='Update source';           Value=$sourceKind;                              Evidence='Policy registry' })
    $sources.Add([pscustomobject]@{
        Setting='WSUS server';             Value=([string]$wsusServer);                    Evidence=$wuPath })
    $sources.Add([pscustomobject]@{
        Setting='WSUS reporting server';   Value=([string]$wsusStatus);                    Evidence=$wuPath })
    $sources.Add([pscustomobject]@{
        Setting='WSUS target group';       Value=([string]$targetGroup);                   Evidence=$wuPath })
    $sources.Add([pscustomobject]@{
        Setting='Automatic update mode';   Value=(Get-WuAutoUpdateModeLabel $auOptions);   Evidence=$auPath })
    $sources.Add([pscustomobject]@{
        Setting='Automatic updates disabled by policy'; Value=([string][bool]($noAutoUpdate -eq 1)); Evidence=$auPath })

    if ($wsusServer) {
        Add-DependencyEdge -Context $Context -SourceType 'Server' -SourceName $Context.ComputerName `
            -DependencyType 'PatchesFrom' -Target ([string]$wsusServer) -Evidence 'WUServer policy value' `
            -Confidence 'Confirmed' -SourceDataset 'UpdateSources' -ProjectImpact 'Cutover Complexity' `
            -ValidationQuestion 'Does this WSUS/update server survive the migration, and is the replacement server pointed at it?' | Out-Null
    }

    # ---- Update agent service state ----------------------------------------
    $wuServiceState = ''
    $wuServiceStart = ''
    try {
        $svc = Invoke-CimSafe -ClassName 'Win32_Service' -Filter "Name='wuauserv'" | Select-Object -First 1
        if ($svc) { $wuServiceState = [string]$svc.State; $wuServiceStart = [string]$svc.StartMode }
    } catch { }

    # ---- WSUS server ROLE on this box (different from being a WSUS client) --
    try {
        $isWsusServer = $false
        if (Test-RegistryPathSafe 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup') { $isWsusServer = $true }
        if (Get-Service -Name 'WsusService' -ErrorAction SilentlyContinue) { $isWsusServer = $true }
        if ($isWsusServer) {
            $contentDir = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup' -Name 'ContentDir'
            $wsusRole.Add([pscustomobject]@{
                Item='WSUS Server role'; Detail='This server hosts WSUS.'; ContentDirectory=([string]$contentDir)
                WhyItMatters='Retiring or moving a WSUS server orphans every client pointed at it and its content directory can be very large.'
            })
            Add-Unknown -Context $Context -Unknown 'This server hosts WSUS; the set of clients pointed at it is not discoverable from the server alone.' `
                -WhyItMatters 'Clients pointed at a retired WSUS server silently stop patching.' -Module 'WindowsUpdate' `
                -RecommendedValidationQuestion 'Which clients are pointed at this WSUS server, and where will they point afterwards?' | Out-Null
        }
    } catch { }

    # ---- Posture summary row ------------------------------------------------
    $daysSince = $null
    if ($newestDate) { $daysSince = [int][math]::Round(((Get-Date) - $newestDate).TotalDays, 0) }

    $pendingReboot = $false
    try {
        if ($Context.DataSets.Contains('PendingReboot')) {
            $pendingReboot = [bool](@($Context.DataSets['PendingReboot'].Rows | Where-Object { $_.RebootPending -eq $true }).Count -gt 0)
        }
    } catch { }

    $posture = [pscustomobject]@{
        HotfixCount                 = $hotfixes.Count
        NewestHotfixInstalledOn     = (Normalize-DateTime $newestDate)
        DaysSinceNewestHotfix       = $daysSince
        PatchingLooksStale          = [bool](($null -ne $daysSince) -and ($daysSince -gt 90))
        NoPatchHistoryAvailable     = [bool]($hotfixes.Count -eq 0)
        UpdateSource                = $sourceKind
        WsusServer                  = ([string]$wsusServer)
        AutomaticUpdateMode         = (Get-WuAutoUpdateModeLabel $auOptions)
        AutomaticUpdatesDisabled    = [bool]($noAutoUpdate -eq 1)
        UpdateAgentServiceState     = $wuServiceState
        UpdateAgentServiceStartMode = $wuServiceStart
        UpdateAgentDisabled         = [bool]($wuServiceStart -match '(?i)disabled')
        LastSuccessfulSearch        = (Get-WuLastActionTime -Action 'Detect')
        LastSuccessfulInstall       = (Get-WuLastActionTime -Action 'Install')
        PendingReboot               = $pendingReboot
        IsWsusServer                = [bool]($wsusRole.Count -gt 0)
        Note                        = 'Hotfix history is an indicator only: Win32_QuickFixEngineering does not list every servicing update on every build, and third-party patching tools may not register here.'
    }

    return ,@{
        UpdatePosture     = @($posture)
        InstalledHotfixes = @($hotfixes)
        UpdateSources     = @($sources)
        WsusServerRole    = @($wsusRole)
    }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'UpdatePosture'     -Description 'Patch currency and update configuration summary.'      -Rows (& $get 'UpdatePosture')     -Visibility 'Both'     -SourceModule 'WindowsUpdate' | Out-Null
    Add-DataSet -Context $Context -Name 'InstalledHotfixes' -Description 'Installed hotfixes from Win32_QuickFixEngineering.'    -Rows (& $get 'InstalledHotfixes') -Visibility 'Internal' -SourceModule 'WindowsUpdate' | Out-Null
    Add-DataSet -Context $Context -Name 'UpdateSources'     -Description 'Where this server gets its updates from.'              -Rows (& $get 'UpdateSources')     -Visibility 'Internal' -SourceModule 'WindowsUpdate' | Out-Null
    Add-DataSet -Context $Context -Name 'WsusServerRole'    -Description 'WSUS server role indicators (this host serves updates).' -Rows (& $get 'WsusServerRole')  -Visibility 'Both'     -SourceModule 'WindowsUpdate' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        Add-FollowUpQuestion -Context $Context -Category 'Patching / maintenance' -Module 'WindowsUpdate' -Audience 'Both' `
            -Question 'How is this server patched today (WSUS, RMM tool, manual), who approves the patches, and when is its maintenance window?' | Out-Null
        if ($Context.DataSets.Contains('UpdatePosture')) {
            $p = @($Context.DataSets['UpdatePosture'].Rows) | Select-Object -First 1
            if ($p -and $p.PatchingLooksStale) {
                Add-FollowUpQuestion -Context $Context -Category 'Patching / maintenance' -Module 'WindowsUpdate' -Audience 'ClientSafe' `
                    -Question 'This server does not appear to have been patched recently. Is patching handled by another tool we should know about, or has it been deliberately held back for an application?' | Out-Null
            }
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-WuAutoUpdateModeLabel','Get-WuLastActionTime'
