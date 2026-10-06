<#
.SYNOPSIS
    Compares two completed Discover-WindowsServer runs of the same server (or two fleet
    engagement folders) and reports what changed between them.

.DESCRIPTION
    Every discovery run today is a standalone snapshot - there's no way to see "what changed
    since last time we scanned this client" without opening two report folders side by side and
    comparing by eye. This reads each run's evidence\data\json\<Dataset>.json files directly (the
    same per-dataset exports every run already produces) and diffs matching datasets by a natural
    key, rather than a raw text/JSON diff, so a share being renamed shows up as one row that
    changed, not as a removed-then-added pair, and so noisy-but-meaningless fields (a scheduled
    task's LastRunTime, a file share's usage counters) don't drown out real drift.

    Only datasets in $script:DriftKeyMap are compared - a dataset with no known natural key, or
    one that's been deliberately excluded (EventLogSamples, RunningProcesses - neither has a
    stable identity across two runs, since timestamps and PIDs are never the same twice), is
    reported as Unsupported rather than guessed at. This list is deliberately incomplete and easy
    to extend - see Compare-DiscoveryDataset.

    Two comparison modes:
      1. Single-server: -BaselineRunFolder / -CurrentRunFolder, each a
         Discover-WindowsServer_<ComputerName>_<timestamp>\ folder.
      2. Fleet-wide: -BaselineEngagementFolder / -CurrentEngagementFolder, each a folder
         containing one or more of those run folders (exactly what tools\Invoke-FleetDiscovery.ps1
         produces). Servers are matched by ComputerName across the two folders; a server present
         in only one side is reported under OnlyInBaseline/OnlyInCurrent rather than silently
         dropped.

    Dot-sources tools\Merge-FleetDiscoveryResults.ps1 to reuse its run-folder enumeration
    (Get-FleetRunFolder/Get-FleetRunMetadata), its report plumbing (ConvertTo-FleetHtmlTable/
    ConvertTo-FleetMarkdownTable), and its branding (Get-FleetBranding/Get-FleetLogoHtml) rather
    than re-implementing any of that a second time - safe because that file's own "only runs when
    executed directly" guard never fires for a dot-sourced call, exactly the same way the GUI
    already dot-sources it.

    CLIENT SAFETY: the client-facing summary (drift-client-summary.html/.md) only ever surfaces
    a dataset's drift if that dataset's Visibility (read from the CURRENT run's own
    collection-metadata.json, the same per-run recorded value Get-FleetClientSafeDataset already
    reads) is ClientSafe or Both, and even then only as a generic count ("3 new, 1 removed") -
    never the actual field-level Added/Removed/Changed detail, which is Internal-only.

.PARAMETER BaselineRunFolder
    Single-server mode: the OLDER Discover-WindowsServer_<ComputerName>_<timestamp> run folder.

.PARAMETER CurrentRunFolder
    Single-server mode: the NEWER run folder to compare against the baseline.

.PARAMETER BaselineEngagementFolder
    Fleet mode: the OLDER engagement folder (containing one or more run folders).

.PARAMETER CurrentEngagementFolder
    Fleet mode: the NEWER engagement folder to compare against the baseline.

.PARAMETER OutputPath
    Where the drift report files land. Defaults to a drift\ subfolder of whichever "current"
    folder was passed.

.EXAMPLE
    .\tools\Compare-DiscoveryRuns.ps1 -BaselineRunFolder 'C:\Out\Discover-WindowsServer_SRV1_20260901_090000' -CurrentRunFolder 'C:\Out\Discover-WindowsServer_SRV1_20260927_090000'

.EXAMPLE
    .\tools\Compare-DiscoveryRuns.ps1 -BaselineEngagementFolder 'C:\Temp\FleetRuns\Fleet_20260901' -CurrentEngagementFolder 'C:\Temp\FleetRuns\Fleet_20260927'
#>
[CmdletBinding(DefaultParameterSetName = 'SingleServer')]
param(
    [Parameter(ParameterSetName = 'SingleServer')][string]$BaselineRunFolder,
    [Parameter(ParameterSetName = 'SingleServer')][string]$CurrentRunFolder,
    [Parameter(ParameterSetName = 'Fleet')][string]$BaselineEngagementFolder,
    [Parameter(ParameterSetName = 'Fleet')][string]$CurrentEngagementFolder,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

# Reuses Get-FleetRunFolder/Get-FleetRunMetadata (run-folder enumeration), ConvertTo-FleetHtmlTable/
# ConvertTo-FleetMarkdownTable (table rendering) and Get-FleetBranding/Get-FleetLogoHtml (report
# branding) rather than re-implementing any of them here - see this file's own header comment.
. (Join-Path $PSScriptRoot 'Merge-FleetDiscoveryResults.ps1')

#region Natural-key table -----------------------------------------------------

# Which field(s) uniquely identify a row within one dataset, so a row can be matched across two
# runs (rather than the whole dataset being diffed as an opaque blob). Verified against real
# evidence\data\json\*.json output - NOT guessed. Deliberately incomplete: a dataset not listed
# here is reported as Unsupported (see Compare-DiscoveryDataset), never silently mis-keyed.
$script:DriftKeyMap = @{
    'SmbShares'             = @('Name')
    'Services'              = @('Name')
    'LocalUsers'            = @('Name')
    'LocalGroups'           = @('Name')
    'LocalGroupMembers'     = @('Group', 'Member')
    'SharePermissions'      = @('Share', 'Account')
    'ScheduledTasks'        = @('TaskName', 'TaskPath')
    'InstalledApplications' = @('DisplayName', 'DisplayVersion')
    'NtfsAclSummary'        = @('Share')
}

# Fields that exist on a keyed row but churn on ordinary usage rather than representing real
# drift - excluded from the field-by-field comparison so they don't bury genuine changes (or, for
# NtfsAclSummary, generate a "changed" row on literally every re-scan of an active file share).
$script:DriftIgnoredFields = @{
    'ScheduledTasks'        = @('ActionsText', 'LastRunTime', 'NextRunTime', 'LastTaskResult', 'LastRunFailed')
    'InstalledApplications' = @('InstallDate', 'EstimatedSizeMB')
    'NtfsAclSummary'        = @('FileCount', 'TotalSizeGB', 'LargeFilesOverThreshold', 'OldFilesOverYears', 'RecentlyModified30d', 'RecycleBinFilesFound', 'RecycleBinSizeGB')
}

# No stable row identity across two runs at all - a timestamp or a PID is never the same twice,
# so "diffing" these would only ever report 100% churn, contradicting this toolkit's own
# fail-soft, don't-overclaim design. Excluded outright rather than mis-keyed.
$script:DriftExcludedDatasets = @('EventLogSamples', 'RunningProcesses')

# Row-level noise, not field-level: confirmed live comparing two real fleet runs, every
# ScheduledTasks diff reported exactly "1 added, 1 removed" for a task named
# DiscoverWindowsServer_<8 hex chars> - that's this toolkit's OWN remote-run scheduled task
# (Invoke-FleetDiscovery.ps1's $taskName), fresh-named per run and cleaned up after, so it's
# always present-and-different between any two fleet-triggered scans. It's the scanner scanning
# itself, not something a client cares about - filtered out before keying/comparing rather than
# left to show up as drift every single time.
$script:DriftRowExclusionFilters = @{
    'ScheduledTasks' = { param($row) $row.TaskName -match '^DiscoverWindowsServer_[0-9a-f]{8}$' }
}

#endregion

#region Pure diff functions ---------------------------------------------------

function Compare-DiscoveryDataset {
    <#
        Keyed diff of one dataset's rows between two runs. Pure - no file I/O. Returns a plain
        array via .ToArray() on an internal List, never ,@() - the exact pattern that silently
        collapsed the fleet client summary's tables earlier (see Merge-FleetDiscoveryResults.ps1's
        Get-FleetClientSafeDataset/Merge-FleetDataset fix) - every caller here assigns the result
        before any further piping, matching that fix.
    #>
    param(
        [Parameter(Mandatory)][string]$DatasetName,
        [AllowNull()][object[]]$BaselineRows,
        [AllowNull()][object[]]$CurrentRows
    )
    if ($script:DriftExcludedDatasets -contains $DatasetName) {
        return [pscustomobject]@{ DatasetName = $DatasetName; Supported = $false; SkipReason = 'Excluded from drift - no stable row identity across runs (timestamps/PIDs are never the same twice).'; Added = @(); Removed = @(); Changed = @(); UnchangedCount = 0 }
    }
    if (-not $script:DriftKeyMap.ContainsKey($DatasetName)) {
        return [pscustomobject]@{ DatasetName = $DatasetName; Supported = $false; SkipReason = 'Unsupported - no known natural key for this dataset yet.'; Added = @(); Removed = @(); Changed = @(); UnchangedCount = 0 }
    }

    $keyFields = $script:DriftKeyMap[$DatasetName]
    $ignoreFields = @($script:DriftIgnoredFields[$DatasetName])
    $baseline = @(if ($null -eq $BaselineRows) { @() } else { @($BaselineRows) })
    $current  = @(if ($null -eq $CurrentRows)  { @() } else { @($CurrentRows) })
    if ($script:DriftRowExclusionFilters.ContainsKey($DatasetName)) {
        $rowFilter = $script:DriftRowExclusionFilters[$DatasetName]
        $baseline = @($baseline | Where-Object { -not (& $rowFilter $_) })
        $current  = @($current  | Where-Object { -not (& $rowFilter $_) })
    }

    $getKey = { param($row) (($keyFields | ForEach-Object { [string]$row.$_ }) -join '|') }
    $baselineByKey = [ordered]@{}
    foreach ($row in $baseline) { $baselineByKey[(& $getKey $row)] = $row }
    $currentByKey = [ordered]@{}
    foreach ($row in $current) { $currentByKey[(& $getKey $row)] = $row }

    $added = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    $changed = [System.Collections.Generic.List[object]]::new()
    $unchangedCount = 0

    foreach ($key in $currentByKey.Keys) {
        if (-not $baselineByKey.Contains($key)) { $added.Add($currentByKey[$key]); continue }
        $baseRow = $baselineByKey[$key]
        $curRow = $currentByKey[$key]
        $fieldNames = @(@($baseRow.PSObject.Properties.Name) + @($curRow.PSObject.Properties.Name) | Sort-Object -Unique | Where-Object { $ignoreFields -notcontains $_ })
        $fieldChanges = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $fieldNames) {
            $bVal = [string]$baseRow.$f
            $cVal = [string]$curRow.$f
            if ($bVal -ne $cVal) { $fieldChanges.Add([pscustomobject]@{ Field = $f; Baseline = $bVal; Current = $cVal }) }
        }
        if ($fieldChanges.Count -gt 0) { $changed.Add([pscustomobject]@{ Key = $key; Fields = $fieldChanges.ToArray() }) }
        else { $unchangedCount++ }
    }
    foreach ($key in $baselineByKey.Keys) {
        if (-not $currentByKey.Contains($key)) { $removed.Add($baselineByKey[$key]) }
    }

    return [pscustomobject]@{
        DatasetName = $DatasetName; Supported = $true; SkipReason = ''
        Added = $added.ToArray(); Removed = $removed.ToArray(); Changed = $changed.ToArray(); UnchangedCount = $unchangedCount
    }
}

function Get-DriftDatasetRows {
    <# Reads evidence\data\json\<name>.json from one run folder. Empty array (not $null, never throws) when missing/unreadable - a dataset a module didn't produce on one side is not a fatal error, mirrors Merge-FleetDataset's own per-run tolerance. #>
    param([Parameter(Mandatory)][string]$RunFolder, [Parameter(Mandatory)][string]$DatasetName)
    $path = Join-Path $RunFolder ("evidence\data\json\{0}.json" -f $DatasetName)
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    try { return @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return @() }
}

function Compare-DiscoveryRunPair {
    <# Diffs every dataset the UNION of both runs' collection-metadata.json recorded, for one server. A dataset that existed in the baseline but vanished from the current run still gets compared (and shows up entirely under Removed), never silently skipped. #>
    param([Parameter(Mandatory)][string]$BaselineRunFolder, [Parameter(Mandatory)][string]$CurrentRunFolder)

    $baselineMeta = Get-FleetRunMetadata -RunFolder $BaselineRunFolder
    $currentMeta  = Get-FleetRunMetadata -RunFolder $CurrentRunFolder
    $computerName = if ($currentMeta) { $currentMeta.ComputerName } elseif ($baselineMeta) { $baselineMeta.ComputerName } else { Split-Path $CurrentRunFolder -Leaf }

    $baselineDatasetNames = @(if ($baselineMeta -and $baselineMeta.Datasets) { @($baselineMeta.Datasets) | ForEach-Object { $_.Name } } else { @() })
    $currentDatasetNames  = @(if ($currentMeta -and $currentMeta.Datasets)  { @($currentMeta.Datasets)  | ForEach-Object { $_.Name } } else { @() })
    $allDatasetNames = @(@($baselineDatasetNames) + @($currentDatasetNames) | Sort-Object -Unique)

    # The CURRENT run's own recorded Visibility wins when both sides recorded the same dataset -
    # this is "what would the client report show TODAY," which is what a client-facing drift
    # summary should reflect. Falls back to the baseline's value for a dataset that disappeared
    # entirely (nothing else could tell us what it would have been).
    $visibilityByName = @{}
    if ($baselineMeta -and $baselineMeta.Datasets) { foreach ($d in @($baselineMeta.Datasets)) { $visibilityByName[$d.Name] = $d.Visibility } }
    if ($currentMeta -and $currentMeta.Datasets)  { foreach ($d in @($currentMeta.Datasets))  { $visibilityByName[$d.Name] = $d.Visibility } }

    $datasetResults = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $allDatasetNames) {
        $baselineRows = Get-DriftDatasetRows -RunFolder $BaselineRunFolder -DatasetName $name
        $currentRows  = Get-DriftDatasetRows -RunFolder $CurrentRunFolder -DatasetName $name
        $datasetResults.Add((Compare-DiscoveryDataset -DatasetName $name -BaselineRows $baselineRows -CurrentRows $currentRows))
    }

    return [pscustomobject]@{
        ComputerName      = $computerName
        BaselineRunId     = if ($baselineMeta) { $baselineMeta.RunId } else { $null }
        CurrentRunId      = if ($currentMeta) { $currentMeta.RunId } else { $null }
        BaselineTimestamp = if ($baselineMeta) { $baselineMeta.StartTime } else { $null }
        CurrentTimestamp  = if ($currentMeta) { $currentMeta.StartTime } else { $null }
        DatasetResults    = $datasetResults.ToArray()
        DatasetVisibility = $visibilityByName
    }
}

function Compare-DiscoveryFleetRuns {
    <# Matches servers by ComputerName across two engagement folders and diffs each match. A server present on only one side is reported, never dropped. #>
    param([Parameter(Mandatory)][string]$BaselineEngagementFolder, [Parameter(Mandatory)][string]$CurrentEngagementFolder)

    # Get-FleetRunFolder returns ,@(...) - bare-assign only, never re-wrap in @() (see that
    # function's own Pester coverage for why re-wrapping collapses it).
    $baselineRunFolders = Get-FleetRunFolder -EngagementFolder $BaselineEngagementFolder
    $currentRunFolders  = Get-FleetRunFolder -EngagementFolder $CurrentEngagementFolder

    # If the same ComputerName appears more than once within one engagement folder, keep the
    # lexicographically-latest folder name - the timestamp suffix in
    # Discover-WindowsServer_<ComputerName>_<timestamp> sorts correctly as a plain string.
    $baselineByComputer = @{}
    foreach ($f in $baselineRunFolders) {
        $meta = Get-FleetRunMetadata -RunFolder $f.FullName
        $name = if ($meta) { $meta.ComputerName } else { $f.Name }
        if (-not $baselineByComputer.ContainsKey($name) -or $f.Name -gt $baselineByComputer[$name].Name) { $baselineByComputer[$name] = $f }
    }
    $currentByComputer = @{}
    foreach ($f in $currentRunFolders) {
        $meta = Get-FleetRunMetadata -RunFolder $f.FullName
        $name = if ($meta) { $meta.ComputerName } else { $f.Name }
        if (-not $currentByComputer.ContainsKey($name) -or $f.Name -gt $currentByComputer[$name].Name) { $currentByComputer[$name] = $f }
    }

    $serverResults  = [System.Collections.Generic.List[object]]::new()
    $onlyInBaseline = [System.Collections.Generic.List[string]]::new()
    $onlyInCurrent  = [System.Collections.Generic.List[string]]::new()

    foreach ($name in $currentByComputer.Keys) {
        if ($baselineByComputer.ContainsKey($name)) {
            $serverResults.Add((Compare-DiscoveryRunPair -BaselineRunFolder $baselineByComputer[$name].FullName -CurrentRunFolder $currentByComputer[$name].FullName))
        } else {
            $onlyInCurrent.Add($name)
        }
    }
    foreach ($name in $baselineByComputer.Keys) {
        if (-not $currentByComputer.ContainsKey($name)) { $onlyInBaseline.Add($name) }
    }

    return [pscustomobject]@{
        ServerResults  = $serverResults.ToArray()
        OnlyInBaseline = $onlyInBaseline.ToArray()
        OnlyInCurrent  = $onlyInCurrent.ToArray()
    }
}

function Get-ClientSafeDriftSummary {
    <#
        Reduces dataset-level drift to a generic count-only label ("3 new, 1 removed"), and only
        for datasets the CURRENT run itself recorded as ClientSafe or Both - the exact same
        per-run Visibility field Get-FleetClientSafeDataset already reads, never a second,
        hardcoded list. Never returns row-level Field/Baseline/Current detail - that's Internal
        information about the server's own configuration, not something to hand to a client,
        matching Get-RbClientHeadlines/Get-FleetClientHeadlines's existing "generic label only"
        contract for anything client-facing.
    #>
    param([Parameter(Mandatory)][object[]]$DatasetResults, [Parameter(Mandatory)][hashtable]$DatasetVisibility)
    $lines = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($DatasetResults)) {
        if (-not $r.Supported) { continue }
        if ($DatasetVisibility[$r.DatasetName] -notin @('ClientSafe', 'Both')) { continue }
        $addedCount = @($r.Added).Count
        $removedCount = @($r.Removed).Count
        $changedCount = @($r.Changed).Count
        if ($addedCount -eq 0 -and $removedCount -eq 0 -and $changedCount -eq 0) { continue }
        $parts = [System.Collections.Generic.List[string]]::new()
        if ($addedCount -gt 0)   { [void]$parts.Add("$addedCount new") }
        if ($removedCount -gt 0) { [void]$parts.Add("$removedCount removed") }
        if ($changedCount -gt 0) { [void]$parts.Add("$changedCount changed") }
        $lines.Add([pscustomobject]@{ DatasetName = $r.DatasetName; Label = ($parts -join ', ') })
    }
    return $lines.ToArray()
}

#endregion

#region Report model -----------------------------------------------------------

function Get-DriftReportModel {
    <#
        Normalizes either a single Compare-DiscoveryRunPair result or a whole
        Compare-DiscoveryFleetRuns result into ONE shape (ServerCount=1 for the single-server
        case) - the same "one model, multiple renderers" pattern every report in this repo
        already follows (Get-FleetRollupModel, Get-RbClientModel, ...), so the HTML and Markdown
        writers below can never drift apart from each other.
    #>
    param([Parameter(Mandatory)][object[]]$ServerResults, [string[]]$OnlyInBaseline = @(), [string[]]$OnlyInCurrent = @())
    $servers = [System.Collections.Generic.List[object]]::new()
    $totalAdded = 0; $totalRemoved = 0; $totalChanged = 0
    foreach ($s in @($ServerResults)) {
        $added = 0; $removed = 0; $changed = 0
        foreach ($dr in @($s.DatasetResults)) {
            if (-not $dr.Supported) { continue }
            $added   += @($dr.Added).Count
            $removed += @($dr.Removed).Count
            $changed += @($dr.Changed).Count
        }
        $clientSafe = Get-ClientSafeDriftSummary -DatasetResults $s.DatasetResults -DatasetVisibility $s.DatasetVisibility
        $servers.Add([pscustomobject]@{
            ComputerName      = $s.ComputerName
            BaselineRunId     = $s.BaselineRunId
            CurrentRunId      = $s.CurrentRunId
            BaselineTimestamp = $s.BaselineTimestamp
            CurrentTimestamp  = $s.CurrentTimestamp
            DatasetResults    = $s.DatasetResults
            ClientSafeSummary = $clientSafe
            TotalAdded = $added; TotalRemoved = $removed; TotalChanged = $changed
        })
        $totalAdded += $added; $totalRemoved += $removed; $totalChanged += $changed
    }
    return [pscustomobject]@{
        Generated      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        ServerCount    = $servers.Count
        Servers        = $servers.ToArray()
        OnlyInBaseline = @($OnlyInBaseline)
        OnlyInCurrent  = @($OnlyInCurrent)
        TotalAdded = $totalAdded; TotalRemoved = $totalRemoved; TotalChanged = $totalChanged
    }
}

#endregion

#region Reports -----------------------------------------------------------------

function Get-DriftReportCss {
    <# Same visual language as Get-FleetReportCss - kept local rather than shared, matching every other report format in this repo owning its own CSS. #>
    param([string]$AccentColorHex = '#1F4E79')
    if ([string]::IsNullOrWhiteSpace($AccentColorHex)) { $AccentColorHex = '#1F4E79' }
    $css = @'
:root{--accent:__ACCENT__;--bg:#ffffff;--surface:#F7F8FA;--fg:#1A1F27;--muted:#5B6472;--line:#E1E5EA;--add:#1A7F37;--add-bg:#E9F7EE;--rem:#B42318;--rem-bg:#FBEAE9;--chg:#B54708;--chg-bg:#FDF1E7}
*{box-sizing:border-box}body{font-family:Segoe UI,Calibri,Arial,sans-serif;color:var(--fg);background:var(--bg);margin:0;line-height:1.55;font-size:14px}
header{background:var(--accent);color:#fff;padding:28px 36px}header .brand-logo{max-height:40px;vertical-align:middle;margin-right:12px}header h1{margin:0 0 5px;font-size:22px;font-weight:600}header .sub{opacity:.9;font-size:13px}
main{max-width:1200px;margin:0 auto;padding:8px 36px 36px}
h2{color:var(--accent);border-bottom:2px solid var(--line);padding-bottom:7px;margin-top:38px;font-size:19px}
h3{color:#333;margin-top:20px;font-size:15px}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13px}
th,td{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{background:var(--surface);font-weight:600}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.kpi{flex:1;min-width:130px;border-radius:8px;padding:14px;text-align:center;background:var(--surface)}
.kpi .n{font-size:26px;font-weight:700;color:var(--accent)}.kpi .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-top:2px}
.muted{color:var(--muted);font-size:12px}
.tag{display:inline-block;padding:2px 9px;border-radius:100px;font-size:11px;font-weight:600}
.tag-add{background:var(--add-bg);color:var(--add)}.tag-rem{background:var(--rem-bg);color:var(--rem)}.tag-chg{background:var(--chg-bg);color:var(--chg)}
.skip{color:var(--muted);font-style:italic;font-size:12.5px;margin:4px 0}
@media print{header{background:#fff;color:var(--accent);border-bottom:3px solid var(--accent)}main{padding:0 8px}}
'@
    return ($css -replace '__ACCENT__', $AccentColorHex)
}

function Write-DriftHtmlReport {
    <# Full internal detail: every supported dataset's Added/Removed/Changed rows, per server. #>
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$Path)
    $esc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $b = Get-FleetBranding
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$html.AppendLine('<title>Discovery Drift Report</title>')
    [void]$html.AppendLine(('<style>{0}</style></head><body>' -f (Get-DriftReportCss -AccentColorHex $b.Accent)))
    [void]$html.AppendLine("<header>$(Get-FleetLogoHtml -Branding $b)<h1>Discovery Drift Report</h1>")
    [void]$html.AppendLine("<div class=`"sub`">$(& $esc $b.Brand) &middot; Generated $(& $esc $Model.Generated)</div></header><main>")

    [void]$html.AppendLine('<div class="kpis">')
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Servers compared</div></div>' -f $Model.ServerCount))
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Rows added</div></div>' -f $Model.TotalAdded))
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Rows removed</div></div>' -f $Model.TotalRemoved))
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Rows changed</div></div>' -f $Model.TotalChanged))
    [void]$html.AppendLine('</div>')

    if (@($Model.OnlyInBaseline).Count -gt 0) { [void]$html.AppendLine(('<p><span class="tag tag-rem">Baseline only</span> no longer in the current run: {0}</p>' -f (& $esc (@($Model.OnlyInBaseline) -join ', ')))) }
    if (@($Model.OnlyInCurrent).Count -gt 0)  { [void]$html.AppendLine(('<p><span class="tag tag-add">Current only</span> new since the baseline: {0}</p>' -f (& $esc (@($Model.OnlyInCurrent) -join ', ')))) }

    foreach ($s in $Model.Servers) {
        [void]$html.AppendLine(('<h2>{0}</h2>' -f (& $esc $s.ComputerName)))
        [void]$html.AppendLine(('<p class="muted">Baseline {0} ({1}) &middot; Current {2} ({3}) &middot; {4} added, {5} removed, {6} changed</p>' -f (& $esc $s.BaselineRunId), (& $esc $s.BaselineTimestamp), (& $esc $s.CurrentRunId), (& $esc $s.CurrentTimestamp), $s.TotalAdded, $s.TotalRemoved, $s.TotalChanged))
        foreach ($dr in $s.DatasetResults) {
            if (-not $dr.Supported) { continue }
            $dsAdded = @($dr.Added).Count; $dsRemoved = @($dr.Removed).Count; $dsChanged = @($dr.Changed).Count
            if ($dsAdded -eq 0 -and $dsRemoved -eq 0 -and $dsChanged -eq 0) { continue }
            [void]$html.AppendLine(('<h3>{0} <span class="tag tag-add">+{1}</span> <span class="tag tag-rem">-{2}</span> <span class="tag tag-chg">~{3}</span></h3>' -f (& $esc $dr.DatasetName), $dsAdded, $dsRemoved, $dsChanged))
            if ($dsAdded -gt 0)   { [void]$html.AppendLine('<p class="muted">Added</p>'); [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $dr.Added)) }
            if ($dsRemoved -gt 0) { [void]$html.AppendLine('<p class="muted">Removed</p>'); [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $dr.Removed)) }
            if ($dsChanged -gt 0) {
                [void]$html.AppendLine('<p class="muted">Changed</p>')
                $changeRows = @(foreach ($c in $dr.Changed) { foreach ($fld in $c.Fields) { [pscustomobject]@{ Key = $c.Key; Field = $fld.Field; Baseline = $fld.Baseline; Current = $fld.Current } } })
                [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $changeRows))
            }
        }
        $skipped = @($s.DatasetResults | Where-Object { -not $_.Supported })
        if ($skipped.Count -gt 0) {
            [void]$html.AppendLine('<p class="skip">Not compared (no known key or explicitly excluded): ')
            foreach ($sk in $skipped) { [void]$html.AppendLine(("{0} ({1}) " -f (& $esc $sk.DatasetName), (& $esc $sk.SkipReason))) }
            [void]$html.AppendLine('</p>')
        }
    }

    [void]$html.AppendLine('</main></body></html>')
    Set-Content -LiteralPath $Path -Value $html.ToString() -Encoding UTF8
}

function Write-DriftMarkdownReport {
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$Path)
    $b = Get-FleetBranding
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# Discovery Drift Report')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('**{0}** &middot; Generated {1}' -f $b.Brand, $Model.Generated))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('- Servers compared: {0}' -f $Model.ServerCount))
    [void]$sb.AppendLine(('- Rows added: {0} &middot; removed: {1} &middot; changed: {2}' -f $Model.TotalAdded, $Model.TotalRemoved, $Model.TotalChanged))
    if (@($Model.OnlyInBaseline).Count -gt 0) { [void]$sb.AppendLine(('- Baseline only (no longer present): {0}' -f (@($Model.OnlyInBaseline) -join ', '))) }
    if (@($Model.OnlyInCurrent).Count -gt 0)  { [void]$sb.AppendLine(('- Current only (new since baseline): {0}' -f (@($Model.OnlyInCurrent) -join ', '))) }
    [void]$sb.AppendLine('')

    foreach ($s in $Model.Servers) {
        [void]$sb.AppendLine(('## {0}' -f $s.ComputerName))
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(('Baseline {0} ({1}) &middot; Current {2} ({3}) &middot; {4} added, {5} removed, {6} changed' -f $s.BaselineRunId, $s.BaselineTimestamp, $s.CurrentRunId, $s.CurrentTimestamp, $s.TotalAdded, $s.TotalRemoved, $s.TotalChanged))
        [void]$sb.AppendLine('')
        foreach ($dr in $s.DatasetResults) {
            if (-not $dr.Supported) { continue }
            $dsAdded = @($dr.Added).Count; $dsRemoved = @($dr.Removed).Count; $dsChanged = @($dr.Changed).Count
            if ($dsAdded -eq 0 -and $dsRemoved -eq 0 -and $dsChanged -eq 0) { continue }
            [void]$sb.AppendLine(('### {0} (+{1} -{2} ~{3})' -f $dr.DatasetName, $dsAdded, $dsRemoved, $dsChanged))
            [void]$sb.AppendLine('')
            if ($dsAdded -gt 0)   { [void]$sb.AppendLine('**Added**'); [void]$sb.AppendLine(''); [void]$sb.AppendLine((ConvertTo-FleetMarkdownTable -Rows $dr.Added)); [void]$sb.AppendLine('') }
            if ($dsRemoved -gt 0) { [void]$sb.AppendLine('**Removed**'); [void]$sb.AppendLine(''); [void]$sb.AppendLine((ConvertTo-FleetMarkdownTable -Rows $dr.Removed)); [void]$sb.AppendLine('') }
            if ($dsChanged -gt 0) {
                [void]$sb.AppendLine('**Changed**')
                [void]$sb.AppendLine('')
                $changeRows = @(foreach ($c in $dr.Changed) { foreach ($fld in $c.Fields) { [pscustomobject]@{ Key = $c.Key; Field = $fld.Field; Baseline = $fld.Baseline; Current = $fld.Current } } })
                [void]$sb.AppendLine((ConvertTo-FleetMarkdownTable -Rows $changeRows))
                [void]$sb.AppendLine('')
            }
        }
    }
    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}

function Write-DriftClientHtmlReport {
    <# Client-safe: generic counts only, only for ClientSafe/Both datasets - see Get-ClientSafeDriftSummary. #>
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$Path)
    $esc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $b = Get-FleetBranding
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$html.AppendLine('<title>Discovery Changes Summary</title>')
    [void]$html.AppendLine(('<style>{0}</style></head><body>' -f (Get-DriftReportCss -AccentColorHex $b.Accent)))
    [void]$html.AppendLine("<header>$(Get-FleetLogoHtml -Branding $b)<h1>Discovery Changes Summary</h1>")
    [void]$html.AppendLine("<div class=`"sub`">$(& $esc $b.Brand) &middot; {0} server(s) compared &middot; $(& $esc $Model.Generated)</div></header><main>" -f $Model.ServerCount)
    [void]$html.AppendLine('<p class="lead">A read-only comparison against the last time we reviewed these servers. Nothing was changed by this comparison itself - this only reports what each server now reports about itself versus last time.</p>')

    $anyRows = $false
    foreach ($s in $Model.Servers) {
        if (@($s.ClientSafeSummary).Count -eq 0) { continue }
        $anyRows = $true
        [void]$html.AppendLine(('<h2>{0}</h2><table><tr><th>Area</th><th>What changed</th></tr>' -f (& $esc $s.ComputerName)))
        foreach ($row in $s.ClientSafeSummary) {
            [void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $esc $row.DatasetName), (& $esc $row.Label)))
        }
        [void]$html.AppendLine('</table>')
    }
    if (-not $anyRows) { [void]$html.AppendLine('<p>No client-visible changes were detected between these two reviews.</p>') }

    [void]$html.AppendLine('</main></body></html>')
    Set-Content -LiteralPath $Path -Value $html.ToString() -Encoding UTF8
}

function Write-DriftClientMarkdownReport {
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$Path)
    $b = Get-FleetBranding
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# Discovery Changes Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('**{0}** &middot; {1} server(s) compared &middot; {2}' -f $b.Brand, $Model.ServerCount, $Model.Generated))
    [void]$sb.AppendLine('')
    $anyRows = $false
    foreach ($s in $Model.Servers) {
        if (@($s.ClientSafeSummary).Count -eq 0) { continue }
        $anyRows = $true
        [void]$sb.AppendLine(('## {0}' -f $s.ComputerName))
        [void]$sb.AppendLine('')
        foreach ($row in $s.ClientSafeSummary) { [void]$sb.AppendLine(('- **{0}:** {1}' -f $row.DatasetName, $row.Label)) }
        [void]$sb.AppendLine('')
    }
    if (-not $anyRows) { [void]$sb.AppendLine('_No client-visible changes were detected between these two reviews._') }
    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}

function New-DriftReport {
    <# Single public entry point - mirrors New-FleetRollupReport's role. Builds the model once, writes all five output files from it. #>
    [CmdletBinding(DefaultParameterSetName = 'SingleServer')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'SingleServer')][string]$BaselineRunFolder,
        [Parameter(Mandatory, ParameterSetName = 'SingleServer')][string]$CurrentRunFolder,
        [Parameter(Mandatory, ParameterSetName = 'Fleet')][string]$BaselineEngagementFolder,
        [Parameter(Mandatory, ParameterSetName = 'Fleet')][string]$CurrentEngagementFolder,
        [string]$OutputPath
    )
    if ($PSCmdlet.ParameterSetName -eq 'SingleServer') {
        $pairResult = Compare-DiscoveryRunPair -BaselineRunFolder $BaselineRunFolder -CurrentRunFolder $CurrentRunFolder
        $model = Get-DriftReportModel -ServerResults @($pairResult)
        if (-not $OutputPath) { $OutputPath = Join-Path $CurrentRunFolder 'drift' }
    } else {
        $fleetResult = Compare-DiscoveryFleetRuns -BaselineEngagementFolder $BaselineEngagementFolder -CurrentEngagementFolder $CurrentEngagementFolder
        $model = Get-DriftReportModel -ServerResults $fleetResult.ServerResults -OnlyInBaseline $fleetResult.OnlyInBaseline -OnlyInCurrent $fleetResult.OnlyInCurrent
        if (-not $OutputPath) { $OutputPath = Join-Path $CurrentEngagementFolder 'drift' }
    }
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

    $jsonPath       = Join-Path $OutputPath 'drift-report.json'
    $htmlPath       = Join-Path $OutputPath 'drift-report.html'
    $mdPath         = Join-Path $OutputPath 'drift-report.md'
    $clientHtmlPath = Join-Path $OutputPath 'drift-client-summary.html'
    $clientMdPath   = Join-Path $OutputPath 'drift-client-summary.md'

    ($model | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-DriftHtmlReport -Model $model -Path $htmlPath
    Write-DriftMarkdownReport -Model $model -Path $mdPath
    Write-DriftClientHtmlReport -Model $model -Path $clientHtmlPath
    Write-DriftClientMarkdownReport -Model $model -Path $clientMdPath

    return [pscustomobject]@{
        JsonPath = $jsonPath; HtmlPath = $htmlPath; MarkdownPath = $mdPath
        ClientHtmlPath = $clientHtmlPath; ClientMarkdownPath = $clientMdPath
        ServerCount = $model.ServerCount; TotalAdded = $model.TotalAdded; TotalRemoved = $model.TotalRemoved; TotalChanged = $model.TotalChanged
    }
}

#endregion

# Only runs when executed directly - dot-source for the functions above (Pester, or the GUI
# calling New-DriftReport in-process), same convention as every other file in tools\.
if ($MyInvocation.InvocationName -ne '.') {
    if ($BaselineRunFolder -and $CurrentRunFolder) {
        $report = New-DriftReport -BaselineRunFolder $BaselineRunFolder -CurrentRunFolder $CurrentRunFolder -OutputPath $OutputPath
    } elseif ($BaselineEngagementFolder -and $CurrentEngagementFolder) {
        $report = New-DriftReport -BaselineEngagementFolder $BaselineEngagementFolder -CurrentEngagementFolder $CurrentEngagementFolder -OutputPath $OutputPath
    } else {
        throw 'Provide either -BaselineRunFolder/-CurrentRunFolder or -BaselineEngagementFolder/-CurrentEngagementFolder.'
    }
    Write-Host ("Drift report built: {0} server(s), +{1} -{2} ~{3} -> {4}" -f $report.ServerCount, $report.TotalAdded, $report.TotalRemoved, $report.TotalChanged, $report.HtmlPath) -ForegroundColor Green
}
