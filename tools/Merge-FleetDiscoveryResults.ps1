<#
.SYNOPSIS
    Merges N completed Discover-WindowsServer runs (pulled back by tools\Invoke-FleetDiscovery.ps1,
    or gathered any other way) into one fleet-level rollup: a combined risk register plus a
    simple per-server summary, instead of N separate report folders.

.DESCRIPTION
    Operates entirely on already-finished run output folders - it never runs the engine, never
    touches a remote machine, and never mutates anything under an individual run's own evidence\
    folder. Point it at an "engagement folder" containing one or more
    Discover-WindowsServer_<ComputerName>_<timestamp>\ subfolders (exactly what
    Invoke-FleetDiscovery.ps1 produces, one per target it ran against) and it reads each run's
    evidence\collection-metadata.json (for identity) and evidence\data\json\<Dataset>.json files
    (for content), stamps ComputerName/RunId onto every row (individual dataset rows don't carry
    that themselves - see New-DiscoveryDataset in modules\Core\Core.psm1), and concatenates.

    "Migration wave grouping" below is a deliberately modest heuristic, not a dependency-graph
    solver: it surfaces findings that share the same Category AND Subject (a cluster name, an AD
    domain, a SQL instance - see Core.psm1's own comment on Subject being "the row's primary
    identifier") across 2+ different servers, as something for a human to look at and confirm -
    not an automated answer to "what moves together."

.PARAMETER EngagementFolder
    Folder containing one or more Discover-WindowsServer_<ComputerName>_<timestamp>\ run outputs.

.PARAMETER OutputPath
    Where the rollup files land. Defaults to <EngagementFolder>\rollup\.

.EXAMPLE
    .\tools\Merge-FleetDiscoveryResults.ps1 -EngagementFolder 'C:\Temp\FleetRuns\Acme_20260925'
#>
[CmdletBinding()]
param(
    [string]$EngagementFolder,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

#region Reading completed runs ---------------------------------------------------

function Get-FleetRunFolder {
    <# Every Discover-WindowsServer_<ComputerName>_<timestamp> subfolder directly under the engagement folder - not fleet-status\ or rollup\, which live alongside them. #>
    param([Parameter(Mandatory)][string]$EngagementFolder)
    if (-not (Test-Path -LiteralPath $EngagementFolder)) { return ,@() }
    return ,@(Get-ChildItem -LiteralPath $EngagementFolder -Directory -Filter 'Discover-WindowsServer_*' -ErrorAction SilentlyContinue)
}

function Get-FleetRunMetadata {
    <# Reads one run's evidence\collection-metadata.json. $null if missing/unreadable - a partial/failed pull-back shouldn't crash the whole rollup. #>
    param([Parameter(Mandatory)][string]$RunFolder)
    $path = Join-Path $RunFolder 'evidence\collection-metadata.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Get-FleetRunOutcome {
    <#
        Reads Invoke-FleetDiscovery.ps1's own fleet-run-results.json (one entry per target it was
        asked to run, win or lose) from the engagement folder root. This is the ONLY record of a
        target that never produced a Discover-WindowsServer_* folder at all - a real gap this
        caught: a rollup built purely from successful folders silently dropped every
        Unreachable/Failed/TimedOut target with no mention anywhere, making a 4-of-7-failed run
        look identical to "only 3 servers were ever asked for." Returns an empty array (not $null)
        if the file is missing or unreadable, so a rollup built from manually-gathered folders
        (no Invoke-FleetDiscovery.ps1 run behind them at all) still works.
    #>
    param([Parameter(Mandatory)][string]$EngagementFolder)
    $path = Join-Path $EngagementFolder 'fleet-run-results.json'
    if (-not (Test-Path -LiteralPath $path)) { return ,@() }
    # Assign BEFORE wrapping - see Output.Tests.ps1's note on the same gotcha: Windows
    # PowerShell 5.1's ConvertFrom-Json emits a JSON array as ONE pipeline object (PS6+
    # enumerates it), so @(...) around the pipeline expression directly would wrap that
    # single array-object into a 1-element outer array on 5.1 - collapsing every non-
    # Succeeded target's real entry into one opaque blob whose properties then broadcast as
    # arrays (a real bug hit live: -LiteralPath got handed a whole array with a $null in it,
    # not one string, once a target had failed with LocalResultPath = $null).
    try {
        $parsed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        return ,@($parsed)
    } catch { return ,@() }
}

function Add-FleetRowStamp {
    <#
        Pure: stamps ComputerName/RunId/Mode onto a set of already-loaded dataset rows. Split
        out from Merge-FleetDataset so the actual stamping logic is testable with plain fixture
        objects, no files involved.
    #>
    param(
        [object[]]$Rows = @(),
        [Parameter(Mandatory)][string]$ComputerName,
        [string]$RunId = '',
        [string]$Mode = ''
    )
    return ,@(foreach ($row in @($Rows)) {
        $stamped = [ordered]@{ ComputerName = $ComputerName; RunId = $RunId; Mode = $Mode }
        foreach ($prop in $row.PSObject.Properties) { $stamped[$prop.Name] = $prop.Value }
        [pscustomobject]$stamped
    })
}

function Merge-FleetDataset {
    <# Reads <DatasetName>.json from every completed run under the engagement folder and concatenates the stamped rows. Missing datasets on a given run (a module that found nothing, or wasn't included) are silently skipped for that run only. #>
    param(
        [Parameter(Mandatory)][string]$EngagementFolder,
        [Parameter(Mandatory)][string]$DatasetName
    )
    $allRows = [System.Collections.Generic.List[object]]::new()
    foreach ($runDir in (Get-FleetRunFolder -EngagementFolder $EngagementFolder)) {
        $meta = Get-FleetRunMetadata -RunFolder $runDir.FullName
        $computerName = if ($meta) { $meta.ComputerName } else { $runDir.Name }
        $runId = if ($meta) { $meta.RunId } else { '' }
        $mode = if ($meta) { $meta.Mode } else { '' }
        $dataPath = Join-Path $runDir.FullName ("evidence\data\json\{0}.json" -f $DatasetName)
        if (-not (Test-Path -LiteralPath $dataPath)) { continue }
        # Assign BEFORE wrapping - see Get-FleetRunOutcome's comment above for why @() around
        # the pipeline expression directly silently collapses every dataset to a single nested
        # blob under Windows PowerShell 5.1.
        try {
            $parsed = Get-Content -LiteralPath $dataPath -Raw | ConvertFrom-Json
            $rows = @($parsed)
        } catch { continue }
        foreach ($stamped in (Add-FleetRowStamp -Rows $rows -ComputerName $computerName -RunId $runId -Mode $mode)) { $allRows.Add($stamped) }
    }
    # Deliberately NOT ,@($allRows) - almost every caller in this file either wraps this call
    # in @(...) directly or pipes it straight into Where-Object/ForEach-Object without an
    # intermediate variable first. A ,@()-wrapped return is exactly one pipeline object (the
    # whole array as a single item), which is correct for a bare `$x = Merge-FleetDataset ...`
    # assignment but silently collapses every downstream `@(Merge-FleetDataset ... | Where...)`
    # or `@(Merge-FleetDataset ...)` call into ONE blob row whose properties are the space-
    # joined values of every real row (confirmed live: Get-FleetClientModel's Shares/Applications/
    # Printers/Vendors/HybridIdentity tables in a real fleet run's client summary). Returning the
    # plain array lets it stream onto the pipeline naturally - 0, 1, or N discrete objects - which
    # every one of those calling conventions handles correctly, including the two callers here
    # that still do a bare assignment (they immediately re-pipe the result rather than indexing
    # it directly, so the scalar-vs-array difference for N=1 never matters to them).
    return $allRows.ToArray()
}

#endregion

#region Risk register + dependency hints -----------------------------------------

function Get-SeverityRank {
    <# Pure: Critical sorts first. Anything unrecognized sorts last rather than erroring. #>
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 5 }
        'High'     { 4 }
        'Medium'   { 3 }
        'Low'      { 2 }
        'Info'     { 1 }
        default    { 0 }
    }
}

function Get-FleetRiskRegister {
    <# The 'ScopingRisks' dataset (every finding - see Build-ContextListDatasets in Discover-WindowsServer.psm1) merged across every run, sorted worst-first. #>
    param([Parameter(Mandatory)][string]$EngagementFolder)
    $rows = Merge-FleetDataset -EngagementFolder $EngagementFolder -DatasetName 'ScopingRisks'
    return ,@($rows | Sort-Object -Property @{ Expression = { Get-SeverityRank $_.Severity }; Descending = $true }, ComputerName)
}

function Get-FleetDependencyHint {
    <#
        Pure heuristic, not a dependency-graph solver: groups findings that share the same
        Category AND Subject (a cluster name, an AD domain, a SQL instance name - Subject is
        each finding's own primary identifier, see New-DiscoveryFinding in Core.psm1) across 2
        or more distinct servers. Surfaced as a suggestion for a human to confirm before treating
        any two servers as a migration-wave unit - this does not claim to know real dependencies.
    #>
    param([object[]]$FindingRows = @())
    $groups = @($FindingRows) | Where-Object { $_.Subject } | Group-Object -Property Category, Subject
    return ,@($groups | Where-Object { (@($_.Group.ComputerName | Select-Object -Unique)).Count -ge 2 } | ForEach-Object {
        $computerNames = @($_.Group.ComputerName | Select-Object -Unique | Sort-Object)
        [pscustomobject]@{
            SuggestedGroupLabel = '{0}: {1}' -f $_.Group[0].Category, $_.Group[0].Subject
            ComputerNames       = $computerNames
            Rationale           = 'These servers each have a finding in the same category referencing the same subject - worth confirming whether they need to move together.'
            BasisFindingIds     = @($_.Group.FindingId | Select-Object -Unique)
        }
    })
}

#endregion

#region Rollup report -------------------------------------------------------------

function Get-FleetFolderSummary {
    param([Parameter(Mandatory)]$RunDir)
    $meta = Get-FleetRunMetadata -RunFolder $RunDir.FullName
    if (-not $meta) { return [pscustomobject]@{ ComputerName = $RunDir.Name; Mode = ''; FindingCount = 0; Status = 'Succeeded'; ErrorMessage = 'No collection-metadata.json found in this folder.'; ReadinessGrade = ''; ReadinessScore = $null } }
    $riskCount = @($meta.Datasets | Where-Object { $_.Name -eq 'ScopingRisks' } | Select-Object -First 1).Rows
    # Read directly rather than via Merge-FleetDataset (which merges across the WHOLE engagement
    # folder) - this function only ever looks at one run folder at a time.
    $readinessGrade = ''
    $readinessScoreValue = $null
    $readinessPath = Join-Path $RunDir.FullName 'evidence\data\json\ReadinessScore.json'
    if (Test-Path -LiteralPath $readinessPath) {
        try {
            $parsed = Get-Content -LiteralPath $readinessPath -Raw | ConvertFrom-Json
            $readinessRow = @($parsed) | Select-Object -First 1
            if ($readinessRow) { $readinessGrade = [string]$readinessRow.Grade; $readinessScoreValue = $readinessRow.Score }
        } catch { }
    }
    [pscustomobject]@{ ComputerName = $meta.ComputerName; Mode = $meta.Mode; FindingCount = $riskCount; Status = 'Succeeded'; ErrorMessage = ''; ReadinessGrade = $readinessGrade; ReadinessScore = $readinessScoreValue }
}

function Get-FleetRollupModel {
    <#
        Single source of truth for what the fleet rollup contains, computed once so the
        printable rollup report and the Command Center dashboard can never show different data
        for the same engagement - same reasoning as Get-InternalReportModel in Output.psm1 for
        the single-server reports.
    #>
    param([Parameter(Mandatory)][string]$EngagementFolder)

    $runFolders = Get-FleetRunFolder -EngagementFolder $EngagementFolder
    $outcomes = Get-FleetRunOutcome -EngagementFolder $EngagementFolder

    # fleet-run-results.json (when present) is authoritative: one row per target
    # Invoke-FleetDiscovery.ps1 was ever ASKED to run, win or lose. Without this, a rollup built
    # purely from successful Discover-WindowsServer_* folders silently dropped every
    # Unreachable/Failed/TimedOut target with no mention anywhere - a real 4-of-7-failed run
    # looked identical to "only 3 servers were ever requested." Falls back to folder-only (the
    # old behavior) when there's no results file to read - e.g. folders gathered by hand rather
    # than through a real fleet run.
    $serverSummaries = @(if (@($outcomes).Count -gt 0) {
        foreach ($o in $outcomes) {
            if ($o.Status -eq 'Succeeded' -and $o.LocalResultPath -and (Test-Path -LiteralPath $o.LocalResultPath)) {
                Get-FleetFolderSummary -RunDir (Get-Item -LiteralPath $o.LocalResultPath)
            } else {
                [pscustomobject]@{ ComputerName = $o.ComputerName; Mode = ''; FindingCount = 0; Status = [string]$o.Status; ErrorMessage = [string]$o.ErrorMessage; ReadinessGrade = ''; ReadinessScore = $null }
            }
        }
    } else {
        foreach ($runDir in $runFolders) { Get-FleetFolderSummary -RunDir $runDir }
    })

    $riskRegister = Get-FleetRiskRegister -EngagementFolder $EngagementFolder
    $counts = @{}
    foreach ($s in @('Critical','High','Medium','Low','Info')) { $counts[$s] = @($riskRegister | Where-Object { $_.Severity -eq $s }).Count }

    $scoredServers = @($serverSummaries | Where-Object { $null -ne $_.ReadinessScore })
    $fleetAverageReadiness = if ($scoredServers.Count -gt 0) { [Math]::Round(($scoredServers | Measure-Object -Property ReadinessScore -Average).Average) } else { $null }

    [pscustomobject]@{
        ServerSummaries       = $serverSummaries
        ServerCount           = @($serverSummaries).Count
        SucceededServerCount  = @($serverSummaries | Where-Object { $_.Status -eq 'Succeeded' }).Count
        RiskRegister          = $riskRegister
        Counts                = $counts
        DependencyHints       = @(Get-FleetDependencyHint -FindingRows $riskRegister)
        DecommissionReadiness = @(Merge-FleetDataset -EngagementFolder $EngagementFolder -DatasetName 'DecommissionReadiness')
        ScopeAssumptions      = @(Merge-FleetDataset -EngagementFolder $EngagementFolder -DatasetName 'ScopeAssumptions')
        ScopeExclusions       = @(Merge-FleetDataset -EngagementFolder $EngagementFolder -DatasetName 'ScopeExclusions')
        FleetAverageReadiness = $fleetAverageReadiness
        DependencyEdges       = @(Merge-FleetDataset -EngagementFolder $EngagementFolder -DatasetName 'DependencyGraph')
    }
}

function Get-FleetReportCss {
    <# Printable rollup: same visual language as Output.psm1's internal-engineering-report.html (KPI tiles, a colored left stripe per finding severity) so the two report families read as one product. Self-contained here rather than shared, matching this repo's convention of each report format owning its own CSS (ReportBuilder.psm1's client report does the same). #>
    param([string]$AccentColorHex = '#1F4E79')
    if ([string]::IsNullOrWhiteSpace($AccentColorHex)) { $AccentColorHex = '#1F4E79' }
    $css = @'
:root{--accent:__ACCENT__;--bg:#ffffff;--surface:#F7F8FA;--fg:#1A1F27;--muted:#5B6472;--line:#E1E5EA;
--critical:#B42318;--critical-bg:#FBEAE9;--high:#B54708;--high-bg:#FDF1E7;--medium:#4A5B79;--medium-bg:#EBEEF4;--low:#5B6472;--low-bg:#EEF0F3;--info:#5B6472;--info-bg:#EEF0F3}
*{box-sizing:border-box}body{font-family:Segoe UI,Calibri,Arial,sans-serif;color:var(--fg);background:var(--bg);margin:0;line-height:1.55;font-size:14px}
header{background:var(--accent);color:#fff;padding:28px 36px}header h1{margin:0 0 5px;font-size:22px;font-weight:600}header .sub{opacity:.9;font-size:13px}
header .brand-logo{max-height:40px;vertical-align:middle;margin-right:12px}
main{max-width:1200px;margin:0 auto;padding:8px 36px 36px}
h2{color:var(--accent);border-bottom:2px solid var(--line);padding-bottom:7px;margin-top:38px;font-size:19px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
th,td{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{background:var(--surface);font-weight:600}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.kpi{flex:1;min-width:130px;border-radius:8px;padding:14px;text-align:center;background:var(--surface)}
.kpi .n{font-size:26px;font-weight:700;color:var(--accent);word-break:break-word}.kpi .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-top:2px}
.muted{color:var(--muted);font-size:12px}
.dep-diagram{overflow-x:auto;border:1px solid var(--line);border-radius:8px;padding:8px;background:#fff;margin-bottom:16px}
.card{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:0 8px 8px 0;padding:12px 16px;margin:10px 0;background:#fff}
.card.sev-Critical{border-left-color:var(--critical);background:var(--critical-bg)}
.card.sev-High{border-left-color:var(--high);background:var(--high-bg)}
.card.sev-Medium{border-left-color:var(--medium);background:var(--medium-bg)}
.card.sev-Low{border-left-color:var(--low);background:var(--low-bg)}
.card.sev-Info{border-left-color:var(--info);background:var(--info-bg)}
.badge{display:inline-block;padding:2px 9px;border-radius:100px;font-size:11px;font-weight:600}
.sev-Critical .badge.sevbadge{background:var(--critical);color:#fff}
.sev-High .badge.sevbadge{background:var(--high);color:#fff}
.sev-Medium .badge.sevbadge{background:var(--medium);color:#fff}
.sev-Low .badge.sevbadge{background:var(--low);color:#fff}
.sev-Info .badge.sevbadge{background:var(--info);color:#fff}
.status-bad td{color:var(--critical)}
code{background:var(--surface);padding:1px 4px;border-radius:3px;font-size:12px;font-family:Consolas,"Cascadia Code",monospace}
@media print{header{background:#fff;color:var(--accent);border-bottom:3px solid var(--accent)}main{padding:0 8px}.card{break-inside:avoid}}
'@
    return ($css -replace '__ACCENT__', $AccentColorHex)
}

function Get-FleetDashboardCss {
    <# Command Center layout, identical structure/behavior to Output.psm1's Get-DashboardReportCss for the single-server dashboard - sidebar nav, per-section panes, scrollable/filterable tables - kept visually consistent across both report families. #>
    param([string]$AccentColorHex = '#1F4E79')
    if ([string]::IsNullOrWhiteSpace($AccentColorHex)) { $AccentColorHex = '#1F4E79' }
    $css = @'
:root{--accent:__ACCENT__;--accent-bg:#EAF1F8;--accent-text:#123350;--bg:#ffffff;--surface:#F5F6F8;--surface-2:#ECEEF1;--fg:#1A1F27;--muted:#5B6472;--line:#DFE3E8;--line-strong:#C6CCD4;
--critical:#B42318;--critical-bg:#FBEAE9;--high:#B54708;--high-bg:#FDF1E7;--medium:#4A5B79;--medium-bg:#EBEEF4;--low:#5B6472;--low-bg:#EEF0F3}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;font-family:Segoe UI,Calibri,Arial,sans-serif;color:var(--fg);background:var(--bg);font-size:14px}
.shell{display:grid;grid-template-columns:230px 1fr;height:100vh}
.side{background:var(--surface);border-right:1px solid var(--line);padding:16px 10px;overflow-y:auto}
.side h1{font-size:14px;font-weight:600;margin:2px 8px 2px;color:var(--accent)}
.side .brand-logo{max-height:28px;display:block;margin:2px 8px 8px}
.side .sub{font-size:11px;color:var(--muted);margin:0 8px 14px}
.side .grp{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:14px 8px 6px}
.side a{display:flex;justify-content:space-between;gap:6px;padding:7px 8px;border-radius:6px;color:#333;text-decoration:none;font-size:13px;cursor:pointer}
.side a:hover{background:var(--surface-2)}
.side a.sel{background:var(--accent-bg);color:var(--accent-text);font-weight:600}
.side a .n{font-size:11px;color:var(--muted)}
.side a.sel .n{color:var(--accent-text)}
.main{padding:20px 26px;overflow-y:auto}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.kpi{background:var(--surface);border-radius:8px;padding:12px 14px;text-align:center}
.kpi .n{font-size:22px;font-weight:700;color:var(--accent);word-break:break-word}
.kpi .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-top:2px}
.dep-diagram{overflow-x:auto;border:1px solid var(--line);border-radius:8px;padding:8px;background:#fff;margin-bottom:16px}
.pane{display:none}
.pane.active{display:block}
.pane h2{font-size:17px;margin:0 0 4px;color:var(--accent)}
.pane .pd{font-size:12.5px;color:var(--muted);margin:0 0 12px}
.filterrow{margin-bottom:8px}
.filterrow input{width:100%;max-width:360px;font-family:inherit;font-size:13px;padding:7px 10px;border:1px solid var(--line-strong);border-radius:6px;background:#fff;color:var(--fg)}
.tablebox{border:1px solid var(--line);border-radius:8px;max-height:60vh;overflow:auto}
table{border-collapse:collapse;width:100%;font-size:12.5px}
thead th{position:sticky;top:0;background:var(--surface);text-align:left;padding:8px 10px;font-weight:600;border-bottom:1px solid var(--line)}
tbody td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr.hide{display:none}
tr.status-bad td{color:var(--critical)}
.card{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:0 8px 8px 0;padding:10px 14px;margin:8px 0;background:#fff}
.card.sev-Critical{border-left-color:var(--critical);background:var(--critical-bg)}
.card.sev-High{border-left-color:var(--high);background:var(--high-bg)}
.card.sev-Medium{border-left-color:var(--medium);background:var(--medium-bg)}
.card.sev-Low,.card.sev-Info{border-left-color:var(--low);background:var(--low-bg)}
.badge{display:inline-block;padding:2px 9px;border-radius:100px;font-size:11px;font-weight:600}
.sev-Critical .badge.sevbadge{background:var(--critical);color:#fff}
.sev-High .badge.sevbadge{background:var(--high);color:#fff}
.sev-Medium .badge.sevbadge{background:var(--medium);color:#fff}
.sev-Low .badge.sevbadge,.sev-Info .badge.sevbadge{background:var(--low);color:#fff}
.muted{color:var(--muted);font-size:12px}
code{background:var(--surface);padding:1px 4px;border-radius:3px;font-size:12px;font-family:Consolas,"Cascadia Code",monospace}
@media (max-width:820px){.shell{grid-template-columns:1fr}.side{display:none}}
'@
    return ($css -replace '__ACCENT__', $AccentColorHex)
}

function Write-FleetRollupHtml {
    <# Printable rollup: reads start to finish like the single-server internal-engineering-report.html - one linear, print-friendly page. See Write-FleetDashboardReport for the interactive companion. #>
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$EngagementFolder, [Parameter(Mandatory)][string]$Path)
    $esc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $b = Get-FleetBranding
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$html.AppendLine('<title>Fleet Discovery Rollup</title>')
    [void]$html.AppendLine(('<style>{0}</style></head><body>' -f (Get-FleetReportCss -AccentColorHex $b.Accent)))
    [void]$html.AppendLine("<header>$(Get-FleetLogoHtml -Branding $b)<h1>Fleet Discovery Rollup</h1>")
    [void]$html.AppendLine("<div class=`"sub`">$(& $esc $b.Brand) &middot; Generated $(& $esc (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) &middot; $(& $esc $EngagementFolder)</div></header><main>")

    [void]$html.AppendLine('<div class="kpis">')
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}/{1}</div><div class="l">Servers succeeded</div></div>' -f $Model.SucceededServerCount, $Model.ServerCount))
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Findings</div></div>' -f @($Model.RiskRegister).Count))
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Critical/High</div></div>' -f ($Model.Counts['Critical'] + $Model.Counts['High'])))
    [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Migration-wave groupings</div></div>' -f @($Model.DependencyHints).Count))
    if ($null -ne $Model.FleetAverageReadiness) {
        [void]$html.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Avg. readiness score</div></div>' -f $Model.FleetAverageReadiness))
    }
    [void]$html.AppendLine('</div>')

    [void]$html.AppendLine('<h2>Servers</h2><table><tr><th>Computer</th><th>Status</th><th>Mode</th><th>Findings</th><th>Readiness</th><th>Details</th></tr>')
    foreach ($s in $Model.ServerSummaries) {
        $rowClass = if ($s.Status -ne 'Succeeded') { ' class="status-bad"' } else { '' }
        $readinessCell = if ($s.ReadinessGrade) { "$($s.ReadinessGrade) ($($s.ReadinessScore))" } else { '' }
        [void]$html.AppendLine("<tr$rowClass><td>$(& $esc $s.ComputerName)</td><td>$(& $esc $s.Status)</td><td>$(& $esc $s.Mode)</td><td>$(& $esc $s.FindingCount)</td><td>$(& $esc $readinessCell)</td><td>$(& $esc $s.ErrorMessage)</td></tr>")
    }
    [void]$html.AppendLine('</table>')

    # Per-server, never fleet-wide - see Get-FleetDependencyDiagramSvg's own comment for why a
    # combined diagram across servers would be misleading given Target is free text.
    $anyDiagram = $false
    $diagramSectionHtml = [System.Text.StringBuilder]::new()
    foreach ($s in ($Model.ServerSummaries | Where-Object { $_.Status -eq 'Succeeded' })) {
        $serverEdges = @($Model.DependencyEdges | Where-Object { $_.ComputerName -eq $s.ComputerName })
        $svg = Get-FleetDependencyDiagramSvg -Edges $serverEdges
        if (-not $svg) { continue }
        $anyDiagram = $true
        [void]$diagramSectionHtml.AppendLine(("<h3>{0}</h3>" -f (& $esc $s.ComputerName)))
        [void]$diagramSectionHtml.AppendLine(('<div class="dep-diagram">{0}</div>' -f $svg))
    }
    if ($anyDiagram) {
        [void]$html.AppendLine('<h2>Dependency Diagrams</h2>')
        [void]$html.AppendLine('<p class="muted">One diagram per server - never combined across servers, since a shared Target value (an IP, a path) does not necessarily mean two servers reference the same underlying resource.</p>')
        [void]$html.AppendLine($diagramSectionHtml.ToString())
    }

    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $group = @($Model.RiskRegister | Where-Object { $_.Severity -eq $sev })
        if ($group.Count -eq 0) { continue }
        [void]$html.AppendLine(('<h2>{0}-severity findings ({1})</h2>' -f $sev, $group.Count))
        foreach ($f in $group) {
            [void]$html.AppendLine(('<div class="card sev-{0}">' -f $f.Severity))
            [void]$html.AppendLine(('<div><span class="badge sevbadge">{0}</span> <b>{1}</b> <span class="muted">{2} &middot; {3}</span></div>' -f $f.Severity, (& $esc $f.Title), (& $esc $f.ComputerName), (& $esc $f.Category)))
            if ($f.Evidence) { [void]$html.AppendLine(('<div><b>Evidence:</b> {0}</div>' -f (& $esc $f.Evidence))) }
            [void]$html.AppendLine('</div>')
        }
    }

    [void]$html.AppendLine('<h2>Possible migration-wave groupings (confirm before relying on these)</h2>')
    if (@($Model.DependencyHints).Count -eq 0) {
        [void]$html.AppendLine('<p class="muted">No cross-server groupings suggested by this heuristic.</p>')
    } else {
        [void]$html.AppendLine('<table><tr><th>Group</th><th>Servers</th><th>Why</th></tr>')
        foreach ($g in $Model.DependencyHints) { [void]$html.AppendLine("<tr><td>$(& $esc $g.SuggestedGroupLabel)</td><td>$(& $esc ($g.ComputerNames -join ', '))</td><td>$(& $esc $g.Rationale)</td></tr>") }
        [void]$html.AppendLine('</table>')
    }

    foreach ($section in @(
        @{ Title = 'Decommission readiness (all servers)'; Rows = $Model.DecommissionReadiness }
        @{ Title = 'Scope assumptions (all servers)'; Rows = $Model.ScopeAssumptions }
        @{ Title = 'Scope exclusions (all servers)'; Rows = $Model.ScopeExclusions }
    )) {
        if (@($section.Rows).Count -eq 0) { continue }
        [void]$html.AppendLine(('<h2>{0}</h2>' -f $section.Title))
        [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $section.Rows))
    }

    [void]$html.AppendLine('</main></body></html>')
    $html.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force
}

function ConvertTo-FleetHtmlTable {
    <# Same shape as Output.psm1's ConvertTo-HtmlTable, kept local so this script has no hard dependency on that module. #>
    param([AllowNull()]$Rows)
    $rowArray = @(if ($null -eq $Rows) { @() } else { @($Rows) })
    if ($rowArray.Count -eq 0) { return '<p class="muted">No data.</p>' }
    $columns = @($rowArray[0].PSObject.Properties.Name)
    $esc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $columns) { [void]$sb.Append(('<th>{0}</th>' -f (& $esc $c))) }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rowArray) {
        [void]$sb.Append('<tr>')
        foreach ($c in $columns) { [void]$sb.Append(('<td>{0}</td>' -f (& $esc $r.$c))) }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function ConvertTo-FleetMarkdownTable {
    <# Same shape as Output.psm1's ConvertTo-MarkdownTable, kept local for the same reason as ConvertTo-FleetHtmlTable above. #>
    param([AllowNull()]$Rows)
    $rowArray = @(if ($null -eq $Rows) { @() } else { @($Rows) })
    if ($rowArray.Count -eq 0) { return '_No data._' }
    $columns = @($rowArray[0].PSObject.Properties.Name)
    $esc = { param($v) ([string]$v) -replace '\|','\|' -replace '(\r\n|\n|\r)',' ' }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('| ' + (($columns | ForEach-Object { & $esc $_ }) -join ' | ') + ' |')
    [void]$sb.AppendLine('| ' + (($columns | ForEach-Object { '---' }) -join ' | ') + ' |')
    foreach ($r in $rowArray) {
        $cells = foreach ($c in $columns) { & $esc $r.$c }
        [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
    }
    return $sb.ToString()
}

function Get-FleetBranding {
    <#
        Local duplicate of Core.psm1's Get-DiscoveryBranding/Get-DiscoveryLogoDataUri - this
        script deliberately has no hard dependency on other modules (same reasoning as
        ConvertTo-FleetHtmlTable/ConvertTo-FleetMarkdownTable above), and has no $Context object
        to read from anyway, so it reads config/output-settings.json (plus the untracked
        config/branding.local.json overlay) off disk directly. Fail-soft:
        a missing/malformed config or logo file degrades to no branding, never throws.
    #>
    param(
        # Parameters exist so tests can point at fixtures; normal callers pass nothing.
        [string]$ConfigDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'config'),
        [string]$ProgramDataBrandingDirectory = (Join-Path $env:ProgramData 'Discover-WindowsServer\branding')
    )
    $result = @{ Brand = 'Your Company'; Accent = '#1F4E79'; LogoDataUri = $null }
    try {
        $configDir = $ConfigDirectory
        $cfgPath = Join-Path $configDir 'output-settings.json'
        if (-not (Test-Path -LiteralPath $cfgPath)) { return $result }
        $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
        $html = $cfg.html
        # Same as Core.psm1's Get-DiscoveryBrandingDirectory + Merge-LocalBranding: the per-machine
        # brand in %ProgramData% wins, then the pre-move config-dir location.
        $brandingDir = if (Test-Path -LiteralPath (Join-Path $ProgramDataBrandingDirectory 'branding.local.json')) { $ProgramDataBrandingDirectory } else { $configDir }
        $localPath = Join-Path $brandingDir 'branding.local.json'
        if (Test-Path -LiteralPath $localPath) {
            $localHtml = (Get-Content -LiteralPath $localPath -Raw | ConvertFrom-Json).html
            if ($localHtml) {
                if (-not $html) { $html = [pscustomobject]@{} }
                foreach ($p in $localHtml.PSObject.Properties) { $html | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force }
            }
        }
        if ($html) {
            if ($html.brandName)      { $result.Brand = [string]$html.brandName }
            if ($html.accentColorHex) { $result.Accent = [string]$html.accentColorHex }
            if ($html.logoPath) {
                $mimeByExtension = @{ '.png' = 'image/png'; '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'; '.gif' = 'image/gif'; '.svg' = 'image/svg+xml' }
                $logoFullPath = Join-Path $brandingDir ([string]$html.logoPath)
                if (-not (Test-Path -LiteralPath $logoFullPath -PathType Leaf)) { $logoFullPath = Join-Path $configDir ([string]$html.logoPath) }
                if (Test-Path -LiteralPath $logoFullPath -PathType Leaf) {
                    $ext = [System.IO.Path]::GetExtension($logoFullPath).ToLowerInvariant()
                    if ($mimeByExtension.ContainsKey($ext)) {
                        $bytes = [System.IO.File]::ReadAllBytes($logoFullPath)
                        if ($bytes.Length -le 512KB) {
                            $result.LogoDataUri = 'data:{0};base64,{1}' -f $mimeByExtension[$ext], [Convert]::ToBase64String($bytes)
                        }
                    }
                }
            }
        }
    } catch { }
    return $result
}

function Get-FleetLogoHtml {
    <# <img> tag for a fleet report header, or '' when no logo is configured. #>
    param([hashtable]$Branding)
    if (-not $Branding.LogoDataUri) { return '' }
    $esc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    return ('<img src="{0}" alt="{1}" class="brand-logo">' -f $Branding.LogoDataUri, (& $esc $Branding.Brand))
}

function Get-FleetDependencyDiagramSvg {
    <#
        Local duplicate of Output.psm1's Get-DependencyDiagramSvg - this script deliberately has
        no hard dependency on other modules (same reasoning as Get-FleetBranding/
        ConvertTo-FleetHtmlTable above), so the rendering logic is copied rather than imported.
        Deliberately PER-SERVER, never fleet-wide: a DependencyGraph row's Target is free text
        (an IP, a UNC path, a hostname), so two servers coincidentally sharing an identical
        Target string does NOT mean they share the same underlying resource - a fleet-wide
        diagram would visually imply a cross-server relationship the data cannot actually
        support. Call this once per ComputerName, on that server's own edges only.

        DependencyType used to be drawn as text at each line's midpoint - with more than a
        handful of edges, midpoints cluster and labels stack into unreadable text (reported by
        the user against a real fleet run). Fixed the same way as Output.psm1's
        Get-DependencyDiagramSvg: type -> fixed legend color, confidence -> line style
        (solid/dashed/dotted), full detail moved to a hover <title>, and right-column order
        picked by a barycenter heuristic instead of alphabetically to cut down crossings.

        Left-column labels are right-aligned so their text ends right where their line starts
        (reported by the user as unclear which label owned which line under a fixed-margin
        layout), and column widths are sized to the longest surviving label instead of fixed.
    #>
    param(
        [AllowNull()][object[]]$Edges,
        [string[]]$ExcludeDependencyTypes = @('ListeningPort'),
        [string[]]$ExcludeTargets = @('127.0.0.1', '::1', 'localhost', 'fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3'),
        [int]$MaxEdges = 40,
        [int]$RowHeight = 26,
        [int]$LabelMaxChars = 42
    )
    $esc = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }
    $truncate = {
        param($s)
        if ([string]::IsNullOrEmpty($s)) { return '' }
        if ($s.Length -gt $LabelMaxChars) { return $s.Substring(0, $LabelMaxChars - 1) + [char]0x2026 }
        return $s
    }
    $confidenceRank = @{ Confirmed = 0; Likely = 1; Possible = 2 }
    $confidenceDash = @{ Confirmed = ''; Likely = '5,3'; Possible = '2,2' }
    $palette = @('#2E6E8E', '#B0562F', '#4A7C4E', '#8B4B8B', '#B08A2E', '#4A5B79', '#A8433A', '#3E8E82')

    $all = @(if ($null -eq $Edges) { @() } else { @($Edges) })
    $filtered = @($all | Where-Object {
        ($ExcludeDependencyTypes -notcontains [string]$_.DependencyType) -and
        ($ExcludeTargets -notcontains ([string]$_.Target).Trim())
    })
    if ($filtered.Count -eq 0) { return $null }

    $groups = [ordered]@{}
    foreach ($e in $filtered) {
        $key = '{0}|{1}|{2}|{3}' -f [string]$e.SourceType, [string]$e.SourceName, [string]$e.DependencyType, [string]$e.Target
        if ($groups.Contains($key)) { $groups[$key].Count++ }
        else {
            $groups[$key] = [pscustomobject]@{
                SourceType = [string]$e.SourceType; SourceName = [string]$e.SourceName
                DependencyType = [string]$e.DependencyType; Target = [string]$e.Target
                Confidence = [string]$e.Confidence; Count = 1
            }
        }
    }
    $deduped = @($groups.Values)
    $sorted = @($deduped | Sort-Object -Property @{ Expression = { if ($confidenceRank.ContainsKey($_.Confidence)) { $confidenceRank[$_.Confidence] } else { 3 } } }, SourceName)
    $overflowCount = [Math]::Max(0, $sorted.Count - $MaxEdges)
    $rendered = @($sorted | Select-Object -First $MaxEdges)
    if ($rendered.Count -eq 0) { return $null }

    $typeColor = @{}
    foreach ($r in $rendered) {
        if (-not $typeColor.ContainsKey($r.DependencyType)) {
            $typeColor[$r.DependencyType] = $palette[$typeColor.Count % $palette.Count]
        }
    }

    $leftNodes = @($rendered | ForEach-Object { "$($_.SourceType): $($_.SourceName)" } | Sort-Object -Unique)
    $leftIndex = @{}; for ($i = 0; $i -lt $leftNodes.Count; $i++) { $leftIndex[$leftNodes[$i]] = $i }

    $rightBarycenter = @{}; $rightCounts = @{}
    foreach ($r in $rendered) {
        $li = $leftIndex["$($r.SourceType): $($r.SourceName)"]
        if (-not $rightBarycenter.ContainsKey($r.Target)) { $rightBarycenter[$r.Target] = 0.0; $rightCounts[$r.Target] = 0 }
        $rightBarycenter[$r.Target] += $li
        $rightCounts[$r.Target]++
    }
    $rightNodes = @($rightBarycenter.Keys | Sort-Object -Property @{ Expression = { $rightBarycenter[$_] / $rightCounts[$_] } }, @{ Expression = { $_ } })
    $rightIndex = @{}; for ($i = 0; $i -lt $rightNodes.Count; $i++) { $rightIndex[$rightNodes[$i]] = $i }

    $charWidth = 6.3
    $leftLabel = @{}; foreach ($n in $leftNodes) { $leftLabel[$n] = & $truncate $n }
    $rightLabel = @{}; foreach ($n in $rightNodes) { $rightLabel[$n] = & $truncate $n }
    $maxLeftChars = ($leftLabel.Values | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $maxRightChars = ($rightLabel.Values | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum

    $topMargin = 40
    $maxRows = [Math]::Max($leftNodes.Count, $rightNodes.Count)
    $leftMargin = 12
    $lineSpan = 220
    $lineStartX = $leftMargin + [Math]::Ceiling($maxLeftChars * $charWidth) + 14
    $lineEndX = $lineStartX + $lineSpan
    $rightTextX = $lineEndX + 10
    $width = $rightTextX + [Math]::Ceiling($maxRightChars * $charWidth) + 20
    $legendTypes = @($typeColor.Keys | Sort-Object)
    $legendCols = [Math]::Max(1, [Math]::Min(4, [Math]::Floor($width / 180)))
    $legendRows = [Math]::Ceiling($legendTypes.Count / $legendCols)
    $legendHeight = 22 + ($legendRows * 18)
    $height = $topMargin + ($RowHeight * $maxRows) + 30 + $legendHeight
    $leftTextX = $lineStartX - 8

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<svg viewBox=`"0 0 $width $height`" xmlns=`"http://www.w3.org/2000/svg`" font-family=`"Segoe UI,Calibri,Arial,sans-serif`" font-size=`"12`">")
    foreach ($r in $rendered) {
        $leftKey = "$($r.SourceType): $($r.SourceName)"
        $y1 = $topMargin + ($leftIndex[$leftKey] * $RowHeight) + [Math]::Round($RowHeight / 2)
        $y2 = $topMargin + ($rightIndex[$r.Target] * $RowHeight) + [Math]::Round($RowHeight / 2)
        $color = $typeColor[$r.DependencyType]
        $dash = if ($confidenceDash.ContainsKey($r.Confidence)) { $confidenceDash[$r.Confidence] } else { '' }
        $dashAttr = if ($dash) { " stroke-dasharray=`"$dash`"" } else { '' }
        $titleText = $r.DependencyType
        if ($r.Count -gt 1) { $titleText = "$titleText (x$($r.Count))" }
        if ($r.Confidence) { $titleText = "$titleText - $($r.Confidence)" }
        [void]$sb.Append("<line class=`"dep-edge`" x1=`"$lineStartX`" y1=`"$y1`" x2=`"$lineEndX`" y2=`"$y2`" stroke=`"$color`" stroke-width=`"1.5`" opacity=`"0.8`"$dashAttr><title>$(& $esc $titleText)</title></line>")
    }
    foreach ($n in $leftNodes) {
        $y = $topMargin + ($leftIndex[$n] * $RowHeight) + [Math]::Round($RowHeight / 2) + 4
        [void]$sb.Append("<text x=`"$leftTextX`" y=`"$y`" text-anchor=`"end`" fill=`"#1A1F27`">$(& $esc $leftLabel[$n])<title>$(& $esc $n)</title></text>")
    }
    foreach ($n in $rightNodes) {
        $y = $topMargin + ($rightIndex[$n] * $RowHeight) + [Math]::Round($RowHeight / 2) + 4
        [void]$sb.Append("<text x=`"$rightTextX`" y=`"$y`" fill=`"#1A1F27`">$(& $esc $rightLabel[$n])<title>$(& $esc $n)</title></text>")
    }
    if ($overflowCount -gt 0) {
        $noteY = $topMargin + ($RowHeight * $maxRows) + 16
        [void]$sb.Append("<text x=`"$leftMargin`" y=`"$noteY`" fill=`"#5B6472`" font-style=`"italic`" font-size=`"11`">+$overflowCount more edge(s) not shown - see the DependencyGraph dataset for the full list.</text>")
    }

    $legendY = $height - $legendHeight + 8
    [void]$sb.Append("<text x=`"$leftMargin`" y=`"$legendY`" fill=`"#5B6472`" font-size=`"11`" font-weight=`"600`">Dependency type (line style: solid = Confirmed, dashed = Likely, dotted = Possible)</text>")
    $legendColWidth = [Math]::Floor($width / $legendCols)
    for ($i = 0; $i -lt $legendTypes.Count; $i++) {
        $type = $legendTypes[$i]
        $col = $i % $legendCols
        $row = [Math]::Floor($i / $legendCols)
        $swX = $leftMargin + ($col * $legendColWidth)
        $swY = $legendY + 14 + ($row * 18)
        [void]$sb.Append("<line x1=`"$swX`" y1=`"$($swY - 4)`" x2=`"$($swX + 24)`" y2=`"$($swY - 4)`" stroke=`"$($typeColor[$type])`" stroke-width=`"3`" />")
        [void]$sb.Append("<text x=`"$($swX + 30)`" y=`"$swY`" fill=`"#1A1F27`" font-size=`"11`">$(& $esc (& $truncate $type))</text>")
    }
    [void]$sb.Append('</svg>')
    return $sb.ToString()
}

function Write-FleetDashboardReport {
    <#
        Interactive Command Center companion to Write-FleetRollupHtml: a sidebar nav in place of
        one long scroll, each table in its own scrollable/filterable box - identical layout and
        behavior to Output.psm1's Write-DashboardHtmlReport for a single server, applied to a
        whole engagement.
    #>
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$EngagementFolder, [Parameter(Mandatory)][string]$Path)
    $esc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $slug = { param($s, $i) (($s.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')) + '-' + $i }
    $b = Get-FleetBranding

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>Fleet Discovery Rollup - Dashboard</title>')
    [void]$sb.AppendLine(('<style>{0}</style></head><body>' -f (Get-FleetDashboardCss -AccentColorHex $b.Accent)))
    [void]$sb.AppendLine('<div class="shell"><nav class="side">')
    [void]$sb.AppendLine(('{0}<h1>Fleet Discovery Rollup</h1><div class="sub">{1}</div>' -f (Get-FleetLogoHtml -Branding $b), (& $esc (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))))

    $panes = [System.Text.StringBuilder]::new()
    $navIndex = [ref]0
    # navIndex is a [ref], not a plain int, for the same reason Output.psm1's
    # Write-DashboardHtmlReport uses one: $addNavAndPane runs via `&`, which gives it its own
    # child scope, so a plain int assignment inside it would rebind a new local rather than
    # mutate this one.
    $addNavAndPane = {
        param([string]$Label, [string]$CountText, [string]$BodyHtml, [bool]$First = $false)
        $navIndex.Value++
        $id = & $slug $Label $navIndex.Value
        $selClass = if ($First) { ' sel' } else { '' }
        $activeClass = if ($First) { ' active' } else { '' }
        [void]$sb.AppendLine(('<a class="navlink{0}" data-pane="p-{1}">{2} <span class="n">{3}</span></a>' -f $selClass, $id, (& $esc $Label), (& $esc $CountText)))
        [void]$panes.AppendLine(('<div class="pane{0}" id="p-{1}">{2}</div>' -f $activeClass, $id, $BodyHtml))
    }

    [void]$sb.AppendLine('<div class="grp">Overview</div>')
    $overviewBody = [System.Text.StringBuilder]::new()
    [void]$overviewBody.AppendLine('<div class="kpis">')
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}/{1}</div><div class="l">Servers succeeded</div></div>' -f $Model.SucceededServerCount, $Model.ServerCount))
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Findings</div></div>' -f @($Model.RiskRegister).Count))
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Critical/High</div></div>' -f ($Model.Counts['Critical'] + $Model.Counts['High'])))
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Migration-wave groupings</div></div>' -f @($Model.DependencyHints).Count))
    if ($null -ne $Model.FleetAverageReadiness) {
        [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Avg. readiness score</div></div>' -f $Model.FleetAverageReadiness))
    }
    [void]$overviewBody.AppendLine('</div>')
    [void]$overviewBody.AppendLine('<h2>Servers</h2><div class="tablebox"><table><thead><tr><th>Computer</th><th>Status</th><th>Mode</th><th>Findings</th><th>Readiness</th><th>Details</th></tr></thead><tbody>')
    foreach ($s in $Model.ServerSummaries) {
        $rowClass = if ($s.Status -ne 'Succeeded') { ' class="status-bad"' } else { '' }
        $readinessCell = if ($s.ReadinessGrade) { "$($s.ReadinessGrade) ($($s.ReadinessScore))" } else { '' }
        [void]$overviewBody.AppendLine("<tr$rowClass><td>$(& $esc $s.ComputerName)</td><td>$(& $esc $s.Status)</td><td>$(& $esc $s.Mode)</td><td>$(& $esc $s.FindingCount)</td><td>$(& $esc $readinessCell)</td><td>$(& $esc $s.ErrorMessage)</td></tr>")
    }
    [void]$overviewBody.AppendLine('</tbody></table></div>')
    & $addNavAndPane 'Summary' '' $overviewBody.ToString() $true

    $diagramPaneBody = [System.Text.StringBuilder]::new()
    $anyDiagram = $false
    foreach ($s in ($Model.ServerSummaries | Where-Object { $_.Status -eq 'Succeeded' })) {
        $serverEdges = @($Model.DependencyEdges | Where-Object { $_.ComputerName -eq $s.ComputerName })
        $svg = Get-FleetDependencyDiagramSvg -Edges $serverEdges
        if (-not $svg) { continue }
        $anyDiagram = $true
        [void]$diagramPaneBody.AppendLine(("<h2>{0}</h2>" -f (& $esc $s.ComputerName)))
        [void]$diagramPaneBody.AppendLine(('<div class="dep-diagram">{0}</div>' -f $svg))
    }
    if ($anyDiagram) {
        [void]$diagramPaneBody.Insert(0, '<p class="pd">One diagram per server - never combined, since a shared Target value does not necessarily mean two servers reference the same underlying resource.</p>')
        & $addNavAndPane 'Dependency Diagrams' '' $diagramPaneBody.ToString()
    }

    [void]$sb.AppendLine('<div class="grp">Findings</div>')
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $group = @($Model.RiskRegister | Where-Object { $_.Severity -eq $sev })
        if ($group.Count -eq 0) { continue }
        $body = [System.Text.StringBuilder]::new()
        [void]$body.AppendLine(('<h2>{0}-severity findings</h2><p class="pd">{1} finding(s) across the fleet.</p>' -f $sev, $group.Count))
        foreach ($f in $group) {
            [void]$body.AppendLine(('<div class="card sev-{0}">' -f $f.Severity))
            [void]$body.AppendLine(('<div><span class="badge sevbadge">{0}</span> <b>{1}</b> <span class="muted">{2} &middot; {3}</span></div>' -f $f.Severity, (& $esc $f.Title), (& $esc $f.ComputerName), (& $esc $f.Category)))
            if ($f.Evidence) { [void]$body.AppendLine(('<div><b>Evidence:</b> {0}</div>' -f (& $esc $f.Evidence))) }
            [void]$body.AppendLine('</div>')
        }
        & $addNavAndPane "$sev severity" ([string]$group.Count) $body.ToString()
    }

    [void]$sb.AppendLine('<div class="grp">Reference</div>')
    $depBody = [System.Text.StringBuilder]::new()
    [void]$depBody.AppendLine('<h2>Possible migration-wave groupings</h2><p class="pd">Confirm before relying on these - a heuristic, not a dependency-graph solver.</p>')
    if (@($Model.DependencyHints).Count -eq 0) {
        [void]$depBody.AppendLine('<p class="muted">No cross-server groupings suggested by this heuristic.</p>')
    } else {
        [void]$depBody.AppendLine('<div class="tablebox"><table><thead><tr><th>Group</th><th>Servers</th><th>Why</th></tr></thead><tbody>')
        foreach ($g in $Model.DependencyHints) { [void]$depBody.AppendLine("<tr><td>$(& $esc $g.SuggestedGroupLabel)</td><td>$(& $esc ($g.ComputerNames -join ', '))</td><td>$(& $esc $g.Rationale)</td></tr>") }
        [void]$depBody.AppendLine('</tbody></table></div>')
    }
    & $addNavAndPane 'Migration-wave groupings' ([string]@($Model.DependencyHints).Count) $depBody.ToString()

    foreach ($section in @(
        @{ Title = 'Decommission readiness'; Rows = $Model.DecommissionReadiness }
        @{ Title = 'Scope assumptions'; Rows = $Model.ScopeAssumptions }
        @{ Title = 'Scope exclusions'; Rows = $Model.ScopeExclusions }
    )) {
        if (@($section.Rows).Count -eq 0) { continue }
        $body = "<h2>$(& $esc $section.Title)</h2>" + '<div class="filterrow"><input type="text" placeholder="Filter rows..." data-filtertarget="1"></div><div class="tablebox">' + (ConvertTo-FleetHtmlTable -Rows $section.Rows) + '</div>'
        & $addNavAndPane $section.Title ([string]@($section.Rows).Count) $body
    }

    [void]$sb.AppendLine('</nav><main class="main">')
    [void]$sb.Append($panes.ToString())
    [void]$sb.AppendLine('</main></div>')

    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine(@'
document.querySelectorAll(".navlink").forEach(function(link){
  link.addEventListener("click", function(){
    document.querySelectorAll(".navlink").forEach(function(l){ l.classList.remove("sel"); });
    document.querySelectorAll(".pane").forEach(function(p){ p.classList.remove("active"); });
    link.classList.add("sel");
    document.getElementById(link.dataset.pane).classList.add("active");
  });
});
document.querySelectorAll("[data-filtertarget]").forEach(function(input){
  input.addEventListener("input", function(){
    var q = input.value.toLowerCase();
    var box = input.closest(".pane").querySelector(".tablebox tbody");
    if (!box) { return; }
    box.querySelectorAll("tr").forEach(function(row){
      row.classList.toggle("hide", q.length > 0 && row.textContent.toLowerCase().indexOf(q) === -1);
    });
  });
});
'@)
    [void]$sb.AppendLine('</script></body></html>')

    $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force
}

#region Client-safe fleet summary -------------------------------------------------

function Get-FleetClientSafeDataset {
    <#
        Like Merge-FleetDataset, but only includes a server's rows for a dataset if THAT
        SERVER's own collection-metadata.json records it as ClientSafe or Both - the same
        per-run Visibility Add-DataSet stamped on it at collection time (see
        Discover-WindowsServer.psm1's Datasets=@($Context.DataSets.Keys | ...) metadata block).
        Reading the recorded Visibility instead of assuming a hardcoded list means this can never
        silently drift from what an individual server's own client report would have shown for
        the same dataset.
    #>
    param([Parameter(Mandatory)][string]$EngagementFolder, [Parameter(Mandatory)][string]$DatasetName)
    $allRows = [System.Collections.Generic.List[object]]::new()
    foreach ($runDir in (Get-FleetRunFolder -EngagementFolder $EngagementFolder)) {
        $meta = Get-FleetRunMetadata -RunFolder $runDir.FullName
        if (-not $meta) { continue }
        $dsMeta = @($meta.Datasets | Where-Object { $_.Name -eq $DatasetName } | Select-Object -First 1)
        if (@($dsMeta).Count -eq 0 -or $dsMeta[0].Visibility -notin @('ClientSafe','Both')) { continue }
        $dataPath = Join-Path $runDir.FullName ("evidence\data\json\{0}.json" -f $DatasetName)
        if (-not (Test-Path -LiteralPath $dataPath)) { continue }
        try {
            $parsed = Get-Content -LiteralPath $dataPath -Raw | ConvertFrom-Json
            $rows = @($parsed)
        } catch { continue }
        foreach ($stamped in (Add-FleetRowStamp -Rows $rows -ComputerName $meta.ComputerName -RunId $meta.RunId -Mode $meta.Mode)) { $allRows.Add($stamped) }
    }
    # Same reasoning as Merge-FleetDataset's own return - see its comment.
    return $allRows.ToArray()
}

function Get-FleetClientHeadlines {
    <#
        The fleet-scale equivalent of ReportBuilder.psm1's Get-RbClientHeadlines: Critical/High
        findings only, Title + WhyItMattersForScoping only (never Evidence, Subject or any other
        field that can carry a path/account/port), grouped by Title across the WHOLE fleet rather
        than deduplicated away within one server - so a client sees "SMBv1 enabled - affects
        SRV-A, SRV-B, SRV-D" as one line instead of the same generic finding repeated per server.
        ScopingRisks itself is Internal (see Discover-WindowsServer.psm1) - reading it here is
        safe ONLY because just these two authored (not collected) fields are ever extracted, the
        same safety contract Get-RbClientHeadlines already relies on for the single-server report.
    #>
    param([Parameter(Mandatory)][string]$EngagementFolder)
    $rows = Merge-FleetDataset -EngagementFolder $EngagementFolder -DatasetName 'ScopingRisks'
    $safe = @($rows | Where-Object { $_.Severity -in @('Critical','High') -and $_.Title } |
        ForEach-Object { [pscustomobject]@{ Title = [string]$_.Title; Category = [string]$_.Category; WhyItMatters = [string]$_.WhyItMattersForScoping; ComputerName = [string]$_.ComputerName } })
    return ,@($safe | Group-Object Title | ForEach-Object {
        [pscustomobject]@{
            Topic        = $_.Group[0].Category
            WhatWeFound  = $_.Name
            WhyItMatters = $_.Group[0].WhyItMatters
            AffectedServers = (@($_.Group.ComputerName | Select-Object -Unique | Sort-Object) -join ', ')
        }
    } | Sort-Object Topic)
}

function Get-FleetClientModel {
    <#
        Builds the fleet client summary's content model once, so the HTML and Markdown
        renderings can never drift apart - same reasoning as Get-RbClientModel for the
        single-server client report and Get-FleetRollupModel for the internal fleet rollup.
    #>
    param([Parameter(Mandatory)][string]$EngagementFolder)

    $outcomes = Get-FleetRunOutcome -EngagementFolder $EngagementFolder
    $serverStatus = @(if (@($outcomes).Count -gt 0) {
        foreach ($o in $outcomes) {
            # Deliberately no ErrorMessage here, unlike the internal rollup's server table - an
            # internal failure reason (a DCOM/Task Scheduler/WinRM detail) is Internal-visibility
            # information about this toolkit's own mechanics, not something to hand to a client.
            [pscustomobject]@{ ComputerName = $o.ComputerName; Reviewed = ($o.Status -eq 'Succeeded') }
        }
    } else {
        foreach ($runDir in (Get-FleetRunFolder -EngagementFolder $EngagementFolder)) {
            $meta = Get-FleetRunMetadata -RunFolder $runDir.FullName
            [pscustomobject]@{ ComputerName = if ($meta) { $meta.ComputerName } else { $runDir.Name }; Reviewed = $true }
        }
    })

    $apps = @(Get-FleetClientSafeDataset -EngagementFolder $EngagementFolder -DatasetName 'ApplicationFingerprints' |
        Where-Object { $_.Confidence -in @('Confirmed','Likely') } |
        ForEach-Object { [pscustomobject]@{ Application = [string]$_.ApplicationName; Vendor = [string]$_.Vendor; Server = [string]$_.ComputerName } } |
        Sort-Object Application, Server -Unique)
    $shares = @(Get-FleetClientSafeDataset -EngagementFolder $EngagementFolder -DatasetName 'SmbShares' |
        Where-Object { $_.IsUserShare } |
        ForEach-Object { [pscustomobject]@{ 'Shared folder' = [string]$_.Name; Server = [string]$_.ComputerName; Description = [string]$_.Description } })
    $printers = @(Get-FleetClientSafeDataset -EngagementFolder $EngagementFolder -DatasetName 'Printers' |
        Where-Object { $_.Shared } |
        ForEach-Object { [pscustomobject]@{ Printer = [string]$_.Name; Server = [string]$_.ComputerName } })
    $vendors = @(Get-FleetClientSafeDataset -EngagementFolder $EngagementFolder -DatasetName 'VendorAgents' |
        ForEach-Object { [pscustomobject]@{ 'Third-party product' = [string]$_.AgentName; Purpose = [string]$_.Category; Server = [string]$_.ComputerName } } |
        Sort-Object 'Third-party product', Server -Unique)
    $hybrid = @(Get-FleetClientSafeDataset -EngagementFolder $EngagementFolder -DatasetName 'HybridIdentity' |
        ForEach-Object { [pscustomobject]@{ 'Cloud connection' = [string]$_.Component; 'What it does' = [string]$_.Role; Server = [string]$_.ComputerName } })
    $backupRows = @(Get-FleetClientSafeDataset -EngagementFolder $EngagementFolder -DatasetName 'BackupDiscovery')
    $backedUpServers = @($backupRows.ComputerName | Select-Object -Unique)
    $notBackedUpServers = @($serverStatus | Where-Object { $_.Reviewed -and $backedUpServers -notcontains $_.ComputerName } | ForEach-Object { $_.ComputerName })

    # Only Grade/Label/Score per server - never FindingsCounted, matching the same
    # client-safety reasoning as Get-RbClientModel's own Readiness field.
    $readiness = @(Get-FleetClientSafeDataset -EngagementFolder $EngagementFolder -DatasetName 'ReadinessScore' |
        ForEach-Object { [pscustomobject]@{ Server = [string]$_.ComputerName; Grade = [string]$_.Grade; Label = [string]$_.Label; Score = $_.Score } })

    $limitations = @(
        'Warranty status, licence entitlement and vendor support status cannot be confirmed from a server itself - those need to come from you or the vendor.'
        'Everything here is an indicator based on what each server reports about itself. Nothing was changed on any server, and nothing should be acted on until you have confirmed it.'
    )

    [pscustomobject]@{
        Generated       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        ServerCount     = @($serverStatus).Count
        ReviewedServers = @($serverStatus | Where-Object { $_.Reviewed } | ForEach-Object { $_.ComputerName })
        Headlines       = Get-FleetClientHeadlines -EngagementFolder $EngagementFolder
        Applications    = $apps
        Shares          = $shares
        Printers        = $printers
        Vendors         = $vendors
        HybridIdentity  = $hybrid
        BackedUpServers = $backedUpServers
        NotBackedUpServers = $notBackedUpServers
        Readiness       = $readiness
        Limitations     = $limitations
    }
}

function Get-FleetClientCss {
    <# Calmer, client-facing styling - deliberately separate from the internal reports' visual language, mirroring ReportBuilder.psm1's Get-RbClientCss for the single-server client report. #>
    param([string]$AccentColorHex = '#1F4E79')
    if ([string]::IsNullOrWhiteSpace($AccentColorHex)) { $AccentColorHex = '#1F4E79' }
    $css = @'
:root{--accent:__ACCENT__;--fg:#22272b;--muted:#5b6670;--line:#e4e8ec;--soft:#f6f8fa}
*{box-sizing:border-box}
body{font-family:Segoe UI,Calibri,Arial,sans-serif;color:var(--fg);background:#fff;margin:0;line-height:1.65;font-size:15px}
header{background:var(--accent);color:#fff;padding:36px 40px}
header .brand-logo{max-height:40px;vertical-align:middle;margin-right:12px}
header h1{margin:0 0 6px;font-size:26px;font-weight:600}
header .sub{opacity:.9;font-size:14px}
main{max-width:940px;margin:0 auto;padding:8px 40px 40px}
h2{color:var(--accent);font-size:20px;margin-top:40px;padding-bottom:8px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin-top:26px;color:#33404a}
p{margin:12px 0}
table{border-collapse:collapse;width:100%;margin:16px 0;font-size:14px}
th,td{border:1px solid var(--line);padding:9px 11px;text-align:left;vertical-align:top}
th{background:var(--soft);font-weight:600}
.lead{font-size:16px;color:var(--muted)}
.callout{border-left:4px solid var(--accent);background:var(--soft);padding:14px 18px;margin:18px 0;border-radius:0 6px 6px 0}
.facts{display:flex;flex-wrap:wrap;gap:14px;margin:20px 0}
.fact{flex:1;min-width:160px;border:1px solid var(--line);border-radius:8px;padding:14px 16px;background:#fff;text-align:center}
.fact .l{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.fact .v{font-size:17px;font-weight:600;color:var(--accent);margin-top:4px;word-break:break-word}
.muted{color:var(--muted);font-size:13px}
footer{max-width:940px;margin:30px auto 0;padding:18px 40px 40px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
@media print{header{background:#fff;color:var(--accent);border-bottom:3px solid var(--accent)}main{padding:0 12px}}
'@
    return ($css -replace '__ACCENT__', $AccentColorHex)
}

function Write-FleetClientHtmlReport {
    <# Writes fleet-client-summary.html - safe to hand to the client as-is, same safety contract as ReportBuilder.psm1's single-server client report. #>
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$Path)
    $esc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $b = Get-FleetBranding
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$html.AppendLine('<title>Fleet Discovery Summary</title>')
    [void]$html.AppendLine(('<style>{0}</style></head><body>' -f (Get-FleetClientCss -AccentColorHex $b.Accent)))
    [void]$html.AppendLine("<header>$(Get-FleetLogoHtml -Branding $b)<h1>Fleet Discovery Summary</h1>")
    [void]$html.AppendLine(("<div class=`"sub`">{0} &middot; {1} server(s) reviewed &middot; {2}</div></header><main>" -f (& $esc $b.Brand), $Model.ServerCount, (& $esc $Model.Generated)))

    [void]$html.AppendLine('<h2>What this document is</h2>')
    [void]$html.AppendLine('<p class="lead">We ran a read-only review of these servers to understand what they do and what depends on them, so that any future migration, replacement or retirement is planned around the things that actually matter to your business.</p>')
    [void]$html.AppendLine('<div class="callout"><b>Nothing was changed on any server.</b> Each review only read configuration. Everything below is our best reading of what the servers report about themselves, and we need you to confirm it.</div>')

    [void]$html.AppendLine('<div class="facts">')
    [void]$html.AppendLine(('<div class="fact"><div class="l">Servers reviewed</div><div class="v">{0} of {1}</div></div>' -f @($Model.ReviewedServers).Count, $Model.ServerCount))
    [void]$html.AppendLine(('<div class="fact"><div class="l">Things worth your attention</div><div class="v">{0}</div></div>' -f @($Model.Headlines).Count))
    [void]$html.AppendLine(('<div class="fact"><div class="l">Servers without backup detected</div><div class="v">{0}</div></div>' -f @($Model.NotBackedUpServers).Count))
    [void]$html.AppendLine('</div>')

    if (@($Model.Readiness).Count -gt 0) {
        [void]$html.AppendLine('<h2>Readiness snapshot</h2><p class="muted">A transparent, rule-based indicator per server - not a certification. Always validate before using it in scoping.</p>')
        [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $Model.Readiness))
    }

    if (@($Model.Applications).Count -gt 0) {
        [void]$html.AppendLine('<h3>Business applications we recognised</h3><p class="muted">Please tell us which of these are still in use, and which are not.</p>')
        [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $Model.Applications))
    }
    if (@($Model.Shares).Count -gt 0) { [void]$html.AppendLine('<h3>Shared folders</h3>'); [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $Model.Shares)) }
    if (@($Model.Printers).Count -gt 0) { [void]$html.AppendLine('<h3>Shared printers</h3>'); [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $Model.Printers)) }
    if (@($Model.HybridIdentity).Count -gt 0) { [void]$html.AppendLine('<h3>Connections to Microsoft 365 / Azure</h3>'); [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $Model.HybridIdentity)) }
    if (@($Model.Vendors).Count -gt 0) {
        [void]$html.AppendLine('<h3>Third-party products installed</h3><p class="muted">If any of these are no longer under contract, tell us - it changes the plan.</p>')
        [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $Model.Vendors))
    }

    [void]$html.AppendLine('<h2>Things worth your attention</h2>')
    if (@($Model.Headlines).Count -gt 0) {
        [void]$html.AppendLine('<p>These are the items most likely to affect cost, timing or risk across your servers. None of them are accusations.</p>')
        [void]$html.AppendLine((ConvertTo-FleetHtmlTable -Rows $Model.Headlines))
    } else {
        [void]$html.AppendLine('<p>Nothing significant enough to raise here. That is a good outcome, but read the limitations at the end before treating it as a clean bill of health.</p>')
    }

    if (@($Model.NotBackedUpServers).Count -gt 0) {
        [void]$html.AppendLine(('<div class="callout"><b>Backup:</b> we did not detect backup software on: {0}. That may simply mean they are protected at the virtualisation or storage layer, which we cannot see from inside the server. Please confirm how each is backed up and when a restore was last tested.</div>' -f (& $esc ($Model.NotBackedUpServers -join ', '))))
    }

    [void]$html.AppendLine('<h2>What this review could not tell us</h2><ul>')
    foreach ($l in $Model.Limitations) { [void]$html.AppendLine(('<li>{0}</li>' -f (& $esc $l))) }
    [void]$html.AppendLine('</ul>')

    [void]$html.AppendLine('</main><footer>Read-only discovery across your servers. This document is a planning aid: the findings are indicators that require confirmation, and it does not assert compliance or non-compliance with any standard.</footer></body></html>')
    $html.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force
}

function Write-FleetClientMarkdownReport {
    <# Markdown twin of Write-FleetClientHtmlReport, same model, for pasting into tickets/SOW drafts. #>
    param([Parameter(Mandatory)][object]$Model, [Parameter(Mandatory)][string]$Path)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# Fleet Discovery Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('**{0} server(s) reviewed** &middot; {1}' -f $Model.ServerCount, $Model.Generated))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> **Nothing was changed on any server.** Each review only read configuration. Everything below is our best reading of what the servers report about themselves, and we need you to confirm it.')
    [void]$sb.AppendLine('')
    if (@($Model.Readiness).Count -gt 0) {
        [void]$sb.AppendLine('## Readiness snapshot'); [void]$sb.AppendLine('')
        [void]$sb.AppendLine('A transparent, rule-based indicator per server - not a certification. Always validate before using it in scoping.'); [void]$sb.AppendLine('')
        [void]$sb.AppendLine((ConvertTo-FleetMarkdownTable -Rows $Model.Readiness)); [void]$sb.AppendLine('')
    }
    $tables = [ordered]@{
        'Business applications we recognised' = $Model.Applications
        'Shared folders' = $Model.Shares
        'Shared printers' = $Model.Printers
        'Connections to Microsoft 365 / Azure' = $Model.HybridIdentity
        'Third-party products installed' = $Model.Vendors
    }
    foreach ($t in $tables.Keys) {
        if (@($tables[$t]).Count -eq 0) { continue }
        [void]$sb.AppendLine(('## {0}' -f $t)); [void]$sb.AppendLine('')
        [void]$sb.AppendLine((ConvertTo-FleetMarkdownTable -Rows $tables[$t])); [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('## Things worth your attention'); [void]$sb.AppendLine('')
    if (@($Model.Headlines).Count -gt 0) { [void]$sb.AppendLine((ConvertTo-FleetMarkdownTable -Rows $Model.Headlines)) }
    else { [void]$sb.AppendLine('_Nothing significant enough to raise._') }
    [void]$sb.AppendLine('')
    if (@($Model.NotBackedUpServers).Count -gt 0) {
        [void]$sb.AppendLine(('> **Backup:** no backup software detected on: {0}.' -f ($Model.NotBackedUpServers -join ', ')))
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('## What this review could not tell us'); [void]$sb.AppendLine('')
    foreach ($l in $Model.Limitations) { [void]$sb.AppendLine(('- {0}' -f $l)) }
    [void]$sb.AppendLine('')
    $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force
}

#endregion

function New-FleetRollupReport {
    <# Writes fleet-rollup.json/.csv (combined risk register), fleet-rollup.html (printable) and fleet-dashboard-report.html (interactive) under -OutputPath. #>
    param(
        [Parameter(Mandatory)][string]$EngagementFolder,
        [string]$OutputPath
    )
    if (-not $OutputPath) { $OutputPath = Join-Path $EngagementFolder 'rollup' }
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

    $model = Get-FleetRollupModel -EngagementFolder $EngagementFolder

    $rollupData = [ordered]@{
        GeneratedTime    = (Get-Date).ToString('o')
        EngagementFolder = $EngagementFolder
        Servers          = $model.ServerSummaries
        RiskRegister     = $model.RiskRegister
        DependencyHints  = $model.DependencyHints
        DecommissionReadiness = $model.DecommissionReadiness
        ScopeAssumptions = $model.ScopeAssumptions
        ScopeExclusions  = $model.ScopeExclusions
    }
    ($rollupData | ConvertTo-Json -Depth 8) | Out-File -LiteralPath (Join-Path $OutputPath 'fleet-rollup.json') -Encoding UTF8 -Force
    if ($model.RiskRegister.Count -gt 0) { $model.RiskRegister | Export-Csv -LiteralPath (Join-Path $OutputPath 'fleet-rollup-risks.csv') -NoTypeInformation -Force }

    $htmlPath = Join-Path $OutputPath 'fleet-rollup.html'
    $dashboardPath = Join-Path $OutputPath 'fleet-dashboard-report.html'
    Write-FleetRollupHtml -Model $model -EngagementFolder $EngagementFolder -Path $htmlPath
    Write-FleetDashboardReport -Model $model -EngagementFolder $EngagementFolder -Path $dashboardPath

    # Client-safe summary, generated alongside the two internal formats every time - matching
    # the single-server engine, which always produces its client report as part of every run
    # rather than gating it behind a separate opt-in step.
    $clientModel = Get-FleetClientModel -EngagementFolder $EngagementFolder
    $clientHtmlPath = Join-Path $OutputPath 'fleet-client-summary.html'
    $clientMdPath = Join-Path $OutputPath 'fleet-client-summary.md'
    Write-FleetClientHtmlReport -Model $clientModel -Path $clientHtmlPath
    Write-FleetClientMarkdownReport -Model $clientModel -Path $clientMdPath

    return [pscustomobject]@{
        JsonPath = Join-Path $OutputPath 'fleet-rollup.json'
        HtmlPath = $htmlPath
        DashboardPath = $dashboardPath
        ClientHtmlPath = $clientHtmlPath
        ClientMarkdownPath = $clientMdPath
        CsvPath  = if ($model.RiskRegister.Count -gt 0) { Join-Path $OutputPath 'fleet-rollup-risks.csv' } else { $null }
        ServerCount = $model.ServerCount
        SucceededServerCount = $model.SucceededServerCount
        FindingCount = @($model.RiskRegister).Count
    }
}

#endregion

# Only runs when executed directly - dot-source for the functions above (Pester, or the GUI
# calling New-FleetRollupReport in-process rather than shelling out for what's a quick,
# read-only, local-only pass over already-finished output).
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $EngagementFolder) { throw '-EngagementFolder is required.' }
    $report = New-FleetRollupReport -EngagementFolder $EngagementFolder -OutputPath $OutputPath
    Write-Host ("Rollup built: {0} server(s), {1} finding(s) -> {2}" -f $report.ServerCount, $report.FindingCount, $report.HtmlPath) -ForegroundColor Green
}
