<#
    Discover-WindowsServer.psm1
    Orchestration engine for the Ultimate Modular Windows Server Discovery Toolkit.

    Responsibilities:
      - Discover, preflight, select, and run collector + synthesis modules.
      - Isolate each module (import -> run contract -> remove) so the ~30 modules
        can all use the same generic contract function names without collisions.
      - Guarantee every required output artifact is produced even if collectors
        return no rows or fail.

    The thin entry script Discover-WindowsServer.ps1 defines parameters, prepares
    the output folder / context, and calls Invoke-Discovery.
#>

# --- Module discovery / isolation -------------------------------------------

function Import-DiscoveryModuleFile {
    <# Imports a module by folder name; returns its module name or $null on failure. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ModulesRoot, [object]$Context)
    $psm1 = Join-Path (Join-Path $ModulesRoot $Name) ("{0}.psm1" -f $Name)
    if (-not (Test-Path -LiteralPath $psm1)) {
        if ($Context) { Add-Limitation -Context $Context -Module $Name -Message ("Module file not found: {0}" -f $psm1) -Impact 'Module skipped' | Out-Null }
        return $null
    }
    try {
        Import-Module -Name $psm1 -Force -DisableNameChecking -Global -ErrorAction Stop
        return $Name
    } catch {
        if ($Context) { Write-Log -Level ERROR -Message ("Failed to import module '{0}'." -f $Name) -Module $Name -Exception $_ -Context $Context }
        return $null
    }
}

function Remove-DiscoveryModuleFile {
    param([Parameter(Mandatory)][string]$Name)
    try { if (Get-Module -Name $Name -ErrorAction SilentlyContinue) { Remove-Module -Name $Name -Force -ErrorAction SilentlyContinue } } catch { }
}

function Start-DiscoverWindowsServerGui {
    <#
        Launches the optional WPF GUI launcher (Discover-WindowsServer-GUI.ps1) from wherever
        this module is actually installed - a git clone or an Install-Module'd copy under
        $env:PSModulePath. $PSScriptRoot inside a function defined in this .psm1 always resolves
        to the directory containing THIS file, the same pattern Invoke-Discovery already relies
        on (Join-Path $PSScriptRoot 'modules'), so no new resolution mechanism is needed.
    #>
    [CmdletBinding()]
    param([string[]]$ArgumentList = @())
    $guiPath = Join-Path $PSScriptRoot 'Discover-WindowsServer-GUI.ps1'
    if (-not (Test-Path -LiteralPath $guiPath)) {
        throw "GUI launcher not found at $guiPath. If this module was installed via Install-Module, reinstall it - the GUI script did not ship with this copy."
    }
    & $guiPath @ArgumentList
}

function Invoke-DiscoverWindowsServer {
    <#
    .SYNOPSIS
        Runs a discovery scan - the installed-module equivalent of .\Discover-WindowsServer.ps1.
    .DESCRIPTION
        Takes exactly the same parameters as Discover-WindowsServer.ps1 (mirrored at runtime from
        that script, so they never drift) and passes them straight through. Full parameter help:
        Get-Help (Join-Path (Get-Module Discover-WindowsServer).ModuleBase 'Discover-WindowsServer.ps1') -Full
    .EXAMPLE
        Invoke-DiscoverWindowsServer -Mode Deep -ProjectType Decommission -OutputRoot D:\Scans
    #>
    [CmdletBinding()]
    param()
    dynamicparam {
        $entry = Get-Command -Name (Join-Path $PSScriptRoot 'Discover-WindowsServer.ps1') -ErrorAction SilentlyContinue
        $dict = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        if (-not $entry) { return $dict }
        $common = [System.Management.Automation.Cmdlet]::CommonParameters + [System.Management.Automation.Cmdlet]::OptionalCommonParameters
        foreach ($p in $entry.Parameters.Values) {
            if ($common -contains $p.Name) { continue }
            $dict.Add($p.Name, [System.Management.Automation.RuntimeDefinedParameter]::new($p.Name, $p.ParameterType, $p.Attributes))
        }
        return $dict
    }
    end {
        $entryPath = Join-Path $PSScriptRoot 'Discover-WindowsServer.ps1'
        if (-not (Test-Path -LiteralPath $entryPath)) {
            throw "Entry script not found at $entryPath. If this module was installed via Install-Module, reinstall it."
        }
        & $entryPath @PSBoundParameters
    }
}

function Test-ModuleCommandExists {
    # Uses the loaded module's ExportedCommands map so probing for optional contract
    # functions does not pollute $Error with CommandNotFound records.
    param([string]$ModuleName, [string]$Command)
    # Filter per module and count: a collector can share its name with an OS module that
    # autoloads mid-run (Storage, ActiveDirectory). [bool] of the two-element array that
    # member enumeration returns is always $true, which made absent hooks "exist".
    try {
        return (@(Get-Module -Name $ModuleName -ErrorAction SilentlyContinue | Where-Object { $_.ExportedCommands.ContainsKey($Command) }).Count -gt 0)
    } catch { return $false }
}

# --- Preflight metadata pass -------------------------------------------------

function Get-AllModuleMetadata {
    <# Imports each module briefly to collect its metadata for the plan/selection. #>
    param([object]$Context, [string]$ModulesRoot, [string[]]$ModuleNames)
    $meta = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $ModuleNames) {
        $imported = Import-DiscoveryModuleFile -Name $name -ModulesRoot $ModulesRoot -Context $Context
        if (-not $imported) { continue }
        try {
            if (Test-ModuleCommandExists -ModuleName $name -Command 'Get-DiscoveryModuleMetadata') {
                $m = Get-DiscoveryModuleMetadata
                if ($m) { $meta.Add($m); $Context.ModuleMetadata.Add($m) }
            } else {
                Add-Limitation -Context $Context -Module $name -Message 'Module does not expose Get-DiscoveryModuleMetadata.' -Impact 'Metadata unavailable' | Out-Null
            }
        } catch {
            Write-Log -Level WARN -Message ("Metadata read failed for '{0}'." -f $name) -Module $name -Exception $_ -Context $Context
        } finally {
            Remove-DiscoveryModuleFile -Name $name
        }
    }
    return $meta
}

# --- Selection ---------------------------------------------------------------

function Resolve-ModuleSelection {
    <# Determines which collector modules run based on mode, metadata, and Include/Exclude. #>
    param(
        [object]$Context, [object[]]$Metadata, [string]$Mode,
        [string[]]$CollectorOrder, [string[]]$Include, [string[]]$Exclude,
        [object]$ModeConfig
    )
    $selected = [System.Collections.Generic.List[string]]::new()
    $metaByName = @{}
    foreach ($m in $Metadata) { $metaByName[$m.ModuleName] = $m }

    foreach ($name in $CollectorOrder) {
        $m = $metaByName[$name]
        $default = $false
        if ($m) {
            if ($Mode -eq 'Deep') { $default = [bool]$m.DefaultInDeep }
            elseif ($Mode -eq 'Fast') { $default = [bool]$m.DefaultInFast }
            else { $default = $false }  # Custom: nothing by default
        }
        if ($default) { [void]$selected.Add($name) }
    }

    # Mode config force enable/disable.
    if ($ModeConfig) {
        foreach ($fe in @($ModeConfig.forceEnableModules)) { if ($fe -and ($CollectorOrder -contains $fe) -and ($selected -notcontains $fe)) { [void]$selected.Add($fe) } }
        foreach ($fd in @($ModeConfig.forceDisableModules)) { if ($fd) { [void]$selected.Remove($fd) } }
    }

    # Explicit includes (add even if not default; valid for Fast + Custom).
    foreach ($inc in @($Include)) {
        if (-not $inc) { continue }
        if ($CollectorOrder -contains $inc) { if ($selected -notcontains $inc) { [void]$selected.Add($inc) } }
        else { Add-Limitation -Context $Context -Module $inc -Message 'IncludeModules referenced an unknown collector module.' -Impact 'Ignored' | Out-Null }
    }
    # Explicit excludes.
    foreach ($exc in @($Exclude)) { if ($exc) { [void]$selected.Remove($exc) } }

    # Preserve canonical order.
    $ordered = @($CollectorOrder | Where-Object { $selected -contains $_ })
    $Context.IncludedModules = $ordered
    $Context.ExcludedModules = @($CollectorOrder | Where-Object { $ordered -notcontains $_ })
    return $ordered
}

# --- Collector execution -----------------------------------------------------

function Invoke-CollectionWithDeadline {
    <#
        Runs a collector's Invoke-DiscoveryCollection with a deadline. Collectors run on the engine's
        own thread, so a hung cmdlet (a remote RPC that never answers, a wedged provider) used to hang
        the entire run with no way out. The collection step runs in a child runspace of the same
        process instead: $Context is shared by reference, so datasets, limitations and log lines the
        collector adds are visible to the engine. On timeout the child is abandoned (Stop is asked
        for but not waited on, because a call blocked in native code may never honour it), the module
        is reported as a limitation, and the run carries on. Returns the collector's raw result, or
        $null on timeout. TimeoutSeconds <= 0 runs inline as before.
    #>
    param([object]$Context, [string]$Name, [string]$ModulesRoot, [int]$TimeoutSeconds)
    if ($TimeoutSeconds -le 0) { return (Invoke-DiscoveryCollection -Context $Context) }
    $rs = [runspacefactory]::CreateRunspace($Host); $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($root, $name, $ctx)
        $ErrorActionPreference = 'Continue'
        foreach ($m in 'Core', 'Output') { Import-Module (Join-Path $root "$m\$m.psm1") -Force -DisableNameChecking -Global -ErrorAction Stop }
        Import-Module (Join-Path $root "$name\$name.psm1") -Force -DisableNameChecking -Global -ErrorAction Stop
        Invoke-DiscoveryCollection -Context $ctx
    }).AddArgument($ModulesRoot).AddArgument($Name).AddArgument($Context)
    $h = $ps.BeginInvoke()
    if (-not $h.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) {
        try { [void]$ps.BeginStop($null, $null) } catch { }
        Add-Limitation -Context $Context -Module $Name -Message ("Collection did not finish within {0} seconds and was abandoned; this module's data is missing or partial." -f $TimeoutSeconds) -Impact 'Module timed out' | Out-Null
        Write-Log -Level WARN -Message ("Collection exceeded the {0}s deadline and was abandoned." -f $TimeoutSeconds) -Module $Name -Context $Context
        return $null
    }
    try {
        $out = $ps.EndInvoke($h)     # rethrows a terminating error from the collector to the caller's catch
        foreach ($e in $ps.Streams.Error) { Write-Log -Level WARN -Message ("Collector error: {0}" -f $e.ToString()) -Module $Name -Context $Context }
        if ($out -and $out.Count -gt 0) { $r = $out[$out.Count - 1]; if ($null -ne $r) { return $r.PSObject.BaseObject } }
        return $null
    } finally { try { $ps.Dispose(); $rs.Dispose() } catch { } }
}

function Invoke-CollectorModule {
    <# Runs the six-function contract for one collector, isolated and defensive. #>
    param([object]$Context, [string]$Name, [string]$ModulesRoot)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'Ready'; $reason = ''; $canRun = $true; $limitations = @()
    Write-SectionStatus -Title $Name -Status 'Collecting' -Context $Context
    $imported = Import-DiscoveryModuleFile -Name $Name -ModulesRoot $ModulesRoot -Context $Context
    if (-not $imported) {
        $sw.Stop()
        Add-ModuleStatus -Context $Context -ModuleName $Name -CanRun $false -Status 'ImportFailed' -Reason 'Module could not be imported.' -Outcome 'Skipped' -DurationMs $sw.ElapsedMilliseconds | Out-Null
        return
    }
    try {
        if (Test-ModuleCommandExists -ModuleName $Name -Command 'Test-DiscoveryPrerequisites') {
            try {
                $pre = Test-DiscoveryPrerequisites -Context $Context
                if ($pre) {
                    $canRun = [bool]$pre.CanRun; $status = [string]$pre.Status; $reason = [string]$pre.Reason
                    if ($pre.Limitations) { $limitations = @($pre.Limitations) }
                    foreach ($l in $limitations) { if ($l) { Add-Limitation -Context $Context -Module $Name -Message ([string]$l) -Impact 'Prerequisite' | Out-Null } }
                }
            } catch { Write-Log -Level WARN -Message 'Prerequisite check failed.' -Module $Name -Exception $_ -Context $Context }
        }

        if ($canRun) {
            $raw = $null
            if (Test-ModuleCommandExists -ModuleName $Name -Command 'Invoke-DiscoveryCollection') {
                $deadline = 600
                try { $tv = $Context.Config.Default.defaults.moduleTimeoutSeconds; if ($null -ne $tv) { $deadline = [int]$tv } } catch { }
                try { $raw = Invoke-CollectionWithDeadline -Context $Context -Name $Name -ModulesRoot $ModulesRoot -TimeoutSeconds $deadline } catch { Write-Log -Level ERROR -Message 'Collection failed.' -Module $Name -Exception $_ -Context $Context }
            }
            if (Test-ModuleCommandExists -ModuleName $Name -Command 'ConvertTo-DiscoveryDatasets') {
                try { ConvertTo-DiscoveryDatasets -Context $Context -RawData $raw | Out-Null } catch { Write-Log -Level ERROR -Message 'Dataset conversion failed.' -Module $Name -Exception $_ -Context $Context }
            }
            if (Test-ModuleCommandExists -ModuleName $Name -Command 'Invoke-DiscoveryRiskAnalysis') {
                try { Invoke-DiscoveryRiskAnalysis -Context $Context | Out-Null } catch { Write-Log -Level WARN -Message 'Module risk analysis failed.' -Module $Name -Exception $_ -Context $Context }
            }
            if (Test-ModuleCommandExists -ModuleName $Name -Command 'Get-DiscoveryFollowUpQuestions') {
                try { Get-DiscoveryFollowUpQuestions -Context $Context | Out-Null } catch { Write-Log -Level WARN -Message 'Follow-up question generation failed.' -Module $Name -Exception $_ -Context $Context }
            }
            $outcome = 'Completed'
        } else {
            $outcome = 'Skipped'
            Write-Log -Level INFO -Message ("Skipped (prerequisites not met): {0}" -f $reason) -Module $Name -Context $Context
        }
    } catch {
        $outcome = 'Failed'
        Write-Log -Level ERROR -Message 'Unhandled module error.' -Module $Name -Exception $_ -Context $Context
    } finally {
        Remove-DiscoveryModuleFile -Name $Name
        $sw.Stop()
    }
    Add-ModuleStatus -Context $Context -ModuleName $Name -CanRun $canRun -Status $status -Reason $reason -Limitations $limitations -Outcome $outcome -DurationMs $sw.ElapsedMilliseconds | Out-Null
}

function Invoke-SynthesisModule {
    param([object]$Context, [string]$Name, [string]$ModulesRoot, [string]$EntryCommand = 'Invoke-DiscoverySynthesis')
    $imported = Import-DiscoveryModuleFile -Name $Name -ModulesRoot $ModulesRoot -Context $Context
    if (-not $imported) { return }
    try {
        if (Test-ModuleCommandExists -ModuleName $Name -Command $EntryCommand) {
            & $EntryCommand -Context $Context
        }
    } catch {
        Write-Log -Level ERROR -Message ("Synthesis module '{0}' failed." -f $Name) -Module $Name -Exception $_ -Context $Context
    } finally {
        Remove-DiscoveryModuleFile -Name $Name
    }
}

# --- Output finalization -----------------------------------------------------

function Get-OutputTargetRoot {
    <#
        Where the narrative deliverables live. Under the two-folder layout that is
        reports\supporting\, not the run root: the run root now holds README.txt and
        the two top-level folders and nothing else, so a recipient opening it is not
        confronted with thirty files and forced to guess which two matter.
        Falls back to the run root if the key is absent, so an older context object
        still produces output rather than throwing.
    #>
    param([object]$Context)
    if ($Context.Paths -and $Context.Paths.Contains('ReportsSupporting')) { return $Context.Paths['ReportsSupporting'] }
    return $Context.OutputPath
}

function Save-EvidenceLogFile {
    <# Writes a run artifact into evidence\logs\ (falling back to the run root). #>
    param([object]$Context, [string]$FileName, [string]$Content)
    $dir = if ($Context.Paths -and $Context.Paths.Contains('Logs')) { $Context.Paths['Logs'] } else { $Context.OutputPath }
    try { $Content | Out-File -LiteralPath (Join-Path $dir $FileName) -Encoding UTF8 -Force } catch { }
}

function Save-OutputCopy {
    <#
        Writes content to the supporting-deliverables folder and mirrors it into a
        themed subfolder when one is requested.

        The mirror is SKIPPED when the subfolder resolves to the same directory as the
        primary target. Under the new layout Markdown and ReportsSupporting are the same
        folder, and without this guard every markdown deliverable would be written twice
        to the same path - harmless, but it doubles the I/O and looks like a bug to the
        next person reading it.
    #>
    param([object]$Context, [string]$FileName, [string]$Content, [string]$SubfolderKey)
    $root = Get-OutputTargetRoot -Context $Context
    $primary = Join-Path $root $FileName
    try { $Content | Out-File -LiteralPath $primary -Encoding UTF8 -Force } catch { }
    if ($SubfolderKey -and $Context.Paths.Contains($SubfolderKey)) {
        $mirror = Join-Path $Context.Paths[$SubfolderKey] $FileName
        if ($mirror -ne $primary) {
            try { $Content | Out-File -LiteralPath $mirror -Encoding UTF8 -Force } catch { }
        }
    }
}

function Build-ApplicationValidationMatrix {
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($Context.DataSets.Contains('ApplicationFingerprints')) {
        foreach ($fp in @($Context.DataSets['ApplicationFingerprints'].Rows)) {
            $rows.Add([pscustomobject]@{
                Application=(Get-RowValue -Row $fp -Column 'ApplicationName'); Vendor=(Get-RowValue -Row $fp -Column 'Vendor')
                DetectedFrom=(Get-RowValue -Row $fp -Column 'EvidenceSource'); ServerPath=''; ServiceName=''; ProcessName=''
                DatabaseDependency=''; FileShareDependency=''; ServiceAccount=''; ScheduledTaskDependency=''
                IISDependency=''; CertificateDependency=''; LicenseDependency=(Get-RowValue -Row $fp -Column 'LikelyDependencyType')
                VendorSupportNeeded=''; BusinessOwner=''; ValidationContact=''
                MigrationCriticality=''; CutoverValidationSteps=''; Confidence=(Get-RowValue -Row $fp -Column 'Confidence')
            })
        }
    }
    Add-DataSet -Context $Context -Name 'ApplicationValidationMatrix' -Description 'Application validation matrix (owners/contacts blank for manual completion).' -Rows @($rows) -Visibility 'Both' -SourceModule 'Engine' | Out-Null
}

function Get-DatasetRowsOrEmpty {
    param([object]$Context, [string]$Name)
    # Unary comma prevents an empty array from unrolling to $null on return.
    if ($Context.DataSets.Contains($Name)) { return ,@($Context.DataSets[$Name].Rows) }
    return ,@()
}

function Build-ContextListDatasets {
    <# Exposes the accumulated context lists as named datasets for the workbook/CSV/JSON. #>
    param([object]$Context)
    $findRows = foreach ($f in @($Context.Findings)) {
        [pscustomobject]@{
            FindingId=$f.FindingId; Severity=$f.Severity; Confidence=$f.Confidence; Category=$f.Category; Title=$f.Title
            Subject=$f.Subject; IsEmphasized=$f.IsEmphasized; EmphasisReason=$f.EmphasisReason
            Evidence=$f.Evidence; WhyItMattersForScoping=$f.WhyItMattersForScoping
            PotentialProjectImpact=(@($f.PotentialProjectImpact) -join '; '); SuggestedValidationQuestion=$f.SuggestedValidationQuestion
            ComplianceRelevance=(@($f.ComplianceRelevance) -join '; '); SourceModule=$f.SourceModule; SourceDataset=$f.SourceDataset
        }
    }
    Add-DataSet -Context $Context -Name 'ScopingRisks' -Description 'All findings (scoping risks).' -Rows @($findRows) -Visibility 'Internal' -SourceModule 'RiskEngine' | Out-Null
    Add-DataSet -Context $Context -Name 'FollowUpQuestions' -Description 'All follow-up / validation questions.' -Rows @($Context.FollowUpQuestions | ForEach-Object { [pscustomobject]@{ Category=$_.Category; Question=$_.Question; Audience=$_.Audience; Module=$_.Module } }) -Visibility 'Both' -SourceModule 'RiskEngine' | Out-Null
    Add-DataSet -Context $Context -Name 'ScopeLanguage' -Description 'Draft scope language entries.' -Rows @($Context.ScopeLanguage | ForEach-Object { [pscustomobject]@{ Type=$_.Type; Text=$_.Text; Module=$_.Module } }) -Visibility 'Both' -SourceModule 'ScopeLanguage' | Out-Null
    Add-DataSet -Context $Context -Name 'Limitations' -Description 'Collection limitations.' -Rows @($Context.Limitations | ForEach-Object { [pscustomobject]@{ Module=$_.Module; Message=$_.Message; Impact=$_.Impact; Reason=$_.Reason } }) -Visibility 'Internal' -SourceModule 'Engine' | Out-Null
    Add-DataSet -Context $Context -Name 'UnknownsThatMatter' -Description 'Unknowns that matter for scoping.' -Rows @($Context.Unknowns | ForEach-Object { [pscustomobject]@{ Unknown=$_.Unknown; WhyItMatters=$_.WhyItMatters; Evidence=$_.Evidence; RecommendedValidationQuestion=$_.RecommendedValidationQuestion; Module=$_.Module } }) -Visibility 'Both' -SourceModule 'RiskEngine' | Out-Null
}

function Write-DiscoveryMarkdownPack {
    param([object]$Context)
    $nl = [Environment]::NewLine
    $header = { param($t) "# $t$nl$nl> Generated $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) on $($Context.ComputerName). Discovery is read-only; findings are indicators requiring human validation.$nl" }

    # summary.md + summary.txt
    $funcs = @(Get-LikelyServerFunctions -Context $Context)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine((& $header 'Discovery Summary'))
    [void]$sb.AppendLine(('- Mode: {0} | Project type: {1} | Compliance lens: {2}' -f $Context.Mode, $Context.ProjectType, $Context.ComplianceLens))
    [void]$sb.AppendLine(('- Elevated: {0} | As SYSTEM: {1} | PowerShell: {2}' -f $Context.IsAdmin, $Context.IsSystem, $Context.PowerShellVersion))
    [void]$sb.AppendLine(('- Datasets: {0} | Findings: {1} | Unknowns: {2} | Limitations: {3}' -f $Context.DataSets.Count, $Context.Findings.Count, $Context.Unknowns.Count, $Context.Limitations.Count))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Likely Server Functions')
    if ($funcs.Count -gt 0) { foreach ($f in $funcs) { [void]$sb.AppendLine("- $f") } } else { [void]$sb.AppendLine('- No definitive functions detected.') }
    [void]$sb.AppendLine('')
    $emphCount = @($Context.Findings | Where-Object { $_.IsEmphasized }).Count
    [void]$sb.AppendLine(('- Findings prioritised for project type **{0}**: {1}' -f $Context.ProjectType, $emphCount))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Findings by Severity')
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $c = @($Context.Findings | Where-Object { $_.Severity -eq $sev }).Count
        [void]$sb.AppendLine(("- {0}: {1}" -f $sev, $c))
    }
    $summaryText = $sb.ToString()
    Save-OutputCopy -Context $Context -FileName 'summary.md' -Content $summaryText -SubfolderKey 'Markdown'
    Save-OutputCopy -Context $Context -FileName 'summary.txt' -Content $summaryText

    # scoping-risks.txt
    # Sort by severity RANK, not alphabetically: 'Sort-Object Severity' yields
    # Critical, High, Info, Low, Medium - which buries Medium below Info.
    $sevRank = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3; 'Info'=4 }
    $orderedFindings = @($Context.Findings) | Sort-Object `
        @{ Expression = { if ($_.IsEmphasized) { 0 } else { 1 } } }, `
        @{ Expression = { $sevRank[$_.Severity] } }, Category
    $riskLines = foreach ($f in $orderedFindings) { "[{0}]{1} ({2}/{3}) {4} :: {5}" -f $f.FindingId, $(if($f.IsEmphasized){' [PRIORITY]'}else{''}), $f.Severity, $f.Confidence, $f.Title, $f.Evidence }
    Save-EvidenceLogFile -Context $Context -FileName 'scoping-risks.txt' -Content (($riskLines -join $nl))

    # limitations.txt -> evidence\logs\
    # Collection limitations are evidence about the RUN, not a deliverable, and they sit
    # next to the logs that explain them.
    $limLines = foreach ($l in @($Context.Limitations)) { "[{0}] {1} {2}" -f $l.Module, $l.Message, ($(if($l.Impact){"(Impact: $($l.Impact))"}else{''})) }
    Save-EvidenceLogFile -Context $Context -FileName 'limitations.txt' -Content (($limLines -join $nl))

    # errors.txt / warnings.txt are NOT written here.
    #
    # Write-Log already maintains evidence\logs\errors.txt and warnings.txt live, for the
    # whole run. Writing a second snapshot of the same content to the same folder would
    # overwrite the live file and truncate any entry logged after this point - including
    # anything that fails during report generation, which is exactly when you want the
    # error. The old flat layout got away with it only because the duplicate landed at the
    # run root instead.

    # unknowns-that-matter.md
    $u = New-Object System.Text.StringBuilder
    [void]$u.AppendLine((& $header 'Unknowns That Matter'))
    if (@($Context.Unknowns).Count -gt 0) {
        [void]$u.AppendLine((ConvertTo-MarkdownTable -Rows $Context.Unknowns -Columns @('Unknown','WhyItMatters','Evidence','RecommendedValidationQuestion')))
    } else { [void]$u.AppendLine('_No unknowns recorded._') }
    Save-OutputCopy -Context $Context -FileName 'unknowns-that-matter.md' -Content ($u.ToString()) -SubfolderKey 'Markdown'

    # follow-up-questions.md & client-interview-questions.md
    $q = New-Object System.Text.StringBuilder
    [void]$q.AppendLine((& $header 'Follow-Up Questions'))
    foreach ($grp in (@($Context.FollowUpQuestions) | Group-Object Category)) {
        [void]$q.AppendLine("## $($grp.Name)")
        foreach ($item in $grp.Group) { [void]$q.AppendLine("- $($item.Question)") }
        [void]$q.AppendLine('')
    }
    Save-OutputCopy -Context $Context -FileName 'follow-up-questions.md' -Content ($q.ToString()) -SubfolderKey 'Markdown'

    $ci = New-Object System.Text.StringBuilder
    [void]$ci.AppendLine((& $header 'Client Interview / Validation Questions'))
    [void]$ci.AppendLine('> Client-safe. Tailored to what discovery detected. Blank answers are expected to be filled in during the interview.')
    [void]$ci.AppendLine('')
    foreach ($grp in (@($Context.FollowUpQuestions | Where-Object { $_.Audience -in @('ClientSafe','Both') }) | Group-Object Category)) {
        [void]$ci.AppendLine("## $($grp.Name)")
        foreach ($item in $grp.Group) { [void]$ci.AppendLine("- $($item.Question)") }
        [void]$ci.AppendLine('')
    }
    Save-OutputCopy -Context $Context -FileName 'client-interview-questions.md' -Content ($ci.ToString()) -SubfolderKey 'Markdown'

    # draft-scope-language.md / scope-assumptions.md / scope-exclusions.md
    $assume = @($Context.ScopeLanguage | Where-Object { $_.Type -notin @('Exclusion','ChangeOrderTrigger') })
    $exclude = @($Context.ScopeLanguage | Where-Object { $_.Type -in @('Exclusion','ChangeOrderTrigger') })
    $scope = New-Object System.Text.StringBuilder
    [void]$scope.AppendLine((& $header 'Draft Scope Language'))
    [void]$scope.AppendLine('> DRAFT ONLY - requires review before use in any statement of work. Generated only where supported by findings/limitations.')
    [void]$scope.AppendLine('')
    [void]$scope.AppendLine('## Assumptions')
    foreach ($s in $assume) { [void]$scope.AppendLine("> **[$($s.Type)]** $($s.Text)"); [void]$scope.AppendLine('') }
    [void]$scope.AppendLine('## Exclusions')
    foreach ($s in $exclude) { [void]$scope.AppendLine("> **[$($s.Type)]** $($s.Text)"); [void]$scope.AppendLine('') }
    Save-OutputCopy -Context $Context -FileName 'draft-scope-language.md' -Content ($scope.ToString()) -SubfolderKey 'Markdown'

    $asm = New-Object System.Text.StringBuilder
    [void]$asm.AppendLine((& $header 'Scope Assumptions (DRAFT)'))
    foreach ($s in $assume) { [void]$asm.AppendLine("- **[$($s.Type)]** $($s.Text)") }
    Save-OutputCopy -Context $Context -FileName 'scope-assumptions.md' -Content ($asm.ToString()) -SubfolderKey 'Markdown'

    $exc = New-Object System.Text.StringBuilder
    [void]$exc.AppendLine((& $header 'Scope Exclusions (DRAFT)'))
    foreach ($s in $exclude) { [void]$exc.AppendLine("- **[$($s.Type)]** $($s.Text)") }
    Save-OutputCopy -Context $Context -FileName 'scope-exclusions.md' -Content ($exc.ToString()) -SubfolderKey 'Markdown'

    # migration-complexity.md
    $mc = New-Object System.Text.StringBuilder
    [void]$mc.AppendLine((& $header 'Migration Complexity'))
    [void]$mc.AppendLine('> Transparent rubric, not fake precision. Ratings: None / Low / Medium / High / Unknown.')
    [void]$mc.AppendLine('')
    [void]$mc.AppendLine((ConvertTo-MarkdownTable -Rows (Get-DatasetRowsOrEmpty -Context $Context -Name 'MigrationComplexity') -Columns @('Category','Rating','Evidence','WhyItMatters','SuggestedValidation')))
    Save-OutputCopy -Context $Context -FileName 'migration-complexity.md' -Content ($mc.ToString()) -SubfolderKey 'Markdown'

    # decommission-readiness.md
    $class = if ($Context.Paths.Contains('_DecommissionClassification')) { $Context.Paths['_DecommissionClassification'] } else { 'Manual validation required' }
    $dr = New-Object System.Text.StringBuilder
    [void]$dr.AppendLine((& $header 'Decommission Readiness'))
    [void]$dr.AppendLine('> This does NOT assert the server is safe to shut down. It classifies apparent dependency and lists what must be validated.')
    [void]$dr.AppendLine('')
    [void]$dr.AppendLine("## Overall Apparent Classification: **$class**")
    [void]$dr.AppendLine('')
    [void]$dr.AppendLine((ConvertTo-MarkdownTable -Rows (Get-DatasetRowsOrEmpty -Context $Context -Name 'DecommissionReadiness') -Columns @('Factor','Status','Confidence','Evidence','WhyItMatters','ValidationNeeded')))
    Save-OutputCopy -Context $Context -FileName 'decommission-readiness.md' -Content ($dr.ToString()) -SubfolderKey 'Markdown'

    # scream-test-plan.md
    # One section per detected function, NOT a table: these 10 fields are full sentences, and
    # ConvertTo-MarkdownTable rendered them as a ~1200-character-wide row that no reader could
    # follow. This is the document an engineer works through before powering a server off.
    $st = New-Object System.Text.StringBuilder
    [void]$st.AppendLine((& $header 'Scream Test Plan'))
    [void]$st.AppendLine('> Power-off test planning. Uses placeholders, not real maintenance windows. Validate before any test.')
    [void]$st.AppendLine('')
    # NOTE: Get-DatasetRowsOrEmpty returns with a unary comma to stop an empty array
    # unrolling to $null, so its result is ALREADY an array. Wrapping it in @() again
    # nests it - the foreach then iterates once over the whole inner array, and $r is
    # Object[] rather than a row. Member enumeration hides this for a single-property
    # read ($r.DetectedFunction still works) but $r.$field renders as System.Object[].
    $stRows = Get-DatasetRowsOrEmpty -Context $Context -Name 'ScreamTestPlan'
    if ($stRows.Count -eq 0) {
        [void]$st.AppendLine('_No data._')
    } else {
        [void]$st.AppendLine(('**System:** {0}' -f $stRows[0].System))
        [void]$st.AppendLine('')
        # Field -> heading. Ordered as an engineer works the test: what/why, then when, then
        # who, then what to watch for, then what closes it out.
        $stFields = [ordered]@{
            ReadinessConcern                = 'Readiness concern'
            RecommendedPowerOffTestWindow   = 'Recommended power-off test window'
            RollbackRequirement             = 'Rollback requirement'
            WhoMustValidate                 = 'Who must validate'
            WhatToMonitor                   = 'What to monitor'
            WhatWouldConstituteAScream      = 'What would constitute a scream'
            MinimumEvidenceBeforeRetirement = 'Minimum evidence before retirement'
        }
        foreach ($r in $stRows) {
            [void]$st.AppendLine(('## {0}' -f $r.DetectedFunction))
            [void]$st.AppendLine('')
            [void]$st.AppendLine(('- **Confidence:** {0}' -f $r.Confidence))
            foreach ($f in $stFields.Keys) {
                [void]$st.AppendLine(('- **{0}:** {1}' -f $stFields[$f], $r.$f))
            }
            [void]$st.AppendLine('')
        }
    }
    Save-OutputCopy -Context $Context -FileName 'scream-test-plan.md' -Content ($st.ToString()) -SubfolderKey 'Markdown'

    # licensing-validation.md
    $lic = New-Object System.Text.StringBuilder
    [void]$lic.AppendLine((& $header 'Licensing Validation'))
    [void]$lic.AppendLine('> Licensing indicators for validation only. This tool makes no legal licensing determinations.')
    [void]$lic.AppendLine('')
    $licRows = Get-DatasetRowsOrEmpty -Context $Context -Name 'Licensing'
    if (@($licRows).Count -gt 0) { [void]$lic.AppendLine((ConvertTo-MarkdownTable -Rows $licRows)) } else { [void]$lic.AppendLine('_No licensing dataset was produced._') }
    [void]$lic.AppendLine('')
    [void]$lic.AppendLine('## Licensing-Related Findings')
    $licFindings = @($Context.Findings | Where-Object { $_.Category -eq 'Licensing' })
    if ($licFindings.Count -gt 0) { foreach ($f in $licFindings) { [void]$lic.AppendLine("- **$($f.Title)** - $($f.Evidence)") } } else { [void]$lic.AppendLine('_No licensing findings._') }
    Save-OutputCopy -Context $Context -FileName 'licensing-validation.md' -Content ($lic.ToString()) -SubfolderKey 'Markdown'

    # vendor-dependencies.md
    $ven = New-Object System.Text.StringBuilder
    [void]$ven.AppendLine((& $header 'Vendor Dependencies'))
    $venRows = Get-DatasetRowsOrEmpty -Context $Context -Name 'VendorAgents'
    if (@($venRows).Count -gt 0) { [void]$ven.AppendLine((ConvertTo-MarkdownTable -Rows $venRows)) } else { [void]$ven.AppendLine('_No vendor agents detected or module not run._') }
    Save-OutputCopy -Context $Context -FileName 'vendor-dependencies.md' -Content ($ven.ToString()) -SubfolderKey 'Markdown'

    # downtime-cutover-considerations.md
    $dc = New-Object System.Text.StringBuilder
    [void]$dc.AppendLine((& $header 'Downtime / Cutover Considerations'))
    $cutFindings = @($Context.Findings | Where-Object { @($_.PotentialProjectImpact) -contains 'Cutover Complexity' -or @($_.PotentialProjectImpact) -contains 'Downtime' })
    if ($cutFindings.Count -gt 0) {
        foreach ($f in $cutFindings) { [void]$dc.AppendLine("- **[$($f.Severity)] $($f.Title)** - $($f.WhyItMattersForScoping)") }
    } else { [void]$dc.AppendLine('_No specific downtime/cutover-sensitive findings were identified._') }
    Save-OutputCopy -Context $Context -FileName 'downtime-cutover-considerations.md' -Content ($dc.ToString()) -SubfolderKey 'Markdown'
}

function Write-SpecialCsvOutputs {
    param([object]$Context)
    $root = Get-OutputTargetRoot -Context $Context
    $delim = Get-CsvDelimiter -Context $Context
    try { Write-ObjectListToCsv -Rows (Get-DatasetRowsOrEmpty -Context $Context -Name 'DependencyGraph') -Path (Join-Path $root 'dependency-graph.csv') -Delimiter $delim -Columns @('SourceType','SourceName','DependencyType','Target','Evidence','Confidence','SourceDataset','ProjectImpact','ValidationQuestion') | Out-Null } catch { }
    try { Write-ObjectListToCsv -Rows (Get-DatasetRowsOrEmpty -Context $Context -Name 'WbsInputs') -Path (Join-Path $root 'wbs-inputs.csv') -Delimiter $delim -Columns @('Finding','Subject','PriorityForProject','SuggestedWBSArea','LaborDriver','Complexity','Evidence','SuggestedScopeNote','ValidationQuestion') | Out-Null } catch { }
    try { Write-ObjectListToCsv -Rows (Get-DatasetRowsOrEmpty -Context $Context -Name 'ApplicationValidationMatrix') -Path (Join-Path $root 'application-validation-matrix.csv') -Delimiter $delim | Out-Null } catch { }
}

function Write-ClientSafeSummary {
    param([object]$Context)
    $funcs = @(Get-LikelyServerFunctions -Context $Context)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Server Discovery - Client Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("> Plain-English summary of what we found on **$($Context.ComputerName)**. This is for planning and validation. Please review and correct anything that looks wrong.")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## What this server appears to do')
    if ($funcs.Count -gt 0) { foreach ($f in $funcs) { [void]$sb.AppendLine("- $f") } } else { [void]$sb.AppendLine('- We could not automatically determine a primary role. Please help us confirm what this server is used for.') }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Questions we need your help to answer')
    foreach ($grp in (@($Context.FollowUpQuestions | Where-Object { $_.Audience -in @('ClientSafe','Both') }) | Group-Object Category)) {
        [void]$sb.AppendLine("**$($grp.Name)**")
        foreach ($item in $grp.Group) { [void]$sb.AppendLine("- $($item.Question)") }
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('## Migration / decommission considerations')
    $class = if ($Context.Paths.Contains('_DecommissionClassification')) { $Context.Paths['_DecommissionClassification'] } else { 'Manual validation required' }
    [void]$sb.AppendLine("- Apparent dependency level: **$class** (indicator only - not a recommendation to shut anything off).")
    [void]$sb.AppendLine('- Any migration or shutdown should be validated with the owners/vendors of the systems above.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Known limitations of this discovery')
    if (-not $Context.IsAdmin) { [void]$sb.AppendLine('- Discovery was not run with full administrative rights, so some details may be incomplete.') }
    if ($Context.Mode -eq 'Fast') { [void]$sb.AppendLine('- This was a Fast scan focused on scoping; deeper analysis is available if needed.') }
    [void]$sb.AppendLine('- Warranty, licensing entitlement, and vendor support status cannot be confirmed from the server itself.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Suggested client action items')
    [void]$sb.AppendLine('- Identify a business owner and validation contact for each key application above.')
    [void]$sb.AppendLine('- Confirm backup coverage and the last successful restore test.')
    [void]$sb.AppendLine('- Answer the questions above so we can scope accurately.')
    Save-OutputCopy -Context $Context -FileName 'client-safe-summary.md' -Content ($sb.ToString()) -SubfolderKey 'ClientSafe'
}

function Write-CollectionMetadata {
    param([object]$Context)
    # Resolved effective parameters, sorted by name. These are what make a run reproducible:
    # the CLI value, mode config, global config and built-in fallback have all already been
    # collapsed into a single value by Resolve-EffValue, and nothing else records the result.
    $effective = [ordered]@{}
    if ($Context.Parameters) {
        foreach ($k in @($Context.Parameters.Keys | Sort-Object)) { $effective[[string]$k] = $Context.Parameters[$k] }
    }
    $meta = [ordered]@{
        RunId=$Context.RunId; ComputerName=$Context.ComputerName; Mode=$Context.Mode
        ProjectType=$Context.ProjectType; ComplianceLens=$Context.ComplianceLens
        StartTime=$Context.StartTime.ToString('o'); EndTime=(Get-Date).ToString('o')
        DurationSeconds=[math]::Round(((Get-Date) - $Context.StartTime).TotalSeconds,1)
        PowerShellVersion=$Context.PowerShellVersion; IsAdmin=$Context.IsAdmin; IsSystem=$Context.IsSystem
        EffectiveParameters=$effective
        IncludedModules=@($Context.IncludedModules); ExcludedModules=@($Context.ExcludedModules)
        ModuleStatuses=@($Context.ModuleStatuses)
        Datasets=@($Context.DataSets.Keys | ForEach-Object { [ordered]@{ Name=$_; Rows=$Context.DataSets[$_].RowCount; Visibility=$Context.DataSets[$_].Visibility } })
        Counters=$Context.Counters
    }
    # Run provenance belongs with the evidence, not with the deliverables.
    $metaDir = if ($Context.Paths.Contains('EvidenceRoot')) { $Context.Paths['EvidenceRoot'] } else { $Context.OutputPath }
    try { ($meta | ConvertTo-Json -Depth 8) | Out-File -LiteralPath (Join-Path $metaDir 'collection-metadata.json') -Encoding UTF8 -Force } catch { }
}

function Write-ReadmeFile {
    param([object]$Context)
    $class = if ($Context.Paths.Contains('_DecommissionClassification')) { $Context.Paths['_DecommissionClassification'] } else { 'Manual validation required' }
    $txt = @"
Windows Server Discovery Toolkit - Output
=========================================

Run ID        : $($Context.RunId)
Computer      : $($Context.ComputerName)
Mode          : $($Context.Mode)
Project type  : $($Context.ProjectType)
Generated     : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Apparent dependency classification : $class

Read-only discovery output for scoping and planning. Every finding is an INDICATOR
that requires human validation. No compliance certification is asserted, and nothing
on the server was changed.

THERE ARE TWO THINGS TO READ. Both are in reports\.

  reports\internal-engineering-report.html   <- START HERE (internal use only)
      Full engineering detail: every finding with its evidence, the dependency map,
      migration complexity, decommission readiness, WBS inputs and draft scope
      language. Contains service accounts, paths, ports and certificate subjects.
      Reads start to finish - the one to print or hand to someone reading through.
      DO NOT SEND THIS TO THE CLIENT.

  reports\internal-dashboard-report.html     <- SAME DATA, for on-screen use (internal only)
      Identical findings and datasets as the file above, in a sidebar-navigated,
      scrollable/filterable layout instead of one long page. Jump straight to a
      severity band or a dataset section instead of scrolling past everything else.

  reports\client-discovery-report.html       <- SEND THIS TO THE CLIENT
      Plain-English summary of what the server does, what depends on it, what is
      worth their attention, and the questions only they can answer. Built solely
      from client-safe datasets; no evidence strings, accounts, paths or ports.

The internal engineering report also exists as .md, and the client report as .md too,
for pasting into tickets, PSA notes and scoping documents.

FOLDER LAYOUT
-------------
  reports\
      internal-engineering-report.html / .md   Internal deliverable
      internal-dashboard-report.html           Internal deliverable, interactive
      client-discovery-report.html / .md       Client deliverable
      supporting\                              Everything the reports draw on:
          summary.md / summary.txt
          decommission-readiness.md, scream-test-plan.md
          migration-complexity.md, downtime-cutover-considerations.md
          draft-scope-language.md, scope-assumptions.md, scope-exclusions.md
          client-interview-questions.md, follow-up-questions.md
          unknowns-that-matter.md, licensing-validation.md, vendor-dependencies.md
          dependency-graph.csv, wbs-inputs.csv, application-validation-matrix.csv
          workbook.xml                         All datasets, opens in Excel
          client-safe\, internal\              Audience-scoped copies

  evidence\
      collection-metadata.json                 What ran, with what resolved settings
      discovery-plan.md                        What the toolkit intended to do
      data\csv\, data\json\                   Every dataset, one file per dataset
      logs\                                    summary / errors / warnings / debug,
                                               plus limitations.txt and scoping-risks.txt
      raw\                                     Raw captures (only when requested)
      status\                                  Live status JSON written during the run
      manifest\                                SHA256 evidence manifest
                                               (only with -GenerateEvidenceManifest)

  archive\                                     ZIP of the whole run (unless -SkipZip)

HANDLING
--------
This output is client data. It describes real infrastructure. Treat the run folder as
confidential, and send only reports\client-discovery-report.html outside your team.
"@
    Save-OutputCopy -Context $Context -FileName 'README.txt' -Content $txt
    # README belongs at the run root as well - it is the map, and a map filed inside
    # one of the folders it describes is no use to whoever opens the run folder first.
    try { $txt | Out-File -LiteralPath (Join-Path $Context.OutputPath 'README.txt') -Encoding UTF8 -Force } catch { }
}

function Write-DiscoveryOutputs {
    <# Produces every required artifact. Runs after collection + synthesis. #>
    param([object]$Context)
    Write-SectionStatus -Title 'Generating outputs' -Context $Context

    # Internal engineering report (HTML) -> reports\internal-engineering-report.html
    # Renamed from internal-report.html so the filename itself states the audience; a
    # file called 'internal-report' has been emailed to a client before now.
    $reportDir = if ($Context.Paths.Contains('Reports')) { $Context.Paths['Reports'] } else { $Context.OutputPath }
    $htmlRoot = Join-Path $reportDir 'internal-engineering-report.html'
    try { Write-HtmlReport -Context $Context -Path $htmlRoot | Out-Null } catch { Write-Log -Level ERROR -Message 'HTML report generation failed.' -Module 'Engine' -Exception $_ -Context $Context }
    if ($Context.Paths.Contains('Internal')) {
        try { Copy-Item -LiteralPath $htmlRoot -Destination (Join-Path $Context.Paths['Internal'] 'internal-engineering-report.html') -Force -ErrorAction SilentlyContinue } catch { }
    }

    # Interactive companion to the report above - same data (Get-InternalReportModel), a
    # sidebar nav + scrollable/filterable tables instead of one long scroll. For on-screen
    # reference; the plain report above is still the one to print or read straight through.
    $dashboardRoot = Join-Path $reportDir 'internal-dashboard-report.html'
    try { Write-DashboardHtmlReport -Context $Context -Path $dashboardRoot | Out-Null } catch { Write-Log -Level ERROR -Message 'Dashboard HTML report generation failed.' -Module 'Engine' -Exception $_ -Context $Context }
    if ($Context.Paths.Contains('Internal')) {
        try { Copy-Item -LiteralPath $dashboardRoot -Destination (Join-Path $Context.Paths['Internal'] 'internal-dashboard-report.html') -Force -ErrorAction SilentlyContinue } catch { }
    }

    # Workbook -> root
    $wbHeader = '#D9EAF7'; $wbFont='Calibri'; $wbSize=11
    if ($Context.Config -and $Context.Config.Output -and $Context.Config.Output.workbook) {
        if ($Context.Config.Output.workbook.headerColorHex) { $wbHeader = $Context.Config.Output.workbook.headerColorHex }
        if ($Context.Config.Output.workbook.fontName) { $wbFont = $Context.Config.Output.workbook.fontName }
        if ($Context.Config.Output.workbook.fontSize) { $wbSize = [int]$Context.Config.Output.workbook.fontSize }
    }
    try { Write-ExcelXmlWorkbook -Context $Context -Path (Join-Path (Get-OutputTargetRoot -Context $Context) 'workbook.xml') -HeaderColor $wbHeader -FontName $wbFont -FontSize $wbSize | Out-Null } catch { Write-Log -Level ERROR -Message 'Workbook generation failed.' -Module 'Engine' -Exception $_ -Context $Context }

    # Per-dataset CSV/JSON
    try { Export-DiscoveryDatasets -Context $Context | Out-Null } catch { Write-Log -Level WARN -Message 'Dataset export failed.' -Module 'Engine' -Exception $_ -Context $Context }

    # Special CSVs + markdown pack + client-safe + metadata + readme
    try { Write-SpecialCsvOutputs -Context $Context } catch { Write-Log -Level WARN -Message 'Special CSV outputs failed.' -Module 'Engine' -Exception $_ -Context $Context }
    try { Write-DiscoveryMarkdownPack -Context $Context } catch { Write-Log -Level WARN -Message 'Markdown pack failed.' -Module 'Engine' -Exception $_ -Context $Context }
    try { Write-ClientSafeSummary -Context $Context } catch { Write-Log -Level WARN -Message 'Client-safe summary failed.' -Module 'Engine' -Exception $_ -Context $Context }
    try { Write-CollectionMetadata -Context $Context } catch { Write-Log -Level WARN -Message 'Collection metadata failed.' -Module 'Engine' -Exception $_ -Context $Context }
    try { Write-ReadmeFile -Context $Context } catch { }
}

# --- Top-level driver --------------------------------------------------------

function Invoke-Discovery {
    <# Main driver. Expects a fully prepared context (folders + log paths + config). #>
    param([Parameter(Mandatory)][object]$Context)

    $modulesRoot = Join-Path $PSScriptRoot 'modules'
    $cfg = $Context.Config
    $collectorOrder = @()
    $synthesisOrder = @('RiskEngine','DecommissionReadiness','ScopeLanguage','ClientInterviewPack')
    if ($cfg -and $cfg.Default) {
        if ($cfg.Default.collectorModuleOrder) { $collectorOrder = @($cfg.Default.collectorModuleOrder) }
        if ($cfg.Default.synthesisModules) { $synthesisOrder = @($cfg.Default.synthesisModules | Where-Object { $_ -ne 'EvidenceManifest' }) }
    }
    if ($collectorOrder.Count -eq 0) {
        $collectorOrder = @('SystemInventory','RolesFeatures','ServicesTasks','Applications','Network','Storage','FileShares','SecurityPosture','ActiveDirectory','DNS','DHCP','IIS','SQL','HyperV','Cluster','RDS','NPS_RADIUS','Certificates','BackupDR','PrintServer','ConfigDependencyScan','Licensing','VendorAgents','PerformanceSnapshot','EventLogs')
    }

    Write-Log -Level INFO -Message ("Discovery started. RunId={0} Mode={1} ProjectType={2}" -f $Context.RunId, $Context.Mode, $Context.ProjectType) -Module 'Engine' -Context $Context

    # Preflight: gather metadata for collectors + synthesis (for plan).
    Update-StatusFile -Context $Context -Phase 'Preflight' -TotalModules $collectorOrder.Count
    # ReportBuilder and EvidenceManifest run outside the ordinary synthesis list (both
    # need the output files to already exist), but their metadata still belongs in the
    # plan - a module that runs and is not listed is how a plan stops being trustworthy.
    $allForMeta = @($collectorOrder) + @($synthesisOrder) + @('ReportBuilder','EvidenceManifest')
    $metadata = Get-AllModuleMetadata -Context $Context -ModulesRoot $modulesRoot -ModuleNames $allForMeta

    # Selection.
    $modeConfig = if ($Context.Mode -eq 'Deep') { $cfg.Deep } elseif ($Context.Mode -eq 'Fast') { $cfg.Fast } else { $null }
    $include = @(); $exclude = @()
    if ($Context.Parameters.ContainsKey('IncludeModules') -and $Context.Parameters['IncludeModules']) { $include = @($Context.Parameters['IncludeModules']) }
    if ($Context.Parameters.ContainsKey('ExcludeModules') -and $Context.Parameters['ExcludeModules']) { $exclude = @($Context.Parameters['ExcludeModules']) }
    # -IncludeConfigDependencyScan explicitly enables the config scan even in Fast mode.
    if ($Context.Parameters['IncludeConfigDependencyScan'] -and ($include -notcontains 'ConfigDependencyScan')) { $include = @($include) + 'ConfigDependencyScan' }
    $selected = Resolve-ModuleSelection -Context $Context -Metadata $metadata -Mode $Context.Mode -CollectorOrder $collectorOrder -Include $include -Exclude $exclude -ModeConfig $modeConfig

    # Discovery plan (before collectors).
    $planDir = if ($Context.Paths.Contains('EvidenceRoot')) { $Context.Paths['EvidenceRoot'] } else { $Context.OutputPath }
    $planPath = Join-Path $planDir 'discovery-plan.md'
    try { Write-DiscoveryPlan -Context $Context -Path $planPath } catch { Write-Log -Level WARN -Message 'Discovery plan generation failed.' -Module 'Engine' -Exception $_ -Context $Context }

    # -WhatIf: show exactly what would run and stop here. No collector executes, so nothing on
    # the server is touched beyond the plan file itself - useful to show a client before a real run.
    if ($Context.Parameters.ContainsKey('WhatIf') -and $Context.Parameters['WhatIf']) {
        Write-Log -Level INFO -Message 'WhatIf: stopping after the plan - no collector will run.' -Module 'Engine' -Context $Context
        if (-not $Context.Quiet) {
            Write-Host ''
            Write-Host ('=== WhatIf: {0} module(s) would run, {1} would be skipped ===' -f @($Context.IncludedModules).Count, @($Context.ExcludedModules).Count) -ForegroundColor Cyan
            foreach ($name in $Context.IncludedModules) { Write-Host ("  [run]     {0}" -f $name) -ForegroundColor Green }
            foreach ($name in $Context.ExcludedModules) { Write-Host ("  [skip]    {0}" -f $name) -ForegroundColor DarkGray }
            Write-Host ''
            Write-Host ("Full plan: {0}" -f $planPath) -ForegroundColor Cyan
        }
        $Context.EndTime = Get-Date
        Update-StatusFile -Context $Context -Phase 'Complete' -CompletedModules 0 -TotalModules @($selected).Count
        return
    }

    # Collection phase.
    $total = @($selected).Count; $done = 0
    foreach ($name in $selected) {
        Update-StatusFile -Context $Context -Phase 'Collecting' -CurrentModule $name -CompletedModules $done -TotalModules $total
        Invoke-CollectorModule -Context $Context -Name $name -ModulesRoot $modulesRoot
        $done++
        Update-StatusFile -Context $Context -Phase 'Collecting' -CurrentModule $name -CompletedModules $done -TotalModules $total
    }

    # Application fingerprint matching. Must sit between collection and synthesis: its
    # matchers reference datasets from modules that run after Applications (ListeningPorts,
    # IisSites, SqlInstances), and its output (ApplicationFingerprints) is read by the
    # RiskEngine, so it cannot be deferred into the synthesis list either.
    if ($selected -contains 'Applications') {
        Invoke-SynthesisModule -Context $Context -Name 'Applications' -ModulesRoot $modulesRoot -EntryCommand 'Invoke-DiscoveryFingerprintSynthesis'
    }

    # Synthesis phase (RiskEngine first).
    Update-StatusFile -Context $Context -Phase 'Synthesis' -CompletedModules $done -TotalModules $total
    foreach ($name in $synthesisOrder) { Invoke-SynthesisModule -Context $Context -Name $name -ModulesRoot $modulesRoot }
    try { Build-ApplicationValidationMatrix -Context $Context } catch { }
    try { Build-ContextListDatasets -Context $Context } catch { Write-Log -Level WARN -Message 'Context list dataset build failed.' -Module 'Engine' -Exception $_ -Context $Context }

    # Output generation.
    Update-StatusFile -Context $Context -Phase 'Output' -CompletedModules $done -TotalModules $total
    Write-DiscoveryOutputs -Context $Context

    # Report build. Deliberately AFTER Write-DiscoveryOutputs: the two finished reports
    # index the supporting pack and the per-dataset exports, so those files have to
    # exist before the reports claim they do. It is also why ReportBuilder is not in the
    # ordinary synthesis list - synthesis runs before output generation.
    Update-StatusFile -Context $Context -Phase 'Reporting' -CompletedModules $done -TotalModules $total
    Invoke-SynthesisModule -Context $Context -Name 'ReportBuilder' -ModulesRoot $modulesRoot -EntryCommand 'Invoke-DiscoveryReportBuild'

    # Evidence manifest (last; only if requested).
    if ($Context.Parameters.ContainsKey('GenerateEvidenceManifest') -and $Context.Parameters['GenerateEvidenceManifest']) {
        Invoke-SynthesisModule -Context $Context -Name 'EvidenceManifest' -ModulesRoot $modulesRoot -EntryCommand 'Invoke-DiscoveryEvidenceManifest'
    }

    # ZIP archive (unless SkipZip).
    $skipZip = ($Context.Parameters.ContainsKey('SkipZip') -and $Context.Parameters['SkipZip'])
    if (-not $skipZip) {
        Update-StatusFile -Context $Context -Phase 'Archiving' -CompletedModules $done -TotalModules $total
        $zipName = ("Discover-WindowsServer_{0}_{1}.zip" -f $Context.ComputerName, $Context.StartTime.ToString('yyyyMMdd_HHmmss'))
        $zipPath = Join-Path $Context.Paths['Archive'] $zipName
        # Compress-Folder fails soft (returns $false) rather than throwing, so a real failure
        # must be checked explicitly here or it never reaches errors.txt/warnings.txt at all.
        $zipOk = Compress-Folder -SourceFolder $Context.OutputPath -DestinationZip $zipPath -ExcludeChildFolders @('archive')
        if (-not $zipOk) {
            $zipErr = Get-CompressFolderLastError
            Write-Log -Level WARN -Message ("Archive creation failed.{0}" -f $(if ($zipErr) { " $zipErr" } else { '' })) -Module 'Engine' -Context $Context
        }
    }

    $Context.EndTime = Get-Date
    Update-StatusFile -Context $Context -Phase 'Complete' -CompletedModules $done -TotalModules $total
    Write-Log -Level INFO -Message ("Discovery complete in {0}s. Findings={1} Datasets={2} Limitations={3}" -f ([math]::Round(($Context.EndTime-$Context.StartTime).TotalSeconds,1)), $Context.Findings.Count, $Context.DataSets.Count, $Context.Limitations.Count) -Module 'Engine' -Context $Context

    if (-not $Context.Quiet) {
        Write-Host ''
        Write-Host ('Discovery complete. Output: {0}' -f $Context.OutputPath) -ForegroundColor Green
        Write-Host ('  Findings: {0} | Datasets: {1} | Limitations: {2} | Errors: {3}' -f $Context.Findings.Count, $Context.DataSets.Count, $Context.Limitations.Count, $Context.Counters.Errors) -ForegroundColor Green
    }
    return $Context
}

Export-ModuleMember -Function `
    'Invoke-Discovery','Get-AllModuleMetadata','Resolve-ModuleSelection','Invoke-CollectorModule', `
    'Invoke-SynthesisModule','Write-DiscoveryOutputs','Import-DiscoveryModuleFile','Remove-DiscoveryModuleFile', `
    'Build-ApplicationValidationMatrix','Build-ContextListDatasets','Get-OutputTargetRoot','Save-EvidenceLogFile', `
    'Start-DiscoverWindowsServerGui','Invoke-DiscoverWindowsServer'
