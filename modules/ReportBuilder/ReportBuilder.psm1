<#
    ReportBuilder.psm1
    Builds the two finished deliverables that a run is judged on:

      reports\internal-engineering-report.md    - the full internal narrative
      reports\client-discovery-report.html/.md  - the client-facing document

    The internal HTML report (and its interactive dashboard companion) are still produced by
    Output.psm1's Write-HtmlReport / Write-DashboardHtmlReport; this module adds the internal
    report's Markdown twin (for pasting into tickets, PSA notes and SOW drafts) and owns the
    client deliverable end to end.

    CLIENT-SAFETY RULE, and it is absolute: the client report may only ever read
    datasets whose Visibility is 'ClientSafe' or 'Both', and questions whose
    Audience is 'ClientSafe' or 'Both'. It never renders a finding's raw Evidence
    string, because evidence carries service accounts, paths, ports and
    certificate subjects. Client-facing text is derived from the finding's Title
    and WhyItMattersForScoping, both of which are authored, not collected.

    Everything here is presentation. No collection, no mutation of the context
    beyond adding the two report datasets used to index the output.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'ReportBuilder'
        DisplayName               = 'Report Builder (internal + client deliverables)'
        Category                  = 'Synthesis'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Minimal'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('ReportIndex')
        ProducesRisks             = $false
        ProducesFollowUpQuestions = $false
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $true
        IsSynthesis               = $true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='ReportBuilder'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

#region helpers ---------------------------------------------------------------

function Get-RbRows {
    <# Unary comma so an empty dataset stays an empty ARRAY instead of unrolling to $null. #>
    param([object]$Context, [string]$Name)
    if ($Context.DataSets.Contains($Name)) { return ,@($Context.DataSets[$Name].Rows) }
    return ,@()
}

function Test-RbClientSafeDataset {
    param([object]$Context, [string]$Name)
    if (-not $Context.DataSets.Contains($Name)) { return $false }
    return ((@($Context.DataSets[$Name].Rows).Count -gt 0) -and ($Context.DataSets[$Name].Visibility -in @('ClientSafe','Both')))
}

function Get-RbDecommissionClass {
    param([object]$Context)
    if ($Context.Paths.Contains('_DecommissionClassification')) { return [string]$Context.Paths['_DecommissionClassification'] }
    return 'Manual validation required'
}

function Get-RbSeverityOrderedFindings {
    param([object]$Context)
    $rank = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3; 'Info'=4 }
    return @(@($Context.Findings) | Sort-Object `
        @{ Expression = { if ($_.IsEmphasized) { 0 } else { 1 } } }, `
        @{ Expression = { $rank[$_.Severity] } }, Category, Title)
}

function Get-RbClientHeadlines {
    <#
        Turns findings into plain-English "things worth knowing" for the client
        report. Deliberately conservative:
          - severity High/Critical only, so the client document is short enough
            to actually be read;
          - Title + WhyItMattersForScoping only - never Evidence;
          - deduplicated by Title, because per-row rules (one finding per service,
            per certificate, per share) would otherwise produce forty near-identical
            lines and bury the three that matter.
    #>
    param([object]$Context)
    $out = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($f in (Get-RbSeverityOrderedFindings -Context $Context)) {
        if ($f.Severity -notin @('Critical','High')) { continue }
        if ([string]::IsNullOrWhiteSpace($f.Title)) { continue }
        if (-not $seen.Add([string]$f.Title)) { continue }
        $out.Add([pscustomobject]@{
            Topic    = [string]$f.Category
            WhatWeFound = [string]$f.Title
            WhyItMatters = [string]$f.WhyItMattersForScoping
            WhatWeNeed   = [string]$f.SuggestedValidationQuestion
        })
    }
    return ,@($out)
}

function ConvertTo-RbHtmlEncoded {
    param([AllowNull()]$Value)
    return [System.Net.WebUtility]::HtmlEncode((ConvertTo-DisplayString -Value $Value))
}

function Get-RbClientCss {
    <# Client deliverable styling: deliberately calmer than the internal report. #>
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
ul{margin:12px 0;padding-left:22px}
li{margin:7px 0}
table{border-collapse:collapse;width:100%;margin:16px 0;font-size:14px}
th,td{border:1px solid var(--line);padding:9px 11px;text-align:left;vertical-align:top}
th{background:var(--soft);font-weight:600}
.lead{font-size:16px;color:var(--muted)}
.callout{border-left:4px solid var(--accent);background:var(--soft);padding:14px 18px;margin:18px 0;border-radius:0 6px 6px 0}
.facts{display:flex;flex-wrap:wrap;gap:14px;margin:20px 0}
.fact{flex:1;min-width:160px;border:1px solid var(--line);border-radius:8px;padding:14px 16px;background:#fff;text-align:center}
.fact .l{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.fact .v{font-size:17px;font-weight:600;color:var(--accent);margin-top:4px;word-break:break-word}
.qbox{border:1px solid var(--line);border-radius:8px;padding:6px 18px 14px;margin:14px 0}
.muted{color:var(--muted);font-size:13px}
footer{max-width:940px;margin:30px auto 0;padding:18px 40px 40px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
@media print{header{background:#fff;color:var(--accent);border-bottom:3px solid var(--accent)}main{padding:0 12px}}
'@
    return ($css -replace '__ACCENT__', $AccentColorHex)
}

function Get-RbLogoHtml {
    <# <img> tag for a report header, or '' when no logo is configured. Shared by both HTML writers below. #>
    param([object]$Branding)
    if (-not $Branding.LogoDataUri) { return '' }
    return ('<img src="{0}" alt="{1}" class="brand-logo">' -f $Branding.LogoDataUri, (ConvertTo-RbHtmlEncoded -Value $Branding.Brand))
}

#endregion

#region internal markdown report ----------------------------------------------

function Write-InternalMarkdownReport {
    <#
        The internal report as a single Markdown document. Same material as the HTML
        report, in a form that pastes into a ticket or a scoping document.
    #>
    param([object]$Context, [string]$Path)

    $sb = New-Object System.Text.StringBuilder
    $findings = Get-RbSeverityOrderedFindings -Context $Context
    $counts = @{}
    foreach ($s in @('Critical','High','Medium','Low','Info')) { $counts[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }
    $funcs = @(Get-LikelyServerFunctions -Context $Context)
    $brand = (Get-DiscoveryBranding -Context $Context).Brand

    [void]$sb.AppendLine('# Internal Engineering Report')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('**{0}** &middot; **{1}** &middot; generated {2}' -f $brand, $Context.ComputerName, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> INTERNAL USE ONLY. Contains service accounts, paths, ports, certificate subjects and other infrastructure detail. Do not send to the client - send `client-discovery-report.html` instead.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> Discovery is read-only. Every finding is an INDICATOR requiring human validation. No compliance certification is asserted.')
    [void]$sb.AppendLine('')

    # --- 1. Run context
    [void]$sb.AppendLine('## 1. Run context and data quality')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('- **Run ID:** {0}' -f $Context.RunId))
    [void]$sb.AppendLine(('- **Mode:** {0} &middot; **Project type:** {1} &middot; **Compliance lens:** {2}' -f $Context.Mode, $Context.ProjectType, $Context.ComplianceLens))
    [void]$sb.AppendLine(('- **Elevated:** {0} &middot; **Running as SYSTEM:** {1} &middot; **PowerShell:** {2}' -f $Context.IsAdmin, $Context.IsSystem, $Context.PowerShellVersion))
    [void]$sb.AppendLine(('- **Datasets:** {0} &middot; **Findings:** {1} &middot; **Unknowns:** {2} &middot; **Limitations:** {3}' -f $Context.DataSets.Count, $Context.Findings.Count, $Context.Unknowns.Count, $Context.Limitations.Count))
    [void]$sb.AppendLine('')
    if (-not $Context.IsAdmin) { [void]$sb.AppendLine('> **Confidence caveat:** this run was NOT elevated. Security posture, event log and several registry/CIM reads are incomplete, so absence of a finding is weak evidence here.'); [void]$sb.AppendLine('') }
    if ($Context.IsSystem)     { [void]$sb.AppendLine('> **Confidence caveat:** this run executed as SYSTEM. User-context dependencies may be under-reported.'); [void]$sb.AppendLine('') }
    if ($Context.Mode -eq 'Fast') { [void]$sb.AppendLine('> **Coverage caveat:** Fast mode. The deep share crawl and config dependency scan did not run unless explicitly enabled.'); [void]$sb.AppendLine('') }

    # --- 2. What this server is
    [void]$sb.AppendLine('## 2. What this server appears to be')
    [void]$sb.AppendLine('')
    if ($funcs.Count -gt 0) { foreach ($f in $funcs) { [void]$sb.AppendLine(('- {0}' -f $f)) } }
    else { [void]$sb.AppendLine('- No definitive role was detected from the collected data. Treat the role as unknown and validate with the client.') }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('**Apparent dependency classification:** {0} (indicator only - not a recommendation to power anything off).' -f (Get-RbDecommissionClass -Context $Context)))
    [void]$sb.AppendLine('')

    # --- 3. Priority findings
    $emph = @($findings | Where-Object { $_.IsEmphasized })
    [void]$sb.AppendLine(('## 3. Priority for this project type ({0})' -f $Context.ProjectType))
    [void]$sb.AppendLine('')
    if ($emph.Count -gt 0) {
        [void]$sb.AppendLine(('{0} finding(s) are flagged as especially relevant to a **{1}** project. Severity is unchanged - this is prioritisation, not escalation.' -f $emph.Count, $Context.ProjectType))
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $emph -Columns @('FindingId','Severity','Category','Title','Subject')))
    } else {
        [void]$sb.AppendLine('_No findings carried a project-type emphasis. Re-run with a specific `-ProjectType` to surface what matters most for that kind of project._')
    }
    [void]$sb.AppendLine('')

    # --- 4. Findings
    [void]$sb.AppendLine('## 4. Findings')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('Severity distribution: Critical {0} &middot; High {1} &middot; Medium {2} &middot; Low {3} &middot; Info {4}' -f $counts['Critical'], $counts['High'], $counts['Medium'], $counts['Low'], $counts['Info']))
    [void]$sb.AppendLine('')
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $group = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($group.Count -eq 0) { continue }
        [void]$sb.AppendLine(('### {0} severity ({1})' -f $sev, $group.Count))
        [void]$sb.AppendLine('')
        foreach ($f in $group) {
            $flag = if ($f.IsEmphasized) { ' **[PRIORITY]**' } else { '' }
            [void]$sb.AppendLine(('#### {0}{1} - {2}' -f $f.FindingId, $flag, $f.Title))
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine(('- **Category / confidence:** {0} / {1}' -f $f.Category, $f.Confidence))
            if ($f.Subject)                     { [void]$sb.AppendLine(('- **Subject:** {0}' -f $f.Subject)) }
            if ($f.Evidence)                    { [void]$sb.AppendLine(('- **Evidence:** {0}' -f $f.Evidence)) }
            if ($f.WhyItMattersForScoping)      { [void]$sb.AppendLine(('- **Why it matters:** {0}' -f $f.WhyItMattersForScoping)) }
            if (@($f.PotentialProjectImpact).Count -gt 0) { [void]$sb.AppendLine(('- **Project impact:** {0}' -f (@($f.PotentialProjectImpact) -join '; '))) }
            if ($f.SuggestedValidationQuestion)  { [void]$sb.AppendLine(('- **Validation question:** {0}' -f $f.SuggestedValidationQuestion)) }
            if (@($f.ComplianceRelevance).Count -gt 0) { [void]$sb.AppendLine(('- **Compliance relevance:** {0}' -f (@($f.ComplianceRelevance) -join '; '))) }
            [void]$sb.AppendLine('')
        }
    }
    if ($findings.Count -eq 0) { [void]$sb.AppendLine('_No findings were produced. On a populated server this is itself suspicious - check `evidence\logs\limitations.txt`._'); [void]$sb.AppendLine('') }

    # --- 5..n dataset-backed sections
    $sections = [ordered]@{
        '5. Migration complexity rubric'   = 'MigrationComplexity'
        '6. Decommission readiness'        = 'DecommissionReadiness'
        '7. Scream test plan'              = 'ScreamTestPlan'
        '8. Dependency map'                = 'DependencyGraph'
        '9. Work-breakdown inputs'         = 'WbsInputs'
        '10. Application validation matrix'= 'ApplicationValidationMatrix'
        '11. Patch posture'                = 'UpdatePosture'
        '12. Hybrid identity / cloud attachment' = 'HybridIdentity'
        '13. Time synchronisation'         = 'TimeSync'
        '14. Security posture'             = 'SecurityPosture'
        '15. Licensing indicators'         = 'Licensing'
        '16. Vendor agents'                = 'VendorAgents'
        '17. User-context dependencies'    = 'MappedDrives'
    }
    foreach ($h in $sections.Keys) {
        $rows = Get-RbRows -Context $Context -Name $sections[$h]
        [void]$sb.AppendLine(('## {0}' -f $h))
        [void]$sb.AppendLine('')
        if ($rows.Count -gt 0) { [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $rows)) }
        else { [void]$sb.AppendLine('_No data - the producing module did not run, or found nothing._') }
        [void]$sb.AppendLine('')
    }

    # --- unknowns / limitations / scope
    [void]$sb.AppendLine('## 18. Unknowns that matter')
    [void]$sb.AppendLine('')
    if (@($Context.Unknowns).Count -gt 0) { [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $Context.Unknowns -Columns @('Unknown','WhyItMatters','RecommendedValidationQuestion','Module'))) }
    else { [void]$sb.AppendLine('_No unknowns recorded._') }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## 19. Collection limitations')
    [void]$sb.AppendLine('')
    if (@($Context.Limitations).Count -gt 0) { [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $Context.Limitations -Columns @('Module','Message','Impact','Reason'))) }
    else { [void]$sb.AppendLine('_No limitations recorded._') }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## 20. Draft scope language')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> DRAFT. Requires review before it goes near a statement of work.')
    [void]$sb.AppendLine('')
    foreach ($s in @($Context.ScopeLanguage)) { [void]$sb.AppendLine(('- **[{0}]** {1}' -f $s.Type, $s.Text)) }
    if (@($Context.ScopeLanguage).Count -eq 0) { [void]$sb.AppendLine('_No scope language generated._') }
    [void]$sb.AppendLine('')

    # --- appendix
    [void]$sb.AppendLine('## Appendix A. Dataset index')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Every dataset below is exported in full to `evidence\data\csv\` and `evidence\data\json\`.')
    [void]$sb.AppendLine('')
    $idx = foreach ($k in ($Context.DataSets.Keys | Sort-Object)) {
        [pscustomobject]@{
            Dataset=$k; Rows=$Context.DataSets[$k].RowCount; Visibility=$Context.DataSets[$k].Visibility
            SourceModule=$Context.DataSets[$k].SourceModule; Description=$Context.DataSets[$k].Description
        }
    }
    [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows @($idx)))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Appendix B. Module execution')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows @($Context.ModuleStatuses) -Columns @('ModuleName','CanRun','Status','Outcome','Reason','DurationMs')))
    [void]$sb.AppendLine('')

    Write-MarkdownFile -Path $Path -Content ($sb.ToString()) | Out-Null
}

#endregion

#region client report ----------------------------------------------------------

function Get-RbClientModel {
    <#
        Builds the client report's content model ONCE, so the HTML and Markdown
        renderings can never drift apart. Nothing in the model is read from an
        Internal-visibility dataset.
    #>
    param([object]$Context)

    $questionGroups = @(@($Context.FollowUpQuestions | Where-Object { $_.Audience -in @('ClientSafe','Both') }) |
        Group-Object Category | Sort-Object Name)

    # Get-RbRows returns ,@(...) so an empty dataset survives as an array rather than
    # unrolling to $null - but that same comma means piping its call directly into
    # Where-Object/ForEach-Object hands the whole array to $_ as ONE item (PowerShell only
    # unrolls a ,@() return on direct assignment, not on pipeline consumption): every row's
    # property then comes back as an array via member enumeration, and a [string] cast on
    # that array silently space-joins every row's value into one garbled cell. Assigning to a
    # plain variable first (which does unroll correctly) before piping avoids it.

    $apps = @()
    if (Test-RbClientSafeDataset -Context $Context -Name 'ApplicationFingerprints') {
        $appRows = Get-RbRows -Context $Context -Name 'ApplicationFingerprints'
        $apps = @($appRows | Where-Object { $_.Confidence -in @('Confirmed','Likely') } |
            ForEach-Object { [pscustomobject]@{
                Application = [string]$_.ApplicationName
                Vendor      = [string]$_.Vendor
                'What it appears to do' = [string]$_.LikelyDependencyType
            } } | Sort-Object Application -Unique)
    }

    $shares = @()
    if (Test-RbClientSafeDataset -Context $Context -Name 'SmbShares') {
        $shareRows = Get-RbRows -Context $Context -Name 'SmbShares'
        $shares = @($shareRows | Where-Object { $_.IsUserShare } |
            ForEach-Object { [pscustomobject]@{ 'Shared folder' = [string]$_.Name; Description = [string]$_.Description } })
    }

    $printers = @()
    if (Test-RbClientSafeDataset -Context $Context -Name 'Printers') {
        $printerRows = Get-RbRows -Context $Context -Name 'Printers'
        $printers = @($printerRows | Where-Object { $_.Shared } |
            ForEach-Object { [pscustomobject]@{ Printer = [string]$_.Name; 'Specialty / label printer' = [string]$_.IsLabelPrinter } })
    }

    $vendors = @()
    if (Test-RbClientSafeDataset -Context $Context -Name 'VendorAgents') {
        $vendorRows = Get-RbRows -Context $Context -Name 'VendorAgents'
        $vendors = @($vendorRows |
            ForEach-Object { [pscustomobject]@{ 'Third-party product' = [string]$_.AgentName; Purpose = [string]$_.Category } })
    }

    $hybrid = @()
    if (Test-RbClientSafeDataset -Context $Context -Name 'HybridIdentity') {
        $hybridRows = Get-RbRows -Context $Context -Name 'HybridIdentity'
        $hybrid = @($hybridRows |
            ForEach-Object { [pscustomobject]@{ 'Cloud connection' = [string]$_.Component; 'What it does' = [string]$_.Role; 'Why it matters' = [string]$_.WhyItMatters } })
    }

    $backupKnown = (Test-RbClientSafeDataset -Context $Context -Name 'BackupDiscovery')
    $backups = @()
    if ($backupKnown) {
        $backupRows = Get-RbRows -Context $Context -Name 'BackupDiscovery'
        $backups = @($backupRows |
            ForEach-Object { [pscustomobject]@{ 'Backup product detected' = [string]$_.Product } })
    }

    $patch = $null
    if (Test-RbClientSafeDataset -Context $Context -Name 'UpdatePosture') {
        $updatePostureRows = Get-RbRows -Context $Context -Name 'UpdatePosture'
        $patch = @($updatePostureRows)[0]
    }

    # Only Grade/Label/Description - never FindingsCounted or TopContributingFindings, which
    # hint at internal finding volume/detail beyond what Get-RbClientHeadlines's own "generic
    # label only, never Evidence" philosophy (see that function's own comment) allows for
    # anything client-facing. The raw numeric Score is fine to keep - it's a computed number,
    # not evidence.
    $readiness = $null
    if (Test-RbClientSafeDataset -Context $Context -Name 'ReadinessScore') {
        $readinessRows = Get-RbRows -Context $Context -Name 'ReadinessScore'
        $readiness = @($readinessRows)[0]
    }
    $readinessSubsections = @()
    if (Test-RbClientSafeDataset -Context $Context -Name 'ReadinessScoreSubsections') {
        $subsectionRows = Get-RbRows -Context $Context -Name 'ReadinessScoreSubsections'
        $readinessSubsections = @($subsectionRows | ForEach-Object {
            [pscustomobject]@{ Subsection = [string]$_.Subsection; Score = $_.Score; Grade = [string]$_.Grade; Label = [string]$_.Label }
        })
    }

    $limitations = [System.Collections.Generic.List[string]]::new()
    if (-not $Context.IsAdmin)    { [void]$limitations.Add('Discovery did not run with full administrative rights, so some details are incomplete.') }
    if ($Context.Mode -eq 'Fast') { [void]$limitations.Add('This was a fast scan aimed at scoping. A deeper scan is available if you need more detail.') }
    [void]$limitations.Add('Warranty status, licence entitlement and vendor support status cannot be confirmed from the server itself - those need to come from you or the vendor.')
    [void]$limitations.Add('Everything here is an indicator based on what the server reports about itself. Nothing was changed, and nothing should be acted on until you have confirmed it.')

    return [pscustomobject]@{
        ComputerName   = $Context.ComputerName
        Generated      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Functions      = @(Get-LikelyServerFunctions -Context $Context)
        Classification = (Get-RbDecommissionClass -Context $Context)
        # No outer @() here - Get-RbClientHeadlines already returns ,@(...), and plain
        # assignment (unlike piping it) unrolls that correctly into a clean array.
        Headlines      = (Get-RbClientHeadlines -Context $Context)
        QuestionGroups = $questionGroups
        Applications   = $apps
        Shares         = $shares
        Printers       = $printers
        Vendors        = $vendors
        HybridIdentity = $hybrid
        Backups        = $backups
        BackupDetected = $backupKnown
        Patch          = $patch
        Readiness      = $readiness
        ReadinessSubsections = $readinessSubsections
        Limitations    = @($limitations)
    }
}

function Write-ClientHtmlReport {
    param([object]$Context, [object]$Model, [string]$Path)

    $b = Get-DiscoveryBranding -Context $Context
    $e = { param($v) ConvertTo-RbHtmlEncoded -Value $v }
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>Server Discovery Summary - {0}</title>' -f (& $e $Model.ComputerName)))
    [void]$sb.AppendLine(('<style>{0}</style></head><body>' -f (Get-RbClientCss -AccentColorHex $b.Accent)))
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine((Get-RbLogoHtml -Branding $b))
    [void]$sb.AppendLine(('<h1>Server Discovery Summary</h1>'))
    [void]$sb.AppendLine(('<div class="sub">{0} &middot; prepared by {1} &middot; {2}</div>' -f (& $e $Model.ComputerName), (& $e $b.Brand), (& $e $Model.Generated)))
    [void]$sb.AppendLine('</header><main>')

    [void]$sb.AppendLine('<h2>What this document is</h2>')
    [void]$sb.AppendLine('<p class="lead">We ran a read-only review of this server to understand what it does and what depends on it, so that any future migration, replacement or retirement is planned around the things that actually matter to your business.</p>')
    [void]$sb.AppendLine('<div class="callout"><b>Nothing was changed on the server.</b> The review only read configuration - it installed nothing, altered nothing, and took no data off the machine beyond what is summarised here. Everything below is our best reading of what the server reports about itself, and we need you to confirm it.</div>')

    [void]$sb.AppendLine('<div class="facts">')
    [void]$sb.AppendLine(('<div class="fact"><div class="l">Server</div><div class="v">{0}</div></div>' -f (& $e $Model.ComputerName)))
    [void]$sb.AppendLine(('<div class="fact"><div class="l">Roles identified</div><div class="v">{0}</div></div>' -f @($Model.Functions).Count))
    [void]$sb.AppendLine(('<div class="fact"><div class="l">Apparent dependency</div><div class="v">{0}</div></div>' -f (& $e $Model.Classification)))
    [void]$sb.AppendLine(('<div class="fact"><div class="l">Questions for you</div><div class="v">{0}</div></div>' -f (@($Model.QuestionGroups | ForEach-Object { $_.Group }) ).Count))
    if ($Model.Readiness) {
        [void]$sb.AppendLine(('<div class="fact"><div class="l">Readiness</div><div class="v">{0} - {1}</div></div>' -f (& $e $Model.Readiness.Grade), (& $e $Model.Readiness.Label)))
    }
    [void]$sb.AppendLine('</div>')

    if ($Model.Readiness) {
        [void]$sb.AppendLine('<h2>Readiness snapshot</h2>')
        [void]$sb.AppendLine(('<p class="lead">{0}</p>' -f (& $e $Model.Readiness.Description)))
        if (@($Model.ReadinessSubsections).Count -gt 0) {
            [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.ReadinessSubsections))
        }
    }

    [void]$sb.AppendLine('<h2>What this server appears to do</h2>')
    if (@($Model.Functions).Count -gt 0) {
        [void]$sb.AppendLine('<ul>')
        foreach ($f in $Model.Functions) { [void]$sb.AppendLine(('<li>{0}</li>' -f (& $e $f))) }
        [void]$sb.AppendLine('</ul>')
    } else {
        [void]$sb.AppendLine('<p>We could not automatically determine a primary role for this server. That is not unusual for a server running a single bespoke application - please tell us what it is used for.</p>')
    }

    if (@($Model.Applications).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Business applications we recognised</h3>')
        [void]$sb.AppendLine('<p class="muted">Recognised by their installed components. Please tell us which of these are still in use, and which are not.</p>')
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.Applications))
    }
    if (@($Model.Shares).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Shared folders</h3>')
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.Shares))
    }
    if (@($Model.Printers).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Shared printers</h3>')
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.Printers))
    }
    if (@($Model.HybridIdentity).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Connections to Microsoft 365 / Azure</h3>')
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.HybridIdentity))
    }
    if (@($Model.Vendors).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Third-party products installed</h3>')
        [void]$sb.AppendLine('<p class="muted">These usually belong to a vendor or managed service. If any of them are no longer under contract, tell us - it changes the plan.</p>')
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.Vendors))
    }

    [void]$sb.AppendLine('<h2>Things worth your attention</h2>')
    if (@($Model.Headlines).Count -gt 0) {
        [void]$sb.AppendLine('<p>These are the items most likely to affect cost, timing or risk. None of them are accusations - several may already be handled by something we cannot see from the server.</p>')
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.Headlines -Columns @('Topic','WhatWeFound','WhyItMatters')))
    } else {
        [void]$sb.AppendLine('<p>Nothing significant enough to raise here. That is a good outcome, but read the limitations at the end before treating it as a clean bill of health.</p>')
    }

    if (-not $Model.BackupDetected) {
        [void]$sb.AppendLine('<div class="callout"><b>Backup:</b> we did not detect backup software on this server. That may simply mean it is protected at the virtualisation or storage layer, which we cannot see from inside the server. Please confirm how it is backed up and when a restore was last tested.</div>')
    } elseif (@($Model.Backups).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Backup</h3>')
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Model.Backups))
        [void]$sb.AppendLine('<p class="muted">Detecting backup software does not confirm that backups are current or that a restore has been tested. Both need confirming before any change.</p>')
    }

    if ($Model.Patch -and $Model.Patch.PatchingLooksStale) {
        [void]$sb.AppendLine(('<div class="callout"><b>Updates:</b> the most recent update we can see on this server was installed around {0} days ago. If patching is handled by a tool we cannot see, let us know - otherwise this is worth scheduling.</div>' -f (& $e $Model.Patch.DaysSinceNewestHotfix)))
    }

    [void]$sb.AppendLine('<h2>What we need from you</h2>')
    [void]$sb.AppendLine('<p>These are the questions we cannot answer from the server itself. Answering them is the single biggest thing that improves the accuracy of our plan and our pricing.</p>')
    foreach ($grp in $Model.QuestionGroups) {
        [void]$sb.AppendLine('<div class="qbox">')
        [void]$sb.AppendLine(('<h3>{0}</h3><ul>' -f (& $e $grp.Name)))
        foreach ($q in $grp.Group) { [void]$sb.AppendLine(('<li>{0}</li>' -f (& $e $q.Question))) }
        [void]$sb.AppendLine('</ul></div>')
    }

    [void]$sb.AppendLine('<h2>Suggested next steps</h2>')
    [void]$sb.AppendLine('<ul>')
    [void]$sb.AppendLine('<li>Name a business owner and a validation contact for each application listed above.</li>')
    [void]$sb.AppendLine('<li>Confirm how this server is backed up, and when a restore was last successfully tested.</li>')
    [void]$sb.AppendLine('<li>Answer the questions above so we can scope the work accurately rather than defensively.</li>')
    [void]$sb.AppendLine('<li>Flag anything we have described incorrectly - a wrong assumption is much cheaper to fix now than during a cutover.</li>')
    [void]$sb.AppendLine('</ul>')

    [void]$sb.AppendLine('<h2>What this review could not tell us</h2>')
    [void]$sb.AppendLine('<ul>')
    foreach ($l in $Model.Limitations) { [void]$sb.AppendLine(('<li>{0}</li>' -f (& $e $l))) }
    [void]$sb.AppendLine('</ul>')

    [void]$sb.AppendLine('</main><footer>')
    [void]$sb.AppendLine(('Prepared by {0}. Read-only discovery of {1}, {2}. This document is a planning aid: the findings are indicators that require confirmation, and it does not assert compliance or non-compliance with any standard.' -f (& $e $b.Brand), (& $e $Model.ComputerName), (& $e $Model.Generated)))
    [void]$sb.AppendLine('</footer></body></html>')

    try { $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force } catch {
        Write-Log -Level WARN -Message 'Client HTML report write failed.' -Module 'ReportBuilder' -Exception $_ -Context $Context
    }
}

function Write-ClientMarkdownReport {
    param([object]$Context, [object]$Model, [string]$Path)

    $b = Get-DiscoveryBranding -Context $Context
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('# Server Discovery Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('**{0}** &middot; prepared by {1} &middot; {2}' -f $Model.ComputerName, $b.Brand, $Model.Generated))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## What this document is')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('We ran a read-only review of this server to understand what it does and what depends on it, so that any future migration, replacement or retirement is planned around the things that actually matter to your business.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> **Nothing was changed on the server.** The review only read configuration. Everything below is our best reading of what the server reports about itself, and we need you to confirm it.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## What this server appears to do')
    [void]$sb.AppendLine('')
    if (@($Model.Functions).Count -gt 0) { foreach ($f in $Model.Functions) { [void]$sb.AppendLine(('- {0}' -f $f)) } }
    else { [void]$sb.AppendLine('- We could not automatically determine a primary role. Please tell us what this server is used for.') }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('**Apparent dependency level:** {0} (an indicator, not a recommendation to switch anything off.)' -f $Model.Classification))
    [void]$sb.AppendLine('')

    if ($Model.Readiness) {
        [void]$sb.AppendLine('## Readiness snapshot')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(('**{0} - {1}.** {2}' -f $Model.Readiness.Grade, $Model.Readiness.Label, $Model.Readiness.Description))
        [void]$sb.AppendLine('')
        if (@($Model.ReadinessSubsections).Count -gt 0) {
            [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $Model.ReadinessSubsections))
            [void]$sb.AppendLine('')
        }
    }

    $tables = [ordered]@{
        'Business applications we recognised' = $Model.Applications
        'Shared folders'                      = $Model.Shares
        'Shared printers'                     = $Model.Printers
        'Connections to Microsoft 365 / Azure'= $Model.HybridIdentity
        'Third-party products installed'      = $Model.Vendors
    }
    foreach ($t in $tables.Keys) {
        if (@($tables[$t]).Count -eq 0) { continue }
        [void]$sb.AppendLine(('### {0}' -f $t))
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $tables[$t]))
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('## Things worth your attention')
    [void]$sb.AppendLine('')
    if (@($Model.Headlines).Count -gt 0) {
        [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $Model.Headlines -Columns @('Topic','WhatWeFound','WhyItMatters')))
    } else { [void]$sb.AppendLine('_Nothing significant enough to raise. Read the limitations below before treating that as a clean bill of health._') }
    [void]$sb.AppendLine('')

    if (-not $Model.BackupDetected) {
        [void]$sb.AppendLine('> **Backup:** we did not detect backup software on this server. It may be protected at the virtualisation or storage layer, which we cannot see from inside the server. Please confirm how it is backed up and when a restore was last tested.')
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('## What we need from you')
    [void]$sb.AppendLine('')
    foreach ($grp in $Model.QuestionGroups) {
        [void]$sb.AppendLine(('### {0}' -f $grp.Name))
        [void]$sb.AppendLine('')
        foreach ($q in $grp.Group) { [void]$sb.AppendLine(('- {0}' -f $q.Question)) }
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('## Suggested next steps')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('- Name a business owner and a validation contact for each application listed above.')
    [void]$sb.AppendLine('- Confirm how this server is backed up, and when a restore was last successfully tested.')
    [void]$sb.AppendLine('- Answer the questions above so we can scope the work accurately.')
    [void]$sb.AppendLine('- Flag anything we have described incorrectly.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## What this review could not tell us')
    [void]$sb.AppendLine('')
    foreach ($l in $Model.Limitations) { [void]$sb.AppendLine(('- {0}' -f $l)) }
    [void]$sb.AppendLine('')

    Write-MarkdownFile -Path $Path -Content ($sb.ToString()) | Out-Null
}

#endregion

function Invoke-DiscoveryReportBuild {
    <#
        Engine entry point. Runs after Write-DiscoveryOutputs, so every dataset,
        finding and question exists and the supporting exports are already on disk.
    #>
    param([object]$Context)
    Write-SectionStatus -Title 'Building reports' -Status 'Rendering' -Context $Context

    $reportDir = if ($Context.Paths.Contains('Reports')) { $Context.Paths['Reports'] } else { $Context.OutputPath }

    $internalMd = Join-Path $reportDir 'internal-engineering-report.md'
    $clientHtml = Join-Path $reportDir 'client-discovery-report.html'
    $clientMd   = Join-Path $reportDir 'client-discovery-report.md'

    try { Write-InternalMarkdownReport -Context $Context -Path $internalMd }
    catch { Write-Log -Level ERROR -Message 'Internal markdown report failed.' -Module 'ReportBuilder' -Exception $_ -Context $Context }

    $model = $null
    try { $model = Get-RbClientModel -Context $Context }
    catch { Write-Log -Level ERROR -Message 'Client report model build failed.' -Module 'ReportBuilder' -Exception $_ -Context $Context }

    if ($model) {
        try { Write-ClientHtmlReport -Context $Context -Model $model -Path $clientHtml }
        catch { Write-Log -Level ERROR -Message 'Client HTML report failed.' -Module 'ReportBuilder' -Exception $_ -Context $Context }
        try { Write-ClientMarkdownReport -Context $Context -Model $model -Path $clientMd }
        catch { Write-Log -Level ERROR -Message 'Client markdown report failed.' -Module 'ReportBuilder' -Exception $_ -Context $Context }
    }

    $index = @(
        [pscustomobject]@{ Report='Internal engineering report (HTML)'; File='reports\internal-engineering-report.html'; Audience='Internal only'; Contents='Full findings with evidence, dependency map, WBS inputs, scope language. Reads top to bottom - use this one to print or read straight through.' }
        [pscustomobject]@{ Report='Internal dashboard (HTML)'; File='reports\internal-dashboard-report.html'; Audience='Internal only'; Contents='Same findings and datasets as the engineering report, in a sidebar-navigated, scrollable/filterable layout for on-screen reference.' }
        [pscustomobject]@{ Report='Internal engineering report (Markdown)'; File='reports\internal-engineering-report.md'; Audience='Internal only'; Contents='Same material, paste-ready for tickets and scoping documents.' }
        [pscustomobject]@{ Report='Client discovery report (HTML)'; File='reports\client-discovery-report.html'; Audience='Client-facing'; Contents='Plain-English roles, applications, attention items, questions, next steps.' }
        [pscustomobject]@{ Report='Client discovery report (Markdown)'; File='reports\client-discovery-report.md'; Audience='Client-facing'; Contents='Same material in Markdown.' }
        [pscustomobject]@{ Report='Supporting deliverables'; File='reports\supporting\'; Audience='Internal'; Contents='Narrative markdown pack, workbook, dependency-graph / WBS / validation-matrix CSVs.' }
        [pscustomobject]@{ Report='Evidence'; File='evidence\'; Audience='Internal'; Contents='Logs, raw captures, live status, and every dataset as CSV and JSON.' }
    )
    Add-DataSet -Context $Context -Name 'ReportIndex' -Description 'Index of generated reports and where the supporting evidence lives.' -Rows $index -Visibility 'Internal' -SourceModule 'ReportBuilder' | Out-Null

    Write-Log -Level INFO -Message 'Reports generated (internal + client).' -Module 'ReportBuilder' -Context $Context
}

Export-ModuleMember -Function `
    'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryReportBuild', `
    'Write-InternalMarkdownReport','Write-ClientHtmlReport','Write-ClientMarkdownReport', `
    'Get-RbClientModel','Get-RbClientHeadlines','Get-RbRows','Test-RbClientSafeDataset','Get-RbClientCss','Get-RbLogoHtml'
