<#
    RiskEngine.psm1
    Ultimate Modular Windows Server Discovery Toolkit - Risk analysis engine.

    Collectors collect FACTS. The RiskEngine analyzes facts. It:
      - Evaluates data-driven rules (config\risk-rules.json) with a small set of
        explicit, SAFE condition types (no arbitrary expression evaluation).
      - Emits standard Finding objects.
      - Applies the compliance lens (interpretive relevance only).
      - Builds the MigrationComplexity, WBS inputs, and DependencyGraph datasets.

    Runs as a synthesis module AFTER all collectors, via Invoke-DiscoverySynthesis.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'RiskEngine'
        DisplayName               = 'Risk Analysis Engine'
        Category                  = 'Synthesis'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Minimal'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('MigrationComplexity','DependencyGraph','WbsInputs','CriticalPaths','ReadinessScore','ReadinessScoreSubsections')
        ProducesRisks             = $true
        ProducesFollowUpQuestions = $true
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $true
        IsSynthesis               = $true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='RiskEngine'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

#region Rule evaluation -------------------------------------------------------

function Test-FieldEquals {
    param($RowValue, $RuleValue)
    if ($null -eq $RowValue) { return $false }
    if ($RuleValue -is [bool]) {
        try { return ([bool]$RowValue -eq [bool]$RuleValue) } catch { return $false }
    }
    $rn = 0.0; $vn = 0.0
    if ([double]::TryParse([string]$RowValue, [ref]$rn) -and [double]::TryParse([string]$RuleValue, [ref]$vn)) {
        return ($rn -eq $vn)
    }
    return ([string]$RowValue -eq [string]$RuleValue)
}

function Test-RuleCondition {
    <# Returns the list of matching rows (or a single sentinel) for a rule condition. #>
    param([object]$Context, [object]$Condition)
    $result = [pscustomobject]@{ Matched = $false; Rows = @() }
    if (-not $Condition -or -not $Condition.type) { return $result }
    $dsName = $Condition.dataset
    $exists = ($dsName -and $Context.DataSets.Contains($dsName))
    $rows = @(if ($exists) { @($Context.DataSets[$dsName].Rows) } else { @() })

    switch ($Condition.type) {
        'datasetNotEmpty'      { if ($exists -and $rows.Count -gt 0) { $result.Matched = $true; $result.Rows = $rows } }
        'datasetMissingOrEmpty'{ if (-not $exists -or $rows.Count -eq 0) { $result.Matched = $true; $result.Rows = @() } }
        'datasetRowCountAtLeast' {
            # $exists is load-bearing: without it a rule omitting 'count' gets [int]$null = 0,
            # and "0 rows >= 0" matches an ABSENT dataset, emitting a finding with no evidence
            # rows behind it. Same silent-failure class as F29.
            #
            # The key must be probed via PSObject.Properties, NOT as $Condition.count. Every
            # PowerShell object carries an intrinsic ETS 'Count' property that returns 1 for a
            # scalar, so $Condition.count is 1 on a rule that never declared it - which is
            # exactly the malformed-rule case this is meant to reject.
            $need = 0
            $cp = $Condition.PSObject.Properties['count']
            if ($cp -and ($null -ne $cp.Value)) { try { $need = [int]$cp.Value } catch { $need = 0 } }
            if ($exists -and $need -ge 1 -and $rows.Count -ge $need) { $result.Matched = $true; $result.Rows = $rows }
        }
        'anyRowFieldEquals' {
            $m = @($rows | Where-Object { Test-FieldEquals -RowValue (Get-RowValue -Row $_ -Column $Condition.field) -RuleValue $Condition.value })
            if ($m.Count -gt 0) { $result.Matched = $true; $result.Rows = $m }
        }
        'anyRowFieldNotEquals' {
            $m = @($rows | Where-Object { $v = Get-RowValue -Row $_ -Column $Condition.field; ($null -ne $v) -and -not (Test-FieldEquals -RowValue $v -RuleValue $Condition.value) })
            if ($m.Count -gt 0) { $result.Matched = $true; $result.Rows = $m }
        }
        'anyRowFieldMatches' {
            $m = @($rows | Where-Object { $v = Get-RowValue -Row $_ -Column $Condition.field; ($null -ne $v) -and ([string]$v -match $Condition.pattern) })
            if ($m.Count -gt 0) { $result.Matched = $true; $result.Rows = $m }
        }
        'anyRowFieldGreaterThan' {
            $m = @($rows | Where-Object { $v=0.0; ([double]::TryParse([string](Get-RowValue -Row $_ -Column $Condition.field), [ref]$v)) -and ($v -gt [double]$Condition.value) })
            if ($m.Count -gt 0) { $result.Matched = $true; $result.Rows = $m }
        }
        'anyRowFieldLessThan' {
            $m = @($rows | Where-Object { $v=0.0; ([double]::TryParse([string](Get-RowValue -Row $_ -Column $Condition.field), [ref]$v)) -and ($v -lt [double]$Condition.value) })
            if ($m.Count -gt 0) { $result.Matched = $true; $result.Rows = $m }
        }
        default { }
    }
    return $result
}

function Expand-RuleTokens {
    <# Replaces {FieldName} tokens in a template using a row's field values. #>
    param([string]$Template, [object]$Row)
    if ([string]::IsNullOrEmpty($Template)) { return $Template }
    if ($null -eq $Row) { return $Template }
    return [regex]::Replace($Template, '\{(\w+)\}', {
        param($match)
        $field = $match.Groups[1].Value
        $val = Get-RowValue -Row $Row -Column $field
        if ($null -eq $val) { return '' }
        return (ConvertTo-DisplayString -Value $val)
    })
}

function Get-ComplianceRelevanceForFinding {
    <# Returns interpretive compliance relevance notes for a finding given the active lens. #>
    param([object]$Context, [object]$Finding, [string[]]$BaseRelevance = @())
    $notes = [System.Collections.Generic.List[string]]::new()
    foreach ($b in @($BaseRelevance)) { if ($b -and -not $notes.Contains($b)) { $notes.Add($b) } }
    $lensName = $Context.ComplianceLens
    if (-not $lensName -or $lensName -eq 'None') { return @($notes) }
    if (-not ($Context.Config -and $Context.Config.Compliance -and $Context.Config.Compliance.lenses)) { return @($notes) }
    $lens = $Context.Config.Compliance.lenses.$lensName
    if (-not $lens) { return @($notes) }
    # By category.
    if ($lens.relevanceByCategory -and $Finding.Category) {
        $byCat = $lens.relevanceByCategory.($Finding.Category)
        foreach ($n in @($byCat)) { if ($n -and -not $notes.Contains($n)) { $notes.Add($n) } }
    }
    # By keyword in title/evidence.
    if ($lens.relevanceByFindingKeyword) {
        $hay = ("{0} {1}" -f $Finding.Title, $Finding.Evidence)
        foreach ($kw in $lens.relevanceByFindingKeyword.PSObject.Properties.Name) {
            if ($hay -match [regex]::Escape($kw)) {
                foreach ($n in @($lens.relevanceByFindingKeyword.$kw)) { if ($n -and -not $notes.Contains($n)) { $notes.Add($n) } }
            }
        }
    }
    return @($notes)
}

function Test-RuleEmphasizedForProjectType {
    <#
        A rule may declare projectTypeEmphasis, e.g. ["Decommission","ServerRefresh"].
        When the active -ProjectType is listed, the resulting findings are flagged as
        emphasized so the reports lead with them.

        Emphasis is PRESENTATION ONLY - it never changes Severity, Confidence, or which
        rules fire, which is what "same data, different emphasis" in docs\README.md means.
        GeneralDiscovery intentionally matches nothing: it is the no-lens default.
    #>
    param([object]$Context, [object]$Rule)
    if (-not $Rule.PSObject.Properties['projectTypeEmphasis']) { return $false }
    $emphasis = @($Rule.projectTypeEmphasis)
    if ($emphasis.Count -eq 0) { return $false }
    $active = [string]$Context.ProjectType
    if ([string]::IsNullOrWhiteSpace($active)) { return $false }
    foreach ($pt in $emphasis) { if ([string]$pt -eq $active) { return $true } }
    return $false
}

function Get-WbsAreasForCategory {
    <#
        Default work-breakdown areas per finding category, used when a rule does not declare
        likelyAffectedWBSAreas explicitly. Without this, wbs-inputs.csv fell back to echoing
        the raw category, which is not a WBS area and is useless for building an estimate.
        An explicit likelyAffectedWBSAreas on the rule always wins.
    #>
    param([string]$Category)
    $map = @{
        'Identity / AD / DC' = @('Active Directory Migration','Cutover Validation','Client Coordination')
        'Service Account'    = @('Application Migration','Cutover Validation','Client Coordination')
        'Database'           = @('Database Migration','Backup and Recovery Validation','Cutover Validation')
        'Applications'       = @('Application Migration','Vendor Coordination','Cutover Validation')
        'Web'                = @('Application Migration','Certificate and Binding Migration','Cutover Validation')
        'File / Print'       = @('File Share Migration','Print Services Migration','Data Migration')
        'Certificates'       = @('Certificate and Binding Migration','Cutover Validation')
        'Backup / DR'        = @('Backup and Recovery Validation','Rollback Planning')
        'Vendor'             = @('Vendor Coordination','Application Migration')
        'Licensing'          = @('Licensing Review','Vendor Coordination')
        'Network'            = @('Network Configuration','Cutover Validation')
        'Storage'            = @('Storage and Capacity Planning','Data Migration')
        'Security'           = @('Security Remediation','Compliance Review')
        'Hyper-V / Cluster'  = @('Virtualization Migration','Cutover Validation','Rollback Planning')
        'Operating System'   = @('Operating System Upgrade','Cutover Validation')
        'Performance'        = @('Capacity and Performance Review','Target Sizing')
        'Services / Tasks'   = @('Service and Automation Migration','Cutover Validation')
        'Discovery Quality'  = @('Discovery and Documentation','Client Coordination')
    }
    if ($Category -and $map.ContainsKey($Category)) { return ,@($map[$Category]) }
    return ,@()
}

function Invoke-DiscoveryRiskAnalysis {
    <# Evaluates all enabled rules against the collected datasets and emits findings. #>
    param([object]$Context)
    $rulesConfig = $null
    if ($Context.Config -and $Context.Config.RiskRules) { $rulesConfig = $Context.Config.RiskRules }
    if (-not $rulesConfig -or -not $rulesConfig.rules) {
        Write-Log -Level WARN -Message 'No risk rules loaded; skipping rule evaluation.' -Module 'RiskEngine' -Context $Context
        return
    }
    $emitted = 0
    # Computed once, not per-rule - reused below wherever a rule's suggestedScopeLanguage names
    # the acting party inline via the literal '{Brand}' token ("{Brand} assumes...").
    $brandName = (Get-DiscoveryBranding -Context $Context).Brand
    foreach ($rule in $rulesConfig.rules) {
        try {
            if ($rule.PSObject.Properties['enabled'] -and -not $rule.enabled) { continue }
            $eval = Test-RuleCondition -Context $Context -Condition $rule.condition
            if (-not $eval.Matched) { continue }

            $emitPerRow = ($rule.PSObject.Properties['emitPerRow'] -and $rule.emitPerRow)
            $baseCompliance = @()
            if ($rule.PSObject.Properties['complianceRelevance']) { $baseCompliance = @($rule.complianceRelevance) }
            $impact = @()
            if ($rule.PSObject.Properties['potentialProjectImpact']) { $impact = @($rule.potentialProjectImpact) }
            $wbs = @()
            if ($rule.PSObject.Properties['likelyAffectedWBSAreas']) { $wbs = @($rule.likelyAffectedWBSAreas) }
            if ($wbs.Count -eq 0) { $wbs = @(Get-WbsAreasForCategory -Category ([string]$rule.category)) }
            $scopeLang = ''
            if ($rule.PSObject.Properties['suggestedScopeLanguage']) { $scopeLang = [string]$rule.suggestedScopeLanguage }
            # Rules author this as a markdown blockquote ('> {Brand} assumes ...'), but the
            # markdown writer prefixes its own '> **[Type]** ', which would double the marker.
            if ($scopeLang) {
                $scopeLang = ($scopeLang -replace '^\s*>\s*', '')
                # risk-rules.json's suggestedScopeLanguage strings name the acting party inline via
                # the literal '{Brand}' token ("{Brand} assumes...") - swapped for the configured
                # brand name here (same source ScopeLanguage.psm1 and every report header already
                # use) so whoever is running this sees their own company's name in generated scope
                # language, not a placeholder token or someone else's name.
                $scopeLang = $scopeLang.Replace('{Brand}', $brandName)
            }
            $emphasized = Test-RuleEmphasizedForProjectType -Context $Context -Rule $rule
            $emphasisReason = ''
            if ($emphasized) { $emphasisReason = ("Prioritised for project type '{0}'." -f $Context.ProjectType) }
            # evidenceField names the row's primary identifier (service name, task name, ...).
            $evidenceField = ''
            if ($rule.PSObject.Properties['evidenceField']) { $evidenceField = [string]$rule.evidenceField }
            # confidenceField lets a per-row rule take its confidence from the row itself (e.g. a
            # detected-but-not-running service is weaker evidence than a running one) instead of
            # every emitted finding sharing one static rule-level confidence regardless of row
            # content. Falls back to $rule.confidence when the field is absent/blank on a row.
            $confidenceField = ''
            if ($rule.PSObject.Properties['confidenceField']) { $confidenceField = [string]$rule.confidenceField }

            if ($emitPerRow -and $eval.Rows.Count -gt 0) {
                $cap = 200  # avoid pathological finding explosions; note truncation
                $rowsToEmit = $eval.Rows
                $truncated = $false
                if ($rowsToEmit.Count -gt $cap) { $rowsToEmit = $rowsToEmit[0..($cap-1)]; $truncated = $true }
                foreach ($row in $rowsToEmit) {
                    $evidence = if ($rule.PSObject.Properties['evidenceTemplate']) { Expand-RuleTokens -Template $rule.evidenceTemplate -Row $row } else { '' }
                    $question = if ($rule.PSObject.Properties['suggestedValidationQuestion']) { Expand-RuleTokens -Template $rule.suggestedValidationQuestion -Row $row } else { '' }
                    $subject = ''
                    if ($evidenceField) {
                        $sv = Get-RowValue -Row $row -Column $evidenceField
                        if ($null -ne $sv) { $subject = ConvertTo-DisplayString -Value $sv }
                    }
                    $rowConfidence = $rule.confidence
                    if ($confidenceField) {
                        $cv = Get-RowValue -Row $row -Column $confidenceField
                        if ($cv) { $rowConfidence = [string]$cv }
                    }
                    $f = Add-Finding -Context $Context -Category $rule.category -Severity $rule.severity -Confidence $rowConfidence `
                        -Title $rule.title -EvidenceSource $rule.sourceDataset -Evidence $evidence `
                        -WhyItMattersForScoping $rule.whyItMattersForScoping -PotentialProjectImpact $impact `
                        -SuggestedValidationQuestion $question -SuggestedScopeLanguage $scopeLang `
                        -LikelyAffectedWBSAreas $wbs -Subject $subject -IsEmphasized $emphasized -EmphasisReason $emphasisReason `
                        -SourceModule $rule.sourceModule -SourceDataset $rule.sourceDataset
                    $f.ComplianceRelevance = Get-ComplianceRelevanceForFinding -Context $Context -Finding $f -BaseRelevance $baseCompliance
                    $emitted++
                }
                if ($truncated) {
                    Add-Limitation -Context $Context -Module 'RiskEngine' -Message ("Rule {0} matched more than {1} rows; only the first {1} findings were emitted." -f $rule.id, $cap) -Impact 'Finding volume capped' | Out-Null
                }
            } else {
                $question = ''
                if ($rule.PSObject.Properties['suggestedValidationQuestion']) { $question = [string]$rule.suggestedValidationQuestion }
                $evidence = ''
                if ($rule.condition.type -eq 'datasetMissingOrEmpty') { $evidence = ("Dataset '{0}' was not present or contained no rows." -f $rule.condition.dataset) }
                elseif ($rule.condition.dataset -and $Context.DataSets.Contains($rule.condition.dataset)) { $evidence = ("{0} matching row(s) in dataset '{1}'." -f $eval.Rows.Count, $rule.condition.dataset) }
                $f = Add-Finding -Context $Context -Category $rule.category -Severity $rule.severity -Confidence $rule.confidence `
                    -Title $rule.title -EvidenceSource $rule.sourceDataset -Evidence $evidence `
                    -WhyItMattersForScoping $rule.whyItMattersForScoping -PotentialProjectImpact $impact `
                    -SuggestedValidationQuestion $question -SuggestedScopeLanguage $scopeLang `
                    -LikelyAffectedWBSAreas $wbs -IsEmphasized $emphasized -EmphasisReason $emphasisReason `
                    -SourceModule $rule.sourceModule -SourceDataset $rule.sourceDataset
                $f.ComplianceRelevance = Get-ComplianceRelevanceForFinding -Context $Context -Finding $f -BaseRelevance $baseCompliance
                $emitted++
            }
            # A rule's suggestedScopeLanguage previously lived only on the finding object, so it
            # never reached draft-scope-language.md / scope-assumptions.md. Contribute it to the
            # shared scope-language list exactly once per matched rule.
            if ($scopeLang) {
                $slType = 'Assumption'
                if ($rule.PSObject.Properties['suggestedScopeLanguageType'] -and $rule.suggestedScopeLanguageType) { $slType = [string]$rule.suggestedScopeLanguageType }
                $already = @($Context.ScopeLanguage | Where-Object { $_.Text -eq $scopeLang }).Count -gt 0
                if (-not $already) {
                    Add-ScopeLanguage -Context $Context -Text $scopeLang -Type $slType -Module 'RiskEngine' -RelatedFinding ([string]$rule.id) | Out-Null
                }
            }
        } catch {
            Write-Log -Level WARN -Message ("Rule '{0}' evaluation failed." -f $rule.id) -Module 'RiskEngine' -Exception $_ -Context $Context
        }
    }
    $emphCount = @($Context.Findings | Where-Object { $_.IsEmphasized }).Count
    Write-Log -Level INFO -Message ("RiskEngine emitted {0} finding(s) from {1} rule(s); {2} emphasised for project type '{3}'." -f $emitted, @($rulesConfig.rules).Count, $emphCount, $Context.ProjectType) -Module 'RiskEngine' -Context $Context
}

#endregion

#region Migration complexity / WBS / dependency graph -------------------------

function Get-ComplexityRating {
    <# Transparent rubric: rating derived from matching finding categories/severities. #>
    param([object[]]$Findings, [string[]]$Categories, [string[]]$ImpactKeywords = @())
    $related = @($Findings | Where-Object {
        ($Categories -contains $_.Category) -or
        (@($_.PotentialProjectImpact | Where-Object { $ImpactKeywords -contains $_ }).Count -gt 0)
    })
    if ($related.Count -eq 0) { return @{ Rating='None'; Evidence='No related findings detected.' } }
    $hasHigh = @($related | Where-Object { $_.Severity -in @('High','Critical') }).Count -gt 0
    $hasMed  = @($related | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0
    $rating = if ($hasHigh) { 'High' } elseif ($hasMed) { 'Medium' } else { 'Low' }
    return @{ Rating=$rating; Evidence=("{0} related finding(s); highest severity contributes to rating." -f $related.Count) }
}

function Build-MigrationComplexity {
    param([object]$Context)
    $f = @($Context.Findings)
    $rubric = @(
        @{ Category='Identity dependency';            Cats=@('Identity / AD / DC');            Kw=@() ; Why='AD/DNS/DHCP/identity roles require careful sequencing and cannot be moved casually.' }
        @{ Category='Network dependency';             Cats=@('Network');                       Kw=@() ; Why='Static IPs, DNS, gateways, and listening ports are frequently referenced by other systems.' }
        @{ Category='Database dependency';            Cats=@('Database');                      Kw=@('Data Migration'); Why='Databases drive data migration effort, backup validation, and cutover coordination.' }
        @{ Category='Application dependency';         Cats=@('Applications','Web');            Kw=@() ; Why='Line-of-business and web apps carry config, runtime, and vendor dependencies.' }
        @{ Category='File/print dependency';          Cats=@('File / Print');                  Kw=@() ; Why='File shares and printers imply user/UNC dependencies and data movement.' }
        @{ Category='Certificate dependency';         Cats=@('Certificates');                  Kw=@() ; Why='Bound certificates may require reissue or migration; keys are never exported by this tool.' }
        @{ Category='Service account dependency';     Cats=@('Service Account');               Kw=@() ; Why='Service/app-pool/task accounts require credential coordination and permission reproduction.' }
        @{ Category='Vendor dependency';              Cats=@('Vendor','Licensing');            Kw=@('Vendor Dependency'); Why='Vendor agents/apps/licensing often require coordination and reactivation.' }
        @{ Category='Data volume';                    Cats=@('Storage','File / Print');        Kw=@('Data Migration'); Why='Data volume affects migration windows, staging, and target sizing.' }
        @{ Category='Downtime sensitivity';           Cats=@('Identity / AD / DC','Database','Web','Hyper-V / Cluster'); Kw=@('Downtime','Cutover Complexity'); Why='Critical roles increase downtime sensitivity during cutover.' }
        @{ Category='Backup/rollback clarity';        Cats=@('Backup / DR');                   Kw=@('Rollback Planning'); Why='Unclear backup/restore state increases rollback risk.' }
        @{ Category='Documentation quality';          Cats=@('Discovery Quality');             Kw=@() ; Why='Unknowns and unavailable data reduce planning confidence.' }
        @{ Category='Security/compliance sensitivity';Cats=@('Security');                      Kw=@('Security/Compliance'); Why='Security posture gaps affect risk and possible remediation scope.' }
        @{ Category='Licensing uncertainty';          Cats=@('Licensing');                     Kw=@('Licensing'); Why='OEM/RDS/SQL/vendor licensing may not transfer and needs validation.' }
        @{ Category='Operating system currency';      Cats=@('Operating System');              Kw=@() ; Why='An OS at or near end of support constrains the target platform and may force an in-place upgrade or a rebuild.' }
        @{ Category='Performance headroom';           Cats=@('Performance');                   Kw=@() ; Why='Observed CPU/memory pressure drives target sizing and whether a like-for-like move is safe.' }
        @{ Category='Automation / scheduled work';    Cats=@('Services / Tasks');              Kw=@() ; Why='Services and scheduled tasks must be reproduced on the target; undocumented automation is a common cutover surprise.' }
    )
    $rows = foreach ($r in $rubric) {
        $res = Get-ComplexityRating -Findings $f -Categories $r.Cats -ImpactKeywords $r.Kw
        [pscustomobject]@{
            Category          = $r.Category
            Rating            = $res.Rating
            Evidence          = $res.Evidence
            WhyItMatters      = $r.Why
            SuggestedValidation = 'Confirm with client/vendor; this rating is a transparent indicator, not a precise estimate.'
        }
    }
    Add-DataSet -Context $Context -Name 'MigrationComplexity' -Description 'Transparent migration-complexity rubric derived from findings.' -Rows $rows -Visibility 'Both' -SourceModule 'RiskEngine' | Out-Null
}

function Build-WbsInputs {
    param([object]$Context)
    $rows = foreach ($f in @($Context.Findings)) {
        if ($f.Severity -eq 'Info') { continue }
        $wbsArea = if (@($f.LikelyAffectedWBSAreas).Count -gt 0) { ($f.LikelyAffectedWBSAreas -join '; ') } else { $f.Category }
        [pscustomobject]@{
            Finding           = $f.Title
            Subject           = $f.Subject
            PriorityForProject= $f.IsEmphasized
            SuggestedWBSArea  = $wbsArea
            LaborDriver       = (@($f.PotentialProjectImpact) -join '; ')
            Complexity        = $f.Severity
            Evidence          = $f.Evidence
    SuggestedScopeNote= $f.SuggestedScopeLanguage
            ValidationQuestion= $f.SuggestedValidationQuestion
        }
    }
    Add-DataSet -Context $Context -Name 'WbsInputs' -Description 'Work-breakdown-structure inputs derived from findings.' -Rows @($rows) -Visibility 'Internal' -SourceModule 'RiskEngine' | Out-Null
}

function Build-ReadinessScore {
    <#
        Deterministic, transparent 0-100 indicator derived from Findings' Severity x
        Confidence - not a certification (see the Caveat field on every returned row,
        wording matching Build-MigrationComplexity's own SuggestedValidation above). Produces
        two datasets: one overall score, and a breakdown across 5 human-readable subsections
        grouping the 18 real finding categories, so a reader can see WHERE risk concentrates
        rather than just one opaque number.
    #>
    param([object]$Context)

    $severityWeight = @{ Critical = 20; High = 10; Medium = 4; Low = 1; Info = 0 }
    # Roughly doubling at each severity step (1-4-10-20, not linear) so a handful of Criticals
    # can legitimately drive a server to 0 while a pile of Lows can't accidentally do the same -
    # matches the qualitative ordering Get-ComplexityRating already encodes (hasHigh beats
    # hasMed beats else) without inventing a new severity taxonomy.
    $confidenceMultiplier = @{ Confirmed = 1.0; Likely = 0.7; Possible = 0.4; NotDetected = 0; Unknown = 0.5 }

    $subsectionMap = [ordered]@{
        'Identity & Access'         = @('Identity / AD / DC', 'Service Account', 'Security')
        'Data & Applications'       = @('Database', 'Applications', 'Web', 'File / Print', 'Storage')
        'Infrastructure & Platform' = @('Operating System', 'Hyper-V / Cluster', 'Network', 'Performance', 'Services / Tasks')
        'Continuity & Compliance'   = @('Backup / DR', 'Certificates', 'Licensing', 'Vendor')
        # Its own subsection, deliberately not folded into another one: a low score here means
        # "we don't know enough," which is a different problem than "we found problems."
        'Discovery Confidence'      = @('Discovery Quality')
    }

    $caveat = 'This score is a transparent, rule-based indicator derived from findings severity and confidence - not a certification, audit, or guarantee. Always validate with the client before using it in scoping or a statement of work.'

    $getBand = {
        param($score)
        if ($score -ge 90)    { return @{ Grade = 'A'; Label = 'Clean';                 Description = 'Few or no notable findings. Still validate before treating this as a certification.' } }
        elseif ($score -ge 75) { return @{ Grade = 'B'; Label = 'Minor gaps';            Description = 'Some findings worth reviewing, nothing that should block planning on its own.' } }
        elseif ($score -ge 55) { return @{ Grade = 'C'; Label = 'Needs attention';       Description = 'Multiple findings, including at least one higher-severity item. Plan time to investigate before committing to a timeline.' } }
        elseif ($score -ge 30) { return @{ Grade = 'D'; Label = 'Significant concerns';  Description = 'Several higher-severity or low-confidence findings. Treat scoping estimates as provisional until these are resolved.' } }
        else                   { return @{ Grade = 'F'; Label = 'High risk';             Description = 'A concentration of Critical/High findings. This server needs hands-on validation before it is scoped or migrated.' } }
    }

    $deductionFor = {
        param($finding)
        $w = if ($severityWeight.ContainsKey($finding.Severity)) { $severityWeight[$finding.Severity] } else { 0 }
        $m = if ($confidenceMultiplier.ContainsKey($finding.Confidence)) { $confidenceMultiplier[$finding.Confidence] } else { 1.0 }
        return [Math]::Round($w * $m)
    }

    # Info findings are never scored - matches Build-WbsInputs's own 'if ($f.Severity -eq
    # ''Info'') { continue }' precedent immediately above.
    $allFindings = @($Context.Findings | Where-Object { $_.Severity -ne 'Info' })
    $totalDeduction = 0
    foreach ($f in $allFindings) { $totalDeduction += (& $deductionFor $f) }
    $overallScore = [Math]::Max(0, 100 - $totalDeduction)
    $overallBand = & $getBand $overallScore

    Add-DataSet -Context $Context -Name 'ReadinessScore' -Description 'Overall server readiness score derived from findings severity and confidence.' -Rows @([pscustomobject]@{
        Score           = $overallScore
        Grade           = $overallBand.Grade
        Label           = $overallBand.Label
        Description     = $overallBand.Description
        FindingsCounted = $allFindings.Count
        Caveat          = $caveat
    }) -Visibility 'Both' -SourceModule 'RiskEngine' | Out-Null

    $subsectionRows = foreach ($subsection in $subsectionMap.Keys) {
        $cats = $subsectionMap[$subsection]
        $subFindings = @($allFindings | Where-Object { $cats -contains $_.Category })
        # Computed once per finding (not inline in Sort-Object's calculated property) to avoid
        # relying on closure capture inside a Sort-Object scriptblock for something this simple.
        $subFindingsWithDeduction = @($subFindings | ForEach-Object { [pscustomobject]@{ Title = $_.Title; Deduction = (& $deductionFor $_) } })
        $subDeduction = ($subFindingsWithDeduction | Measure-Object -Property Deduction -Sum).Sum
        if (-not $subDeduction) { $subDeduction = 0 }
        $subScore = [Math]::Max(0, 100 - $subDeduction)
        $subBand = & $getBand $subScore
        $topFindings = @($subFindingsWithDeduction | Sort-Object -Property Deduction -Descending | Select-Object -First 3 | ForEach-Object { $_.Title })
        [pscustomobject]@{
            Subsection              = $subsection
            Score                   = $subScore
            Grade                   = $subBand.Grade
            Label                   = $subBand.Label
            Categories              = ($cats -join '; ')
            FindingsCounted         = $subFindings.Count
            TopContributingFindings = ($topFindings -join '; ')
        }
    }
    Add-DataSet -Context $Context -Name 'ReadinessScoreSubsections' -Description 'Per-subsection readiness score breakdown.' -Rows @($subsectionRows) -Visibility 'Both' -SourceModule 'RiskEngine' | Out-Null
}

function Build-DependencyGraph {
    param([object]$Context)
    $rows = foreach ($e in @($Context.DependencyEdges)) {
        [pscustomobject]@{
            SourceType         = $e.SourceType
            SourceName         = $e.SourceName
            DependencyType     = $e.DependencyType
            Target             = $e.Target
            Evidence           = $e.Evidence
            Confidence         = $e.Confidence
            SourceDataset      = $e.SourceDataset
            ProjectImpact      = $e.ProjectImpact
            ValidationQuestion = $e.ValidationQuestion
        }
    }
    Add-DataSet -Context $Context -Name 'DependencyGraph' -Description 'Cross-component dependency edges discovered during collection.' -Rows @($rows) -Visibility 'Internal' -SourceModule 'RiskEngine' | Out-Null
}

#endregion

function Build-CriticalPaths {
    <#
        Builds the CriticalPaths dataset from already-collected datasets. This runs
        regardless of whether the config dependency scan ran. ConfigDependencyScan only
        derives Service/SmbShare/IIS paths, so its rows are MERGED with these (deduped on
        Path+Source) rather than replacing them - otherwise SQL and Application paths
        vanish in exactly the Deep runs where they matter.
    #>
    param([object]$Context)
    $have = @{}
    if ($Context.DataSets.Contains('CriticalPaths')) { foreach ($r in @($Context.DataSets['CriticalPaths'].Rows)) { $have[("{0}|{1}" -f $r.Path, $r.Source)] = $true } }
    $rows = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($path, $src, $reason, $related, $impact)
        if ([string]::IsNullOrWhiteSpace($path)) { return }
        if ($have.ContainsKey(("{0}|{1}" -f $path, $src))) { return }
        $have[("{0}|{1}" -f $path, $src)] = $true
        $exists = $false; try { $exists = Test-Path -LiteralPath $path } catch { }
        $rows.Add([pscustomobject]@{ Path=$path; Source=$src; ReasonItMatters=$reason; Exists=$exists; SizeIfSafe=''; RelatedServiceOrApp=$related; Confidence='Likely'; PotentialProjectImpact=$impact })
    }
    try { if ($Context.DataSets.Contains('Services')) { foreach ($s in @($Context.DataSets['Services'].Rows | Where-Object { $_.ExecutablePath -and $_.IsNonMicrosoftAutoStart })) { & $add $s.ExecutablePath 'Service' 'Non-Microsoft service executable location' $s.Name 'Cutover Complexity' } } } catch { }
    try { if ($Context.DataSets.Contains('SmbShares')) { foreach ($s in @($Context.DataSets['SmbShares'].Rows | Where-Object { $_.IsUserShare })) { & $add $s.Path 'SmbShare' 'Shared data location' $s.Name 'Data Migration' } } } catch { }
    try { if ($Context.DataSets.Contains('IisSites')) { foreach ($s in @($Context.DataSets['IisSites'].Rows | Where-Object { $_.PhysicalPath })) { & $add $s.PhysicalPath 'IIS' 'Web content location' $s.Name 'Cutover Complexity' } } } catch { }
    try { if ($Context.DataSets.Contains('SqlInstances')) { foreach ($s in @($Context.DataSets['SqlInstances'].Rows | Where-Object { $_.BinaryPath })) { & $add $s.BinaryPath 'SQL' 'SQL instance binary path' $s.InstanceName 'Data Migration' } } } catch { }
    try { if ($Context.DataSets.Contains('InstalledApplications')) { foreach ($a in @($Context.DataSets['InstalledApplications'].Rows | Where-Object { $_.InstallLocation -and -not $_.SystemComponent })) { & $add $a.InstallLocation 'Application' 'Application install location' $a.DisplayName 'Labor' } } } catch { }
    Add-DataSet -Context $Context -Name 'CriticalPaths' -Description 'Paths critical to service/app function, derived from collected datasets.' -Rows @($rows) -Visibility 'Internal' -SourceModule 'RiskEngine' | Out-Null
}

function Invoke-DiscoverySynthesis {
    <# Synthesis entry point invoked by the orchestrator after all collectors. #>
    param([object]$Context)
    Write-SectionStatus -Title 'Risk Engine' -Status 'Analyzing' -Context $Context
    try { Invoke-DiscoveryRiskAnalysis -Context $Context } catch { Write-Log -Level ERROR -Message 'Risk analysis failed.' -Module 'RiskEngine' -Exception $_ -Context $Context }
    try { Build-DependencyGraph -Context $Context } catch { Write-Log -Level WARN -Message 'Dependency graph build failed.' -Module 'RiskEngine' -Exception $_ -Context $Context }
    try { Build-CriticalPaths -Context $Context } catch { Write-Log -Level WARN -Message 'Critical paths build failed.' -Module 'RiskEngine' -Exception $_ -Context $Context }
    try { Build-MigrationComplexity -Context $Context } catch { Write-Log -Level WARN -Message 'Migration complexity build failed.' -Module 'RiskEngine' -Exception $_ -Context $Context }
    try { Build-WbsInputs -Context $Context } catch { Write-Log -Level WARN -Message 'WBS inputs build failed.' -Module 'RiskEngine' -Exception $_ -Context $Context }
    try { Build-ReadinessScore -Context $Context } catch { Write-Log -Level WARN -Message 'Readiness score build failed.' -Module 'RiskEngine' -Exception $_ -Context $Context }
}

Export-ModuleMember -Function `
    'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryRiskAnalysis', `
    'Invoke-DiscoverySynthesis','Test-RuleCondition','Expand-RuleTokens','Get-ComplianceRelevanceForFinding', `
    'Test-RuleEmphasizedForProjectType','Get-WbsAreasForCategory', `
    'Build-MigrationComplexity','Build-WbsInputs','Build-DependencyGraph','Build-ReadinessScore'
