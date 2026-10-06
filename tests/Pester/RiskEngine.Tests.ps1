#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    RiskEngine.Tests.ps1 - rule matching, token expansion, metadata contract,
    and discovery-plan generation (Pester 5.x).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

    # 'Module metadata contract' below imports every module directory and Remove-Module's each
    # one in its finally - including Core, Output and RiskEngine - so the framework can be
    # unloaded partway through this file. Any Describe that needs the framework must be able to
    # restore it rather than rely on this BeforeAll surviving. Hence a named helper.
    function global:Import-DiscoveryFrameworkForTest {
        param([string]$RootPath)
        Import-Module (Join-Path $RootPath 'modules\Core\Core.psm1')             -Force -DisableNameChecking
        Import-Module (Join-Path $RootPath 'modules\Output\Output.psm1')         -Force -DisableNameChecking
        Import-Module (Join-Path $RootPath 'modules\RiskEngine\RiskEngine.psm1') -Force -DisableNameChecking
    }

    Import-DiscoveryFrameworkForTest -RootPath $script:Root
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-TestContext {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-DataSet -Context $c -Name 'Services' -Rows @(
            [pscustomobject]@{ Name='AcmeSvc'; DisplayName='Acme Service'; StartName='DOMAIN\svc-acme'; PathName='C:\Acme\a.exe'; UnquotedPathWithSpaces=$false; PathExists=$true; IsNonMicrosoftAutoStart=$true }
        ) | Out-Null
        Add-DataSet -Context $c -Name 'Volumes' -Rows @(
            [pscustomobject]@{ DriveLetter='C'; PercentFree=5.0; FreeGB=5; SizeGB=100 }
        ) | Out-Null
        return $c
    }
}

Describe 'Test-RuleCondition' {
    It 'datasetNotEmpty fires when rows exist' {
        $c = New-TestContext
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='datasetNotEmpty'; dataset='Services' })).Matched | Should -BeTrue
    }
    It 'datasetMissingOrEmpty fires for an absent dataset' {
        $c = New-TestContext
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='datasetMissingOrEmpty'; dataset='Nope' })).Matched | Should -BeTrue
    }
    It 'anyRowFieldEquals matches a boolean field' {
        $c = New-TestContext
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='anyRowFieldEquals'; dataset='Services'; field='IsNonMicrosoftAutoStart'; value=$true })).Matched | Should -BeTrue
    }
    It 'anyRowFieldMatches matches a regex' {
        $c = New-TestContext
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='anyRowFieldMatches'; dataset='Services'; field='StartName'; pattern='(?i)DOMAIN\\' })).Matched | Should -BeTrue
    }
    It 'anyRowFieldLessThan matches a numeric threshold' {
        $c = New-TestContext
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='anyRowFieldLessThan'; dataset='Volumes'; field='PercentFree'; value=10 })).Matched | Should -BeTrue
    }
    # --- Regression guard: PowerShell 5.1 array unrolling --------------------
    # A 1-element array emitted from an if-block unrolls to a scalar, and Windows
    # PowerShell 5.1 gives a bare object no .Count - so datasetNotEmpty silently
    # returned $false for any single-row dataset on the documented target runtime,
    # while passing on PowerShell 7. Row counts are parameterised deliberately: the
    # bug ONLY showed at exactly 1 row, so a 2-row fixture would not have caught it.
    It 'datasetNotEmpty fires for a dataset with exactly <Rows> row(s)' -ForEach @(
        @{ Rows = 1 }
        @{ Rows = 2 }
        @{ Rows = 3 }
    ) {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-DataSet -Context $c -Name 'Services' -Rows @(
            1..$Rows | ForEach-Object { [pscustomobject]@{ Name = "Svc$_"; StartName = 'LocalSystem' } }
        ) | Out-Null
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='datasetNotEmpty'; dataset='Services' })).Matched |
            Should -BeTrue -Because 'a single-row dataset must not unroll to a scalar'
    }

    It 'datasetRowCountAtLeast counts a single row correctly' {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-DataSet -Context $c -Name 'Services' -Rows @([pscustomobject]@{ Name='Svc1' }) | Out-Null
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='datasetRowCountAtLeast'; dataset='Services'; count=1 })).Matched |
            Should -BeTrue
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='datasetRowCountAtLeast'; dataset='Services'; count=2 })).Matched |
            Should -BeFalse
    }

    It 'does not fire when the field value does not match' {
        $c = New-TestContext
        (Test-RuleCondition -Context $c -Condition ([pscustomobject]@{ type='anyRowFieldEquals'; dataset='Services'; field='PathExists'; value=$false })).Matched | Should -BeFalse
    }
}

Describe 'Expand-RuleTokens' {
    It 'substitutes {Field} tokens from a row' {
        $row = [pscustomobject]@{ Name='AcmeSvc'; StartName='DOMAIN\svc' }
        Expand-RuleTokens -Template "Service '{Name}' runs as '{StartName}'" -Row $row | Should -Be "Service 'AcmeSvc' runs as 'DOMAIN\svc'"
    }
}

Describe 'Rule evaluation end-to-end' {
    It 'emits findings from the shipped rules against sample data' {
        $c = New-TestContext
        Invoke-DiscoveryRiskAnalysis -Context $c
        $c.Findings.Count | Should -BeGreaterThan 0
        # The domain-account service rule should have produced a Service Account finding.
        @($c.Findings | Where-Object { $_.Category -eq 'Service Account' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'suggestedScopeLanguage brand substitution' {
    # Regression test: risk-rules.json's suggestedScopeLanguage strings name the acting party
    # inline via a literal '{Brand}' token ("{Brand} assumes...") - RiskEngine.psm1 swaps that
    # token for the configured brand name (config/output-settings.json's html.brandName) so
    # whoever runs this sees their own company's name in a generated finding's scope language.
    It 'replaces the literal {Brand} token with the configured brand name' {
        $customConfig = [pscustomobject]@{
            RiskRules = $script:Config.RiskRules
            Output    = [pscustomobject]@{ html = [pscustomobject]@{ brandName = 'Acme MSP Test' } }
            ConfigDir = $script:Config.ConfigDir
        }
        $c = New-DiscoveryContext -Mode Fast -Config $customConfig
        Add-DataSet -Context $c -Name 'DomainContext' -Rows @([pscustomobject]@{ IsDomainController = $true }) | Out-Null
        Invoke-DiscoveryRiskAnalysis -Context $c
        $dcFinding = $c.Findings | Where-Object { $_.Title -eq 'Server is a Domain Controller' } | Select-Object -First 1
        $dcFinding | Should -Not -BeNullOrEmpty
        $dcFinding.SuggestedScopeLanguage | Should -Match '^Acme MSP Test assumes'
        $dcFinding.SuggestedScopeLanguage | Should -Not -Match '\{Brand\}'
    }
}

Describe 'Build-ReadinessScore' {
    # Deterministic point-deduction formula: 100 minus Severity-weight x Confidence-multiplier
    # per non-Info finding, floored at 0. See the function's own doc-comment for the exact tables.

    It 'computes the expected score for a known mix of findings' {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-Finding -Context $c -Category 'Security' -Severity 'Critical' -Confidence 'Confirmed' -Title 'Crit1' -EvidenceSource 'x' | Out-Null
        Add-Finding -Context $c -Category 'Security' -Severity 'Critical' -Confidence 'Confirmed' -Title 'Crit2' -EvidenceSource 'x' | Out-Null
        Add-Finding -Context $c -Category 'Database' -Severity 'Medium'   -Confidence 'Likely'    -Title 'Med1'  -EvidenceSource 'x' | Out-Null
        Add-Finding -Context $c -Category 'Discovery Quality' -Severity 'Info' -Confidence 'Confirmed' -Title 'Info1' -EvidenceSource 'x' | Out-Null
        Build-ReadinessScore -Context $c
        $overall = $c.DataSets['ReadinessScore'].Rows[0]
        # 100 - 20 - 20 - round(4*0.7=2.8->3) = 57
        $overall.Score | Should -Be 57
        $overall.Grade | Should -Be 'C'
        $overall.FindingsCounted | Should -Be 3
        $overall.Caveat | Should -Not -BeNullOrEmpty
    }

    It 'floors the score at 0 rather than going negative' {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        1..10 | ForEach-Object { Add-Finding -Context $c -Category 'Security' -Severity 'Critical' -Confidence 'Confirmed' -Title "C$_" -EvidenceSource 'x' | Out-Null }
        Build-ReadinessScore -Context $c
        $c.DataSets['ReadinessScore'].Rows[0].Score | Should -Be 0
        $c.DataSets['ReadinessScore'].Rows[0].Grade | Should -Be 'F'
    }

    It 'produces exactly 5 subsections, each independently scored' {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-Finding -Context $c -Category 'Identity / AD / DC' -Severity 'Critical' -Confidence 'Confirmed' -Title 'IdCrit' -EvidenceSource 'x' | Out-Null
        Build-ReadinessScore -Context $c
        $subsections = $c.DataSets['ReadinessScoreSubsections'].Rows
        @($subsections).Count | Should -Be 5
        ($subsections | Where-Object { $_.Subsection -eq 'Identity & Access' }).Score | Should -Be 80
        ($subsections | Where-Object { $_.Subsection -eq 'Data & Applications' }).Score | Should -Be 100
    }

    It 'never scores an Info-severity finding' {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-Finding -Context $c -Category 'Security' -Severity 'Info' -Confidence 'Confirmed' -Title 'JustInfo' -EvidenceSource 'x' | Out-Null
        Build-ReadinessScore -Context $c
        $c.DataSets['ReadinessScore'].Rows[0].Score | Should -Be 100
        $c.DataSets['ReadinessScore'].Rows[0].FindingsCounted | Should -Be 0
    }

    It 'does not throw and returns a full score when there are no findings at all' {
        $c = New-DiscoveryContext -Mode Fast -Config $script:Config
        { Build-ReadinessScore -Context $c } | Should -Not -Throw
        $c.DataSets['ReadinessScore'].Rows[0].Score | Should -Be 100
        $c.DataSets['ReadinessScore'].Rows[0].Grade | Should -Be 'A'
    }
}

Describe 'Module metadata contract' {
    $modules = Get-ChildItem (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path 'modules') -Directory
    It '<Name> exposes valid Get-DiscoveryModuleMetadata' -ForEach ($modules | ForEach-Object { @{ Name = $_.Name; Path = (Join-Path $_.FullName ($_.Name + '.psm1')) } }) {
        if (-not (Test-Path $Path)) { Set-ItResult -Skipped -Because 'module file not present'; return }
        Import-Module $Path -Force -DisableNameChecking
        try {
            if (-not (Get-Command -Name 'Get-DiscoveryModuleMetadata' -ErrorAction SilentlyContinue)) {
                Set-ItResult -Skipped -Because "$Name does not expose metadata (framework helper module)"; return
            }
            $m = Get-DiscoveryModuleMetadata
            $m.ModuleName            | Should -Not -BeNullOrEmpty
            $m.EstimatedImpact       | Should -BeIn @('Minimal','Low','Medium','High')
            $m.PSObject.Properties.Name | Should -Contain 'DefaultInFast'
            $m.PSObject.Properties.Name | Should -Contain 'ProducesDatasets'
        } finally {
            # Must unload so the next iteration's Get-Command only sees the module under test -
            # otherwise a module that exposes no metadata would silently test the previous one.
            Remove-Module $Name -Force -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        # The loop above unloaded Core/Output/RiskEngine along with everything else. Put the
        # framework back so Describes that follow this one still have it. Without this, the
        # next Describe fails with 'New-DiscoveryContext is not recognized'.
        Import-DiscoveryFrameworkForTest -RootPath (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    }
}

Describe 'Discovery plan generation' {
    BeforeAll {
        # Self-sufficient by design - see the note in the file-level BeforeAll.
        $script:PlanRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        Import-DiscoveryFrameworkForTest -RootPath $script:PlanRoot
        $script:PlanConfig = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $script:PlanRoot 'config')
    }

    It 'writes discovery-plan.md' {
        $c = New-DiscoveryContext -Mode Fast -Config $script:PlanConfig -OutputPath ([System.IO.Path]::GetTempPath())
        $c.IncludedModules = @('SystemInventory','Applications')
        $c.ExcludedModules = @('SQL')
        $p = Join-Path ([System.IO.Path]::GetTempPath()) ("plan-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.md')
        Write-DiscoveryPlan -Context $c -Path $p
        Test-Path $p | Should -BeTrue
        (Get-Content $p -Raw) | Should -Match 'Discovery Plan'
        Remove-Item $p -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Project-type emphasis' {
    # A rule's projectTypeEmphasis must change PRESENTATION only. If a future change makes
    # emphasis alter severity or the set of findings, these tests fail - that is the point.
    BeforeAll {
        # Re-import the framework explicitly. 'Module metadata contract' above imports every
        # module directory and Remove-Module's each one in its finally - including Core, Output
        # and RiskEngine - so by the time this block runs the framework may be unloaded. Any
        # Describe that needs the framework must therefore set itself up rather than rely on
        # the file-level BeforeAll surviving.
        $script:EmphRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        Import-Module (Join-Path $script:EmphRoot 'modules\Core\Core.psm1')            -Force -DisableNameChecking
        Import-Module (Join-Path $script:EmphRoot 'modules\Output\Output.psm1')        -Force -DisableNameChecking
        Import-Module (Join-Path $script:EmphRoot 'modules\RiskEngine\RiskEngine.psm1') -Force -DisableNameChecking
        $script:EmphConfig = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $script:EmphRoot 'config')

        # Cfg is passed in rather than read from an outer scope so the helper does not depend
        # on how the test host scopes BeforeAll variables.
        function global:New-EmphasisContext {
            param([string]$ProjectType, [object]$Cfg)
            $c = New-DiscoveryContext -Mode Deep -ProjectType $ProjectType -Config $Cfg
            # DomainContext/RolesFeatures drive Decommission-emphasised rules;
            # SecurityPosture drives the CMMCReadiness-emphasised ones;
            # Services carries emitPerRow rules with an evidenceField, which is what populates Subject.
            Add-DataSet -Context $c -Name 'DomainContext'   -Rows @([pscustomobject]@{ IsDomainController=$true; HoldsFsmoRole=$true }) | Out-Null
            Add-DataSet -Context $c -Name 'RolesFeatures'   -Rows @([pscustomobject]@{ Name='DNS'; DisplayName='DNS Server'; InstallState='Installed' }) | Out-Null
            Add-DataSet -Context $c -Name 'SecurityPosture' -Rows @([pscustomobject]@{ Smb1Enabled=$true; RdpEnabledNoNla=$true; AnyAvOrEdrDetected=$false; LocalAdminCount=9 }) | Out-Null
            Add-DataSet -Context $c -Name 'Services'        -Rows @([pscustomobject]@{ Name='AcmeSvc'; DisplayName='Acme Service'; StartName='DOMAIN\svc-acme'; PathName='C:\Acme\a.exe'; ExecutablePath='C:\Acme\a.exe'; UnquotedPathWithSpaces=$false; PathExists=$true; IsNonMicrosoftAutoStart=$true }) | Out-Null
            Invoke-DiscoveryRiskAnalysis -Context $c
            return $c
        }
    }

    It 'Test-RuleEmphasizedForProjectType matches only the listed project types' {
        $rule = [pscustomobject]@{ projectTypeEmphasis = @('Decommission','ServerRefresh') }
        $dec = New-DiscoveryContext -Mode Fast -ProjectType 'Decommission'   -Config $script:EmphConfig
        $azu = New-DiscoveryContext -Mode Fast -ProjectType 'AzureMigration' -Config $script:EmphConfig
        Test-RuleEmphasizedForProjectType -Context $dec -Rule $rule | Should -BeTrue
        Test-RuleEmphasizedForProjectType -Context $azu -Rule $rule | Should -BeFalse
    }

    It 'a rule with no projectTypeEmphasis is never emphasised' {
        $c = New-DiscoveryContext -Mode Fast -ProjectType 'Decommission' -Config $script:EmphConfig
        Test-RuleEmphasizedForProjectType -Context $c -Rule ([pscustomobject]@{ id='X' }) | Should -BeFalse
    }

    It 'GeneralDiscovery applies no lens' {
        $c = New-EmphasisContext -ProjectType 'GeneralDiscovery' -Cfg $script:EmphConfig
        @($c.Findings | Where-Object { $_.IsEmphasized }).Count | Should -Be 0
    }

    It 'Decommission emphasises at least one finding' {
        $c = New-EmphasisContext -ProjectType 'Decommission' -Cfg $script:EmphConfig
        @($c.Findings | Where-Object { $_.IsEmphasized }).Count | Should -BeGreaterThan 0
    }

    It 'different project types emphasise different findings' {
        $dec  = New-EmphasisContext -ProjectType 'Decommission' -Cfg $script:EmphConfig
        $cmmc = New-EmphasisContext -ProjectType 'CMMCReadiness' -Cfg $script:EmphConfig
        $decT  = (@($dec.Findings  | Where-Object { $_.IsEmphasized } | ForEach-Object { $_.Title }) | Sort-Object) -join ';'
        $cmmcT = (@($cmmc.Findings | Where-Object { $_.IsEmphasized } | ForEach-Object { $_.Title }) | Sort-Object) -join ';'
        $decT | Should -Not -Be $cmmcT
    }

    It 'emphasis does not change how many findings are produced' {
        $a = New-EmphasisContext -ProjectType 'GeneralDiscovery' -Cfg $script:EmphConfig
        $b = New-EmphasisContext -ProjectType 'CMMCReadiness' -Cfg $script:EmphConfig
        $b.Findings.Count | Should -Be $a.Findings.Count -Because 'the lens must not change which rules fire'
    }

    It 'emphasis does not escalate severity' {
        $a = New-EmphasisContext -ProjectType 'GeneralDiscovery' -Cfg $script:EmphConfig
        $b = New-EmphasisContext -ProjectType 'CMMCReadiness' -Cfg $script:EmphConfig
        $sa = (@($a.Findings | Sort-Object Title | ForEach-Object { "$($_.Title)=$($_.Severity)" }) -join '|')
        $sb = (@($b.Findings | Sort-Object Title | ForEach-Object { "$($_.Title)=$($_.Severity)" }) -join '|')
        $sb | Should -Be $sa -Because 'emphasis is presentation, never escalation'
    }

    It 'sets an EmphasisReason naming the project type' {
        $c = New-EmphasisContext -ProjectType 'CMMCReadiness' -Cfg $script:EmphConfig
        $e = @($c.Findings | Where-Object { $_.IsEmphasized })
        $e.Count | Should -BeGreaterThan 0
        $e[0].EmphasisReason | Should -Match 'CMMCReadiness'
    }

    It 'populates Subject from the rule evidenceField on per-row findings' {
        $c = New-EmphasisContext -ProjectType 'Decommission' -Cfg $script:EmphConfig
        @($c.Findings | Where-Object { $_.Subject }).Count | Should -BeGreaterThan 0
    }
}
