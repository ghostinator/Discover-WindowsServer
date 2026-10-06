#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    ScopeLanguage.Tests.ps1 - regression coverage for the brand-name substitution in the draft
    scope-language text. The by-category table names the acting party inline via a literal
    '{Brand}' token ("{Brand} assumes...") - swapped for the configured brand name
    (config/output-settings.json's html.brandName) so whoever runs this sees their own company's
    name in draft-scope-language.md, not a placeholder token or someone else's name.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                 -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1')             -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\ScopeLanguage\ScopeLanguage.psm1') -Force -DisableNameChecking

    function New-BrandedContext {
        param([string]$BrandName)
        $config = [pscustomobject]@{ Output = [pscustomobject]@{ html = [pscustomobject]@{ brandName = $BrandName } } }
        return New-DiscoveryContext -Mode Fast -Config $config
    }
}

Describe 'Invoke-DiscoverySynthesis (ScopeLanguage) brand substitution' {
    It 'the always-present baseline entries use the configured brand name' {
        $ctx = New-BrandedContext -BrandName 'Acme MSP Test'
        Invoke-DiscoverySynthesis -Context $ctx
        $baseline = $ctx.ScopeLanguage | Where-Object { $_.Text -match 'validation contacts' }
        $baseline.Text | Should -Match '^Acme MSP Test assumes'
    }

    It 'a category-triggered entry uses the configured brand name' {
        $ctx = New-BrandedContext -BrandName 'Acme MSP Test'
        Add-Finding -Context $ctx -Category 'Database' -Severity 'Low' -Confidence 'Confirmed' -Title 'Test' -EvidenceSource 'x' | Out-Null
        Invoke-DiscoverySynthesis -Context $ctx
        $dbEntry = $ctx.ScopeLanguage | Where-Object { $_.Text -match 'database backups' }
        $dbEntry.Text | Should -Match '^Acme MSP Test assumes'
        $dbEntry.Text | Should -Not -Match '\{Brand\}'
    }

    It 'falls back to the default brand name when nothing is configured' {
        $ctx = New-DiscoveryContext -Mode Fast -Config ([pscustomobject]@{})
        Invoke-DiscoverySynthesis -Context $ctx
        $baseline = $ctx.ScopeLanguage | Where-Object { $_.Text -match 'validation contacts' }
        $baseline.Text | Should -Match '^Your Company assumes'
    }

    It 'an entry with no company-name mention is left untouched' {
        $ctx = New-BrandedContext -BrandName 'Acme MSP Test'
        Invoke-DiscoverySynthesis -Context $ctx
        $exclusion = $ctx.ScopeLanguage | Where-Object { $_.Type -eq 'Exclusion' -and $_.Module -eq 'ScopeLanguage' } | Select-Object -First 1
        $exclusion.Text | Should -Match '^Scope does not include vendor application upgrades'
    }
}
