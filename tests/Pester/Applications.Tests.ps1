#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Applications.Tests.ps1 - fixture tests for Get-FingerprintMatches, the confidence-scoring
    logic that directly feeds the client report's "business applications we recognised" table
    (a misclassification here is client-visible, not just an internal detail).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')         -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1')     -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Applications\Applications.psm1') -Force -DisableNameChecking

    # Small, self-contained fixture matching config\application-fingerprints.json's real schema -
    # not the real (larger, evolving) file, so this test never breaks because someone added a
    # fingerprint for an unrelated product.
    $script:FakeFingerprints = ConvertFrom-Json @'
{
  "confidenceModel": {
    "oneWeakMatch": "Possible",
    "oneStrongMatch": "Likely",
    "multipleMatches": "Confirmed",
    "strongSources": ["Services", "InstalledApplications"]
  },
  "fingerprints": [
    {
      "applicationName": "Acme ERP",
      "vendor": "Acme",
      "category": "ERP",
      "likelyDependencyType": "Application Server",
      "potentialProjectImpact": ["Data Migration"],
      "suggestedValidationQuestion": "Who owns Acme ERP?",
      "matchers": [
        { "source": "Services", "field": "Name", "pattern": "(?i)^AcmeErpSvc$" },
        { "source": "InstalledApplications", "field": "DisplayName", "pattern": "(?i)Acme ERP" }
      ]
    },
    {
      "applicationName": "Weak Signal Tool",
      "vendor": "Someone",
      "category": "Utility",
      "likelyDependencyType": "Utility",
      "potentialProjectImpact": [],
      "suggestedValidationQuestion": "Is this still used?",
      "matchers": [
        { "source": "RunningProcesses", "field": "Name", "pattern": "(?i)^weaksignal\\.exe$" }
      ]
    }
  ]
}
'@

    function New-FingerprintContext {
        <# Builds a real context via Core.psm1/Output.psm1 with the fake fingerprints config wired in, and whatever DataSets the caller supplies. #>
        param([hashtable]$Datasets = @{})
        $ctx = New-DiscoveryContext -Mode Fast -Config ([pscustomobject]@{ Fingerprints = $script:FakeFingerprints })
        foreach ($name in $Datasets.Keys) { Add-DataSet -Context $ctx -Name $name -Rows $Datasets[$name] | Out-Null }
        return $ctx
    }
}

Describe 'Get-FingerprintMatches' {
    # Get-FingerprintMatches returns ,@($results) - Invoke-DiscoveryFingerprintSynthesis's own
    # comment explains why: assign it BARE, then @() the already-assigned variable if you need to
    # count/index it. Wrapping the CALL itself in @() (`@(Get-FingerprintMatches ...)`) nests the
    # result one level deeper instead - the exact bug class that broke the fleet client summary's
    # tables earlier this session (Get-FleetClientSafeDataset/Merge-FleetDataset). Every test here
    # follows the safe two-step pattern rather than the shortcut, on purpose.

    It 'returns Confirmed when two or more matchers hit, regardless of source strength' {
        $ctx = New-FingerprintContext -Datasets @{
            Services = @([pscustomobject]@{ Name = 'AcmeErpSvc' })
            InstalledApplications = @([pscustomobject]@{ DisplayName = 'Acme ERP Suite 4.2' })
        }
        $raw = Get-FingerprintMatches -Context $ctx
        $matches = @($raw)
        $hit = $matches | Where-Object { $_.ApplicationName -eq 'Acme ERP' }
        $hit | Should -Not -BeNullOrEmpty
        $hit.Confidence | Should -Be 'Confirmed'
    }

    It 'returns Likely for exactly one match on a strong source' {
        $ctx = New-FingerprintContext -Datasets @{
            Services = @([pscustomobject]@{ Name = 'AcmeErpSvc' })
        }
        $raw = Get-FingerprintMatches -Context $ctx
        $matches = @($raw)
        $hit = $matches | Where-Object { $_.ApplicationName -eq 'Acme ERP' }
        $hit.Confidence | Should -Be 'Likely'
    }

    It 'returns Possible for exactly one match on a weak (non-strong) source' {
        $ctx = New-FingerprintContext -Datasets @{
            RunningProcesses = @([pscustomobject]@{ Name = 'weaksignal.exe' })
        }
        $raw = Get-FingerprintMatches -Context $ctx
        $matches = @($raw)
        $hit = $matches | Where-Object { $_.ApplicationName -eq 'Weak Signal Tool' }
        $hit.Confidence | Should -Be 'Possible'
    }

    It 'does not report a fingerprint with zero matcher hits' {
        $ctx = New-FingerprintContext -Datasets @{
            Services = @([pscustomobject]@{ Name = 'SomethingUnrelated' })
        }
        $raw = Get-FingerprintMatches -Context $ctx
        $matches = @($raw)
        ($matches | Where-Object { $_.ApplicationName -eq 'Acme ERP' }) | Should -BeNullOrEmpty
    }

    It 'returns an empty array rather than throwing when the fingerprints config is missing entirely' {
        $ctx = New-DiscoveryContext -Mode Fast -Config ([pscustomobject]@{})
        { Get-FingerprintMatches -Context $ctx } | Should -Not -Throw
        $raw = Get-FingerprintMatches -Context $ctx
        @($raw).Count | Should -Be 0
    }

    It 'does not throw when a dataset a matcher references was never collected' {
        $ctx = New-FingerprintContext -Datasets @{}
        { Get-FingerprintMatches -Context $ctx } | Should -Not -Throw
    }
}
