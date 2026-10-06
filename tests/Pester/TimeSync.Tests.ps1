#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    TimeSync.Tests.ps1 - fixture tests for ConvertFrom-W32tmOffset/Get-W32tmField, the w32tm
    /status text parser. Explicitly returns $null (never 0) when unparseable, since a silent
    zero would read as "healthy" and be a lie - worth locking in with a test.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\TimeSync\TimeSync.psm1') -Force -DisableNameChecking
}

Describe 'ConvertFrom-W32tmOffset' {
    It 'parses a positive phase offset' {
        ConvertFrom-W32tmOffset -Text 'Phase Offset: 0.0012345s' | Should -Be 0.0012
    }

    It 'parses a negative phase offset' {
        ConvertFrom-W32tmOffset -Text 'Phase Offset: -1.5s' | Should -Be -1.5
    }

    It 'finds the field within a larger multi-line w32tm /status block' {
        $text = @'
Leap Indicator: 0(no warning)
Stratum: 3 (secondary reference - syncd by (S)NTP)
Phase Offset: 0.5s
Poll Interval: 10 (1024s)
'@
        ConvertFrom-W32tmOffset -Text $text | Should -Be 0.5
    }

    It 'returns $null (not 0) for text with no Phase Offset line at all' {
        ConvertFrom-W32tmOffset -Text 'Leap Indicator: 0(no warning)' | Should -BeNullOrEmpty
    }

    It 'returns $null (not 0) for an unparseable offset value' {
        ConvertFrom-W32tmOffset -Text 'Phase Offset: notanumber s' | Should -BeNullOrEmpty
    }

    It 'returns $null for null/blank input rather than throwing' {
        { ConvertFrom-W32tmOffset -Text $null } | Should -Not -Throw
        ConvertFrom-W32tmOffset -Text $null | Should -BeNullOrEmpty
        ConvertFrom-W32tmOffset -Text '   ' | Should -BeNullOrEmpty
    }
}

Describe 'Get-W32tmField' {
    It 'extracts a labeled field''s value' {
        Get-W32tmField -Text "Stratum: 3 (secondary reference)" -Label 'Stratum' | Should -Be '3 (secondary reference)'
    }

    It 'returns an empty string (not $null or a throw) when the label is not present' {
        { Get-W32tmField -Text 'Stratum: 3' -Label 'Source' } | Should -Not -Throw
        Get-W32tmField -Text 'Stratum: 3' -Label 'Source' | Should -Be ''
    }

    It 'treats the label as a literal string, not a regex, when it contains regex metacharacters' {
        Get-W32tmField -Text 'C.O(M): value' -Label 'C.O(M)' | Should -Be 'value'
    }
}
