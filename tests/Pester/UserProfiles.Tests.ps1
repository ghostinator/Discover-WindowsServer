#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    UserProfiles.Tests.ps1 - fixture tests for Get-UpSidIsRealUser, the real-user SID filter. A
    wrong answer here either leaks a system account as a "real user" or drops a genuine one -
    small function, correctness-critical.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\UserProfiles\UserProfiles.psm1') -Force -DisableNameChecking
}

Describe 'Get-UpSidIsRealUser' {
    It 'accepts a normal domain/local user SID (S-1-5-21-...)' {
        Get-UpSidIsRealUser -Sid 'S-1-5-21-1111111111-2222222222-3333333333-1001' | Should -BeTrue
    }

    It 'rejects SYSTEM, LOCAL SERVICE and NETWORK SERVICE' {
        Get-UpSidIsRealUser -Sid 'S-1-5-18' | Should -BeFalse
        Get-UpSidIsRealUser -Sid 'S-1-5-19' | Should -BeFalse
        Get-UpSidIsRealUser -Sid 'S-1-5-20' | Should -BeFalse
    }

    It 'rejects a _Classes hive suffix even when the base SID looks like a real user' {
        Get-UpSidIsRealUser -Sid 'S-1-5-21-1111111111-2222222222-3333333333-1001_Classes' | Should -BeFalse
    }

    It 'rejects a well-known SID outside the S-1-5-21- prefix (e.g. Everyone)' {
        Get-UpSidIsRealUser -Sid 'S-1-1-0' | Should -BeFalse
    }

    It 'rejects $null, empty or whitespace without throwing' {
        { Get-UpSidIsRealUser -Sid $null } | Should -Not -Throw
        Get-UpSidIsRealUser -Sid $null | Should -BeFalse
        Get-UpSidIsRealUser -Sid '' | Should -BeFalse
        Get-UpSidIsRealUser -Sid '   ' | Should -BeFalse
    }

    It 'rejects a malformed string that merely contains S-1-5-21 as a substring' {
        Get-UpSidIsRealUser -Sid 'NotReallyS-1-5-21-1001' | Should -BeFalse
    }
}
