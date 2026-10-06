#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    RolesFeatures.Tests.ps1 - fixture tests for ConvertFrom-DismFeatureText (parses two different
    'dism /online /get-features' output formats) and Get-RolesFeaturesDetectedFunctions (the
    regex-based role classifier feeding every report's "likely server role" line).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\RolesFeatures\RolesFeatures.psm1') -Force -DisableNameChecking
}

Describe 'ConvertFrom-DismFeatureText' {
    # Both functions under test return ,@($list) - bare-assign first, @() the variable
    # afterward if you need .Count/indexing. Wrapping the CALL in @() nests it one level deeper
    # instead (the same bug class that broke the fleet client summary's tables earlier this
    # session) - every test here follows the safe two-step pattern on purpose.

    It 'parses the table format (columns separated by |)' {
        $text = @'
Feature Name                                | State
-------------------------------------------------------------
NetFx4-AdvSrvs                              | Enabled
IIS-WebServer                               | Disabled
'@
        $raw = ConvertFrom-DismFeatureText -Text $text
        $items = @($raw)
        $items.Count | Should -Be 2
        ($items | Where-Object { $_.Name -eq 'NetFx4-AdvSrvs' }).State | Should -Be 'Enabled'
        ($items | Where-Object { $_.Name -eq 'IIS-WebServer' }).State | Should -Be 'Disabled'
    }

    It 'parses the classic Feature Name / State pair format' {
        $text = @'
Feature Name : NetFx4-AdvSrvs
State : Enabled

Feature Name : IIS-WebServer
State : Disabled
'@
        $raw = ConvertFrom-DismFeatureText -Text $text
        $items = @($raw)
        $items.Count | Should -Be 2
        ($items | Where-Object { $_.Name -eq 'NetFx4-AdvSrvs' }).State | Should -Be 'Enabled'
    }

    It 'returns an empty array (not $null or a throw) for null or blank input' {
        { ConvertFrom-DismFeatureText -Text $null } | Should -Not -Throw
        $raw1 = ConvertFrom-DismFeatureText -Text $null
        @($raw1).Count | Should -Be 0
        $raw2 = ConvertFrom-DismFeatureText -Text '   '
        @($raw2).Count | Should -Be 0
    }

    It 'ignores the table header row and separator line' {
        $text = @'
Feature Name | State
-------------|--------
RealFeature  | Enabled
'@
        $raw = ConvertFrom-DismFeatureText -Text $text
        $items = @($raw)
        $items.Count | Should -Be 1
        $items[0].Name | Should -Be 'RealFeature'
    }

    It 'ignores a table row whose State does not start with Enabled or Disabled' {
        $text = 'SomeFeature | Unknown'
        $raw = ConvertFrom-DismFeatureText -Text $text
        @($raw).Count | Should -Be 0
    }
}

Describe 'Get-RolesFeaturesDetectedFunctions' {
    It 'detects a role by matching the Name field against the pattern' {
        $rows = @([pscustomobject]@{ Name = 'Web-Server'; DisplayName = '' })
        $raw = Get-RolesFeaturesDetectedFunctions -Rows $rows
        $labels = @($raw)
        $labels | Should -Contain 'IIS Web Server'
    }

    It 'detects a role by matching the DisplayName field when Name does not match' {
        $rows = @([pscustomobject]@{ Name = ''; DisplayName = 'Hyper-V' })
        $raw = Get-RolesFeaturesDetectedFunctions -Rows $rows
        $labels = @($raw)
        $labels | Should -Contain 'Hyper-V Virtualization Host'
    }

    It 'never returns the same label twice even if multiple rows match it' {
        $rows = @(
            [pscustomobject]@{ Name = 'RDS-RD-Server'; DisplayName = '' }
            [pscustomobject]@{ Name = 'Remote-Desktop-Services'; DisplayName = '' }
        )
        $raw = Get-RolesFeaturesDetectedFunctions -Rows $rows
        $labels = @($raw)
        @($labels | Where-Object { $_ -eq 'Remote Desktop Services (RDS)' }).Count | Should -Be 1
    }

    It 'anchored patterns do not false-positive on an unrelated substring match' {
        # ^DNS$ must not match a feature merely containing "DNS" as part of a longer name.
        $rows = @([pscustomobject]@{ Name = 'DNS-Server-Some-Other-Thing'; DisplayName = '' })
        $raw = Get-RolesFeaturesDetectedFunctions -Rows $rows
        $labels = @($raw)
        $labels | Should -Not -Contain 'DNS Server'
    }

    It 'returns an empty array (not $null or a throw) for no rows' {
        { Get-RolesFeaturesDetectedFunctions -Rows @() } | Should -Not -Throw
        $raw = Get-RolesFeaturesDetectedFunctions -Rows @()
        @($raw).Count | Should -Be 0
        { Get-RolesFeaturesDetectedFunctions -Rows $null } | Should -Not -Throw
    }

    It 'skips a $null row in the input rather than throwing' {
        $rows = @($null, [pscustomobject]@{ Name = 'Web-Server'; DisplayName = '' })
        { Get-RolesFeaturesDetectedFunctions -Rows $rows } | Should -Not -Throw
        $raw = Get-RolesFeaturesDetectedFunctions -Rows $rows
        @($raw) | Should -Contain 'IIS Web Server'
    }
}
