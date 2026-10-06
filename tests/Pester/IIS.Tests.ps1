#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    IIS.Tests.ps1 - fixture-based tests for the IIS collector.

    Seventh collector covered. Picked for a real fix this session with zero prior test
    coverage: the appcmd fallback (used when the WebAdministration module isn't present, e.g.
    non-elevated or a leaner install) used to truncate a site's bindings at the first comma -
    a site with more than one binding (http + https, or two hostheaders on the same protocol)
    only ever produced ONE IisBindings row. Fixed by capturing the whole bindings run
    non-greedily up to ",state:" and then splitting THAT on commas. Regression-tested directly
    with a two-binding site below.

    Get-IisAppCmdPath is native to this module (same gotcha as ConfigDependencyScan's
    Get-ConfigScanRoots - mocking it directly would need InModuleScope). Sidestepped instead by
    mocking Test-Path (a cross-module external cmdlet, no InModuleScope needed) so the REAL
    Get-IisAppCmdPath body runs unmocked and just believes the path exists.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\IIS\IIS.psm1')   -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-IisTestContext {
        New-DiscoveryContext -Mode Fast -Config $script:Config
    }

    # Forces the appcmd fallback path: WebAdministration reads as unavailable, and
    # Get-IisAppCmdPath's own Test-Path call believes appcmd.exe exists without touching disk.
    function Set-IisAppcmdFallbackMocks {
        Mock -CommandName Get-ModuleAvailable -ModuleName IIS -MockWith { $false }
        Mock -CommandName Test-Path -ModuleName IIS -ParameterFilter { $Path -like '*appcmd.exe' } -MockWith { $true }
    }
}

Describe 'Test-IisIdentityIsDomainAccount' {
    It 'treats DOMAIN\user as a domain account' {
        Test-IisIdentityIsDomainAccount -acct 'CORP\svc-web' | Should -BeTrue
    }
    It 'treats an IIS APPPOOL identity as built-in, not a domain account' {
        Test-IisIdentityIsDomainAccount -acct 'IIS APPPOOL\DefaultAppPool' | Should -BeFalse
    }
    It 'treats NT AUTHORITY\... as a built-in identity' {
        Test-IisIdentityIsDomainAccount -acct 'NT AUTHORITY\NETWORK SERVICE' | Should -BeFalse
    }
    It 'treats BUILTIN\... as a built-in identity' {
        Test-IisIdentityIsDomainAccount -acct 'BUILTIN\Administrators' | Should -BeFalse
    }
    It 'returns false for blank input' {
        Test-IisIdentityIsDomainAccount -acct '' | Should -BeFalse
    }
    It 'returns false for a string with no backslash' {
        Test-IisIdentityIsDomainAccount -acct 'ApplicationPoolIdentity' | Should -BeFalse
    }
}

Describe 'Test-IisPresent' {
    It 'is true when the W3SVC service exists' {
        Mock -CommandName Get-Service -ModuleName IIS -MockWith { [pscustomobject]@{ Name = 'W3SVC' } }
        Mock -CommandName Test-Path -ModuleName IIS -MockWith { $false }
        Mock -CommandName Get-ModuleAvailable -ModuleName IIS -MockWith { $false }
        Test-IisPresent | Should -BeTrue
    }
    It 'is true when appcmd.exe exists even without the W3SVC service being found' {
        Mock -CommandName Get-Service -ModuleName IIS -MockWith { $null }
        Mock -CommandName Test-Path -ModuleName IIS -ParameterFilter { $Path -like '*appcmd.exe' } -MockWith { $true }
        Mock -CommandName Get-ModuleAvailable -ModuleName IIS -MockWith { $false }
        Test-IisPresent | Should -BeTrue
    }
    It 'is false when none of service, appcmd, or WebAdministration are present' {
        Mock -CommandName Get-Service -ModuleName IIS -MockWith { $null }
        Mock -CommandName Test-Path -ModuleName IIS -MockWith { $false }
        Mock -CommandName Get-ModuleAvailable -ModuleName IIS -MockWith { $false }
        Test-IisPresent | Should -BeFalse
    }
}

Describe 'Invoke-DiscoveryCollection - appcmd fallback' {

    It 'splits a multi-binding site into one IisBindings row per binding, not one truncated at the first comma' {
        $ctx = New-IisTestContext
        Set-IisAppcmdFallbackMocks
        $siteOut = 'SITE "Multi Binding Site" (id:2,bindings:http/*:8080:,http/*:8081:internal.corp.local,state:Started)'
        Mock -CommandName Invoke-CommandLineSafe -ModuleName IIS -MockWith {
            if ($Arguments -contains 'site') { [pscustomobject]@{ Succeeded = $true; StdOut = $siteOut; StdErr = ''; ExitCode = 0; TimedOut = $false } }
            else { [pscustomobject]@{ Succeeded = $true; StdOut = ''; StdErr = ''; ExitCode = 0; TimedOut = $false } }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.IisSites.Count | Should -Be 1
        $raw.IisSites[0].State | Should -Be 'Started'
        $siteBindings = @($raw.IisBindings | Where-Object Site -eq 'Multi Binding Site')
        $siteBindings.Count | Should -Be 2 -Because 'the site has two distinct bindings, both must survive'
        ($siteBindings | Where-Object BindingInformation -eq '*:8081:internal.corp.local').Protocol | Should -Be 'http'
    }

    It 'parses separate http and https bindings on the same site' {
        $ctx = New-IisTestContext
        Set-IisAppcmdFallbackMocks
        $siteOut = 'SITE "Default Web Site" (id:1,bindings:http/*:80:,https/*:443:,state:Started)'
        Mock -CommandName Invoke-CommandLineSafe -ModuleName IIS -MockWith {
            if ($Arguments -contains 'site') { [pscustomobject]@{ Succeeded = $true; StdOut = $siteOut; StdErr = ''; ExitCode = 0; TimedOut = $false } }
            else { [pscustomobject]@{ Succeeded = $true; StdOut = ''; StdErr = ''; ExitCode = 0; TimedOut = $false } }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $bindings = @($raw.IisBindings | Where-Object Site -eq 'Default Web Site')
        $bindings.Count | Should -Be 2
        ($bindings.Protocol -contains 'http')  | Should -BeTrue
        ($bindings.Protocol -contains 'https') | Should -BeTrue
    }

    It 'flags an app pool on the legacy .NET runtime (v2.0) and not one on v4.0' {
        $ctx = New-IisTestContext
        Set-IisAppcmdFallbackMocks
        $poolOut = @'
APPPOOL "DefaultAppPool" (MgdVersion:v4.0,MgdMode:Integrated,state:Started)
APPPOOL "LegacyPool" (MgdVersion:v2.0,MgdMode:Classic,state:Stopped)
'@
        Mock -CommandName Invoke-CommandLineSafe -ModuleName IIS -MockWith {
            if ($Arguments -contains 'apppool') { [pscustomobject]@{ Succeeded = $true; StdOut = $poolOut; StdErr = ''; ExitCode = 0; TimedOut = $false } }
            else { [pscustomobject]@{ Succeeded = $true; StdOut = ''; StdErr = ''; ExitCode = 0; TimedOut = $false } }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.IisAppPools.Count | Should -Be 2
        ($raw.IisAppPools | Where-Object Name -eq 'DefaultAppPool').IsLegacyDotNet | Should -BeFalse
        ($raw.IisAppPools | Where-Object Name -eq 'LegacyPool').IsLegacyDotNet     | Should -BeTrue
    }

    It 'logs a limitation when no IIS management tooling is available at all' {
        $ctx = New-IisTestContext
        Mock -CommandName Get-ModuleAvailable -ModuleName IIS -MockWith { $false }
        Mock -CommandName Test-Path -ModuleName IIS -MockWith { $false }   # appcmd.exe does not exist either
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.IisSites.Count | Should -Be 0
        ($ctx.Limitations | Where-Object { $_.Message -match 'No IIS management tooling available' }) | Should -Not -BeNullOrEmpty
    }
}
