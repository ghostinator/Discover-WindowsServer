#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    AzureHybrid.Tests.ps1 - fixture-based tests for the hybrid identity collector.

    Eighth collector covered. Picked for a real fix this session with zero prior test
    coverage: Test-AhEvidence now distinguishes a component that is actually RUNNING from
    one that is merely installed (service present but stopped/disabled, or evidence limited
    to a registry key/app entry) - a real and common gap (e.g. AD FS installed for lab/test
    coverage with no farm ever created). The caller maps that into Confidence: 'Likely' when
    running, 'Possible' when only installed. That confidence split is exactly the kind of
    thing a single live host can't fully exercise (it's only ever one state at a time) but a
    fixture can cover both sides of directly.

    dsregcmd fixture data below was captured live from this lab's DC (`dsregcmd /status`)
    rather than guessed, per the lesson from ActiveDirectory.Tests.ps1's nltest mix-up.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')               -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\AzureHybrid\AzureHybrid.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-AhTestContext {
        New-DiscoveryContext -Mode Fast -Config $script:Config
    }
}

Describe 'Test-AhEvidence' {
    It 'reports Found+Running when a matching service is actually Running' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name = 'ADSync'; DisplayName = 'Microsoft Azure AD Sync'; Status = 'Running' }
        ) | Out-Null
        $res = Test-AhEvidence -Context $ctx -Pattern '(?i)ADSync' -RegistryPaths @()
        $res.Found   | Should -BeTrue
        $res.Running | Should -BeTrue
        $res.Evidence | Should -Match 'service:ADSync'
    }

    It 'reports Found but NOT Running when the matching service is stopped' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name = 'ADSync'; DisplayName = 'Microsoft Azure AD Sync'; Status = 'Stopped' }
        ) | Out-Null
        $res = Test-AhEvidence -Context $ctx -Pattern '(?i)ADSync' -RegistryPaths @()
        $res.Found   | Should -BeTrue
        $res.Running | Should -BeFalse
    }

    It 'reports Found but not Running for app-only evidence (no matching service at all)' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @(
            [pscustomobject]@{ DisplayName = 'Microsoft Azure AD Connect' }
        ) | Out-Null
        $res = Test-AhEvidence -Context $ctx -Pattern '(?i)Azure AD Connect' -RegistryPaths @()
        $res.Found    | Should -BeTrue
        $res.Running  | Should -BeFalse
        $res.Evidence | Should -Match 'app:Microsoft Azure AD Connect'
    }

    It 'reports Found but not Running for registry-only evidence' {
        $ctx = New-AhTestContext
        Mock -CommandName Test-RegistryPathSafe -ModuleName AzureHybrid -MockWith { $true }
        $res = Test-AhEvidence -Context $ctx -Pattern '(?i)NeverMatches' -RegistryPaths @('HKLM:\SOFTWARE\Microsoft\Azure AD Connect')
        $res.Found    | Should -BeTrue
        $res.Running  | Should -BeFalse
        $res.Evidence | Should -Match 'registry:HKLM:\\SOFTWARE\\Microsoft\\Azure AD Connect'
    }

    It 'reports not Found when nothing matches at all' {
        $ctx = New-AhTestContext
        Mock -CommandName Test-RegistryPathSafe -ModuleName AzureHybrid -MockWith { $false }
        $res = Test-AhEvidence -Context $ctx -Pattern '(?i)NeverMatches' -RegistryPaths @('HKLM:\SOFTWARE\Nope')
        $res.Found    | Should -BeFalse
        $res.Evidence | Should -Be ''
    }

    It 'combines evidence from multiple sources' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name = 'ADSync'; DisplayName = 'Microsoft Azure AD Sync'; Status = 'Running' }
        ) | Out-Null
        Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @(
            [pscustomobject]@{ DisplayName = 'Microsoft Azure AD Connect' }
        ) | Out-Null
        $res = Test-AhEvidence -Context $ctx -Pattern '(?i)Azure AD (Sync|Connect)' -RegistryPaths @()
        $res.Evidence | Should -Match 'service:ADSync'
        $res.Evidence | Should -Match 'app:Microsoft Azure AD Connect'
    }
}

Describe 'Invoke-DiscoveryCollection - Confidence reflects actually-running vs merely-installed' {

    BeforeEach {
        Mock -CommandName Get-CommandAvailable -ModuleName AzureHybrid -MockWith { $false }   # skip dsregcmd section
        # Without this, Test-AhEvidence's registry check hits the REAL registry on whatever
        # host runs the suite - and on this lab's own DC, at least one catalog entry's
        # registry path genuinely exists, which made one of these tests depend on live host
        # state instead of being hermetic.
        Mock -CommandName Test-RegistryPathSafe -ModuleName AzureHybrid -MockWith { $false }
    }

    It 'reports Likely confidence when Entra Connect''s service is Running' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name = 'ADSync'; DisplayName = 'Microsoft Azure AD Sync'; Status = 'Running' }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.HybridIdentity | Where-Object Component -eq 'Entra Connect (Azure AD Connect)'
        $row               | Should -Not -BeNullOrEmpty
        $row.Confidence    | Should -Be 'Likely'
    }

    It 'reports Possible confidence when Entra Connect''s service is present but stopped' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name = 'ADSync'; DisplayName = 'Microsoft Azure AD Sync'; Status = 'Stopped' }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.HybridIdentity | Where-Object Component -eq 'Entra Connect (Azure AD Connect)'
        $row.Confidence | Should -Be 'Possible'
    }

    It 'reports Possible confidence for installed-app-only evidence (AD FS present, no service match)' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @(
            [pscustomobject]@{ DisplayName = 'Active Directory Federation Services' }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.HybridIdentity | Where-Object Component -match 'Federation Services'
        $row.Confidence | Should -Be 'Possible'
    }

    It 'does not add a component when nothing matches its catalog pattern' {
        $ctx = New-AhTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.HybridIdentity.Count | Should -Be 0
    }
}

Describe 'Invoke-DiscoveryCollection - dsregcmd join state' {
    It 'parses join-state lines from real dsregcmd /status output' {
        $ctx = New-AhTestContext
        Mock -CommandName Get-CommandAvailable -ModuleName AzureHybrid -MockWith { $true }
        # Captured live via `dsregcmd /status` on this lab's DC.
        $stdout = @'
             AzureAdJoined : NO
          EnterpriseJoined : NO
              DomainJoined : YES
           WorkplaceJoined : NO
'@
        Mock -CommandName Invoke-CommandLineSafe -ModuleName AzureHybrid -MockWith {
            [pscustomobject]@{ Succeeded = $true; StdOut = $stdout; StdErr = ''; ExitCode = 0; TimedOut = $false }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($raw.AzureAttachment | Where-Object Item -eq 'Entra joined').Value  | Should -Be 'NO'
        ($raw.AzureAttachment | Where-Object Item -eq 'Domain joined').Value | Should -Be 'YES'
    }

    It 'logs a limitation when dsregcmd returns no usable output' {
        $ctx = New-AhTestContext
        Mock -CommandName Get-CommandAvailable -ModuleName AzureHybrid -MockWith { $true }
        Mock -CommandName Invoke-CommandLineSafe -ModuleName AzureHybrid -MockWith {
            [pscustomobject]@{ Succeeded = $false; StdOut = ''; StdErr = 'error'; ExitCode = 1; TimedOut = $false }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($ctx.Limitations | Where-Object { $_.Message -match 'dsregcmd /status returned no usable output' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-DiscoveryCollection - cloud endpoints from ConfigDependencyHints' {

    BeforeEach {
        Mock -CommandName Get-CommandAvailable -ModuleName AzureHybrid -MockWith { $false }
    }

    It 'surfaces a cloud-endpoint attachment when a config hint references one' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'ConfigDependencyHints' -Rows @(
            [pscustomobject]@{ FilePath = 'C:\inetpub\app\web.config'; RedactedLine = 'GraphEndpoint=https://graph.microsoft.com/v1.0' }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($raw.AzureAttachment | Where-Object Item -match 'cloud endpoints referenced') | Should -Not -BeNullOrEmpty
    }

    It 'does not surface a cloud-endpoint attachment when no hint references one' {
        $ctx = New-AhTestContext
        Add-DataSet -Context $ctx -Name 'ConfigDependencyHints' -Rows @(
            [pscustomobject]@{ FilePath = 'C:\app\local.config'; RedactedLine = 'Server=sql01;Database=ERP' }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($raw.AzureAttachment | Where-Object Item -match 'cloud endpoints referenced') | Should -BeNullOrEmpty
    }
}
