#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    ActiveDirectory.Tests.ps1 - fixture-based tests for the domain context collector.

    Sixth collector covered. Picked for two real logic changes this session with zero prior
    test coverage:
      1. The FSMO "whole host label" match (2026-09-22 fix): netdom query fsmo's output used
         to be matched with a bare substring test, so a DC named DC1 would falsely "hold" a
         role that actually belonged to DC10 (DC1 is a substring of DC10). Now matched with a
         boundary-aware regex. This is exactly the kind of off-by-boundary bug a live lab (one
         DC, or a cluster of differently-prefixed names) may never organically exercise.
      2. AppliedGroupPolicy's "gpresult produced no Applied Group Policy Objects section"
         honest-limitation fix: distinguishes a genuine zero-GPO result (header present,
         then "N/A") from gpresult silently having no RSoP data at all (no header line) -
         seen for real on a 2012 R2 box even right after a successful gpupdate /force.

    Per-mock -ModuleName is enough here (no InModuleScope needed): every command mocked below
    (Invoke-CimSafe, Invoke-CommandLineSafe, Get-CommandAvailable) is cross-module, imported
    from Core.psm1 rather than native to ActiveDirectory.psm1 itself - see
    ConfigDependencyScan.Tests.ps1's header for why that distinction matters.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                       -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\ActiveDirectory\ActiveDirectory.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-AdTestContext {
        New-DiscoveryContext -Mode Fast -Config $script:Config
    }

    # Dispatches by exe name/arguments so one mock can serve netdom/nltest/gpresult calls
    # within a single Invoke-DiscoveryCollection run. $script:-scoped per the ConfigDependency-
    # Scan lesson: a plain local variable is not reliably visible inside a Mock -MockWith body.
    $script:AdNetdomOutput   = ''
    $script:AdGpResultOutput = ''
    $script:AdGpResultOk     = $false
    $script:AdDcListOutput   = ''

    function Set-AdCommandLineMock {
        Mock -CommandName Invoke-CommandLineSafe -ModuleName ActiveDirectory -MockWith {
            switch ($FilePath) {
                'netdom.exe' { [pscustomobject]@{ Succeeded = $true; StdOut = $script:AdNetdomOutput; StdErr = ''; ExitCode = 0; TimedOut = $false } }
                'nltest.exe' {
                    if ($Arguments -contains '/dsgetsite') {
                        [pscustomobject]@{ Succeeded = $true; StdOut = "Default-First-Site-Name`r`nThe command completed successfully"; StdErr = ''; ExitCode = 0; TimedOut = $false }
                    } else {
                        [pscustomobject]@{ Succeeded = $true; StdOut = $script:AdDcListOutput; StdErr = ''; ExitCode = 0; TimedOut = $false }
                    }
                }
                'gpresult.exe' { [pscustomobject]@{ Succeeded = $script:AdGpResultOk; StdOut = $script:AdGpResultOutput; StdErr = ''; ExitCode = 0; TimedOut = $false } }
                default { [pscustomobject]@{ Succeeded = $false; StdOut = ''; StdErr = ''; ExitCode = 1; TimedOut = $false } }
            }
        }
    }
}

Describe 'ConvertTo-AdFunctionalLevelName' {
    It 'maps known numeric levels to their names' {
        ConvertTo-AdFunctionalLevelName -Level 6 | Should -Be 'Windows2012R2'
        ConvertTo-AdFunctionalLevelName -Level 7 | Should -Be 'Windows2016'
        ConvertTo-AdFunctionalLevelName -Level 0 | Should -Be 'Windows2000'
    }
    It 'falls back to a generic LevelN label for an unmapped level' {
        ConvertTo-AdFunctionalLevelName -Level 8 | Should -Be 'Level8'
    }
    It 'returns empty for null' {
        ConvertTo-AdFunctionalLevelName -Level $null | Should -Be ''
    }
}

Describe 'Invoke-DiscoveryCollection - FSMO whole-host-label matching' {

    BeforeEach {
        $script:OrigComputerName = $env:COMPUTERNAME
        $script:AdGpResultOk = $false
        $script:AdGpResultOutput = ''
        $script:AdDcListOutput = ''
        Mock -CommandName Get-CommandAvailable -ModuleName ActiveDirectory -MockWith { $false }   # skip the SmbShare SYSVOL/NETLOGON check, not under test here
        Set-AdCommandLineMock
    }

    AfterEach {
        $env:COMPUTERNAME = $script:OrigComputerName
    }

    It 'does not let DC1 falsely "hold" a role that actually belongs to DC10' {
        $env:COMPUTERNAME = 'DC1'
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 5; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'dc1.corp.local' })
        }
        $script:AdNetdomOutput = "Schema owner               DC10.corp.local`r`nDomain role owner           DC10.corp.local`r`nThe command completed successfully."
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.DomainContext[0].HoldsFsmoRole | Should -BeFalse
    }

    It 'recognizes DC1 correctly when the output genuinely names DC1' {
        $env:COMPUTERNAME = 'DC1'
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 5; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'dc1.corp.local' })
        }
        $script:AdNetdomOutput = "Schema owner               DC1.corp.local`r`nThe command completed successfully."
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.DomainContext[0].HoldsFsmoRole | Should -BeTrue
    }

    It 'still recognizes a longer host name (DC10) correctly, not just guards against DC1' {
        $env:COMPUTERNAME = 'DC10'
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 5; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'dc10.corp.local' })
        }
        $script:AdNetdomOutput = "Schema owner               DC10.corp.local`r`nThe command completed successfully."
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.DomainContext[0].HoldsFsmoRole | Should -BeTrue
    }
}

Describe 'Invoke-DiscoveryCollection - AppliedGroupPolicy honest reporting' {

    BeforeEach {
        # Member Server (not a DC) - keeps the FSMO/SYSVOL block out of the way entirely, so
        # these tests only need to think about the gpresult parsing.
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 3; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'srv1.corp.local' })
        }
        Mock -CommandName Get-CommandAvailable -ModuleName ActiveDirectory -MockWith { $false }
        $script:AdDcListOutput = ''
        Set-AdCommandLineMock
    }

    It 'captures each applied GPO under the header' {
        $script:AdGpResultOk = $true
        $script:AdGpResultOutput = @'
    Applied Group Policy Objects
    -----------------------------
        Default Domain Policy
        Corp Security Baseline

    The following GPOs were not applied because they were filtered out
'@
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.AppliedGroupPolicy.Count | Should -Be 2
        ($raw.AppliedGroupPolicy.PolicyName -contains 'Default Domain Policy') | Should -BeTrue
    }

    It 'does not log the "no section" limitation for a genuine zero-GPO result (header present, then N/A)' {
        $script:AdGpResultOk = $true
        $script:AdGpResultOutput = @'
    Applied Group Policy Objects
    -----------------------------
        N/A
'@
        $ctx = New-AdTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.AppliedGroupPolicy.Count | Should -Be 0
        ($ctx.Limitations | Where-Object { $_.Message -match 'no Applied Group Policy Objects section' }) | Should -BeNullOrEmpty
    }

    It 'logs the "no section" limitation, with gpresult''s own first line, when there is no header at all (no RSoP data)' {
        $script:AdGpResultOk = $true
        $script:AdGpResultOutput = @'
INFO: The user does not have RSOP data.
'@
        $ctx = New-AdTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.AppliedGroupPolicy.Count | Should -Be 0
        $lim = $ctx.Limitations | Where-Object { $_.Message -match 'no Applied Group Policy Objects section' }
        $lim               | Should -Not -BeNullOrEmpty
        $lim.Message        | Should -Match 'does not have RSOP data'
    }

    It 'logs a different limitation when gpresult fails outright' {
        $script:AdGpResultOk = $false
        $script:AdGpResultOutput = ''
        $ctx = New-AdTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.AppliedGroupPolicy.Count | Should -Be 0
        ($ctx.Limitations | Where-Object { $_.Message -match 'may require user context' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-DiscoveryCollection - LDAP signing / channel binding' {
    # DC-only registry keys under NTDS\Parameters - deliberately gated on IsDomainController in
    # the collector so a member server can never compute the same "not enforced" flag a real
    # unhardened DC would (there is no NTDS\Parameters key on a member server at all, so an
    # ungated read would silently come back $null -> "not enforced" -> a false positive on
    # every non-DC in a fleet scan).

    BeforeEach {
        Mock -CommandName Get-CommandAvailable -ModuleName ActiveDirectory -MockWith { $false }
        $script:AdGpResultOk = $false
        $script:AdGpResultOutput = ''
        $script:AdDcListOutput = ''
        $script:AdNetdomOutput = ''
        Set-AdCommandLineMock
    }

    It 'never flags a member server, even if the registry mock would otherwise say "not enforced"' {
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 3; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'srv1.corp.local' })
        }
        Mock -CommandName Get-RegistryValueSafe -ModuleName ActiveDirectory -MockWith { $null }
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.DomainContext[0].LdapSigningNotEnforced        | Should -BeFalse
        $raw.DomainContext[0].LdapChannelBindingNotEnforced | Should -BeFalse
    }

    It 'flags a real DC when LDAPServerIntegrity/LdapEnforceChannelBinding are unconfigured' {
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 5; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'dc1.corp.local' })
        }
        Mock -CommandName Get-RegistryValueSafe -ModuleName ActiveDirectory -MockWith { $null }
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.DomainContext[0].LdapSigningNotEnforced        | Should -BeTrue
        $raw.DomainContext[0].LdapChannelBindingNotEnforced | Should -BeTrue
    }

    It 'does not flag a real DC when both are explicitly hardened' {
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 5; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'dc1.corp.local' })
        }
        Mock -CommandName Get-RegistryValueSafe -ModuleName ActiveDirectory -MockWith {
            if ($Name -eq 'LDAPServerIntegrity') { 2 } elseif ($Name -eq 'LdapEnforceChannelBinding') { 1 } else { $null }
        }
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.DomainContext[0].LdapSigningNotEnforced        | Should -BeFalse
        $raw.DomainContext[0].LdapChannelBindingNotEnforced | Should -BeFalse
    }

    It 'flags LDAP signing alone when only channel binding is hardened' {
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 5; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'dc1.corp.local' })
        }
        Mock -CommandName Get-RegistryValueSafe -ModuleName ActiveDirectory -MockWith {
            if ($Name -eq 'LDAPServerIntegrity') { 1 } elseif ($Name -eq 'LdapEnforceChannelBinding') { 2 } else { $null }
        }
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $raw.DomainContext[0].LdapSigningNotEnforced        | Should -BeTrue
        $raw.DomainContext[0].LdapChannelBindingNotEnforced | Should -BeFalse
    }
}

Describe 'Invoke-DiscoveryCollection - domain controller discovery' {
    It 'parses DC names out of nltest /dclist output' {
        # Real format (captured live from this lab's DC, not guessed): no leading '\\', and a
        # DC line always carries at least one bracket tag ([PDC], [DS], ...), which is what the
        # parsing regex (deliberately) requires to distinguish a DC line from the header/footer.
        Mock -CommandName Invoke-CimSafe -ModuleName ActiveDirectory -MockWith {
            ,@([pscustomobject]@{ DomainRole = 3; PartOfDomain = $true; Domain = 'corp.local'; DNSHostName = 'srv1.corp.local' })
        }
        Mock -CommandName Get-CommandAvailable -ModuleName ActiveDirectory -MockWith { $false }
        $script:AdGpResultOk = $false
        $script:AdGpResultOutput = ''
        $script:AdDcListOutput = @'
Get list of DCs in domain 'corp.local' from '\\DC1.corp.local'.
    DC1.corp.local [PDC]  [DS] Site: Default-First-Site-Name
    DC2.corp.local  [DS] Site: Default-First-Site-Name
The command completed successfully
'@
        Set-AdCommandLineMock
        $raw = Invoke-DiscoveryCollection -Context (New-AdTestContext)
        $names = @($raw.DomainControllerDiscovery | Where-Object Item -eq 'DomainController' | ForEach-Object { $_.DcName })
        $names | Should -Contain 'DC1.corp.local'
        $names | Should -Contain 'DC2.corp.local'
    }
}
