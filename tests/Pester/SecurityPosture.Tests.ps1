#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    SecurityPosture.Tests.ps1 - fixture-based tests for the Security Posture collector.

    Picked (with ServicesTasks) as the module named in HANDOFF.md/memory as having the
    least real-world exercise so far. New-PostureRow and Test-TlsProtocolEnabled combine
    a lot of independent registry/CIM/cmdlet signals into a handful of booleans that
    drive real findings - RdpEnabledNoNla, AnyAvOrEdrDetected, Smb1Enabled - so getting the
    combining logic right (not just each individual read) is exactly what a fixture can
    pin down and a single live host cannot, since one host is only ever one combination of
    these flags at a time.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                     -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\SecurityPosture\SecurityPosture.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-SecTestContext {
        New-DiscoveryContext -Mode Fast -Config $script:Config
    }

    # Keyed 'Path|Name' -> value. Read dynamically by the Get-RegistryValueSafe mock below,
    # so each It just reassigns this before calling the function under test.
    $script:PostureRegistryValues = @{}
    # Command names Get-CommandAvailable should report as present; everything else is "not
    # available", forcing that path's fallback branch. Empty by default (all fallbacks).
    $script:PostureAvailableCommands = @()
}

Describe 'Test-TlsProtocolEnabled' {
    BeforeEach {
        Mock -CommandName Get-RegistryValueSafe -ModuleName SecurityPosture -MockWith {
            $key = '{0}|{1}' -f $Path, $Name
            if ($script:PostureRegistryValues.ContainsKey($key)) { $script:PostureRegistryValues[$key] } else { $null }
        }
    }

    It 'reports enabled when the Enabled registry value is non-zero' {
        $script:PostureRegistryValues = @{ 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server|Enabled' = 1 }
        Test-TlsProtocolEnabled -Protocol 'TLS 1.0' | Should -BeTrue
    }

    It 'reports disabled when the Enabled registry value is zero' {
        $script:PostureRegistryValues = @{ 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server|Enabled' = 0 }
        Test-TlsProtocolEnabled -Protocol 'TLS 1.1' | Should -BeFalse
    }

    It 'reports NotDetected (false) rather than assuming enabled when the value is not configured at all' {
        # Documented intent: "cannot confirm -> report false, to avoid over-claiming." An
        # absent registry value must never read as "enabled".
        $script:PostureRegistryValues = @{}
        Test-TlsProtocolEnabled -Protocol 'TLS 1.0' | Should -BeFalse
    }
}

Describe 'New-PostureRow' {
    BeforeEach {
        $script:PostureRegistryValues = @{}
        $script:PostureAvailableCommands = @()
        Mock -CommandName Get-CommandAvailable -ModuleName SecurityPosture -MockWith { $script:PostureAvailableCommands -contains $Name }
        Mock -CommandName Get-RegistryValueSafe -ModuleName SecurityPosture -MockWith {
            $key = '{0}|{1}' -f $Path, $Name
            if ($script:PostureRegistryValues.ContainsKey($key)) { $script:PostureRegistryValues[$key] } else { $null }
        }
        Mock -CommandName Test-RegistryPathSafe -ModuleName SecurityPosture -MockWith { $false }
        Mock -CommandName Invoke-CimSafe -ModuleName SecurityPosture -MockWith { @() }
        Mock -CommandName Get-Service -ModuleName SecurityPosture -MockWith { $null }
    }

    It 'flags RdpEnabledNoNla when RDP is enabled and NLA is not required' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{
            'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections'               = 0
            'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication' = 0
        }
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 1
        $row.RdpEnabled      | Should -BeTrue
        $row.NlaEnabled      | Should -BeFalse
        $row.RdpEnabledNoNla | Should -BeTrue
    }

    It 'does not flag RdpEnabledNoNla when NLA is required' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{
            'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections'               = 0
            'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication' = 1
        }
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 1
        $row.NlaEnabled      | Should -BeTrue
        $row.RdpEnabledNoNla | Should -BeFalse
    }

    It 'does not flag RdpEnabledNoNla when RDP itself is disabled, regardless of NLA' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{
            'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections' = 1
        }
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 1
        $row.RdpEnabled      | Should -BeFalse
        $row.RdpEnabledNoNla | Should -BeFalse
    }

    It 'detects SMBv1 via the registry fallback when Get-SmbServerConfiguration is unavailable' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = 1 }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).Smb1Enabled | Should -BeTrue
    }

    It 'detects SMBv1 via Get-SmbServerConfiguration when it is available, ignoring the registry' {
        $ctx = New-SecTestContext
        $script:PostureAvailableCommands = @('Get-SmbServerConfiguration')
        Mock -CommandName Get-SmbServerConfiguration -ModuleName SecurityPosture -MockWith {
            [pscustomobject]@{ EnableSMB1Protocol = $true }
        }
        # Registry says disabled - the cmdlet result must win because it's authoritative.
        $script:PostureRegistryValues = @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = 0 }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).Smb1Enabled | Should -BeTrue
    }

    It 'detects an EDR/AV agent from the Services dataset even when Defender and SecurityCenter2 see nothing' {
        $ctx = New-SecTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ DisplayName = 'SentinelOne Agent' }
        ) | Out-Null
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0
        $row.DefenderEnabled      | Should -BeFalse
        $row.ThirdPartyAvPresent  | Should -BeFalse
        $row.AnyAvOrEdrDetected   | Should -BeTrue -Because 'the EDR service name match should be enough on its own'
    }

    It 'detects a third-party AV product from SecurityCenter2 even when Defender and EDR services see nothing' {
        $ctx = New-SecTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName SecurityPosture -MockWith {
            if ($ClassName -eq 'AntiVirusProduct') { @([pscustomobject]@{ displayName = 'Some Third-Party AV' }) } else { @() }
        }
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0
        $row.ThirdPartyAvPresent | Should -BeTrue
        $row.AnyAvOrEdrDetected  | Should -BeTrue
    }

    It 'does not count a SecurityCenter2 entry named Defender as a third-party product' {
        $ctx = New-SecTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName SecurityPosture -MockWith {
            if ($ClassName -eq 'AntiVirusProduct') { @([pscustomobject]@{ displayName = 'Windows Defender' }) } else { @() }
        }
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0
        $row.ThirdPartyAvPresent | Should -BeFalse
    }

    It 'reports AnyAvOrEdrDetected false when Defender, third-party AV, and known EDR services are all absent' {
        $ctx = New-SecTestContext
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0
        $row.AnyAvOrEdrDetected | Should -BeFalse
    }

    It 'reads UacEnabled from the EnableLUA registry value' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{ 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA' = 1 }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).UacEnabled | Should -BeTrue
    }

    It 'reports BitLockerAnyProtected true only when at least one volume is actually On' {
        $ctx = New-SecTestContext
        $script:PostureAvailableCommands = @('Get-BitLockerVolume')
        Mock -CommandName Get-BitLockerVolume -ModuleName SecurityPosture -MockWith {
            @(
                [pscustomobject]@{ ProtectionStatus = 'Off' }
                [pscustomobject]@{ ProtectionStatus = 'On' }
            )
        }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).BitLockerAnyProtected | Should -BeTrue
    }

    It 'reports BitLockerAnyProtected false when every volume is Off' {
        $ctx = New-SecTestContext
        $script:PostureAvailableCommands = @('Get-BitLockerVolume')
        Mock -CommandName Get-BitLockerVolume -ModuleName SecurityPosture -MockWith {
            @([pscustomobject]@{ ProtectionStatus = 'Off' })
        }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).BitLockerAnyProtected | Should -BeFalse
    }

    It 'detects LAPS from either known registry location' {
        $ctx = New-SecTestContext
        Mock -CommandName Test-RegistryPathSafe -ModuleName SecurityPosture -MockWith { $Path -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS' }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).LapsDetected | Should -BeTrue
    }

    It 'flags GuestAccountEnabled only when a user literally named Guest is present and enabled' {
        $ctx = New-SecTestContext
        $users = @(
            [pscustomobject]@{ Name = 'Guest'; Enabled = $true }
            [pscustomobject]@{ Name = 'Administrator'; Enabled = $true }
        )
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0 -Users $users).GuestAccountEnabled | Should -BeTrue
    }

    It 'does not flag GuestAccountEnabled when Guest exists but is disabled' {
        $ctx = New-SecTestContext
        $users = @([pscustomobject]@{ Name = 'Guest'; Enabled = $false })
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0 -Users $users).GuestAccountEnabled | Should -BeFalse
    }

    It 'detects required SMB server signing via Get-SmbServerConfiguration when available' {
        $ctx = New-SecTestContext
        $script:PostureAvailableCommands = @('Get-SmbServerConfiguration')
        Mock -CommandName Get-SmbServerConfiguration -ModuleName SecurityPosture -MockWith { [pscustomobject]@{ EnableSMB1Protocol = $false; RequireSecuritySignature = $true } }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).SmbServerSigningRequired | Should -BeTrue
    }

    It 'falls back to the registry for SMB signing when Get-SmbServerConfiguration is unavailable' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature' = 0 }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).SmbServerSigningRequired | Should -BeFalse
    }

    It 'flags NtlmLegacyCompatibilityAllowed when LmCompatibilityLevel is explicitly below 3' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{ 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel' = 1 }
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0
        $row.LmCompatibilityLevel           | Should -Be 1
        $row.NtlmLegacyCompatibilityAllowed | Should -BeTrue
    }

    It 'does not flag NtlmLegacyCompatibilityAllowed when LmCompatibilityLevel is 3 or higher' {
        $ctx = New-SecTestContext
        $script:PostureRegistryValues = @{ 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel' = 5 }
        (New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0).NtlmLegacyCompatibilityAllowed | Should -BeFalse
    }

    It 'does not flag NtlmLegacyCompatibilityAllowed when the policy is not configured at all, to avoid over-claiming' {
        $ctx = New-SecTestContext
        $row = New-PostureRow -Context $ctx -FirewallProfiles @() -AdminCount 0
        $row.LmCompatibilityLevel           | Should -BeNullOrEmpty
        $row.NtlmLegacyCompatibilityAllowed | Should -BeFalse
    }
}

Describe 'Get-NonExpiringPasswordAccounts' {
    It 'includes only enabled accounts with a non-expiring password' {
        $users = @(
            [pscustomobject]@{ Name = 'Administrator'; Enabled = $true;  PasswordNeverExpires = $true }
            [pscustomobject]@{ Name = 'svc-app';        Enabled = $true;  PasswordNeverExpires = $false }
            [pscustomobject]@{ Name = 'OldDisabled';    Enabled = $false; PasswordNeverExpires = $true }
        )
        $result = @(Get-NonExpiringPasswordAccounts -Users $users)
        $result.Count        | Should -Be 1
        $result[0].Name      | Should -Be 'Administrator'
    }

    It 'returns an empty array, not null, when nothing matches' {
        $result = Get-NonExpiringPasswordAccounts -Users @([pscustomobject]@{ Name = 'x'; Enabled = $true; PasswordNeverExpires = $false })
        @($result).Count | Should -Be 0
    }
}

Describe 'Get-SensitiveUserRightsGrants' {
    # secedit's own USER_RIGHTS export renders well-known built-in groups as raw SIDs
    # ("*S-1-5-32-544" for Administrators) and only resolves to a plain name for a genuine
    # custom/domain account - confirmed live. These fixtures use that same real shape.

    # NOTE: every assertion below assigns the function's result to a variable BEFORE wrapping
    # it in @() for .Count - never @(Get-SensitiveUserRightsGrants ...).Count directly. The
    # function returns ,@($list) (this repo's own established-safe shape for a function that
    # must always return an array, even empty/single-element); wrapping the CALL ITSELF in
    # @() nests that result one level deeper instead of flattening it - confirmed live while
    # writing this file: @(Get-SensitiveUserRightsGrants -Rights $rights).Count reported 1 for
    # an input that should score 0, while the bare-assign-then-@() form correctly reported 0
    # for the exact same input. Same footgun class already documented in TODO.md item 8 for
    # Get-FingerprintMatches.

    It 'does not flag SeDebugPrivilege granted only to the well-known Administrators SID' {
        $rights = @([pscustomobject]@{ Right = 'SeDebugPrivilege'; Principals = '*S-1-5-32-544' })
        $result = Get-SensitiveUserRightsGrants -Rights $rights
        @($result).Count | Should -Be 0
    }

    It 'flags SeDebugPrivilege granted to a real named account alongside Administrators' {
        $rights = @([pscustomobject]@{ Right = 'SeDebugPrivilege'; Principals = '*S-1-5-32-544,svc-monitoring' })
        $result = Get-SensitiveUserRightsGrants -Rights $rights
        @($result).Count                | Should -Be 1
        $result[0].UnexpectedPrincipals  | Should -Be 'svc-monitoring'
    }

    It 'flags SeTcbPrivilege granted to anyone at all, since the default is nobody' {
        $rights = @([pscustomobject]@{ Right = 'SeTcbPrivilege'; Principals = '*S-1-5-32-544' })
        $result = Get-SensitiveUserRightsGrants -Rights $rights
        @($result).Count | Should -Be 1
    }

    It 'ignores rights outside the curated sensitive list entirely' {
        $rights = @([pscustomobject]@{ Right = 'SeChangeNotifyPrivilege'; Principals = 'Everyone' })
        $result = Get-SensitiveUserRightsGrants -Rights $rights
        @($result).Count | Should -Be 0
    }

    It 'accepts Server Operators and Backup Operators for SeBackupPrivilege without flagging' {
        $rights = @([pscustomobject]@{ Right = 'SeBackupPrivilege'; Principals = '*S-1-5-32-544,*S-1-5-32-549,*S-1-5-32-551' })
        $result = Get-SensitiveUserRightsGrants -Rights $rights
        @($result).Count | Should -Be 0
    }
}

Describe 'Get-LocalAdministrators' {

    It 'builds rows from Get-LocalGroupMember when the LocalAccounts cmdlets are available' {
        Mock -CommandName Get-CommandAvailable -ModuleName SecurityPosture -MockWith { $Name -eq 'Get-LocalGroupMember' }
        Mock -CommandName Get-LocalGroup -ModuleName SecurityPosture -MockWith { [pscustomobject]@{ Name = 'Administrators' } }
        Mock -CommandName Get-LocalGroupMember -ModuleName SecurityPosture -MockWith {
            @(
                [pscustomobject]@{ Name = 'CORP\Domain Admins'; ObjectClass = 'Group'; PrincipalSource = 'ActiveDirectory' }
                [pscustomobject]@{ Name = "$env:COMPUTERNAME\Administrator"; ObjectClass = 'User'; PrincipalSource = 'Local' }
            )
        }
        $admins = Get-LocalAdministrators
        $admins.Count | Should -Be 2
        ($admins | Where-Object Member -like '*Domain Admins').ObjectClass | Should -Be 'Group'
    }

    It 'falls back to parsing net.exe localgroup output when the LocalAccounts cmdlets are unavailable' {
        Mock -CommandName Get-CommandAvailable -ModuleName SecurityPosture -MockWith { $false }
        $stdout = @'
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------
Administrator
CORP\Domain Admins
svc-backup
The command completed successfully.

'@
        Mock -CommandName Invoke-CommandLineSafe -ModuleName SecurityPosture -MockWith {
            [pscustomobject]@{ Succeeded = $true; StdOut = $stdout; StdErr = ''; ExitCode = 0; TimedOut = $false }
        }
        $admins = Get-LocalAdministrators
        $admins.Count               | Should -Be 3
        ($admins.Member -contains 'CORP\Domain Admins') | Should -BeTrue
        ($admins | Where-Object Member -eq 'The command completed successfully.') | Should -BeNullOrEmpty
    }
}
