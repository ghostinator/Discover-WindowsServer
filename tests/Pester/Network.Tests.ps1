#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Network.Tests.ps1 - fixture-based tests for the Network collector.

    Two things this session found the hard way, live, which fixtures now guard forever:
      1. Get-NwNetstatRows's 'clean array via ,@()' contract, and the specific double-wrap
         bug (an extra @() at the call site collapses every consumer's foreach into one
         iteration over the whole array) - see HISTORY.md.
      2. Get-NwFirewallRows's bulk-fetch-and-join-by-InstanceID enrichment, which replaced
         an O(n) per-rule cmdlet call pattern that took 65s+ on this lab.

    NOTE: every Get-Nw* function here returns via 'return ,@($rows)'. That unrolls
    correctly on DIRECT assignment ($x = Get-Foo) but NOT if the call itself is wrapped
    in an extra @() ($x = @(Get-Foo)) - the exact double-wrap bug this file guards
    against. Writing the test that way silently hides the bug it's meant to catch (an
    early draft of this file did exactly that and every count assertion read 1
    regardless of the real row count). Call sites below assign directly; @() is only
    used around an already-materialized variable/property, which is safe.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')       -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Network\Network.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-NwTestContext {
        New-DiscoveryContext -Mode Fast -Config $script:Config
    }
}

Describe 'Get-NwNetstatRows' {

    It 'parses TCP and UDP lines and skips headers/malformed lines' {
        $ctx = New-NwTestContext
        $stdout = @'
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    10.0.0.5:3389          10.0.0.9:51000         ESTABLISHED     1234
  UDP    0.0.0.0:123            *:*                                    900
  garbage line that is not a connection
'@
        Mock -CommandName Invoke-CommandLineSafe -ModuleName Network -MockWith {
            [pscustomobject]@{ Succeeded = $true; StdOut = $stdout; StdErr = ''; ExitCode = 0; TimedOut = $false }
        }
        $rows = Get-NwNetstatRows -Context $ctx
        $rows.Count | Should -Be 3
        (@($rows | Where-Object Protocol -eq 'TCP')).Count | Should -Be 2
        $udp = $rows | Where-Object Protocol -eq 'UDP'
        $udp.LocalPort       | Should -Be '123'
        $udp.OwningProcessId | Should -Be 900
        ($rows | Where-Object { $_.LocalPort -eq '445' }).State | Should -Be 'LISTENING'
    }

    It 'returns a real empty array, not $null, when netstat produces no output' {
        $ctx = New-NwTestContext
        Mock -CommandName Invoke-CommandLineSafe -ModuleName Network -MockWith {
            [pscustomobject]@{ Succeeded = $false; StdOut = ''; StdErr = 'denied'; ExitCode = 1; TimedOut = $false }
        }
        $result = Get-NwNetstatRows -Context $ctx
        ($null -ne $result)  | Should -BeTrue
        @($result).Count     | Should -Be 0
    }
}

Describe 'Invoke-DiscoveryCollection network fallback (regression guard)' {

    It 'produces one row per connection via the netstat fallback, not one collapsed row' {
        $ctx = New-NwTestContext
        # Forces every Get-CommandAvailable check in the module to say "not available",
        # which is what pushes ListeningPorts/EstablishedConnections onto the netstat path.
        Mock -CommandName Get-CommandAvailable -ModuleName Network -MockWith { $false }
        $stdout = @'
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       5
  TCP    10.0.0.5:3389          10.0.0.9:51000         ESTABLISHED     1234
  TCP    10.0.0.5:445           10.0.0.9:51001         ESTABLISHED     1235
  TCP    10.0.0.5:445           10.0.0.9:51002         ESTABLISHED     1236
'@
        Mock -CommandName Invoke-CommandLineSafe -ModuleName Network -MockWith {
            [pscustomobject]@{ Succeeded = $true; StdOut = $stdout; StdErr = ''; ExitCode = 0; TimedOut = $false }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        # If a future edit re-wraps Get-NwNetstatRows's result in an extra @() anywhere on
        # this path, these counts collapse to 1 instead of N - that was the actual bug.
        @($raw.ListeningPorts).Count         | Should -Be 2
        @($raw.EstablishedConnections).Count | Should -Be 3
    }
}

Describe 'Get-NwFirewallRows' {

    It 'joins port/application filters onto rules by InstanceID and excludes disabled/deny rules' {
        $ctx = New-NwTestContext
        Mock -CommandName Get-CommandAvailable -ModuleName Network -MockWith { $true }
        Mock -CommandName Get-NetFirewallRule -ModuleName Network -MockWith {
            @(
                [pscustomobject]@{ InstanceID = 'R1'; DisplayName = 'Web';      Name = 'Web';      DisplayGroup = 'IIS'; Direction = 'Inbound';  Action = 'Allow'; Enabled = 'True';  Profile = 'Domain' }
                [pscustomobject]@{ InstanceID = 'R2'; DisplayName = 'Blocked';  Name = 'Blocked';  DisplayGroup = '';    Direction = 'Inbound';  Action = 'Block'; Enabled = 'True';  Profile = 'Domain' }
                [pscustomobject]@{ InstanceID = 'R3'; DisplayName = 'Disabled'; Name = 'Disabled'; DisplayGroup = '';    Direction = 'Inbound';  Action = 'Allow'; Enabled = 'False'; Profile = 'Domain' }
            )
        }
        Mock -CommandName Get-NetFirewallPortFilter -ModuleName Network -MockWith {
            @([pscustomobject]@{ InstanceID = 'R1'; Protocol = 'TCP'; LocalPort = @('80', '443') })
        }
        Mock -CommandName Get-NetFirewallApplicationFilter -ModuleName Network -MockWith {
            @([pscustomobject]@{ InstanceID = 'R1'; Program = 'C:\inetpub\w3wp.exe' })
        }
        $rows = Get-NwFirewallRows -Context $ctx
        $rows.Count | Should -Be 1 -Because 'only the enabled Allow rule should survive the filter'
        $rows[0].Name      | Should -Be 'Web'
        $rows[0].Protocol  | Should -Be 'TCP'
        $rows[0].LocalPort | Should -Be '80,443'
        $rows[0].Program   | Should -Be 'C:\inetpub\w3wp.exe'
    }

    It 'leaves Protocol/LocalPort/Program blank rather than failing when no filter matches' {
        $ctx = New-NwTestContext
        Mock -CommandName Get-CommandAvailable -ModuleName Network -MockWith { $true }
        Mock -CommandName Get-NetFirewallRule -ModuleName Network -MockWith {
            @([pscustomobject]@{ InstanceID = 'R9'; DisplayName = 'Orphan'; Name = 'Orphan'; DisplayGroup = ''; Direction = 'Outbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any' })
        }
        Mock -CommandName Get-NetFirewallPortFilter -ModuleName Network -MockWith { @() }
        Mock -CommandName Get-NetFirewallApplicationFilter -ModuleName Network -MockWith { @() }
        $rows = Get-NwFirewallRows -Context $ctx
        $rows.Count       | Should -Be 1
        $rows[0].Protocol | Should -Be ''
        $rows[0].Program  | Should -Be ''
    }

    It 'truncates to MaxFirewallRules and logs a limitation naming the true total' {
        $ctx = New-NwTestContext
        $ctx.Parameters['MaxFirewallRules'] = 2
        Mock -CommandName Get-CommandAvailable -ModuleName Network -MockWith { $true }
        Mock -CommandName Get-NetFirewallRule -ModuleName Network -MockWith {
            1..5 | ForEach-Object { [pscustomobject]@{ InstanceID = "R$_"; DisplayName = "Rule$_"; Name = "Rule$_"; DisplayGroup = ''; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Domain' } }
        }
        Mock -CommandName Get-NetFirewallPortFilter -ModuleName Network -MockWith { @() }
        Mock -CommandName Get-NetFirewallApplicationFilter -ModuleName Network -MockWith { @() }
        $rows = Get-NwFirewallRows -Context $ctx
        $rows.Count | Should -Be 2
        ($ctx.Limitations | Where-Object { $_.Message -match 'truncated to 2 of 5' }) | Should -Not -BeNullOrEmpty
    }

    It 'reports a limitation and returns empty when Get-NetFirewallRule is unavailable' {
        $ctx = New-NwTestContext
        Mock -CommandName Get-CommandAvailable -ModuleName Network -MockWith { $false }
        $rows = Get-NwFirewallRows -Context $ctx
        $rows.Count | Should -Be 0
        ($ctx.Limitations | Where-Object { $_.Message -match 'not available' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-NwEstablishedRows' {

    It 'caps at 300 rows and logs a limitation naming the true total' {
        $ctx = New-NwTestContext
        Mock -CommandName Get-CommandAvailable -ModuleName Network -MockWith { $true }
        Mock -CommandName Get-NetTCPConnection -ModuleName Network -MockWith {
            1..305 | ForEach-Object { [pscustomobject]@{ LocalAddress = '10.0.0.5'; LocalPort = $_; RemoteAddress = '10.0.0.9'; RemotePort = 51000; OwningProcess = 100 } }
        }
        $rows = Get-NwEstablishedRows -Context $ctx -ProcMap @{} -Netstat @()
        $rows.Count | Should -Be 300
        ($ctx.Limitations | Where-Object { $_.Message -match 'truncated to 300 of 305' }) | Should -Not -BeNullOrEmpty
    }
}
