#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    DNS.Tests.ps1 - fixture-based tests for Get-DnsRecordsReferencingThisServer.

    Mocks Get-DnsServerResourceRecord so this exercises the module's own matching/cap
    logic against synthetic record sets - including the 3000-record cap, which the lab
    cannot organically trip. Complements, does not replace, the live-server verification
    this function got on 2026-09-22 (see HISTORY.md).

    NOTE: the function under test returns via 'return ,@($rows)' - the established
    toolkit idiom so a 0-row result still comes back as an array. That unrolls correctly
    on DIRECT assignment ($x = Get-Foo) but NOT if the call is itself wrapped in an
    extra @() ($x = @(Get-Foo)) - that double-wraps into a 1-element array whose single
    element is the real array, and .Count then reads 1 regardless of the real row count.
    Every call site below assigns directly for exactly this reason - do not "helpfully"
    wrap them in @().
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\DNS\DNS.psm1')   -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    # The function reads $env:COMPUTERNAME/$env:USERDNSDOMAIN directly, so pin them to
    # known values for the test rather than depending on whatever host runs the suite.
    $script:OrigComputerName  = $env:COMPUTERNAME
    $script:OrigUserDnsDomain = $env:USERDNSDOMAIN
    $env:COMPUTERNAME  = 'TESTHOST'
    $env:USERDNSDOMAIN = 'test.local'

    function New-DnsTestContext {
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-DataSet -Context $ctx -Name 'IPConfiguration' -Rows @(
            [pscustomobject]@{ AllIPv4Addresses = '10.0.0.5'; IPv4Address = '10.0.0.5' }
        ) | Out-Null
        return $ctx
    }

    function New-DnsZone([string]$Name, [bool]$IsReverse = $false) {
        [pscustomobject]@{ ZoneName = $Name; IsReverse = $IsReverse }
    }
}

AfterAll {
    $env:COMPUTERNAME  = $script:OrigComputerName
    $env:USERDNSDOMAIN = $script:OrigUserDnsDomain
}

Describe 'Get-DnsRecordsReferencingThisServer' {

    It 'matches an A record pointing at this server''s own IP' {
        $ctx = New-DnsTestContext
        Mock -CommandName Get-DnsServerResourceRecord -ModuleName DNS -MockWith {
            @([pscustomobject]@{ RecordType = 'A'; HostName = 'www'; RecordData = [pscustomobject]@{ IPv4Address = [ipaddress]'10.0.0.5' } })
        }
        $rows = Get-DnsRecordsReferencingThisServer -Context $ctx -Zones @((New-DnsZone 'corp.local'))
        $rows.Count | Should -Be 1
        $rows[0].RecordName | Should -Be 'www.corp.local'
        $rows[0].PointsTo   | Should -Be '10.0.0.5'
    }

    It 'matches a CNAME record whose alias is this server''s hostname, trimming the trailing dot' {
        $ctx = New-DnsTestContext
        Mock -CommandName Get-DnsServerResourceRecord -ModuleName DNS -MockWith {
            @([pscustomobject]@{ RecordType = 'CNAME'; HostName = 'intranet'; RecordData = [pscustomobject]@{ HostNameAlias = 'TESTHOST.test.local.' } })
        }
        $rows = Get-DnsRecordsReferencingThisServer -Context $ctx -Zones @((New-DnsZone 'corp.local'))
        $rows.Count | Should -Be 1
        $rows[0].RecordType | Should -Be 'CNAME'
        $rows[0].PointsTo   | Should -Be 'TESTHOST.test.local'
    }

    It 'ignores records that do not reference this server' {
        $ctx = New-DnsTestContext
        Mock -CommandName Get-DnsServerResourceRecord -ModuleName DNS -MockWith {
            @([pscustomobject]@{ RecordType = 'A'; HostName = 'other'; RecordData = [pscustomobject]@{ IPv4Address = [ipaddress]'10.0.0.99' } })
        }
        $rows = Get-DnsRecordsReferencingThisServer -Context $ctx -Zones @((New-DnsZone 'corp.local'))
        $rows.Count | Should -Be 0
    }

    It 'skips reverse lookup zones entirely, without even querying them' {
        $ctx = New-DnsTestContext
        Mock -CommandName Get-DnsServerResourceRecord -ModuleName DNS -MockWith { throw 'must not be called for a reverse zone' }
        { Get-DnsRecordsReferencingThisServer -Context $ctx -Zones @((New-DnsZone '0.0.10.in-addr.arpa' $true)) } | Should -Not -Throw
        Should -Invoke -CommandName Get-DnsServerResourceRecord -ModuleName DNS -Times 0
    }

    It 'stops at the 3000-record cap and logs a limitation, rather than scanning every record' {
        $ctx = New-DnsTestContext
        Mock -CommandName Get-DnsServerResourceRecord -ModuleName DNS -MockWith {
            1..3001 | ForEach-Object {
                [pscustomobject]@{ RecordType = 'A'; HostName = "host$_"; RecordData = [pscustomobject]@{ IPv4Address = [ipaddress]'10.0.0.99' } }
            }
        }
        $rows = Get-DnsRecordsReferencingThisServer -Context $ctx -Zones @((New-DnsZone 'corp.local'))
        $rows.Count | Should -Be 0 -Because 'none of the synthetic records match this server'
        ($ctx.Limitations | Where-Object { $_.Message -match 'cap 3000' }) | Should -Not -BeNullOrEmpty
    }

    It 'does nothing when this server has no known IPs, without querying DNS at all' {
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config   # no IPConfiguration dataset seeded
        Mock -CommandName Get-DnsServerResourceRecord -ModuleName DNS -MockWith { throw 'must not be called with no known IPs' }
        $rows = Get-DnsRecordsReferencingThisServer -Context $ctx -Zones @((New-DnsZone 'corp.local'))
        $rows.Count | Should -Be 0
        Should -Invoke -CommandName Get-DnsServerResourceRecord -ModuleName DNS -Times 0
    }
}
