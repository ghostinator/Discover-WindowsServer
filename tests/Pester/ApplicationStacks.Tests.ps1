#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    ApplicationStacks.Tests.ps1 - evidence matching for config\application-stacks.json and the
    fleet-level server/client correlation built on it (tools\Merge-FleetDiscoveryResults.ps1).

    Fixtures are generic (APP01, RDS01, WS01). No client-specific names belong in this file.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                             -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1')                         -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\ApplicationStacks\ApplicationStacks.psm1')   -Force -DisableNameChecking
    . (Join-Path $Root 'tools\Merge-FleetDiscoveryResults.ps1')
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')
    $script:Stacks = @($script:Config.AppStacks.stacks)

    function New-Getter { param([hashtable]$Data) return { param($n) if ($Data.ContainsKey($n)) { @($Data[$n]) } else { @() } }.GetNewClosure() }
}

Describe 'application-stacks.json' {
    It 'loads through the config bundle and defines the Sage and Actian stacks' {
        $script:Stacks.Count | Should -BeGreaterOrEqual 2
        ($script:Stacks.name -join '|') | Should -Match 'Sage 300'
        ($script:Stacks.name -join '|') | Should -Match 'Actian'
    }
}

Describe 'Find-AppStackEvidence / Get-AppStackSummary' {
    It 'separates Sage server and client components and keeps their versions' {
        $get = New-Getter @{ InstalledApplications = @(
            [pscustomobject]@{ DisplayName='Sage 300 Construction and Real Estate Server'; DisplayVersion='24.1.1' }
            [pscustomobject]@{ DisplayName='Sage 300 Construction and Real Estate'; DisplayVersion='24.1.1' }
            [pscustomobject]@{ DisplayName='Actian PSQL v13 Server Engine'; DisplayVersion='13.31' }
        ) }
        $ev = Find-AppStackEvidence -Stacks $script:Stacks -GetRows $get
        ($ev | Where-Object { $_.Stack -match 'Sage' -and $_.Role -eq 'Server' }).Version | Should -Be '24.1.1'
        ($ev | Where-Object { $_.Stack -match 'Sage' -and $_.Role -eq 'Client' }).Version | Should -Be '24.1.1'
        ($ev | Where-Object { $_.Stack -match 'Actian' -and $_.Role -eq 'Server' }) | Should -Not -BeNullOrEmpty
        @($ev | Where-Object { $_.EvidenceId -notmatch '^EV-\d{4}$' }).Count | Should -Be 0
        $sum = Get-AppStackSummary -Evidence $ev -Stacks $script:Stacks
        ($sum | Where-Object Stack -match 'Sage').HostRole | Should -Be 'Server and client'
        ($sum | Where-Object Stack -match 'Sage').LocalServerClientVersionsDiffer | Should -BeFalse
    }

    It 'flags a local server/client version difference for vendor validation, never as compatible' {
        $get = New-Getter @{ InstalledApplications = @(
            [pscustomobject]@{ DisplayName='Sage 300 Construction and Real Estate Server'; DisplayVersion='24.1.1' }
            [pscustomobject]@{ DisplayName='Sage 300 Construction and Real Estate'; DisplayVersion='23.1.0' }
        ) }
        $sum = Get-AppStackSummary -Evidence (Find-AppStackEvidence -Stacks $script:Stacks -GetRows $get) -Stacks $script:Stacks
        $s = $sum | Where-Object Stack -match 'Sage'
        $s.LocalServerClientVersionsDiffer | Should -BeTrue
        $s.ValidationNote | Should -Match 'vendor'
    }

    It 'cites every evidence record behind a summary' {
        $get = New-Getter @{
            Services = @([pscustomobject]@{ Name='SageLic'; DisplayName='Sage Pervasive License Service' })
            OdbcDrivers = @([pscustomobject]@{ Name='Timberline Data'; Bitness='32' })
        }
        $ev = Find-AppStackEvidence -Stacks $script:Stacks -GetRows $get
        $sum = Get-AppStackSummary -Evidence $ev -Stacks $script:Stacks
        $s = $sum | Where-Object Stack -match 'Sage'
        $s.HostRole | Should -Be 'Related components only'
        foreach ($e in @($ev | Where-Object Stack -match 'Sage')) { $s.EvidenceIds | Should -Match $e.EvidenceId }
    }

    It 'returns no stacks for a server with no matching evidence' {
        $sum = Get-AppStackSummary -Evidence (Find-AppStackEvidence -Stacks $script:Stacks -GetRows (New-Getter @{})) -Stacks $script:Stacks
        @($sum).Count | Should -Be 0
    }

    It 'marks an RDS host that carries the client' {
        $get = New-Getter @{ InstalledApplications = @([pscustomobject]@{ DisplayName='Sage 300 Construction and Real Estate'; DisplayVersion='24.1.1' }) }
        $sum = Get-AppStackSummary -Evidence (Find-AppStackEvidence -Stacks $script:Stacks -GetRows $get) -Stacks $script:Stacks -IsRdsHost $true
        ($sum | Where-Object Stack -match 'Sage').RdsHostWithClient | Should -BeTrue
    }
}

Describe 'Get-FleetAppStackCorrelation - Sage client and server versions across servers' {
    BeforeAll {
        $mk = { param($srv, $role, $ver, $id) [pscustomobject]@{ ComputerName=$srv; Stack='Sage 300 Construction and Real Estate'; Component=('Sage ' + $role); Role=$role; Version=$ver; Confidence='Confirmed'; EvidenceId=$id } }
        $script:Ev = @(
            (& $mk 'APP01' 'Server' '24.1.1' 'EV-0001'), (& $mk 'APP01' 'Client' '24.1.1' 'EV-0002'),
            (& $mk 'RDS01' 'Client' '24.1.1' 'EV-0001'), (& $mk 'WS01' 'Client' '23.1.0' 'EV-0003')
        )
    }
    It 'names the engine host, client hosts and RDS hosts with clients' {
        $c = @(Get-FleetAppStackCorrelation -EvidenceRows $script:Ev -RdsHosts @('RDS01'))[0]
        $c.ServerEngineHosts | Should -Be 'APP01'
        $c.ClientHosts | Should -Be 'APP01, RDS01, WS01'
        $c.RdsHostsWithClient | Should -Be 'RDS01'
    }
    It 'reports a possible version mismatch requiring vendor validation and cites evidence by server' {
        $c = @(Get-FleetAppStackCorrelation -EvidenceRows $script:Ev)[0]
        $c.VersionAssessment | Should -Match 'Possible mismatch - vendor validation required'
        $c.VersionAssessment | Should -Match '23\.1\.0'
        $c.EvidenceIds | Should -Match 'WS01:EV-0003'
    }
    It 'does not call identical versions compatible' {
        $c = @(Get-FleetAppStackCorrelation -EvidenceRows @($script:Ev | Where-Object ComputerName -ne 'WS01'))[0]
        $c.VersionAssessment | Should -Match 'still confirm compatibility with the vendor'
    }
    It 'proposes candidate source and target servers from the retiring/target lists' {
        $c = @(Get-FleetAppStackCorrelation -EvidenceRows $script:Ev -RetiringServers @('APP01') -TargetServers @('APP02'))[0]
        $c.CandidateSourceServers | Should -Be 'APP01'
        $c.CandidateTargetServers | Should -Be 'APP02'
    }
}

Describe 'Get-FleetCapacityComparison - target capacity' {
    BeforeAll {
        $script:Profiles = @(
            [pscustomobject]@{ ComputerName='OLD01'; SqlDataGB=300; ShareDataGB=500; ShareSizeUnknown=$false; SqlInstanceCount=1; TotalMemoryGB=32; FreeCapacityGB=100; UserShareCount=4; ApplicationStacks='Sage (Server)'; LogicalProcessors=8 }
            [pscustomobject]@{ ComputerName='NEW01'; SqlDataGB=10; ShareDataGB=0; ShareSizeUnknown=$false; SqlInstanceCount=1; TotalMemoryGB=16; FreeCapacityGB=400; UserShareCount=0; ApplicationStacks=''; LogicalProcessors=8 }
            [pscustomobject]@{ ComputerName='NEW02'; SqlDataGB=$null; ShareDataGB=$null; ShareSizeUnknown=$false; SqlInstanceCount=0; TotalMemoryGB=64; FreeCapacityGB=4000; UserShareCount=2; ApplicationStacks=''; LogicalProcessors=16 }
        )
    }
    It 'flags insufficient known free capacity, SQL already present and a likely VM resize' {
        $r = @(Get-FleetCapacityComparison -Profiles $script:Profiles -SourceServers @('OLD01') -TargetServers @('NEW01'))[0]
        $r.Findings | Should -Match 'Target has insufficient known free capacity'
        $r.Findings | Should -Match 'SQL is already present on target'
        $r.Findings | Should -Match 'VM resize may be needed'
        $r.Findings | Should -Match 'Additional performance evidence is required'
        $r.SourceDataGBMeasured | Should -Be 800
    }
    It 'treats a target with room and shares as the logical data target, without recommending a size' {
        $r = @(Get-FleetCapacityComparison -Profiles $script:Profiles -SourceServers @('OLD01') -TargetServers @('NEW02'))[0]
        $r.Findings | Should -Not -Match 'insufficient'
        $r.Findings | Should -Match 'File server appears to be the logical data target'
        $r.Findings | Should -Not -Match '(?i)\b(D|E|F)\d+s?_v\d|Standard_'
    }
    It 'asks for storage validation when a source share volume was not measured' {
        $p = @($script:Profiles | ForEach-Object { $_.PSObject.Copy() }); $p[0].ShareSizeUnknown = $true
        $r = @(Get-FleetCapacityComparison -Profiles $p -SourceServers @('OLD01') -TargetServers @('NEW02'))[0]
        $r.Findings | Should -Match 'Target storage requires validation'
    }
    It 'reports an unscanned target as unknown capacity' {
        $r = @(Get-FleetCapacityComparison -Profiles $script:Profiles -SourceServers @('OLD01') -TargetServers @('GHOST'))[0]
        $r.Findings | Should -Match 'capacity unknown'
    }
}

Describe 'Get-FleetCorrelations - end to end over a fixture engagement' {
    BeforeAll {
        function New-Run { param($Eng, $Name, [hashtable]$Data, $ProjectType = 'GeneralDiscovery')
            $dir = Join-Path $Eng ("Discover-WindowsServer_{0}_20261001_000000" -f $Name)
            New-Item -ItemType Directory (Join-Path $dir 'evidence\data\json') -Force | Out-Null
            @{ RunId="r-$Name"; ComputerName=$Name; Mode='Fast'; ProjectType=$ProjectType; Datasets=@() } | ConvertTo-Json | Out-File (Join-Path $dir 'evidence\collection-metadata.json') -Encoding utf8
            foreach ($k in $Data.Keys) { ConvertTo-Json @($Data[$k]) -Depth 4 | Out-File (Join-Path $dir "evidence\data\json\$k.json") -Encoding utf8 }
        }
        $script:Eng = Join-Path $TestDrive 'eng'
        New-Run $script:Eng 'OLD01' -ProjectType 'Decommission' -Data @{
            SmbShares = @([pscustomobject]@{ Name='Data'; Path='D:\Data'; IsUserShare=$true })
            IPConfiguration = @([pscustomobject]@{ InterfaceAlias='Ethernet'; IPv4Address='10.0.0.10'; AllIPv4Addresses='10.0.0.10'; DnsServers='10.0.0.10' })
            AppStackEvidence = @([pscustomobject]@{ Stack='Sage 300 Construction and Real Estate'; Component='Sage / Timberline DSN'; Role='DSN'; Item='TS Data'; Bitness='32'; Version=''; Confidence='Likely'; EvidenceId='EV-0001' })
        }
        New-Run $script:Eng 'NEW01' -Data @{
            SmbShares = @([pscustomobject]@{ Name='Data_old'; Path='E:\Data_old'; IsUserShare=$true })
            IPConfiguration = @([pscustomobject]@{ InterfaceAlias='Ethernet'; IPv4Address='10.0.0.20'; AllIPv4Addresses='10.0.0.20'; DnsServers='10.0.0.10, 10.0.0.11' })
            OdbcDsns = @([pscustomobject]@{ DsnName='Payroll'; Server='OLD01\SQLEXPRESS'; Scope='System'; Bitness='64'; Driver='SQL Server'; DbqOrPath='' })
        }
    }
    It 'defaults retiring servers to Decommission runs and finds DNS, ODBC and similar-share references to them' {
        $c = Get-FleetCorrelations -EngagementFolder $script:Eng -TargetServers @('NEW01')
        $c.RetiringServers | Should -Be @('OLD01')
        @($c.DnsReferencesToRetiring | Where-Object Server -eq 'NEW01').Count | Should -Be 1
        $o = @($c.OdbcReferences)[0]; $o.SourceServer | Should -Be 'NEW01'; $o.ReferencesServer | Should -Be 'OLD01'; $o.TargetIsRetiring | Should -BeTrue
        $s = @($c.SimilarShareNames)[0]; $s.NormalisedName | Should -Be 'data'; $s.OnTargetServer | Should -Be 'NEW01'; $s.OnRetiringServer | Should -Be 'OLD01'
        @($c.ApplicationStacks)[0].DsnsByPlatform | Should -Be 'OLD01: TS Data (32-bit)'
    }
    It 'does not fail on runs that pre-date the new datasets' {
        { Get-FleetCorrelations -EngagementFolder $script:Eng } | Should -Not -Throw
    }
}

Describe 'Resolve-FleetServerReference' {
    It 'matches NetBIOS names, FQDNs, UNC paths, host\instance and IPs' {
        $map = @{ '10.0.0.7' = 'FS01' }
        Resolve-FleetServerReference -Text 'APP01.corp.example' -ServerNames @('APP01','FS01') | Should -Be 'APP01'
        Resolve-FleetServerReference -Text '\\fs01\data\x' -ServerNames @('APP01','FS01') | Should -Be 'FS01'
        Resolve-FleetServerReference -Text 'APP01\SQLEXPRESS' -ServerNames @('APP01') | Should -Be 'APP01'
        Resolve-FleetServerReference -Text '10.0.0.7,1433' -ServerNames @('APP01') -AddressMap $map | Should -Be 'FS01'
        Resolve-FleetServerReference -Text 'unknownhost' -ServerNames @('APP01') | Should -Be ''
    }
}
