#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Invoke-FleetDiscovery.Tests.ps1 - fixture/self-contained tests for the pure and
    network-primitive pieces of the fleet discovery orchestrator.

    Dot-sourcing is safe here for the same reason it's safe for
    Discover-WindowsServer-GUI.Tests.ps1: the actual remote-execution loop only runs when this
    file is executed directly with -TargetComputerNames (see its own "only runs when executed
    directly" guard at the bottom), never on dot-source.

    NOT covered here (deliberately, not an oversight): Get-AdServerCandidate,
    Invoke-RemoteDiscoveryRun, and Get-FleetTargetPowerShellInfo. All three are thin wrappers
    around real ADSI/WinRM I/O with no seam Pester's Mock can reach (raw .NET object
    construction, or a runspace pool dispatching a real New-PSSession, not a mockable command) -
    faking that contract would test an imagined API surface, not real behavior. Each was instead
    verified live against this session's actual lab domain before being
    considered done - see the session notes/commit for that run's result rather than a mocked
    unit test standing in for it.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $Root 'tools\Invoke-FleetDiscovery.ps1')
}

Describe 'ConvertTo-CidrHostRange' {

    It 'expands a /30 to exactly its 2 usable host addresses' {
        $hosts = ConvertTo-CidrHostRange -Cidr '10.0.5.0/30'
        $hosts | Should -Be @('10.0.5.1', '10.0.5.2')
    }

    It 'expands a /24 to 254 usable host addresses, first and last correct' {
        # Deliberately NOT wrapped in @() - ConvertTo-CidrHostRange already returns ,@(...), and
        # re-wrapping an already-array result at the call site is the exact "@(Get-Foo) instead
        # of Get-Foo" gotcha documented elsewhere in this repo's own test notes: it nests the
        # real 254-element array as the single element of a new 1-element array, so .Count reads
        # 1 instead of 254. Caught by hand while writing this very test.
        $hosts = ConvertTo-CidrHostRange -Cidr '10.0.5.0/24'
        $hosts.Count | Should -Be 254
        $hosts[0]    | Should -Be '10.0.5.1'
        $hosts[-1]   | Should -Be '10.0.5.254'
    }

    It 'rejects a prefix broader than /22 rather than expanding it' {
        { ConvertTo-CidrHostRange -Cidr '10.0.0.0/8' } | Should -Throw
    }

    It 'rejects malformed input instead of guessing' {
        { ConvertTo-CidrHostRange -Cidr 'not-a-cidr' } | Should -Throw
    }
}

Describe 'Merge-DiscoveryCandidate' {

    It 'tags a host found by both AD and the subnet scan as Both, matching by IP over FQDN string' {
        $ad = @([pscustomobject]@{ Name = 'SRV1'; FQDN = 'srv1.corp.local'; OperatingSystem = 'Windows Server 2019'; Source = 'AD'; IPAddress = '10.0.5.10' })
        # Reverse DNS deliberately disagrees with the AD FQDN here (a real thing seen against a
        # live lab) - IP-based matching should still merge these into one row.
        $scan = @([pscustomobject]@{ Name = 'weird-ptr-name'; FQDN = 'weird-ptr-name.local'; OperatingSystem = ''; Source = 'Scan'; IPAddress = '10.0.5.10' })
        $merged = Merge-DiscoveryCandidate -AdResults $ad -ScanResults $scan
        $merged.Count        | Should -Be 1
        $merged[0].Source    | Should -Be 'Both'
        $merged[0].FQDN      | Should -Be 'srv1.corp.local'
    }

    It 'keeps distinct hosts as separate rows' {
        $ad = @([pscustomobject]@{ Name = 'SRV1'; FQDN = 'srv1.corp.local'; OperatingSystem = ''; Source = 'AD'; IPAddress = '10.0.5.10' })
        $scan = @([pscustomobject]@{ Name = 'SRV2'; FQDN = 'srv2.corp.local'; OperatingSystem = ''; Source = 'Scan'; IPAddress = '10.0.5.11' })
        $merged = Merge-DiscoveryCandidate -AdResults $ad -ScanResults $scan
        $merged.Count | Should -Be 2
        @($merged.Source | Sort-Object) | Should -Be @('AD', 'Scan')
    }

    It 'falls back to FQDN-string matching when IPAddress is absent on both sides' {
        $ad = @([pscustomobject]@{ Name = 'SRV1'; FQDN = 'srv1.corp.local'; OperatingSystem = ''; Source = 'AD' })
        $scan = @([pscustomobject]@{ Name = 'srv1.corp.local'; FQDN = 'srv1.corp.local'; OperatingSystem = ''; Source = 'Scan' })
        $merged = Merge-DiscoveryCandidate -AdResults $ad -ScanResults $scan
        $merged.Count     | Should -Be 1
        $merged[0].Source | Should -Be 'Both'
    }

    It 'skips a candidate with no FQDN rather than throwing' {
        $ad = @([pscustomobject]@{ Name = ''; FQDN = ''; OperatingSystem = ''; Source = 'AD' })
        Merge-DiscoveryCandidate -AdResults $ad -ScanResults @() | Should -BeNullOrEmpty
    }
}

Describe 'Test-WinRmPort and Invoke-SubnetWinRmScan' {
    # Self-contained: opens a real loopback TCP listener on a random free port rather than
    # depending on any external host actually running WinRM, so this is fully deterministic.

    It 'returns true for a port something is actually listening on' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $port = $listener.LocalEndpoint.Port
            Test-WinRmPort -ComputerName '127.0.0.1' -Port $port -TimeoutMs 500 | Should -BeTrue
        } finally { $listener.Stop() }
    }

    It 'returns false for a port nothing is listening on' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $listener.Stop()
        Test-WinRmPort -ComputerName '127.0.0.1' -Port $port -TimeoutMs 300 | Should -BeFalse
    }

    It 'Invoke-SubnetWinRmScan returns only the reachable host out of a mixed list' {
        # Not wrapped in @() at the call site - see the /24 test above for why.
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $openPort = $listener.LocalEndpoint.Port
            $closedListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $closedListener.Start(); $closedPort = $closedListener.LocalEndpoint.Port; $closedListener.Stop()

            $foundOnOpen = Invoke-SubnetWinRmScan -HostList @('127.0.0.1') -Port $openPort -MaxConcurrency 4 -TimeoutMs 500
            $foundOnClosed = Invoke-SubnetWinRmScan -HostList @('127.0.0.1') -Port $closedPort -MaxConcurrency 4 -TimeoutMs 300

            $foundOnOpen.Count   | Should -Be 1
            $foundOnOpen[0].Source | Should -Be 'Scan'
            $foundOnClosed.Count | Should -Be 0
        } finally { $listener.Stop() }
    }

    It 'returns cleanly (no error, zero results) for an empty host list' {
        { $script:emptyScanResult = Invoke-SubnetWinRmScan -HostList @() } | Should -Not -Throw
        $script:emptyScanResult.Count | Should -Be 0
    }
}

Describe 'Get-FleetTargetPowerShellInfo' {
    # Needs a real authenticated WinRM session per host - see this file's own header for why
    # that's not unit-tested here. Only the empty-list short circuit is pure enough to cover.

    It 'returns cleanly (no error, zero results) for an empty host list' {
        $fakeCred = [pscredential]::new('placeholder', (ConvertTo-SecureString 'x' -AsPlainText -Force))
        { $script:emptyPsInfo = Get-FleetTargetPowerShellInfo -HostList @() -Credential $fakeCred } | Should -Not -Throw
        $script:emptyPsInfo.Count | Should -Be 0
    }
}

Describe 'ConvertTo-CredentialFromEncodedLines' {
    # The two lines -CredentialFromStdin actually reads: a plain username and a base64'd UTF8
    # password. Tested here instead of via real stdin/process piping.

    It 'round-trips a username and password back into a matching PSCredential' {
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('P@ssw0rd!'))
        $cred = ConvertTo-CredentialFromEncodedLines -UserName 'CORP\svc-discover' -PasswordBase64 $b64
        $cred.UserName | Should -Be 'CORP\svc-discover'
        $cred.GetNetworkCredential().Password | Should -Be 'P@ssw0rd!'
    }

    It 'preserves non-ASCII characters through the UTF8/base64 round trip' {
        # Built from char codes rather than literal non-ASCII characters in the source file -
        # this file has no BOM, and Windows PowerShell 5.1 (unlike pwsh) parses a BOM-less
        # script using the system codepage, not UTF-8, corrupting literal accented/symbol
        # characters into mojibake that breaks the string literal itself (confirmed live: this
        # exact test file failed to PARSE under real PS 5.1 before this change).
        $nonAscii = 'p' + [char]0xE4 + 'ssw' + [char]0xF6 + 'rd' + [char]0x20AC
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($nonAscii))
        $cred = ConvertTo-CredentialFromEncodedLines -UserName 'user' -PasswordBase64 $b64
        $cred.GetNetworkCredential().Password | Should -Be $nonAscii
    }
}

Describe 'Invoke-FleetRunsInParallel' {
    # Invoke-RemoteDiscoveryRun itself needs real WinRM (see this file's own header for why it's
    # deliberately not unit-tested), so these point the pool at a small fixture script that
    # defines a FAKE Invoke-RemoteDiscoveryRun with the same contract (sleeps briefly, returns a
    # canned result) instead - that's enough to test the pool/polling/aggregation logic in
    # Invoke-FleetRunsInParallel itself, which is real orchestration code independent of what the
    # function it's fanning out actually does.

    BeforeAll {
        $script:FixtureScript = Join-Path $TestDrive 'fake-fleet-functions.ps1'
        @'
function Invoke-RemoteDiscoveryRun {
    param($ComputerName, $Credential, $LocalOutputRoot, $LocalToolkitRoot, $Mode, $ProjectType, $ComplianceLens, $TimeoutMinutes, [switch]$EnableWinRmIfUnreachable)
    Start-Sleep -Milliseconds 300
    [pscustomobject]@{
        ComputerName = $ComputerName; Status = 'Succeeded'; LocalResultPath = "C:\fake\$ComputerName"
        ErrorMessage = ''; StartTime = (Get-Date); EndTime = (Get-Date); WinRmEnabledByThisTool = $false
    }
}
'@ | Out-File -LiteralPath $FixtureScript -Encoding utf8
    }

    It 'returns one result per target, all succeeded' {
        $results = Invoke-FleetRunsInParallel -TargetComputerNames @('SRV1','SRV2','SRV3') `
            -LocalOutputRoot (Join-Path $TestDrive 'out') -LocalToolkitRoot $TestDrive -MaxConcurrency 2 -ScriptPath $FixtureScript
        @($results).Count | Should -Be 3
        (@($results | Where-Object { $_.Status -eq 'Succeeded' })).Count | Should -Be 3
        (@($results.ComputerName) | Sort-Object) | Should -Be @('SRV1','SRV2','SRV3')
    }

    It 'actually runs targets concurrently, not one at a time' {
        # Compare MaxConcurrency 1 vs 6 for the SAME 6*300ms workload, on the same machine in the
        # same test run, rather than asserting against a fixed wall-clock cutoff - runspace-pool
        # startup overhead varies enough by machine that a fixed threshold is a flaky hair-trigger
        # (confirmed: an absolute 1.2s cutoff failed once already at 1.25s). Relative comparison
        # is what actually proves concurrency without depending on how fast the whole pool
        # machinery spins up.
        $targets = 1..6 | ForEach-Object { "SRV$_" }
        $swSeq = [System.Diagnostics.Stopwatch]::StartNew()
        $seqResults = Invoke-FleetRunsInParallel -TargetComputerNames $targets `
            -LocalOutputRoot (Join-Path $TestDrive 'out2seq') -LocalToolkitRoot $TestDrive -MaxConcurrency 1 -ScriptPath $FixtureScript
        $swSeq.Stop()

        $swPar = [System.Diagnostics.Stopwatch]::StartNew()
        $parResults = Invoke-FleetRunsInParallel -TargetComputerNames $targets `
            -LocalOutputRoot (Join-Path $TestDrive 'out2par') -LocalToolkitRoot $TestDrive -MaxConcurrency 6 -ScriptPath $FixtureScript
        $swPar.Stop()

        @($seqResults).Count | Should -Be 6
        @($parResults).Count | Should -Be 6
        $swPar.Elapsed.TotalMilliseconds | Should -BeLessThan ($swSeq.Elapsed.TotalMilliseconds * 0.7)
    }

    It 'writes progress to the status file as targets complete' {
        $statusPath = Join-Path $TestDrive 'status3\progress.json'
        Invoke-FleetRunsInParallel -TargetComputerNames @('SRV1','SRV2') `
            -LocalOutputRoot (Join-Path $TestDrive 'out3') -LocalToolkitRoot $TestDrive -MaxConcurrency 2 `
            -ScriptPath $FixtureScript -FleetStatusPath $statusPath | Out-Null
        Test-Path -LiteralPath $statusPath | Should -BeTrue
        $final = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        $final.CompletedTargets | Should -Be 2
        $final.TotalTargets | Should -Be 2
    }

    It "relays a target's own live phase into progress.json while it is still running" {
        # Real Invoke-RemoteDiscoveryRun drops a per-target phase file in -FleetStatusDir (read
        # from that target's own remote evidence\status\status.json) while it polls; this fixture
        # stands in for that by writing one directly, for SRV1 only, then sleeping long enough
        # that the orchestrator's periodic (every-few-seconds) progress.json refresh - not just
        # the on-completion one - has a chance to pick it up while SRV1 is still "running".
        $fixture2 = Join-Path $TestDrive 'fake-fleet-functions-phased.ps1'
        @'
function Invoke-RemoteDiscoveryRun {
    param($ComputerName, $Credential, $LocalOutputRoot, $LocalToolkitRoot, $Mode, $ProjectType, $ComplianceLens, $TimeoutMinutes, [switch]$EnableWinRmIfUnreachable, $FleetStatusDir)
    if ($ComputerName -eq 'SRV1' -and $FleetStatusDir) {
        if (-not (Test-Path -LiteralPath $FleetStatusDir)) { New-Item -ItemType Directory -Path $FleetStatusDir -Force | Out-Null }
        [pscustomobject]@{ ComputerName = $ComputerName; Phase = 'Synthesizing'; CurrentModule = 'RiskEngine'; PercentComplete = 62 } |
            ConvertTo-Json | Out-File -LiteralPath (Join-Path $FleetStatusDir "$ComputerName.json") -Encoding utf8 -Force
        Start-Sleep -Seconds 4
    } else {
        Start-Sleep -Milliseconds 300
    }
    [pscustomobject]@{
        ComputerName = $ComputerName; Status = 'Succeeded'; LocalResultPath = "C:\fake\$ComputerName"
        ErrorMessage = ''; StartTime = (Get-Date); EndTime = (Get-Date); WinRmEnabledByThisTool = $false
    }
}
'@ | Out-File -LiteralPath $fixture2 -Encoding utf8

        $statusPath = Join-Path $TestDrive 'status4\progress.json'
        $statusDir = Split-Path -Parent $statusPath
        # Runs Invoke-FleetRunsInParallel in a SEPARATE process (Start-Job), not inline, so this
        # test's own thread is free to poll progress.json WHILE the fleet job is still running -
        # an inline call only returns after everything finishes, by which point CurrentTargets/
        # TargetPhases are empty again and the mid-run relay this is testing would be invisible.
        $job = Start-Job -ScriptBlock {
            param($RootPath, $Fixture, $StatusPath, $StatusDir, $OutRoot)
            . (Join-Path $RootPath 'tools\Invoke-FleetDiscovery.ps1')
            Invoke-FleetRunsInParallel -TargetComputerNames @('SRV1', 'SRV2') -LocalOutputRoot $OutRoot -LocalToolkitRoot $RootPath `
                -MaxConcurrency 2 -ScriptPath $Fixture -FleetStatusPath $StatusPath -FleetStatusDir $StatusDir
        } -ArgumentList $Root, $fixture2, $statusPath, $statusDir, (Join-Path $TestDrive 'out4')

        try {
            $seenPhase = $false
            $deadline = (Get-Date).AddSeconds(15)
            while ((Get-Date) -lt $deadline -and -not $seenPhase) {
                if (Test-Path -LiteralPath $statusPath) {
                    try {
                        $snap = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                        if (@($snap.TargetPhases) | Where-Object { $_.ComputerName -eq 'SRV1' -and $_.CurrentModule -eq 'RiskEngine' -and $_.PercentComplete -eq 62 }) { $seenPhase = $true }
                    } catch { }
                }
                if (-not $seenPhase) { Start-Sleep -Milliseconds 300 }
            }
            $seenPhase | Should -BeTrue
        } finally {
            Wait-Job $job -Timeout 30 | Out-Null
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
