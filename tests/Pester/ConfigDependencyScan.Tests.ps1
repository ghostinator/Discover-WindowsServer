#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    ConfigDependencyScan.Tests.ps1 - fixture-based tests for the config-file dependency scanner.

    Fifth collector covered. Named in TODO.md as needing "heavier setup than DNS/Network" -
    true, because the collector walks the real filesystem rather than calling a handful of
    named cmdlets. The approach here: mock Get-ConfigScanRoots (already its own exported
    function) to point the scan at a real, disposable directory under Pester's $TestDrive,
    then let the module's actual Get-ChildItem/Get-Content logic run for real against small
    fixture files - a hybrid of mocking (which roots to scan) and real I/O (the scan itself),
    which avoids deep-mocking built-in filesystem cmdlets while never touching the real host
    filesystem outside $TestDrive.

    NOT covered here: the "only scan the newest C:\inetpub\history\CFGHISTORY_* folder"
    dedup logic. That path is reached by recursing into the real, hardcoded 'C:\inetpub' root
    (one of Get-ConfigScanRoots's own defaults) - not cleanly separable from the general file
    walk without either touching the real C:\inetpub on whatever host runs this suite (this
    session's own DC has real CFGHISTORY data there - not something a fixture test should
    depend on or disturb) or refactoring the history root into an injectable parameter, which
    is out of scope for a test-only change. Left as a known gap rather than forcing a bad test.

    THREE gotchas hit while writing this file, all worth knowing before adding more tests here
    or to any other collector:
      1. A Mock -MockWith scriptblock registered with -ModuleName does NOT reliably close
         over a plain local (It-scope) variable - only $script:-scoped variables are
         guaranteed visible inside it. A mock body referencing a local $dir directly
         silently resolved to nothing.
      2. Mocking a function that is NATIVE to the module under test (Get-ConfigScanRoots is
         defined in ConfigDependencyScan.psm1 itself, not imported from Core.psm1) only
         takes effect for calls made from INSIDE that module's own scope - i.e. wrapped in
         InModuleScope. Calling Invoke-DiscoveryCollection directly from the test (as every
         other fixture-test file in this repo does successfully) silently ran the REAL
         Get-ConfigScanRoots. Mocking a cross-module/external command (Test-Path,
         Get-ChildItem, anything from Core.psm1) does NOT need this - only same-module
         self-calls do.
      3. The SAME ",@()-unrolls-on-direct-assignment-but-not-otherwise" gotcha that shows up
         throughout this codebase's OWN collectors also bites a Mock's return value: a mock
         body written as `{ @($script:CdsScanDir) }` returns a 1-element array, but Pester's
         own mock-invocation pipeline unrolled it back down to a bare scalar string by the
         time it reached `$roots = Get-ConfigScanRoots ...` - so `$roots.Count` read 1 (a
         string's own Count is always 1) and `$roots[0]` indexed into the STRING's characters
         instead of the array's elements, silently pointing every scan at a 1-character path
         and finding nothing. Comma-wrapping the mock body (`{ ,@(...) }`), exactly like the
         toolkit's own functions do, fixes it.
      4. (Not a gotcha, a real behavior worth knowing): $TestDrive lives under
         C:\Users\<you>\AppData\Local\Temp\..., which this collector deliberately excludes by
         default (the IncludeUserProfiles gate, meant to avoid scanning real user-profile data
         unasked). Every fixture test that expects a real scan to happen must set
         $ctx.Parameters['IncludeUserProfiles'] = $true - and the collateral discovery turned
         into its own test below, since it's real, meaningful gating logic.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                             -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\ConfigDependencyScan\ConfigDependencyScan.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-CdsTestContext {
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config
        $ctx.Parameters['IncludeUserProfiles'] = $true   # see gotcha #4 - $TestDrive is under C:\Users
        return $ctx
    }

    # A fresh, empty, disposable directory per test - not shared $TestDrive content - so
    # tests can never see each other's fixture files regardless of TestDrive's own reset
    # semantics between Its. Stashed in $script: scope (see gotcha #1), not just returned,
    # since it must be readable from inside a Mock -MockWith scriptblock.
    function New-CdsScanDir {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $script:CdsScanDir = $dir
        return $dir
    }

    # Points the scan at $script:CdsScanDir. Comma-wrapped per gotcha #3.
    function Set-CdsScanRootsMock {
        Mock -CommandName Get-ConfigScanRoots -ModuleName ConfigDependencyScan -MockWith { ,@($script:CdsScanDir) }
    }

    # Runs Invoke-DiscoveryCollection INSIDE the module's own scope (see gotcha #2), so its
    # internal call to the mocked Get-ConfigScanRoots actually resolves to the mock. $Context
    # is a reference type, so mutations (e.g. Add-Limitation) are visible on the same object
    # back in the caller's scope after this returns.
    function Invoke-CdsCollection([object]$Context) {
        InModuleScope ConfigDependencyScan { param($ctx) Invoke-DiscoveryCollection -Context $ctx } -Parameters @{ ctx = $Context }
    }
}

Describe 'Get-ConfigScanRoots' {
    It 'includes an InstalledApplications InstallLocation that exists on disk' {
        $ctx = New-CdsTestContext
        $dir = New-CdsScanDir
        Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @([pscustomobject]@{ InstallLocation = $dir }) | Out-Null
        $roots = Get-ConfigScanRoots -Context $ctx
        $roots | Should -Contain $dir
    }

    It 'excludes an InstallLocation that does not exist on disk' {
        $ctx = New-CdsTestContext
        $fake = Join-Path $TestDrive 'DoesNotExist9f3a2b'
        Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @([pscustomobject]@{ InstallLocation = $fake }) | Out-Null
        $roots = Get-ConfigScanRoots -Context $ctx
        $roots | Should -Not -Contain $fake
    }

    It 'deduplicates repeated roots' {
        $ctx = New-CdsTestContext
        $dir = New-CdsScanDir
        Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @(
            [pscustomobject]@{ InstallLocation = $dir }
            [pscustomobject]@{ InstallLocation = $dir }
        ) | Out-Null
        $roots = Get-ConfigScanRoots -Context $ctx
        (@($roots | Where-Object { $_ -eq $dir })).Count | Should -Be 1
    }
}

Describe 'Invoke-DiscoveryCollection - config file scanning' {

    BeforeEach {
        # Keeps every test off the real filesystem outside $TestDrive: no scan root other
        # than the one this test creates, and the C:\inetpub\history probe reads as absent.
        Mock -CommandName Test-Path -ModuleName ConfigDependencyScan -ParameterFilter { $LiteralPath -eq 'C:\inetpub\history' } -MockWith { $false }
    }

    It 'matches an indicator, redacts the secret, and keeps the surrounding structure readable' {
        $ctx = New-CdsTestContext
        $dir = New-CdsScanDir
        Set-CdsScanRootsMock
        Set-Content -LiteralPath (Join-Path $dir 'app.config') -Value 'Data Source=sql01;Initial Catalog=ERP;User ID=svc;Password=Sup3rSecret123'
        $raw = Invoke-CdsCollection -Context $ctx
        $hint = $raw.ConfigDependencyHints | Where-Object FilePath -like '*app.config'
        $hint               | Should -Not -BeNullOrEmpty
        $hint.RedactedLine  | Should -Not -Match 'Sup3rSecret123'
        $hint.RedactedLine  | Should -Match 'sql01'
    }

    It 'skips files whose extension is not in the tracked list' {
        $ctx = New-CdsTestContext
        $dir = New-CdsScanDir
        Set-CdsScanRootsMock
        Set-Content -LiteralPath (Join-Path $dir 'notes.txt') -Value 'Password=ShouldNeverBeScanned'
        $raw = Invoke-CdsCollection -Context $ctx
        ($raw.ConfigDependencyHints | Where-Object FilePath -like '*notes.txt') | Should -BeNullOrEmpty
    }

    It 'matches a UNC path indicator on a line with no other indicator content' {
        $ctx = New-CdsTestContext
        $dir = New-CdsScanDir
        Set-CdsScanRootsMock
        Set-Content -LiteralPath (Join-Path $dir 'paths.ini') -Value 'BackupPath=\\fileserver\share\app\config'
        $raw = Invoke-CdsCollection -Context $ctx
        $hint = $raw.ConfigDependencyHints | Where-Object FilePath -like '*paths.ini'
        $hint.IndicatorType | Should -Be 'UNCPath'
    }

    It 'skips a file larger than the configured size cap, without even reading its content' {
        $ctx = New-CdsTestContext
        $dir = New-CdsScanDir
        Set-CdsScanRootsMock
        $ctx.Parameters['ConfigScanMaxFileSizeMB'] = 1
        $line = 'Password=' + ('x' * 200)
        $sb = New-Object System.Text.StringBuilder
        1..8000 | ForEach-Object { [void]$sb.AppendLine($line) }   # ~1.7MB, over the 1MB cap
        Set-Content -LiteralPath (Join-Path $dir 'huge.config') -Value $sb.ToString() -NoNewline
        $raw = Invoke-CdsCollection -Context $ctx
        ($raw.ConfigDependencyHints | Where-Object FilePath -like '*huge.config') | Should -BeNullOrEmpty
    }

    It 'does not scan under a user profile path by default (IncludeUserProfiles unset)' {
        # $TestDrive itself lives under C:\Users\<you>\AppData\Local\Temp\... - real proof
        # this gate does what it claims, using the exact directory the other tests in this
        # file are otherwise forced to opt back into scanning.
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config   # deliberately skip New-CdsTestContext's opt-in
        $dir = New-CdsScanDir
        Set-CdsScanRootsMock
        Set-Content -LiteralPath (Join-Path $dir 'app.config') -Value 'Password=Sup3rSecret123'
        $raw = Invoke-CdsCollection -Context $ctx
        $raw.ConfigDependencyHints.Count | Should -Be 0
    }
}

Describe 'Invoke-DiscoveryCollection - file cap' {
    It 'stops at the 3000-file cap and logs a limitation naming it' {
        $ctx = New-CdsTestContext
        $dir = New-CdsScanDir
        Set-CdsScanRootsMock
        Mock -CommandName Test-Path -ModuleName ConfigDependencyScan -ParameterFilter { $LiteralPath -eq 'C:\inetpub\history' } -MockWith { $false }
        1..3001 | ForEach-Object { Set-Content -LiteralPath (Join-Path $dir "f$_.config") -Value 'nothing interesting here' -NoNewline }
        $raw = Invoke-CdsCollection -Context $ctx
        ($ctx.Limitations | Where-Object { $_.Message -match 'file cap 3000' }) | Should -Not -BeNullOrEmpty
    }
}
