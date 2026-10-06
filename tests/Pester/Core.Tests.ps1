#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Core.Tests.ps1 - framework Core module tests (Pester 5.x).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')   -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')
    $script:Ctx = New-DiscoveryContext -Mode Fast -Config $Config
}

Describe 'ConvertTo-SafeFileName' {
    It 'replaces invalid characters' {
        (ConvertTo-SafeFileName -Name 'a:b/c\d*e?').Contains(':') | Should -BeFalse
    }
    It 'returns a fallback for empty input' {
        ConvertTo-SafeFileName -Name '' | Should -Be 'unnamed'
    }
}

Describe 'Convert-BytesToGB / Convert-BytesToMB' {
    It 'converts 1GB correctly' { Convert-BytesToGB -Bytes 1073741824 | Should -Be 1 }
    It 'converts 1MB correctly' { Convert-BytesToMB -Bytes 1048576 | Should -Be 1 }
    It 'returns null for null input' { Convert-BytesToGB -Bytes $null | Should -BeNullOrEmpty }
}

Describe 'Normalize-DateTime' {
    It 'formats a DateTime consistently' {
        Normalize-DateTime -Value ([datetime]'2024-01-02 03:04:05') | Should -Be '2024-01-02 03:04:05'
    }
    It 'returns null for null' { Normalize-DateTime -Value $null | Should -BeNullOrEmpty }
}

Describe 'Redaction' {
    It 'redacts a connection-string password but keeps structure' {
        $r = Redact-SensitiveValue -InputString 'Server=x;Password=Secret123;Database=y' -Context $Ctx
        $r | Should -Not -Match 'Secret123'
        $r | Should -Match 'Server=x'
    }
    It 'flags a sensitive key label' {
        Test-SensitiveKeyLabel -Name 'API Key' -Context $Ctx | Should -BeTrue
        Test-SensitiveKeyLabel -Name 'DisplayName' -Context $Ctx | Should -BeFalse
    }
}

Describe 'Finding object creation' {
    It 'New-DiscoveryFinding produces the standard shape' {
        $f = New-DiscoveryFinding -Category 'Security' -Severity 'High' -Confidence 'Confirmed' -Title 'T'
        $f.PSObject.Properties.Name | Should -Contain 'FindingId'
        $f.PSObject.Properties.Name | Should -Contain 'WhyItMattersForScoping'
        $f.Severity | Should -Be 'High'
    }
    It 'Add-Finding assigns sequential FindingIds and appends' {
        $c = New-DiscoveryContext -Mode Fast -Config $Config
        $a = Add-Finding -Context $c -Category 'X' -Severity 'Low' -Confidence 'Likely' -Title 'A'
        $b = Add-Finding -Context $c -Category 'X' -Severity 'Low' -Confidence 'Likely' -Title 'B'
        $a.FindingId | Should -Be 'FIND-0001'
        $b.FindingId | Should -Be 'FIND-0002'
        $c.Findings.Count | Should -Be 2
    }
    It 'rejects an invalid severity' {
        { New-DiscoveryFinding -Category 'X' -Title 'T' -Severity 'Bogus' } | Should -Throw
    }
}

Describe 'Context and datasets' {
    It 'New-DiscoveryContext initializes collections' {
        # Do NOT pipe a collection into Should here. An empty List[object] unrolls to
        # nothing in the pipeline, so '$Ctx.Findings | Should -Not -BeNullOrEmpty'
        # receives no value at all and fails - asserting the opposite of the intent.
        # Assert on the object identity and the Count instead.
        ($null -ne $Ctx.Findings)          | Should -BeTrue -Because 'the list is initialized, not null'
        ($null -ne $Ctx.FollowUpQuestions) | Should -BeTrue
        ($null -ne $Ctx.Limitations)       | Should -BeTrue
        ($null -ne $Ctx.DependencyEdges)   | Should -BeTrue
        $Ctx.Findings.Count  | Should -Be 0 -Because 'a fresh context starts empty'
        $Ctx.DataSets.Count  | Should -Be 0
        $Ctx.RunId | Should -Match '^[0-9a-fA-F-]{36}$'
    }
    It 'Add-DataSet stores a dataset and merges on repeat' {
        $c = New-DiscoveryContext -Mode Fast -Config $Config
        Add-DataSet -Context $c -Name 'Demo' -Rows @([pscustomobject]@{A=1}) | Out-Null
        Add-DataSet -Context $c -Name 'Demo' -Rows @([pscustomobject]@{A=2}) | Out-Null
        $c.DataSets['Demo'].RowCount | Should -Be 2
    }
}

Describe 'Get-CommandAvailable' {
    # This helper gates optional collection at 57 call sites across 17 modules, so a false
    # negative silently skips an entire dataset - usually while logging a "cmdlet not
    # available" limitation that is untrue. It once used
    # $ExecutionContext.InvokeCommand.GetCommands(), which does NOT trigger module
    # auto-loading, so any cmdlet in a not-yet-imported module read as absent. On a real
    # Deep run that cost: FirewallRules 0 rows instead of 557, ListeningPorts 1 instead of
    # 42, LocalGroups 0 instead of 22, Partitions 0 instead of 4.
    #
    # The auto-load behaviour can ONLY be tested in a session where the module has not
    # already been loaded, so these tests spawn a CHILD host process. Testing in-process
    # would pass even with the broken implementation, because earlier tests in this suite
    # have already pulled those modules in.

    BeforeAll {
        # Resolve the host executable from $PSHOME rather than Get-Process, so this does
        # not depend on any cmdlet the tests are themselves exercising, and assert it
        # exists - otherwise a bad path surfaces as an obscure '&' pipeline error instead
        # of a clear assertion failure.
        $exeName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
        $script:HostExe = Join-Path $PSHOME $exeName
        $script:CorePath = Join-Path $script:Root 'modules\Core\Core.psm1'
    }

    It 'can locate the host executable and Core.psm1 (harness precondition)' {
        # If either of these is wrong, the two child-process tests below cannot mean
        # anything - so fail loudly here rather than confusingly there.
        Test-Path -LiteralPath $script:HostExe  | Should -BeTrue -Because "expected a host exe at $script:HostExe"
        Test-Path -LiteralPath $script:CorePath | Should -BeTrue -Because "expected Core.psm1 at $script:CorePath"
    }

    It 'finds cmdlets whose owning module has not been auto-loaded yet' {
        # ORDER IS LOAD-BEARING. Ask Get-CommandAvailable about EVERY name first, then ask
        # Get-Command. Get-Command auto-loads the module, so interleaving the two would
        # pre-load each module and the assertion would pass even with the broken
        # implementation - which is exactly what happened on the first attempt at this test.
        # Only cmdlets that genuinely exist on this host are asserted on, so the test stays
        # valid on a machine that lacks some of them.
        $probe = @'
Import-Module '{0}' -Force -DisableNameChecking
$names = @('Get-NetFirewallRule','Get-Partition','Get-LocalGroup','Get-PrinterDriver','Get-SmbShareAccess','Get-NetTCPConnection')

# Pass 1 - the toolkit's answer, before anything has been auto-loaded.
$toolkit = @{{}}
foreach ($n in $names) {{ $toolkit[$n] = [bool](Get-CommandAvailable -Name $n) }}

# Pass 2 - ground truth. This auto-loads, but pass 1 is already recorded.
$out = @()
foreach ($n in $names) {{
    if ((Get-Command -Name $n -ErrorAction Ignore) -and (-not $toolkit[$n])) {{ $out += $n }}
}}
if ($out.Count -eq 0) {{ 'NONE' }} else {{ $out -join ',' }}
'@ -f $script:CorePath

        $result = & $script:HostExe -NoProfile -NonInteractive -Command $probe
        ($result | Select-Object -Last 1).Trim() |
            Should -Be 'NONE' -Because 'a present cmdlet must never be reported as unavailable'
    }

    It 'returns false for a command that genuinely does not exist' {
        Get-CommandAvailable -Name 'Totally-NotACommand-9f3a2b' | Should -BeFalse
    }

    It 'finds an external executable, not just cmdlets' {
        # secedit/dism/wevtutil are probed by name elsewhere in the toolkit.
        Get-CommandAvailable -Name 'where.exe' | Should -BeTrue
    }

    It 'does not pollute $Error when probing absent commands' {
        # The reason the original implementation avoided Get-Command. -ErrorAction Ignore
        # keeps that property; -ErrorAction SilentlyContinue would not.
        $probe = @'
Import-Module '{0}' -Force -DisableNameChecking
$Error.Clear()
foreach ($n in @('No-SuchCmdlet-1','No-SuchCmdlet-2','No-SuchCmdlet-3')) {{ $null = Get-CommandAvailable -Name $n }}
$Error.Count
'@ -f $script:CorePath

        $result = & $script:HostExe -NoProfile -NonInteractive -Command $probe
        [int](($result | Select-Object -Last 1).Trim()) |
            Should -Be 0 -Because 'probing optional cmdlets must not fill $Error with CommandNotFound'
    }
}

Describe 'Get-DiscoveryBranding' {
    # Regression coverage for a real bug found reviewing a live fleet run: report branding
    # (single-server AND fleet - see Merge-FleetDiscoveryResults.ps1's own Get-FleetBranding,
    # which mirrors this logic) must degrade to sensible defaults rather than throwing, since a
    # cosmetic setting must never be able to break report generation.
    BeforeAll {
        # 1x1 red pixel PNG, small enough to embed directly rather than checking in a binary fixture.
        $script:TinyPngBytes = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')
    }

    It 'returns real config values, including a base64 logo data URI, when everything is set' {
        $dir = Join-Path $TestDrive 'branding1'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $dir 'logo.png'), $script:TinyPngBytes)
        $ctx = [pscustomobject]@{ Config = [pscustomobject]@{ ConfigDir = $dir; Output = [pscustomobject]@{ html = [pscustomobject]@{ title = 'T'; brandName = 'Acme'; accentColorHex = '#ABCDEF'; logoPath = 'logo.png' } } } }

        $b = Get-DiscoveryBranding -Context $ctx
        $b.Title  | Should -Be 'T'
        $b.Brand  | Should -Be 'Acme'
        $b.Accent | Should -Be '#ABCDEF'
        $b.LogoDataUri | Should -Match '^data:image/png;base64,'
    }

    It 'falls back to defaults, not $null/throw, when Context has no Config at all' {
        $b = Get-DiscoveryBranding -Context ([pscustomobject]@{})
        $b.Brand | Should -Be 'Your Company'
        $b.Accent | Should -Be '#1F4E79'
        $b.LogoDataUri | Should -BeNullOrEmpty
    }

    It 'falls back to no logo when logoPath points at a file that does not exist' {
        $dir = Join-Path $TestDrive 'branding2'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $ctx = [pscustomobject]@{ Config = [pscustomobject]@{ ConfigDir = $dir; Output = [pscustomobject]@{ html = [pscustomobject]@{ logoPath = 'does-not-exist.png' } } } }
        (Get-DiscoveryBranding -Context $ctx).LogoDataUri | Should -BeNullOrEmpty
    }

    It 'falls back to no logo for an unrecognized file extension' {
        $dir = Join-Path $TestDrive 'branding3'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $dir 'logo.bmp'), $script:TinyPngBytes)
        $ctx = [pscustomobject]@{ Config = [pscustomobject]@{ ConfigDir = $dir; Output = [pscustomobject]@{ html = [pscustomobject]@{ logoPath = 'logo.bmp' } } } }
        (Get-DiscoveryBranding -Context $ctx).LogoDataUri | Should -BeNullOrEmpty
    }

    It 'falls back to no logo for an oversized file rather than embedding it' {
        $dir = Join-Path $TestDrive 'branding4'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        # 512KB is the cutoff - one byte over must be rejected, not silently truncated.
        [System.IO.File]::WriteAllBytes((Join-Path $dir 'big.png'), (New-Object byte[] (512KB + 1)))
        $ctx = [pscustomobject]@{ Config = [pscustomobject]@{ ConfigDir = $dir; Output = [pscustomobject]@{ html = [pscustomobject]@{ logoPath = 'big.png' } } } }
        (Get-DiscoveryBranding -Context $ctx).LogoDataUri | Should -BeNullOrEmpty
    }

    It 'overlays untracked branding.local.json onto output-settings.json, keeping the shared keys' {
        $dir = Join-Path $TestDrive 'branding5'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'output-settings.json') -Value '{"html":{"title":"T","brandName":"Your Company","logoPath":""},"requiredOutputFiles":["README.txt"]}'
        Set-Content -LiteralPath (Join-Path $dir 'branding.local.json') -Value '{"html":{"brandName":"Acme","logoPath":"logo.png"}}'
        $out = (Get-DiscoveryConfigBundle -ConfigDirectory $dir -BrandingDirectory $dir).Output
        $out.html.brandName | Should -Be 'Acme'
        $out.html.logoPath  | Should -Be 'logo.png'
        $out.html.title     | Should -Be 'T'
        @($out.requiredOutputFiles) | Should -Be @('README.txt')
    }

    It 'leaves output-settings.json untouched when there is no branding.local.json' {
        $dir = Join-Path $TestDrive 'branding6'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'output-settings.json') -Value '{"html":{"brandName":"Your Company"}}'
        (Get-DiscoveryConfigBundle -ConfigDirectory $dir -BrandingDirectory $dir).Output.html.brandName | Should -Be 'Your Company'
    }

    It 'finds branding in %ProgramData% first, then the pre-move config dir, else defaults to %ProgramData%' {
        $cfg = Join-Path $TestDrive 'bd-config'; $pd = Join-Path $TestDrive 'bd-programdata'
        New-Item -ItemType Directory -Path $cfg, $pd -Force | Out-Null
        Get-DiscoveryBrandingDirectory -ConfigDirectory $cfg -ProgramDataDirectory $pd | Should -Be $pd
        Set-Content -LiteralPath (Join-Path $cfg 'branding.local.json') -Value '{}'
        Get-DiscoveryBrandingDirectory -ConfigDirectory $cfg -ProgramDataDirectory $pd | Should -Be $cfg
        Set-Content -LiteralPath (Join-Path $pd 'branding.local.json') -Value '{}'
        Get-DiscoveryBrandingDirectory -ConfigDirectory $cfg -ProgramDataDirectory $pd | Should -Be $pd
    }

    It 'embeds a logo saved in the branding directory (not the config directory)' {
        $cfg = Join-Path $TestDrive 'logo-config'; $bd = Join-Path $TestDrive 'logo-branding'
        New-Item -ItemType Directory -Path $cfg, $bd -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $bd 'branding-logo.png'), $script:TinyPngBytes)
        $ctx = [pscustomobject]@{ Config = [pscustomobject]@{ ConfigDir = $cfg; BrandingDir = $bd; Output = [pscustomobject]@{ html = [pscustomobject]@{ logoPath = 'branding-logo.png' } } } }
        (Get-DiscoveryBranding -Context $ctx).LogoDataUri | Should -Match '^data:image/png;base64,'
    }
}
