#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Discover-WindowsServer-GUI.Tests.ps1 - fixture-based tests for Build-DiscoveryArgumentList,
    the one piece of the WPF launcher that is plain logic rather than UI wiring.

    Dot-sourcing Discover-WindowsServer-GUI.ps1 is safe here specifically because everything
    WPF-related (STA relaunch, Add-Type, the XAML, ShowDialog) is gated behind an
    "only run when invoked directly" guard - see that file's own header comment for why this
    matters more than it does for tools\Send-DiscoveryOutput.ps1's identical-looking guard:
    the STA-relaunch branch calls `exit`, which would otherwise kill the entire Pester process
    the moment this file was dot-sourced under a non-STA apartment (Pester's default).

    No WPF assembly is loaded by these tests at all - Build-DiscoveryArgumentList takes plain
    strings/bools, not control objects, by design (see that file's header for why).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $Root 'Discover-WindowsServer-GUI.ps1')

    # Every switch defaults to $false and every numeric text to a valid default, so each test
    # only needs to override what it's actually checking.
    function Invoke-BuildArgs {
        param([hashtable]$Overrides = @{})
        $defaults = @{
            EngineScriptPath              = 'C:\Discover-WindowsServer.ps1'
            Mode                          = 'Fast'
            ProjectType                   = 'GeneralDiscovery'
            ComplianceLens                = 'None'
            OutputRoot                    = 'C:\Temp'
            IncludedModules               = @()
            DeepFileShareScan             = $false
            FullEventLogExport            = $false
            IncludeConfigDependencyScan   = $false
            IncludeUserProfiles           = $false
            IncludeRecycleBin             = $false
            IncludeWindowsFolder          = $false
            AttemptSqlIntegratedAuth      = $false
            GenerateEvidenceManifest      = $false
            SkipZip                       = $false
            VerboseLogging                = $false
            MaxDepthText                  = '3'
            LargeFileThresholdGBText      = '5'
            OldFileYearsText              = '7'
            EventLogDaysText              = '14'
            MaxEventSamplesText           = '50'
            ConfigScanMaxFileSizeMBText   = '10'
        }
        foreach ($k in $Overrides.Keys) { $defaults[$k] = $Overrides[$k] }
        Build-DiscoveryArgumentList @defaults
    }
}

Describe 'Build-DiscoveryArgumentList' {

    It 'returns a real array, not a scalar, even with the default (all-off) options' {
        $args = Invoke-BuildArgs
        $args.GetType().IsArray | Should -BeTrue
        $args.Count             | Should -BeGreaterThan 0
    }

    It 'includes the core Mode/ProjectType/ComplianceLens/OutputRoot values, with the script path and output root quoted' {
        $args = Invoke-BuildArgs -Overrides @{ Mode = 'Deep'; ProjectType = 'Decommission'; ComplianceLens = 'CMMC'; OutputRoot = 'D:\Scans' }
        $args | Should -Contain '-Mode'
        $args | Should -Contain 'Deep'
        $args | Should -Contain '-ProjectType'
        $args | Should -Contain 'Decommission'
        $args | Should -Contain '-ComplianceLens'
        $args | Should -Contain 'CMMC'
        $args | Should -Contain '"D:\Scans"'
        $args | Should -Contain '"C:\Discover-WindowsServer.ps1"'
    }

    It 'adds -IncludeModules with a comma-joined list only in Custom mode' {
        $args = Invoke-BuildArgs -Overrides @{ Mode = 'Custom'; IncludedModules = @('SystemInventory', 'SQL', 'IIS') }
        $idx = [array]::IndexOf($args, '-IncludeModules')
        $idx | Should -BeGreaterThan -1
        $args[$idx + 1] | Should -Be 'SystemInventory,SQL,IIS'
    }

    It 'does not add -IncludeModules in Custom mode when nothing is checked' {
        $args = Invoke-BuildArgs -Overrides @{ Mode = 'Custom'; IncludedModules = @() }
        $args | Should -Not -Contain '-IncludeModules'
    }

    It 'ignores IncludedModules entirely outside Custom mode, even if some were passed' {
        $args = Invoke-BuildArgs -Overrides @{ Mode = 'Fast'; IncludedModules = @('SystemInventory') }
        $args | Should -Not -Contain '-IncludeModules'
    }

    It 'adds a switch only when its boolean is true' {
        $onArgs  = Invoke-BuildArgs -Overrides @{ AttemptSqlIntegratedAuth = $true }
        $offArgs = Invoke-BuildArgs -Overrides @{ AttemptSqlIntegratedAuth = $false }
        $onArgs  | Should -Contain '-AttemptSqlIntegratedAuth'
        $offArgs | Should -Not -Contain '-AttemptSqlIntegratedAuth'
    }

    It 'adds every switch when every switch is on' {
        $args = Invoke-BuildArgs -Overrides @{
            DeepFileShareScan = $true; FullEventLogExport = $true; IncludeConfigDependencyScan = $true
            IncludeUserProfiles = $true; IncludeRecycleBin = $true; IncludeWindowsFolder = $true
            AttemptSqlIntegratedAuth = $true; GenerateEvidenceManifest = $true; SkipZip = $true; VerboseLogging = $true
        }
        foreach ($sw in '-DeepFileShareScan', '-FullEventLogExport', '-IncludeConfigDependencyScan', '-IncludeUserProfiles',
                        '-IncludeRecycleBin', '-IncludeWindowsFolder', '-AttemptSqlIntegratedAuth', '-GenerateEvidenceManifest',
                        '-SkipZip', '-VerboseLogging') {
            $args | Should -Contain $sw -Because "$sw should be present when its checkbox is on"
        }
    }

    It 'passes through a valid numeric text value alongside its argument name' {
        $args = Invoke-BuildArgs -Overrides @{ EventLogDaysText = '30' }
        $idx = [array]::IndexOf($args, '-EventLogDays')
        $idx | Should -BeGreaterThan -1
        $args[$idx + 1] | Should -Be '30'
    }

    It 'silently omits a numeric field whose text is not a valid integer, rather than passing garbage to the engine' {
        $args = Invoke-BuildArgs -Overrides @{ EventLogDaysText = 'not-a-number' }
        $args | Should -Not -Contain '-EventLogDays'
    }

    It 'silently omits a numeric field left blank' {
        $args = Invoke-BuildArgs -Overrides @{ MaxDepthText = '' }
        $args | Should -Not -Contain '-MaxDepth'
    }

    It 'appends -WhatIf only when -WhatIfOnly is requested' {
        $withWhatIf = Build-DiscoveryArgumentList -EngineScriptPath 'x' -Mode Fast -ProjectType GeneralDiscovery -ComplianceLens None -OutputRoot 'C:\Temp' -WhatIfOnly
        $withoutWhatIf = Build-DiscoveryArgumentList -EngineScriptPath 'x' -Mode Fast -ProjectType GeneralDiscovery -ComplianceLens None -OutputRoot 'C:\Temp'
        $withWhatIf    | Should -Contain '-WhatIf'
        $withoutWhatIf | Should -Not -Contain '-WhatIf'
    }
}

Describe 'ConvertTo-DiscoveryLauncherScript' {
    <#
        Regression coverage for a real bug: launching a script via `-File` does not re-parse
        trailing arguments as PowerShell syntax, so a comma-joined array token (exactly what
        Build-DiscoveryArgumentList produces for -IncludeModules, and what the Fleet tab built
        for -TargetComputerNames) arrives as ONE element containing the literal comma-joined
        text, not several elements - silently breaking Custom Mode for any 2+ module selection
        and Fleet Discovery for any 2+ server selection. These tests actually run the generated
        launcher end to end against a real fixture script rather than just inspecting its text,
        since the first version of this function had the actual command-building line go
        missing during an edit and every one of these would have caught that immediately.
    #>

    BeforeAll {
        $script:FixtureScript = Join-Path $TestDrive 'fixture.ps1'
        Set-Content -LiteralPath $script:FixtureScript -Value @'
param([string[]]$IncludeModules = @(), [string]$Mode = '')
[pscustomobject]@{ IncludeModules = $IncludeModules; Mode = $Mode } | ConvertTo-Json -Compress
'@
    }

    It 'passes a multi-element array through correctly, unlike a direct -File launch' {
        $argList = @('-NoProfile', '-File', "`"$script:FixtureScript`"", '-IncludeModules', 'SystemInventory,SQL,IIS')
        $launcherPath = ConvertTo-DiscoveryLauncherScript -ArgList $argList -ArrayParameterNames @('IncludeModules')
        try {
            $output = & (Get-Process -Id $PID).Path -NoProfile -File $launcherPath | ConvertFrom-Json
            @($output.IncludeModules).Count | Should -Be 3
            @($output.IncludeModules) | Should -Be @('SystemInventory', 'SQL', 'IIS')
        } finally {
            Remove-Item -LiteralPath $launcherPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does NOT self-delete - cleanup is the caller''s job, under the creating identity' {
        # Deliberately not self-deleting: both call sites in Discover-WindowsServer-GUI.ps1 delete
        # the launcher themselves, in their own completion-timer handler, under the same identity
        # that created it - see Start-DiscoveryRun and the Fleet run's Add_Click handler. (This
        # used to matter more when the Fleet launch ran its child process as a different domain
        # account via Start-Process -Credential, which could read but not delete a launcher this
        # identity created - a stray leftover .ps1 was the visible symptom. That launch mechanism
        # was replaced - see Invoke-FleetDiscovery.ps1's header for why - but "the creator cleans
        # up, not the launcher itself" is still the simpler, more robust design either way.)
        $argList = @('-NoProfile', '-File', "`"$script:FixtureScript`"", '-IncludeModules', 'SystemInventory')
        $launcherPath = ConvertTo-DiscoveryLauncherScript -ArgList $argList -ArrayParameterNames @('IncludeModules')
        try {
            & (Get-Process -Id $PID).Path -NoProfile -File $launcherPath | Out-Null
            Test-Path -LiteralPath $launcherPath | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $launcherPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes the launcher under the current user''s own %TEMP%' {
        # No longer %ProgramData% - both launches now run their child process under this same
        # identity (see the note above), so there's no cross-account access to design around.
        $argList = @('-NoProfile', '-File', "`"$script:FixtureScript`"", '-IncludeModules', 'SystemInventory')
        $launcherPath = ConvertTo-DiscoveryLauncherScript -ArgList $argList -ArrayParameterNames @('IncludeModules')
        try {
            $launcherPath | Should -Match ([regex]::Escape([System.IO.Path]::GetTempPath().TrimEnd('\')))
        } finally {
            Remove-Item -LiteralPath $launcherPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'leaves a non-array scalar parameter as a single value' {
        $argList = @('-NoProfile', '-File', "`"$script:FixtureScript`"", '-Mode', 'Deep')
        $launcherPath = ConvertTo-DiscoveryLauncherScript -ArgList $argList -ArrayParameterNames @('IncludeModules')
        try {
            $output = & (Get-Process -Id $PID).Path -NoProfile -File $launcherPath | ConvertFrom-Json
            $output.Mode | Should -Be 'Deep'
        } finally {
            Remove-Item -LiteralPath $launcherPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'throws when the argument list has no -File token' {
        { ConvertTo-DiscoveryLauncherScript -ArgList @('-Mode', 'Fast') } | Should -Throw
    }
}

Describe 'Get-DiscoveryModuleSummary' {

    It 'parses the compact single-line metadata style used by most collector modules' {
        $src = @'
function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='DNS'; DisplayName='DNS Server'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false
    }
}
'@
        $result = Get-DiscoveryModuleSummary -ModuleName 'DNS' -ModuleSource $src
        $result.DisplayName   | Should -Be 'DNS Server'
        $result.Category      | Should -Be 'Identity'
        $result.DefaultInFast | Should -BeTrue
        $result.DefaultInDeep | Should -BeTrue
    }

    It 'parses the one-property-per-line style and a Fast/Deep mismatch' {
        $src = @'
function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'ConfigDependencyScan'
        DisplayName               = 'Config Dependency Scan'
        Category                  = 'Applications'
        DefaultInFast             = $false
        DefaultInDeep             = $true
    }
}
'@
        $result = Get-DiscoveryModuleSummary -ModuleName 'ConfigDependencyScan' -ModuleSource $src
        $result.DefaultInFast | Should -BeFalse
        $result.DefaultInDeep | Should -BeTrue
    }

    It 'returns $null for a module file with no Get-DiscoveryModuleMetadata function (Core, Output)' {
        Get-DiscoveryModuleSummary -ModuleName 'Core' -ModuleSource 'function Write-Log { }' | Should -BeNullOrEmpty
    }

    It 'returns $null for a synthesis-only module (never a valid Custom Mode include target)' {
        $src = @'
function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName = 'RiskEngine'; DisplayName = 'Risk Analysis Engine'; Category = 'Synthesis'
        DefaultInFast = $true; DefaultInDeep = $true; IsSynthesis = $true
    }
}
'@
        Get-DiscoveryModuleSummary -ModuleName 'RiskEngine' -ModuleSource $src | Should -BeNullOrEmpty
    }
}
