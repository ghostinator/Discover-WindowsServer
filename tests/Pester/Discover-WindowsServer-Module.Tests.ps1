#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Discover-WindowsServer-Module.Tests.ps1 - PowerShell Gallery publish-readiness checks for
    the root module manifest, and Start-DiscoverWindowsServerGui's "works from wherever this
    module is actually installed" claim.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

Describe 'Discover-WindowsServer.psd1 (PowerShell Gallery publish-readiness)' {
    It 'is a valid module manifest' {
        { Test-ModuleManifest -Path (Join-Path $Root 'Discover-WindowsServer.psd1') -ErrorAction Stop } | Should -Not -Throw
    }

    It 'every FileList entry exists on disk' {
        Push-Location $Root
        try {
            $m = Test-ModuleManifest -Path (Join-Path $Root 'Discover-WindowsServer.psd1')
            $missing = @($m.FileList | Where-Object { -not (Test-Path -LiteralPath $_) })
            $missing | Should -BeNullOrEmpty
        } finally { Pop-Location }
    }

    It 'FileList includes every runtime file (a file left off would be silently missing from the Gallery package)' {
        $m = Test-ModuleManifest -Path (Join-Path $Root 'Discover-WindowsServer.psd1')
        $runtime = @(
            Get-ChildItem -Path (Join-Path $Root 'modules') -Recurse -File -Include '*.psm1', '*.psd1'
            Get-ChildItem -Path (Join-Path $Root 'tools') -File -Filter '*.ps1'
            # branding.local.json is per-machine and untracked - never shipped.
            Get-ChildItem -Path (Join-Path $Root 'config') -File -Filter '*.json' | Where-Object { $_.Name -ne 'branding.local.json' }
        ) | ForEach-Object { $_.FullName.Substring($Root.Length + 1) }
        $notListed = @($runtime | Where-Object { $m.FileList -notcontains (Join-Path $Root $_) -and $m.FileList -notcontains $_ })
        $notListed | Should -BeNullOrEmpty
    }

    It 'has a real GUID, not the old hand-made placeholder (a published GUID can never change)' {
        (Test-ModuleManifest -Path (Join-Path $Root 'Discover-WindowsServer.psd1')).Guid.ToString() | Should -Not -Match '^b1c0a0e1-0000-'
    }

    It 'declares Tags, LicenseUri and ProjectUri for Gallery discoverability' {
        $m = Test-ModuleManifest -Path (Join-Path $Root 'Discover-WindowsServer.psd1')
        @($m.PrivateData.PSData.Tags).Count | Should -BeGreaterThan 0
        $m.PrivateData.PSData.LicenseUri | Should -Not -BeNullOrEmpty
        $m.PrivateData.PSData.ProjectUri | Should -Not -BeNullOrEmpty
    }

    It 'FunctionsToExport matches every module member Export-ModuleMember actually exports' {
        $m = Test-ModuleManifest -Path (Join-Path $Root 'Discover-WindowsServer.psd1')
        Import-Module (Join-Path $Root 'Discover-WindowsServer.psm1') -Force -DisableNameChecking
        $realExports = @((Get-Module Discover-WindowsServer).ExportedFunctions.Keys | Sort-Object)
        $manifestFns = @($m.ExportedFunctions.Keys | Sort-Object)
        $manifestFns | Should -Be $realExports
        Remove-Module Discover-WindowsServer -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Start-DiscoverWindowsServerGui' {
    # $PSScriptRoot inside a function defined in the root .psm1 always resolves to that file's
    # own directory, regardless of whether that directory is a git checkout or an
    # Install-Module'd copy under $env:PSModulePath - confirmed by copying the module to a
    # DIFFERENTLY-NAMED location and checking it resolves relative to THAT copy, not the
    # original repo. Never invokes the real GUI (a WPF window) - only exercises the path
    # resolution and the "GUI script missing" error path, which is the concrete point being
    # verified: a Gallery-installed copy without an actual desktop launcher available.

    It 'throws an informative error naming the COPIED location, not the original repo, when the GUI script is absent from that copy' {
        $fakeModuleDir = Join-Path $TestDrive 'Discover-WindowsServer-Fake-Install'
        New-Item -ItemType Directory -Path $fakeModuleDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $Root 'Discover-WindowsServer.psm1') -Destination $fakeModuleDir
        Copy-Item -LiteralPath (Join-Path $Root 'Discover-WindowsServer.psd1') -Destination $fakeModuleDir
        # Deliberately do NOT copy Discover-WindowsServer-GUI.ps1 - simulates a broken/partial install.
        New-Item -ItemType Directory -Path (Join-Path $fakeModuleDir 'modules\Core') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $Root 'modules\Core\Core.psm1') -Destination (Join-Path $fakeModuleDir 'modules\Core\Core.psm1')

        Import-Module (Join-Path $fakeModuleDir 'Discover-WindowsServer.psm1') -Force -DisableNameChecking
        try {
            # -Throw matches with simple wildcards (-like semantics), not regex - a literal
            # backslash in the path needs no escaping here.
            { Start-DiscoverWindowsServerGui } | Should -Throw '*Discover-WindowsServer-GUI.ps1*'
            { Start-DiscoverWindowsServerGui } | Should -Throw ('*' + $fakeModuleDir + '*')
        } finally {
            Remove-Module Discover-WindowsServer -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-DiscoverWindowsServer' {
    # The installed-module way to run a scan. Its parameters are mirrored at runtime from
    # Discover-WindowsServer.ps1, so they can't drift - this pins that claim.
    BeforeAll {
        Import-Module (Join-Path $Root 'Discover-WindowsServer.psd1') -Force -DisableNameChecking
        $script:Common = [System.Management.Automation.Cmdlet]::CommonParameters + [System.Management.Automation.Cmdlet]::OptionalCommonParameters
    }
    AfterAll { Remove-Module Discover-WindowsServer -Force -ErrorAction SilentlyContinue }

    It 'exposes exactly the entry script''s parameters, with its validation' {
        $entry   = Get-Command (Join-Path $Root 'Discover-WindowsServer.ps1')
        $wrapper = Get-Command Invoke-DiscoverWindowsServer
        @($wrapper.Parameters.Keys | Where-Object { $Common -notcontains $_ } | Sort-Object) |
            Should -Be @($entry.Parameters.Keys | Where-Object { $Common -notcontains $_ } | Sort-Object)
        { Invoke-DiscoverWindowsServer -Mode NotAMode } | Should -Throw '*Mode*'
    }

    It 'throws an informative error naming the installed location when the entry script is missing' {
        $fake = Join-Path $TestDrive 'Fake-Install-NoEntry'
        New-Item -ItemType Directory -Path (Join-Path $fake 'modules\Core') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $Root 'Discover-WindowsServer.psm1') -Destination $fake
        Copy-Item -LiteralPath (Join-Path $Root 'modules\Core\Core.psm1') -Destination (Join-Path $fake 'modules\Core\Core.psm1')
        Import-Module (Join-Path $fake 'Discover-WindowsServer.psm1') -Force -DisableNameChecking
        try {
            { Invoke-DiscoverWindowsServer } | Should -Throw ('*' + $fake + '*')
        } finally {
            Import-Module (Join-Path $Root 'Discover-WindowsServer.psd1') -Force -DisableNameChecking
        }
    }
}
