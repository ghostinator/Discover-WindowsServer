#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Engine.Tests.ps1 - regression guards for defects found by running the toolkit on a real
    Windows Server: optional-hook probing across a module-name collision, and CriticalPaths
    merging (Pester 5.x).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $script:Root 'modules\Core\Core.psm1')             -Force -DisableNameChecking -Global
    Import-Module (Join-Path $script:Root 'modules\Output\Output.psm1')         -Force -DisableNameChecking -Global
    Import-Module (Join-Path $script:Root 'modules\RiskEngine\RiskEngine.psm1') -Force -DisableNameChecking -Global
    Import-Module (Join-Path $script:Root 'Discover-WindowsServer.psm1')        -Force -DisableNameChecking -Global
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $script:Root 'config')
}

Describe 'Test-ModuleCommandExists' {
    It 'is false when an OS module of the same name is loaded alongside the collector' {
        # Storage is the real-world case: Get-Volume autoloads the OS 'Storage' module while
        # the toolkit's Storage collector is still loaded. [bool] of the two-element array that
        # member enumeration returned was always $true, so absent optional hooks "existed".
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dws-collide-' + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory $tmp | Out-Null
        try {
            $a = New-Module -Name CollideTest -ScriptBlock { function Invoke-DiscoveryCollection { } } | Import-Module -PassThru -Global -Force
            $b = New-Module -Name CollideTest -ScriptBlock { function Get-Other { } } | Import-Module -PassThru -Global -Force
            @(Get-Module -Name CollideTest).Count | Should -Be 2
            (& (Get-Module Discover-WindowsServer) { param($c) Test-ModuleCommandExists -ModuleName CollideTest -Command $c } 'Invoke-DiscoveryCollection')   | Should -BeTrue
            (& (Get-Module Discover-WindowsServer) { param($c) Test-ModuleCommandExists -ModuleName CollideTest -Command $c } 'Invoke-DiscoveryRiskAnalysis') | Should -BeFalse
        } finally {
            Get-Module -Name CollideTest | Remove-Module -Force -ErrorAction SilentlyContinue
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Add-DataSet redaction safety net' {
    It 'redacts a secret in a free-text field no collector redacts itself (Hyper-V VM Notes)' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        Add-DataSet -Context $c -Name 'HyperVVMs' -Rows @([pscustomobject]@{ Name='VM1'; Notes='Owner: Finance. sa password = Sup3rS3cret!' }) | Out-Null
        $c.DataSets['HyperVVMs'].Rows[0].Notes | Should -Not -BeLike '*Sup3rS3cret*'
        $c.DataSets['HyperVVMs'].Rows[0].Notes | Should -BeLike 'Owner: Finance*'
    }
    It 'is idempotent and leaves ordinary text alone' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        $once = 'Server=sql01;Database=ERP;Password=[REDACTED];'
        Add-DataSet -Context $c -Name 'X' -Rows @([pscustomobject]@{ A=$once; B='Front Office HP, second floor printer' }) | Out-Null
        $c.DataSets['X'].Rows[0].A | Should -Be $once
        $c.DataSets['X'].Rows[0].B | Should -Be 'Front Office HP, second floor printer'
    }
}

Describe 'Invoke-CollectionWithDeadline' {
    BeforeAll {
        # A throwaway modules root: the real Core/Output plus two synthetic collectors.
        $script:DlRoot = Join-Path ([IO.Path]::GetTempPath()) ('dws-deadline-' + [guid]::NewGuid().ToString('N').Substring(0,8))
        foreach ($m in 'Core','Output') { New-Item -ItemType Directory (Join-Path $script:DlRoot $m) -Force | Out-Null; Copy-Item (Join-Path $script:Root "modules\$m\$m.psm1") (Join-Path $script:DlRoot "$m\$m.psm1") }
        New-Item -ItemType Directory (Join-Path $script:DlRoot 'QuickTest') -Force | Out-Null
        Set-Content (Join-Path $script:DlRoot 'QuickTest\QuickTest.psm1') 'function Invoke-DiscoveryCollection { param($Context) Add-DataSet -Context $Context -Name ''FromChild'' -Rows @([pscustomobject]@{ A=1 }) | Out-Null; return ,@{ Answer=42 } }'
        New-Item -ItemType Directory (Join-Path $script:DlRoot 'HangTest') -Force | Out-Null
        Set-Content (Join-Path $script:DlRoot 'HangTest\HangTest.psm1') 'function Invoke-DiscoveryCollection { param($Context) Start-Sleep -Seconds 60; return ,@{ Late=1 } }'
    }
    AfterAll { Remove-Item $script:DlRoot -Recurse -Force -ErrorAction SilentlyContinue }
    It 'returns the collector result and lets it mutate the shared context' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        $r = & (Get-Module Discover-WindowsServer) { param($ctx,$root) Invoke-CollectionWithDeadline -Context $ctx -Name 'QuickTest' -ModulesRoot $root -TimeoutSeconds 30 } $c $script:DlRoot
        $r.Answer | Should -Be 42
        $c.DataSets.Contains('FromChild') | Should -BeTrue
    }
    It 'abandons a hung collector at the deadline, logs a limitation and returns' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        $t = Measure-Command { $r = & (Get-Module Discover-WindowsServer) { param($ctx,$root) Invoke-CollectionWithDeadline -Context $ctx -Name 'HangTest' -ModulesRoot $root -TimeoutSeconds 3 } $c $script:DlRoot }
        $t.TotalSeconds | Should -BeLessThan 20
        $r | Should -BeNullOrEmpty
        @($c.Limitations | Where-Object { $_.Module -eq 'HangTest' -and $_.Message -match 'did not finish' }).Count | Should -Be 1
    }
}

Describe 'Storage volumes' {
    It 'never lists a CD-ROM/ISO volume (always 0% free, raised a bogus low-free-space finding)' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        Import-Module (Join-Path $script:Root 'modules\Storage\Storage.psm1') -Force -DisableNameChecking
        $r = Invoke-DiscoveryCollection -Context $c
        @($r.Volumes | Where-Object { $_.DriveType -eq 'CD-ROM' }).Count | Should -Be 0
    }
}

Describe 'RDS prerequisite' {
    BeforeAll { Import-Module (Join-Path $script:Root 'modules\RDS\RDS.psm1') -Force -DisableNameChecking -Global }
    It 'an installed RDS role service enables the module' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        Add-DataSet -Context $c -Name 'RolesFeatures' -Rows @([pscustomobject]@{ Name='RDS-RD-Server'; DisplayName='RD Session Host'; InstallState='Installed' }) | Out-Null
        (Test-DiscoveryPrerequisites -Context $c).CanRun | Should -BeTrue
    }
    It 'an available-but-not-installed RDS role changes nothing (a plain file server was reported as an RDS host)' {
        $none = New-DiscoveryContext -Mode Deep -Config $script:Config
        $avail = New-DiscoveryContext -Mode Deep -Config $script:Config
        Add-DataSet -Context $avail -Name 'RolesFeatures' -Rows @([pscustomobject]@{ Name='RDS-RD-Server'; DisplayName='RD Session Host'; InstallState='Available' }) | Out-Null
        (Test-DiscoveryPrerequisites -Context $avail).CanRun | Should -Be ((Test-DiscoveryPrerequisites -Context $none).CanRun)
    }
}

Describe 'Build-CriticalPaths' {
    It 'merges derived rows into rows already produced by ConfigDependencyScan instead of skipping' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        Add-DataSet -Context $c -Name 'CriticalPaths' -Rows @(
            [pscustomobject]@{ Path='C:\svc\a.exe'; Source='Service'; ReasonItMatters='x'; Exists=$true; SizeIfSafe=''; RelatedServiceOrApp='A'; Confidence='Likely'; PotentialProjectImpact='Cutover Complexity' }
        ) | Out-Null
        Add-DataSet -Context $c -Name 'SqlInstances' -Rows @([pscustomobject]@{ InstanceName='SRV\SQL'; BinaryPath='C:\Sql\Binn' }) | Out-Null
        & (Get-Module RiskEngine) { param($ctx) Build-CriticalPaths -Context $ctx } $c
        $rows = @($c.DataSets['CriticalPaths'].Rows)
        @($rows | Where-Object { $_.Source -eq 'SQL' }).Count     | Should -Be 1
        @($rows | Where-Object { $_.Source -eq 'Service' }).Count | Should -Be 1
    }
    It 'does not duplicate a Path+Source pair already present' {
        $c = New-DiscoveryContext -Mode Deep -Config $script:Config
        Add-DataSet -Context $c -Name 'CriticalPaths' -Rows @(
            [pscustomobject]@{ Path='C:\Sql\Binn'; Source='SQL'; ReasonItMatters='x'; Exists=$true; SizeIfSafe=''; RelatedServiceOrApp='A'; Confidence='Likely'; PotentialProjectImpact='Data Migration' }
        ) | Out-Null
        Add-DataSet -Context $c -Name 'SqlInstances' -Rows @([pscustomobject]@{ InstanceName='SRV\SQL'; BinaryPath='C:\Sql\Binn' }) | Out-Null
        & (Get-Module RiskEngine) { param($ctx) Build-CriticalPaths -Context $ctx } $c
        @($c.DataSets['CriticalPaths'].Rows).Count | Should -Be 1
    }
}
