#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    FileShares.Tests.ps1 - file-server migration readiness: the deep scan is opt-in, the scan
    survives unreadable folders and says so, and the migration flags fire on the right shapes.
    Share enumeration cmdlets are mocked; the deep scan runs against real files in $TestDrive.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                 -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\FileShares\FileShares.psm1')     -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function Set-ShareMocks {
        param([string]$SharePath)
        $script:SharePath = $SharePath
        Mock -CommandName Get-CommandAvailable -ModuleName FileShares -MockWith { $Name -in @('Get-SmbShare','Get-SmbShareAccess') }
        Mock -CommandName Get-SmbShare -ModuleName FileShares -MockWith {
            ,@([pscustomobject]@{ Name='Data'; Path=$script:SharePath; Description='Dept data'; ShareType='FileSystemDirectory'; FolderEnumerationMode='Unrestricted'; EncryptData=$false }
               [pscustomobject]@{ Name='ADMIN$'; Path='C:\Windows'; Description='Remote Admin'; ShareType='FileSystemDirectory'; FolderEnumerationMode='Unrestricted'; EncryptData=$false })
        }
        Mock -CommandName Get-SmbShareAccess -ModuleName FileShares -MockWith { ,@([pscustomobject]@{ AccountName='Everyone'; AccessRight='Read'; AccessControlType='Allow' }) }
        Mock -CommandName Get-Service -ModuleName FileShares -MockWith { $null }
    }
}

Describe 'Deep file scan is opt-in' {
    It 'does not crawl shares unless -DeepFileShareScan was requested' {
        $dir = Join-Path $TestDrive 'share1'; New-Item -ItemType Directory $dir -Force | Out-Null
        Set-Content (Join-Path $dir 'a.txt') 'x'
        Set-ShareMocks -SharePath $dir
        Mock -CommandName Get-ShareDeepScanStats -ModuleName FileShares -MockWith { throw 'deep scan must not run' }
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config -Parameters @{}
        $raw = Invoke-DiscoveryCollection -Context $ctx
        @($raw.NtfsAclSummary).Count | Should -Be 0
        $raw.FileShareSummary[0].DeepScanPerformed | Should -BeFalse
        $raw.SmbShares.Count | Should -Be 2
    }

    It 'the shipped Fast configuration keeps the deep scan off' {
        $script:Config.Fast.parameterDefaults.deepFileShareScan | Should -BeFalse
        $script:Config.Default.defaults.deepFileShareScan | Should -BeFalse
    }

    It 'crawls and reports per-share stats when requested' {
        $dir = Join-Path $TestDrive 'share2'; New-Item -ItemType Directory (Join-Path $dir 'sub') -Force | Out-Null
        Set-Content (Join-Path $dir 'a.txt') 'hello'; Set-Content (Join-Path $dir 'sub\b.txt') 'world'
        Set-ShareMocks -SharePath $dir
        $ctx = New-DiscoveryContext -Mode Deep -Config $script:Config -Parameters @{ DeepFileShareScan = $true; MaxDepth = 3 }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = @($raw.NtfsAclSummary)[0]
        $row.Share | Should -Be 'Data'
        $row.FileCount | Should -Be 2
        $row.ScanStatus | Should -Be 'Complete'
        $row.OldestWriteTime | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-ShareDeepScanStats' {
    It 'counts unreadable folders, keeps scanning the rest, and marks the scan Incomplete' {
        $dir = Join-Path $TestDrive 'scan'; New-Item -ItemType Directory (Join-Path $dir 'Locked') -Force | Out-Null
        New-Item -ItemType Directory (Join-Path $dir 'Open') -Force | Out-Null
        Set-Content (Join-Path $dir 'Open\f1.txt') 'abc'; Set-Content (Join-Path $dir 'root.txt') 'abc'; Set-Content (Join-Path $dir 'Locked\secret.txt') 'abc'
        $enum = { param($d) if ($d -like '*\Locked') { throw [System.UnauthorizedAccessException]::new('Access is denied') }; ([System.IO.DirectoryInfo]$d).EnumerateFileSystemInfos() }
        $s = Get-ShareDeepScanStats -Path $dir -MaxDepth 3 -ChildEnumerator $enum
        $s.AccessDeniedCount | Should -Be 1
        $s.FileCount | Should -Be 2
        $s.ScanStatus | Should -Be 'Incomplete'
        $s.IncompleteReason | Should -Match 'could not be read'
    }

    It 'reports DepthLimited rather than Complete when folders exist below the depth limit' {
        $dir = Join-Path $TestDrive 'deep'; New-Item -ItemType Directory (Join-Path $dir 'a\b\c') -Force | Out-Null
        Set-Content (Join-Path $dir 'a\b\c\x.txt') 'x'
        $s = Get-ShareDeepScanStats -Path $dir -MaxDepth 1
        $s.ScanStatus | Should -Be 'DepthLimited'
        $s.FileCount | Should -Be 0
    }

    It 'stops at the time budget and says so' {
        $dir = Join-Path $TestDrive 'slow'; New-Item -ItemType Directory $dir -Force | Out-Null
        $s = Get-ShareDeepScanStats -Path $dir -TimeoutSeconds 0
        $s.ScanStatus | Should -Be 'Incomplete'
        $s.IncompleteReason | Should -Match 'time budget'
    }

    It 'excludes the recycle bin from totals but reports it separately' {
        $dir = Join-Path $TestDrive 'rb'; New-Item -ItemType Directory (Join-Path $dir '$RECYCLE.BIN') -Force | Out-Null
        Set-Content (Join-Path $dir '$RECYCLE.BIN\old.txt') 'gone'; Set-Content (Join-Path $dir 'live.txt') 'here'
        $s = Get-ShareDeepScanStats -Path $dir -MaxDepth 3
        $s.FileCount | Should -Be 1
        $s.RecycleBinFilesFound | Should -Be 1
        $s.TopLevelFolders | Should -Be 0
    }
}

Describe 'Get-ShareMigrationFlags' {
    It 'recognises profile / home / redirected-folder shares' {
        (Get-ShareMigrationFlags -Name 'Users' -Path 'D:\Users' -Description '').IsProfileOrRedirectedShare | Should -BeTrue
        (Get-ShareMigrationFlags -Name 'Profiles$' -Path 'E:\Profiles' -Description '').IsProfileOrRedirectedShare | Should -BeTrue
        (Get-ShareMigrationFlags -Name 'Accounting' -Path 'D:\Accounting' -Description '').IsProfileOrRedirectedShare | Should -BeFalse
    }
    It 'recognises a likely prior migration copy' {
        (Get-ShareMigrationFlags -Name 'Data_old' -Path 'D:\Data_old' -Description '').PossiblePriorMigrationCopy | Should -BeTrue
        (Get-ShareMigrationFlags -Name 'Data' -Path 'D:\Data-20240115' -Description '').PossiblePriorMigrationCopy | Should -BeTrue
        (Get-ShareMigrationFlags -Name 'Data' -Path 'D:\Data' -Description '').PossiblePriorMigrationCopy | Should -BeFalse
    }
    It 'flags shares on the system drive' {
        (Get-ShareMigrationFlags -Name 'Data' -Path ($env:SystemDrive + '\Data') -Description '').PathOnSystemDrive | Should -BeTrue
    }
}
