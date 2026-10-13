#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Odbc.Tests.ps1 - the shared DSN normaliser (Core) and the SQL collector's system DSN/driver
    inventory across the 32- and 64-bit registry views. The contract that matters most: no
    password, user ID or other credential attribute ever reaches a row.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\SQL\SQL.psm1')   -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')
}

Describe 'ConvertTo-OdbcDsnRecord - secrets excluded' {
    It 'drops PWD, UID, Password and LastUser and never echoes their values' {
        $props = @{ Driver='SQL Server'; Server='sql01'; Database='erp'; PWD='Sup3rS3cret!'; UID='sa'; Password='hunter2public'; LastUser='admin'; Trusted_Connection='No'; Description='ERP' }
        $r = ConvertTo-OdbcDsnRecord -DsnName 'ERP' -Properties $props -Scope 'System' -Bitness '64'
        $all = ($r.PSObject.Properties | ForEach-Object { [string]$_.Value }) -join ' | '
        $all | Should -Not -Match 'Sup3rS3cret'
        $all | Should -Not -Match 'hunter2public'
        $r.SafeAttributes | Should -Not -Match '(?i)\b(PWD|UID|Password|LastUser)='
        $r.SafeAttributes | Should -Match 'Trusted_Connection=No'
        $r.Server | Should -Be 'sql01'
        $r.Description | Should -Be 'ERP'
    }
    It 'drops any attribute whose name looks sensitive (token, secret, key)' {
        $r = ConvertTo-OdbcDsnRecord -DsnName 'X' -Properties @{ Driver='d'; ApiToken='abc123456789'; ClientSecret='zzz98765432'; Server='h' }
        $r.SafeAttributes | Should -Not -Match 'abc123|zzz987'
    }
    It 'ignores the PowerShell registry provider properties' {
        $r = ConvertTo-OdbcDsnRecord -DsnName 'X' -Properties ([pscustomobject]@{ PSPath='p'; PSChildName='c'; Driver='d'; Server='h' })
        $r.SafeAttributes | Should -Not -Match 'PSPath|PSChildName'
    }
}

Describe 'ConvertTo-OdbcDsnRecord - migration flags' {
    It 'flags a file-based DSN and its path, and recognises application families' {
        $r = ConvertTo-OdbcDsnRecord -DsnName 'TS Data' -Properties @{ Driver='Timberline Data'; DBQ='\\fs01\Sage\Data'; Description='Timberline' }
        $r.IsFileBased | Should -BeTrue
        $r.UsesUncPath | Should -BeTrue
        $r.DbqOrPath | Should -Be '\\fs01\Sage\Data'
        $r.ApplicationHint | Should -Be 'Sage / Timberline'
    }
    It 'flags a DSN that points at this server by name, localhost or a named instance' {
        (ConvertTo-OdbcDsnRecord -DsnName 'A' -Properties @{ Server=('{0}\SQLEXPRESS' -f $env:COMPUTERNAME) }).PointsToLocalServer | Should -BeTrue
        (ConvertTo-OdbcDsnRecord -DsnName 'B' -Properties @{ Server='(local)' }).PointsToLocalServer | Should -BeTrue
        (ConvertTo-OdbcDsnRecord -DsnName 'C' -Properties @{ Server='otherhost' }).PointsToLocalServer | Should -BeFalse
    }
    It 'recognises Actian / Pervasive DSNs' {
        (ConvertTo-OdbcDsnRecord -DsnName 'PSQL' -Properties @{ Driver='Pervasive ODBC Interface'; ServerName='app01.1583' }).ApplicationHint | Should -Be 'Actian / Pervasive'
    }
}

Describe 'Set-OdbcCrossChecks' {
    It 'marks a DSN present in both 32-bit and 64-bit views, per scope' {
        $rows = @(
            (ConvertTo-OdbcDsnRecord -DsnName 'ERP' -Properties @{ Driver='SQL Server' } -Bitness '64')
            (ConvertTo-OdbcDsnRecord -DsnName 'erp' -Properties @{ Driver='SQL Server' } -Bitness '32')
            (ConvertTo-OdbcDsnRecord -DsnName 'Only64' -Properties @{ Driver='SQL Server' } -Bitness '64')
        )
        Set-OdbcCrossChecks -Dsns $rows -Drivers @()
        $rows[0].DuplicateAcrossBitness | Should -BeTrue
        $rows[1].DuplicateAcrossBitness | Should -BeTrue
        $rows[2].DuplicateAcrossBitness | Should -BeFalse
        $rows[2].DriverInstalled | Should -BeNullOrEmpty
    }
    It 'checks the driver against the drivers registered for the same bitness' {
        $rows = @((ConvertTo-OdbcDsnRecord -DsnName 'A' -Properties @{ Driver='Pervasive ODBC Interface' } -Bitness '32'), (ConvertTo-OdbcDsnRecord -DsnName 'B' -Properties @{ Driver='Pervasive ODBC Interface' } -Bitness '64'))
        Set-OdbcCrossChecks -Dsns $rows -Drivers @([pscustomobject]@{ Name='Pervasive ODBC Interface'; Bitness='32'; DriverPath='C:\x\w3odbcci.dll' })
        $rows[0].DriverInstalled | Should -BeTrue
        $rows[1].DriverInstalled | Should -BeFalse
    }
}

Describe 'SQL collector - 32-bit and 64-bit system DSNs and drivers' {
    It 'reads both registry views, labels bitness, and keeps credentials out' {
        Mock -CommandName Test-RegistryPathSafe -ModuleName SQL -MockWith { $Path -match 'ODBC' }
        Mock -CommandName Invoke-CimSafe -ModuleName SQL -MockWith { ,@() }
        Mock -CommandName Get-RegistryValueSafe -ModuleName SQL -MockWith { if ($Name -eq 'Driver') { 'C:\Windows\system32\SQLSRV32.dll' } else { $null } }
        Mock -CommandName Get-ChildItem -ModuleName SQL -MockWith {
            if ($LiteralPath -like '*WOW6432Node*') { ,@([pscustomobject]@{ PSChildName='Payroll'; PSPath='wow:Payroll' }) }
            else { ,@([pscustomobject]@{ PSChildName='Payroll'; PSPath='native:Payroll' }, [pscustomobject]@{ PSChildName='ODBC Data Sources'; PSPath='native:list' }) }
        }
        Mock -CommandName Get-ItemProperty -ModuleName SQL -MockWith {
            if ($LiteralPath -like '*ODBC Drivers') { [pscustomobject]@{ 'SQL Server'='Installed'; PSPath='x'; PSChildName='x'; PSParentPath='x'; PSDrive='x'; PSProvider='x' } }
            elseif ($LiteralPath -like 'wow:*') { [pscustomobject]@{ Driver='SQL Server'; Server='sql02'; Database='pay'; PWD='hunter2public' } }
            else { [pscustomobject]@{ Driver='SQL Server'; Server='sql02'; Database='pay'; UID='payuser' } }
        }
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config
        $raw = Invoke-DiscoveryCollection -Context $ctx
        @($raw.OdbcDsns).Count | Should -Be 2
        ($raw.OdbcDsns.Bitness | Sort-Object) -join ',' | Should -Be '32,64'
        @($raw.OdbcDsns | Where-Object DuplicateAcrossBitness).Count | Should -Be 2
        (($raw.OdbcDsns | ConvertTo-Json -Depth 3)) | Should -Not -Match 'hunter2public|payuser'
        @($raw.OdbcDrivers).Count | Should -Be 2
        @($raw.OdbcDsns | Where-Object { $_.DriverInstalled -eq $true }).Count | Should -Be 2
    }
}
