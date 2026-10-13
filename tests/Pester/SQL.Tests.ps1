#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    SQL.Tests.ps1 - fixture-based tests for the SQL Server collector.

    Ninth collector covered. Picked for a real feature added this session with zero prior
    coverage: HostLogicalProcessors, summed once from the Processors dataset (SystemInventory
    runs before SQL in collectorModuleOrder) and stamped onto every SqlInstances row - the
    signal RULE-SQL-009 uses to flag Enterprise-edition-vs-core-count licensing exposure.
    Also covers the Windows Internal Database (WID) detection path, whose IsWindowsInternalDatabase
    flag is what RULE-SQL-001 uses to exclude WID from the "SQL Server instance detected"
    finding (a real fix this session, even though the rule itself lives in risk-rules.json).

    -AttemptSqlIntegratedAuth defaults off, so $deepQuery just logs an Unknown and returns
    false without ever opening a real SqlConnection - none of these tests need to mock ADO.NET.

    Every Invoke-CimSafe/Get-RegistryValueSafe mock below is comma-wrapped (`,@(...)`) per the
    lesson in ConfigDependencyScan.Tests.ps1's header - a mock's own return value silently
    unrolls a 1-element array to a bare scalar through Pester's mock pipeline otherwise.

    Get-SqlServiceAccount was missing from the module's Export-ModuleMember list (unlike every
    other collector's equivalent testable helper - Get-ConfigScanRoots, Test-AhEvidence, etc.)
    - added it there so it's directly testable, matching the established convention. No
    behavior change, just visibility.

    Writing the WID/service-fallback tests below also caught a wrong assumption in the TEST,
    not the code: InstanceName on a service-fallback row is the raw Win32_Service name (e.g.
    'MSSQL$MICROSOFT##WID'), not the friendly connection target ('np:\\.\pipe\...' or
    'HOST\INSTANCE') the code computes as $fbTarget - that friendly string is used only for the
    deep-query connection string and is never stored on the row. Registry-detected instances
    DO store the friendly form as InstanceName, so the two detection paths are inconsistent
    here - worth knowing if this dataset's InstanceName field is ever consumed expecting one
    shape or the other, but a real observation about existing behavior, not something this
    test-only pass changed.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\SQL\SQL.psm1')   -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-SqlTestContext {
        New-DiscoveryContext -Mode Fast -Config $script:Config
    }

    $script:SqlRegistryValues = @{}

    function Set-SqlRegistryValuesMock {
        Mock -CommandName Get-RegistryValueSafe -ModuleName SQL -MockWith {
            $key = '{0}|{1}' -f $Path, $Name
            if ($script:SqlRegistryValues.ContainsKey($key)) { $script:SqlRegistryValues[$key] } else { $null }
        }
    }
}

Describe 'Get-SqlServiceAccount' {
    It 'reads the service account from the Services dataset when present' {
        $ctx = New-SqlTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name = 'MSSQLSERVER'; StartName = 'CORP\svc-sql' }
        ) | Out-Null
        Get-SqlServiceAccount -Context $ctx -ServiceName 'MSSQLSERVER' | Should -Be 'CORP\svc-sql'
    }

    It 'falls back to a direct CIM lookup when the service is not in the Services dataset' {
        $ctx = New-SqlTestContext   # no Services dataset seeded
        Mock -CommandName Invoke-CimSafe -ModuleName SQL -MockWith {
            ,@([pscustomobject]@{ StartName = 'NT SERVICE\MSSQL$SQLEXPRESS' })
        }
        Get-SqlServiceAccount -Context $ctx -ServiceName 'MSSQL$SQLEXPRESS' | Should -Be 'NT SERVICE\MSSQL$SQLEXPRESS'
    }
}

Describe 'Invoke-DiscoveryCollection - registry-based instance detection' {

    BeforeEach {
        $script:SqlRegistryValues = @{
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\Setup|Version'     = '15.0.4153.1'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\Setup|Edition'     = 'Enterprise Edition'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\Setup|SQLBinRoot'  = 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\Setup|Version'       = '15.0.2000.5'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\Setup|Edition'       = 'Express Edition'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\Setup|SQLBinRoot'    = 'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\Binn'
        }
        Set-SqlRegistryValuesMock
        # True ONLY for the SQL instance-name registry key, so ODBC DSN enumeration (which
        # also calls Test-RegistryPathSafe, on unrelated paths) stays out of the way.
        Mock -CommandName Test-RegistryPathSafe -ModuleName SQL -MockWith {
            $Path -eq 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
        }
        Mock -CommandName Get-ItemProperty -ModuleName SQL -MockWith {
            [pscustomobject]@{
                MSSQLSERVER = 'MSSQL15.MSSQLSERVER'; SQLEXPRESS = 'MSSQL15.SQLEXPRESS'
                PSPath = 'x'; PSParentPath = 'x'; PSChildName = 'x'; PSDrive = 'x'; PSProvider = 'x'
            }
        }
        Mock -CommandName Invoke-CimSafe -ModuleName SQL -MockWith { ,@() }   # no extra services via the fallback scan
    }

    It 'sums Processors.NumberOfLogicalProcessors once and stamps it onto every instance row' {
        $ctx = New-SqlTestContext
        Add-DataSet -Context $ctx -Name 'Processors' -Rows @(
            [pscustomobject]@{ NumberOfLogicalProcessors = 8 }
            [pscustomobject]@{ NumberOfLogicalProcessors = 4 }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.SqlInstances.Count | Should -Be 2
        foreach ($row in $raw.SqlInstances) { $row.HostLogicalProcessors | Should -Be 12 }
    }

    It 'leaves HostLogicalProcessors null when no Processors dataset is available' {
        $ctx = New-SqlTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($raw.SqlInstances | Select-Object -First 1).HostLogicalProcessors | Should -BeNullOrEmpty
    }

    It 'reads Version/Edition/BinaryPath per instance from that instance''s own Setup key' {
        $ctx = New-SqlTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.SqlInstances | Where-Object InstanceName -eq $env:COMPUTERNAME
        $row.Version     | Should -Be '15.0.4153.1'
        $row.Edition      | Should -Be 'Enterprise Edition'
        $row.BinaryPath   | Should -Match 'MSSQL15\.MSSQLSERVER'
        $row.IsExpress    | Should -BeFalse
    }

    It 'flags a SQLEXPRESS instance as IsExpress based on the service name alone' {
        $ctx = New-SqlTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.SqlInstances | Where-Object InstanceName -like "*\SQLEXPRESS"
        $row.IsExpress | Should -BeTrue
    }

    It 'picks up the service account from the Services dataset for the default instance' {
        $ctx = New-SqlTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name = 'MSSQLSERVER'; StartName = 'CORP\svc-sql' }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.SqlInstances | Where-Object InstanceName -eq $env:COMPUTERNAME
        $row.ServiceAccount | Should -Be 'CORP\svc-sql'
    }

    It 'logs an Unknown instead of attempting a deep query when -AttemptSqlIntegratedAuth is not set' {
        $ctx = New-SqlTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($raw.SqlInstances | Select-Object -First 1).DeepQueryPerformed | Should -BeFalse
        ($ctx.Unknowns | Where-Object { $_.Unknown -match 'deep enumeration not attempted' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-DiscoveryCollection - Windows Internal Database detection (service-based fallback)' {

    It 'flags a WID instance as IsWindowsInternalDatabase (InstanceName is the raw service name - the friendly np: target is used only for the deep-query connection, not stored on the row)' {
        $ctx = New-SqlTestContext
        Mock -CommandName Test-RegistryPathSafe -ModuleName SQL -MockWith { $false }   # no registry-detected instances
        Mock -CommandName Invoke-CimSafe -ModuleName SQL -MockWith {
            if ($Filter -like "Name LIKE 'MSSQL%'") {
                ,@([pscustomobject]@{ Name = 'MSSQL$MICROSOFT##WID'; PathName = '"C:\Windows\WID\bin\sqlservr.exe" -sMICROSOFT##WID'; StartName = 'NT SERVICE\MSSQL$MICROSOFT##WID' })
            } else { ,@() }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.SqlInstances.Count | Should -Be 1
        $row = $raw.SqlInstances[0]
        $row.IsWindowsInternalDatabase | Should -BeTrue
        $row.InstanceName              | Should -Be 'MSSQL$MICROSOFT##WID'
        $row.ServiceAccount            | Should -Be 'NT SERVICE\MSSQL$MICROSOFT##WID'
        $row.BinaryPath                | Should -Match 'WID\\bin'
    }

    It 'does not flag a normal named-instance service as WID' {
        $ctx = New-SqlTestContext
        Mock -CommandName Test-RegistryPathSafe -ModuleName SQL -MockWith { $false }
        Mock -CommandName Invoke-CimSafe -ModuleName SQL -MockWith {
            if ($Filter -like "Name LIKE 'MSSQL%'") {
                ,@([pscustomobject]@{ Name = 'MSSQL$SQLEXPRESS'; PathName = '"C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\Binn\sqlservr.exe"'; StartName = 'NT SERVICE\MSSQL$SQLEXPRESS' })
            } else { ,@() }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.SqlInstances[0]
        $row.IsWindowsInternalDatabase | Should -BeFalse
        $row.InstanceName              | Should -Be 'MSSQL$SQLEXPRESS'
    }
}

Describe 'Invoke-DiscoveryCollection - other database engines' {

    BeforeEach {
        Mock -CommandName Test-RegistryPathSafe -ModuleName SQL -MockWith { $false }
        Mock -CommandName Invoke-CimSafe -ModuleName SQL -MockWith { ,@() }
    }

    It 'detects PostgreSQL from a matching installed application' {
        $ctx = New-SqlTestContext
        Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @(
            [pscustomobject]@{ DisplayName = 'PostgreSQL 16' }
        ) | Out-Null
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($raw.OtherDatabaseEngines | Where-Object Engine -eq 'PostgreSQL') | Should -Not -BeNullOrEmpty
    }

    It 'does not report an engine with no service or application evidence' {
        $ctx = New-SqlTestContext
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.OtherDatabaseEngines.Count | Should -Be 0
    }
}

Describe 'Get-SqlInstanceClassification - default and named instances' {
    It 'leaves a default instance with no application signal as Unknown, not guessed' {
        $c = Get-SqlInstanceClassification -InstanceName $env:COMPUTERNAME -Edition 'Standard Edition' -IsWid $false
        $c.Classification | Should -Be 'General-purpose / unknown'
        $c.Confidence | Should -Be 'Unknown'
    }
    It 'classifies a BKUPEXEC named instance as Likely from the name alone' {
        $c = Get-SqlInstanceClassification -InstanceName 'HOST\BKUPEXEC' -Edition 'Express Edition' -IsWid $false
        $c.Classification | Should -Be 'Backup Exec catalog'
        $c.Confidence | Should -Be 'Likely'
    }
    It 'raises it to Confirmed when an independent service corroborates the name' {
        $svc = @([pscustomobject]@{ Name='BackupExecRPCService'; DisplayName='Backup Exec Server' })
        $c = Get-SqlInstanceClassification -InstanceName 'HOST\BKUPEXEC' -Edition '' -IsWid $false -ServiceRows $svc
        $c.Confidence | Should -Be 'Confirmed'
        $c.Evidence | Should -Match 'Backup Exec Server'
    }
    It 'calls any other named instance application-specific with Possible confidence' {
        $c = Get-SqlInstanceClassification -InstanceName 'HOST\ACCTG' -Edition 'Standard Edition' -IsWid $false
        $c.Classification | Should -Be 'Application-specific named instance'
        $c.Confidence | Should -Be 'Possible'
    }
    It 'recognises WID with certainty' {
        (Get-SqlInstanceClassification -InstanceName 'MSSQL$MICROSOFT##WID' -IsWid $true).Confidence | Should -Be 'Confirmed'
    }
}

Describe 'Get-SqlVersionInfo / Get-SqlAccountType / Get-SqlServiceRole' {
    It 'maps builds to products and support state as of a given date' {
        $v = Get-SqlVersionInfo -Version '12.0.6024.0' -AsOf ([datetime]'2026-10-13')
        $v.ProductName | Should -Be 'SQL Server 2014'
        $v.IsUnsupported | Should -BeTrue
        (Get-SqlVersionInfo -Version '10.50.6000.34').ProductName | Should -Be 'SQL Server 2008 R2'
        (Get-SqlVersionInfo -Version '15.0.4153.1' -AsOf ([datetime]'2026-10-13')).IsUnsupported | Should -BeFalse
        (Get-SqlVersionInfo -Version '').ProductName | Should -Be ''
    }
    It 'classifies service accounts' {
        Get-SqlAccountType -Account 'LocalSystem' | Should -Be 'LocalSystem'
        Get-SqlAccountType -Account 'NT Service\MSSQL$SQLEXPRESS' | Should -Be 'VirtualAccount'
        Get-SqlAccountType -Account 'CORP\svc-sql' | Should -Be 'DomainAccount'
        Get-SqlAccountType -Account 'CORP\gmsa-sql$' | Should -Be 'ManagedServiceAccount'
    }
    It 'maps SQL service names to roles and instances' {
        (Get-SqlServiceRole -Name 'SQLAgent$SAGE').Role | Should -Be 'SQL Agent'
        (Get-SqlServiceRole -Name 'SQLAgent$SAGE').Instance | Should -Be 'SAGE'
        (Get-SqlServiceRole -Name 'SQLSERVERAGENT').Instance | Should -Be 'MSSQLSERVER'
        (Get-SqlServiceRole -Name 'SQLBrowser').Role | Should -Be 'SQL Browser'
        (Get-SqlServiceRole -Name 'SQLWriter').Role | Should -Be 'VSS Writer'
        (Get-SqlServiceRole -Name 'MSSQLFDLauncher$SAGE').Role | Should -Be 'Full-Text'
        Get-SqlServiceRole -Name 'Spooler' | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-DiscoveryCollection - named instance ports and connection failure' {
    BeforeEach {
        $script:SqlRegistryValues = @{
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.ACCTG\Setup|Version' = '15.0.2000.5'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.ACCTG\Setup|Edition' = 'Standard Edition'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.ACCTG\MSSQLServer\SuperSocketNetLib\Tcp\IPAll|TcpDynamicPorts' = '49731'
            'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.ACCTG\MSSQLServer\SuperSocketNetLib\Tcp|Enabled' = 1
        }
    }

    It 'detects a named instance, its dynamic port and agent state' {
        $ctx = New-SqlTestContext
        Add-DataSet -Context $ctx -Name 'Services' -Rows @(
            [pscustomobject]@{ Name='MSSQL$ACCTG'; DisplayName='SQL Server (ACCTG)'; Status='Running'; StartMode='Auto'; StartName='CORP\svc-sql'; ExecutablePath='C:\x\sqlservr.exe' }
            [pscustomobject]@{ Name='SQLAgent$ACCTG'; DisplayName='SQL Server Agent (ACCTG)'; Status='Stopped'; StartMode='Disabled'; StartName='CORP\svc-sql'; ExecutablePath='C:\x\SQLAGENT.EXE' }
        ) | Out-Null
        Set-SqlRegistryValuesMock
        Mock -CommandName Test-RegistryPathSafe -ModuleName SQL -MockWith { $Path -eq 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' }
        Mock -CommandName Get-ItemProperty -ModuleName SQL -MockWith { [pscustomobject]@{ ACCTG = 'MSSQL15.ACCTG'; PSPath='x'; PSParentPath='x'; PSChildName='x'; PSDrive='x'; PSProvider='x' } }
        Mock -CommandName Invoke-CimSafe -ModuleName SQL -MockWith { ,@() }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = @($raw.SqlInstances)[0]
        $row.InstanceName | Should -Be "$env:COMPUTERNAME\ACCTG"
        $row.UsesDynamicPort | Should -BeTrue
        $row.TcpDynamicPorts | Should -Be '49731'
        $row.AgentDisabled | Should -BeTrue
        $row.ServiceAccountType | Should -Be 'DomainAccount'
        $row.ConnectionStatus | Should -Be 'NotAttempted'
        $raw.SqlServerSummary[0].AnyAgentDisabled | Should -BeTrue
    }

    It 'records a failed integrated-auth connection per instance and keeps going' {
        InModuleScope SQL -Parameters @{ Cfg = $script:Config; Reg = $script:SqlRegistryValues } {
            param($Cfg, $Reg)
            $script:Reg = $Reg
            Mock Get-RegistryValueSafe { $k = '{0}|{1}' -f $Path, $Name; if ($script:Reg.ContainsKey($k)) { $script:Reg[$k] } else { $null } }
            Mock Test-RegistryPathSafe { $Path -eq 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' }
            Mock Get-ItemProperty { [pscustomobject]@{ ACCTG = 'MSSQL15.ACCTG'; PSPath='x'; PSParentPath='x'; PSChildName='x'; PSDrive='x'; PSProvider='x' } }
            Mock Invoke-CimSafe { ,@() }
            Mock Invoke-SqlIntegratedQuery { [pscustomobject]@{ Success=$false; Error='Login failed for user'; Databases=@(); Files=@(); Jobs=@(); Linked=@(); Logins=@(); Config=@() } }
            $ctx = New-DiscoveryContext -Mode Deep -Config $Cfg -Parameters @{ AttemptSqlIntegratedAuth = $true }
            $raw = Invoke-DiscoveryCollection -Context $ctx
            $row = @($raw.SqlInstances)[0]
            $row.ConnectionStatus | Should -Be 'Failed'
            $row.ConnectionError | Should -Match 'Login failed'
            $row.DeepQueryPerformed | Should -BeFalse
            $raw.SqlServerSummary[0].InstancesNotEnumerated | Should -Be 1
            $raw.SqlServerSummary[0].DatabasesEnumerated | Should -BeFalse
            ($ctx.Limitations | Where-Object { $_.Message -match 'Integrated-auth query' }) | Should -Not -BeNullOrEmpty
            ($ctx.Unknowns | Where-Object { $_.Unknown -match 'enumeration failed' }) | Should -Not -BeNullOrEmpty
        }
    }
}
