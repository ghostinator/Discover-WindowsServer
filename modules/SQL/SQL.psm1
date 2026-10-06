<#
    SQL.psm1 - SQL Server detection, optional integrated-auth enumeration, other
    database engines, and ODBC DSNs (read-only).
    Produces: SqlInstances, SqlDatabases, SqlAgentJobs, SqlLinkedServers,
              SqlLoginsSummary, OtherDatabaseEngines, OdbcDsns.
    Deep query happens ONLY with -AttemptSqlIntegratedAuth; login names only (no hashes).
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='SQL'; DisplayName='SQL Server & Databases'; Category='Database'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('SqlInstances','SqlDatabases','SqlAgentJobs','SqlLinkedServers','SqlLoginsSummary','SqlConfiguration','OtherDatabaseEngines','OdbcDsns')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='SQL'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Get-SqlServiceAccount {
    param([object]$Context, [string]$ServiceName)
    try { if ($Context.DataSets.Contains('Services')) { $s = $Context.DataSets['Services'].Rows | Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1; if ($s) { return $s.StartName } } } catch { }
    try { $s = Invoke-CimSafe -ClassName 'Win32_Service' -Filter ("Name='{0}'" -f $ServiceName) | Select-Object -First 1; if ($s) { return $s.StartName } } catch { }
    return ''
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $instances = [System.Collections.Generic.List[object]]::new()
    $databases = [System.Collections.Generic.List[object]]::new()
    $jobs = [System.Collections.Generic.List[object]]::new()
    $linked = [System.Collections.Generic.List[object]]::new()
    $logins = [System.Collections.Generic.List[object]]::new()
    $sqlconfig = [System.Collections.Generic.List[object]]::new()
    $other = [System.Collections.Generic.List[object]]::new()
    $dsns = [System.Collections.Generic.List[object]]::new()
    $attempt = ([bool]$Context.Parameters['AttemptSqlIntegratedAuth'])

    # Total logical processor count, for the Enterprise-edition per-core-licensing signal below.
    # Enterprise is licensed per physical/logical core on the host, so knowing the instance is
    # Enterprise without knowing the core count it is running on is half the scoping question.
    # SystemInventory runs before SQL in collectorModuleOrder, so Processors is already here.
    $hostLogicalProcessors = $null
    try {
        if ($Context.DataSets.Contains('Processors')) {
            $sum = (@($Context.DataSets['Processors'].Rows) | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
            if ($sum) { $hostLogicalProcessors = [int]$sum }
        }
    } catch { }

    # ---- Detect SQL instances via registry ----
    $instMap = @{}
    try {
        $p = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
        if (Test-RegistryPathSafe $p) {
            $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                $instMap[$prop.Name] = $prop.Value
            }
        }
    } catch { }

    # Shared by the registry path and the service-based fallback: runs the integrated-auth
    # query when enabled, folds the results into the dataset lists, and returns whether it ran.
    $deepQuery = {
        param($row, $connTarget)
        if (-not $attempt) {
            Add-Unknown -Context $Context -Unknown ("SQL instance '{0}' detected; deep enumeration not attempted (use -AttemptSqlIntegratedAuth)." -f $connTarget) -WhyItMatters 'Database-level details unknown without querying.' -Module 'SQL' -RecommendedValidationQuestion 'Should integrated-auth SQL enumeration be enabled?' | Out-Null
            return $false
        }
        $res = Invoke-SqlIntegratedQuery -Instance $connTarget
        if (-not $res.Success) {
            Add-Limitation -Context $Context -Module 'SQL' -Message ("Integrated-auth query to '{0}' failed." -f $connTarget) -Reason $res.Error | Out-Null
            Add-Unknown -Context $Context -Unknown ("SQL instance '{0}' detected but database enumeration failed." -f $connTarget) -WhyItMatters 'Database inventory, sizes, and backup status remain unknown.' -Module 'SQL' -RecommendedValidationQuestion 'Can a DBA provide the database inventory and backup status?' | Out-Null
            return $false
        }
        if (-not $row.Version) { $row.Version = $res.Version }
        if (-not $row.Edition) { $row.Edition = $res.Edition; if ($res.Edition -match '(?i)Express') { $row.IsExpress = $true } }
        # Tag rows with their instance: with two instances (e.g. SQLEXPRESS + WID) every 'master' looks alike.
        # WID databases (SUSDB, RDCms, ...) are role-managed; "no SQL backup" there is not a DBA gap.
        if ($row.IsWindowsInternalDatabase) { foreach ($d in $res.Databases) { $d.NoFullBackup = $false } }
        foreach ($d in $res.Databases) { $d | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $databases.Add($d) }
        foreach ($j in $res.Jobs) { $j | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $jobs.Add($j) }
        foreach ($l in $res.Linked) { $l | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $linked.Add($l) }
        foreach ($g in $res.Logins) { $g | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $logins.Add($g) }
        $row.XpCmdShellEnabled = [bool]@($res.Config | Where-Object { $_.Setting -eq 'xp_cmdshell' -and [int64]$_.ValueInUse -eq 1 }).Count
        foreach ($c in $res.Config) { $sqlconfig.Add([pscustomobject]@{ Instance=$connTarget; Setting=$c.Setting; ValueInUse=$c.ValueInUse }) }
        return $true
    }

    foreach ($instName in $instMap.Keys) {
        try {
            $internalId = $instMap[$instName]
            $svcName = if ($instName -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { "MSSQL`$$instName" }
            $connTarget = if ($instName -eq 'MSSQLSERVER') { $env:COMPUTERNAME } else { "$env:COMPUTERNAME\$instName" }
            $ver = ''; $edition = ''; $binRoot = ''
            try {
                $setup = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$internalId\Setup"
                $ver = Get-RegistryValueSafe -Path $setup -Name 'Version'
                $edition = Get-RegistryValueSafe -Path $setup -Name 'Edition'
                # BinaryPath feeds the CriticalPaths dataset (RiskEngine.Build-CriticalPaths).
                $binRoot = Get-RegistryValueSafe -Path $setup -Name 'SQLBinRoot'
            } catch { }
            $acct = Get-SqlServiceAccount -Context $Context -ServiceName $svcName
            $row = [pscustomobject]@{
                InstanceName=$connTarget; ServiceName=$svcName; Version=$ver; Edition=$edition
                ServiceAccount=$acct; InternalId=$internalId; DeepQueryPerformed=$false; BinaryPath=$binRoot
                IsExpress=([bool]($svcName -match '(?i)SQLEXPRESS' -or $edition -match '(?i)Express')); IsWindowsInternalDatabase=$false; XpCmdShellEnabled=$false
                HostLogicalProcessors=$hostLogicalProcessors
            }

            $row.DeepQueryPerformed = (& $deepQuery $row $connTarget)
            Add-DependencyEdge -Context $Context -SourceType 'SQL Instance' -SourceName $connTarget -DependencyType 'RunsAs' -Target $acct -Evidence 'SQL service account' -Confidence 'Confirmed' -SourceDataset 'SqlInstances' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Who owns the SQL service account?' | Out-Null
            $instances.Add($row)
        } catch { }
    }

    # Service-based detection for anything the registry did not yield. Additive, not a
    # fallback-only path: WID (WSUS, AD FS, RDS broker) has no registry entry and must still
    # be reported on a box that also runs a real SQL instance.
    $knownSvc = @($instances | ForEach-Object { $_.ServiceName })
    if ($true) {
        try {
            foreach ($s in (Invoke-CimSafe -ClassName 'Win32_Service' -Filter "Name LIKE 'MSSQL%'")) {
                if ($s.Name -match '^MSSQL(SERVER|\$)' -and $s.Name -notin $knownSvc) {
                    # Service-based fallback: derive the binary directory from the service image path.
                    $fbBin = ''
                    try {
                        if ($s.PathName) {
                            $m = [regex]::Match([string]$s.PathName, '^"?([^"]+\.exe)')
                            if ($m.Success) { $fbBin = Split-Path -Parent $m.Groups[1].Value }
                        }
                    } catch { }
                    # Windows Internal Database (WSUS, AD FS, ...) has no Instance Names registry key and
                    # is reachable only over its named pipe.
                    $isWid = [bool]($s.Name -match '(?i)MICROSOFT##WID|MICROSOFT\$WID')
                    $fbTarget = if ($isWid) { 'np:\\.\pipe\MICROSOFT##WID\tsql\query' } elseif ($s.Name -eq 'MSSQLSERVER') { $env:COMPUTERNAME } else { "$env:COMPUTERNAME\" + ($s.Name -replace '^MSSQL\$','') }
                    $fbRow = [pscustomobject]@{ InstanceName=$s.Name; ServiceName=$s.Name; Version=''; Edition=''; ServiceAccount=$s.StartName; InternalId=''; DeepQueryPerformed=$false; BinaryPath=$fbBin; IsExpress=([bool]($s.Name -match '(?i)SQLEXPRESS')); IsWindowsInternalDatabase=$isWid; XpCmdShellEnabled=$false; HostLogicalProcessors=$hostLogicalProcessors }
                    $fbRow.DeepQueryPerformed = (& $deepQuery $fbRow $fbTarget)
                    $instances.Add($fbRow)
                }
            }
        } catch { }
    }

    # ---- Other database engines ----
    try {
        $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
        $appRows = @(if ($Context.DataSets.Contains('InstalledApplications')) { @($Context.DataSets['InstalledApplications'].Rows) } else { @() })
        $engines = @(
            @{ Engine='MySQL/MariaDB'; Pattern='(?i)mysql|mariadb' },
            @{ Engine='PostgreSQL'; Pattern='(?i)postgres' },
            @{ Engine='Oracle'; Pattern='(?i)oracle' },
            @{ Engine='Firebird'; Pattern='(?i)firebird' },
            @{ Engine='MongoDB'; Pattern='(?i)mongodb' },
            @{ Engine='Pervasive/Actian Zen'; Pattern='(?i)pervasive|actian|zen psql|btrieve' },
            @{ Engine='Informix'; Pattern='(?i)informix' }
        )
        foreach ($e in $engines) {
            $svcHit = @($svcRows | Where-Object { $_.DisplayName -match $e.Pattern -or $_.Name -match $e.Pattern })
            $appHit = @($appRows | Where-Object { $_.DisplayName -match $e.Pattern })
            if ($svcHit.Count -gt 0 -or $appHit.Count -gt 0) {
                $ev = @()
                if ($svcHit.Count) { $ev += ("service:" + $svcHit[0].Name) }
                if ($appHit.Count) { $ev += ("app:" + $appHit[0].DisplayName) }
                $other.Add([pscustomobject]@{ Engine=$e.Engine; Evidence=($ev -join '; '); Confidence='Likely' })
            }
        }
    } catch { }

    # ---- ODBC DSNs ----
    foreach ($scope in @(
        @{ Path='HKLM:\SOFTWARE\ODBC\ODBC.INI'; Bitness='64'; ScopeName='System' },
        @{ Path='HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI'; Bitness='32'; ScopeName='System' }
    )) {
        try {
            if (-not (Test-RegistryPathSafe $scope.Path)) { continue }
            foreach ($k in (Get-ChildItem -LiteralPath $scope.Path -ErrorAction SilentlyContinue)) {
                if ($k.PSChildName -eq 'ODBC Data Sources') { continue }
                try {
                    $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                    $dsns.Add([pscustomobject]@{
                        DsnName=$k.PSChildName; Driver=$p.Driver; Server=$p.Server; Database=($p.Database); Scope=$scope.ScopeName; Bitness=$scope.Bitness
                    })
                    if ($p.Server) { Add-DependencyEdge -Context $Context -SourceType 'ODBC DSN' -SourceName $k.PSChildName -DependencyType 'ConnectsTo' -Target ("{0}/{1}" -f $p.Server, $p.Database) -Evidence 'ODBC DSN' -Confidence 'Confirmed' -SourceDataset 'OdbcDsns' -ProjectImpact 'Data Migration' -ValidationQuestion 'Does this DSN target change after migration?' | Out-Null }
                } catch { }
            }
        } catch { }
    }

    return ,@{ SqlInstances=@($instances); SqlDatabases=@($databases); SqlAgentJobs=@($jobs); SqlLinkedServers=@($linked); SqlLoginsSummary=@($logins); SqlConfiguration=@($sqlconfig); OtherDatabaseEngines=@($other); OdbcDsns=@($dsns) }
}

function Invoke-SqlIntegratedQuery {
    param([string]$Instance)
    $out = [pscustomobject]@{ Success=$false; Error=''; Version=''; Edition=''; Databases=@(); Jobs=@(); Linked=@(); Logins=@(); Config=@() }
    $conn = $null
    try {
        $cs = "Data Source=$Instance;Integrated Security=SSPI;Connect Timeout=5;Application Name=Discover-WindowsServer"
        $conn = New-Object System.Data.SqlClient.SqlConnection $cs
        $conn.Open()
        # Version/edition: the registry read that normally supplies these is absent for WID.
        try {
            $cv = $conn.CreateCommand(); $cv.CommandTimeout = 10; $cv.CommandText = "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(64)) AS v, CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS e"
            $rv = $cv.ExecuteReader(); if ($rv.Read()) { $out.Version = [string]$rv['v']; $out.Edition = [string]$rv['e'] }; $rv.Close()
        } catch { }
        $dbs = [System.Collections.Generic.List[object]]::new()
        $q = "SELECT d.database_id, d.name, d.state_desc, d.recovery_model_desc, d.compatibility_level, d.create_date, suser_sname(d.owner_sid) AS owner FROM sys.databases d"
        $cmd = $conn.CreateCommand(); $cmd.CommandTimeout = 10; $cmd.CommandText = $q
        $rdr = $cmd.ExecuteReader()
        $ids = @{}; $dbId = @{}; $backupKnown = $false
        while ($rdr.Read()) {
            $row = [pscustomobject]@{ Name=$rdr['name']; State=$rdr['state_desc']; RecoveryModel=$rdr['recovery_model_desc']; CompatLevel=$rdr['compatibility_level']; CreateDate=(Normalize-DateTime $rdr['create_date']); Owner=$rdr['owner']; SizeGB=$null; LastBackup=$null; NoFullBackup=$false }
            $dbId[[string]$rdr['name']] = [int]$rdr['database_id']
            $ids[[string]$rdr['name']] = $row; $dbs.Add($row)
        }
        $rdr.Close()
        # Size and last full backup are separate queries so a permissions failure on one
        # (msdb is the usual culprit) cannot discard the database list.
        try {
            $cs2 = $conn.CreateCommand(); $cs2.CommandTimeout = 10; $cs2.CommandText = "SELECT DB_NAME(database_id) AS n, CAST(SUM(size) * 8.0 / 1048576 AS decimal(18,2)) AS gb FROM sys.master_files GROUP BY database_id"
            $r6 = $cs2.ExecuteReader(); while ($r6.Read()) { if ($ids.ContainsKey([string]$r6['n'])) { $ids[[string]$r6['n']].SizeGB = [double]$r6['gb'] } }; $r6.Close()
        } catch { }
        try {
            $cb = $conn.CreateCommand(); $cb.CommandTimeout = 10; $cb.CommandText = "SELECT database_name AS n, MAX(backup_finish_date) AS f FROM msdb.dbo.backupset WHERE type = 'D' GROUP BY database_name"
            $r7 = $cb.ExecuteReader(); while ($r7.Read()) { if ($ids.ContainsKey([string]$r7['n'])) { $ids[[string]$r7['n']].LastBackup = (Normalize-DateTime $r7['f']) } }; $r7.Close()
            $backupKnown = $true
        } catch { }
        # Only claim "never backed up" when the msdb read actually succeeded; ids <= 4 are system databases.
        if ($backupKnown) { foreach ($k in $ids.Keys) { if ($dbId[$k] -gt 4 -and -not $ids[$k].LastBackup) { $ids[$k].NoFullBackup = $true } } }
        $out.Databases = @($dbs)

        # Logins (names only, no hashes)
        try {
            $lg = [System.Collections.Generic.List[object]]::new()
            $cmd2 = $conn.CreateCommand(); $cmd2.CommandTimeout=10; $cmd2.CommandText = "SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%'"
            $r2 = $cmd2.ExecuteReader(); while ($r2.Read()) { $lg.Add([pscustomobject]@{ LoginName=$r2['name']; Type=$r2['type_desc'] }) } ; $r2.Close()
            $out.Logins = @($lg)
        } catch { }
        # Linked servers
        try {
            $ls = [System.Collections.Generic.List[object]]::new()
            $cmd3 = $conn.CreateCommand(); $cmd3.CommandTimeout=10; $cmd3.CommandText = "SELECT name, product, data_source FROM sys.servers WHERE is_linked = 1"
            $r3 = $cmd3.ExecuteReader(); while ($r3.Read()) { $ls.Add([pscustomobject]@{ Name=$r3['name']; Product=$r3['product']; DataSource=$r3['data_source'] }) } ; $r3.Close()
            $out.Linked = @($ls)
        } catch { }
        # Agent jobs (names/enabled)
        try {
            $jb = [System.Collections.Generic.List[object]]::new()
            $cmd4 = $conn.CreateCommand(); $cmd4.CommandTimeout=10; $cmd4.CommandText = "SELECT name, enabled FROM msdb.dbo.sysjobs"
            $r4 = $cmd4.ExecuteReader(); while ($r4.Read()) { $jb.Add([pscustomobject]@{ JobName=$r4['name']; Enabled=$r4['enabled'] }) } ; $r4.Close()
            $out.Jobs = @($jb)
        } catch { }
        # Key configuration values (safe read from sys.configurations)
        try {
            $cf = [System.Collections.Generic.List[object]]::new()
            $cmd5 = $conn.CreateCommand(); $cmd5.CommandTimeout=10; $cmd5.CommandText = "SELECT name, CAST(value_in_use AS bigint) AS v FROM sys.configurations WHERE name IN ('max server memory (MB)','min server memory (MB)','max degree of parallelism','cost threshold for parallelism','clr enabled','xp_cmdshell','remote access','backup compression default')"
            $r5 = $cmd5.ExecuteReader(); while ($r5.Read()) { $cf.Add([pscustomobject]@{ Setting=$r5['name']; ValueInUse=$r5['v'] }) } ; $r5.Close()
            $out.Config = @($cf)
        } catch { }

        $out.Success = $true
    } catch {
        $out.Error = $_.Exception.Message
    } finally {
        if ($conn) { try { $conn.Close(); $conn.Dispose() } catch { } }
    }
    return $out
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'SqlInstances'        -Description 'Detected SQL Server instances.'         -Rows (& $get 'SqlInstances')        -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlDatabases'        -Description 'Databases (integrated-auth enumeration).'-Rows (& $get 'SqlDatabases')        -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlAgentJobs'        -Description 'SQL Agent jobs.'                        -Rows (& $get 'SqlAgentJobs')        -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlLinkedServers'    -Description 'SQL linked servers.'                    -Rows (& $get 'SqlLinkedServers')    -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlLoginsSummary'    -Description 'SQL login names (no hashes).'           -Rows (& $get 'SqlLoginsSummary')    -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlConfiguration'    -Description 'Key SQL configuration values (integrated-auth).' -Rows (& $get 'SqlConfiguration') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'OtherDatabaseEngines'-Description 'Non-Microsoft database engines.'        -Rows (& $get 'OtherDatabaseEngines')-Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'OdbcDsns'            -Description 'System ODBC DSNs (32/64-bit).'          -Rows (& $get 'OdbcDsns')            -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('SqlInstances') -and @($Context.DataSets['SqlInstances'].Rows).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'Databases' -Module 'SQL' -Audience 'Both' -Question 'Which applications depend on each SQL instance, who is the DBA/owner, and is there a documented backup and recovery process?' | Out-Null
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Invoke-SqlIntegratedQuery','Get-SqlServiceAccount'
