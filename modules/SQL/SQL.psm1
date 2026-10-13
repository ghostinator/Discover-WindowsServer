<#
    SQL.psm1 - SQL Server detection, optional integrated-auth enumeration, other
    database engines, and ODBC DSNs/drivers (read-only).
    Produces: SqlInstances, SqlServices, SqlComponents, SqlServerSummary, SqlDatabases,
              SqlDatabaseFiles, SqlAgentJobs, SqlLinkedServers, SqlLoginsSummary,
              SqlConfiguration, OtherDatabaseEngines, OdbcDsns, OdbcDrivers.
    Deep query happens ONLY with -AttemptSqlIntegratedAuth (local Windows integrated auth,
    5-second connect timeout, SELECT-only); login names only (no hashes). No SQL setting is
    ever changed and no SQL credential is ever accepted or stored.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='SQL'; DisplayName='SQL Server, Databases & ODBC'; Category='Database'; Version='1.1.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('SqlInstances','SqlServices','SqlComponents','SqlServerSummary','SqlDatabases','SqlDatabaseFiles','SqlAgentJobs','SqlLinkedServers','SqlLoginsSummary','SqlConfiguration','OtherDatabaseEngines','OdbcDsns','OdbcDrivers')
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

function Get-SqlVersionInfo {
    <#
        Pure: maps a SQL build (15.0.4153.1) to its product name and Microsoft extended-support end
        date. IsUnsupported compares against today, so it stays correct as dates pass. An unknown
        major version is reported as unknown, never as supported.
    #>
    param([string]$Version, [datetime]$AsOf = (Get-Date))
    $out = [pscustomobject]@{ ProductName=''; MajorVersion=$null; ExtendedSupportEnd=''; IsUnsupported=$false }
    if ([string]::IsNullOrWhiteSpace($Version)) { return $out }
    $parts = $Version.Split('.')
    $major = 0; if (-not [int]::TryParse($parts[0], [ref]$major)) { return $out }
    $minor = 0; if ($parts.Count -gt 1) { [void][int]::TryParse($parts[1], [ref]$minor) }
    $out.MajorVersion = $major
    $map = @{
        8 = @('SQL Server 2000','2013-04-09'); 9 = @('SQL Server 2005','2016-04-12'); 11 = @('SQL Server 2012','2022-07-12')
        12 = @('SQL Server 2014','2024-07-09'); 13 = @('SQL Server 2016','2026-07-14'); 14 = @('SQL Server 2017','2027-10-12')
        15 = @('SQL Server 2019','2030-01-08'); 16 = @('SQL Server 2022','2033-01-11'); 17 = @('SQL Server 2025','')
    }
    $entry = $null
    if ($major -eq 10) { $entry = @(if ($minor -ge 50) { 'SQL Server 2008 R2','2019-07-09' } else { 'SQL Server 2008','2019-07-09' }) }
    elseif ($map.ContainsKey($major)) { $entry = $map[$major] }
    if ($entry) {
        $out.ProductName = $entry[0]; $out.ExtendedSupportEnd = $entry[1]
        if ($entry[1]) { $out.IsUnsupported = ([datetime]$entry[1] -lt $AsOf) }
    }
    return $out
}

function Get-SqlAccountType {
    <# Pure: classifies a service logon account. Built-in and virtual accounts do not exist on a target server and cannot hold network permissions the same way. #>
    param([string]$Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return 'Unknown' }
    $a = $Account.Trim()
    if ($a -match '(?i)^(LocalSystem|NT AUTHORITY\\SYSTEM|\.\\LocalSystem)$') { return 'LocalSystem' }
    if ($a -match '(?i)NetworkService|NT AUTHORITY\\NETWORK ?SERVICE') { return 'NetworkService' }
    if ($a -match '(?i)LocalService|NT AUTHORITY\\LOCAL ?SERVICE') { return 'LocalService' }
    if ($a -match '(?i)^NT SERVICE\\') { return 'VirtualAccount' }
    if ($a -match '\$$') { return 'ManagedServiceAccount' }
    if ($a -match '^\.\\' -or $a -match ('(?i)^' + [regex]::Escape($env:COMPUTERNAME) + '\\')) { return 'LocalAccount' }
    if ($a -match '\\|@') { return 'DomainAccount' }
    return 'Unknown'
}

function Get-SqlServiceRole {
    <# Pure: role + instance for a SQL-related service name, or $null for anything else. #>
    param([string]$Name)
    $rules = @(
        @{ Rx='^(MSSQLSERVER)$|^MSSQL\$(.+)$';                Role='Database Engine' }
        @{ Rx='^(SQLSERVERAGENT)$|^SQLAgent\$(.+)$';          Role='SQL Agent' }
        @{ Rx='^(SQLBrowser)$';                               Role='SQL Browser' }
        @{ Rx='^(MSSQLFDLauncher)$|^MSSQLFDLauncher\$(.+)$';  Role='Full-Text' }
        @{ Rx='^(SQLWriter)$';                                Role='VSS Writer' }
        @{ Rx='^(MsDtsServer\d*)$';                           Role='Integration Services' }
        @{ Rx='^(ReportServer)$|^ReportServer\$(.+)$|^(SQLServerReportingServices|PowerBIReportServer)$'; Role='Reporting Services' }
        @{ Rx='^(MSSQLServerOLAPService)$|^MSOLAP\$(.+)$';    Role='Analysis Services' }
        @{ Rx='^(MSSQLLaunchpad)$|^MSSQLLaunchpad\$(.+)$';    Role='Launchpad' }
        @{ Rx='^(SQLTELEMETRY|SSISTELEMETRY\d*|SSASTELEMETRY)$|^SQLTELEMETRY\$(.+)$'; Role='Telemetry' }
    )
    foreach ($r in $rules) {
        $m = [regex]::Match([string]$Name, $r.Rx, 'IgnoreCase')
        if ($m.Success) {
            $inst = 'MSSQLSERVER'
            foreach ($g in @($m.Groups | Select-Object -Skip 1)) { if ($g.Success -and $g.Value -and $g.Value -notmatch '(?i)^(MSSQLSERVER|SQLSERVERAGENT|SQLBrowser|MSSQLFDLauncher|SQLWriter|MsDtsServer\d*|ReportServer|SQLServerReportingServices|PowerBIReportServer|MSSQLServerOLAPService|MSSQLLaunchpad|SQLTELEMETRY|SSISTELEMETRY\d*|SSASTELEMETRY)$') { $inst = $g.Value } }
            if ($r.Role -in @('SQL Browser','VSS Writer','Integration Services')) { $inst = '(shared)' }
            return [pscustomobject]@{ Role=$r.Role; Instance=$inst }
        }
    }
    return $null
}

# Evidence-based instance classification. Pattern = instance-name signal; Confirm = a service or
# installed application that independently corroborates it (name + corroboration = Confirmed).
$script:SqlClassificationRules = @(
    @{ Label='Backup Exec catalog';   Pattern='(?i)^BKUPEXEC';                  Confirm='(?i)Backup Exec' }
    @{ Label='Sage / Timberline';     Pattern='(?i)SAGE|TIMBERLINE|^STO\b';     Confirm='(?i)\bSage\b|Timberline' }
    @{ Label='Veeam';                 Pattern='(?i)VEEAM';                      Confirm='(?i)Veeam' }
    @{ Label='Sophos';                Pattern='(?i)SOPHOS';                     Confirm='(?i)Sophos' }
    @{ Label='SolarWinds';            Pattern='(?i)SOLARWINDS|ORION';           Confirm='(?i)SolarWinds' }
    @{ Label='VMware vCenter';        Pattern='(?i)VIM_SQLEXP|VCENTER';         Confirm='(?i)VMware vCenter' }
)

function Get-SqlInstanceClassification {
    <#
        Pure-ish (no system calls): Confirmed / Likely / Possible / Unknown classification of an instance,
        with the evidence that produced it. Never guesses from version numbers.
    #>
    param([string]$InstanceName, [string]$Edition, [bool]$IsWid, [object[]]$ServiceRows = @(), [object[]]$AppRows = @())
    $short = ([string]$InstanceName -split '\\')[-1] -replace '^MSSQL\$',''
    if ($IsWid) { return [pscustomobject]@{ Classification='Windows Internal Database'; Confidence='Confirmed'; Evidence='Service name MICROSOFT##WID' } }
    foreach ($r in $script:SqlClassificationRules) {
        if ($short -match $r.Pattern) {
            $corro = @($ServiceRows | Where-Object { $_.DisplayName -match $r.Confirm -or $_.Name -match $r.Confirm } | Select-Object -First 1)
            if (-not $corro) { $corro = @($AppRows | Where-Object { $_.DisplayName -match $r.Confirm } | Select-Object -First 1) }
            if ($corro) { return [pscustomobject]@{ Classification=$r.Label; Confidence='Confirmed'; Evidence=("instance name '{0}' + {1}" -f $short, [string]$corro[0].DisplayName) } }
            return [pscustomobject]@{ Classification=$r.Label; Confidence='Likely'; Evidence=("instance name '{0}'" -f $short) }
        }
    }
    if ($Edition -match '(?i)Express') { return [pscustomobject]@{ Classification='Express (application-bundled likely)'; Confidence='Likely'; Evidence=("edition '{0}'" -f $Edition) } }
    if ($short -match '(?i)^SQLEXPRESS') { return [pscustomobject]@{ Classification='Express (application-bundled likely)'; Confidence='Possible'; Evidence='instance name SQLEXPRESS (edition not read)' } }
    if ($short -and $short -notin @('MSSQLSERVER', $env:COMPUTERNAME)) { return [pscustomobject]@{ Classification='Application-specific named instance'; Confidence='Possible'; Evidence=("named instance '{0}'" -f $short) } }
    return [pscustomobject]@{ Classification='General-purpose / unknown'; Confidence='Unknown'; Evidence='default instance; no application signal' }
}

function Get-SqlRegistryInstanceDetail {
    <# Per-instance registry facts that need no SQL connection: ports, cluster membership, patch level. #>
    param([string]$InternalId)
    $base = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InternalId"
    $tcp = "$base\MSSQLServer\SuperSocketNetLib\Tcp"
    $port = [string](Get-RegistryValueSafe -Path "$tcp\IPAll" -Name 'TcpPort')
    $dyn  = [string](Get-RegistryValueSafe -Path "$tcp\IPAll" -Name 'TcpDynamicPorts')
    $en   = Get-RegistryValueSafe -Path $tcp -Name 'Enabled'
    $clusterName = Get-RegistryValueSafe -Path "$base\Cluster" -Name 'ClusterName'
    [pscustomobject]@{
        TcpPort=$port; TcpDynamicPorts=$dyn
        TcpEnabled=$(if ($null -eq $en) { $null } else { [bool]([int]$en -eq 1) })
        UsesDynamicPort=[bool]($dyn -and $dyn -ne '0' -and -not $port)
        IsClustered=[bool]$clusterName
        PatchLevel=[string](Get-RegistryValueSafe -Path "$base\Setup" -Name 'PatchLevel')
    }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $instances = [System.Collections.Generic.List[object]]::new()
    $databases = [System.Collections.Generic.List[object]]::new()
    $dbFiles = [System.Collections.Generic.List[object]]::new()
    $jobs = [System.Collections.Generic.List[object]]::new()
    $linked = [System.Collections.Generic.List[object]]::new()
    $logins = [System.Collections.Generic.List[object]]::new()
    $sqlconfig = [System.Collections.Generic.List[object]]::new()
    $other = [System.Collections.Generic.List[object]]::new()
    $dsns = [System.Collections.Generic.List[object]]::new()
    $drivers = [System.Collections.Generic.List[object]]::new()
    $sqlServices = [System.Collections.Generic.List[object]]::new()
    $components = [System.Collections.Generic.List[object]]::new()
    $attempt = ([bool]$Context.Parameters['AttemptSqlIntegratedAuth'])

    # Shared source data, read once.
    $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
    $appRows = @(if ($Context.DataSets.Contains('InstalledApplications')) { @($Context.DataSets['InstalledApplications'].Rows) } else { @() })
    $portRows = @(if ($Context.DataSets.Contains('ListeningPorts')) { @($Context.DataSets['ListeningPorts'].Rows) } else { @() })

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

    # ---- SQL-related Windows services (engine, agent, browser, full-text, VSS writer, ...) ----
    try {
        $svcSource = @(if ($svcRows.Count -gt 0) { $svcRows } else { @(Invoke-CimSafe -ClassName 'Win32_Service' | ForEach-Object { [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; Status=$_.State; StartMode=$_.StartMode; StartName=$_.StartName; ExecutablePath=[string]$_.PathName } }) })
        foreach ($s in $svcSource) {
            $role = Get-SqlServiceRole -Name ([string]$s.Name)
            if (-not $role) { continue }
            $sqlServices.Add([pscustomobject]@{
                Name=$s.Name; DisplayName=$s.DisplayName; Role=$role.Role; Instance=$role.Instance
                Status=[string]$s.Status; StartMode=[string]$s.StartMode; StartName=[string]$s.StartName
                AccountType=(Get-SqlAccountType -Account ([string]$s.StartName)); ExecutablePath=[string]$s.ExecutablePath
            })
        }
    } catch { Add-Limitation -Context $Context -Module 'SQL' -Message 'SQL service enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    $svcByName = @{}; foreach ($s in $sqlServices) { $svcByName[[string]$s.Name] = $s }

    # ---- Installed SQL components (client tools, native clients, ODBC drivers, ...) ----
    try {
        foreach ($a in @($appRows | Where-Object { $_.DisplayName -match '(?i)SQL Server|SQL Native Client|ODBC Driver \d+ for SQL|OLE DB Driver.*SQL' })) {
            $components.Add([pscustomobject]@{ DisplayName=$a.DisplayName; DisplayVersion=$a.DisplayVersion; Publisher=$a.Publisher; Architecture=$a.ArchitectureHint })
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

    # Enrichment shared by both detection paths: service state, agent state, version support,
    # account type, classification, observed listening ports.
    $enrich = {
        param($row, $shortName)
        $svc = $svcByName[[string]$row.ServiceName]
        $row.ServiceState = if ($svc) { $svc.Status } else { '' }
        $row.ServiceStartMode = if ($svc) { $svc.StartMode } else { '' }
        $row.ServiceAccountType = Get-SqlAccountType -Account ([string]$row.ServiceAccount)
        $agentName = if ($shortName -eq 'MSSQLSERVER') { 'SQLSERVERAGENT' } else { "SQLAgent`$$shortName" }
        $agent = $svcByName[$agentName]
        $row.AgentServiceName = if ($agent) { $agentName } else { '' }
        $row.AgentState = if ($agent) { $agent.Status } else { 'NotInstalled' }
        $row.AgentStartMode = if ($agent) { $agent.StartMode } else { '' }
        $row.AgentDisabled = [bool]($agent -and ($agent.StartMode -match '(?i)Disabled' -or ($agent.StartMode -match '(?i)Manual' -and $agent.Status -ne 'Running')))
        $vi = Get-SqlVersionInfo -Version ([string]$row.Version)
        $row.ProductName = $vi.ProductName; $row.MajorVersion = $vi.MajorVersion; $row.ExtendedSupportEnd = $vi.ExtendedSupportEnd
        # WID is serviced with Windows, not on the SQL Server lifecycle.
        $row.IsUnsupportedVersion = [bool]($vi.IsUnsupported -and -not $row.IsWindowsInternalDatabase)
        $cl = Get-SqlInstanceClassification -InstanceName ([string]$row.InstanceName) -Edition ([string]$row.Edition) -IsWid ([bool]$row.IsWindowsInternalDatabase) -ServiceRows $svcRows -AppRows $appRows
        $row.Classification = $cl.Classification; $row.ClassificationConfidence = $cl.Confidence; $row.ClassificationEvidence = $cl.Evidence
        $row.ListeningPortsObserved = ((@($portRows | Where-Object { $_.ServiceName -eq $row.ServiceName -and $_.Protocol -ne 'UDP' } | ForEach-Object { [string]$_.LocalPort }) | Select-Object -Unique) -join ', ')
    }

    $newRow = {
        param($instanceName, $serviceName, $ver, $edition, $acct, $internalId, $binRoot, $isExpress, $isWid)
        [pscustomobject]@{
            InstanceName=$instanceName; ServiceName=$serviceName; Version=$ver; Edition=$edition
            ServiceAccount=$acct; InternalId=$internalId; DeepQueryPerformed=$false; BinaryPath=$binRoot
            IsExpress=$isExpress; IsWindowsInternalDatabase=$isWid; XpCmdShellEnabled=$false
            HostLogicalProcessors=$hostLogicalProcessors
            ProductName=''; MajorVersion=$null; ProductLevel=''; PatchLevel=''; ExtendedSupportEnd=''; IsUnsupportedVersion=$false
            IsClustered=$false; TcpEnabled=$null; TcpPort=''; TcpDynamicPorts=''; UsesDynamicPort=$false; ListeningPortsObserved=''
            ServiceState=''; ServiceStartMode=''; ServiceAccountType=''
            AgentServiceName=''; AgentState=''; AgentStartMode=''; AgentDisabled=$false
            Classification=''; ClassificationConfidence=''; ClassificationEvidence=''
            ConnectionStatus='NotAttempted'; ConnectionError=''; DatabaseCount=$null; TotalDatabaseSizeGB=$null
        }
    }

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
            $row.ConnectionStatus = 'Failed'; $row.ConnectionError = [string]$res.Error
            Add-Limitation -Context $Context -Module 'SQL' -Message ("Integrated-auth query to '{0}' failed." -f $connTarget) -Reason $res.Error | Out-Null
            Add-Unknown -Context $Context -Unknown ("SQL instance '{0}' detected but database enumeration failed." -f $connTarget) -WhyItMatters 'Database inventory, sizes, and backup status remain unknown.' -Module 'SQL' -RecommendedValidationQuestion 'Can a DBA provide the database inventory and backup status?' | Out-Null
            return $false
        }
        $row.ConnectionStatus = 'Connected'
        if (-not $row.Version) { $row.Version = $res.Version }
        if (-not $row.Edition) { $row.Edition = $res.Edition; if ($res.Edition -match '(?i)Express') { $row.IsExpress = $true } }
        $row.ProductLevel = $res.ProductLevel
        if ($res.IsClustered) { $row.IsClustered = $true }
        # Tag rows with their instance: with two instances (e.g. SQLEXPRESS + WID) every 'master' looks alike.
        # WID databases (SUSDB, RDCms, ...) are role-managed; "no SQL backup" there is not a DBA gap.
        if ($row.IsWindowsInternalDatabase) { foreach ($d in $res.Databases) { $d.NoFullBackup = $false } }
        foreach ($d in $res.Databases) { $d | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $databases.Add($d) }
        foreach ($f in $res.Files) { $f | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $dbFiles.Add($f) }
        foreach ($j in $res.Jobs) { $j | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $jobs.Add($j) }
        foreach ($l in $res.Linked) { $l | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $linked.Add($l) }
        foreach ($g in $res.Logins) { $g | Add-Member -NotePropertyName Instance -NotePropertyValue $row.InstanceName -Force; $logins.Add($g) }
        $row.XpCmdShellEnabled = [bool]@($res.Config | Where-Object { $_.Setting -eq 'xp_cmdshell' -and [int64]$_.ValueInUse -eq 1 }).Count
        foreach ($c in $res.Config) { $sqlconfig.Add([pscustomobject]@{ Instance=$connTarget; Setting=$c.Setting; ValueInUse=$c.ValueInUse }) }
        $row.DatabaseCount = @($res.Databases).Count
        $sz = (@($res.Databases) | Where-Object { $null -ne $_.SizeGB } | Measure-Object -Property SizeGB -Sum).Sum
        if ($null -ne $sz) { $row.TotalDatabaseSizeGB = [math]::Round([double]$sz, 2) }
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
            $row = & $newRow $connTarget $svcName $ver $edition $acct $internalId $binRoot ([bool]($svcName -match '(?i)SQLEXPRESS' -or $edition -match '(?i)Express')) $false
            try {
                $rd = Get-SqlRegistryInstanceDetail -InternalId $internalId
                $row.TcpPort = $rd.TcpPort; $row.TcpDynamicPorts = $rd.TcpDynamicPorts; $row.TcpEnabled = $rd.TcpEnabled
                $row.UsesDynamicPort = $rd.UsesDynamicPort; $row.IsClustered = $rd.IsClustered; $row.PatchLevel = $rd.PatchLevel
            } catch { }
            $row.DeepQueryPerformed = (& $deepQuery $row $connTarget)
            & $enrich $row $instName
            Add-DependencyEdge -Context $Context -SourceType 'SQL Instance' -SourceName $connTarget -DependencyType 'RunsAs' -Target $acct -Evidence 'SQL service account' -Confidence 'Confirmed' -SourceDataset 'SqlInstances' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Who owns the SQL service account?' | Out-Null
            $instances.Add($row)
        } catch { }
    }

    # Service-based detection for anything the registry did not yield. Additive, not a
    # fallback-only path: WID (WSUS, AD FS, RDS broker) has no registry entry and must still
    # be reported on a box that also runs a real SQL instance.
    $knownSvc = @($instances | ForEach-Object { $_.ServiceName })
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
                $fbRow = & $newRow $s.Name $s.Name '' '' $s.StartName '' $fbBin ([bool]($s.Name -match '(?i)SQLEXPRESS')) $isWid
                $fbRow.DeepQueryPerformed = (& $deepQuery $fbRow $fbTarget)
                & $enrich $fbRow ($(if ($s.Name -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { $s.Name -replace '^MSSQL\$','' }))
                $instances.Add($fbRow)
            }
        }
    } catch { }

    # ---- Server-level summary: the migration-readiness facts that span instances ----
    $summary = @()
    $real = @($instances | Where-Object { -not $_.IsWindowsInternalDatabase })
    if ($real.Count -gt 0) {
        $versions = @($real | Where-Object { $_.ProductName } | ForEach-Object { $_.ProductName } | Select-Object -Unique)
        $appInst = @($real | Where-Object { $_.Classification -notin @('General-purpose / unknown','') })
        $browser = @($sqlServices | Where-Object { $_.Role -eq 'SQL Browser' } | Select-Object -First 1)
        $writer = @($sqlServices | Where-Object { $_.Role -eq 'VSS Writer' } | Select-Object -First 1)
        $sized = @($real | Where-Object { $null -ne $_.TotalDatabaseSizeGB })
        $summary = @([pscustomobject]@{
            SqlInstanceCount=$real.Count
            ProductVersions=($versions -join ', ')
            MultipleSqlVersions=[bool]($versions.Count -gt 1)
            ApplicationInstanceCount=$appInst.Count
            MultipleApplicationInstances=[bool]($appInst.Count -gt 1)
            InstancesNotEnumerated=@($real | Where-Object { $_.ConnectionStatus -ne 'Connected' }).Count
            DatabasesEnumerated=[bool](@($real | Where-Object { $_.ConnectionStatus -eq 'Connected' }).Count -gt 0)
            TotalDatabaseSizeGB=$(if ($sized.Count -gt 0) { [math]::Round([double](($sized | Measure-Object -Property TotalDatabaseSizeGB -Sum).Sum), 2) } else { $null })
            AnyUnsupportedVersion=[bool](@($real | Where-Object { $_.IsUnsupportedVersion }).Count -gt 0)
            AnyAgentDisabled=[bool](@($real | Where-Object { $_.AgentDisabled }).Count -gt 0)
            AnyBuiltInServiceAccount=[bool](@($real | Where-Object { $_.ServiceAccountType -in @('LocalSystem','NetworkService','LocalService','VirtualAccount') }).Count -gt 0)
            AnyDomainServiceAccount=[bool](@($real | Where-Object { $_.ServiceAccountType -in @('DomainAccount','ManagedServiceAccount') }).Count -gt 0)
            BrowserState=$(if ($browser) { "{0}/{1}" -f $browser[0].Status, $browser[0].StartMode } else { 'NotInstalled' })
            VssWriterState=$(if ($writer) { "{0}/{1}" -f $writer[0].Status, $writer[0].StartMode } else { 'NotInstalled' })
            DeepQueryRequested=$attempt
        })
    }

    # ---- Other database engines ----
    try {
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

    # ---- ODBC drivers (32/64-bit) ----
    foreach ($scope in @(
        @{ Path='HKLM:\SOFTWARE\ODBC\ODBCINST.INI'; Bitness='64' },
        @{ Path='HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI'; Bitness='32' }
    )) {
        try {
            $listPath = Join-Path $scope.Path 'ODBC Drivers'
            if (-not (Test-RegistryPathSafe $listPath)) { continue }
            $list = Get-ItemProperty -LiteralPath $listPath -ErrorAction SilentlyContinue
            foreach ($prop in @($list.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') })) {
                $dllPath = [string](Get-RegistryValueSafe -Path (Join-Path $scope.Path $prop.Name) -Name 'Driver')
                # 32-bit drivers are registered as System32 paths that WOW64 redirects to SysWOW64.
                $checkPath = if ($scope.Bitness -eq '32') { $dllPath -replace '(?i)\\system32\\', '\SysWOW64\' } else { $dllPath }
                $drivers.Add([pscustomobject]@{ Name=$prop.Name; Bitness=$scope.Bitness; DriverPath=$dllPath; Installed=[string]$prop.Value; FileExists=$(if ($dllPath) { [bool](Test-Path -LiteralPath $checkPath) } else { $null }) })
            }
        } catch { }
    }

    # ---- System ODBC DSNs (user DSNs come from UserProfiles, which reads every loaded user hive) ----
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
                    $rec = ConvertTo-OdbcDsnRecord -DsnName $k.PSChildName -Properties $p -Scope $scope.ScopeName -Bitness $scope.Bitness -Context $Context
                    $dsns.Add($rec)
                    if ($rec.Server -or $rec.DbqOrPath) { Add-DependencyEdge -Context $Context -SourceType 'ODBC DSN' -SourceName $k.PSChildName -DependencyType 'ConnectsTo' -Target ($(if ($rec.Server) { "{0}/{1}" -f $rec.Server, $rec.Database } else { $rec.DbqOrPath })) -Evidence ("ODBC DSN ({0}-bit, {1})" -f $scope.Bitness, $rec.Driver) -Confidence 'Confirmed' -SourceDataset 'OdbcDsns' -ProjectImpact 'Data Migration' -ValidationQuestion 'Does this DSN target change after migration, and does the target have the same driver and bitness?' | Out-Null }
                } catch { }
            }
        } catch { }
    }
    Set-OdbcCrossChecks -Dsns @($dsns) -Drivers @($drivers)

    return ,@{ SqlInstances=@($instances); SqlServices=@($sqlServices); SqlComponents=@($components); SqlServerSummary=@($summary); SqlDatabases=@($databases); SqlDatabaseFiles=@($dbFiles); SqlAgentJobs=@($jobs); SqlLinkedServers=@($linked); SqlLoginsSummary=@($logins); SqlConfiguration=@($sqlconfig); OtherDatabaseEngines=@($other); OdbcDsns=@($dsns); OdbcDrivers=@($drivers) }
}

function Invoke-SqlIntegratedQuery {
    param([string]$Instance)
    $out = [pscustomobject]@{ Success=$false; Error=''; Version=''; Edition=''; ProductLevel=''; IsClustered=$false; Databases=@(); Files=@(); Jobs=@(); Linked=@(); Logins=@(); Config=@() }
    $conn = $null
    try {
        $cs = "Data Source=$Instance;Integrated Security=SSPI;Connect Timeout=5;Application Name=Discover-WindowsServer"
        $conn = New-Object System.Data.SqlClient.SqlConnection $cs
        $conn.Open()
        # Version/edition: the registry read that normally supplies these is absent for WID.
        try {
            $cv = $conn.CreateCommand(); $cv.CommandTimeout = 10; $cv.CommandText = "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(64)) AS v, CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS e, CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(64)) AS l, CAST(SERVERPROPERTY('IsClustered') AS int) AS c"
            $rv = $cv.ExecuteReader(); if ($rv.Read()) { $out.Version = [string]$rv['v']; $out.Edition = [string]$rv['e']; $out.ProductLevel = [string]$rv['l']; try { $out.IsClustered = ([int]$rv['c'] -eq 1) } catch { } }; $rv.Close()
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
        # Data/log file locations (where permitted) - what a target server's volume layout must match.
        try {
            $fl = [System.Collections.Generic.List[object]]::new()
            $cf = $conn.CreateCommand(); $cf.CommandTimeout = 10; $cf.CommandText = "SELECT DB_NAME(database_id) AS n, type_desc AS t, physical_name AS p, CAST(size * 8.0 / 1048576 AS decimal(18,2)) AS gb FROM sys.master_files"
            $r8 = $cf.ExecuteReader(); while ($r8.Read()) { $fl.Add([pscustomobject]@{ Database=[string]$r8['n']; FileType=[string]$r8['t']; PhysicalName=[string]$r8['p']; SizeGB=[double]$r8['gb'] }) }; $r8.Close()
            $out.Files = @($fl)
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
    Add-DataSet -Context $Context -Name 'SqlInstances'        -Description 'Detected SQL Server instances (version support, ports, services, classification, connection status).' -Rows (& $get 'SqlInstances') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlServices'         -Description 'SQL-related Windows services (engine, agent, browser, full-text, VSS writer, SSIS/SSRS/SSAS).' -Rows (& $get 'SqlServices') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlComponents'       -Description 'Installed SQL Server components and client drivers.' -Rows (& $get 'SqlComponents') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlServerSummary'    -Description 'Server-level SQL migration-readiness summary across instances.' -Rows (& $get 'SqlServerSummary') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlDatabases'        -Description 'Databases (integrated-auth enumeration).'-Rows (& $get 'SqlDatabases')        -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlDatabaseFiles'    -Description 'Database data/log file locations (integrated-auth enumeration).' -Rows (& $get 'SqlDatabaseFiles') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlAgentJobs'        -Description 'SQL Agent jobs.'                        -Rows (& $get 'SqlAgentJobs')        -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlLinkedServers'    -Description 'SQL linked servers.'                    -Rows (& $get 'SqlLinkedServers')    -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlLoginsSummary'    -Description 'SQL login names (no hashes).'           -Rows (& $get 'SqlLoginsSummary')    -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'SqlConfiguration'    -Description 'Key SQL configuration values (integrated-auth).' -Rows (& $get 'SqlConfiguration') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'OtherDatabaseEngines'-Description 'Non-Microsoft database engines.'        -Rows (& $get 'OtherDatabaseEngines')-Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'OdbcDsns'            -Description 'System ODBC DSNs (32/64-bit), credentials excluded.' -Rows (& $get 'OdbcDsns') -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
    Add-DataSet -Context $Context -Name 'OdbcDrivers'         -Description 'Registered ODBC drivers (32/64-bit).'   -Rows (& $get 'OdbcDrivers')         -Visibility 'Internal' -SourceModule 'SQL' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('SqlInstances') -and @($Context.DataSets['SqlInstances'].Rows).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'Databases' -Module 'SQL' -Audience 'Both' -Question 'Which applications depend on each SQL instance, who is the DBA/owner, and is there a documented backup and recovery process?' | Out-Null
        }
        if ($Context.DataSets.Contains('OdbcDsns') -and @($Context.DataSets['OdbcDsns'].Rows | Where-Object { $_.DuplicateAcrossBitness -or $_.IsFileBased }).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'Databases' -Module 'SQL' -Audience 'Internal' -Question 'Some ODBC DSNs exist in both 32- and 64-bit views or point at file paths. Which applications use them, and will the target server provide the same driver, bitness and path?' | Out-Null
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Invoke-SqlIntegratedQuery','Get-SqlServiceAccount','Get-SqlVersionInfo','Get-SqlAccountType','Get-SqlServiceRole','Get-SqlInstanceClassification','Get-SqlRegistryInstanceDetail'
