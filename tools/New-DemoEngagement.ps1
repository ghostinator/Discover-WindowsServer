<#
.SYNOPSIS
    Generates a synthetic multi-server "demo fleet" - no real server required - so anyone
    evaluating this toolkit can see real report output (single-server reports, a fleet rollup,
    the client-safe summary, the dependency diagram, the readiness score, and optionally a
    drift comparison) without pointing it at actual infrastructure.

.DESCRIPTION
    Drives the exact same real pipeline tests\Invoke-OutputSmokeTest.ps1 already proves works
    (collection is skipped - synthetic datasets are seeded directly - but every synthesis module,
    every report writer, and the archive step are the real ones), once per canned "persona"
    (a Domain Controller, a SQL Server, a File/Print server, an aging near-EOL server, a Hyper-V
    host), each with richer/more varied data than the smoke test's single-row-per-dataset fixtures
    so the result actually looks populated rather than looking like a regression-test fixture.

    Each persona's run folder is written as a real, complete
    Discover-WindowsServer_<ComputerName>_<timestamp>\ folder - not a temp folder that gets
    cleaned up - so tools\Merge-FleetDiscoveryResults.ps1 and tools\Compare-DiscoveryRuns.ps1 can
    operate on it completely unmodified, with zero awareness the data is synthetic.

    With -TwoSnapshots, a second engagement folder is generated with small, deliberate,
    reproducible differences per persona (a share added, a service's account changed, a new
    scheduled task) so Compare-DiscoveryRuns.ps1's drift detection has real drift to show off too
    - not randomized, so the demo is reproducible run to run.

.PARAMETER OutputFolder
    Where the demo engagement folder(s) are written.

.PARAMETER Personas
    Which personas to generate. Defaults to all five.

.PARAMETER ProjectType
    -ProjectType passed through to every persona's discovery context (affects which findings are
    emphasised). Defaults to GeneralDiscovery (no emphasis bias) so the demo doesn't look tuned
    toward one particular kind of engagement.

.PARAMETER TwoSnapshots
    Also generates a second, slightly-different engagement folder (named with a later timestamp)
    so tools\Compare-DiscoveryRuns.ps1 has something real to compare.

.EXAMPLE
    .\tools\New-DemoEngagement.ps1 -OutputFolder C:\Temp\Demo

.EXAMPLE
    .\tools\New-DemoEngagement.ps1 -OutputFolder C:\Temp\Demo -TwoSnapshots
    # then:
    #   .\tools\Merge-FleetDiscoveryResults.ps1 -EngagementFolder <the newer Fleet_* folder>
    #   .\tools\Compare-DiscoveryRuns.ps1 -BaselineEngagementFolder <older> -CurrentEngagementFolder <newer>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputFolder,
    [ValidateSet('DomainController', 'SqlServer', 'FilePrintServer', 'AgingNearEol', 'HyperVHost')]
    [string[]]$Personas = @('DomainController', 'SqlServer', 'FilePrintServer', 'AgingNearEol', 'HyperVHost'),
    [string]$ProjectType = 'GeneralDiscovery',
    [switch]$TwoSnapshots
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

#region Persona fixtures ---------------------------------------------------------

function Get-DemoServerPersona {
    <#
        Pure: returns one persona's synthetic dataset rows (field names/shapes match the
        real collector schemas - confirmed against tests\Invoke-OutputSmokeTest.ps1's own proven
        fixtures, just with more rows and more variety per dataset so a demo actually looks
        populated). -Overrides replaces specific dataset names wholesale (used for the
        -TwoSnapshots drift pass) rather than merging field-by-field - keeps the diff concrete
        and easy to reason about.
    #>
    param(
        [Parameter(Mandatory)][string]$PersonaName,
        [hashtable]$Overrides = @{}
    )

    $computerName = switch ($PersonaName) {
        'DomainController' { 'DEMO-DC01' }
        'SqlServer'        { 'DEMO-SQL01' }
        'FilePrintServer'  { 'DEMO-FS01' }
        'AgingNearEol'     { 'DEMO-LEGACY01' }
        'HyperVHost'       { 'DEMO-HV01' }
    }

    $datasets = [ordered]@{}
    $edges = [System.Collections.Generic.List[object]]::new()

    switch ($PersonaName) {
        'DomainController' {
            $datasets['ExecutionContext']  = @([pscustomobject]@{ IsAdmin = $true })
            $datasets['OperatingSystem']   = @([pscustomobject]@{ Caption = 'Windows Server 2019 Standard'; BuildNumber = '17763'; IsEndOfLifeOrNear = $false })
            $datasets['PendingReboot']     = @([pscustomobject]@{ RebootPending = $false })
            $datasets['RolesFeatures']     = @(
                [pscustomobject]@{ Name = 'AD-Domain-Services'; DisplayName = 'Active Directory Domain Services'; InstallState = 'Installed' }
                [pscustomobject]@{ Name = 'DNS'; DisplayName = 'DNS Server'; InstallState = 'Installed' }
                [pscustomobject]@{ Name = 'DHCP'; DisplayName = 'DHCP Server'; InstallState = 'Installed' }
            )
            $datasets['DomainContext']     = @([pscustomobject]@{ IsDomainController = $true; HoldsFsmoRole = $true })
            $datasets['Services']          = @(
                [pscustomobject]@{ Name = 'NTDS'; DisplayName = 'Active Directory Domain Services'; StartName = 'LocalSystem'; PathName = 'C:\Windows\System32\ntdsa.dll'; PathExists = $true; UnquotedPathWithSpaces = $false; IsNonMicrosoftAutoStart = $false }
                [pscustomobject]@{ Name = 'DNS'; DisplayName = 'DNS Server'; StartName = 'LocalSystem'; PathName = 'C:\Windows\System32\dns.exe'; PathExists = $true; UnquotedPathWithSpaces = $false; IsNonMicrosoftAutoStart = $false }
            )
            $datasets['ScheduledTasks']    = @(
                [pscustomobject]@{ TaskName = 'ADBackup'; Principal = 'CORP\svc-adbackup'; ActionsText = 'wbadmin start systemstatebackup'; LastTaskResult = 0; UsesUncPath = $false; LastRunFailed = $false; RunsAsDomainAccount = $true }
            )
            $datasets['SecurityPosture']   = @([pscustomobject]@{ Smb1Enabled = $false; RdpEnabledNoNla = $false; AnyAvOrEdrDetected = $true; LocalAdminCount = 3 })
            $datasets['Volumes']           = @([pscustomobject]@{ DriveLetter = 'C'; PercentFree = 42; FreeGB = 210; SizeGB = 500 })
            $datasets['IPConfiguration']   = @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; IPv4Address = '10.0.0.10'; IsStatic = $true })
            $datasets['Licensing']         = @([pscustomobject]@{ Indicator = 'Windows Server Standard - 16 core license'; Evidence = 'registry' })
            $edges.Add((New-DemoEdge 'Server' $computerName 'DNS' '10.0.0.10' 'IPConfiguration'))
            $edges.Add((New-DemoEdge 'ScheduledTask' 'ADBackup' 'RunsAs' 'CORP\svc-adbackup' 'ScheduledTasks'))
        }
        'SqlServer' {
            $datasets['ExecutionContext']  = @([pscustomobject]@{ IsAdmin = $true })
            $datasets['OperatingSystem']   = @([pscustomobject]@{ Caption = 'Windows Server 2019 Standard'; BuildNumber = '17763'; IsEndOfLifeOrNear = $false })
            $datasets['PendingReboot']     = @([pscustomobject]@{ RebootPending = $false })
            $datasets['SqlInstances']      = @(
                [pscustomobject]@{ InstanceName = 'DEMO-SQL01\PROD'; ServiceName = 'MSSQL$PROD'; DeepQueryPerformed = $false; BinaryPath = 'C:\Program Files\Microsoft SQL Server\MSSQL15.PROD\MSSQL\Binn' }
                [pscustomobject]@{ InstanceName = 'DEMO-SQL01\REPORTING'; ServiceName = 'MSSQL$REPORTING'; DeepQueryPerformed = $false; BinaryPath = 'C:\Program Files\Microsoft SQL Server\MSSQL15.REPORTING\MSSQL\Binn' }
            )
            $datasets['OdbcDsns']          = @(
                [pscustomobject]@{ DsnName = 'ERP'; Server = 'DEMO-SQL01\PROD'; Database = 'erp'; Driver = 'SQL Server' }
                [pscustomobject]@{ DsnName = 'Reporting'; Server = 'DEMO-SQL01\REPORTING'; Database = 'reporting'; Driver = 'SQL Server' }
            )
            $datasets['Services']          = @(
                [pscustomobject]@{ Name = 'MSSQL$PROD'; DisplayName = 'SQL Server (PROD)'; StartName = 'CORP\svc-sqlprod'; PathName = 'C:\Program Files\Microsoft SQL Server\MSSQL15.PROD\MSSQL\Binn\sqlservr.exe'; PathExists = $true; UnquotedPathWithSpaces = $false; IsNonMicrosoftAutoStart = $false }
            )
            $datasets['ListeningPorts']    = @([pscustomobject]@{ LocalPort = 1433; Process = 'sqlservr'; ServiceName = 'MSSQL$PROD' })
            $datasets['SecurityPosture']   = @([pscustomobject]@{ Smb1Enabled = $false; RdpEnabledNoNla = $false; AnyAvOrEdrDetected = $true; LocalAdminCount = 4 })
            $datasets['Certificates']      = @([pscustomobject]@{ Subject = 'CN=demo-sql01.corp.local'; NotAfter = '2026-11-15'; Thumbprint = 'AB12CD34'; ExpiringSoon = $true; HasPrivateKey = $true })
            $datasets['Volumes']           = @([pscustomobject]@{ DriveLetter = 'D'; PercentFree = 18; FreeGB = 180; SizeGB = 1000 })
            $datasets['Licensing']         = @([pscustomobject]@{ Indicator = 'SQL Server Standard - core-based licensing'; Evidence = 'registry' })
            $edges.Add((New-DemoEdge 'SQL Instance' 'DEMO-SQL01\PROD' 'RunsAs' 'CORP\svc-sqlprod' 'Services'))
            $edges.Add((New-DemoEdge 'ODBC DSN' 'ERP' 'ConnectsTo' 'DEMO-SQL01\PROD' 'OdbcDsns'))
        }
        'FilePrintServer' {
            $datasets['ExecutionContext']  = @([pscustomobject]@{ IsAdmin = $true })
            $datasets['OperatingSystem']   = @([pscustomobject]@{ Caption = 'Windows Server 2022 Standard'; BuildNumber = '20348'; IsEndOfLifeOrNear = $false })
            $datasets['PendingReboot']     = @([pscustomobject]@{ RebootPending = $false })
            $shareRows = @(
                [pscustomobject]@{ Name = 'Finance'; Path = 'D:\Shares\Finance'; IsUserShare = $true }
                [pscustomobject]@{ Name = 'HR'; Path = 'D:\Shares\HR'; IsUserShare = $true }
                [pscustomobject]@{ Name = 'Public'; Path = 'D:\Shares\Public'; IsUserShare = $true }
                [pscustomobject]@{ Name = 'Engineering'; Path = 'D:\Shares\Engineering'; IsUserShare = $true }
            )
            $datasets['SmbShares']         = if ($Overrides.ContainsKey('SmbShares')) { $Overrides['SmbShares'] } else { $shareRows }
            $datasets['FileShareSummary']  = @([pscustomobject]@{ DeepScanPerformed = $true })
            $datasets['NtfsAclSummary']    = @(
                [pscustomobject]@{ Share = 'Finance'; Path = 'D:\Shares\Finance'; TopLevelFolders = 24; FileCount = 41000; TotalSizeGB = 210; LargeFilesOverThreshold = 2; OldFilesOverYears = 900; RecentlyModified30d = 300; MaxDepthScanned = 3; RecycleBinIncluded = $false; RecycleBinFilesFound = 12; RecycleBinSizeGB = 2 }
                [pscustomobject]@{ Share = 'Engineering'; Path = 'D:\Shares\Engineering'; TopLevelFolders = 58; FileCount = 120000; TotalSizeGB = 890; LargeFilesOverThreshold = 15; OldFilesOverYears = 2200; RecentlyModified30d = 4100; MaxDepthScanned = 3; RecycleBinIncluded = $false; RecycleBinFilesFound = 30; RecycleBinSizeGB = 6 }
            )
            $datasets['Printers']          = @(
                [pscustomobject]@{ Name = 'Finance-Printer'; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.51'; Shared = $true }
                [pscustomobject]@{ Name = 'HR-Printer'; DriverName = 'HP Universal'; PortName = 'IP_10.0.0.52'; Shared = $true }
                [pscustomobject]@{ Name = 'Warehouse-Label'; DriverName = 'Zebra ZPL'; PortName = 'USB001'; Shared = $true }
            )
            $datasets['SecurityPosture']   = @([pscustomobject]@{ Smb1Enabled = $false; RdpEnabledNoNla = $false; AnyAvOrEdrDetected = $true; LocalAdminCount = 3 })
            $datasets['Volumes']           = @([pscustomobject]@{ DriveLetter = 'D'; PercentFree = 22; FreeGB = 440; SizeGB = 2000 })
            $edges.Add((New-DemoEdge 'SmbShare' 'Finance' 'ServesPath' 'D:\Shares\Finance' 'FileShares'))
            $edges.Add((New-DemoEdge 'SmbShare' 'Engineering' 'ServesPath' 'D:\Shares\Engineering' 'FileShares'))
            $edges.Add((New-DemoEdge 'Printer' 'Finance-Printer' 'UsesPort' 'IP_10.0.0.51' 'Printers'))
        }
        'AgingNearEol' {
            $datasets['ExecutionContext']  = @([pscustomobject]@{ IsAdmin = $true })
            $datasets['OperatingSystem']   = @([pscustomobject]@{ Caption = 'Windows Server 2012 R2 Standard'; BuildNumber = '9600'; IsEndOfLifeOrNear = $true })
            $datasets['PendingReboot']     = @([pscustomobject]@{ RebootPending = $true })
            $datasets['SecurityPosture']   = @([pscustomobject]@{ Smb1Enabled = $true; RdpEnabledNoNla = $true; AnyAvOrEdrDetected = $false; LocalAdminCount = 11 })
            $datasets['Services']          = @(
                [pscustomobject]@{ Name = 'LegacyAppSvc'; DisplayName = 'Legacy Line-of-Business App'; StartName = 'CORP\svc-legacy'; PathName = 'C:\LegacyApp\svc.exe'; PathExists = $true; UnquotedPathWithSpaces = $true; IsNonMicrosoftAutoStart = $true }
            )
            $datasets['InstalledApplications'] = @(
                [pscustomobject]@{ DisplayName = 'Legacy ERP 3.2'; Publisher = 'Contoso Software'; InstallLocation = 'C:\LegacyApp'; SystemComponent = $false }
            )
            $datasets['Volumes']           = @([pscustomobject]@{ DriveLetter = 'C'; PercentFree = 3; FreeGB = 6; SizeGB = 200 })
            $datasets['Certificates']      = @([pscustomobject]@{ Subject = 'CN=legacy01.corp.local'; NotAfter = '2026-10-01'; Thumbprint = 'DEAD00BEEF'; ExpiringSoon = $true; HasPrivateKey = $true })
            $datasets['ListeningPorts']    = @([pscustomobject]@{ LocalPort = 8080; Process = 'legacyapp'; ServiceName = 'LegacyAppSvc' })
            $edges.Add((New-DemoEdge 'Service' 'LegacyAppSvc' 'RunsAs' 'CORP\svc-legacy' 'Services'))
        }
        'HyperVHost' {
            $datasets['ExecutionContext']  = @([pscustomobject]@{ IsAdmin = $true })
            $datasets['OperatingSystem']   = @([pscustomobject]@{ Caption = 'Windows Server 2022 Datacenter'; BuildNumber = '20348'; IsEndOfLifeOrNear = $false })
            $datasets['PendingReboot']     = @([pscustomobject]@{ RebootPending = $false })
            $datasets['RolesFeatures']     = @([pscustomobject]@{ Name = 'Hyper-V'; DisplayName = 'Hyper-V'; InstallState = 'Installed' })
            $vmRows = @(
                [pscustomobject]@{ Name = 'VM-App01'; State = 'Running'; Generation = 2; HasCheckpoints = $true }
                [pscustomobject]@{ Name = 'VM-App02'; State = 'Running'; Generation = 2; HasCheckpoints = $false }
                [pscustomobject]@{ Name = 'VM-Test01'; State = 'Off'; Generation = 1; HasCheckpoints = $true }
                [pscustomobject]@{ Name = 'VM-DB01'; State = 'Running'; Generation = 2; HasCheckpoints = $false }
            )
            $datasets['HyperVVMs']         = if ($Overrides.ContainsKey('HyperVVMs')) { $Overrides['HyperVVMs'] } else { $vmRows }
            $datasets['PerformanceSnapshot'] = @([pscustomobject]@{ CpuPercent = 78 })
            $datasets['SecurityPosture']   = @([pscustomobject]@{ Smb1Enabled = $false; RdpEnabledNoNla = $false; AnyAvOrEdrDetected = $true; LocalAdminCount = 3 })
            $datasets['Volumes']           = @([pscustomobject]@{ DriveLetter = 'D'; PercentFree = 14; FreeGB = 420; SizeGB = 3000 })
            foreach ($vm in $vmRows) { $edges.Add((New-DemoEdge 'Server' $computerName 'HostsVM' $vm.Name 'HyperVVMs')) }
        }
    }

    # Apply any remaining overrides not already handled inline above (generic dataset replacement).
    foreach ($key in $Overrides.Keys) {
        if (-not $datasets.Contains($key)) { continue }
        $datasets[$key] = $Overrides[$key]
    }

    return [pscustomobject]@{
        ComputerName    = $computerName
        Datasets        = $datasets
        DependencyEdges = @($edges)
    }
}

function New-DemoEdge {
    param([string]$SourceType, [string]$SourceName, [string]$DependencyType, [string]$Target, [string]$SourceDataset)
    return [pscustomobject]@{ SourceType = $SourceType; SourceName = $SourceName; DependencyType = $DependencyType; Target = $Target; SourceDataset = $SourceDataset }
}

#endregion

#region Pipeline ------------------------------------------------------------------

function New-DemoServerRun {
    <#
        Drives the real pipeline (synthesis modules, report writers, archive) against one
        persona's synthetic data - the exact sequence tests\Invoke-OutputSmokeTest.ps1 already
        proves works. Kept in sync with that file's own "Real synthesis + output chain" section
        by hand; a divergence between the two is a maintenance trap worth checking for if either
        one changes.
    #>
    param(
        [Parameter(Mandatory)][string]$PersonaName,
        [Parameter(Mandatory)][string]$EngagementFolder,
        [string]$ProjectType = 'GeneralDiscovery',
        [datetime]$AsOfTime = (Get-Date),
        [hashtable]$Overrides = @{}
    )

    $persona = Get-DemoServerPersona -PersonaName $PersonaName -Overrides $Overrides
    $cfg = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $root 'config')
    $runFolderName = 'Discover-WindowsServer_{0}_{1}' -f $persona.ComputerName, $AsOfTime.ToString('yyyyMMdd_HHmmss')
    $out = Join-Path $EngagementFolder $runFolderName

    $ctx = New-DiscoveryContext -Mode Deep -ProjectType $ProjectType -ComplianceLens 'None' -OutputPath $out -IsAdmin $true -Config $cfg `
        -Parameters @{ Mode = 'Deep'; GenerateEvidenceManifest = $true; SkipZip = $false }
    $ctx.ComputerName = $persona.ComputerName
    Ensure-Directory -Path $out | Out-Null
    # Mirror of $folderMap in Discover-WindowsServer.ps1 / Invoke-OutputSmokeTest.ps1 - keep in sync.
    $folderMap = [ordered]@{ Reports = 'reports'; ReportsSupporting = 'reports\supporting'; ClientSafe = 'reports\supporting\client-safe'; Internal = 'reports\supporting\internal'; EvidenceRoot = 'evidence'; Csv = 'evidence\data\csv'; Json = 'evidence\data\json'; Logs = 'evidence\logs'; Raw = 'evidence\raw'; Status = 'evidence\status'; Evidence = 'evidence\manifest'; Archive = 'archive' }
    $paths = [ordered]@{}
    foreach ($k in $folderMap.Keys) { $p = Join-Path $out $folderMap[$k]; Ensure-Directory -Path $p | Out-Null; $paths[$k] = $p }
    $ctx.Paths = $paths
    $ctx.LogPaths = [ordered]@{ Summary = (Join-Path $paths['Logs'] 'summary.txt'); Errors = (Join-Path $paths['Logs'] 'errors.txt'); Warnings = (Join-Path $paths['Logs'] 'warnings.txt'); Debug = (Join-Path $paths['Logs'] 'debug.log') }
    foreach ($lp in $ctx.LogPaths.Values) { New-Item -ItemType File -Path $lp -Force | Out-Null }
    $ctx.IncludedModules = @($persona.Datasets.Keys | Select-Object -Unique)

    foreach ($name in $persona.Datasets.Keys) {
        Add-DataSet -Context $ctx -Name $name -Rows $persona.Datasets[$name] -Visibility 'Internal' -SourceModule 'Demo' | Out-Null
    }
    foreach ($e in $persona.DependencyEdges) {
        Add-DependencyEdge -Context $ctx -SourceType $e.SourceType -SourceName $e.SourceName -DependencyType $e.DependencyType -Target $e.Target -SourceDataset $e.SourceDataset | Out-Null
    }

    # Real synthesis + output chain - see this function's own doc-comment.
    Invoke-SynthesisModule -Context $ctx -Name 'Applications' -ModulesRoot (Join-Path $root 'modules') -EntryCommand 'Invoke-DiscoveryFingerprintSynthesis'
    foreach ($m in @('RiskEngine', 'DecommissionReadiness', 'ScopeLanguage', 'ClientInterviewPack')) {
        Invoke-SynthesisModule -Context $ctx -Name $m -ModulesRoot (Join-Path $root 'modules')
    }
    Build-ApplicationValidationMatrix -Context $ctx
    Build-ContextListDatasets -Context $ctx
    Write-DiscoveryPlan -Context $ctx -Path (Join-Path $out 'evidence\discovery-plan.md')
    Write-DiscoveryOutputs -Context $ctx
    Invoke-SynthesisModule -Context $ctx -Name 'ReportBuilder' -ModulesRoot (Join-Path $root 'modules') -EntryCommand 'Invoke-DiscoveryReportBuild'
    Invoke-SynthesisModule -Context $ctx -Name 'EvidenceManifest' -ModulesRoot (Join-Path $root 'modules') -EntryCommand 'Invoke-DiscoveryEvidenceManifest'
    Update-StatusFile -Context $ctx -Phase 'Complete' -CompletedModules 6 -TotalModules 6
    Compress-Folder -SourceFolder $out -DestinationZip (Join-Path $ctx.Paths['Archive'] 'run.zip') -ExcludeChildFolders @('archive') | Out-Null

    return $out
}

function New-DemoEngagement {
    <# Builds one (or, with -TwoSnapshots, two) demo engagement folder(s) - see this file's own header comment for the full scenario. #>
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [string[]]$Personas = @('DomainController', 'SqlServer', 'FilePrintServer', 'AgingNearEol', 'HyperVHost'),
        [string]$ProjectType = 'GeneralDiscovery',
        [switch]$TwoSnapshots
    )

    $baselineTime = (Get-Date).AddDays(-7)
    $baselineFolder = Join-Path $OutputFolder ('Fleet_{0}' -f $baselineTime.ToString('yyyyMMdd_HHmmss'))
    Ensure-Directory -Path $baselineFolder | Out-Null
    foreach ($p in $Personas) { New-DemoServerRun -PersonaName $p -EngagementFolder $baselineFolder -ProjectType $ProjectType -AsOfTime $baselineTime | Out-Null }

    $result = [ordered]@{ Snapshot1 = $baselineFolder; Snapshot2 = $null }
    if ($TwoSnapshots) {
        # Small, reproducible, per-persona differences - not randomized, so the demo is the same
        # every time it's generated. Only personas with a defined override actually drift; the
        # rest re-run identically, which is realistic (not every server changes every week).
        $driftOverrides = @{
            'FilePrintServer' = @{ SmbShares = @(
                [pscustomobject]@{ Name = 'Finance'; Path = 'D:\Shares\Finance'; IsUserShare = $true }
                [pscustomobject]@{ Name = 'HR'; Path = 'D:\Shares\HR'; IsUserShare = $true }
                [pscustomobject]@{ Name = 'Public'; Path = 'D:\Shares\Public'; IsUserShare = $true }
                [pscustomobject]@{ Name = 'Engineering'; Path = 'D:\Shares\Engineering'; IsUserShare = $true }
                [pscustomobject]@{ Name = 'Archive2026'; Path = 'D:\Shares\Archive2026'; IsUserShare = $true }
            ) }
            'HyperVHost' = @{ HyperVVMs = @(
                [pscustomobject]@{ Name = 'VM-App01'; State = 'Running'; Generation = 2; HasCheckpoints = $false }
                [pscustomobject]@{ Name = 'VM-App02'; State = 'Running'; Generation = 2; HasCheckpoints = $false }
                [pscustomobject]@{ Name = 'VM-Test01'; State = 'Off'; Generation = 1; HasCheckpoints = $true }
                [pscustomobject]@{ Name = 'VM-DB01'; State = 'Running'; Generation = 2; HasCheckpoints = $false }
                [pscustomobject]@{ Name = 'VM-App03'; State = 'Running'; Generation = 2; HasCheckpoints = $false }
            ) }
        }
        $currentTime = Get-Date
        $currentFolder = Join-Path $OutputFolder ('Fleet_{0}' -f $currentTime.ToString('yyyyMMdd_HHmmss'))
        Ensure-Directory -Path $currentFolder | Out-Null
        foreach ($p in $Personas) {
            $overrides = if ($driftOverrides.ContainsKey($p)) { $driftOverrides[$p] } else { @{} }
            New-DemoServerRun -PersonaName $p -EngagementFolder $currentFolder -ProjectType $ProjectType -AsOfTime $currentTime -Overrides $overrides | Out-Null
        }
        $result.Snapshot2 = $currentFolder
    }
    return [pscustomobject]$result
}

#endregion

# Only runs when executed directly - dot-source for the functions above (Pester, or future
# GUI integration), same convention as every other file in tools\.
if ($MyInvocation.InvocationName -ne '.') {
    Import-Module (Join-Path $root 'modules/Core/Core.psm1')   -Force -DisableNameChecking -Global
    Import-Module (Join-Path $root 'modules/Output/Output.psm1') -Force -DisableNameChecking -Global
    Import-Module (Join-Path $root 'Discover-WindowsServer.psm1') -Force -DisableNameChecking -Global

    Ensure-Directory -Path $OutputFolder | Out-Null
    $result = New-DemoEngagement -OutputFolder $OutputFolder -Personas $Personas -ProjectType $ProjectType -TwoSnapshots:$TwoSnapshots
    Write-Host ("Demo engagement generated: {0}" -f $result.Snapshot1) -ForegroundColor Green
    if ($result.Snapshot2) { Write-Host ("Second (drifted) snapshot: {0}" -f $result.Snapshot2) -ForegroundColor Green }
    Write-Host ''
    Write-Host 'Next steps:'
    $latestFolder = if ($result.Snapshot2) { $result.Snapshot2 } else { $result.Snapshot1 }
    Write-Host ("  .\tools\Merge-FleetDiscoveryResults.ps1 -EngagementFolder '{0}'" -f $latestFolder)
    if ($result.Snapshot2) {
        Write-Host ("  .\tools\Compare-DiscoveryRuns.ps1 -BaselineEngagementFolder '{0}' -CurrentEngagementFolder '{1}'" -f $result.Snapshot1, $result.Snapshot2)
    }
}
