#Requires -Version 5.1
# Windows Server 2012 R2 ships PowerShell 4.0 and fails this check. tools\Install-LegacyPrerequisites.ps1
# installs PowerShell 7 there (asks first, never restarts); then run this script with pwsh.exe.
<#
.SYNOPSIS
    Ultimate Modular Windows Server Discovery Toolkit - main entry point.

.DESCRIPTION
    Read-only, modular Windows Server discovery for MSP project scoping, server
    refresh / Hyper-V refresh, application / Azure migration, decommission
    readiness, CMMC/security review, and infrastructure documentation.

    Runs LOCALLY on the server being discovered. Nothing in this toolkit changes
    the system except writing its own output files. See docs\README.md and the
    "Critical Safety Rules" in the build spec.

.EXAMPLE
    .\Discover-WindowsServer.ps1
.EXAMPLE
    .\Discover-WindowsServer.ps1 -Mode Deep -ProjectType Decommission -IncludeConfigDependencyScan
.EXAMPLE
    .\Discover-WindowsServer.ps1 -Mode Custom -IncludeModules SystemInventory,Applications,SQL,IIS
.EXAMPLE
    .\Discover-WindowsServer.ps1 -Mode Fast -ComplianceLens CMMC
.EXAMPLE
    .\Discover-WindowsServer.ps1 -Mode Deep -WhatIf
    Prints which modules would run and writes discovery-plan.md, then exits without
    collecting anything - useful to show a client exactly what will be touched first.
#>
[CmdletBinding()]
param(
    [ValidateSet('Fast','Deep','Custom')]
    [string]$Mode = 'Fast',

    [ValidateSet('GeneralDiscovery','ServerRefresh','HyperVRefresh','Decommission','AzureMigration','AppMigration','CMMCReadiness')]
    [string]$ProjectType = 'GeneralDiscovery',

    [string[]]$IncludeModules,
    [string[]]$ExcludeModules,
    [string]$OutputRoot = 'C:\Temp',
    [switch]$DeepFileShareScan,
    [int]$MaxDepth = 3,
    [int]$LargeFileThresholdGB = 5,
    [int]$OldFileYears = 7,
    [int]$EventLogDays = 14,
    [int]$MaxEventSamplesPerLog = 50,
    [switch]$FullEventLogExport,
    [switch]$IncludeConfigDependencyScan,
    [int]$ConfigScanMaxFileSizeMB = 10,
    [switch]$IncludeUserProfiles,
    [switch]$IncludeRecycleBin,
    [switch]$IncludeWindowsFolder,
    [switch]$AttemptSqlIntegratedAuth,
    [switch]$SkipZip,
    [switch]$GenerateEvidenceManifest,
    [ValidateSet('None','CMMC','GeneralSecurity')]
    [string]$ComplianceLens = 'None',
    [switch]$Quiet,
    [switch]$VerboseLogging,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Continue'
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

# --- Import framework + engine (global so collector modules can resolve them) ---
$coreModule   = Join-Path $scriptRoot 'modules\Core\Core.psm1'
$outputModule = Join-Path $scriptRoot 'modules\Output\Output.psm1'
$engineModule = Join-Path $scriptRoot 'Discover-WindowsServer.psm1'
try {
    Import-Module $coreModule   -Force -DisableNameChecking -Global -ErrorAction Stop
    Import-Module $outputModule -Force -DisableNameChecking -Global -ErrorAction Stop
    Import-Module $engineModule -Force -DisableNameChecking -Global -ErrorAction Stop
} catch {
    Write-Host ("FATAL: Failed to load toolkit framework modules: {0}" -f $_.Exception.Message) -ForegroundColor Red
    throw
}

# --- Load configuration ------------------------------------------------------
$configDir = Join-Path $scriptRoot 'config'
$config = Get-DiscoveryConfigBundle -ConfigDirectory $configDir

# --- Resolve identity context ------------------------------------------------
$isAdmin  = Test-IsAdministrator
$isSystem = Test-IsSystem

# --- Resolve effective parameters --------------------------------------------
# Precedence: explicit command line > mode config (fast/deep parameterDefaults)
#             > global config (default.discovery.json "defaults") > built-in fallback.
#
# NOTE: this resolver is deliberately type-agnostic. The earlier version only handled
# [bool], so the numeric keys in fast/deep parameterDefaults (eventLogDays,
# maxEventSamplesPerLog) were silently ignored and Deep mode never actually collected
# more event-log samples than Fast. Cast the result at the call site.
$modeCfg = if ($Mode -eq 'Deep') { $config.Deep } elseif ($Mode -eq 'Fast') { $config.Fast } else { $null }
$globalDefaults = $null
if ($config -and $config.Default -and $config.Default.defaults) { $globalDefaults = $config.Default.defaults }

function Resolve-EffValue {
    param([bool]$IsBound, $UserValue, [string]$ConfigKey, $ModeConfig, $GlobalDefaults, $Default)
    if ($IsBound) { return $UserValue }
    if ($ModeConfig -and $ModeConfig.parameterDefaults) {
        $pd = $ModeConfig.parameterDefaults
        if ($pd.PSObject.Properties[$ConfigKey] -and ($null -ne $pd.$ConfigKey)) { return $pd.$ConfigKey }
    }
    if ($GlobalDefaults -and $GlobalDefaults.PSObject.Properties[$ConfigKey] -and ($null -ne $GlobalDefaults.$ConfigKey)) {
        return $GlobalDefaults.$ConfigKey
    }
    return $Default
}

# Switches
$effDeepFileShareScan     = [bool](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('DeepFileShareScan')           -UserValue $DeepFileShareScan.IsPresent           -ConfigKey 'deepFileShareScan'           -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default $false)
$effIncludeConfigDepScan  = [bool](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('IncludeConfigDependencyScan') -UserValue $IncludeConfigDependencyScan.IsPresent -ConfigKey 'includeConfigDependencyScan' -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default $false)
$effAttemptSqlAuth        = [bool](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('AttemptSqlIntegratedAuth')    -UserValue $AttemptSqlIntegratedAuth.IsPresent    -ConfigKey 'attemptSqlIntegratedAuth'    -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default $false)
$effFullEventLogExport    = [bool](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('FullEventLogExport')          -UserValue $FullEventLogExport.IsPresent          -ConfigKey 'fullEventLogExport'          -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default $false)
$effIncludeUserProfiles   = [bool](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('IncludeUserProfiles')         -UserValue $IncludeUserProfiles.IsPresent         -ConfigKey 'includeUserProfiles'         -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default $false)
$effIncludeRecycleBin     = [bool](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('IncludeRecycleBin')           -UserValue $IncludeRecycleBin.IsPresent           -ConfigKey 'includeRecycleBin'           -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default $false)
$effIncludeWindowsFolder  = [bool](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('IncludeWindowsFolder')        -UserValue $IncludeWindowsFolder.IsPresent        -ConfigKey 'includeWindowsFolder'        -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default $false)

# Numeric / string tuning values (previously hardcoded to the param() defaults regardless of config)
$effMaxDepth              = [int](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('MaxDepth')                -UserValue $MaxDepth                -ConfigKey 'maxDepth'                -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default 3)
$effLargeFileThresholdGB  = [int](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('LargeFileThresholdGB')    -UserValue $LargeFileThresholdGB    -ConfigKey 'largeFileThresholdGB'    -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default 5)
$effOldFileYears          = [int](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('OldFileYears')            -UserValue $OldFileYears            -ConfigKey 'oldFileYears'            -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default 7)
$effEventLogDays          = [int](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('EventLogDays')            -UserValue $EventLogDays            -ConfigKey 'eventLogDays'            -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default 14)
$effMaxEventSamples       = [int](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('MaxEventSamplesPerLog')   -UserValue $MaxEventSamplesPerLog   -ConfigKey 'maxEventSamplesPerLog'   -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default 50)
$effConfigScanMaxFileMB   = [int](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('ConfigScanMaxFileSizeMB') -UserValue $ConfigScanMaxFileSizeMB -ConfigKey 'configScanMaxFileSizeMB' -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default 10)
$effOutputRoot            = [string](Resolve-EffValue -IsBound $PSBoundParameters.ContainsKey('OutputRoot')           -UserValue $OutputRoot              -ConfigKey 'outputRoot'              -ModeConfig $modeCfg -GlobalDefaults $globalDefaults -Default 'C:\Temp')
if ([string]::IsNullOrWhiteSpace($effOutputRoot)) { $effOutputRoot = 'C:\Temp' }
# Always absolute: child processes (secedit, ...) resolve relative paths against the process
# cwd, which is not PowerShell's location, and drive-relative forms like C:out mean something else again.
$effOutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($effOutputRoot)

# Custom mode requires include and/or exclude.
if ($Mode -eq 'Custom' -and -not ($IncludeModules -or $ExcludeModules)) {
    Write-Host 'Custom mode requires -IncludeModules and/or -ExcludeModules. Falling back to Fast mode.' -ForegroundColor Yellow
    $Mode = 'Fast'
}

# --- Prepare output folder ---------------------------------------------------
$timestamp  = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outputPath = Join-Path $effOutputRoot ("Discover-WindowsServer_{0}_{1}" -f $env:COMPUTERNAME, $timestamp)
Ensure-Directory -Path $effOutputRoot | Out-Null
Ensure-Directory -Path $outputPath | Out-Null

# Output layout. TWO top-level folders, because a run folder with a dozen sibling
# directories and thirty loose files at its root is not a deliverable, it is a dump:
#
#   reports\    what a human reads - two finished documents plus their supporting pack.
#   evidence\   everything those documents were built from: logs, raw captures, live
#               status, and every dataset as CSV and JSON.
#
# The PATH KEYS below are the contract every module codes against ($Context.Paths['Csv']
# and friends). They are deliberately unchanged from the previous flat layout - only the
# directories they resolve to have moved - so no collector needed editing to adopt this.
$folderMap = [ordered]@{
    Reports           = 'reports'
    ReportsSupporting = 'reports\supporting'
    Html              = 'reports'
    Markdown          = 'reports\supporting'
    ClientSafe        = 'reports\supporting\client-safe'
    Internal          = 'reports\supporting\internal'
    EvidenceRoot      = 'evidence'
    Csv               = 'evidence\data\csv'
    Json              = 'evidence\data\json'
    Logs              = 'evidence\logs'
    Raw               = 'evidence\raw'
    Status            = 'evidence\status'
    Evidence          = 'evidence\manifest'
    Archive           = 'archive'
}
$paths = [ordered]@{}
foreach ($k in $folderMap.Keys) {
    $p = Join-Path $outputPath $folderMap[$k]
    Ensure-Directory -Path $p | Out-Null
    $paths[$k] = $p
}

# Log file paths + create empty files so appends succeed.
$logPaths = [ordered]@{
    Summary  = Join-Path $paths['Logs'] 'summary.txt'
    Errors   = Join-Path $paths['Logs'] 'errors.txt'
    Warnings = Join-Path $paths['Logs'] 'warnings.txt'
    Debug    = Join-Path $paths['Logs'] 'debug.log'
}
foreach ($lp in $logPaths.Values) { if (-not (Test-Path -LiteralPath $lp)) { New-Item -ItemType File -Path $lp -Force | Out-Null } }

# --- Build the parameters hashtable passed into the context ------------------
$parameters = @{
    Mode                        = $Mode
    ProjectType                 = $ProjectType
    IncludeModules              = $IncludeModules
    ExcludeModules              = $ExcludeModules
    OutputRoot                  = $effOutputRoot
    DeepFileShareScan           = $effDeepFileShareScan
    MaxDepth                    = $effMaxDepth
    LargeFileThresholdGB        = $effLargeFileThresholdGB
    OldFileYears                = $effOldFileYears
    EventLogDays                = $effEventLogDays
    MaxEventSamplesPerLog       = $effMaxEventSamples
    FullEventLogExport          = $effFullEventLogExport
    IncludeConfigDependencyScan = $effIncludeConfigDepScan
    ConfigScanMaxFileSizeMB     = $effConfigScanMaxFileMB
    IncludeUserProfiles         = $effIncludeUserProfiles
    IncludeRecycleBin           = $effIncludeRecycleBin
    IncludeWindowsFolder        = $effIncludeWindowsFolder
    AttemptSqlIntegratedAuth    = $effAttemptSqlAuth
    SkipZip                     = $SkipZip.IsPresent
    GenerateEvidenceManifest    = $GenerateEvidenceManifest.IsPresent
    ComplianceLens              = $ComplianceLens
    Quiet                       = $Quiet.IsPresent
    VerboseLogging              = $VerboseLogging.IsPresent
    WhatIf                      = $WhatIf.IsPresent
}

# --- Build context -----------------------------------------------------------
$context = New-DiscoveryContext -Mode $Mode -ProjectType $ProjectType -ComplianceLens $ComplianceLens `
    -OutputRoot $effOutputRoot -OutputPath $outputPath -IsAdmin $isAdmin -IsSystem $isSystem `
    -Parameters $parameters -Config $config -Quiet:$Quiet.IsPresent -VerboseLogging:$VerboseLogging.IsPresent
$context.Paths    = $paths
$context.LogPaths = $logPaths

if (-not $Quiet.IsPresent) {
    Write-Host ''
    Write-Host '=== Ultimate Modular Windows Server Discovery Toolkit ===' -ForegroundColor Cyan
    Write-Host ("Computer: {0} | Mode: {1} | Project: {2} | Lens: {3}" -f $env:COMPUTERNAME, $Mode, $ProjectType, $ComplianceLens) -ForegroundColor Cyan
    Write-Host ("Elevated: {0} | SYSTEM: {1} | Output: {2}" -f $isAdmin, $isSystem, $outputPath) -ForegroundColor Cyan
    Write-Host ''
}

# --- Run ---------------------------------------------------------------------
$null = Invoke-Discovery -Context $context

# Return the output path for callers / pipelines.
$outputPath
