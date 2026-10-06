<#
.SYNOPSIS
    Dynamic smoke test for the output layer. Seeds synthetic datasets shaped per
    docs\FIELD-USAGE.md, runs the real synthesis + output chain, and asserts that every
    artifact docs\OUTPUT-GUIDE.md promises is produced and non-trivial.

.DESCRIPTION
    Complements Invoke-ToolkitSelfCheck.ps1 (which is static). This one actually executes
    the RiskEngine, the synthesis modules, and every writer, so it catches broken markdown
    tables, malformed workbook XML, missing CSV columns, and dropped deliverables.

    It collects nothing from the host: all input is synthetic. Output goes to a temp folder
    which is removed afterwards unless -KeepOutput is passed.

    Cross-platform note: this runs on PowerShell 7 on macOS/Linux too, which is useful for
    development, but the toolkit itself targets Windows PowerShell 5.1 on Windows Server.

.EXAMPLE
    .\tests\Invoke-OutputSmokeTest.ps1
.EXAMPLE
    .\tests\Invoke-OutputSmokeTest.ps1 -ProjectType CMMCReadiness -KeepOutput
#>
[CmdletBinding()]
param(
    [ValidateSet('GeneralDiscovery','ServerRefresh','HyperVRefresh','Decommission','AzureMigration','AppMigration','CMMCReadiness')]
    [string]$ProjectType = 'Decommission',
    [switch]$KeepOutput
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
function Assert-That { param([string]$Name, [bool]$Ok, [string]$Detail='')
    if ($Ok) { Write-Host ("  [ ok ] {0}" -f $Name) -ForegroundColor DarkGray }
    else { Write-Host ("  [FAIL] {0}" -f $Name) -ForegroundColor Red; if ($Detail) { Write-Host ("         {0}" -f $Detail) -ForegroundColor Red }; $script:fail++ }
}

Import-Module (Join-Path $root 'modules/Core/Core.psm1')   -Force -DisableNameChecking -Global
Import-Module (Join-Path $root 'modules/Output/Output.psm1') -Force -DisableNameChecking -Global
Import-Module (Join-Path $root 'Discover-WindowsServer.psm1') -Force -DisableNameChecking -Global

$out = Join-Path ([System.IO.Path]::GetTempPath()) ("dws-smoke-" + [guid]::NewGuid().ToString('N').Substring(0,8))
$cfg = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $root 'config')
$ctx = New-DiscoveryContext -Mode Deep -ProjectType $ProjectType -ComplianceLens 'CMMC' -OutputPath $out -IsAdmin $true -Config $cfg `
    -Parameters @{ Mode='Deep'; GenerateEvidenceManifest=$true; SkipZip=$false; IncludeConfigDependencyScan=$true; DeepFileShareScan=$true }
Ensure-Directory -Path $out | Out-Null
# Mirror of $folderMap in Discover-WindowsServer.ps1 (two-folder layout). Keep in sync.
$folderMap = [ordered]@{ Reports='reports'; ReportsSupporting='reports\supporting'; Html='reports'; Markdown='reports\supporting'; ClientSafe='reports\supporting\client-safe'; Internal='reports\supporting\internal'; EvidenceRoot='evidence'; Csv='evidence\data\csv'; Json='evidence\data\json'; Logs='evidence\logs'; Raw='evidence\raw'; Status='evidence\status'; Evidence='evidence\manifest'; Archive='archive' }
$paths = [ordered]@{}
foreach ($k in $folderMap.Keys) { $p = Join-Path $out $folderMap[$k]; Ensure-Directory -Path $p | Out-Null; $paths[$k] = $p }
$ctx.Paths = $paths
$ctx.LogPaths = [ordered]@{ Summary=(Join-Path $paths['Logs'] 'summary.txt'); Errors=(Join-Path $paths['Logs'] 'errors.txt'); Warnings=(Join-Path $paths['Logs'] 'warnings.txt'); Debug=(Join-Path $paths['Logs'] 'debug.log') }
foreach ($lp in $ctx.LogPaths.Values) { New-Item -ItemType File -Path $lp -Force | Out-Null }
$ctx.IncludedModules = @('SystemInventory','ServicesTasks','FileShares','SQL','IIS','SecurityPosture')

# ---- Synthetic datasets, field names per docs\FIELD-USAGE.md ----
Add-DataSet -Context $ctx -Name 'ExecutionContext' -Rows @([pscustomobject]@{ IsAdmin=$true }) -SourceModule 'SystemInventory' | Out-Null
Add-DataSet -Context $ctx -Name 'OperatingSystem'  -Rows @([pscustomobject]@{ Caption='Windows Server 2012 R2'; BuildNumber='9600'; IsEndOfLifeOrNear=$true }) -SourceModule 'SystemInventory' | Out-Null
Add-DataSet -Context $ctx -Name 'PendingReboot'    -Rows @([pscustomobject]@{ RebootPending=$true }) -SourceModule 'SystemInventory' | Out-Null
Add-DataSet -Context $ctx -Name 'RolesFeatures'    -Rows @([pscustomobject]@{ Name='AD-Domain-Services'; DisplayName='AD DS'; InstallState='Installed' },[pscustomobject]@{ Name='DNS'; DisplayName='DNS Server'; InstallState='Installed' }) -SourceModule 'RolesFeatures' | Out-Null
Add-DataSet -Context $ctx -Name 'Services'         -Rows @([pscustomobject]@{ Name='AcmeSvc'; DisplayName='Acme App'; StartName='CORP\svc-acme'; PathName='C:\Acme\svc.exe'; ExecutablePath='C:\Acme\svc.exe'; PathExists=$true; UnquotedPathWithSpaces=$true; IsNonMicrosoftAutoStart=$true }) -SourceModule 'ServicesTasks' | Out-Null
Add-DataSet -Context $ctx -Name 'ScheduledTasks'   -Rows @([pscustomobject]@{ TaskName='NightlyBackup'; Principal='CORP\svc-bak'; ActionsText='robocopy \\fs01\share D:\bak'; LastTaskResult=1; UsesUncPath=$true; LastRunFailed=$true; RunsAsDomainAccount=$true }) -SourceModule 'ServicesTasks' | Out-Null
Add-DataSet -Context $ctx -Name 'InstalledApplications' -Rows @([pscustomobject]@{ DisplayName='Acme ERP'; Publisher='Acme'; InstallLocation='C:\Acme'; SystemComponent=$false }) -SourceModule 'Applications' | Out-Null
Add-DataSet -Context $ctx -Name 'IPConfiguration'  -Rows @([pscustomobject]@{ InterfaceAlias='Ethernet'; IPv4Address='10.0.0.5'; IsStatic=$true }) -SourceModule 'Network' | Out-Null
Add-DataSet -Context $ctx -Name 'ListeningPorts'   -Rows @([pscustomobject]@{ LocalPort=1433; Process='sqlservr'; ServiceName='MSSQLSERVER' }) -SourceModule 'Network' | Out-Null
Add-DataSet -Context $ctx -Name 'FirewallProfiles' -Rows @([pscustomobject]@{ Name='Domain'; Enabled=$false }) -SourceModule 'SecurityPosture' | Out-Null
Add-DataSet -Context $ctx -Name 'SecurityPosture'  -Rows @([pscustomobject]@{ Smb1Enabled=$true; RdpEnabledNoNla=$true; AnyAvOrEdrDetected=$false; LocalAdminCount=9 }) -SourceModule 'SecurityPosture' | Out-Null
Add-DataSet -Context $ctx -Name 'Volumes'          -Rows @([pscustomobject]@{ DriveLetter='C'; PercentFree=4; FreeGB=8; SizeGB=200 }) -SourceModule 'Storage' | Out-Null
Add-DataSet -Context $ctx -Name 'SmbShares'        -Rows @([pscustomobject]@{ Name='Data'; Path='D:\Data'; IsUserShare=$true }) -SourceModule 'FileShares' | Out-Null
Add-DataSet -Context $ctx -Name 'FileShareSummary' -Rows @([pscustomobject]@{ DeepScanPerformed=$true }) -SourceModule 'FileShares' | Out-Null
Add-DataSet -Context $ctx -Name 'NtfsAclSummary'   -Rows @([pscustomobject]@{ Share='Data'; Path='D:\Data'; TopLevelFolders=12; FileCount=90000; TotalSizeGB=620; LargeFilesOverThreshold=3; OldFilesOverYears=400; RecentlyModified30d=1200; MaxDepthScanned=3; RecycleBinIncluded=$false; RecycleBinFilesFound=51; RecycleBinSizeGB=8 }) -SourceModule 'FileShares' | Out-Null
Add-DataSet -Context $ctx -Name 'Printers'         -Rows @([pscustomobject]@{ Name='Label1'; DriverName='Zebra'; PortName='USB'; Shared=$true }) -SourceModule 'PrintServer' | Out-Null
Add-DataSet -Context $ctx -Name 'SqlInstances'     -Rows @([pscustomobject]@{ InstanceName='SRV\SQL'; ServiceName='MSSQLSERVER'; DeepQueryPerformed=$false; BinaryPath='C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn' }) -SourceModule 'SQL' | Out-Null
Add-DataSet -Context $ctx -Name 'OdbcDsns'         -Rows @([pscustomobject]@{ DsnName='ERP'; Server='sql01'; Database='erp'; Driver='SQL Server' }) -SourceModule 'SQL' | Out-Null
Add-DataSet -Context $ctx -Name 'IisSites'         -Rows @([pscustomobject]@{ Name='Default Web Site'; State='Started'; PhysicalPath='C:\inetpub\wwwroot' }) -SourceModule 'IIS' | Out-Null
Add-DataSet -Context $ctx -Name 'IisAppPools'      -Rows @([pscustomobject]@{ Name='AcmePool'; IdentityType='SpecificUser'; UserName='CORP\svc-web'; UsesCustomIdentity=$true }) -SourceModule 'IIS' | Out-Null
Add-DataSet -Context $ctx -Name 'Certificates'     -Rows @([pscustomobject]@{ Subject='CN=acme.local'; NotAfter='2026-09-01'; Thumbprint='ABC123'; ExpiringSoon=$true; HasPrivateKey=$true }) -SourceModule 'Certificates' | Out-Null
Add-DataSet -Context $ctx -Name 'DomainContext'    -Rows @([pscustomobject]@{ IsDomainController=$true; HoldsFsmoRole=$true }) -SourceModule 'ActiveDirectory' | Out-Null
Add-DataSet -Context $ctx -Name 'HyperVVMs'        -Rows @([pscustomobject]@{ Name='VM1'; State='Running'; Generation=2; HasCheckpoints=$true }) -SourceModule 'HyperV' | Out-Null
Add-DataSet -Context $ctx -Name 'PerformanceSnapshot' -Rows @([pscustomobject]@{ CpuPercent=93 }) -SourceModule 'PerformanceSnapshot' | Out-Null
Add-DataSet -Context $ctx -Name 'VendorAgents'     -Rows @([pscustomobject]@{ AgentName='Datto RMM'; Category='RMM' }) -Visibility 'Both' -SourceModule 'VendorAgents' | Out-Null
Add-DataSet -Context $ctx -Name 'Licensing'        -Rows @([pscustomobject]@{ Indicator='RDS per-device CALs'; Evidence='registry' }) -Visibility 'Both' -SourceModule 'Licensing' | Out-Null
Add-DependencyEdge -Context $ctx -SourceType 'Service' -SourceName 'AcmeSvc' -DependencyType 'RunsAs' -Target 'CORP\svc-acme' -SourceDataset 'Services' | Out-Null
Add-DependencyEdge -Context $ctx -SourceType 'SmbShare' -SourceName 'Data' -DependencyType 'ServesPath' -Target 'C:\Shares\Data' -SourceDataset 'FileShares' | Out-Null
# ListeningPort edges are excluded by default from the rendered dependency diagram (real-world
# noise confirmed live) but must still flow into the DependencyGraph dataset/table - this exercises
# that filtering path without asserting anything visual here (see DependencyDiagram.Tests.ps1).
Add-DependencyEdge -Context $ctx -SourceType 'Process' -SourceName 'svchost' -DependencyType 'ListeningPort' -Target '445' -SourceDataset 'Network' | Out-Null
Add-Unknown -Context $ctx -Unknown 'SQL databases not enumerated' -WhyItMatters 'Data migration sizing unknown' -Module 'SQL' | Out-Null
Add-Limitation -Context $ctx -Module 'SQL' -Message 'Integrated auth not attempted' -Impact 'Incomplete' | Out-Null

# ---- Real synthesis + output chain ----
# Fingerprint matching runs between collection and synthesis (its matchers reference
# datasets from late collectors), exactly as the orchestrator sequences it.
Invoke-SynthesisModule -Context $ctx -Name 'Applications' -ModulesRoot (Join-Path $root 'modules') -EntryCommand 'Invoke-DiscoveryFingerprintSynthesis'
foreach ($m in @('RiskEngine','DecommissionReadiness','ScopeLanguage','ClientInterviewPack')) {
    Invoke-SynthesisModule -Context $ctx -Name $m -ModulesRoot (Join-Path $root 'modules')
}
Build-ApplicationValidationMatrix -Context $ctx
# Exposes the accumulated context lists (findings, questions, scope language, limitations,
# unknowns) as datasets so they reach csv/ and json/ - same as a real run.
Build-ContextListDatasets -Context $ctx
Write-DiscoveryPlan -Context $ctx -Path (Join-Path $out 'evidence\discovery-plan.md')
Write-DiscoveryOutputs -Context $ctx
# Same order as the engine: reports are built AFTER the outputs they reference exist.
Invoke-SynthesisModule -Context $ctx -Name 'ReportBuilder' -ModulesRoot (Join-Path $root 'modules') -EntryCommand 'Invoke-DiscoveryReportBuild'
Invoke-SynthesisModule -Context $ctx -Name 'EvidenceManifest' -ModulesRoot (Join-Path $root 'modules') -EntryCommand 'Invoke-DiscoveryEvidenceManifest'
Update-StatusFile -Context $ctx -Phase 'Complete' -CompletedModules 6 -TotalModules 6
Compress-Folder -SourceFolder $out -DestinationZip (Join-Path $ctx.Paths['Archive'] 'run.zip') -ExcludeChildFolders @('archive') | Out-Null

Write-Host ''
Write-Host ("Run: ProjectType={0}  findings={1}  datasets={2}  questions={3}  errors={4}" -f $ProjectType, $ctx.Findings.Count, $ctx.DataSets.Count, $ctx.FollowUpQuestions.Count, $ctx.Counters.Errors)
Write-Host ''
Write-Host '== documented artifacts exist and are non-trivial =='
# The authoritative list lives in config/output-settings.json (requiredOutputFiles) so this
# test and the toolkit cannot drift apart. Path-qualified copies are checked separately below.
$expected = @()
try { $expected = @($cfg.Output.requiredOutputFiles) } catch { }
if ($expected.Count -eq 0) { Write-Host '  [FAIL] config requiredOutputFiles is empty' -ForegroundColor Red; $fail++ }
$expected = @($expected) + @(
 'evidence\status\status.json','evidence\status\progress.json','evidence\status\findings-live.json',
 'evidence\manifest\evidence-manifest.csv','evidence\manifest\hashes.sha256',
 'reports\supporting\client-safe\client-safe-summary.md','archive\run.zip'
)
foreach ($rel in $expected) {
    $p = Join-Path $out $rel
    $exists = Test-Path -LiteralPath $p
    $size = if ($exists) { (Get-Item -LiteralPath $p).Length } else { 0 }
    # errors.txt / warnings.txt are legitimately empty on a clean run - existence only.
    $min = if ($rel -match '(errors|warnings)\.txt$') { -1 } else { 20 }
    Assert-That -Name ("{0} ({1} bytes)" -f $rel, $size) -Ok ($exists -and $size -gt $min)
}
# errors.txt / warnings.txt are legitimately near-empty on a clean run - existence only.
foreach ($rel in @('errors.txt','warnings.txt')) { Assert-That -Name ("{0} exists" -f $rel) -Ok (Test-Path -LiteralPath (Join-Path $out ('evidence\logs\' + $rel))) }

Write-Host ''
Write-Host '== structural integrity =='
$wb = Join-Path $out 'reports\supporting\workbook.xml'
$wbOk = $false; $sheets = 0
try { [xml]$x = Get-Content -LiteralPath $wb -Raw; $sheets = @($x.Workbook.Worksheet).Count; $wbOk = ($sheets -gt 0) } catch { }
Assert-That -Name ("workbook.xml is well-formed XML ({0} worksheets)" -f $sheets) -Ok $wbOk
$html = Get-Content -LiteralPath (Join-Path $out 'reports\internal-engineering-report.html') -Raw
Assert-That -Name 'internal-engineering-report.html is closed'      -Ok ($html.TrimEnd().EndsWith('</html>'))
Assert-That -Name 'internal-engineering-report.html renders findings' -Ok ($html -match 'class="card')
Assert-That -Name 'HTML has the project-type priority section' -Ok ($html -match 'Priority For This Project Type')
$csvCount  = @(Get-ChildItem (Join-Path $out 'evidence\data\csv')  -File).Count
$jsonCount = @(Get-ChildItem (Join-Path $out 'evidence\data\json') -File).Count
Assert-That -Name ("per-dataset csv/ ({0}) and json/ ({1}) match dataset count ({2})" -f $csvCount, $jsonCount, $ctx.DataSets.Count) -Ok ($csvCount -ge ($ctx.DataSets.Count - 1) -and $jsonCount -ge ($ctx.DataSets.Count - 1))

# wbs-inputs.csv must carry the emphasis columns or the lens is invisible in the tabular output.
$wbs = Get-Content -LiteralPath (Join-Path $out 'reports\supporting\wbs-inputs.csv') -Raw
Assert-That -Name 'wbs-inputs.csv has PriorityForProject column' -Ok ($wbs -match 'PriorityForProject')
Assert-That -Name 'wbs-inputs.csv has Subject column'            -Ok ($wbs -match 'Subject')

# Emphasis must actually appear for a lens-bearing project type.
if ($ProjectType -ne 'GeneralDiscovery') {
    $emph = @($ctx.Findings | Where-Object { $_.IsEmphasized }).Count
    Assert-That -Name ("findings emphasised for {0}: {1}" -f $ProjectType, $emph) -Ok ($emph -gt 0)
    Assert-That -Name 'summary.md reports the prioritised count' -Ok ((Get-Content -LiteralPath (Join-Path $out 'reports\supporting\summary.md') -Raw) -match 'prioritised for project type')
}

# ApplicationFingerprints must be derived post-collection from matcher sources.
$fpRows = @()
if ($ctx.DataSets.Contains('ApplicationFingerprints')) { $fpRows = @($ctx.DataSets['ApplicationFingerprints'].Rows) }
Assert-That -Name ("fingerprints derived post-collection: {0}" -f $fpRows.Count) -Ok ($fpRows.Count -gt 0)
Assert-That -Name 'fingerprint rows are flat objects (not a nested array)' -Ok ($fpRows.Count -eq 0 -or ($fpRows[0].ApplicationName -is [string]))

# Rule-authored scope language must reach the scope deliverables, not just the finding object.
$slPath = Join-Path $out 'evidence\data\csv\ScopeLanguage.csv'
Assert-That -Name 'ScopeLanguage dataset exported' -Ok (Test-Path -LiteralPath $slPath)
if (Test-Path -LiteralPath $slPath) {
    $sl = @(Import-Csv -LiteralPath $slPath)
    Assert-That -Name ("scope language entries: {0}" -f $sl.Count) -Ok ($sl.Count -gt 5)
    Assert-That -Name 'RiskEngine contributed rule-authored scope language' -Ok (@($sl | Where-Object { $_.Module -eq 'RiskEngine' }).Count -gt 0)
    Assert-That -Name 'no doubled markdown blockquote marker in scope text' -Ok (@($sl | Where-Object { $_.Text -like '>*' }).Count -eq 0)
}
$draft = Get-Content -LiteralPath (Join-Path $out 'reports\supporting\draft-scope-language.md') -Raw
Assert-That -Name 'draft-scope-language.md has both Assumptions and Exclusions content' -Ok (($draft -match '## Assumptions') -and ($draft -match '## Exclusions') -and ($draft -match 'ChangeOrderTrigger|Exclusion'))

# wbs-inputs.csv WBS areas must be real areas, not an echo of the finding category.
$wbsRows = @(Import-Csv -LiteralPath (Join-Path $out 'reports\supporting\wbs-inputs.csv'))
$rawCats = @('Applications','Backup / DR','Certificates','Database','Discovery Quality','File / Print','Hyper-V / Cluster','Identity / AD / DC','Licensing','Network','Operating System','Performance','Security','Service Account','Services / Tasks','Storage','Vendor','Web')
$echoed = @($wbsRows | Where-Object { $rawCats -contains $_.SuggestedWBSArea })
Assert-That -Name ("wbs-inputs.csv WBS areas are real areas (raw-category echoes: {0})" -f $echoed.Count) -Ok ($echoed.Count -eq 0)

# CriticalPaths must pick up the SQL binary path (the branch was dead while SqlInstances
# emitted no BinaryPath field).
$cpRows = @()
if ($ctx.DataSets.Contains('CriticalPaths')) { $cpRows = @($ctx.DataSets['CriticalPaths'].Rows) }
Assert-That -Name 'CriticalPaths includes the SQL binary path' -Ok (@($cpRows | Where-Object { $_.Source -eq 'SQL' }).Count -gt 0)

# EvidenceManifest registers its dataset after the generic export, so it exports its own.
Assert-That -Name 'EvidenceManifest dataset exported to csv/'  -Ok (Test-Path -LiteralPath (Join-Path $out 'evidence\data\csv\EvidenceManifest.csv'))
Assert-That -Name 'EvidenceManifest dataset exported to json/' -Ok (Test-Path -LiteralPath (Join-Path $out 'evidence\data\json\EvidenceManifest.json'))

# Severity-ranked (not alphabetical) ordering in scoping-risks.txt.
$risks = @(Get-Content -LiteralPath (Join-Path $out 'evidence\logs\scoping-risks.txt'))
$firstSev = ''
foreach ($l in $risks) { if ($l -match '\((Critical|High|Medium|Low|Info)/') { $firstSev = $Matches[1]; break } }
Assert-That -Name ("scoping-risks.txt leads with the highest severity present (got '{0}')" -f $firstSev) -Ok ($firstSev -in @('Critical','High'))

if ($KeepOutput) { Write-Host ''; Write-Host ("Output kept at: {0}" -f $out) -ForegroundColor Yellow }
else { try { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue } catch { } }

Write-Host ''
if ($fail -eq 0) { Write-Host 'OUTPUT SMOKE TEST PASSED' -ForegroundColor Green; exit 0 }
Write-Host ("OUTPUT SMOKE TEST FAILED - {0} assertion(s)" -f $fail) -ForegroundColor Red; exit 1
