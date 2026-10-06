<#
.SYNOPSIS
    Verifies one or more Discover-WindowsServer output folders and writes a compact report
    that is safe to share outside the environment the discovery ran in.

.DESCRIPTION
    Discovery output is client data: share paths, ACLs, service accounts, listening ports,
    event-log samples, certificate subjects. Verifying that the toolkit WORKED needs only
    structure and counts, not content. This script reports counts, booleans, field-name
    presence and category labels - never a collected value.

    What it checks:
      1  Structural health: every declared artifact present, all json/ exports are valid
         JSON arrays, csv/ and json/ agree, workbook.xml parses, HTML is closed.
      2  Dataset population: row count per dataset.
      3  The server-specific paths that a workstation cannot exercise -
         SQL BinaryPath -> CriticalPaths, the deep share crawl's recycle-bin fields,
         fingerprint matchers sourced from ListeningPorts / IisSites, raw\userrights.inf,
         and RolesFeatures via Get-WindowsFeature rather than the DISM fallback.
      4  Regression sanity for the defects fixed during validation (F29, F32, F33).
      5  ProjectType emphasis: with two or more runs, asserts findings and severities are
         identical and only the priority marking differs.
      6  Redaction audit in both directions: what got redacted (by triggering keyword only)
         and whether anything credential-shaped survived (masked).

    Read-only. It never modifies the run folder.

.PARAMETER Path
    One or more discovery output folders (the Discover-WindowsServer_<host>_<stamp> ones).
    Pass two runs that differ only by -ProjectType to enable the emphasis comparison.

.PARAMETER ReportPath
    Where to write the report. Defaults to .\discovery-verification-report.txt

.PARAMETER IncludeHostName
    Include the real computer name. Off by default - it is replaced with a short stable
    hash so two runs of the same host can still be correlated.

.EXAMPLE
    .\tools\Verify-DiscoveryRun.ps1 -Path C:\Temp\Discover-WindowsServer_SRV01_20260822_101500

.EXAMPLE
    # Two runs differing only by -ProjectType enables the emphasis comparison.
    .\tools\Verify-DiscoveryRun.ps1 -Path C:\Temp\Run_Decommission, C:\Temp\Run_CMMC
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string[]]$Path,
    [string]$ReportPath = '.\discovery-verification-report.txt',
    [switch]$IncludeHostName
)

$ErrorActionPreference = 'Continue'
# Deliberately distinctive. At SCRIPT scope a bare $lines refers to this same variable,
# so a check doing "$lines = ..." would silently overwrite the entire report with its own
# data. That happened during development: the userrights.inf check replaced the report with
# raw privilege assignments. Do not rename this to anything a check might use as a local.
$script:ReportLines = [System.Collections.Generic.List[string]]::new()

function W { param([string]$Text = '') $script:ReportLines.Add($Text); Write-Host $Text }
function Section { param([string]$Title)
    W ''
    W ('=' * 78)
    W $Title
    W ('=' * 78)
}
function Verdict {
    param([string]$Name, [string]$State, [string]$Detail = '')
    # State: PASS / FAIL / BLOCKED / INFO
    W ("  [{0,-7}] {1}{2}" -f $State, $Name, $(if ($Detail) { " - $Detail" } else { '' }))
}

# ---------------------------------------------------------------------------
# Layout resolution.
#
# The run folder now has two top-level directories - reports\ and evidence\ -
# instead of a flat root with a dozen siblings. This verifier has to keep working
# against BOTH, because run folders produced before the change still need to be
# verifiable, and a verifier that only understands the current layout would report
# a perfectly good older run as structurally broken.
#
# Every path lookup below goes through these two helpers. Nothing hardcodes a
# folder name at the point of use.
# ---------------------------------------------------------------------------

$script:LayoutMap = [ordered]@{
    # logical name          = @(new layout, legacy layout)
    'json'                  = @('evidence\data\json', 'json')
    'csv'                   = @('evidence\data\csv', 'csv')
    'logs'                  = @('evidence\logs', 'logs')
    'raw'                   = @('evidence\raw', 'raw')
    'status'                = @('evidence\status', 'status')
    'manifest'              = @('evidence\manifest', 'evidence')
    'reports'               = @('reports', '.')
    'supporting'            = @('reports\supporting', '.')
    'evidenceroot'          = @('evidence', '.')
}

function Resolve-RunDir {
    <# Returns the first directory that exists for a logical name, or the preferred one. #>
    param([string]$Run, [string]$Logical)
    $candidates = $script:LayoutMap[$Logical.ToLowerInvariant()]
    if (-not $candidates) { return (Join-Path $Run $Logical) }
    foreach ($c in $candidates) {
        $full = if ($c -eq '.') { $Run } else { Join-Path $Run $c }
        if (Test-Path -LiteralPath $full) { return $full }
    }
    return (Join-Path $Run $candidates[0])
}

function Resolve-RunFile {
    <#
        Finds a named file by trying each candidate relative path in order. Accepts a
        list so a file that was renamed (internal-report.html -> reports\internal-
        engineering-report.html) still resolves in an older run.
        Returns $null when none exist, so callers can report BLOCKED rather than FAIL.
    #>
    param([string]$Run, [string[]]$Candidates)
    foreach ($rel in $Candidates) {
        $full = Join-Path $Run ($rel -replace '/', '\')
        if (Test-Path -LiteralPath $full) { return $full }
    }
    return $null
}

function Get-ShortId {
    param([string]$Value)
    if (-not $Value) { return 'none' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant()))
    return ('h' + (($b[0..3] | ForEach-Object { $_.ToString('x2') }) -join ''))
}

function Read-Json {
    param([string]$File)
    if (-not (Test-Path -LiteralPath $File)) { return $null }
    if ((Get-Item -LiteralPath $File).Length -eq 0) { return @() }
    try { return (Get-Content -LiteralPath $File -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return 'ERR' }
}

function Get-DataSetRows {
    param([string]$Run, [string]$Name)
    $file = Join-Path (Resolve-RunDir -Run $Run -Logical 'json') ("$Name.json")
    if (-not (Test-Path -LiteralPath $file)) { return $null }   # not exported at all

    $raw = ''
    try { $raw = Get-Content -LiteralPath $file -Raw -Encoding UTF8 } catch { return 'ERR' }

    # '[]' must count as ZERO rows. ConvertFrom-Json turns it into $null, and @($null) is a
    # ONE-element array containing $null - so wrapping the parse result directly reports an
    # empty dataset as populated. (This is the same 5.1/7 unrolling trap recorded in TODO.md;
    # it bit this very script on its first run.)
    if ($null -eq $raw) { return @() }
    $trimmed = $raw.Trim()
    if ($trimmed -eq '' -or $trimmed -eq '[]') { return @() }

    $v = $null
    try { $v = $trimmed | ConvertFrom-Json } catch { return 'ERR' }
    if ($null -eq $v) { return @() }
    return @($v | Where-Object { $null -ne $_ })
}

function Get-FieldNames {
    param($Rows)
    $r = @($Rows)
    if ($r.Count -eq 0) { return @() }
    return @($r[0].PSObject.Properties.Name)
}

function Test-HasField {
    param($Rows, [string]$Field)
    return ((Get-FieldNames -Rows $Rows) -contains $Field)
}

function Count-Populated {
    param($Rows, [string]$Field)
    return @(@($Rows) | Where-Object {
        $v = $_.$Field
        ($null -ne $v) -and ([string]$v).Trim() -ne ''
    }).Count
}

# ---------------------------------------------------------------------------
$runs = @()
foreach ($p in $Path) {
    $rp = try { (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { $null }
    if (-not $rp) { Write-Warning "Not found: $p"; continue }
    $runs += $rp
}
if ($runs.Count -eq 0) { Write-Error 'No valid run folders supplied.'; exit 2 }

W 'Discover-WindowsServer - run verification report'
W ('Generated : {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
W ('Verifier  : tools\Verify-DiscoveryRun.ps1')
W ('Runtime   : PowerShell {0}' -f $PSVersionTable.PSVersion)
W ''
W 'This report contains counts, field names and pass/fail verdicts only - no collected'
W 'values, no host or share names, no account names. It is intended to be shareable.'

# ===========================================================================
Section '0. RUN IDENTITY AND HEADLINE COUNTERS'
$meta = @{}
foreach ($run in $runs) {
    $metaFile = Resolve-RunFile -Run $run -Candidates @('evidence\collection-metadata.json','collection-metadata.json')
    $m = if ($metaFile) { Read-Json $metaFile } else { $null }
    if (-not $m -or $m -eq 'ERR') { Verdict "metadata for $(Split-Path $run -Leaf)" 'FAIL' 'collection-metadata.json missing or unparseable'; continue }
    $meta[$run] = $m
    $hostLabel = if ($IncludeHostName) { [string]$m.ComputerName } else { Get-ShortId ([string]$m.ComputerName) }
    W ''
    W ("  run        : {0}" -f (Split-Path $run -Leaf))
    W ("  host       : {0}   (product type / SKU is shown below)" -f $hostLabel)
    W ("  mode       : {0}    projectType: {1}    complianceLens: {2}" -f $m.Mode, $m.ProjectType, $m.ComplianceLens)
    W ("  elevated   : {0}    psVersion: {1}    duration: {2}s" -f $m.IsAdmin, $m.PowerShellVersion, $m.DurationSeconds)
    $c = $m.Counters
    W ("  counters   : findings={0} limitations={1} errors={2} warnings={3} questions={4}" -f `
        $c.Findings, $c.Limitations, $c.Errors, $c.Warnings, $c.Questions)
    W ("  modules    : included={0} excluded={1}" -f @($m.IncludedModules).Count, @($m.ExcludedModules).Count)

    # Server vs workstation. The OperatingSystem dataset has no ProductType field, so
    # derive it from Caption / Edition. The OS product name is not client-identifying and
    # is needed to interpret everything below, so it is printed.
    $os = Get-DataSetRows -Run $run -Name 'OperatingSystem'
    if ($os -and $os -ne 'ERR' -and @($os).Count -gt 0) {
        $row = @($os)[0]
        $caption = [string]$row.Caption
        $isServer = ($caption -match '(?i)server') -or ([string]$row.Edition -match '(?i)server')
        W ("  os         : {0}  (edition: {1}, build {2})" -f $caption, $row.Edition, $row.BuildNumber)
        W ("  SKU        : {0}" -f $(if ($isServer) { 'SERVER - server-specific paths are exercisable' } else { 'workstation - items 2/3/5/7 will be BLOCKED' }))
    } else {
        W '  os         : OperatingSystem dataset empty - cannot determine SKU'
    }
}

# ===========================================================================
Section '1. STRUCTURAL HEALTH'
$outCfgPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config\output-settings.json'
$required = @()
if (Test-Path -LiteralPath $outCfgPath) {
    $oc = Read-Json $outCfgPath
    if ($oc -and $oc -ne 'ERR' -and $oc.requiredOutputFiles) { $required = @($oc.requiredOutputFiles) }
}

foreach ($run in $runs) {
    W ''
    W ("  -- {0}" -f (Split-Path $run -Leaf))

    if ($required.Count -gt 0) {
        $miss = @(); $zero = @()
        foreach ($rel in $required) {
            $f = Join-Path $run ($rel -replace '/', '\')
            if (-not (Test-Path -LiteralPath $f)) { $miss += $rel }
            elseif ((Get-Item -LiteralPath $f).Length -eq 0 -and $rel -notmatch '(errors|warnings)\.txt$') { $zero += $rel }   # empty is correct on a clean run
        }
        Verdict 'required artifacts' $(if ($miss.Count -or $zero.Count) { 'FAIL' } else { 'PASS' }) `
            ("{0} declared, {1} missing, {2} zero-byte" -f $required.Count, $miss.Count, $zero.Count)
        if ($miss.Count) { W ("           missing: {0}" -f ($miss -join ', ')) }
        if ($zero.Count) { W ("           zero   : {0}" -f ($zero -join ', ')) }
    }

    # json/ exports must ALL be valid JSON arrays (F32).
    $jdir = Resolve-RunDir -Run $run -Logical 'json'
    $bad = @(); $notArr = @(); $total = 0
    if (Test-Path -LiteralPath $jdir) {
        foreach ($f in (Get-ChildItem -LiteralPath $jdir -Filter *.json -File)) {
            $total++
            if ($f.Length -eq 0) { $bad += $f.Name; continue }
            $v = Read-Json $f.FullName
            if ($v -eq 'ERR') { $bad += $f.Name; continue }
            # A dataset export must be an array at every row count.
            $raw = (Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8).TrimStart()
            if (-not $raw.StartsWith('[')) { $notArr += $f.Name }
        }
    }
    Verdict 'all json/ exports are valid JSON arrays (F32)' $(if ($bad.Count -or $notArr.Count) { 'FAIL' } else { 'PASS' }) `
        ("{0} files, {1} invalid/zero-byte, {2} not-an-array" -f $total, $bad.Count, $notArr.Count)
    if ($bad.Count)    { W ("           invalid  : {0}" -f (($bad    | Select-Object -First 8) -join ', ')) }
    if ($notArr.Count) { W ("           not array: {0}" -f (($notArr | Select-Object -First 8) -join ', ')) }

    $nc = @(Get-ChildItem -LiteralPath (Resolve-RunDir -Run $run -Logical 'csv') -Filter *.csv -File -ErrorAction SilentlyContinue).Count
    Verdict 'csv/ and json/ counts agree' $(if ($nc -eq $total) { 'PASS' } else { 'FAIL' }) ("csv={0} json={1}" -f $nc, $total)

    $wb = Resolve-RunFile -Run $run -Candidates @('reports\supporting\workbook.xml','workbook.xml')
    if ($wb) {
        try {
            $x = New-Object System.Xml.XmlDocument
            $x.Load($wb)
            $sheets = $x.GetElementsByTagName('Worksheet').Count
            Verdict 'workbook.xml well-formed' 'PASS' ("{0} worksheets, {1:N1} MB" -f $sheets, ((Get-Item $wb).Length / 1MB))
        } catch { Verdict 'workbook.xml well-formed' 'FAIL' $_.Exception.Message }
    }

    $html = Resolve-RunFile -Run $run -Candidates @('reports\internal-engineering-report.html','internal-report.html')
    if ($html) {
        $h = Get-Content -LiteralPath $html -Raw -Encoding UTF8
        $closed = $h.TrimEnd().EndsWith('</html>')
        $cards = ([regex]::Matches($h, 'class="card')).Count
        Verdict 'internal-report.html closed + renders findings' $(if ($closed -and $cards -gt 0) { 'PASS' } else { 'FAIL' }) `
            ("{0:N0} KB, {1} finding cards, prioritySection={2}" -f ($h.Length / 1KB), $cards, $h.Contains('Priority For This Project Type'))
    }

    $dashHtml = Resolve-RunFile -Run $run -Candidates @('reports\internal-dashboard-report.html')
    if ($dashHtml) {
        $dh = Get-Content -LiteralPath $dashHtml -Raw -Encoding UTF8
        $dashClosed = $dh.TrimEnd().EndsWith('</html>')
        $navLinks = ([regex]::Matches($dh, 'class="navlink')).Count
        Verdict 'internal-dashboard-report.html closed + has nav' $(if ($dashClosed -and $navLinks -gt 0) { 'PASS' } else { 'FAIL' }) `
            ("{0:N0} KB, {1} nav sections" -f ($dh.Length / 1KB), $navLinks)
    }

    # Every attested hash must verify. Match on RelativePath, never FileName - summary.txt
    # exists at both the root and logs\, so a name-based match reports false mismatches.
    # Files still being written when the manifest runs (status\, logs\) are deliberately
    # excluded from it; collection-metadata.json records that as UnhashedPaths.
    $hashFile = Resolve-RunFile -Run $run -Candidates @('evidence\manifest\hashes.sha256','evidence\hashes.sha256')
    if ($hashFile) {
        $mismatch = @(); $absent = @(); $ok = 0
        foreach ($line in (Get-Content -LiteralPath $hashFile -Encoding UTF8)) {
            if ($line -notmatch '^([0-9A-Fa-f]{64})\s+\*(.+)$') { continue }
            $expect = $Matches[1]; $rel = $Matches[2]
            $fp = Join-Path $run $rel
            if (-not (Test-Path -LiteralPath $fp)) { $absent += $rel; continue }
            if ((Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash -eq $expect) { $ok++ } else { $mismatch += $rel }
        }
        Verdict 'every attested hash verifies' $(if ($mismatch.Count -or $absent.Count) { 'FAIL' } else { 'PASS' }) `
            ("{0} verified, {1} mismatched, {2} missing" -f $ok, $mismatch.Count, $absent.Count)
        if ($mismatch.Count) { W ("           mismatch : {0}" -f (($mismatch | Select-Object -First 8) -join ', ')) }
        if ($absent.Count)   { W ("           missing  : {0}" -f (($absent   | Select-Object -First 8) -join ', ')) }
    }

    # scream-test-plan.md: per-function sections, and no array that failed to stringify.
    $stp = Resolve-RunFile -Run $run -Candidates @('reports\supporting\scream-test-plan.md','scream-test-plan.md')
    if ($stp) {
        $stl = Get-Content -LiteralPath $stp -Encoding UTF8
        $secs = @($stl | Where-Object { $_ -like '## *' }).Count
        $objLeak = @($stl -match 'System\.Object').Count
        $widest = ($stl | Measure-Object -Property Length -Maximum).Maximum
        Verdict 'scream-test-plan.md renders readably' $(if ($secs -gt 0 -and $objLeak -eq 0 -and $widest -lt 400) { 'PASS' } else { 'FAIL' }) `
            ("{0} sections, {1} Object[] leaks, widest line {2} chars" -f $secs, $objLeak, $widest)
    }

    foreach ($n in 'errors.txt', 'warnings.txt') {
        # Under the two-folder layout these live only in evidence\logs\ - the engine no
        # longer writes a duplicate at the run root, because that duplicate would have
        # overwritten the live log and truncated anything logged after output generation.
        $f = Resolve-RunFile -Run $run -Candidates @(("evidence\logs\" + $n), $n, ("logs\" + $n))
        if ($f) {
            $len = (Get-Item -LiteralPath $f).Length
            # Judge by CONTENT, not length. Windows PowerShell writes a UTF-8 BOM, so an
            # empty errors.txt is 3 bytes of BOM plus a CRLF - 5 bytes of nothing. Reading
            # length alone reported a perfectly clean server run as INFO.
            $body = ''
            try { $body = (Get-Content -LiteralPath $f -Raw -Encoding UTF8) } catch { }
            if ($null -ne $body) { $body = $body.Trim([char]0xFEFF).Trim() }
            $hasContent = -not [string]::IsNullOrWhiteSpace($body)
            $lineCount = if ($hasContent) { @($body -split "`r?`n" | Where-Object { $_.Trim() }).Count } else { 0 }
            Verdict "$n" $(if ($n -eq 'errors.txt' -and $hasContent) { 'INFO' } else { 'PASS' }) `
                ("{0} bytes, {1} content line(s){2}" -f $len, $lineCount, $(if (-not $hasContent) { ' - empty' } else { '' }))
        }
    }
}

# ===========================================================================
Section '2. DATASET POPULATION (row counts only)'
$primary = $runs[0]
$jdir = Resolve-RunDir -Run $primary -Logical 'json'
$names = @(Get-ChildItem -LiteralPath $jdir -Filter *.json -File -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName } | Sort-Object)
$pop = @(); $emptyList = @()
foreach ($n in $names) {
    $r = Get-DataSetRows -Run $primary -Name $n
    $cnt = if ($r -eq 'ERR') { -1 } else { @($r).Count }
    if ($cnt -gt 0) { $pop += [pscustomobject]@{ Name = $n; Rows = $cnt } } else { $emptyList += $n }
}
W ("  datasets: {0} total, {1} populated, {2} empty" -f $names.Count, $pop.Count, $emptyList.Count)
W ''
W '  populated:'
foreach ($x in ($pop | Sort-Object -Property Rows -Descending)) { W ("    {0,-36} {1,7}" -f $x.Name, $x.Rows) }
W ''
W '  empty:'
W ('    ' + (($emptyList) -join ', '))

# ===========================================================================
Section '3. SERVER-SPECIFIC PATHS (the point of running this on a server)'

# --- RolesFeatures: primary Get-WindowsFeature path, not the DISM/optional-features fallback
$lim = ''
$limFile = Resolve-RunFile -Run $primary -Candidates @('evidence\logs\limitations.txt','limitations.txt','logs\limitations.txt')
if ($limFile) { $lim = Get-Content -LiteralPath $limFile -Raw -Encoding UTF8 }
$usedFallback = $lim -match 'Get-WindowsFeature not present'
$rf = Get-DataSetRows -Run $primary -Name 'RolesFeatures'
$rfCount = if ($rf -and $rf -ne 'ERR') { @($rf).Count } else { 0 }
Verdict 'RolesFeatures used the Get-WindowsFeature primary path' $(if ($usedFallback) { 'BLOCKED' } else { 'PASS' }) `
    ("rows={0}; fallbackLimitationPresent={1}  (this code path has never executed before)" -f $rfCount, [bool]$usedFallback)
$rawRf = Resolve-RunFile -Run $primary -Candidates @('evidence\raw\RolesFeatures.raw.json','raw\RolesFeatures.raw.json')
if ($rawRf) {
    # Report BYTES, not KB. A 168-byte file rounds to "0 KB" and reads like a failure.
    $rawLen = (Get-Item -LiteralPath $rawRf).Length
    Verdict 'raw\RolesFeatures.raw.json written' $(if ($rawLen -gt 2) { 'PASS' } else { 'FAIL' }) `
        ("{0:N0} bytes" -f $rawLen)
} else {
    Verdict 'raw\RolesFeatures.raw.json written' 'FAIL' 'absent'
}

# --- Item 7: raw\userrights.inf, Se* only, no secrets
$ur = Resolve-RunFile -Run $primary -Candidates @('evidence\raw\userrights.inf','raw\userrights.inf')
if ($ur) {
    $txt = Get-Content -LiteralPath $ur -Raw
    $urLines = @($txt -split "`r?`n" | Where-Object { $_.Trim() })
    $se = @($urLines | Where-Object { $_.Trim() -match '^Se[A-Za-z]+' })
    $assign = @($urLines | Where-Object { $_ -match '=' -and $_.Trim() -notmatch '^Se[A-Za-z]+' -and $_.Trim() -notmatch '^\[' })
    $secretish = ([regex]::Matches($txt, '(?i)(password|secret|privatekey|BEGIN [A-Z ]*PRIVATE)')).Count
    Verdict 'raw\userrights.inf written (needs elevation)' 'PASS' ("{0} lines" -f $urLines.Count)
    Verdict 'userrights.inf holds only Se* privilege assignments' $(if ($assign.Count -eq 0) { 'PASS' } else { 'INFO' }) `
        ("Se* lines={0}, other assignment lines={1}" -f $se.Count, $assign.Count)
    Verdict 'userrights.inf contains no secret-shaped tokens' $(if ($secretish -eq 0) { 'PASS' } else { 'FAIL' }) `
        ("matches={0}" -f $secretish)
} else {
    Verdict 'raw\userrights.inf written' 'BLOCKED' 'absent - secedit /export needs an elevated session'
}

# --- Item 2: SQL BinaryPath -> CriticalPaths
$sql = Get-DataSetRows -Run $primary -Name 'SqlInstances'
$sqlN = if ($sql -and $sql -ne 'ERR') { @($sql).Count } else { 0 }
if ($sqlN -eq 0) {
    Verdict 'SQL BinaryPath -> CriticalPaths (F6)' 'BLOCKED' 'SqlInstances is empty - no SQL on this host'
} else {
    $hasField = Test-HasField -Rows $sql -Field 'BinaryPath'
    $withBin = if ($hasField) { Count-Populated -Rows $sql -Field 'BinaryPath' } else { 0 }
    $cp = Get-DataSetRows -Run $primary -Name 'CriticalPaths'
    $sqlSourced = @(@($cp) | Where-Object { "$($_.Source)" -eq 'SQL' }).Count
    Verdict 'SqlInstances emits a populated BinaryPath' $(if ($withBin -gt 0) { 'PASS' } else { 'FAIL' }) `
        ("instances={0}, BinaryPath field present={1}, populated={2}" -f $sqlN, $hasField, $withBin)
    Verdict 'CriticalPaths contains a SQL-sourced row (F6)' $(if ($sqlSourced -gt 0) { 'PASS' } else { 'FAIL' }) `
        ("SQL-sourced rows={0} of {1}" -f $sqlSourced, @($cp).Count)
    $deep = @(@($sql) | Where-Object { "$($_.DeepQueryPerformed)" -eq 'True' }).Count
    Verdict 'SQL deep query performed' 'INFO' ("{0} of {1} instances (needs -AttemptSqlIntegratedAuth + rights)" -f $deep, $sqlN)
}

# --- Item 3: deep share crawl + recycle-bin fields
$acl = Get-DataSetRows -Run $primary -Name 'NtfsAclSummary'
$aclN = if ($acl -and $acl -ne 'ERR') { @($acl).Count } else { 0 }
$fss = Get-DataSetRows -Run $primary -Name 'FileShareSummary'
if ($fss -and $fss -ne 'ERR' -and @($fss).Count -gt 0) {
    $f0 = @($fss)[0]
    W ("  share context: ShareCount={0} UserShareCount={1} DeepScanPerformed={2} DeepScannedShares={3}" -f `
        $f0.ShareCount, $f0.UserShareCount, $f0.DeepScanPerformed, $f0.DeepScannedShares)
}
if ($aclN -eq 0) {
    Verdict 'recycle-bin exclusion fields (F5)' 'BLOCKED' 'NtfsAclSummary empty - no user shares were deep-crawled'
} else {
    foreach ($fld in 'RecycleBinIncluded', 'RecycleBinFilesFound', 'RecycleBinSizeGB', 'TotalSizeGB') {
        Verdict ("NtfsAclSummary has {0}" -f $fld) $(if (Test-HasField -Rows $acl -Field $fld) { 'PASS' } else { 'FAIL' })
    }
    $incl = @(@($acl) | ForEach-Object { "$($_.RecycleBinIncluded)" } | Sort-Object -Unique)
    $binGB = 0.0
    foreach ($r in @($acl)) { $v = 0.0; if ([double]::TryParse("$($r.RecycleBinSizeGB)", [ref]$v)) { $binGB += $v } }
    $totGB = 0.0
    foreach ($r in @($acl)) { $v = 0.0; if ([double]::TryParse("$($r.TotalSizeGB)", [ref]$v)) { $totGB += $v } }
    Verdict 'recycle bin reported separately' 'PASS' `
        ("rows={0}, RecycleBinIncluded values={1}, summed RecycleBinSizeGB={2:N2}, summed TotalSizeGB={3:N2}" -f `
            $aclN, ($incl -join '/'), $binGB, $totGB)
    W '           To finish F5: re-run the same command adding -IncludeRecycleBin and confirm'
    W '           RecycleBinIncluded flips to True and summed TotalSizeGB grows by roughly the'
    W '           RecycleBinSizeGB above. Then pass both runs to this script.'
}

# --- Item 5: fingerprint matchers sourced from ListeningPorts / IisSites
$fp = Get-DataSetRows -Run $primary -Name 'ApplicationFingerprints'
$lp = Get-DataSetRows -Run $primary -Name 'ListeningPorts'
$iis = Get-DataSetRows -Run $primary -Name 'IisSites'
$lpN = if ($lp -and $lp -ne 'ERR') { @($lp).Count } else { 0 }
$iisN = if ($iis -and $iis -ne 'ERR') { @($iis).Count } else { 0 }
$srcTally = @{}
foreach ($r in @($fp)) {
    foreach ($part in ("$($r.EvidenceSource)" -split ';')) {
        $k = $part.Trim(); if ($k) { $srcTally[$k] = 1 + [int]$srcTally[$k] }
    }
}
$viaLate = @($srcTally.Keys | Where-Object { $_ -in @('ListeningPorts', 'IisSites', 'SqlInstances') })
Verdict 'fingerprint inputs available post-collection (F19)' $(if ($lpN -gt 0) { 'PASS' } else { 'FAIL' }) `
    ("ListeningPorts rows={0}, IisSites rows={1}" -f $lpN, $iisN)

# Composition of ListeningPorts. Ephemeral sockets (>= 49152, the Windows dynamic range)
# are not services and are never scoping evidence, but a DNS server opens thousands of
# them - on the first real DC run they were 5040 of 5145 rows.
if ($lpN -gt 0 -and (Test-HasField -Rows $lp -Field 'LocalPort')) {
    $eph = 0; $wellKnown = 0; $registered = 0
    $udp = 0; $tcp = 0
    foreach ($r in @($lp)) {
        $p = 0
        if ([int]::TryParse("$($r.LocalPort)", [ref]$p)) {
            if ($p -ge 49152) { $eph++ } elseif ($p -lt 1024) { $wellKnown++ } else { $registered++ }
        }
        if ("$($r.Protocol)" -eq 'UDP') { $udp++ } elseif ("$($r.Protocol)" -eq 'TCP') { $tcp++ }
    }
    $ephPct = if ($lpN) { [math]::Round(100.0 * $eph / $lpN, 1) } else { 0 }
    Verdict 'ListeningPorts signal-to-noise' $(if ($ephPct -ge 50) { 'INFO' } else { 'PASS' }) `
        ("TCP={0} UDP={1}; ports: wellKnown={2} registered={3} EPHEMERAL={4} ({5}%)" -f `
            $tcp, $udp, $wellKnown, $registered, $eph, $ephPct)
    if ($ephPct -ge 50) {
        W '           Ephemeral sockets dominate this dataset. They are not listening services.'
        W '           See TODO.md - filtering or flagging them is an open recommendation.'
    }
}
Verdict 'a ListeningPorts/IisSites/SqlInstances matcher actually fired (F19)' `
    $(if ($viaLate.Count -gt 0) { 'PASS' } else { 'BLOCKED' }) `
    ("fingerprints={0}; evidence sources used: {1}" -f @($fp).Count, (($srcTally.Keys | Sort-Object) -join ', '))

# ===========================================================================
Section '4. REGRESSION SANITY FOR DEFECTS FIXED DURING VALIDATION'

# F33 - collection no longer suppressed by a broken cmdlet probe
$f33 = @{}
foreach ($n in 'ListeningPorts', 'FirewallRules', 'LocalGroups', 'Partitions', 'EstablishedConnections', 'PrinterDrivers') {
    $r = Get-DataSetRows -Run $primary -Name $n
    $f33[$n] = if ($r -and $r -ne 'ERR') { @($r).Count } else { 0 }
}
$zeroes = @($f33.Keys | Where-Object { $f33[$_] -eq 0 })
Verdict 'F33 - optional-cmdlet datasets are populated' $(if ($zeroes.Count -eq 0) { 'PASS' } else { 'INFO' }) `
    (($f33.Keys | Sort-Object | ForEach-Object { "$_=$($f33[$_])" }) -join ' ')
if ($zeroes.Count) {
    W ("           still zero: {0}" -f ($zeroes -join ', '))
    W '           On a server these should all be non-zero. A zero here means either the role'
    W '           genuinely is absent, or a cmdlet probe is failing again - check limitations.txt'
    W '           for a "not available" message naming that cmdlet.'
}
$falseLim = @()
foreach ($pat in 'Get-NetFirewallRule not available', 'Get-NetTCPConnection') {
    if ($lim -match [regex]::Escape($pat)) { $falseLim += $pat }
}
Verdict 'F33 - no "cmdlet not available" limitation for core network cmdlets' `
    $(if ($falseLim.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
    $(if ($falseLim.Count) { "present: $($falseLim -join '; ')" } else { 'none' })

# F29 - datasetNotEmpty must fire for single-row datasets
$single = @($pop | Where-Object { $_.Rows -eq 1 } | ForEach-Object { $_.Name })
Verdict 'F29 - single-row datasets exist to exercise datasetNotEmpty' 'INFO' `
    ("{0} datasets have exactly 1 row: {1}" -f $single.Count, (($single | Select-Object -First 10) -join ', '))

# ===========================================================================
Section '5. PROJECTTYPE EMPHASIS (needs two runs differing only by -ProjectType)'
if ($runs.Count -lt 2) {
    Verdict 'emphasis comparison' 'BLOCKED' 'supply two run folders that differ only by -ProjectType'
} else {
    $sets = @()
    foreach ($run in $runs) {
        $w = Resolve-RunFile -Run $run -Candidates @('reports\supporting\wbs-inputs.csv','wbs-inputs.csv')
        if (-not $w) { continue }
        $rows = @(Import-Csv -LiteralPath $w)
        $sets += [pscustomobject]@{
            Run    = Split-Path $run -Leaf
            PT     = [string]$meta[$run].ProjectType
            Rows   = $rows.Count
            Key    = (($rows | ForEach-Object { "$($_.Finding)|$($_.Complexity)" } | Sort-Object) -join "`n")
            Pri    = @($rows | Where-Object { "$($_.PriorityForProject)" -eq 'True' }).Count
            PriSet = (($rows | Where-Object { "$($_.PriorityForProject)" -eq 'True' } | ForEach-Object { $_.Finding } | Sort-Object -Unique) -join '|')
        }
    }
    foreach ($s in $sets) { W ("  {0,-16} rows={1,-5} prioritised={2}" -f $s.PT, $s.Rows, $s.Pri) }
    if ($sets.Count -ge 2) {
        $identical = ($sets[0].Key -eq $sets[1].Key)
        Verdict 'findings + severities identical across project types (F2/F18)' $(if ($identical) { 'PASS' } else { 'FAIL' }) `
            ("emphasis must be presentation only; rows {0} vs {1}" -f $sets[0].Rows, $sets[1].Rows)
        $differ = ($sets[0].PriSet -ne $sets[1].PriSet)
        Verdict 'prioritised sets differ between project types' $(if ($differ) { 'PASS' } else { 'INFO' }) `
            ("{0}={1} prioritised, {2}={3}" -f $sets[0].PT, $sets[0].Pri, $sets[1].PT, $sets[1].Pri)
    }
}

# ===========================================================================
Section '6. REDACTION AUDIT (both directions, values never shown)'
$keywords = 'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'api-key',
            'credential', 'community', 'bearer', 'accesskey', 'access_key', 'privatekey', 'auth'
$redTotal = 0
$byKeyword = @{}
$scanned = 0
foreach ($f in (Get-ChildItem -LiteralPath $primary -Recurse -File -Include *.csv, *.json, *.txt, *.md, *.xml, *.html -ErrorAction SilentlyContinue)) {
    $scanned++
    $t = ''
    try { $t = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 } catch { continue }
    if (-not $t) { continue }
    $hits = [regex]::Matches($t, '([A-Za-z0-9_.\-]{2,60})\s*[:=]\s*\[REDACTED')
    $redTotal += ([regex]::Matches($t, '\[REDACTED')).Count
    foreach ($m in $hits) {
        $key = $m.Groups[1].Value.ToLowerInvariant()
        $kw = ($keywords | Where-Object { $key.Contains($_) } | Select-Object -First 1)
        if (-not $kw) { $kw = '<no known keyword in key>' }
        $byKeyword[$kw] = 1 + [int]$byKeyword[$kw]
    }
}
W ("  files scanned: {0}   total [REDACTED] markers: {1}" -f $scanned, $redTotal)
W ''
W '  which keyword triggered each keyed redaction (key names NOT shown):'
if ($byKeyword.Count -eq 0) { W '    (none - no keyed redactions in this run)' }
foreach ($k in ($byKeyword.Keys | Sort-Object { -$byKeyword[$_] })) {
    W ("    {0,-30} {1}" -f $k, $byKeyword[$k])
}
W ''
W '  NOTE: a high count against "community" is the known over-redaction of any key'
W '  containing that substring (intended for SNMP community strings). See TODO.md.'

# survivors: credential-shaped values that were NOT redacted
$shapes = @(
    # (?<!publickey) mirrors the toolkit's own redaction-patterns.json exception: a .NET
    # assembly publicKeyToken is a public identity hash, never a secret, and is common enough
    # in scanned config trees (assemblyIdentity/bindingRedirect elements) that without this the
    # verifier flags hundreds of them as "survived redaction" every run - a false alarm the
    # toolkit deliberately stopped hiding (see ConfigDependencyScan / redaction-patterns.json).
    @{ Name = 'key=value secret'; Rx = '(?i)(?:password|passwd|pwd|secret|apikey|api_key|(?<!publickey)token|credential)\s*[:=]\s*(?<v>"[^"]{2,}"|''[^'']{2,}''|[^\s;,)"'']{2,})' }
    @{ Name = 'bare JWT';         Rx = '(?<v>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})' }
    @{ Name = 'PEM private key';  Rx = '(?<v>-----BEGIN [A-Z ]*PRIVATE KEY-----)' }
    @{ Name = 'AWS access key';   Rx = '(?<v>AKIA[0-9A-Z]{16})' }
)
$survivors = @{}
foreach ($f in (Get-ChildItem -LiteralPath $primary -Recurse -File -Include *.csv, *.json, *.txt, *.md, *.xml, *.html -ErrorAction SilentlyContinue)) {
    $t = ''
    try { $t = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 } catch { continue }
    if (-not $t) { continue }
    foreach ($s in $shapes) {
        foreach ($m in [regex]::Matches($t, $s.Rx)) {
            $v = $m.Groups['v'].Value
            if ($v -match 'REDACTED') { continue }

            # Noise filters. Without these the scanner cries wolf, which is worse than
            # useless on a real server run - a spurious FAIL costs someone an afternoon.
            # Observed noise: XML/HTML entities and markup, and JSON pretty-print
            # punctuation such as '",\n    "' picked up when a key ends a line.
            if ($v -match '^(&quot|&apos|&amp|&lt|&gt|</)') { continue }
            $inner = $v.Trim([char]34).Trim([char]39)
            if ($inner -match '[\r\n]') { continue }              # spans lines - formatting
            if ($inner -match '[{}\[\]<>]') { continue }           # structural punctuation
            if ($inner -match '^[\s\p{P}]*$') { continue }         # punctuation/space only
            if ((($inner -replace '[^A-Za-z0-9]', '').Length) -lt 4) { continue }  # too short to be a secret

            $key = $s.Name
            $survivors[$key] = 1 + [int]$survivors[$key]
        }
    }
}
W ''
if ($survivors.Count -eq 0) {
    Verdict 'no credential-shaped value survived redaction' 'PASS' 'scanner found 0 survivors'
} else {
    Verdict 'credential-shaped values survived redaction' 'FAIL' 'INVESTIGATE - counts by shape below'
    foreach ($k in ($survivors.Keys | Sort-Object)) { W ("    {0,-24} {1}" -f $k, $survivors[$k]) }
    W '    Values are deliberately not printed. Grep the run folder locally to inspect.'
}

# ===========================================================================
Section '7. LIMITATIONS REPORTED BY THE RUN'
W '  (toolkit-authored messages. Review before sharing in case a path was interpolated.)'
W ''
if ($lim) { foreach ($l in ($lim -split "`r?`n")) { if ($l.Trim()) { W ('    ' + $l.Trim()) } } }
else { W '    (none)' }

# ===========================================================================
Section 'END'
$dir = Split-Path -Parent $ReportPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
# Self-guard. The report MUST look like a report. If a future edit reintroduces a
# script-scope variable collision, this catches it instead of writing collected data to a
# file labelled safe to share.
$reportText = ($script:ReportLines -join [Environment]::NewLine)
if ($reportText -notmatch 'Discover-WindowsServer - run verification report') {
    Write-Error 'INTERNAL: the report buffer does not look like a report - refusing to write it. This indicates a variable-scope collision in this script.'
    exit 3
}
if ($reportText -match '(?m)^\s*Se[A-Za-z]+Privilege\s*=' -or $reportText -match '(?m)^\[Privilege Rights\]') {
    Write-Error 'INTERNAL: the report buffer contains raw privilege-assignment data - refusing to write it.'
    exit 3
}
Set-Content -LiteralPath $ReportPath -Value $reportText -Encoding UTF8
Write-Host ''
Write-Host ("Report written to: {0}" -f (Resolve-Path -LiteralPath $ReportPath).Path) -ForegroundColor Green
Write-Host 'Review it once, then it is safe to share.' -ForegroundColor Green
