<#
.SYNOPSIS
    Static self-check for the Discover-WindowsServer toolkit. Verifies the contracts that
    nothing else enforces. Read-only: collects nothing from the host and writes nothing.

.DESCRIPTION
    A renamed dataset or field silently disables a risk rule - the engine does not error,
    the finding just never appears. These checks make that failure loud. Run before
    committing, and after editing any collector, risk rule, or module manifest.

    Checks:
      1  Every .ps1/.psm1/.psd1 parses.
      2  Every config/*.json parses.
      3  Each .psd1 FunctionsToExport matches its .psm1 Export-ModuleMember, and RootModule is right.
      4  Each module's metadata ProducesDatasets matches the datasets it actually Add-DataSets.
      5  Rule integrity: unique ids, valid regex, enum-legal severity/confidence/impact, required keys.
      6  Every rule condition type is implemented by the engine.
      7  Every rule's dataset is actually produced by some module.
      8  Every rule's condition field / evidenceField / {Token} exists in the producing module.
      9  Every field documented in FIELD-USAGE.md exists in its producing module.
     10  Compliance-lens category keys match real rule categories.
     11  No unread keys in the discovery config files (dead config).
     12  No PowerShell 5.1 array-unrolling hazards (see the section for why this matters).

.EXAMPLE
    .\tests\Invoke-ToolkitSelfCheck.ps1
.EXAMPLE
    .\tests\Invoke-ToolkitSelfCheck.ps1 -Quiet   # only failures + summary
#>
[CmdletBinding()]
param([switch]$Quiet)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:Checks = 0

function Test-Item {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $script:Checks++
    if ($Ok) { if (-not $Quiet) { Write-Host ("  [ ok ] {0}" -f $Name) -ForegroundColor DarkGray } }
    else {
        Write-Host ("  [FAIL] {0}" -f $Name) -ForegroundColor Red
        if ($Detail) { foreach ($l in @($Detail -split "`n")) { if ($l) { Write-Host ("         {0}" -f $l) -ForegroundColor Red } } }
        $script:Failures.Add($Name)
    }
}
function Write-Section { param([string]$Title) if (-not $Quiet) { Write-Host ''; Write-Host ("== {0}" -f $Title) -ForegroundColor Cyan } }

# ---- AST helpers ------------------------------------------------------------
function Get-Ast { param([string]$Path) [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null) }

function Get-CommandStringArg {
    <# Returns the string value of a named parameter on a CommandAst, or $null. #>
    param($CommandAst, [string]$ParameterName)
    $el = $CommandAst.CommandElements
    for ($i = 0; $i -lt $el.Count - 1; $i++) {
        if ($el[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $el[$i].ParameterName -eq $ParameterName) {
            if ($el[$i+1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $el[$i+1].Value }
            return $null
        }
    }
    return $null
}

function Get-AddDataSetNames {
    param($Ast)
    $names = @()
    foreach ($c in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        if ($c.GetCommandName() -ne 'Add-DataSet') { continue }
        $n = Get-CommandStringArg -CommandAst $c -ParameterName 'Name'
        if ($n) { $names += $n }
    }
    return @($names | Sort-Object -Unique)
}

function Get-ExportedFunctionNames {
    param($Ast)
    $fns = @()
    foreach ($c in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        if ($c.GetCommandName() -ne 'Export-ModuleMember') { continue }
        foreach ($e in $c.CommandElements) {
            if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $e.Value -ne 'Export-ModuleMember') { $fns += $e.Value }
            elseif ($e -is [System.Management.Automation.Language.ArrayLiteralAst]) {
                foreach ($x in $e.Elements) { if ($x -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $fns += $x.Value } }
            }
        }
    }
    return @($fns | Sort-Object -Unique)
}

function Get-DeclaredProducesDatasets {
    param($Ast)
    $declared = @()
    foreach ($h in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)) {
        foreach ($kv in $h.KeyValuePairs) {
            if ($kv.Item1.Extent.Text -match 'ProducesDatasets') {
                foreach ($sc in $kv.Item2.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) { $declared += $sc.Value }
            }
        }
    }
    return @($declared | Sort-Object -Unique)
}

function Get-FileSymbolSet {
    <# Every hashtable key and member name in a file - i.e. the field names it can emit. #>
    param($Ast)
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($h in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)) {
        foreach ($kv in $h.KeyValuePairs) {
            if ($kv.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) { [void]$set.Add($kv.Item1.Value) }
        }
    }
    foreach ($m in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)) {
        if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { [void]$set.Add($m.Member.Value) }
    }
    return $set
}

# ---- 1. Parse ---------------------------------------------------------------
Write-Section 'PowerShell parses'
# -Include is SILENTLY IGNORED when combined with -LiteralPath on Windows PowerShell
# 5.1, so this used to enumerate every file in the tree and try to parse .md / .json /
# .yml / .gitignore as PowerShell. PowerShell 7 honours it, which is why the bug was
# invisible on the audit machine and only surfaced when 5.1 was added to CI.
# Filtering on the extension explicitly behaves identically on both runtimes.
#
# .git is excluded as well: it holds thousands of files, none of them toolkit source.
# (Get-ChildItem without -Force already skips it because git marks it hidden on
# Windows, but relying on a file attribute for correctness is too fragile.)
$psExtensions = @('.ps1', '.psm1', '.psd1')
$psFiles = @(
    Get-ChildItem -LiteralPath $root -Recurse -File |
        Where-Object {
            $psExtensions -contains $_.Extension -and
            $_.FullName -notlike (Join-Path $root '.git\*')
        } |
        Sort-Object FullName
)
foreach ($f in $psFiles) {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    $rel = $f.FullName.Substring($root.Length + 1)
    Test-Item -Name ("parses: {0}" -f $rel) -Ok (-not ($errs -and $errs.Count)) -Detail $(if ($errs -and $errs.Count) { ($errs | ForEach-Object { "L$($_.Extent.StartLineNumber): $($_.Message)" }) -join "`n" } else { '' })
}

# ---- 2. JSON ----------------------------------------------------------------
Write-Section 'JSON parses'
$cfgDir = Join-Path $root 'config'
$cfg = @{}
foreach ($f in (Get-ChildItem -LiteralPath $cfgDir -Filter *.json -File)) {
    $ok = $true; $detail = ''
    try { $cfg[$f.BaseName] = (Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $ok = $false; $detail = $_.Exception.Message }
    Test-Item -Name ("valid JSON: config/{0}" -f $f.Name) -Ok $ok -Detail $detail
}

# ---- Build the module map ---------------------------------------------------
$moduleDirs = @(Get-ChildItem -LiteralPath (Join-Path $root 'modules') -Directory)
$produced = @{}     # dataset -> list of "module"
$symbols  = @{}     # module  -> symbol set
foreach ($d in $moduleDirs) {
    $psm1 = Join-Path $d.FullName ("{0}.psm1" -f $d.Name)
    if (-not (Test-Path -LiteralPath $psm1)) { continue }
    $ast = Get-Ast -Path $psm1
    $symbols[$d.Name] = Get-FileSymbolSet -Ast $ast
    foreach ($n in (Get-AddDataSetNames -Ast $ast)) {
        if (-not $produced.ContainsKey($n)) { $produced[$n] = @() }
        $produced[$n] += $d.Name
    }
}
# The engine itself also registers datasets.
$engine = Join-Path $root 'Discover-WindowsServer.psm1'
if (Test-Path -LiteralPath $engine) {
    $eAst = Get-Ast -Path $engine
    $symbols['Engine'] = Get-FileSymbolSet -Ast $eAst
    foreach ($n in (Get-AddDataSetNames -Ast $eAst)) {
        if (-not $produced.ContainsKey($n)) { $produced[$n] = @() }
        $produced[$n] += 'Engine'
    }
}

# ---- 3. Manifests -----------------------------------------------------------
Write-Section 'Module manifests match exports'
foreach ($d in $moduleDirs) {
    $psd1 = Join-Path $d.FullName ("{0}.psd1" -f $d.Name)
    $psm1 = Join-Path $d.FullName ("{0}.psm1" -f $d.Name)
    if (-not (Test-Path -LiteralPath $psd1)) { Test-Item -Name ("manifest exists: {0}" -f $d.Name) -Ok $false; continue }
    if (-not (Test-Path -LiteralPath $psm1)) { continue }
    $data = $null
    try { $data = Import-PowerShellDataFile -LiteralPath $psd1 } catch { }
    if (-not $data) { Test-Item -Name ("manifest loads: {0}" -f $d.Name) -Ok $false; continue }
    $srcFns = Get-ExportedFunctionNames -Ast (Get-Ast -Path $psm1)
    $manFns = @(@($data.FunctionsToExport) | Where-Object { $_ } | Sort-Object -Unique)
    $problems = @()
    if ([string]$data.RootModule -ne ("{0}.psm1" -f $d.Name)) { $problems += ("RootModule is '{0}'" -f $data.RootModule) }
    if ($manFns -contains '*') { $problems += "FunctionsToExport is '*' (no explicit contract)" }
    else {
        $onlyMan = @($manFns | Where-Object { $srcFns -notcontains $_ })
        $onlySrc = @($srcFns | Where-Object { $manFns -notcontains $_ })
        if ($onlyMan.Count) { $problems += ("in manifest only: {0}" -f ($onlyMan -join ', ')) }
        if ($onlySrc.Count) { $problems += ("in psm1 only: {0}" -f ($onlySrc -join ', ')) }
    }
    Test-Item -Name ("manifest/exports agree: {0}" -f $d.Name) -Ok ($problems.Count -eq 0) -Detail ($problems -join "`n")
}

# ---- 4. ProducesDatasets ----------------------------------------------------
Write-Section 'Metadata ProducesDatasets matches reality'
foreach ($d in $moduleDirs) {
    $psm1 = Join-Path $d.FullName ("{0}.psm1" -f $d.Name)
    if (-not (Test-Path -LiteralPath $psm1)) { continue }
    $ast = Get-Ast -Path $psm1
    $declared = Get-DeclaredProducesDatasets -Ast $ast
    if ($declared.Count -eq 0) { continue }
    $actual = Get-AddDataSetNames -Ast $ast
    $missing = @($declared | Where-Object { $actual -notcontains $_ })
    $extra   = @($actual   | Where-Object { $declared -notcontains $_ })
    $problems = @()
    if ($missing.Count) { $problems += ("declared but not produced: {0}" -f ($missing -join ', ')) }
    if ($extra.Count)   { $problems += ("produced but not declared: {0}" -f ($extra -join ', ')) }
    Test-Item -Name ("ProducesDatasets accurate: {0}" -f $d.Name) -Ok ($problems.Count -eq 0) -Detail ($problems -join "`n")
}

# ---- 5-8. Rules -------------------------------------------------------------
Write-Section 'Risk rules'
$rules = @()
if ($cfg.ContainsKey('risk-rules')) { $rules = @($cfg['risk-rules'].rules) }
Test-Item -Name 'risk-rules.json has rules' -Ok ($rules.Count -gt 0)

$dupIds = @($rules | Group-Object id | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
Test-Item -Name 'rule ids are unique' -Ok ($dupIds.Count -eq 0) -Detail ($dupIds -join ', ')

$validSev  = @('Info','Low','Medium','High','Critical')
$validConf = @('Confirmed','Likely','Possible','NotDetected','Unknown')
$validImp  = @('Labor','Licensing','Downtime','Vendor Dependency','Security/Compliance','Data Migration','Cutover Complexity','Client Coordination','Architecture Decision','Rollback Planning')
$validPT   = @('GeneralDiscovery','ServerRefresh','HyperVRefresh','Decommission','AzureMigration','AppMigration','CMMCReadiness')
# Condition types the engine implements, read from the engine's own switch statement.
$engineTypes = @()
$reAst = Get-Ast -Path (Join-Path $root 'modules/RiskEngine/RiskEngine.psm1')
foreach ($sw in $reAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)) {
    foreach ($cl in $sw.Clauses) { if ($cl.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $engineTypes += $cl.Item1.Value } }
}
$engineTypes = @($engineTypes | Sort-Object -Unique)

$badSev = @(); $badConf = @(); $badImp = @(); $badPT = @(); $badRx = @(); $missKey = @()
$unimplemented = @(); $deadDataset = @(); $badField = @(); $badToken = @()
foreach ($r in $rules) {
    if ($validSev  -notcontains $r.severity)   { $badSev  += ("{0}={1}" -f $r.id, $r.severity) }
    if ($validConf -notcontains $r.confidence) { $badConf += ("{0}={1}" -f $r.id, $r.confidence) }
    foreach ($i in @($r.potentialProjectImpact)) { if ($i -and ($validImp -notcontains $i)) { $badImp += ("{0}='{1}'" -f $r.id, $i) } }
    foreach ($p in @($r.projectTypeEmphasis))    { if ($p -and ($validPT  -notcontains $p)) { $badPT  += ("{0}='{1}'" -f $r.id, $p) } }
    foreach ($k in @('id','category','severity','confidence','title','condition','whyItMattersForScoping','sourceModule','sourceDataset')) {
        if (-not $r.PSObject.Properties[$k]) { $missKey += ("{0} missing '{1}'" -f $r.id, $k) }
    }
    $c = $r.condition
    if (-not $c) { continue }
    if ($c.type -and ($engineTypes -notcontains $c.type)) { $unimplemented += ("{0} uses '{1}'" -f $r.id, $c.type) }
    if ($c.pattern) { try { [void][regex]::new($c.pattern) } catch { $badRx += $r.id } }

    $ds = [string]$c.dataset
    if (-not $ds) { continue }
    if (-not $produced.ContainsKey($ds)) { $deadDataset += ("{0} -> {1}" -f $r.id, $ds); continue }
    $owners = $produced[$ds]
    $fieldsToCheck = @()
    if ($c.field) { $fieldsToCheck += [string]$c.field }
    if ($r.evidenceField) { $fieldsToCheck += [string]$r.evidenceField }
    foreach ($fld in ($fieldsToCheck | Sort-Object -Unique)) {
        $found = $false
        foreach ($o in $owners) { if ($symbols[$o] -and $symbols[$o].Contains($fld)) { $found = $true; break } }
        if (-not $found) { $badField += ("{0}: {1}.{2}" -f $r.id, $ds, $fld) }
    }
    $tpl = ("{0} {1}" -f $r.evidenceTemplate, $r.suggestedValidationQuestion)
    foreach ($m in [regex]::Matches($tpl, '\{(\w+)\}')) {
        $tok = $m.Groups[1].Value
        $found = $false
        foreach ($o in $owners) { if ($symbols[$o] -and $symbols[$o].Contains($tok)) { $found = $true; break } }
        if (-not $found) { $badToken += ("{0}: {{{1}}} in {2}" -f $r.id, $tok, $ds) }
    }
}
Test-Item -Name 'rule severities are enum-legal'            -Ok ($badSev.Count  -eq 0) -Detail ($badSev  -join "`n")
Test-Item -Name 'rule confidences are enum-legal'           -Ok ($badConf.Count -eq 0) -Detail ($badConf -join "`n")
Test-Item -Name 'potentialProjectImpact values are legal'   -Ok ($badImp.Count  -eq 0) -Detail ($badImp  -join "`n")
Test-Item -Name 'projectTypeEmphasis values are legal'      -Ok ($badPT.Count   -eq 0) -Detail ($badPT   -join "`n")
Test-Item -Name 'rules have all required keys'              -Ok ($missKey.Count -eq 0) -Detail ($missKey -join "`n")
Test-Item -Name 'rule regex patterns compile'               -Ok ($badRx.Count   -eq 0) -Detail ($badRx   -join ', ')
Test-Item -Name 'all condition types are implemented'       -Ok ($unimplemented.Count -eq 0) -Detail ($unimplemented -join "`n")
Test-Item -Name 'every rule dataset is produced'            -Ok ($deadDataset.Count   -eq 0) -Detail ($deadDataset   -join "`n")
Test-Item -Name 'every rule field exists in its producer'   -Ok ($badField.Count -eq 0) -Detail ($badField -join "`n")
Test-Item -Name 'every {Token} exists in its producer'      -Ok ($badToken.Count -eq 0) -Detail ($badToken -join "`n")

# ---- 9. FIELD-USAGE.md ------------------------------------------------------
Write-Section 'FIELD-USAGE.md matches the code'
$docPath = Join-Path $root 'docs/FIELD-USAGE.md'
$docBad = @()
if (Test-Path -LiteralPath $docPath) {
    # -Encoding UTF8 is REQUIRED, not cosmetic. Windows PowerShell 5.1 reads a BOM-less
    # file as ANSI, which mangles the em-dash this loop depends on (see the IndexOf below)
    # and silently turns prose into fake field names. PowerShell 7 defaults to UTF-8, which
    # is why this only failed once 5.1 was added to CI.
    foreach ($line in (Get-Content -LiteralPath $docPath -Encoding UTF8)) {
        if ($line -notmatch '^\|\s*`([A-Za-z0-9_]+)`\s*\|\s*([A-Za-z0-9_]+)\s*\|(.*)$') { continue }
        $ds = $Matches[1]; $rest = $Matches[3]
        # Convention in FIELD-USAGE.md: the field list comes first, then an em-dash and prose.
        # Only the field list is a contract - prose may legitimately name other datasets.
        $emDash = $rest.IndexOf([char]0x2014)
        if ($emDash -ge 0) { $rest = $rest.Substring(0, $emDash) }
        if (-not $produced.ContainsKey($ds)) { $docBad += ("dataset {0} is documented but never produced" -f $ds); continue }
        $owners = $produced[$ds]
        foreach ($m in [regex]::Matches($rest, '`([A-Za-z0-9_]+)`')) {
            $fld = $m.Groups[1].Value
            $found = $false
            foreach ($o in $owners) { if ($symbols[$o] -and $symbols[$o].Contains($fld)) { $found = $true; break } }
            if (-not $found) { $docBad += ("{0}.{1} documented but not emitted" -f $ds, $fld) }
        }
    }
}
Test-Item -Name 'documented datasets/fields all exist' -Ok ($docBad.Count -eq 0) -Detail ($docBad -join "`n")

# ---- 9b. Application fingerprints -------------------------------------------
Write-Section 'Application fingerprints'
# Fingerprint matchers reference datasets by name and fields by name, and a miss is silent -
# the fingerprint simply never matches. Same failure mode as a dead risk rule.
$fpBadSource = @(); $fpBadField = @(); $fpBadConf = @()
if ($cfg.ContainsKey('application-fingerprints')) {
    $fpCfg = $cfg['application-fingerprints']
    foreach ($fp in @($fpCfg.fingerprints)) {
        foreach ($m in @($fp.matchers)) {
            $src = [string]$m.source
            if (-not $src) { continue }
            if (-not $produced.ContainsKey($src)) { $fpBadSource += ("{0} -> {1}" -f $fp.applicationName, $src); continue }
            $fld = [string]$m.field
            if (-not $fld) { continue }
            $found = $false
            foreach ($o in $produced[$src]) { if ($symbols[$o] -and $symbols[$o].Contains($fld)) { $found = $true; break } }
            if (-not $found) { $fpBadField += ("{0}: {1}.{2}" -f $fp.applicationName, $src, $fld) }
        }
        if ($m -and $m.pattern) { try { [void][regex]::new([string]$m.pattern) } catch { $fpBadConf += $fp.applicationName } }
    }
    # confidenceModel source lists should name datasets that exist.
    $cm = $fpCfg.confidenceModel
    if ($cm) {
        foreach ($listName in @('strongSources','weakSources')) {
            foreach ($srcName in @($cm.$listName)) {
                if ($srcName -and -not $produced.ContainsKey([string]$srcName)) { $fpBadSource += ("confidenceModel.{0} -> {1}" -f $listName, $srcName) }
            }
        }
    }
}
Test-Item -Name 'fingerprint matcher sources are produced datasets' -Ok ($fpBadSource.Count -eq 0) -Detail ($fpBadSource -join "`n")
Test-Item -Name 'fingerprint matcher fields exist in their producer' -Ok ($fpBadField.Count -eq 0) -Detail ($fpBadField -join "`n")
Test-Item -Name 'fingerprint matcher patterns compile'              -Ok ($fpBadConf.Count -eq 0) -Detail ($fpBadConf -join ', ')

# ---- 9c. Migration-complexity rubric coverage -------------------------------
Write-Section 'Migration-complexity rubric'
# Build-MigrationComplexity rates categories listed in its rubric. A rule category absent from
# every rubric row can only influence a rating by accident (via a matching impact keyword),
# so the complexity report silently ignores it.
$rubricCats = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$reText = Get-Content -LiteralPath (Join-Path $root 'modules/RiskEngine/RiskEngine.psm1') -Raw -Encoding UTF8
foreach ($m in [regex]::Matches($reText, "Cats\s*=\s*@\(([^)]*)\)")) {
    foreach ($q in [regex]::Matches($m.Groups[1].Value, "'([^']+)'")) { [void]$rubricCats.Add($q.Groups[1].Value) }
}
$ruleCats = @($rules | ForEach-Object { $_.category } | Where-Object { $_ } | Sort-Object -Unique)
$uncovered = @($ruleCats | Where-Object { -not $rubricCats.Contains($_) })
Test-Item -Name ("every rule category appears in the complexity rubric ({0} categories)" -f $ruleCats.Count) -Ok ($uncovered.Count -eq 0) -Detail ("not in rubric: " + ($uncovered -join ', '))

# ---- 10. Compliance lenses --------------------------------------------------
Write-Section 'Compliance lenses'
$lensBad = @()
if ($cfg.ContainsKey('compliance-lenses')) {
    $cats = @($rules | ForEach-Object { $_.category } | Sort-Object -Unique)
    foreach ($ln in $cfg['compliance-lenses'].lenses.PSObject.Properties.Name) {
        $byCat = $cfg['compliance-lenses'].lenses.$ln.relevanceByCategory
        if (-not $byCat) { continue }
        foreach ($k in $byCat.PSObject.Properties.Name) { if ($cats -notcontains $k) { $lensBad += ("{0}.{1} matches no rule category" -f $ln, $k) } }
    }
}
Test-Item -Name 'lens category keys match rule categories' -Ok ($lensBad.Count -eq 0) -Detail ($lensBad -join "`n")

# ---- 11. Dead config keys ---------------------------------------------------
Write-Section 'No dead keys in discovery config'
# Gather every quoted string and every .Property access across all code, then check that
# each discovery-config key is referenced somewhere.
$codeText = ''
foreach ($f in $psFiles) { $codeText += (Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8) + "`n" }
function Test-KeyReferenced { param([string]$Key) return ($codeText -match ("(?i)(\['" + [regex]::Escape($Key) + "'\]|\." + [regex]::Escape($Key) + "\b|'" + [regex]::Escape($Key) + "')")) }
$deadKeys = @()
# output-settings.json is included: it accumulated 15 unread keys before this check existed.
# Keys whose value is a LIST consumed wholesale (not by key name) are named here explicitly.
$listKeysReadWholesale = @('requiredOutputFiles','collectorModuleOrder','synthesisModules','forceEnableModules','forceDisableModules')
foreach ($name in @('default.discovery','fast.discovery','deep.discovery','output-settings')) {
    if (-not $cfg.ContainsKey($name)) { continue }
    $obj = $cfg[$name]
    foreach ($top in $obj.PSObject.Properties) {
        if ($top.Name -in @('schemaVersion','description','mode')) { continue }
        if ($listKeysReadWholesale -contains $top.Name) {
            if (-not (Test-KeyReferenced -Key $top.Name)) { $deadKeys += ("{0}.{1}" -f $name, $top.Name) }
            continue
        }
        $val = $top.Value
        if ($val -is [System.Management.Automation.PSCustomObject]) {
            foreach ($sub in $val.PSObject.Properties) { if (-not (Test-KeyReferenced -Key $sub.Name)) { $deadKeys += ("{0}.{1}.{2}" -f $name, $top.Name, $sub.Name) } }
        } else {
            if (-not (Test-KeyReferenced -Key $top.Name)) { $deadKeys += ("{0}.{1}" -f $name, $top.Name) }
        }
    }
}
Test-Item -Name 'every discovery-config key is read by code' -Ok ($deadKeys.Count -eq 0) -Detail ($deadKeys -join "`n")

# ---- 12. PowerShell 5.1 array-unrolling hazards -----------------------------
# Windows PowerShell 5.1 is the documented target runtime, and it does NOT give a bare
# object a .Count. PowerShell 7 does. That difference makes two idioms silently wrong on
# 5.1 while passing on 7:
#
#   $rows = if ($ok) { @($x) } else { @() }     <-- an if-block writes to the pipeline,
#                                                  which unrolls a 1-element array to a
#                                                  scalar and an empty one to $null
#   ($list | Where-Object {...}).Count  <-- same unrolling, so .Count is $null   lint-allow-pipeline-count
#
# This actually happened: RiskEngine's datasetNotEmpty condition never fired for a
# single-row dataset on 5.1, which silently disabled risk rules on the target platform.
# Fix by wrapping the whole expression in @(...).
Write-Section 'PowerShell 5.1 array-unrolling hazards'

$unrollHits = @()
foreach ($f in $psFiles) {
    $fileAst = Get-Ast -Path $f.FullName
    if (-not $fileAst) { continue }
    $rel = $f.FullName.Substring($root.Length + 1)

    # (a) Assignment whose right-hand side is an if-statement with a collection branch.
    #     Using the AST rather than a regex means a collection in the CONDITION - e.g.
    #     "if (@($x).Count -gt 0) { 'a' } else { 'b' }", which yields a scalar - is not a
    #     false positive.
    foreach ($ifAst in $fileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true)) {
        $parent = $ifAst.Parent
        while ($parent -and -not ($parent -is [System.Management.Automation.Language.AssignmentStatementAst])) {
            if ($parent -is [System.Management.Automation.Language.ScriptBlockAst] -or
                $parent -is [System.Management.Automation.Language.NamedBlockAst]) { $parent = $null; break }
            $parent = $parent.Parent
        }
        if (-not $parent) { continue }

        # Already guarded? "$x = @(if ...)" puts an ArrayExpressionAst above the if.
        $guarded = $false
        $up = $ifAst.Parent
        while ($up -and $up -ne $parent) {
            if ($up -is [System.Management.Automation.Language.ArrayExpressionAst]) { $guarded = $true; break }
            $up = $up.Parent
        }
        if ($guarded) { continue }

        $bodies = @()
        foreach ($clause in $ifAst.Clauses) { $bodies += $clause.Item2 }
        if ($ifAst.ElseClause) { $bodies += $ifAst.ElseClause }

        # A branch only creates a hazard if it yields a COLLECTION. "@($x).Count" and
        # "@($x)[0]" are array expressions whose result is immediately reduced to a scalar
        # by a member access or an index, so assigning them from an if-block is safe -
        # $n = if ($ok) { @($x).Count } else { 0 } is idiomatic and correct. Only a bare
        # array expression is a hazard.
        $collectionBranch = $false
        foreach ($b in $bodies) {
            if (-not $b) { continue }
            foreach ($arr in $b.FindAll({ param($n) $n -is [System.Management.Automation.Language.ArrayExpressionAst] }, $true)) {
                $reduced = ($arr.Parent -is [System.Management.Automation.Language.MemberExpressionAst]) -or
                           ($arr.Parent -is [System.Management.Automation.Language.IndexExpressionAst])
                if (-not $reduced) { $collectionBranch = $true; break }
            }
            if ($collectionBranch) { break }
        }
        if ($collectionBranch) {
            $unrollHits += ("{0}:{1} assignment from an if-block with a collection branch - wrap the whole expression in @()" -f $rel, $ifAst.Extent.StartLineNumber)
        }
    }

    # (b) .Count / .Length taken directly off an unwrapped pipeline.
    $lineNo = 0
    foreach ($line in (Get-Content -LiteralPath $f.FullName -Encoding UTF8)) {
        $lineNo++
        # A line can opt out with the marker below. Exactly one line needs it: the
        # pattern literal on the next line, which otherwise matches itself. Using a
        # marker rather than skipping this whole file keeps the check live everywhere.
        if ($line -like '*lint-allow-pipeline-count*') { continue }
        if ($line -match '[^@]\([^()]*\|[^()]*\)\.(Count|Length)\b') {   # lint-allow-pipeline-count
            $unrollHits += ("{0}:{1} .Count on an unwrapped pipeline - use @(...).Count" -f $rel, $lineNo)
        }
    }
}
Test-Item -Name 'no PowerShell 5.1 array-unrolling hazards' -Ok ($unrollHits.Count -eq 0) -Detail ($unrollHits -join "`n")

# ---- Summary ----------------------------------------------------------------
Write-Host ''
if ($script:Failures.Count -eq 0) {
    Write-Host ("SELF-CHECK PASSED - {0} checks, 0 failures." -f $script:Checks) -ForegroundColor Green
    exit 0
}
Write-Host ("SELF-CHECK FAILED - {0} of {1} checks failed:" -f $script:Failures.Count, $script:Checks) -ForegroundColor Red
foreach ($f in $script:Failures) { Write-Host ("  - {0}" -f $f) -ForegroundColor Red }
exit 1
