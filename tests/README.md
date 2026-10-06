# Tests

Three layers, none of which touch the host system: the self-check only parses files, the smoke
test writes to a temp folder it then removes, and the Pester suite exercises framework
functions with synthetic data. None of them collect anything from the machine they run on.

## One command

```powershell
.\tests\Invoke-AllChecks.ps1
```

Runs all three layers and returns a single exit code. Use it before sharing the toolkit or
handing it to an engineer. There is no git repository or CI pipeline behind this project, so
there is nowhere to hang a pre-commit hook — this script is the substitute.

A layer that *cannot* run (e.g. Pester not installed) reports `NOT RUN`, never `PASS`.

## The three layers

### 1. `Invoke-ToolkitSelfCheck.ps1` — static contract checks

Fast, no side effects. Catches the failure mode this toolkit is most prone to: a renamed
dataset or field silently disables a risk rule. The engine does not error, the finding just
never appears.

```powershell
.\tests\Invoke-ToolkitSelfCheck.ps1          # verbose
.\tests\Invoke-ToolkitSelfCheck.ps1 -Quiet   # failures + summary only
```

Verifies: every file parses; every config JSON parses; each `.psd1` matches its `.psm1`
exports and `RootModule`; each module's metadata `ProducesDatasets` matches what it actually
produces; rule integrity (unique ids, valid regex, enum-legal severity/confidence/impact/
projectTypeEmphasis, required keys); every rule condition type is implemented; every rule
dataset, condition field, `evidenceField` and `{Token}` exists in its producing module; every
fingerprint matcher source/field/pattern is valid; every field documented in `FIELD-USAGE.md`
is really emitted; compliance-lens keys match real rule categories; every rule category appears
in the migration-complexity rubric; and no config key is left unread.

**Run it after touching any collector, risk rule, fingerprint, module manifest, or config key.**

### 2. `Invoke-OutputSmokeTest.ps1` — dynamic output check

Seeds synthetic datasets shaped per `docs\FIELD-USAGE.md`, then runs the real fingerprinting,
synthesis and output chain. Catches broken markdown tables, malformed workbook XML, missing CSV
columns and dropped deliverables — things static analysis cannot see.

```powershell
.\tests\Invoke-OutputSmokeTest.ps1
.\tests\Invoke-OutputSmokeTest.ps1 -ProjectType CMMCReadiness -KeepOutput
```

The list of artifacts it requires comes from `requiredOutputFiles` in
`config\output-settings.json`, so the test and the toolkit cannot drift apart.

### 3. Pester suite

```powershell
Invoke-Pester -Path .\tests\Pester
Invoke-Pester -Path .\tests\Pester\Redaction.Tests.ps1   # single file
```

Requires Pester 5.x: `Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0`.
Installing Pester is a developer action and is never performed by the toolkit itself.

| File | Covers |
|---|---|
| `Pester\Core.Tests.ps1` | Safe file names, byte/date conversion, finding object creation, context initialisation, sequential `FindingId` |
| `Pester\Output.Tests.ps1` | Worksheet-name sanitisation, CSV escaping, XML escaping, workbook well-formedness, markdown tables, dependency-edge rows |
| `Pester\RiskEngine.Tests.ps1` | Rule condition matching, token expansion, module-metadata contract, discovery-plan generation, project-type emphasis |
| `Pester\Redaction.Tests.ps1` | The secret-shape corpus — both directions: secrets must never survive, scoping evidence must never be destroyed |

## Known platform-dependent result

`Core.Tests.ps1` → *'replaces invalid characters'* **fails on macOS/Linux and passes on
Windows.** `[System.IO.Path]::GetInvalidFileNameChars()` returns 2 characters on Unix versus 41
on Windows (including `:`), so `:` survives sanitising off-Windows. The test is correct for the
target platform. If it fails **on Windows**, that is a real bug.

## Folders

- `sample-data\` — small sample inputs used by tests.
- `mock-outputs\` — reference/expected output snippets (illustrative).
