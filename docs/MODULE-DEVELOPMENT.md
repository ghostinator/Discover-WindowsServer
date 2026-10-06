# Module Development Guide

This toolkit is modular. Each collector lives in `modules\<Name>\<Name>.psm1` (with a
matching `<Name>.psd1`). The orchestrator loads modules **in isolation** — it imports
one module (alongside the always-loaded `Core` and `Output`), runs its contract
functions, then removes it. That is why every module can safely reuse the same generic
contract function names without collisions.

## The safety contract (non-negotiable)

Modules are **strictly read-only**. Forbidden: restarting services/the server;
modifying the registry (except toolkit output), firewall, scheduled tasks,
users/groups, IIS, SQL, certificates, AD, DNS, DHCP, clustering, or Hyper-V; enabling
PSRemoting; installing modules/software; changing execution policy or Group Policy;
destructive cleanup/repair (defrag, chkdsk repair); creating checkpoints; exporting
private keys/certs; collecting passwords, hashes, BitLocker recovery keys, or RADIUS
shared secrets. If data can't be collected safely, call `Add-Limitation` and continue.
Wrap every collection block in `try/catch` — one failure must never stop the module.

## The six-function contract

The orchestrator calls whichever of these your module defines:

```powershell
Get-DiscoveryModuleMetadata                     # REQUIRED — static metadata (see below)
Test-DiscoveryPrerequisites  -Context           # can this module run here?
Invoke-DiscoveryCollection   -Context           # read-only collection; return raw (hashtable) or $null
ConvertTo-DiscoveryDatasets  -Context -RawData   # normalize raw -> Add-DataSet
Invoke-DiscoveryRiskAnalysis -Context           # OPTIONAL module-specific findings
Get-DiscoveryFollowUpQuestions -Context         # OPTIONAL module-specific questions
```

End the `.psm1` with `Export-ModuleMember -Function ...`.

### Metadata

```powershell
[pscustomobject]@{
    ModuleName='SQL'; DisplayName='SQL Server Discovery'; Category='Database'; Version='1.0.0'
    DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
    RequiresRole=$null; EstimatedImpact='Low'   # Minimal | Low | Medium | High
    CanRunAsSystem=$true; ProducesDatasets=@('SqlInstances','SqlDatabases','OdbcDsns')
    ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
}
```

- Fast mode should default to `Minimal`/`Low` impact modules.
- `Medium`/`High` behavior must require Deep mode or an explicit switch.

### Prerequisites

```powershell
[pscustomobject]@{ ModuleName='IIS'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
```

For role-specific modules, detect the role/cmdlet/service/registry and set
`CanRun=$false`, `Status='NotApplicable'`, `Reason='<role> not present'` when absent —
the orchestrator records a clean skip (never fake rows).

## Execution model: your collector runs in a child runspace

The engine calls `Invoke-DiscoveryCollection` **inside a child runspace of the same process**,
with a deadline (`moduleTimeoutSeconds`, default 600 s), so a hung cmdlet cannot hang the run.
`Test-DiscoveryPrerequisites`, `ConvertTo-DiscoveryDatasets`, `Invoke-DiscoveryRiskAnalysis` and
`Get-DiscoveryFollowUpQuestions` still run on the engine's own thread. What this means for you:

- The child runspace imports only **Core** and **Output** and then your module. Anything else
  (another collector, engine internals) is not loaded there. Read other modules' data through
  `$Context.DataSets`, never by calling their functions.
- `$Context` is the same object as in the engine (shared by reference): `Add-DataSet`,
  `Add-Limitation`, `Add-DependencyEdge`, `Write-Log` and friends work normally and are visible
  to the engine afterwards.
- **Module-scoped (`$script:`) state does not cross the boundary**: your collection function and
  your `ConvertTo-DiscoveryDatasets` run in different runspaces, so pass data between them through
  the function's return value (the raw hashtable), not through script variables.
- **Return** the raw hashtable with the unary comma (`return ,@{ ... }`). If the deadline expires the
  engine gets `$null` and your `ConvertTo-DiscoveryDatasets` must tolerate that (all existing ones do).
- Dependency edges you add before the deadline are kept; work that had not finished is lost, so
  add datasets/edges incrementally in slow collectors rather than only at the end.

## Framework API available to every module

Data & findings: `Add-DataSet`, `Add-Finding`, `Add-Limitation`, `Add-Unknown`,
`Add-FollowUpQuestion`, `Add-ScopeLanguage`, `Add-DependencyEdge`.
Safe collection: `Invoke-CimSafe`, `Get-RegistryValueSafe`, `Test-RegistryPathSafe`,
`Invoke-CommandLineSafe`, `Get-CommandAvailable`, `Get-ModuleAvailable`,
`Invoke-WindowsPowerShellJson`, `Test-WindowsPowerShellModule`.

`Get-CommandAvailable` gates optional collection: a false *negative* silently empties a dataset.
Under PowerShell 7 it falls back to `Import-Module -SkipEditionCheck` when `Get-Command` fails,
because PowerShell 7 hides every Windows PowerShell module on Windows Server 2012 R2.
`Invoke-WindowsPowerShellJson -Script '...'` runs a **read-only** snippet in the machine's own
Windows PowerShell and returns parsed JSON (or `$null`); use it, guarded by
`Test-WindowsPowerShellModule -Name <module>`, for cmdlets PowerShell 7 cannot load there.
`Add-DataSet` redacts every string cell (safety net), so datasets never carry raw secrets even if you
forget, but redact at the source anyway.
Utility: `Convert-BytesToGB`, `Convert-BytesToMB`, `Normalize-DateTime`,
`Redact-SensitiveValue`, `Test-SensitiveKeyLabel`, `Write-Log`, `Write-SectionStatus`.

`Add-DataSet` shape:

```powershell
Add-DataSet -Context $Context -Name 'Services' -Description 'Windows services and accounts' `
    -Rows $rows -Visibility Internal -IncludeInWorkbook $true -IncludeInClientReport $false -SourceModule 'ServicesTasks'
```

Visibility: `Internal` | `ClientSafe` | `Both` | `SensitiveRedacted`.

## PowerShell conventions (learned the hard way)

- **Never name a function like an alias.** `H`, `R`, `T` (and many other one/two-letter names) are
  built-in aliases (`Get-History`, `Invoke-History`, ...); the alias wins over your function and the
  call fails with a baffling parameter-binding error.
- **Assigning from an `if` that returns a collection unrolls it** on 5.1: write
  `$x = @(if (...) { ... } else { ... })`. The self-check enforces this.
- **Cmdlets that take `-ComputerName` resolve `$env:COMPUTERNAME` through DNS on every call** (about
  1 s each, and a failure is swallowed by `-ErrorAction SilentlyContinue` as an empty result). Set
  `$PSDefaultParameterValues = @{ 'Get-VM*:ComputerName' = 'localhost' }` inside the collector (done for
  Hyper-V, DHCP, DNS). **Never do this for `Get-Printer`**: with `-ComputerName localhost` it hangs on a
  remote print-server RPC.

- **Windows PowerShell 5.1 compatible.** No PS7-only syntax (`?:`, `??`,
  `ForEach-Object -Parallel`).
- **Create generic collections with `::new()`**, not `New-Object`:
  `[System.Collections.Generic.List[object]]::new()`. (`New-Object` on a generic list
  can break the `@()` array operator on some runtimes.)
- **Return possibly-empty arrays with the unary comma:** `return ,@($items)` — a bare
  `return @()` unrolls to `$null` at the call site.
- Do **not** use `Set-StrictMode`; collectors touch highly dynamic CIM/registry objects
  with frequently-absent properties.
- Use `[pscustomobject]` with ordered, consistently-named properties. Emit the exact
  field names in [FIELD-USAGE.md](FIELD-USAGE.md) so the RiskEngine rules fire.
- Redact sensitive values with `Redact-SensitiveValue`; report *where* a secret was
  found, never the value.

## Minimal module skeleton

```powershell
function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{ ModuleName='Example'; DisplayName='Example'; Category='System'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true; ProducesDatasets=@('Example')
        ProducesRisks=$false; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false }
}
function Test-DiscoveryPrerequisites { param([object]$Context)
    [pscustomobject]@{ ModuleName='Example'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}
function Invoke-DiscoveryCollection { param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()
    try { foreach ($x in (Invoke-CimSafe -ClassName 'Win32_OperatingSystem')) {
        $rows.Add([pscustomobject]@{ Caption=$x.Caption; Version=$x.Version })
    } } catch { Add-Limitation -Context $Context -Module 'Example' -Message 'OS query failed' }
    return ,@{ Example = @($rows) }
}
function ConvertTo-DiscoveryDatasets { param([object]$Context, $RawData)
    $rows = if ($RawData -and $RawData.Example) { @($RawData.Example) } else { @() }
    Add-DataSet -Context $Context -Name 'Example' -Description 'Example dataset' -Rows $rows -SourceModule 'Example' | Out-Null
}
Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets'
```

## Registering a module

Add the module name to `collectorModuleOrder` in `config/default.discovery.json` (order
matters — earlier modules' datasets are available to later ones). Synthesis modules run
after all collectors via `Invoke-DiscoverySynthesis`.

### Reading another module's dataset

If your module reads a dataset it does not own, check where its owner sits in
`collectorModuleOrder`. A dataset produced by a *later* collector simply will not exist yet,
and because collectors guard with `$Context.DataSets.Contains(...)` the result is **silent** —
no error, just a feature that never works. This is what happened to application
fingerprinting: matchers referencing `ListeningPorts` and `IisSites` could never fire because
`Applications` runs 4th while `Network` and `IIS` run 5th and 12th.

Two ways out, in order of preference:

1. **Move the cross-dataset work after collection.** Expose a distinct entry point (e.g.
   `Invoke-DiscoveryFingerprintSynthesis`) and have the orchestrator call it once every
   collector has run. Robust against future reordering and against new cross-dataset reads.
2. **Reorder `collectorModuleOrder`.** One line, but fragile — the bug returns the moment
   someone references a dataset from a module that still runs later.

`tests\Invoke-ToolkitSelfCheck.ps1` verifies that every risk-rule and fingerprint-matcher
dataset/field actually exists, so this class of silent breakage fails the build.
