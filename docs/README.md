# Ultimate Modular Windows Server Discovery Toolkit

A **read-only**, modular, PowerShell-based Windows Server discovery toolkit for MSP
project scoping: server refresh, Hyper-V refresh, application migration, Azure
migration, decommission readiness, CMMC/security review, and infrastructure
documentation.

This is **not just an inventory script**. It helps a Project Architect answer:

- What does this server do?
- What business/application, service-account, database, share, certificate, license,
  and vendor dependencies exist?
- What hidden migration blockers exist?
- Can this server be safely decommissioned?
- What should be scoped, excluded, validated, or quoted — and what should we ask the
  client before quoting?

## Safety first — the toolkit is strictly read-only

It never restarts services or the server; never modifies the registry (except its own
output files), firewall, scheduled tasks, users/groups, IIS, SQL, certificates, AD,
DNS, DHCP, clustering, or Hyper-V; never enables PSRemoting; never installs modules or
software; never changes execution policy or Group Policy; never runs destructive
cleanup/repair; and never collects passwords, hashes, private keys, BitLocker recovery
keys, or RADIUS shared secrets. If data cannot be collected safely, it logs a
limitation and continues. See [MODULE-DEVELOPMENT.md](MODULE-DEVELOPMENT.md) for the
full safety contract.

## Requirements

- Windows Server 2016+ (also runs on Windows 10/11 for testing). Validated on Server 2016,
  2019 and 2025 under Windows PowerShell 5.1, and on 2025 under PowerShell 7 as well.
- Windows PowerShell 5.1 (PowerShell 7 works too; no internet; no Excel required).
- **Windows Server 2012 R2** ships PowerShell 4.0, which is too old. Run
  `tools\Install-LegacyPrerequisites.ps1` there: it shows a plan, asks before each install,
  **never restarts the machine**, requires a valid Microsoft signature on every installer, and
  installs PowerShell 7 side by side (plus the Universal C Runtime update KB2999226 if needed).
  `-PlanOnly` changes nothing; `-SourceFolder` installs from pre-staged files on servers without
  internet. Then run `pwsh.exe -File .\Discover-WindowsServer.ps1`. On 2012 R2 under PowerShell 7,
  Windows modules that need .NET Framework types (ServerManager, WebAdministration, NetTCPIP,
  DnsClient) cannot load; the toolkit works around ServerManager by asking the machine's own Windows
  PowerShell, and reports the remaining gaps (see the 2012 R2 notes in `TODO.md`). Older than
  2012 R2 is not supported.
- Run **locally** on the server being discovered. Elevated (Administrator) is
  recommended for completeness but not required.
- No external PowerShell modules are required. Optional Windows role modules
  (ActiveDirectory, DnsServer, DhcpServer, WebAdministration, Hyper-V,
  FailoverClusters, etc.) are used *if already present*, never installed.

## Quick start

```powershell
# From inside the project folder:
.\Discover-WindowsServer.ps1                 # Fast mode (default), GeneralDiscovery
.\Discover-WindowsServer.ps1 -Mode Deep
.\Discover-WindowsServer.ps1 -Mode Deep -ProjectType Decommission -IncludeConfigDependencyScan
.\Discover-WindowsServer.ps1 -Mode Custom -IncludeModules SystemInventory,Applications,SQL,IIS
.\Discover-WindowsServer.ps1 -Mode Fast -ComplianceLens CMMC
.\Discover-WindowsServer.ps1 -Mode Deep -AttemptSqlIntegratedAuth
.\Discover-WindowsServer.ps1 -Mode Deep -FullEventLogExport -GenerateEvidenceManifest
```

If script execution is blocked, launch a scoped session without changing machine
policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 -Mode Fast
```

## Modes

- **Fast** (default) — quick scoping: primary role, obvious dependencies, major risks,
  follow-up questions. Avoids recursive share crawling, config scanning (unless
  enabled), deep SQL enumeration, and full event-log export.
- **Deep** — everything in Fast plus deeper file-share analysis, the config
  dependency scan, more event-log samples, richer IIS/SQL/certificate/backup analysis.
  Still strictly read-only.
- **Custom** — only the modules you name via `-IncludeModules` / `-ExcludeModules`.

## Project types (same data, different emphasis)

`GeneralDiscovery`, `ServerRefresh`, `HyperVRefresh`, `Decommission`,
`AzureMigration`, `AppMigration`, `CMMCReadiness`.

`-ProjectType` selects an **emphasis lens**. Risk rules declare which project types they
matter most for (`projectTypeEmphasis` in `config/risk-rules.json`), and findings from a
matching rule are flagged as priorities:

- the HTML report opens with a **Priority For This Project Type** section
- those findings sort first within their severity band
- `scoping-risks.txt` marks them `[PRIORITY]`
- `wbs-inputs.csv` gains a `PriorityForProject` column
- `summary.md` reports how many were prioritised

For example `-ProjectType Decommission` leads with domain-controller, FSMO, DNS, DHCP and
Hyper-V findings, while `-ProjectType CMMCReadiness` leads with SMBv1, RDP/NLA, firewall,
antivirus and local-admin findings — from *exactly the same collected data*.

The lens changes **ordering and visibility only**. It does not change which rules fire, and
it never alters a finding's severity or confidence, so the finding set is identical whichever
project type you choose. `GeneralDiscovery` applies no lens.

## Key parameters

| Parameter | Purpose |
|---|---|
| `-Mode` | `Fast` (default) / `Deep` / `Custom` |
| `-ProjectType` | Emphasis lens (see above) |
| `-IncludeModules` / `-ExcludeModules` | Module selection |
| `-OutputRoot` | Output root (default `C:\Temp`, overridable in config — see below) |
| `-DeepFileShareScan` | Enable folder-size/large-file/ACL analysis (never implied by Fast) |
| `-IncludeConfigDependencyScan` | Run the config dependency scan even in Fast |
| `-AttemptSqlIntegratedAuth` | Attempt local integrated-auth SQL enumeration |
| `-FullEventLogExport` | Export selected event logs to `raw\` (may be large) |
| `-IncludeUserProfiles` / `-IncludeWindowsFolder` | Include these locations in the config dependency scan |
| `-IncludeRecycleBin` | Count `$Recycle.Bin` contents in deep file-share size/age totals (excluded by default; the recycled volume is always reported separately) |
| `-MaxDepth` / `-LargeFileThresholdGB` / `-OldFileYears` | Deep file-share crawl tuning |
| `-EventLogDays` / `-MaxEventSamplesPerLog` | Event log window and sample cap (Deep defaults to 30 days / 100 samples) |
| `-ConfigScanMaxFileSizeMB` | Skip config files larger than this |
| `-ComplianceLens` | `None` / `CMMC` / `GeneralSecurity` (interpretive relevance only) |
| `-GenerateEvidenceManifest` | Produce SHA256 hashes + evidence metadata |
| `-SkipZip` | Do not create the ZIP archive |
| `-Quiet` / `-VerboseLogging` | Console verbosity |

### Where parameter values come from

Every tunable resolves through four layers, first match wins:

1. What you pass on the command line
2. `config\fast.discovery.json` / `config\deep.discovery.json` → `parameterDefaults` (per mode)
3. `config\default.discovery.json` → `defaults` (global)
4. The built-in fallback in the script's `param()` block

So editing the config files genuinely changes behaviour — e.g. Deep mode's
`eventLogDays: 30` / `maxEventSamplesPerLog: 100` come from `deep.discovery.json`, and setting
`outputRoot` in `default.discovery.json` redirects output without a command-line switch. Only
keys the code actually reads are present in those files; nothing there is decorative.

## Output

Output is written to `C:\Temp\Discover-WindowsServer_<ComputerName>_<yyyyMMdd_HHmmss>\`.
Start with **`internal-report.html`** (engineers) and **`client-safe-summary.md`**
(clients). See [OUTPUT-GUIDE.md](OUTPUT-GUIDE.md) for every file.

## Reliability guarantees

- **A hung collector cannot hang the run.** Each collector's collection step has a deadline
  (`defaults.moduleTimeoutSeconds` in `config\default.discovery.json`, default 600 s, `0` disables).
  On expiry the module is abandoned, a limitation is recorded, and the run continues.
- **Secrets are redacted centrally.** Every string cell of every dataset passes through
  `Redact-SensitiveValue` in `Add-DataSet` (`Protect-DatasetRows`), so a collector that forgets to
  redact a free-text field (e.g. a Hyper-V VM's Notes) cannot leak a credential into the CSV, JSON,
  workbook or reports. Collectors should still redact at the source.
- **Missing data is reported, not silent.** A cmdlet that cannot run produces a limitation; an
  empty dataset is not a clean bill of health.

## Documentation

- [OUTPUT-GUIDE.md](OUTPUT-GUIDE.md) — what each output file/folder contains
- [FIELD-USAGE.md](FIELD-USAGE.md) — canonical datasets/fields (collector ⇄ risk engine contract)
- [RISK-SCORING.md](RISK-SCORING.md) — finding model, severities, rule engine, compliance lens
- [MODULE-DEVELOPMENT.md](MODULE-DEVELOPMENT.md) — the module contract and how to add a collector
- [PUBLISHING.md](PUBLISHING.md) — releasing to the PowerShell Gallery

## A note on confidence

Every conclusion is labeled `Confirmed` / `Likely` / `Possible` / `NotDetected` /
`Unknown`. The toolkit produces **indicators for scoping that require human
validation**; it makes no compliance certification and no absolute
"safe-to-decommission" claim.
