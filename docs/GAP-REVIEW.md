# Review of the toolkit, and what changed

This is the record of a full read of the script, the engine, all 30 modules, the seven
config files and the verifier - what was already sound, what was genuinely missing, and
what was done about it.

## 1. What was already complete

Nothing declared was missing. All 25 collectors named in
`config\default.discovery.json` → `collectorModuleOrder` existed on disk with both a
`.psd1` and a `.psm1`, all five synthesis modules existed, and every module implemented
the six-function contract correctly, including the optional members
(`Invoke-DiscoveryRiskAnalysis`, `Get-DiscoveryFollowUpQuestions`) where relevant.

The parts that are easy to get wrong were already right: module isolation via
import/remove around a shared contract; the unary-comma idiom that stops an empty array
unrolling to `$null`; `Write-ObjectListToJson` always emitting an array regardless of row
count; the post-collection fingerprint pass so matchers keyed on late datasets can fire;
the evidence manifest excluding files still being written; redaction that reports *where*
a secret is without ever recording the value.

So the gap was not "a module is missing from the list". It was **coverage** - subject
areas no module claimed - and **presentation** - a run folder that was a dump rather than
a deliverable.

## 2. Coverage gaps found, and the four modules built to close them

| Gap | Why it mattered | New module |
| --- | --- | --- |
| **No patch/update discovery at all.** The toolkit reported the OS build and a pending reboot, and stopped. | "When was this last patched, and by what?" is asked within minutes of any server being handed over. It drives migration urgency, CMMC evidence, and whether the maintenance window needs to allow for a catch-up run. A WSUS *server* role was also entirely invisible - retiring one silently stops patching for every client pointed at it. | `WindowsUpdate` → `UpdatePosture`, `InstalledHotfixes`, `UpdateSources`, `WsusServerRole` |
| **User-context dependencies were disclaimed but never collected.** Three modules record a limitation saying mapped drives, per-user DSNs and HKCU installs are invisible under SYSTEM. Nothing went and got them. `-IncludeUserProfiles` existed as a parameter but only ever acted as an *exclusion* filter in the config scan. | Mapped drives are hardcoded dependencies created by people, not by configuration management, and a server rename breaks them silently. Per-user ODBC DSNs are where legacy line-of-business apps keep their database target and are not in the system DSN list. Both are readable from the loaded `HKEY_USERS` hives without impersonating anyone. | `UserProfiles` → `UserProfiles`, `MappedDrives`, `UserOdbcDsns`, `LogonScripts` |
| **No time synchronisation discovery.** | Time is a hard dependency for Kerberos, certificate validation and log correlation. A drifted clock presents as authentication failure, which sends people hunting in entirely the wrong place, and a server advertising itself as an authoritative time source cannot be retired without moving that role. | `TimeSync` → `TimeSync` |
| **No hybrid identity / cloud attachment discovery.** | Entra Connect is the classic decommission landmine: it looks like an ordinary member server, holds a role that exists exactly once per tenant, and switching it off stops directory synchronisation with no local error. AD FS, App Proxy connectors and Azure Arc are the same shape of problem. | `AzureHybrid` → `HybridIdentity`, `AzureAttachment` |

All four are read-only, follow the existing contract exactly, register dependency edges
and unknowns like every other collector, and are wired into `collectorModuleOrder` in
positions where the datasets they consume already exist (`WindowsUpdate` and `TimeSync`
after `SecurityPosture`; `UserProfiles` and `AzureHybrid` after `VendorAgents`, so
`AzureHybrid` can read `Services`, `InstalledApplications` and `ConfigDependencyHints`).

**12 new rules** were added to `config\risk-rules.json` so the new datasets actually
produce findings rather than sitting inert in the workbook: `RULE-PATCH-001..004`,
`RULE-WSUS-001`, `RULE-HYBRID-001`, `RULE-TIME-001..003`, `RULE-USER-001..003`.

`Get-LikelyServerFunctions` was extended to recognise three roles that are not Windows
features and so were previously undetectable: WSUS server, hybrid identity connector,
and authoritative time source.

## 3. Deliberately *not* built

Judgement calls worth recording, so nobody re-litigates them from scratch:

* **Exchange collector** - on-premises Exchange is detected by `AzureHybrid` as a hybrid
  component, which is the scoping-relevant fact. A full Exchange collector is a project
  in itself and would rarely fire for the servers this toolkit is pointed at.
* **RRAS / VPN collector** - substantially covered by `NPS_RADIUS`, `VendorAgents` and
  the listening-port data. A separate module would mostly duplicate them.
* **Live Windows Update COM search** - `WindowsUpdate` reads cached registry results
  rather than triggering a detection pass. A live search against WSUS or Microsoft Update
  is a network operation with a side effect on the client's reporting data, which is not
  what "read-only" should mean.
* **Tenant identifiers from `dsregcmd`** - join *state* is the scoping fact; tenant IDs,
  device IDs and certificate thumbprints are tenant data with no scoping value, so they
  are parsed past rather than collected.

## 4. Output restructure

The run folder previously had ~30 loose files and 11 sibling directories at its root,
with the two things anyone actually wanted - the internal report and the client summary -
sitting among them undistinguished. Now:

* **`reports\`** - two finished deliverables plus a `supporting\` pack.
* **`evidence\`** - logs, raw captures, live status, and every dataset as CSV and JSON.

Implementation note worth knowing before you edit anything: the **path keys** in
`$Context.Paths` (`Csv`, `Json`, `Logs`, `Raw`, `Status`, `Markdown`, `Html`,
`ClientSafe`, `Internal`, `Evidence`) are unchanged - only the directories they resolve
to moved. That is why **no collector module needed editing** to adopt the new layout.
The keys are the contract; the folder names never were.

Changes that fell out of the restructure:

* `internal-report.html` → `reports\internal-engineering-report.html`. Renamed because
  a filename is the last warning before someone forwards it.
* A proper **client report** now exists (`ReportBuilder`), replacing a thin
  `client-safe-summary.md`. Both reports are produced as HTML *and* Markdown from a
  single shared content model, so the two renderings cannot drift apart.
* `Save-OutputCopy` writes to `reports\supporting\` rather than the run root, and skips
  the themed mirror when it resolves to the same directory.
* The engine **no longer writes duplicate `errors.txt` / `warnings.txt`**. `Write-Log`
  maintains those live in `evidence\logs\`; a second snapshot written at output time
  would have overwritten the live file and truncated anything logged afterwards -
  including a failure during report generation, which is precisely when you want it.
  The old flat layout got away with it only because the duplicate landed at the root.
* `Test-FileIsLiveDuringManifest` and `Get-FileSensitivity` in `EvidenceManifest` were
  updated for the new paths. Missing this would have silently stopped excluding the live
  status and log files, reintroducing the stale-hash problem that guard exists for.
* `tools\Verify-DiscoveryRun.ps1` resolves paths through two new helpers
  (`Resolve-RunDir`, `Resolve-RunFile`) that try the new layout and fall back to the old,
  so **run folders produced before this change still verify**.
* `config\output-settings.json` → `requiredOutputFiles` now lists run-root-relative
  paths and is still the authoritative contract the verifier enforces.

## 5. What still needs a real server

Unchanged from `SERVER-RUN.md`, and none of it is addressable from a workstation: the
`Get-WindowsFeature` primary path in `RolesFeatures` has still never executed, SQL
`BinaryPath` → `CriticalPaths` is unproven, the recycle-bin exclusion needs real user
shares, and `raw\userrights.inf` needs elevation.

The four new modules add to that list: `WindowsUpdate` needs a server with real patch
history and ideally a WSUS client configuration, `UserProfiles` needs loaded user hives
(an RDS host is the ideal test), `TimeSync` needs a domain member to exercise the broken
hierarchy rule, and `AzureHybrid` needs a box with Entra Connect or AD FS on it. Until
then those code paths are written but unexercised.
