# Discover-WindowsServer — Findings & Fix History

> **START HERE: [HANDOFF.md](HANDOFF.md)** has the lab inventory, standing rules, procedures, gotchas and the
> current open-items list. **[TODO.md](TODO.md)** is the short, current "what's actually left to do" list.
> **This file (HISTORY.md) is the detailed archive** of every finding and fix from the very first audit
> (2026-08-17) through the real-server sessions of 2026-09-21/22 — nothing here needs action, it's the record
> of what was found and how it was fixed. Split from a single TODO.md on 2026-09-22 once that file grew past
> 1300 lines and mixed "still to do" with "here's what we already fixed" - if you're looking for open work,
> you want TODO.md or HANDOFF.md instead. The newest work is in the section "Real-server test session
> (2026-09-21)" and its sub-rounds. Current gate: 187 static checks + 150 Pester tests + output smoke test,
> green on Windows PowerShell 5.1 and PowerShell 7.

**Audit date:** 2026-08-17 · **Audited by:** Claude Code
**Windows validation started:** 2026-08-21 · PowerShell 7.6.5 **and 5.1.26100** · Pester 6.1.0
**Git:** now version-controlled — `github.com/ghostinator/Discover-WindowsServer` (private), CI on both runtimes

**Status: Phases 1-4 COMPLETE. Phase 5 partly done. Windows validation IN PROGRESS — see
[WINDOWS-VALIDATION.md](WINDOWS-VALIDATION.md) for the run-book.**

**Verify any change with these two, both of which must stay green:**
```powershell
.\tests\Invoke-AllChecks.ps1            # all three layers, one exit code
```
or individually:
```powershell
.\tests\Invoke-ToolkitSelfCheck.ps1      # 163 static contract checks
.\tests\Invoke-OutputSmokeTest.ps1       # runs the real output chain end-to-end
Invoke-Pester -Path .\tests\Pester       # needs Pester 5.x
```

Decisions locked with the owner:
- `-ProjectType` → **implement emphasis** (see F2/F18 — the rule data already exists).
- Dead config → **wire up the useful ones, delete the rest**.
- Work one item at a time and verify each before moving on (avoids leaving many half-finished
  changes if a session ends early).

---

## 1.0.1 (2026-10-06) - GUI fixes found in the README screenshots

| Defect | Fix | Verified |
|---|---|---|
| **Branding swatch blank on launch.** The saved accent color was loaded before the TextChanged handler was attached, and the "trigger it once" line re-assigned the same Text, which WPF ignores. So the swatch stayed white until the color was edited. | `Update-AccentSwatch`, called by the handler and once directly after loading. | Live: GUI opened with the saved `#1F4E79` swatch painted |
| **Delivery tab note named `archive\run.zip`,** the old hardcoded name (fixed in code in the pre-release round, not in this label). | Now "the finished run's zip in its archive\ folder". | Live: GUI shows the new text |

## Pre-release review round (2026-10-05) - packaged and run from a PSGallery-style install

Found by publishing to a throwaway local repository, installing from it, and running a Fast
scan from the installed copy on the lab DC.

| Defect | Fix | Verified |
|---|---|---|
| **Delivery never found the zip.** The GUI and `Invoke-NinjaDiscovery.ps1` looked for `archive\run.zip`, but the engine names it `Discover-WindowsServer_<host>_<stamp>.zip`. Only `New-DemoEngagement` and the smoke tests write `run.zip`, which hid it. | `Find-DiscoveryRunZip` in `Send-DiscoveryOutput.ps1` (newest `.zip` under `archive\`), used by both callers. | Pester |
| **No TLS 1.2 on 2012 R2/2016.** Windows PowerShell defaults to `Ssl3, Tls` there (LABSRV12/LABSRV16), which SendGrid, SMTP2GO, M365 SMTP and GitHub refuse. | `Enable-DiscoveryTls12` (adds Tls12, leaves `SystemDefault` alone so TLS 1.3 still works) in the delivery dispatcher; same logic inline before the Ninja wrapper's GitHub download. | Live on LABSRV16: HTTPS to github.com failed before, OK after |
| **EventLogs timed out on a DC.** It loaded every event in the window; 180k Security records hit the 600s deadline and the whole module's data (audit policy included) was dropped. | Query only levels 1-3, or audit failures (AuditFailure keyword) for Security, capped at 20,000 newest per log; `NoMatchingEventsFound` is a clean zero. `TotalEvents` became `RecordsInLog`; new `AuditFailureCount` and `QueryCapped`. | Live on the DC: 14s, all 8 logs, 60 auditpol rows, 0 limitations |
| **Analyzer findings (PSScriptAnalyzer 1.25).** Assignments to the automatic `$args` (Install-LegacyPrerequisites) and `$matches` (RiskEngine `Get-ComplexityRating`); 5 unused variables, one of them a `w32tm /query /configuration` call whose output was never read (up to 30s per run); untyped `$Credential` in two fleet runspace script blocks. | Renamed / removed / typed. String-only credential inputs (NinjaOne parameters, the fleet stdin hand-off, a store key name) are suppressed per function with a Justification; style rules that contradict the design are excluded, with reasons, in `PSScriptAnalyzerSettings.psd1`. | 0 findings with repo settings; 0 errors with Gallery defaults |
| **Not Gallery-ready.** Placeholder GUID; no command to run a scan after `Install-Module`; branding saved inside the module folder (needs admin under Program Files, orphaned by `Update-Module`); Ninja wrapper required a token (private-repo assumption) and wiped the `%ProgramData%` folder branding would live in. | Real GUID; `Invoke-DiscoverWindowsServer` (parameters mirrored from the entry script); branding in `%ProgramData%\Discover-WindowsServer\branding` with `config\` fallback, staged to fleet targets; Ninja scratch moved to `...\ninja`, token optional. New tests: FileList covers every runtime file, GUID isn't the placeholder, wrapper mirrors the entry script, branding lookup order (Core + fleet). | Pester on 5.1 and 7 |
| **Plain-HTTP delivery allowed.** Upload and Postal URLs accepted `http://`, sending client data (and Postal's API key) unencrypted. | `Assert-DiscoveryHttpsUrl` rejects anything but absolute `https://` before any network call. | Pester |

## Real-server test session (2026-09-21) - Server 2025 lab VM, seeded roles, promoted to DC

Host: Server 2025 Datacenter, PS 5.1.26100, elevated and as SYSTEM. First workgroup member
server (IIS, DNS, DHCP-inactive, WSUS/WID, NPS, print, shares, certs, tasks, secrets-bearing
config), then forest-root DC + Enterprise CA. Deep runs: 0 errors, 0 warnings; verifier 35 PASS, 0 FAIL
except the emphasis comparison, which differed by one *environmental* finding (a task re-ran between runs).
Gate: 186 static checks, 143 Pester, smoke test - all green.

**Fixed (all with real-output verification):**
- 🔴 `Test-ModuleCommandExists`: two same-named modules (OS `Storage`/`ActiveDirectory` autoload) made `[bool]` of a 2-element array `$true`, so absent optional hooks "existed" and logged bogus WARNs. Regression test in `tests/Pester/Engine.Tests.ps1`.
- 🔴 `FileShares` deep crawl lacked `-Force`: `$RECYCLE.BIN` is Hidden+System, so the recycle-bin exclusion (F5) was a silent no-op and hidden files were uncounted. Seeded 5 recycled files; now reports 5.
- `FileShares` counted print-queue shares as user shares (and mangled `Path`).
- `Build-CriticalPaths` skipped entirely when ConfigDependencyScan had produced rows (every Deep run), so SQL/Application paths vanished (F6 regression). Now merges, deduped on Path+Source.
- `SQL`: WID (no `Instance Names` key) never got version/edition/deep query; added named-pipe target, `SERVERPROPERTY` version/edition, DB `SizeGB` and `LastBackup` (was declared but always null), `IsWindowsInternalDatabase`. Needs `Data Source=` (not `Server=`) for `np:` targets.
- `NPS_RADIUS`: regex matched `Client name:` but real netsh output is `Name = X` under section headers, so clients/policies were never enumerated. Rewritten with an allow-list; the shared secret is never read.
- `ActiveDirectory`: `gpresult` scope was always labelled `User` and returned nothing under SYSTEM -> now `/scope computer`; FSMO holder match was a bare substring (DC1 vs DC10); `FsmoDetail` no longer carries netdom chatter.
- `UserProfiles.LogonScripts`: now includes NETLOGON scripts and AD users' `scriptPath` on a DC.
- New dataset `CertificateAuthority` (Certificates): configured CA type, publication URLs, and whether they hard-code this server (`%1`).
- `-OutputRoot` is now always resolved to an absolute path (child processes such as secedit resolve relative/drive-relative paths against their own cwd).
- Tests/config: smoke test rebuilt on the two-folder layout and now runs ReportBuilder; stale SNMP redaction test aligned with the 2026-09-18 owner decision; two dead `clientReport` config keys removed (client-safety allow-lists stay hard-coded); verifier no longer fails an empty `errors.txt`.

**SQL round (same day, SQL Server 2025 Express installed as SQLEXPRESS + default MSSQLSERVER, alongside WID):**
- 🔴 WID disappeared as soon as a real instance existed: the service-based detection was a fallback-only path. Now additive (`$knownSvc`).
- Rows from `SqlDatabases`/logins/linked/jobs now carry `Instance` (two instances made every `master` identical).
- 🔴 High TCP listeners were dropped from dependency edges by the DNS-noise filter, hiding a named instance's dynamic port. Filter now drops only non-TCP ephemerals.
- New per-DB `NoFullBackup` (only when msdb is readable; never for WID) and per-instance `XpCmdShellEnabled`, with `RULE-SQL-007` (High) and `RULE-SQL-008`.
- Verified: default + named + WID connect strings, stopped-instance path (limitation logged, other instances still enumerated), and SYSTEM context.
- Gotcha: the SQL installer extracts into its working directory; run it from a scratch folder. `/TCPPORT` is not a valid setup switch.

**Hyper-V round (nested virtualization enabled in Proxmox; Hyper-V installed; 2 switches, 3 VMs: Running Gen2 with 2 checkpoints, Saved Gen2 on a differencing disk, Off Gen1 v8.0 with ISO):**
- 🔴 **Credential leak, systemic.** A VM's `Notes` held a plaintext password and reached `HyperVVMs.csv`, `.json` and the workbook, because redaction was opt-in per field in only 5 collectors. Now `Add-DataSet` runs `Protect-DatasetRows` over every string cell (memoised, idempotent, skips cells already marked `[REDACTED`). Measured over 40,546 real cells first: one true hit, no new false positives; no measurable runtime cost. Tests in `Engine.Tests.ps1`.
- 🔴 **Default Hyper-V/DHCP/DNS cmdlets resolve `$env:COMPUTERNAME` through DNS on every call** (~1 s each here, 20-30x slower than `-ComputerName localhost`), and a resolution failure is swallowed by `-ErrorAction SilentlyContinue` as an *empty result* (F33 class). HyperV 27 s -> 7 s, DHCP/DNS ~1.5 s. Applied via `$PSDefaultParameterValues` inside those three collectors only: **do not extend this to `Get-Printer`**, `-ComputerName localhost` makes it hang on a remote print-server RPC.
- HyperV collector enriched: VHD type/max/file size and parent chain (`IsDifferencing`), VM->switch mapping, `CheckpointCount`, memory min/max (only when dynamic; placeholders otherwise), `VersionBehindHostDefault`. New `RULE-HV-006` (config version behind host default) and `RULE-HV-007` (differencing/checkpoint chain).
- Verified: empty host baseline, SYSTEM context, a VM changing state mid-run, and the rules/questions/report path (client report does not render `HyperVVMs` rows).
- Lab notes: an Internal vSwitch gives the DC a `vEthernet` adapter that registers an APIPA/extra address in DNS, after which the box's own name resolved to an unreachable address and `Start-VM` failed. Give it a static address and turn off DNS registration. Server 2025 rejects VM config versions below 8.0. Differencing children must be `.vhdx`.
- **Not exercised (needs a second host):** `HyperVReplication`, live migration, cluster shared volumes, pass-through disks (no spare physical disk).

**Cluster + storage round (3 machines: DC/node 1, LABVH02/node 2, LABFS01 file server + iSCSI target; cluster LABCLUS01):**
- Toolkit run remotely on all three via `Copy-Item -ToSession` + a SYSTEM scheduled task (a job/Start-Process dies with the remoting session). 0 errors, 0 warnings, verifier clean on every node.
- New `Cluster` datasets `ClusterNodes/Networks/Groups/SharedVolumes`; `RULE-CL-002` (node not Up), `RULE-CL-003` (network not Up: caught the Partitioned lab network).
- New `Storage` datasets `IscsiTargets`, `IscsiVirtualDisks`, `IscsiInitiatorConnections` + dependency edge `UsesRemoteStorage`; `RULE-ISCSI-001` (High: a target serves LUNs to other servers) and `RULE-ISCSI-002`. iSCSI was previously visible only as a role name. Target side only runs when the `WinTarget` service exists (the cmdlets ship everywhere and threw a bogus limitation on the initiator).
- 🔴 `RDS`: `Test-RdsPresent` treated the *existence* of the Terminal Server / licensing registry keys as RDS, which exist on every Windows Server, so a plain file server was reported "Remote Desktop Services role detected" + "RDS licensing dependency". Now requires a chosen CAL mode (2/4), specified licence servers, or `Get-RDServer` results; prerequisite also requires the RDS role feature to be *Installed*. Tests in `Engine.Tests.ps1`. The `Licensing` module had the same flaw independently ("RDS licensing dependency indicator (LicensingMode=1)" on every server) and got the same 2/4-only fix; found only because the round-2 verification re-read the findings, not the datasets.
- Lab/platform findings (not toolkit bugs, but worth knowing): an iSCSI Target Server cannot run on a cluster node (Wintarget disables standalone objects once the node joins a cluster); Hyper-V refuses VMs stored on an SMB share of the same server; **a domain controller as a cluster node crashed 3x (bugcheck 0x7E, identical fault offset, 6-8 min apart) after a CSV was added, and the cluster quarantined the node**. Removing the CSV made it stable (>35 min); a CSV was `Direct` on the non-DC node but `Unavailable` on the DC. Clearing it needed `Start-ClusterNode -ClearQuarantine`.
- HA VM: a VM on `\\LABFS01\VMStore` could not be made a cluster role from the DC ("not a possible owner"); creating it on LABVH02 over **CredSSP** (the double hop to the file share) worked. Live migration failed on nested virtualization even after enabling migration, any-network and `-NotMonitoredInCluster`; quick migration works both ways.

**Disk round (LABVH02 extended to 64 GB; LABFS01 gained a 4 TB disk that is a 14 TB USB HDD on the Proxmox host):**
- LABVH02: the Recovery partition sat between C: and the new space. Procedure that worked: `reagentc /disable` (copies Winre.wim back into C:), verify `C:\Windows\System32\Recovery\Winre.wim`, `Remove-Partition` the recovery partition, `Resize-Partition C` to max minus 1 GB, create a new 1 GB GPT Recovery partition (type de94bba4-...), `diskpart gpt attributes=0x8000000000000001`, copy Winre.wim to `R:\Recovery\WindowsRE`, `reagentc /setreimage` + `/enable`. Ends with WinRE enabled.
- LABFS01 F: (4 TB, quick format, Defender-excluded, 162 small files + a 100 GB `fsutil createnew` file that writes nothing). Toolkit numbers were exact (4095.98 GB, the 100 GB file counted, 80 old files, 1 large file) and the FileShares deep crawl took 1.6 s: it only reads metadata, so a slow USB disk is not a problem. The guest sees the disk as ordinary SATA (`QEMU HARDDISK`), so USB origin is not detectable from inside.
- 🔴 `Storage` listed a mounted ISO / CD-ROM as a volume. It is always 0% free, so **every VM with an attached ISO got a Medium "Volume with low free space" finding** (all three machines here). Optical volumes are now skipped; regression test added.

**Older-OS round (2016 = LABSRV16 .188, 2019 = LABSRV19 .189, 2012 R2 = LABSRV12 .124; all domain-joined; toolkit copies at C:\Discovery):**
- Static self-check (186) and output smoke test pass on Server 2016 (PS 5.1.14393) and 2019 (5.1.17763). **Fast mode** (the default; first time run) completes on both: 0 errors, 22 modules, 50-72 s, verifier clean.
- PowerShell 7.6.6 installed on the DC; the **whole gate passes under PS7** as well as 5.1 (CI parity).
- 🔴 **Per-module deadline** (`Invoke-CollectionWithDeadline`, config `defaults.moduleTimeoutSeconds`, default 600, 0 disables): the engine ran every collector inline, so one hung cmdlet hung the entire run (seen with `Get-Printer -ComputerName localhost`). The collection step now runs in a child runspace of the same process (`$Context` shared by reference), is abandoned at the deadline, and is reported as a limitation. Tests: a normal collector returns its result and mutates the shared context; a deliberately hung one is abandoned in ~3 s.
- **2012 R2** (PowerShell 4.0): `Discover-WindowsServer.ps1` now has `#Requires -Version 5.1` (clear message on PS4). New `tools\Install-LegacyPrerequisites.ps1` (PS3/4-safe syntax): shows a plan, asks before EACH install, **never restarts** (`/norestart`, only reports a pending restart), requires a valid Microsoft Authenticode signature on every installer, supports `-SourceFolder` for offline servers and `-PlanOnly`. Installs PowerShell 7 (default 7.4.20 LTS) + KB2999226 (Universal C Runtime, ~1 MB, needed on 2012 R2) if missing; refuses if KB2919355 is absent (large, restart-needing) rather than doing it. Verified on the real box: plan is correct, and without consent nothing changes (no download, no hotfix, no restart). **Then run with consent on LABSRV12**: KB2999226 (downloaded by the script itself; TLS 1.2 works on the old .NET) + PowerShell 7.4.20 (.NET 8.0.31) in 16 s, PS 7 starts, Windows PowerShell 4.0 untouched, no restart or pending restart.
- 🔴 **First real PS7-on-2012 R2 run was silently 2/3 empty** (27 findings, 39 datasets empty vs 2019). Cause: PS7 hides every Windows PowerShell module whose manifest lacks `CompatiblePSEditions` (all of them on 2012 R2) and its compatibility session needs Windows PowerShell **5.1**, which 2012 R2 lacks. `Get-Command` therefore fails to autoload `Get-NetFirewallRule`, `Get-SmbShare`, `Get-Volume`, ... and 57 call sites read "not available". Fix in `Core`: `Get-CommandAvailable` falls back (PS Core only, after `Get-Command` fails, once per module) to `Import-Module -SkipEditionCheck` for the module that exports the cmdlet. That loads the CIM-based ones (NetSecurity, SmbShare, Storage, ScheduledTasks, PrintManagement, NetAdapter, Dism). Result: 27 -> 89 findings, 39 -> 7 datasets differing from 2019.
- Modules that CANNOT load in PS7 there (need .NET Framework types): ServerManager, WebAdministration, NetTCPIP, DnsClient. `Get-WindowsFeature` (roles) is now obtained by running it in the box's own Windows PowerShell 4 via new `Core` helpers `Invoke-WindowsPowerShellJson` / `Test-WindowsPowerShellModule` (read-only, `-EncodedCommand`, time-bounded), so role detection uses canonical names again; limitations on 2012 R2 now match 2016/2019.
- **Remaining 2012 R2 gaps (vs 2019):** `IisBindings` (WebAdministration), `EstablishedConnections` (Get-NetTCPConnection), `DnsClient`, `LocalGroups` (no LocalAccounts module before WMF 5.1) - each fixable with a fallback (parse applicationHost.config; `netstat -ano`; Win32_NetworkAdapterConfiguration; Win32_Group), and `AppliedGroupPolicy` (not investigated). `AzureAttachment` (no dsregcmd) and `VendorAgents` (no virtio agent) are expected. Alternative for full fidelity: install WMF 5.1 on 2012 R2 (needs .NET 4.5.2+ and a restart) and run under Windows PowerShell 5.1; the installer script does not offer that yet.

**Run matrix round (2026-09-22, LABSRV16/19/12 - HANDOFF task 1, "never done end to end"):** 7 Deep/Fast/Custom runs across
the three older-OS boxes as SYSTEM scheduled tasks (`Copy-Item -ToSession` refresh to `C:\Discovery`, `schtasks /RU SYSTEM`,
pull back with `Copy-Item -FromSession`), exercising every remaining untested combination: `-Mode Custom -IncludeModules`
(LABSRV19), `-ComplianceLens CMMC` + `-SkipZip -Quiet -IncludeRecycleBin` together (LABSRV19), `-ComplianceLens
GeneralSecurity` (LABSRV12), and `-ProjectType` across Decommission/CMMCReadiness/AppMigration/ServerRefresh/
AzureMigration/HyperVRefresh. All 7: 0 errors, 0 warnings, verifier structural checks PASS, no seeded secret found.
- 🔴 **Archive step failed completely silently under a SYSTEM scheduled task** - first real run on LABSRV16 completed
  with `ErrorCount=0 WarningCount=0` but `archive\run.zip` was simply missing, no trace anywhere. Root cause, two
  compounding bugs: `Compress-Folder` (`modules\Output\Output.psm1`) caught its own `Compress-Archive` exception and
  reported it only via `Write-Warning`, whose output is discarded entirely with no host and no stream redirection
  (exactly the SYSTEM-task shape every real run uses); and the caller in `Discover-WindowsServer.psm1` wrapped the
  call in `try/catch` expecting that exception, but `Compress-Folder` never let one propagate - it always returned a
  plain `$false` - so the catch was dead code that could never fire. `Compress-Folder` now retries once (2 s) before
  giving up - a file it zips, like the live status JSON, can still be mid-write when archiving starts, which is the
  likely cause of the one-off failure - and stashes the exception via new `Get-CompressFolderLastError`; the engine
  now checks the actual boolean return and logs a real WARN. Re-ran the same Decommission command on LABSRV16 after
  the fix: zip present, 0 errors/0 warnings. Gate green on PS 5.1 and PS7 (187 static + 150 Pester + smoke test,
  smoke test now also asserts `archive\run.zip` exists).
- ProjectType emphasis (F2/F18) re-confirmed on real hardware, not just the DC: LABSRV16 Decommission-vs-CMMCReadiness
  (40 vs 40 rows, only `IsEmphasized`/priority differs) and LABSRV12 AzureMigration-vs-HyperVRefresh (89 vs 89) both
  verifier-PASS. First LABSRV16 attempt showed a spurious 1-row diff (41 vs 42) - not a toolkit bug: the scheduled
  task used to *launch* the second run was still registered on the box, so its own `ScheduledTasks` collector picked
  up its own launcher as an extra "runs a script/interpreter" finding. Test-harness artifact (schtasks entries left
  behind between runs), same class as the "task re-ran between runs" noise from the 2026-09-21 DC round - fixed by
  deleting each scheduled task immediately after it completes, before creating the next one.
- `-IncludeRecycleBin` confirmed flipping `RecycleBinIncluded` False -> True on LABSRV19 (F5 finish-line item from the
  DC round, now confirmed on a second box); `-SkipZip` confirmed suppressing `archive\` entirely; `-Quiet` produced
  no console noise while still writing full logs.
- 2012 R2's `LocalGroups`/`EstablishedConnections` still read zero, as already known and tracked as HANDOFF task 3 -
  not a new defect, not in scope here.
- Gotcha: `schtasks /Create /TR` chokes on a quoted exe path plus unquoted arguments on 2012 R2's older `schtasks.exe`
  (`ERROR: Invalid argument/option - '-NoProfile'` - it stopped parsing `/TR` at the closing quote and treated the
  rest as new schtasks options). Worked fine on 2016/2019. Fix: use the 8.3 short path for `pwsh.exe`
  (`C:\PROGRA~1\POWERS~1\7\pwsh.exe`, via `(New-Object -ComObject Scripting.FileSystemObject).GetFile(...).ShortPath`)
  so the command has no embedded spaces or quotes to mis-parse at all.

**Non-elevated run round (2026-09-22, LABSRV19, HANDOFF task 2):** Deep run as domain user `alice` (plain Domain
User, confirmed not a member of the local Administrators group), non-elevated, headless via Task Scheduler.
Run folder owner confirmed `CORP\alice`. Result: 0 errors, 0 warnings, no hang (46.5 s), 12 clearly-labeled
limitations, verifier all-PASS on every applicable check (the rest correctly `[BLOCKED]`, e.g.
`raw\userrights.inf` - "secedit /export needs an elevated session"), no seeded secret. Findings dropped from the
elevated baseline (27 vs the ~40s seen elsewhere) and 39 datasets went empty (IIS, BackupDR, UserRightsAssignments,
Services/ServiceDependencies, Volumes/Partitions/Disks, SQL, iSCSI, ...), each with a named cause in
`limitations.txt` - the toolkit's actual behavior is **degrade gracefully with a per-capability limitation**, not a
blanket "skip modules with `RequiresAdmin=true`" (that metadata field is declarative only; enforcement is coded per
module in `Test-DiscoveryPrerequisites`/inline checks against `$Context.IsAdmin`, and most modules choose to collect
whatever they can rather than skip outright). This is arguably better than a hard skip and satisfies the spirit of
the acceptance test (no exception, no hang, every gap explained) even though the literal mechanism differs from how
the task was originally phrased.
- Minor: `[IIS] Get-Website failed.` has no reason suffix, unlike sibling messages (`... may require elevation.`
  etc.) - cosmetic, folded into the task 5 small-bug bundle rather than fixed here.
- Test-harness note, not a toolkit gap: a plain Domain User has no "Log on as a batch job" right by default, so a
  headless scheduled-task run as one needs it granted first (`secedit` export/edit/import on `USER_RIGHTS`,
  `SeBatchLogonRight`). Granted to `alice` on LABSRV19 for this test only and reverted immediately after (verified
  the exported policy matches the pre-change export exactly). `Start-Process -Credential` was tried first as a
  policy-free alternative and fails over WinRM with "Access is denied" (needs an interactive window station a
  remoting session doesn't have) - not usable for this pattern.

**2012 R2 dataset-gap round (2026-09-22, LABSRV12, HANDOFF task 3):** All five listed gaps addressed. Gate green on
PS 5.1 and PS7 (187 static + 150 Pester + smoke test) both before and after deploying; fresh Deep run on LABSRV12
after the fix: 0 errors, 0 warnings, `EstablishedConnections=6 FirewallRules=63 ListeningPorts=33 LocalGroups=23
Partitions=2 PrinterDrivers=3` (F33 regression check), no seeded secret.
- 🔴 **Root cause for `EstablishedConnections` (and most of `ListeningPorts`) was a double-array-wrap, not a missing
  module.** `Network.psm1`'s `Get-NwNetstatRows` already returns a clean array via `,@($rows)` (per the codebase's
  own documented convention - see the comment two lines above the bug at `Discover-WindowsServer.psm1`). The
  netstat-fallback gate wrapped that return in an *extra* `@()`: `$netstat = @(Get-NwNetstatRows -Context $Context)`.
  That produces a 1-element array whose single element **is** the real array, so `Get-NwListeningRows`/
  `Get-NwEstablishedRows`'s `foreach ($n in @($Netstat))` ran its body exactly **once**, over the whole array via
  PowerShell member-enumeration (`$n.Protocol` on an array returns an array of every row's Protocol, not one
  value) - producing at most one garbled row instead of one row per connection. Proved with a live A/B on LABSRV12:
  `Get-NwNetstatRows -Context $null` alone → `Count=43`; `@(Get-NwNetstatRows -Context $null)` (the buggy call
  shape) → `Count=1`, and `doubleWrapped[0].Count` → `43`. This bug is not 2012-R2-specific - it would misfire on
  *any* box where `Get-NetTCPConnection` is unavailable - but this lab has no other box that ever takes the
  netstat-fallback path, so it was invisible until this task exercised it. Fix: drop the redundant `@()`.
  `ListeningPorts` 1 -> 33 rows, `EstablishedConnections` 0 -> 6 rows on the same LABSRV12 run.
- `IisBindings`: the appcmd fallback (`modules\IIS\IIS.psm1`, used when `WebAdministration` can't load) already
  parsed each site's raw bindings text but only to display it on the `IisSites` row (`Bindings=...`) - it was never
  split into `IisBindings` rows at all. Also fixed a latent truncation in the site regex: `bindings:([^,]+)` stopped
  at the *first* comma, so a site with more than one binding (e.g. http + https) would have silently lost every
  binding after the first even in the raw `Bindings` text; changed to `bindings:(.+?),state:` (non-greedy up to
  `,state:`) so multi-binding sites parse correctly, not just this lab's single-binding site. `CertificateHash` is
  left blank in the fallback (matching the primary WebAdministration path's own best-effort nature, and there was no
  HTTPS binding anywhere in this lab to test against); a cross-reference against `CertificateBindings` (which the
  Certificates module already owns) was considered and skipped as unneeded scope.
- `DnsClient`: the per-interface-DNS-servers section had no fallback at all when `Get-DnsClientServerAddress` was
  unavailable (only the suffix-search-list section already had one, via a registry read). Added a
  `Win32_NetworkAdapterConfiguration` (CIM, `IPEnabled = True`) fallback via the existing `Invoke-CimSafe` helper.
- `LocalGroups`: same shape of gap - `Get-LocalGroup` (LocalAccounts module, needs WMF 5.1+) had no fallback. Added
  `Win32_Group -Filter 'LocalAccount = True'` via `Invoke-CimSafe`. Also gave the "other sensitive groups" member
  lookup (Remote Desktop Users/Backup Operators/Hyper-V Administrators, `SecurityPosture.psm1`) the same `net.exe
  localgroup` fallback that `Get-LocalAdministrators` two dozen lines above already used successfully - not itself
  in HANDOFF's list, but the identical unavailable-cmdlet problem in the same file.
- `AppliedGroupPolicy`: **genuinely not a toolkit bug** - `gpresult /scope computer /r` returns exit 0 with `INFO:
  The user "..." does not have RSoP data.` on this specific LABSRV12 box, even as a full Administrator and even
  immediately after a successful `gpupdate /force`. Confirmed by A/B against LABSRV19, which returns real applied
  GPOs (`Default Domain Policy`, `Lab Baseline`) for the identical command. Root cause is outside the toolkit
  (2012 R2 RSoP/WMI logging state on this VM specifically) and out of scope to chase further. What *was* a toolkit
  bug: this failure mode produced a **silently empty dataset with no limitation at all**, because the parser only
  logged a limitation on the `else` branch (`$rg.Succeeded -eq $false`), and this case exits 0 - the "does not have
  RSoP data" text isn't the "Applied Group Policy Objects" header the parser looks for, so it fell through with
  nothing captured and nothing logged. Fixed by tracking whether that header was ever seen at all, and logging the
  tool's own first output line as a limitation when it wasn't - still 0 GPOs after the fix, now with an honest
  reason instead of a silent gap.

**Firewall truncation round (2026-09-22, the DC, HANDOFF task 4):** Root-caused, not just tuned. The 300-rule
cap and 45s enrichment time budget existed because `Get-NetFirewallPortFilter`/`Get-NetFirewallApplicationFilter`
piped **one rule at a time** each re-query the *entire* filter store per call - measured at ~190ms/rule on the DC's
345 rules (extrapolates to 65s+ for all of them, which is exactly the ~62s this project's own runtime notes already
recorded). Both cmdlets accept no filter arguments and cost the same whether queried for one rule or all of them, so
fetching each **once** for every rule up front and joining by `InstanceID` (shared between a rule and its own
filters - confirmed directly: a rule's `InstanceID` equals its `PortFilter.InstanceID` equals its
`ApplicationFilter.InstanceID`) replaces up to 690 individual cmdlet calls with exactly 2. Benchmarked on the DC:
enumerate + fetch-all + join for all 345 rules = 3.5s total (was 65s+), with **every** rule fully enriched -
no cap needed at all in practice. `$maxRules` raised from 300 to 20000 as a sanity backstop only (no longer doing
any performance work), and the time-budget/"enrichment stopped early" mechanism removed entirely - there is no
longer a per-rule cost for it to protect against. Verified live and end-to-end (not just benchmarked in isolation):
`.\Discover-WindowsServer.ps1 -Mode Custom -IncludeModules Network` on the DC completed in 49s total, `FirewallRules`
= 345 rows, **all 345 with `Protocol` populated**, `limitations.txt` empty - the literal HANDOFF accept criterion
("no truncation limitation on this lab"). Gate green on PS 5.1 and PS7.

**Small-bug bundle (2026-09-22, the DC, HANDOFF task 5):** All five items resolved, one turned out to be
clean. Verified together with a real full Deep run on the DC (357s, 0 errors, 0 warnings, verifier 0 FAIL,
no seeded secret) rather than trusting each fix in isolation - see below, that run caught a real regression
the isolated checks would have missed.
- 🔴 **TimeSync's "second mostly-empty row" was a second collector, not a formatting bug.** `SystemInventory.psm1`
  had its own older, independent, partial TimeSync collection (`TimeZone`/`CurrentTime`/`LastBootTime`/
  `W32TimeSource`/`Stratum`/`LastSuccessfulSync` only) that predates the dedicated `TimeSync.psm1` module and
  was never removed - both wrote to the same `TimeSync` dataset name, which `Add-DataSet` appends rather than
  replaces, so every run always had two rows: one rich, one sparse. Deleted SystemInventory's copy outright
  (strictly superseded, not merged) rather than reconciling two schemas for the same fact.
- 🔴 **"No rule flags a forest-root PDC on Local CMOS Clock" was a module-ordering bug.** `RULE-TIME-001` keys on
  `BrokenDomainTimeHierarchy` (`= $isDomainMember -and $usesLocalClock`), and `TimeSync` computes
  `$isDomainMember` by reading the `DomainContext` dataset - but `config/default.discovery.json`'s
  `collectorModuleOrder` ran `TimeSync` *before* `ActiveDirectory` (the module that produces `DomainContext`),
  so that dataset was never there yet and `$isDomainMember` was always `$false`, unconditionally, regardless of
  actual domain membership. The rule could never fire for ANY domain member, not just PDCs. Fixed by swapping
  the two in the order list. Confirmed on the DC (a forest-root DC, genuinely running off `Local CMOS Clock`
  right now, `w32tm /query /source` checked directly): `BrokenDomainTimeHierarchy` now reads `true` and
  `TimeSync` is a single row.
- `HybridIdentity` reporting an unconfigured AD FS as `Likely`: `Test-AhEvidence` (`AzureHybrid.psm1`) treated a
  matched service as equally strong evidence whether it was actually running or merely installed-and-stopped -
  a real distinction on this lab DC, where AD FS was installed for role-detection coverage but no farm was ever
  configured. Now checks the matched service's `Status` and reports `Possible` instead of `Likely` when it isn't
  running. Getting this to actually change the *finding* (not just the raw dataset row) needed a small, genuinely
  useful RiskEngine addition: `emitPerRow` rules already supported `evidenceField` (read a row's identifying
  value into the finding); added the matching `confidenceField` so a rule can likewise take its confidence from
  the row instead of one static value for every emitted finding regardless of content. Wired into
  `RULE-HYBRID-001`. Confirmed on the DC: AD FS (`service:adfssrv`, not running) now emits `Possible`.
- `ConfigDependencyScan` spending ~19% of hints on `C:\inetpub\history`: IIS auto-backs up its whole config into
  a new `CFGHISTORY_nnnnnnnnnn` folder on every change and keeps several - 6 on this lab DC, each a
  near-complete duplicate of the last - so scanning all of them just re-finds the same facts repeatedly. Now
  scans only the newest backup folder (name's numeric suffix is IIS's own ordering). Measured on the DC:
  `C:\inetpub\history` hints dropped from what would have been ~19% to 2.8% of a 3179-hint run.
- 🔴 **`publicKeyToken` redaction was destroying real evidence for something that was never a secret.** Same root
  cause as the `community` over-redaction already fixed 2026-09-18: `redaction-patterns.json`'s
  `KeyedSecretAnyDelimiter` pattern matches "token" as a bare substring with no word boundary, so
  `publicKeyToken="b03f5f7f11d50a3a"` (a .NET assembly's public strong-name identity hash - never secret, and
  common in any `<assemblyIdentity>`/`bindingRedirect` config) got blanked to `publicKeyToken=[REDACTED]`.
  Added `(?<!publickey)` immediately before the bare `token` alternative - narrow enough that `SecurityToken`,
  `ApiToken`, `sasToken` etc. still redact correctly (verified all four shapes directly). **Caught a real
  regression this fix caused**, only because verification used a real Deep run instead of trusting the isolated
  fix: `tools\Verify-DiscoveryRun.ps1` has its *own*, independent "credential-shaped value survived redaction"
  safety-net regex, which also matches bare "token" with no exception - so the moment the toolkit correctly
  stopped hiding `publicKeyToken` values (582 of them on the DC), the verifier flagged all of them as
  `[FAIL] credential-shaped values survived redaction`, a false alarm that would read as a real leak to
  whoever runs it. Applied the identical `(?<!publickey)` exception there; re-run confirmed 0 survivors, 0 FAIL.
- `NetworkAdapters` name field: **checked, not a bug.** `InterfaceAlias` was populated and non-empty on every
  real run collected this session - LABSRV16/19/12 (`"Ethernet"`) and the DC, including its Hyper-V `vEthernet`
  virtual adapter (`"vEthernet (LabInternal)"`). No fix made.
- Gate green on PS 5.1 and PS7. Module load order: `ActiveDirectory` now runs before `TimeSync` in
  `collectorModuleOrder` - worth remembering if a future module needs `DomainContext` and is placed near there.

**Report review round (2026-09-22, the DC, HANDOFF task 6):** Opened both reports from a real Deep run in a
browser (a throwaway local static-file server, since the browser pane can't act on `file://`). Found real bugs,
not just cosmetics - none of the previous sessions had actually looked at the client report rendered.
- 🔴 **The client report's per-item tables were silently collapsing every row into one.** `Shared folders`,
  `Shared printers`, `Third-party products installed`, `Business applications we recognised`, and `Things worth
  your attention` all rendered as a single row with every value space-joined together (e.g. 12 share names
  concatenated into one cell, 12 descriptions into the other, names and descriptions no longer paired). Root
  cause is a genuine PowerShell gotcha, confirmed with a controlled A/B: a function returning `,@($rows)` (the
  established idiom in this codebase, so an empty dataset survives as `@()` instead of unrolling to `$null`)
  unrolls correctly on **direct assignment** (`$x = Get-Foo`) but **not** when piped into `Where-Object`/
  `ForEach-Object` (`Get-Foo | Where-Object {...}`) - the whole array arrives as a single `$_` there, and
  `[string]$_.SomeField` then space-joins that field across every row via PowerShell member enumeration.
  `ReportBuilder.psm1`'s `Get-RbClientModel` did exactly that for every client-report table
  (`Get-RbRows -Context $Context -Name 'X' | Where-Object {...} | ForEach-Object {...}`), and separately
  double-wrapped `Get-RbClientHeadlines`'s own `,@()` return in an extra `@()` at the property assignment (the
  same "`@()` around an already-`,@()`-returning call" shape fixed twice already this session in `Network.psm1`
  and `Get-CompressFolderLastError`'s caller). Fixed by assigning `Get-RbRows`'s result to a variable before
  piping it, and dropping the redundant outer `@()` on `Get-RbClientHeadlines`. Searched the rest of the
  codebase for the same "call a `,@()`-returning function and pipe it directly" shape (`grep` for
  `-Context \$Context ... | Where-Object|ForEach-Object`) - this was the only place it occurs; everywhere else
  either assigns first or builds rows via `[List[object]]::new()` + `.Add()`, which isn't susceptible.
  Verified on the DC: `Shared folders` 1 row -> 12 correctly-paired rows, `Things worth your attention` 1
  blank row -> 14 real rows (this one already had a proper "nothing to raise" fallback message for the
  genuinely-empty case - it just could never be reached, since the bug made `.Count` read `1` even when the
  real array was empty).
- User feedback mid-review: `MSSQL$MICROSOFT##WID` (Windows Internal Database - the SQL engine WSUS/ADCS/etc.
  install for themselves, not something a client owns or licenses separately) was showing up in the High-severity
  "SQL Server instance detected" finding alongside real instances, which is noise for planning purposes. The
  `SqlInstances` dataset already carries an `IsWindowsInternalDatabase` flag from the 2026-09-21 SQL round, so
  `RULE-SQL-001`'s condition changed from `datasetNotEmpty` to `anyRowFieldNotEquals` on that field - the new
  `anyRowFieldNotEquals` condition type already existed in the engine, unused until now. WID stays fully visible
  in the raw `SqlInstances` export and still surfaces via the lower-severity `RULE-SQL-002` ("deep database
  enumeration was not performed") - left that one alone; excluding WID there too would need a compound
  AND-condition the rule engine doesn't support yet, and it's the Medium-severity secondary finding, not what
  prompted the ask. Verified on the DC: the High finding now lists 2 instances instead of 3; WID absent from it.
- Both fixes verified together with a fresh Deep run end to end (not just the isolated repro): 0 errors, 0
  warnings, verifier 0 FAIL, 0 seeded secrets, gate green on PS 5.1 and PS7.

**Feature round (2026-09-22, the DC, HANDOFF task 8 / TODO "Then" phase N4/N5/N6):** Checked the "Then" phase
plan (N4/N5/N6/F21) against the actual code before doing anything - it was written before several later
sessions, and two of its three items turned out to already be done.
- **N5 (narrower scream-test rendering) - already done.** `Discover-WindowsServer.psm1`'s `scream-test-plan.md`
  generator already renders one section per function, not the old 10-column table; the code comment there
  documents the exact fix N5 asked for. No action needed - the phased-plan table just never got updated.
- **N6 (`-WhatIf`/dry-run mode) - genuinely missing, now added.** `Discover-WindowsServer.ps1` takes `-WhatIf`;
  `Invoke-Discovery` resolves the module plan and writes `discovery-plan.md` exactly as a normal run does, then
  stops before any collector runs - reuses `Resolve-ModuleSelection`/`Write-DiscoveryPlan` as-is rather than a
  parallel no-context code path. Verified live: Deep mode WhatIf printed all 29 modules and exited in 2.3s
  (vs. ~6 min for a real run), writing only the plan + empty log/status skeleton - no datasets, no reports, no
  zip. Custom mode with `-IncludeModules` correctly narrowed the plan to just those modules; `-Quiet`
  correctly suppressed the console listing while still writing the plan file.
- **N4 (new MSP scoping rules) - checked all 5 listed items against the code; 3 already existed** (OS
  end-of-life, hotfix recency via `UpdatePosture.PatchingLooksStale`, and the `anyRowFieldNotEquals`/
  `anyRowFieldMatches` condition types F21 called "unused" - `anyRowFieldNotEquals` was in fact just used for
  the WID exclusion earlier this session). Added the 2 genuinely missing ones:
  - **Domain/forest functional level.** Not collected at all before. Added via `[ADSI]'LDAP://RootDSE'`
    (`domainFunctionality`/`forestFunctionality`) - works on any domain-joined machine, no RSAT/
    ActiveDirectory module needed, unlike `Get-ADDomain`/`Get-ADForest`. New `RULE-DC-003` flags
    Windows2000/2003/2008/2008R2 as legacy (Medium). Verified on the DC: `DomainFunctionalLevel` /
    `ForestFunctionalLevel` = `Windows2016` (this lab's real level - correctly does NOT fire the rule, a true
    negative confirmed by direct regex testing against the full range of level names).
  - **SQL edition vs. core count.** `SqlInstances.Edition` and `Processors.NumberOfLogicalProcessors` already
    existed in separate datasets with no rule joining them. `SQL.psm1` now sums logical processors across all
    `Processors` rows once (SystemInventory runs before SQL in `collectorModuleOrder`, so it's already there)
    and stamps it onto every `SqlInstances` row as `HostLogicalProcessors`. New `RULE-SQL-009` fires on
    `Edition -match Enterprise` (Medium - per-core licensing is a real cost driver). First attempt stamped the
    field via `Add-Member` post-collection and failed `Invoke-ToolkitSelfCheck.ps1`'s "every {Token} exists in
    its producer" check - it discovers dataset fields by static AST scan of `[pscustomobject]@{...}` literals
    and member-expressions, so a field added only via `Add-Member` at runtime is invisible to it. Fixed by
    computing the sum once up front and including `HostLogicalProcessors` as a literal property in both
    `SqlInstances` row constructors instead. Verified on the DC: all 3 instances (Express edition, so
    correctly does not fire RULE-SQL-009) show `HostLogicalProcessors=6`, matching the real hardware.
  - `datasetRowCountAtLeast` (F21's other "unused" condition type) remains genuinely unused - no natural fit
    found this round; left as pre-emptive hardening per F21's original note.
- Gate green on PS 5.1 and PS7 both before and after; verified end-to-end with a fresh Deep run (0 errors, 0
  warnings, verifier 0 FAIL, 0 seeded secrets).

**DNS records round (2026-09-22, the DC, N4's 5th item / HANDOFF's "DNS records" feature ask):** The one N4
item that needed a genuinely new collector, not just a new rule joining data that already existed. `DNS.psm1`
previously only reported zone summaries (name/type/DS-integrated), never record content.
- New `Get-DnsRecordsReferencingThisServer`: for every non-reverse zone, walks its A/CNAME records and matches
  each against this server's own hostname/FQDN (`$env:COMPUTERNAME`/`$env:USERDNSDOMAIN`) and IP addresses
  (reused from the already-collected `IPConfiguration` dataset - `Network` runs before `DNS` in
  `collectorModuleOrder`, so no re-querying). Capped at 3000 records examined across all zones (same shape as
  `ConfigDependencyScan`'s file/hint caps), with a limitation logged if the cap trips. New dataset
  `DnsRecordsReferencingThisServer` (`ZoneName`, `RecordType`, `RecordName`, `PointsTo`); new `RULE-DNS-002`
  (Medium, one finding per matching record) - "what resolves this record to reach this server, and does it get
  updated as part of the migration/decommission plan?"
- Verified `RecordData` field names live rather than guessing: A records expose `RecordData.IPv4Address`,
  CNAME records expose `RecordData.HostNameAlias` (trailing dot - `.TrimEnd('.')` before comparing).
- **Real positive matches on this lab, not just true negatives like the other N4 rules:** 14 records found,
  including the zone apex and hostname A records (expected), the cluster's `LABCLUS01` A record (this DC is a
  cluster node, so one of the cluster's addresses is genuinely registered on it), and a `CNAME intranet ->
  CLAUDEWIN2025DE...` record seeded earlier in this lab's history - exactly the kind of "this breaks silently
  on rename/retirement" case the feature exists to catch. `RULE-DNS-002` correctly produced 14 matching
  findings. 0 errors, 0 warnings on both a targeted `Network,DNS`-only run (45.6s) and a full Deep run (332s,
  152 findings up from 141, verifier 0 FAIL, 0 seeded secrets). Gate green on PS 5.1 and PS7.

**Still open / not built:**
- CSV state is recorded per volume only. A CSV that is Online at the resource level but `Unavailable` on one node (seen on the DC) is not visible; per-node state via `Get-ClusterSharedVolumeState` would show it (not added: no live CSV left to verify against).
- Runtime: a Deep run is now ~6 min here (down from ~9), dominated by `ConfigDependencyScan` (now much lighter after the inetpub/history fix) and `BackupDR` (~34 s). WMF 5.1 installer option for 2012 R2 (needs a restart, so it must ask first - not built); fixture-based collector tests (not built); `[IIS] Get-Website failed.` has no reason suffix unlike sibling limitation messages (cosmetic, noticed during the non-elevated-run task); Hyper-V/Cluster collectors could not be exercised on the older-OS boxes (no nested virtualization there).

## Windows validation log (session of 2026-08-21)

### Validation host capabilities — read this before trusting any "confirmed" below

The validation host is **not** a Windows Server and the session is **not elevated**. This bounds
what can be confirmed here:

| Host fact | Value | Consequence |
|---|---|---|
| OS | Windows 11 Enterprise 10.0.26200 | `ProductType = 1` (workstation, not server) |
| Elevated | **No** | `secedit /export` and privileged registry/CIM reads fail or return partial data |
| `Get-WindowsFeature` | **absent** (server-only cmdlet) | `RolesFeatures` cannot collect normally |
| IIS / `appcmd.exe` | **absent** | `IisSites` will always be empty |
| `Get-SmbShare` | present | share enumeration is testable |
| SQL Server | none detected | `SqlInstances` empty |

**Items 2, 3, 5 and 7 of the WINDOWS-VALIDATION.md table therefore cannot be fully confirmed on
this host** — they need an elevated session on a real Windows Server with SQL and/or IIS. They are
recorded as **BLOCKED (host)**, never as passing. Items 1, 4, 6 and 8 are testable here.

### Step 1 — `Invoke-AllChecks.ps1` under real Pester: ✅ ALL CHECKS PASSED (exit 0)

| Layer | Result |
|---|---|
| `Invoke-ToolkitSelfCheck.ps1` | ✅ PASS |
| `Invoke-OutputSmokeTest.ps1` | ✅ PASS (43 datasets, 42 worksheets, all required artifacts) |
| Pester suite | ✅ **114 passed / 0 failed / 2 skipped** |

The 2 skips are legitimate and expected: `Core` and `Output` are framework helper modules that
deliberately expose no `Get-DiscoveryModuleMetadata`, and the test calls `Set-ItResult -Skipped`
for exactly that case.

**The predicted macOS-only failure did vanish.** `Core.Tests.ps1` → `ConvertTo-SafeFileName` →
'replaces invalid characters' now passes (Core.Tests.ps1 is 14/14), confirming the diagnosis that
`GetInvalidFileNameChars()` returning 2 chars on Unix vs 41 on Windows was the whole story. No real
bug there.

Pester note: the Gallery installed **Pester 6.1.0**, not 5.x. The suite declares
`#Requires -ModuleVersion 5.0.0` and runs clean on 6.1.0, so no pinning was needed.

### ✅ F26 — FIXED 2026-08-21 — F25's bug class survived in a second Describe

Real bug, found by the first-ever real-Pester run. `RiskEngine.Tests.ps1` →
`Describe 'Discovery plan generation'` → 'writes discovery-plan.md' failed with
**`The term 'New-DiscoveryContext' is not recognized`**.

Same root cause as F25: `Describe 'Module metadata contract'` imports every module directory and
`Remove-Module`s each one in its `finally` — including `Core`, `Output` and `RiskEngine` — so it
unloads the framework partway through the file. F25 fixed this for the `Project-type emphasis`
Describe by giving it its own `BeforeAll`, but **`Discovery plan generation` sits between the two
and was missed**. It never surfaced on macOS because the offline Describe/It shim used there did
not emulate `Remove-Module` module-scope teardown.

Fixed at the root rather than per-site:
1. The framework import is now a named helper, `Import-DiscoveryFrameworkForTest`, defined in the
   file-level `BeforeAll`.
2. `Describe 'Module metadata contract'` gained an **`AfterAll` that re-imports the framework**, so
   every Describe that follows it gets a working framework regardless of ordering. This is the
   class fix — adding a new Describe after it can no longer reintroduce the bug.
3. `Discovery plan generation` also sets itself up via the helper (defence in depth) and now uses
   its own `$script:PlanConfig` instead of reaching for the outer `$Config`.

The `Remove-Module` in the loop was **kept deliberately** — without it, a module exposing no
metadata would silently be tested against the previously-loaded module's
`Get-DiscoveryModuleMetadata` and produce a false pass. A comment now records that.

Verification: suite **114 passed / 0 failed / 2 skipped**; `Invoke-AllChecks.ps1` exits 0 with all
three layers PASS.

### Under version control as of 2026-08-21

`github.com/ghostinator/Discover-WindowsServer` — **private** (the repo carried hardcoded
company-branded draft scope/contract language at this point, so it was not public - since made
configurable, see the 2026-09-27/28 branding entries below). This closes the Phase 5 "nowhere to
hang a pre-commit hook" gap:

- **`.githooks/pre-commit`** runs the self-check + output smoke test before every commit. Enable
  per clone with `git config core.hooksPath .githooks` (already set on this machine). The Pester
  suite is deliberately left to CI so the hook stays fast.
- **`.github/workflows/checks.yml`** runs `Invoke-AllChecks.ps1` on `windows-latest` under **both
  PowerShell 7 and Windows PowerShell 5.1**, both required.
- **`.gitignore`** excludes discovery output. That output is client data — share paths, ACLs,
  service accounts, listening ports, event-log samples — and must never be committed. Verified:
  a stray run written inside the repo folder produced zero git-visible changes.
- **`.gitattributes`** pins CRLF for PowerShell/JSON/Markdown and LF for `.githooks/*` (a CRLF
  shell script fails with a bad-interpreter error).

Commit identity is overridden per-repo (`.git/config`); the global git identity on this machine
is a different address.

### The 5.1 CI job immediately earned its keep — 4 real defects (F27–F30)

Adding Windows PowerShell 5.1 to CI was meant to be informational. Its **first run found four
genuine defects that PowerShell 7 structurally cannot expose.** All four are fixed; the job is now
a **required** check. Do not demote it.

### ✅ F27 — FIXED 2026-08-21 — `-Include` is silently ignored with `-LiteralPath` on 5.1

`tests/Invoke-ToolkitSelfCheck.ps1` enumerated files as
`Get-ChildItem -LiteralPath $root -Recurse -Include *.ps1,*.psm1,*.psd1 -File`. Windows PowerShell
5.1 **silently ignores `-Include` when it is combined with `-LiteralPath`**, so the self-check
tried to parse every file in the tree as PowerShell — `.md`, `.json`, `.yml`, `.gitignore` — and
reported dozens of phantom parse failures. PowerShell 7 honours the combination, which is why the
audit machine never saw it.

Fixed by filtering on `$_.Extension` explicitly (identical on both runtimes) and excluding `.git`.
Both runtimes now run exactly the same **164** checks.

### ✅ F28 — FIXED 2026-08-21 — `Get-Content` without `-Encoding` reads UTF-8 as ANSI on 5.1

The `FIELD-USAGE.md` contract check truncates each row at the em-dash (`[char]0x2014`) because only
the field list before it is a contract; the prose after it may legitimately name other datasets.
The docs are **UTF-8 with no BOM**, and 5.1 defaults `Get-Content` to the ANSI codepage — so the
em-dash arrived as mojibake, `IndexOf` returned `-1`, nothing was truncated, and dataset names in
the prose were then validated as if they were documented *fields*. Result: 3 phantom failures
(`ApplicationFingerprints.ListeningPorts` / `.IisSites` / `.SqlInstances`).

Fixed with explicit `-Encoding UTF8` on that read and the harness's other whole-file reads.

**Scope of the encoding hazard, checked rather than assumed:** all 8 `config/*.json` files and all
44 PowerShell files are **pure ASCII**. Non-ASCII exists only in the Markdown docs (318 chars —
em-dashes, arrows, `≥`). So there is **no** mojibake risk to `risk-rules.json`, the redaction
patterns, or any client deliverable. `SecurityPosture.psm1` reads `userrights.inf`, which `secedit`
writes as UTF-16 **with** a BOM, so BOM auto-detection handles it on both runtimes.

### ✅ F29 — FIXED 2026-08-21 — **`datasetNotEmpty` never fired for a single-row dataset on 5.1**

**The serious one.** `RiskEngine.psm1` built its row list as:

```powershell
$rows = if ($exists) { @($Context.DataSets[$dsName].Rows) } else { @() }
```

An `if` block writes to the **pipeline**, and the pipeline **unrolls** a 1-element array to a bare
scalar (and an empty array to `$null`). PowerShell 7 gives every object a `.Count` of 1, so this
works there. Windows PowerShell 5.1 does not: `$rows.Count` is `$null`, `$null -gt 0` is `$false`.

Measured, not inferred:

| Rows in dataset | 5.1 before fix | 5.1 after fix | PS 7 |
|---|---|---|---|
| **1** | **`$false` — BROKEN** | `$true` | `$true` |
| 2 | `$true` | `$true` | `$true` |
| 3 | `$true` | `$true` | `$true` |

`datasetRowCountAtLeast` was broken the same way. `anyRowFieldEquals`/`Matches`/`LessThan` were
**not** affected, because they pipe `$rows` instead of counting it — which is exactly why only one
test failed and the rest looked healthy.

**Impact:** on the documented target runtime, any `datasetNotEmpty` rule silently failed to fire
whenever its dataset had exactly one row. Single-row datasets are the normal case for
`DomainContext`, a lone SQL instance, a single certificate, one cluster, and so on. Rules did not
error — the findings simply never appeared, which is the exact silent-failure class this audit
exists to eliminate.

**Fixed at 26 sites** across 13 modules by wrapping the whole expression in `@(...)`, which forces
an array on both runtimes and is idempotent. 7 of the 26 were provably live (the variable was
`.Count`ed or indexed): `RiskEngine.psm1:64`, `RDS.psm1:65`, `FileShares.psm1:65`, and
`Output.psm1:119/217/321/673`. Two consequences worth noting beyond the RiskEngine one:

- `FileShares` reported a **blank `FileCount`** for a share containing exactly one file.
- `Output`'s table writers rendered an **empty table instead of `_No data._`** for an empty
  dataset, because `@()` from an if-block unrolls to `$null`.

`RiskEngine.psm1:340` (`$wbsArea`) was **deliberately not** wrapped: its `@(` is in the *condition*,
and the expression yields a scalar string for a CSV column — wrapping it would have turned that
column into an array.

### ✅ F30 — FIXED 2026-08-21 — the same unrolling class in three test assertions

`($list | Where-Object {...}).Count` has the same defect: with exactly one match the pipeline
unrolls and `.Count` is `$null` on 5.1. Three sites, all in the suite — `RiskEngine.Tests.ps1:76`
(the one that failed) plus two latent ones in `Output.Tests.ps1`. All now use `@(...).Count`.

This is the **same antipattern F13 fixed** in 2026-08. It came back because nothing was watching
for it — hence the new static check below.

### New guards so F29/F30 cannot silently return

1. **Self-check #12 — "no PowerShell 5.1 array-unrolling hazards"** (`Invoke-ToolkitSelfCheck.ps1`).
   Flags both shapes: an assignment from an if-block with a collection branch, and `.Count` on an
   unwrapped pipeline. The first uses the **AST**, not a regex, specifically so a collection in the
   *condition* (the `$wbsArea` shape) is not a false positive. A line may opt out with a
   `lint-allow-pipeline-count` marker; exactly one line needs it — the lint's own pattern literal.
   **Negative-tested:** reintroducing the `RiskEngine.psm1:64` hazard makes it fail at that exact
   line, and it passes again on restore.
2. **Four new Pester tests** (`RiskEngine.Tests.ps1`) asserting `datasetNotEmpty` fires at 1, 2 and
   3 rows, plus `datasetRowCountAtLeast` on a single row. Row counts are **parameterised on
   purpose** — the bug appeared *only* at exactly 1 row, so a 2-row fixture would have missed it.
   **Negative-tested:** with the hazard reintroduced, 3 tests fail, including the 1-row case, while
   the 2- and 3-row cases still pass.

### Current state of the gate — green on both runtimes

| Layer | PowerShell 7.6.5 | Windows PowerShell 5.1 |
|---|---|---|
| `Invoke-ToolkitSelfCheck.ps1` | ✅ 164 checks, 0 failures | ✅ 164 checks, 0 failures |
| `Invoke-OutputSmokeTest.ps1` | ✅ PASS | ✅ PASS |
| Pester suite | ✅ **118 passed / 0 failed / 2 skipped** | ✅ **118 passed / 0 failed / 2 skipped** |

### Step 2 (partial) — first real Fast-mode discovery run

`.\Discover-WindowsServer.ps1 -Mode Fast` completed in **55.4s**: **71 findings, 87 datasets,
9 limitations, 0 errors**. 4 application fingerprints matched. Modules correctly self-skipped on
absent prerequisites (DNS, DHCP, IIS, Cluster, NPS). `RolesFeatures` fell back to **DISM** since
`Get-WindowsFeature` is server-only — worth noting that the fallback path works, but it returned
only 1 record on this workstation.

### Step 2 (complete) — real Deep-mode runs

| Run | Result |
|---|---|
| `-Mode Fast` | 55.4s · 71 findings · 87 datasets · 9 limitations · **0 errors** |
| `-Mode Deep -ProjectType Decommission -GenerateEvidenceManifest` | 181.9s · 269 findings · 89 datasets · 11 limitations · **0 errors** · manifest hashed 227 files |
| `-Mode Deep -ProjectType CMMCReadiness` | 184.1s · 269 findings · 88 datasets · 11 limitations · **0 errors** |

`errors.txt` was empty on all three. Everything in `limitations.txt` is a legitimate
host-capability limitation (not elevated, non-Server SKU, no Hyper-V module, no
`Get-NetFirewallRule`), **except** the two that are working-as-designed cap notices, which are
exactly what items 4 and the per-row cap are supposed to emit.

### ✅ F31 — FIXED 2026-08-21 — redaction's `-P` pattern over-matched and destroyed evidence

Found by actually looking at what got redacted on a real run, rather than only asking whether
anything leaked. `config/redaction-patterns.json` → `CommandLineSecretFlag` carried a bare
`(?-i:-P)` alternative, intended for `sqlcmd -U sa -P <password>`. It matched **any**
space-delimited `-P` and consumed the following token.

**Every single redaction in the Fast run was this false positive, and not one was a real secret** —
the output was full of `pwd -P [REDACTED]` where the redacted token was an ordinary directory path.
Over-redaction is not a safe failure: it silently deletes the dependency evidence a quote is built
from, which is precisely the harm F1's design notes warned about.

Scoped it with a lookbehind requiring a SQL command-line tool earlier on the line
(`sqlcmd|osql|bcp|isql`). **.NET supports variable-length lookbehind**, which is what makes this
expressible; Python and most other engines do not, so do not "port" this pattern casually.

| Case | Before | After |
|---|---|---|
| `sqlcmd -S s -U sa -P Secret!` | redacted | redacted |
| `bcp … -U u -P Secret!` | redacted | redacted |
| `osql -U sa -P Secret!` | redacted | redacted |
| `pwd -P /c/Users/x` | **redacted (wrong)** | preserved |
| `tar -P -xf a.tar` | **redacted (wrong)** | preserved |
| `curl -P 21 ftp://h/f` | **redacted (wrong)** | preserved |
| `tool.exe -P ProfileName` | **redacted (wrong)** | preserved |

schemaVersion → 1.1.2. **8 new Pester tests** (3 must-redact, 5 must-survive); the corpus is now
**46 assertions**. The old pattern scores 7 pass / 4 fail against the same table, so the guard is
negative-tested by construction.

### ✅ F32 — FIXED 2026-08-21 — every `json/` export had the wrong shape, and 35% were unparseable

`Output.psm1` → `Write-ObjectListToJson` was one line:

```powershell
$json = if ($null -eq $InputObject) { '[]' } else { $InputObject | ConvertTo-Json -Depth $Depth }
```

Two defects, both measured on the real Deep run's 89 exports:

| Rows | What was written | Problem |
|---|---|---|
| 0 | **0-byte file** | An empty array is not `$null`, so it fell through to `ConvertTo-Json` — and `@() \| ConvertTo-Json` emits **nothing**. **31 of 89** exports. No JSON parser accepts an empty file. |
| 1 | `{ "A": 1 }` | Piping **unrolls** the 1-element array, so a bare object was serialised instead of an array. **21 of 89** were parseable but not arrays. |
| 2+ | `[ {…}, {…} ]` | correct |

So only **37 of 89** exports (42%) were a valid JSON array. A consumer iterating `json/*.json` hit
three different shapes depending on row count, and threw outright on a third of them. These files
are also hashed into the evidence manifest, so the malformed ones were being attested.

Fixed by passing `-InputObject` instead of piping (that is what preserves the array) and treating
empty as `[]`. `ConvertTo-Json -AsArray` would be the obvious fix but **does not exist in Windows
PowerShell 5.1**, the target runtime. `$null` is handled *before* the `@()` normalisation, because
`@($null)` is a one-element array and would otherwise serialise as `[null]` — a regression caught
by the new tests, not by inspection.

**4 new Pester tests** (`Output.Tests.ps1` → `Describe 'JSON writing'`) covering 0, 1, 2 rows and
`$null`. Row counts are parameterised deliberately: a 2-row fixture catches neither defect.

One further 5.1 divergence surfaced while writing those tests, worth knowing about:
**`@($x | ConvertFrom-Json).Count` is 1 on Windows PowerShell 5.1 regardless of row count**,
because 5.1 emits the deserialised array as a single pipeline object (PowerShell 6+ made it
enumerate). Assign first, then wrap: `$p = $x | ConvertFrom-Json; @($p).Count`.

### Step 3 — the 8-item table from WINDOWS-VALIDATION.md, against real output

| # | Item | Verdict |
|---|---|---|
| 1 | **Redaction of real secrets** | ✅ **No plaintext credential survived** in either run. 70 values redacted in the Deep run; a credential-shape scanner (negative-tested — it finds 7/7 planted secrets) reported **0 surviving** credential-shaped values. The 22 raw "hits" were all XML entities (`&quot;`), XML closing tags, and the literal string `Secret` used as the ConfigDependencyHints *indicator name* column. **But see F31** — the redaction that *was* happening was entirely false-positive. |
| 2 | SQL `BinaryPath` → `CriticalPaths` | ⛔ **BLOCKED (host)** — `SqlInstances` has 0 rows; no SQL on this box. `CriticalPaths` has 301 rows, all `Source=Service`, so the SQL branch is still unexercised on real data. |
| 3 | Recycle-bin exclusion | ⛔ **BLOCKED (host)** — 3 shares exist but all are admin shares (`UserShareCount=0`, `DeepScannedShares=0`), so `NtfsAclSummary` is empty and the new `RecycleBin*` fields never populate. Needs a server with real user shares. |
| 4 | **Config-scan bounding** | ✅ **CONFIRMED.** `limitations.txt` carries exactly the intended message: *"Config scan stopped early (file cap 3000, hint cap 5000, max depth 8); results may be incomplete."* and `ConfigDependencyHints` is exactly **5000** rows — the hint cap, reported rather than silent. The Deep run finished in 182s on a machine with a large `Program Files`, so the `-Depth 8` bound works. |
| 5 | Fingerprint matching post-collection | 🟡 **MECHANISM CONFIRMED, matcher unexercised.** 4 fingerprints matched (Datto, SentinelOne, Datto RMM, Auvik) via `Services` + `InstalledApplications`. Critically, **`ListeningPorts` is populated (7 rows) at fingerprinting time**, which is exactly what F19 set out to fix — the input is now available. But none of the 7 ports belong to a DB engine in the config, and `IisSites` does not exist (no IIS), so no `ListeningPorts`/`IisSites` matcher actually fired. Needs a box running SQL or IIS. |
| 6 | **Deep-mode event-log depth** | ✅ **CONFIRMED, measured not declared.** Fast: 10 samples, max 5/log, 3-day span. Deep: **177 samples, max 100/log, span 2026-07-22 → 2026-08-21 = exactly 30 days.** F3 is live on real data. Two doc notes below. |
| 7 | `raw/` contents | 🟡 **PARTIAL.** `raw/RolesFeatures.raw.json` is written on **every** run, confirming F14. `raw/userrights.inf` is **absent** — `secedit /export` needs elevation, and the run correctly logged *"User rights export not available"* rather than failing. The "contains only `Se*` privileges, no secrets" half is unverified. |
| 8 | **ProjectType emphasis** | ✅ **CONFIRMED.** Two Deep runs on the same box: **identical 269 findings, identical 268 WBS rows, identical severity distribution {Medium 218, Low 50}, and an identical (Finding,Severity) multiset.** Only the priority marking differs — Decommission 0, CMMCReadiness 1 (`BitLocker not detected on any volume`), matching the `[PRIORITY]` marker counts in `scoping-risks.txt` (0 vs 1). Emphasis is presentation-only, exactly as F2/F18 requires. |

**Doc corrections needed from item 6** (not yet applied):
1. `WINDOWS-VALIDATION.md` item 6 says to verify the depth via `collection-metadata.json`. That file
   records **no parameter block at all** — only `RunId`, `ComputerName`, `Mode`, `ProjectType`,
   `ComplianceLens`, timings, `IsAdmin`, module statuses, datasets and counters. The check as
   written cannot work. Either fix the doc or, better, **record the resolved effective parameters
   in `collection-metadata.json`** — they are what makes a run reproducible and are exactly the
   kind of thing an evidence manifest should attest.
2. Item 6 also says Fast is "14/50". The 14 days is right, but `EventLogs.psm1` deliberately caps
   Fast at `[math]::Min(5, $maxSamples)` — so Fast is **5** samples per log, not 50. Measured: 5.

**Remaining after this session:** items 2, 3, 5 and 7 need an **elevated session on a real Windows
Server** with SQL and/or IIS and real user shares. Nothing else in the run-book is blocked.

### Output-data review of the real runs (2026-08-21) — F33 plus four judgement calls

After the run-book items, the actual output data was reviewed against what the host really
contains, by comparing every dataset's row count with what the underlying cmdlet returns. That
comparison found the single worst defect of this whole audit.

### 🔴 ✅ F33 — FIXED 2026-08-21 — `Get-CommandAvailable` gave false negatives, silently gutting collection

**The most consequential defect found so far.** `Core.psm1`'s `Get-CommandAvailable` gates optional
collection at **57 call sites across 17 modules**, probing 42 distinct cmdlets. It used:

```powershell
$found = $ExecutionContext.InvokeCommand.GetCommands($Name, [CommandTypes]::All, $false)
```

chosen deliberately (the comment said so) because it returns an empty set for a missing name
instead of polluting `$Error` with `CommandNotFound`. Right goal, wrong mechanism:
**`GetCommands()` does not trigger module auto-loading.** Any cmdlet in a module that had not yet
been imported read as *absent* — so the module skipped the dataset and, worse, often logged a
"cmdlet not available" limitation that was simply false.

Measured in a fresh session: **7 of 14 probed cmdlets were false negatives**, and inconsistently so
*within the same module* — `Get-Disk` found but `Get-Partition` not; `Get-Printer` found but
`Get-PrinterDriver` not; `Get-SmbShare` found but `Get-SmbShareAccess` not. The result depends on
module-analysis-cache state and on which module happened to be auto-loaded first, which is why this
never looked like a systematic failure.

**Cost, measured on two otherwise-identical Deep runs of the same host:**

| Dataset | Before | After | |
|---|---|---|---|
| `ListeningPorts` | **1** | **233** | dependency evidence, and the input F19 fixed the ordering for |
| `FirewallRules` | **0** | **300** | plus a *false* "Get-NetFirewallRule not available" limitation |
| `EstablishedConnections` | **0** | **171** | |
| `LocalGroups` | **0** | **22** | while `LocalGroupMembers` had 3 — internally inconsistent |
| `PrintPorts` | 0 | 13 | |
| `PrinterDrivers` | 0 | 9 | |
| `Partitions` | 0 | 4 | |
| `Routes` | 42 | 53 | |
| `DnsClient` | 31 | 35 | |
| `Disks` / `Volumes` / `NetworkAdapters` / `IPConfiguration` | 1/1/3/2 | 2/2/4/3 | |
| **Findings** | **269** | **280** | 11 real findings were invisible |
| **Follow-up questions** | 181 | 194 | |

**20 datasets gained rows; both false limitations disappeared**, replaced by two honest ones
(*"Enabled/allow firewall rules truncated to 300 of 302"* and a firewall-enrichment time budget).

Note what this means for F19: the fingerprint matchers keyed on `ListeningPorts` could not fire in
the earlier validation because `ListeningPorts` had **1 row instead of 233** — the ordering fix was
correct, but this defect starved it of input.

**Fix:** `Get-Command -Name $Name -ErrorAction Ignore`. `Get-Command` *does* auto-load, and
`-ErrorAction Ignore` (not `SilentlyContinue`) suppresses `CommandNotFound` **without recording
it**, preserving the original design goal. Measured: probing 7 absent commands leaves `$Error.Count`
at **0** with `Ignore` and at **6** with `SilentlyContinue`. Verified identical on 5.1 and 7.

Callers still guard the invocation, which matters: `Get-VM` exists whenever the Hyper-V module is
installed even if Hyper-V is not enabled, and `HyperV.psm1` wraps every call in try/catch, so
proceeding past the probe degrades gracefully.

**Bonus fix:** `ScheduledTasks` went 294 → 211 rows, which is a *correction*. Distinct tasks are
**211 in both runs** — the old `schtasks.exe` fallback emitted **50 duplicated task keys** (83
surplus rows) and crammed the folder path into `TaskName` leaving `TaskPath` empty. Both code paths
emit the identical 14-field set, and all 5 `ScheduledTasks` rules match on boolean flags with
`TaskName` used only as `evidenceField`, so no rule behaviour changed.

**Guard:** 4 new Pester tests in `Core.Tests.ps1`. The auto-load property can only be tested in a
session where the module is not already loaded, so they spawn a **child host process**. Order is
load-bearing — ask `Get-CommandAvailable` about every name *first*, then `Get-Command`; interleaving
pre-loads each module and the test passes even against the broken implementation. **That exact
mistake was made and caught**: the first version of the test passed 18/18 with the bug reinstated.
The corrected version fails with a clear assertion message. Also asserts `$Error` stays clean, that
a genuinely absent command returns false, and that external executables resolve.

### Four judgement calls for the owner — evidence gathered, not acted on

**1. The `community` keyword redacts URLs (84% of config-hint redactions).**
`KeyedSecretAnyDelimiter` includes `community` for SNMP community strings. It matches **any** key
containing that substring. On the real run, of 62 redactions in `ConfigDependencyHints`:

| Redacted key | Count | Real secret? |
|---|---|---|
| `core.utilnav.help.community.ccd.link` | 26 | no — an Adobe help URL |
| `core.utilnav.help.community.other.link` | 26 | no — an Adobe help URL |
| `password` / `passwd` / `bind_password` | 9 | **yes** |
| other | 1 | — |

So **52 of 62 (84%) are false positives**, and they specifically blank the endpoint out of
`ConfigDependencyHints` — a dataset whose entire purpose is recording hardcoded endpoints for
migration planning. Narrowing to `snmp[_ -]?community` / `community[_ -]?string` would drop all 52
while keeping the 9 true positives.

**Deliberately not changed.** `redaction-patterns.json`'s own description states the policy:
*"Erring toward over-redaction is correct here - a false positive costs a little evidence detail, a
false negative writes a live credential into a client deliverable."* Narrowing a security pattern
is the owner's call, and F1's notes say not to loosen these casually. This is distinct from F31,
where the `-P` pattern produced **100% false positives and zero true positives** — that one was
unambiguous.

**2. The evidence manifest attests 3 stale hashes.** Verified properly (matching on
`RelativePath`, not `FileName` — two files share a name across root and `logs/`):
**224 of 227 hashes match, 0 files missing.** The 3 mismatches are all live/append-only files
written *after* the manifest is generated: `logs/summary.txt`, `status/progress.json`,
`status/status.json`. A recipient verifying the manifest sees 3 failures and cannot distinguish
them from tampering. Fix by excluding live status/log files from the manifest, or by hashing them
last.

**3. One rule produces 72% of the deliverable.** `wbs-inputs.csv` has 279 rows across only **19
distinct finding titles**, and *"Config dependency hint detected"* accounts for **200 of them
(71.7%)** — the RULE-CFG-001 per-row cap. `scoping-risks.txt` therefore opens with 200 near-identical
Medium rows. Severity spread is Medium 230 / Low 49 / Info 1 — no Critical, no High. For a document
a human reads to scope work, the signal-to-noise is poor. Consider collapsing per-row config hints
into one finding with a count plus a detail table.

**4. `DependencyGraph` is 97% config-file noise.** 5156 edges: `ConfigFile` **5000 (97.0%)**,
`Service` 111, `Process` 39, `Server` 6. The genuinely actionable edges are 3% of the graph. Same
root cause and same suggested remedy as (3).

### What the review confirmed is healthy

- **All 25 declared `requiredOutputFiles` present and non-empty.**
- `workbook.xml` well-formed, **88 worksheets**, 11.4 MB. `internal-report.html` 406 KB, properly
  closed, **280 finding cards**, priority section present. `csv/` and `json/` both 89, matching.
- **All 89 JSON exports are valid arrays** (F32 holding on real data).
- `errors.txt` empty on every run — **0 errors across 4 real runs**.
- Every remaining empty dataset is legitimately empty: no SQL, no IIS, no DNS/DHCP/Cluster/RDS/NPS
  role, not a DC, not a print server, no DFS, and `secedit`/`vssadmin`/BitLocker needing elevation.

### FIRST REAL SERVER RUN (2026-08-21) - a Windows Server 2022 domain controller

One **Fast** run, **elevated**, on **Windows Server 2022 Standard** (build 20348) under
**Windows PowerShell 5.1.20348** - the documented target runtime, natively, for the first time.
314.7s, **110 findings, 0 errors, 1 limitation, 124 questions**. Reviewed via
`tools\Verify-DiscoveryRun.ps1`, so no client data left the environment.

#### Server-only paths: 3 of 5 now CONFIRMED

| Item | Verdict | Evidence |
|---|---|---|
| **RolesFeatures via `Get-WindowsFeature`** | ✅ **CONFIRMED** | **59 rows**, no fallback limitation, `raw\RolesFeatures.raw.json` **86,859 bytes**. This is the code path that had **never executed anywhere** - `Get-WindowsFeature` is Server-only, so every prior run used the optional-features/DISM fallback. It works, and it produced the canonical role names the risk rules key on: the run correctly identified the box as a DC holding FSMO roles. |
| **7 - `raw\userrights.inf`** | ✅ **CONFIRMED** | Written (needs elevation): **39 lines, 33 `Se*` privilege assignments, 0 secret-shaped tokens**. The 3 non-`Se*` lines are benign INF structure (`Unicode=yes`, `Revision=1`, `signature=`). `UserRightsAssignments` dataset has 33 rows. |
| **5 - fingerprint matchers on late datasets** | ✅ **CONFIRMED** | **An `IisSites` matcher actually fired.** 6 fingerprints, evidence sources = `IisSites`, `InstalledApplications`, `RolesFeatures`, `Services`. F19's whole point was that `IisSites`/`ListeningPorts` matchers could never fire; one now demonstrably does. |
| 2 - SQL `BinaryPath` → `CriticalPaths` | ⛔ BLOCKED | No SQL on this DC (`SqlInstances` = 0). Still needs a SQL host. |
| 3 - recycle-bin exclusion | ⛔ BLOCKED, **but now trivially unblockable** | `ShareCount=7`, **`UserShareCount=4`** - real user shares exist. `DeepScanPerformed=False` only because this was a **Fast** run. A single `-Mode Deep` run on this same box closes it. |
| 8 - ProjectType emphasis | ⛔ needs a second run | Only one run supplied; the comparison needs two differing solely by `-ProjectType`. |

#### The validation fixes, confirmed on server-shaped data under 5.1

- **F32** ✅ **90 of 90** `json/` exports are valid JSON arrays. 25/25 required artifacts present,
  `csv/`=`json/`=90, `workbook.xml` well-formed with 90 worksheets, HTML closed with 110 cards.
- **F33** ✅ every optional-cmdlet dataset populated: `FirewallRules` 231, `ListeningPorts` 5145,
  `LocalGroups` 8, `Partitions` 4, `PrinterDrivers` 6, `EstablishedConnections` 69,
  `SharePermissions` 9, `ShadowCopies` 26, `VssWriters` 19. No false "cmdlet not available"
  limitation. The **only** limitation in the entire run was a firewall-enrichment time budget.
- **Redaction** ✅ 0 `[REDACTED]` markers and **0 surviving credential-shaped values** across 230
  files. Zero redactions is expected here: a Fast run skips the config dependency scan, which is
  what produced them on the workstation Deep run. The `community` false positive did not fire.

#### 🔴 F29 was not academic - it would have hidden that this box is a domain controller

The single most valuable thing this run proved. **11 findings came from 8 single-row datasets**, and
before the F29 fix `datasetNotEmpty` returned `$false` for a single-row dataset **on exactly this
runtime (5.1)**. Those findings would have been silently absent - no error, just gone:

| Severity | Finding | Source dataset (1 row) |
|---|---|---|
| **High** | **Server is a Domain Controller** | `DomainContext` |
| **High** | **Server holds one or more FSMO roles** | `DomainContext` |
| Medium | RDP enabled without Network Level Authentication | `SecurityPosture` |
| Medium | Remote Desktop Services role detected | `RdsDiscovery` |
| Medium | DFS namespace/replication detected | `DfsDiscovery` |
| Medium | Backup software detected but recent success unknown | `BackupDiscovery` |
| Medium | IIS site(s) present | `IisSites` |
| Low | Static IP configuration detected | `IPConfiguration` |
| Low | WinRM is enabled | `SecurityPosture` |
| Low | Deep file share scan not performed | `FileShareSummary` |

A decommission scoping run against a domain controller would have failed to report **that it is a
domain controller**. That is the cost of the silent-failure class this audit exists to eliminate.

#### 🟡 New finding - `ListeningPorts` is 98.5% ephemeral sockets on a DC

`ListeningPorts` returned **5145 rows with zero duplicates**, but the composition is almost all
noise:

| | count | share |
|---|---|---|
| TCP | 58 | 1.1% |
| UDP | 5087 | 98.9% |
| **ephemeral ports (>= 49152)** | **5068** | **98.5%** |
| well-known (< 1024) | 37 | 0.7% |
| registered (1024-49151) | 40 | 0.8% |

**5008 of them are owned by the `dns` process** - a DNS server's ephemeral UDP socket pool.
Ephemeral sockets are not listening services and are never scoping evidence, but they bury the ~105
actionable listeners and inflate the `ListeningPorts` worksheet to 5145 rows. DCs running DNS are a
common scoping target, so this will recur on most of them.

**Recommended, not applied** (it changes collected data, same class as the `community` and
config-hint items): either exclude ports >= 49152 from `ListeningPorts`, or keep them and add an
`IsEphemeral` flag so the workbook and report can filter while the raw export stays complete. The
verifier now reports this split under section 3 so it is never a surprise.

#### Verifier bugs found by using it - one of them serious

`tools\Verify-DiscoveryRun.ps1` was written to be safe to share. Running it on real server output
found five defects in it, fixed:

1. 🔴 **It wrote raw privilege data into the "safe to share" report.** At **script scope** a bare
   `$lines` *is* `$script:Lines`, the report buffer - so the `userrights.inf` check's
   `$lines = @($txt -split ...)` silently replaced the entire report with raw `Se*` privilege
   assignments and SIDs. Renamed the buffer to `$script:ReportLines` (deliberately distinctive),
   renamed the local, and added a **pre-write guard** that refuses to write a report which does not
   look like a report or which contains privilege-assignment data.
2. `[]` parses to `$null` and `@($null)` is a **one-element** array, so all empty datasets counted
   as populated - the same 5.1/7 unrolling trap from F29, in the script written to detect it.
3. `OperatingSystem` has no `ProductType` field; server detection now derives from `Caption`/`Edition`.
4. The survivor scanner flagged JSON pretty-print punctuation as a surviving secret. A false FAIL
   here costs someone an afternoon, so the noise filter now rejects multi-line, structural and
   too-short values.
5. An empty `errors.txt` is 5 bytes - a UTF-8 BOM plus CRLF - so judging by length reported a
   perfectly clean server run as `INFO`. It now judges by content.

Also refined self-check #12, which flagged seven lines in the verifier of the form
`$n = if (...) { @($x).Count } else { 0 }`. An array expression immediately reduced to a scalar by a
member access is safe and idiomatic; the check now ignores those and still catches a bare
collection branch (re-verified against the `RiskEngine.psm1:64` hazard).

#### Still outstanding after this run

| What | Needs |
|---|---|
| Item 3 - recycle-bin exclusion | **One `-Mode Deep` run on this same DC.** 4 user shares are already there. |
| Item 8 - ProjectType emphasis | A second run differing only by `-ProjectType`. |
| Item 2 - SQL `BinaryPath` | A host with SQL Server installed. |

### Minor hardening noted, not fixed

- Redaction handles `&quot;`-escaped values but **not `&apos;`**. Low priority (rare in Windows
  config files), but it is an asymmetry in an otherwise symmetric pattern set.
- An empty dataset writes a CSV containing the single header `Value`, because `Get-DatasetColumns`
  has no columns to report. Harmless but odd; a zero-byte-with-header or an explicit
  `_No data._` marker would read better.

## ✅ Work completed so far

| Item | What changed | Verification |
|---|---|---|
| **F1** | Rewrote `valuePatterns` in `config/redaction-patterns.json` (schemaVersion → 1.1.0). Now handles `:` and `=` delimiters, single/double-quoted values, XML `key=/value=` attribute pairs, CLI-flag secrets (`--password`, `-pwd`, `sqlcmd -P`), `net use` positional passwords, bare JWTs, and `token`. `keepStructure` replacements now consume the whole value instead of decorating it. | 21 secret shapes redacted, 8 scoping-evidence values preserved — **29/29**. All 5 previously-leaking cases fixed. |
| **N1** | Added `tests/Pester/Redaction.Tests.ps1` — the secret-shape corpus, both directions (must-redact **and** must-survive), plus idempotency and no-config-fallback cases. | **38/38 passing** |
| **F13** | Fixed the impossible assertion in `tests/Pester/Core.Tests.ps1` and broadened it to check the other collections are initialized. Confirmed no other empty-collection-pipe antipatterns exist in the suite. | Full suite **106 passed / 1 failed** |
| **F3** | Replaced `Resolve-EffSwitch` with type-agnostic `Resolve-EffValue` in `Discover-WindowsServer.ps1` and added the missing **global defaults** layer. All 7 switches plus `maxDepth`, `largeFileThresholdGB`, `oldFileYears`, `eventLogDays`, `maxEventSamplesPerLog`, `configScanMaxFileSizeMB`, `outputRoot` now resolve through it, and the resolved values are what actually reach `$parameters` / the context. Also removed the hardcoded Deep-mode override of `IncludeConfigDependencyScan`, which had been silently defeating that config key. | Deep now resolves **eventLogDays=30 / samples=100** (was stuck at 14/50); CLI still wins; global layer reachable |
| **F4** | `default.discovery.json`: `defaults` is now a real, consumed layer (14 keys); dropped `jsonDepth` (duplicated `output-settings.json`), `includeProgramFiles`/`includeProgramData` (unimplemented) and `frameworkModules` (unusable — Core must load *before* config can be read). `fast`/`deep`: dropped the entire `collectionProfile` block (all 8 keys were duplicates of existing switches or unimplemented). | 0 unread keys remain in any discovery config |
| **F5** | `-IncludeRecycleBin` now does something real: the deep file-share crawl excludes `$Recycle.Bin` from `TotalSizeGB` and the file-age counts by default (deleted data isn't migration payload and was silently inflating the volume a quote is built from), and reports it separately via new `RecycleBinIncluded` / `RecycleBinFilesFound` / `RecycleBinSizeGB` fields. Documented in `FIELD-USAGE.md` (which was missing `NtfsAclSummary` entirely) and `README.md`. | Filter logic **5/5**, incl. case-insensitivity and no false positive on a `Recycle.Bin.Notes` folder |
| **F14** | Corrected `OUTPUT-GUIDE.md` to state what `raw/` really contains: `RolesFeatures.raw.json` and `userrights.inf` are always written (the `secedit /export` *is* the read mechanism), event logs only with `-FullEventLogExport`. Chose doc-correction over adding a switch, since the export is required to read the data. | — |
| — | Documented the 4-layer parameter precedence in `README.md` and expanded its parameter table with the previously-undocumented tuning switches. | — |
| **F2 + F18** | `-ProjectType` is no longer inert. Added `Test-RuleEmphasizedForProjectType` to the RiskEngine, which reads the `projectTypeEmphasis` key that already existed on 16 rules. Matching findings get `IsEmphasized` + `EmphasisReason`, and the outputs lead with them: a new **Priority For This Project Type** HTML section, emphasis-first sort within each severity band, `[PRIORITY]` markers in `scoping-risks.txt`, a `PriorityForProject` column in `wbs-inputs.csv`, and a prioritised count in `summary.md`. `evidenceField` (45 rules) is now wired to a new `Subject` field on findings, making per-row findings machine-readable. **Emphasis is presentation only — it never touches severity.** | Decommission emphasises 5, CMMCReadiness 5, HyperVRefresh 1, AzureMigration 3, GeneralDiscovery 0 — with **identical finding counts and identical severities** across all. 10 new Pester tests, suite **115 passed / 1 failed** |
| **F9** | `scoping-risks.txt` now sorts by severity *rank* (and emphasis) instead of alphabetically, reusing the same order the HTML report uses. | Smoke test asserts the file leads with the highest severity present |
| **F16** | Declared the two missing datasets in module metadata (`RiskEngine` → `CriticalPaths`, `SQL` → `SqlConfiguration`). Found by the new self-check. | Self-check green |
| **N2** *(pulled forward from Phase 5)* | Added **`tests/Invoke-ToolkitSelfCheck.ps1`** — static contract checks (161 at time of writing): parse, JSON, manifest↔export, metadata↔datasets, rule integrity, condition-type implementation, rule→dataset/field/`{Token}` contract, `FIELD-USAGE.md` accuracy, compliance-lens keys, and dead-config detection. Added **`tests/Invoke-OutputSmokeTest.ps1`** — seeds synthetic datasets and runs the real synthesis+output chain, asserting all 35 documented artifacts exist and are non-trivial, the workbook is well-formed XML, and the emphasis columns are present. | Both green; the self-check immediately caught F16 |
| **F19** | Application fingerprinting moved out of `Applications.ConvertTo-DiscoveryDatasets` into a new post-collection `Invoke-DiscoveryFingerprintSynthesis`, which the orchestrator calls between the collection and synthesis phases. **6 matchers across 6 fingerprints** (SQL Server, IIS, PostgreSQL, MySQL/MariaDB, Oracle, Firebird) referenced `ListeningPorts`/`IisSites` and could never fire; they now do. The follow-up questions those matches imply moved with it. Also wired the previously-dead `confidenceModel` block (`strongSources` + the three confidence labels were hardcoded). Chose post-collection over simply reordering `collectorModuleOrder`, because reordering leaves the trap open for the next cross-dataset matcher. | Seeding *only* late-collected datasets now matches 2 fingerprints — SQL Server via `ListeningPorts` (Possible/weak) and IIS via `IisSites` (Likely/strong), confirming both ordering and the config-driven confidence model. Smoke test asserts fingerprints are derived, not seeded. |
| **N2 (extended)** | Added 3 fingerprint checks to the self-check: every matcher `source` is a produced dataset, every matcher `field` exists in its producer, every matcher pattern compiles — plus `confidenceModel` source lists. Same silent-failure class as a dead risk rule. | 161 checks green |
| **F7 + N3** *(wiring + generic content)* | A rule's `suggestedScopeLanguage` now reaches the scope deliverables: the RiskEngine contributes it to `$Context.ScopeLanguage` **once per matched rule** (not once per emitted row, which would have added 200 duplicates for a capped per-row rule), stripping the leading markdown `>` so the writer's own `> **[Type]** ` prefix doesn't double up. Added a category→WBS-area map (`Get-WbsAreasForCategory`) so `wbs-inputs.csv` stops echoing the raw finding category. Extended `ScopeLanguage.psm1` from **6 categories to all 18**, table-driven, existing approved texts kept verbatim. | `wbs-inputs.csv` raw-category echoes: **36 → 0**. Scope language entries **23**, including both rule-authored texts, no doubled blockquote. Smoke test now asserts all of this. |
| **F11** | Added the three missing migration-complexity rubric rows — *Operating system currency*, *Performance headroom*, *Automation / scheduled work* — so `Operating System`, `Performance` and `Services / Tasks` findings can influence a rating instead of only doing so by accident via a matching impact keyword. | All 17 rubric rows produce ratings; new self-check asserts **all 18 rule categories** appear in the rubric |
| **N2 (extended again)** | Self-check now also verifies every rule category is represented in the complexity rubric. Exported `Build-ContextListDatasets` from the engine (runtime behaviour unchanged — `Invoke-Discovery` already called it internally) so the smoke test can exercise the five context-derived datasets. | 162 checks green |
| **F6** | `SqlInstances` now emits `BinaryPath` (from the `SQLBinRoot` value under the Setup key already being read for Version/Edition, with a service-image-path fallback), so `Build-CriticalPaths`' SQL branch is live instead of dead. | Smoke test asserts `CriticalPaths` contains a `SQL`-sourced row |
| **F8 + F23** | `ConvertTo-DisplayString` and `Get-DatasetColumns` both tested `IEnumerable`/`psobject` **before** dictionary, and a hashtable satisfies both — so hashtable values rendered as `System.Collections.DictionaryEntry` and hashtable rows produced `Keys/Values/Count` as column names. Dictionary is now tested first in both. | Hashtables render as JSON; column extraction returns real keys |
| **F10** | Config scan bounded: added `-Depth 8` (previously `Get-ChildItem -Recurse` walked entire install trees *before* the loop, so the file cap could not limit the expensive part), and the hint cap now stops the file loop instead of only the inner line loop. Limitation message reports which cap tripped. | — |
| **F12** | `EvidenceManifest` runs after the generic per-dataset export (it must hash finished files), so its dataset never reached `csv/`/`json/`. It now exports its own. | Smoke test asserts both files exist |
| **F15** | `NotDetected` is now used. Of the three `datasetMissingOrEmpty` rules only `RULE-BAK-001` genuinely means "not found" — changed `Possible` → `NotDetected`. The GPO and config-scan rules mean *data unavailable / scan not run*, for which `Unknown` is correct, so they were left alone. | Self-check confirms enum legality |
| **F20** | Removed the dead `Get-DiscoveryModulesRoot` (never called; `Invoke-Discovery` inlines the same expression). | grep clean |
| **F22** | `csv.delimiter` is honoured. Added `Get-CsvDelimiter` and passed it from `Export-DiscoveryDatasets`, the three special CSVs, and the evidence manifest — no caller had ever passed `-Delimiter`. | — |
| **F24** | Renamed `ServicesTasksIsDomain` → `Test-IisIdentityIsDomainAccount` in `IIS.psm1` (copy-paste artifact carrying another module's name in IIS's public surface). Manifest synced. | grep clean; self-check green |
| **Dead output config** *(new, fixed)* | `config/output-settings.json` had **15 unread keys**. Wired the two worth keeping — `html.accentColorHex` (was hardcoded in the CSS) and `requiredOutputFiles` (now the single source of truth the smoke test asserts against, so test and toolkit can't drift). Deleted the rest: output file/folder names stay fixed in code because `OUTPUT-GUIDE.md` documents them and consumers depend on them, and encoding is always UTF-8. | Dead-key check extended to `output-settings.json`; negative-tested by injecting a key and confirming it fails |
| **Phase 5 (partial)** | Added **`tests/Invoke-AllChecks.ps1`** — runs the self-check, the output smoke test and the Pester suite, returning one exit code. A layer that cannot run reports **NOT RUN**, never PASS, so a missing Pester install can't read as a green build. Rewrote `tests/README.md` (it was stale: referenced a nonexistent "PowerShell 3.4 Pester", listed 3 of the 4 test files, and predated both harnesses). Added **`WINDOWS-VALIDATION.md`** with the Windows run-book, the 8 things needing Windows eyes, and a paste-ready resume prompt. | All checks green on macOS; Pester correctly reported NOT RUN |
| **F25** *(new, fixed)* | `Describe 'Module metadata contract'` in `RiskEngine.Tests.ps1` imports every module directory and `Remove-Module`s each in its `finally` — including `Core`, `Output` and `RiskEngine` — so it unloads the framework mid-suite and any later Describe that relies on the file-level `BeforeAll` breaks. The new emphasis Describe now imports what it needs itself. Worth keeping in mind when adding Describes to that file. | Suite green |
| **F26** *(new, fixed on Windows)* | The F25 bug class survived in `Describe 'Discovery plan generation'`, which sits between the metadata Describe and the emphasis Describe and was missed. Fixed at the root with an `AfterAll` that restores the framework, plus a named `Import-DiscoveryFrameworkForTest` helper. See the validation log above. | Suite **114 passed / 0 failed / 2 skipped** on Windows |
| **F27** *(5.1 only)* | `Get-ChildItem -LiteralPath -Include` silently ignores `-Include` on Windows PowerShell 5.1, so the self-check tried to parse every `.md`/`.json`/`.yml` in the tree as PowerShell. Now filters on `$_.Extension` and skips `.git`. | Both runtimes run the same 164 checks |
| **F28** *(5.1 only)* | `Get-Content` without `-Encoding` reads UTF-8-no-BOM as ANSI on 5.1, mangling the em-dash the `FIELD-USAGE.md` check truncates on and producing 3 phantom field failures. Added explicit `-Encoding UTF8`. Confirmed all config JSON and all PowerShell source is pure ASCII, so no deliverable was ever affected. | Self-check green on 5.1 |
| **F29** *(5.1 only, serious)* | **`datasetNotEmpty` never fired for a single-row dataset on the documented target runtime.** An `if`-block writes to the pipeline, which unrolls a 1-element array to a scalar; 5.1 gives a bare object no `.Count`. Fixed at **26 sites** across 13 modules by wrapping in `@(...)`; 7 were provably live. Also fixed a blank `FileCount` for single-file shares and empty tables rendering instead of `_No data._`. | 1/2/3-row matrix correct on both runtimes; new self-check #12 negative-tested |
| **F30** *(5.1 only)* | The same unrolling class in 3 test assertions — `($x \| Where-Object {...}).Count` is `$null` at exactly one match on 5.1. Now `@(...).Count`. Same antipattern as F13, returned because nothing watched for it. | Suite 118/0/2 on both runtimes |
| **F31** | Redaction's `CommandLineSecretFlag` used a bare `(?-i:-P)`, so it matched any space-delimited `-P` and ate the next token — **every redaction in the first real run was this false positive and none were real secrets**. Scoped to `sqlcmd\|osql\|bcp\|isql` via .NET variable-length lookbehind. schemaVersion → 1.1.2. | Corpus now **46 assertions** (3 must-redact + 5 must-survive added); old pattern fails 4 of them |
| **F32** | `Write-ObjectListToJson` wrote a **0-byte file** for an empty dataset (31 of 89 exports on a real Deep run) and a bare **object instead of an array** for a single-row dataset (21 of 89) — only 42% of exports were valid JSON arrays, and the malformed ones were being hashed into the evidence manifest. Fixed by passing `-InputObject` instead of piping, and treating empty as `[]`. `-AsArray` was unavailable (not in 5.1). | 4 new Pester tests over 0/1/2 rows and `$null`; suite **130/0/2** on both runtimes |
| **F33** *(worst defect found)* | `Get-CommandAvailable` used `$ExecutionContext.InvokeCommand.GetCommands()`, which does **not** auto-load modules, so cmdlets in un-imported modules read as absent — gating 57 call sites across 17 modules. 7 of 14 probes were false negatives in a fresh session, inconsistently even within one module. Real cost: `ListeningPorts` **1 row instead of 233**, `FirewallRules` **0 instead of 300**, `LocalGroups` 0 instead of 22, plus two *false* "not available" limitations. Fixed with `Get-Command -ErrorAction Ignore`, which auto-loads and still leaves `$Error` clean. | **20 datasets gained rows**, findings 269 → 280; 4 new child-process Pester tests, negative-tested (the first version of the test was vacuous and was corrected) |

**About that 1 failure:** `Core.Tests.ps1` → `ConvertTo-SafeFileName` → 'replaces invalid
characters' failed **only when run off-Windows**. `[System.IO.Path]::GetInvalidFileNameChars()`
returns 2 chars on Unix (`\0`, `/`) versus 41 on Windows (including `:`), so `:` survived
sanitising on a Mac. **Confirmed passing on Windows 2026-08-21 — no fix was needed.** (Optional
hardening still available: have `ConvertTo-SafeFileName` sanitise the fixed Windows-invalid set
rather than the host's, since the toolkit always writes Windows filenames.)

> **Running the tests:** the real Pester could not be installed on the audit machine (no
> network to PowerShell Gallery), so the suite was originally executed through a minimal offline
> Describe/It/Should shim. **This has now been re-run under real Pester 6.1.0 on Windows** — see
> the Windows validation log above.

---

## Verdict

**The toolkit is in good shape and works end-to-end.** I simulated the full post-collection
pipeline against synthetic datasets shaped per `docs/FIELD-USAGE.md`: **35 findings fired from
the 74 rules, all 37 documented artifacts were produced, `workbook.xml` was well-formed with 34
worksheets, `internal-report.html` rendered 35 finding cards (61 KB, properly closed), 34 CSVs +
34 JSONs exported, the evidence manifest hashed 115 files, and 0 errors were logged.**

The collector⇄RiskEngine contract in `docs/FIELD-USAGE.md` is **fully intact** — zero dead
rules, zero field mismatches, zero doc/code field drift. All 30 module manifests match their
exports. The read-only and no-secret-harvesting contracts hold.

The audit found two real problem areas: **one security defect** (F1 — redaction let plaintext
credentials into the deliverables) and a cluster of **silently inert documented features**
(F2/F3/F4/F18/F19). **F1, F3 and F4 are now fixed** (Phases 1–2); the remaining inert features
are **F2** (`-ProjectType`), **F18** (`projectTypeEmphasis` / `evidenceField`) and **F19**
(fingerprint matcher ordering), all in Phase 3.

### Mechanically proven clean

| Check | Method | Result |
|---|---|---|
| Syntax, all 44 `.ps1`/`.psm1`/`.psd1` | `[Parser]::ParseFile` AST | ✅ 0 parse errors |
| JSON validity, all 9 config/data files | `ConvertFrom-Json` | ✅ all valid |
| Rule integrity (74 rules) | scripted | ✅ 0 dup ids, 0 invalid regex, 0 out-of-enum severity/confidence/impact, 0 missing required props |
| Rule→dataset contract | AST diff: all `Add-DataSet` vs all rule `dataset` refs | ✅ **0 dead rules** (40 refs, 106 datasets) |
| Rule→field + `{Token}` + `FIELD-USAGE.md` | AST property-set diff per producing module | ✅ **0 mismatches** |
| `.psd1` ↔ `Export-ModuleMember` ↔ `RootModule` | `Import-PowerShellDataFile` + AST | ✅ 0 mismatches, 30 modules |
| Compliance-lens keys ↔ rule categories | scripted | ✅ 0 orphans (CMMC 8, GeneralSecurity 3) |
| Read-only contract | grep, all mutating cmdlet families | ✅ no mutations outside toolkit output |
| No-secrets contract | grep: BitLocker keys, `KeyProtector`, PFX/cert export, `ntds.dit`, lsass, `ConvertFrom-SecureString`, RADIUS secrets | ✅ clean. `NPS_RADIUS.psm1` is exemplary |
| End-to-end deliverables | live simulation, `pwsh 7.6.1` | ✅ 37/37 artifacts |

### Do NOT re-raise these — investigated and disproved

- `MigrationComplexity` / `WbsInputs` / `DependencyGraph` **are** produced (`RiskEngine.psm1:249,267,285`).
- `ScreamTestPlan` **is** produced (`DecommissionReadiness.psm1:139`).
- `$Context.Paths['_DecommissionClassification']` **is** set (`DecommissionReadiness.psm1:117`) and harms nothing.
- `Build-ContextListDatasets` isn't in the engine's `Export-ModuleMember`, but `Invoke-Discovery`
  calls it from **inside the same module** — works fine, not a bug.

---

## Findings

### ✅ F1 — FIXED 2026-08-17 — Redaction failed on most real secret shapes; plaintext credentials reached the deliverables

> **Resolved.** `config/redaction-patterns.json` rewritten and covered by
> `tests/Pester/Redaction.Tests.ps1` (38/38). The description below is kept because it explains
> *why* the patterns are shaped the way they are — do not "simplify" them back.

`modules/Core/Core.psm1:360` (`Redact-SensitiveValue`) + `config/redaction-patterns.json`.

Every `valuePattern` terminates its value with `[^;\r\n"']+`, so **it cannot match a value that
starts with a quote**; only `ConnectionStringPassword` accepts `=`, and nothing handles
`:`-delimited or CLI-flag secrets. `token` is in `keyLabels` but has **no** `valuePattern`.

Executed against the real function with the project's own config loaded:

| Input | Output |
|---|---|
| `svc.exe --password="Sup3rS3cret!"` | **unchanged** |
| `svc.exe -pwd:'Sup3rS3cret!'` | **unchanged** |
| `sqlcmd -U sa -P Sup3rS3cret!` | **unchanged** |
| `net use Z: \\fs01\d /user:DOMAIN\svc Sup3rS3cret!` | **unchanged** |
| `sync.exe --token eyJhbGciOiJIUzI1NiJ9.payload.sig` | **unchanged** |
| `-ConnectionString "Server=s;Password=Sup3rS3cret!;"` | `Password=[REDACTED]` ✅ |

**5 of 7 realistic cases keep the secret verbatim.** These are exactly the values populating
`Services.PathName` (`ServicesTasks.psm1:77`), `ScheduledTasks.ActionsText`
(`ServicesTasks.psm1:110`), and `RunningProcesses` command lines — **all collected in Fast mode
by default** and exported to `csv/`, `json/`, `workbook.xml`, `internal-report.html`. This
contradicts `docs/README.md:24` and `docs/MODULE-DEVELOPMENT.md:17` ("never collects passwords").

Two related defects:
- `keepStructure` can *append* the secret after the marker:
  `$pwd = "Sup3rS3cret!"` → `$pwd=[REDACTED]"Sup3rS3cret!"` — reads as redacted, is not.
- `password: Sup3rS3cret!` and `token: eyJ…` both match `ConfigDependencyScan`'s `Secret`
  indicator (`ConfigDependencyScan.psm1:52`, which accepts `[:=]`) and so are **stored**
  unredacted in `ConfigDependencyHints.RedactedLine`.

**Fix:** rewrite `valuePatterns` to (a) accept `[:=]`, (b) consume optionally-quoted values —
`\s*[:=]\s*("[^"]*"|'[^']*'|[^;\s,)]+)`, (c) add CLI-flag patterns (`-P`, `-pwd`, `--password`,
`--token`, `--secret`, `/pass:`) and a bare `token` pattern, (d) anchor `keepStructure`
replacements so the whole matched value is consumed. Then add N1.

### ✅ F2 — FIXED 2026-08-20 — `-ProjectType` was completely inert
All 7 values are only printed/recorded. No code branches on `$Context.ProjectType`; every grep
hit is a `Write-Host`/markdown/JSON/HTML emission (`Discover-WindowsServer.psm1:261,446,467,552`;
`Output.psm1:392,513`; `Core.psm1:98,807`; `SystemInventory.psm1:277,576`;
`EvidenceManifest.psm1:81`). `-ProjectType Decommission` yields byte-identical analysis to the
default, while `docs/README.md:71` promises "same data, different emphasis."
**See F18 — the per-rule emphasis data already exists, so this is cheaper than it looks.**

### ✅ F18 — FIXED 2026-08-20 — `risk-rules.json` carried emphasis/evidence config that no code read
Verified 0 code references for all four:

| Key | Occurrences in `risk-rules.json` | Code refs |
|---|---|---|
| `projectTypeEmphasis` | 16 | **0** |
| `evidenceField` | 45 | **0** |
| `supportedConditionTypes` | 1 | **0** |
| `conditionNotes` | 1 | **0** |

`projectTypeEmphasis` is the smoking gun for F2: the ProjectType emphasis mechanism was
**designed into the rule data and never implemented in the engine.** Implementing F2 is largely
a matter of reading this existing key in `Invoke-DiscoveryRiskAnalysis` (weight/severity-shift
or filter per active `$Context.ProjectType`), not designing a new mechanism.

### ✅ F19 — FIXED 2026-08-20 — 6 application fingerprints had matchers that could never fire (module ordering)
`Applications` runs at **position 4** of 25 in `collectorModuleOrder`, but `Get-FingerprintMatches`
(`Applications.psm1:95-115`) reads datasets by name at that moment:

| Matcher source | Producer | Position | Fingerprints using it | Status |
|---|---|---|---|---|
| `Services` | ServicesTasks | 3 | 38 | ✅ available |
| `InstalledApplications` | Applications | 4 | 43 | ✅ available |
| `RunningProcesses` | Applications | 4 | 2 | ✅ available |
| `ListeningPorts` | **Network** | **5** | **5** | 🔴 **not yet collected** |
| `IisSites` | **IIS** | **12** | **1** | 🔴 **not yet collected** |
| `RolesFeatures` | RolesFeatures | 2 | — | ✅ available |

Also `config/application-fingerprints.json:8` declares
`confidenceModel.strongSources = Services, InstalledApplications, SqlInstances, IisSites` — but
`SqlInstances` is used by **no** matcher at all, and `IisSites` is unreachable. So the
`Confidence='Confirmed'` tier (needs ≥2 hit sources) is harder to reach than designed.
**Fix:** move fingerprint matching out of `Applications.ConvertTo-DiscoveryDatasets` into a
post-collection synthesis step (or reorder), so every matcher source is populated first.

### ✅ F3 — FIXED 2026-08-17 — Deep mode's larger event-log sampling never applied
`Resolve-EffSwitch` (`Discover-WindowsServer.ps1:82-90`) resolves **booleans only**. Ints pass
through raw at `:147-148`, so `deep.discovery.json`'s `eventLogDays: 30` /
`maxEventSamplesPerLog: 100` are ignored and `EventLogs.psm1:24-25` always sees 14/50. Deep mode
does not collect "more event-log samples" as `docs/README.md:64` claims.

### ✅ F4 — FIXED 2026-08-17 — ~30 config keys were dead; editing them did nothing
Verified 0 code references:
- `config/default.discovery.json` → the whole **`defaults`** block (14 keys: `outputRoot`,
  `maxDepth`, `largeFileThresholdGB`, `oldFileYears`, `eventLogDays`, `maxEventSamplesPerLog`,
  `configScanMaxFileSizeMB`, `jsonDepth`, `includeUserProfiles`, `includeRecycleBin`,
  `includeWindowsFolder`, `includeProgramFiles`, `includeProgramData`, `deepFileShareScan`).
  Real defaults are hardcoded in `param()`. Six of these *are* live tuning knobs via CLI
  parameters — so the config file advertises them with no working config path to set them.
- `fast.discovery.json` + `deep.discovery.json` → the whole **`collectionProfile`** block
  (8 keys each).
- `default.discovery.json` → `frameworkModules` (harmless; imports are hardcoded).
- `config/output-settings.json` → `csv.delimiter` is unreachable (see F22).

### ✅ F5 — FIXED 2026-08-17 — `-IncludeRecycleBin` was a no-op switch
Consumed nowhere but the plan printout (`Output.psm1:428`), yet `docs/README.md:86` lists it as
opt-in scan scope. (`-IncludeUserProfiles` / `-IncludeWindowsFolder` **are** honored at
`ConfigDependencyScan.psm1:65-66`.)

### ✅ F6 — FIXED 2026-08-20 — `Build-CriticalPaths` SQL branch was dead code
`RiskEngine.psm1:308` filters `SqlInstances` on `$_.BinaryPath`; `SQL.psm1` never emits
`BinaryPath` (0 hits). SQL binary paths never reach `CriticalPaths`.

### ✅ F7 — FIXED 2026-08-20 (wiring; per-rule content still optional) — Rule-authored scope language never reached the scope deliverables
`Add-ScopeLanguage` is called **only** by `ScopeLanguage.psm1` (11 canned/conditional entries).
A rule's `suggestedScopeLanguage` is stored on the finding but never added to
`$Context.ScopeLanguage`, so it never appears in `draft-scope-language.md`,
`scope-assumptions.md`, `scope-exclusions.md`, or the HTML "Draft Scope Language" section — only
in `wbs-inputs.csv`. Compounding it: only **2 of 74** rules define `suggestedScopeLanguage` and
only **2 of 74** define `likelyAffectedWBSAreas`, so `wbs-inputs.csv`'s `SuggestedWBSArea` falls
back to the raw category on 72 rows and `SuggestedScopeNote` is blank on 72 rows.

### ✅ F8 — FIXED 2026-08-20 — `ConvertTo-DisplayString`'s hashtable branch was unreachable
`Output.psm1:36` tests `IEnumerable` before `:43` tests `hashtable`; a hashtable *is*
`IEnumerable`, so it enumerates `DictionaryEntry` and cells render
`System.Collections.DictionaryEntry`. Move the hashtable/pscustomobject test above it.

### ✅ F9 — FIXED 2026-08-20 — `scoping-risks.txt` sorted alphabetically, not by severity
`Discover-WindowsServer.psm1:278` `Sort-Object Severity` → Critical, High, Info, Low, Medium.
`Write-HtmlReport` already does it right with a rank map (`Output.psm1:478-479`) — reuse that
`$sevOrder` hashtable.

### ✅ F10 — FIXED 2026-08-20 — `ConfigDependencyScan`'s file cap didn't bound the expensive part
`ConfigDependencyScan.psm1:59` materializes `Get-ChildItem -Recurse -File` across
`ProgramFiles`, `ProgramFiles(x86)`, `ProgramData`, `C:\inetpub` **plus every discovered
`InstallLocation`** before the loop starts; `$fileCap = 3000` (`:61`) only limits files *parsed*,
so full-tree enumeration cost is already paid. Also `if ($hints.Count -ge 5000)` (`:81`) breaks
only the inner line loop, so files keep being opened past the hint cap.

### ✅ F11 — FIXED 2026-08-20 — Migration-complexity rubric ignored 3 rule categories
`Build-MigrationComplexity` (`RiskEngine.psm1:223-238`) covers 15 categories; no rubric row
references `Operating System`, `Performance`, or `Services / Tasks`. Those findings influence a
rating only if they happen to carry a matching impact keyword. No row for OS currency,
performance headroom, or automation/task migration.

### ✅ F12 — FIXED 2026-08-20 — `EvidenceManifest` dataset registered after export
Runs at `Discover-WindowsServer.psm1:591-593`, after `Export-DiscoveryDatasets`, so its
`Add-DataSet` (`EvidenceManifest.psm1:93`) never reaches `csv/` or `json/`, and the root
`collection-metadata.json` under-reports `DatasetCount` by one. (`evidence/evidence-manifest.csv`
and `hashes.sha256` are correct — cosmetic.)

### ✅ F13 — FIXED 2026-08-17 — `Core.Tests.ps1` had an assertion that cannot pass
`tests/Pester/Core.Tests.ps1`, `Describe 'Context and datasets'`:
`$Ctx.Findings | Should -Not -BeNullOrEmpty` — an empty `List[object]` yields **nothing** to the
pipeline, so it asserts the opposite of its intent. Verified by reproducing the pipeline
semantics (Pester isn't installed on the audit machine). Use `$Ctx.Findings.Count | Should -Be 0`.

### ✅ F14 — FIXED 2026-08-17 (docs corrected) — `raw/` is populated on every run
`docs/OUTPUT-GUIDE.md:67` says `raw/` holds captures "only when explicitly requested." But
`RolesFeatures.psm1:269-273` writes `raw/RolesFeatures.raw.json` and
`SecurityPosture.psm1:113-118` writes `raw/userrights.inf` (read-only
`secedit /export /areas USER_RIGHTS`) whenever the `Raw` path exists — i.e. always. Content is
safe (no secrets) and both get zipped and hashed. Doc drift, not a leak.

### 🟡 F21 — Two rule condition types are unused, and one has a latent match bug
`datasetRowCountAtLeast` (`RiskEngine.psm1:69`) and `anyRowFieldNotEquals` (`:74-77`) are
implemented but used by **0 of 74** rules. `datasetRowCountAtLeast` also never checks `$exists`,
so with a missing `count` key (`[int]$null` → `0`) it would match an **absent** dataset and emit
a finding with no evidence rows. Currently unreachable; fix on principle before anyone adds a
rule that uses it.

### ✅ F15 — FIXED 2026-08-20 — `NotDetected` confidence was documented but never used
0 of 74 rules use `confidence: "NotDetected"` despite `docs/RISK-SCORING.md:41` and
`docs/FIELD-USAGE.md:75` defining it for `datasetMissingOrEmpty` findings; they use
`Unknown`/`Likely`.

### ✅ F16 — FIXED 2026-08-20 — Two `ProducesDatasets` metadata omissions
`RiskEngine` doesn't declare `CriticalPaths`; `SQL` doesn't declare `SqlConfiguration`.

### ✅ F20 — FIXED 2026-08-20 — `Get-DiscoveryModulesRoot` was dead code
Defined at `Discover-WindowsServer.psm1:18`, never called; `Invoke-Discovery` inlines the same
expression at `:540`.

### ✅ F22 — FIXED 2026-08-20 — `Write-ObjectListToCsv -Delimiter` was inert
No caller ever passes it, so `csv.delimiter` in `config/output-settings.json` is unreachable.

### ✅ F23 — FIXED 2026-08-20 — `Get-DatasetColumns`' hashtable branch was dead
`Output.psm1:57-58` handles hashtable rows, but `Get-RowValue` (`:68`) uses `ContainsKey` while
`Get-DatasetColumns` uses `.Keys` — inconsistent, and in practice all rows are `pscustomobject`.

### ✅ F24 — FIXED 2026-08-20 — `IIS.psm1` exported a misnamed copy-paste function
`ServicesTasksIsDomain` (`IIS.psm1:88`) is a duplicate of `ServicesTasks`'s `Test-DomainAccount`,
carrying the wrong module's name, and it is exported in both `IIS.psm1:106` and `IIS.psd1:9`.
Works, but duplicates logic and pollutes IIS's public surface.

### ✅ F17 — CLOSED 2026-08-21 — The test suite had never been verified to pass
Pester wasn't installed on the audit machine, and there was no parse-check/CI harness. **Closed on
Windows:** Pester 6.1.0 installed, suite runs **114 passed / 0 failed / 2 skipped**, and
`Invoke-AllChecks.ps1` gates all three layers. Redaction coverage now exists
(`Redaction.Tests.ps1`, 38 assertions), which was the specific gap called out here.

---

## Note on the remaining N3 content task

`wbs-inputs.csv`'s `SuggestedScopeNote` is still blank on most rows, because only 2 of 74 rules
define their own `suggestedScopeLanguage`. That column is deliberately left sparse: per-rule
scope text is **contract language**, and inventing 72 bespoke SOW clauses is the owner's call,
not something to auto-generate. What *is* covered now is the category level — every one of the
18 finding categories produces reviewed DRAFT assumption/exclusion language in
`draft-scope-language.md`, `scope-assumptions.md` and `scope-exclusions.md`.

To add per-rule language, put a `suggestedScopeLanguage` string on the rule in
`config/risk-rules.json` (house style: `"> {Brand} assumes ..."` - the literal `{Brand}` token gets
swapped for the configured brand name at generation time, see RiskEngine.psm1); it flows automatically into
the scope deliverables and that row's `SuggestedScopeNote`. Optionally add
`suggestedScopeLanguageType` to control which section it lands in (any `Add-ScopeLanguage` type,
e.g. `Exclusion`, `ChangeOrderTrigger`, `Cutover`); it defaults to `Assumption`.

## Suggested additions (ranked by value-to-effort)

- **N1 — Secret-redaction corpus test.** Pester test asserting ~25 secret shapes (quoted, colon,
  CLI-flag, YAML, JSON, XML, connection-string, JWT, PEM) never survive `Redact-SensitiveValue`.
  The regression guard F1 lacked; highest-value single addition. **S**
- **N2 — `Invoke-ToolkitSelfCheck` contract harness.** Package the checks scripted during this
  audit: AST parse-check every file, validate every JSON, and re-run the rule→dataset /
  rule→field / `{Token}` / `FIELD-USAGE.md` / manifest-vs-export / `ProducesDatasets` /
  dead-config-key diffs. They found 0 contract issues today — which is exactly why they're worth
  keeping, since a renamed field silently disables a rule. **M**
- **N3 — Populate the other 72 rules** with `suggestedScopeLanguage` and
  `likelyAffectedWBSAreas`, and route rule scope language through `Add-ScopeLanguage` (F7). **M**
- **N4 — Rules for common MSP scoping questions not yet covered:** OS currency vs. target, no
  installed-hotfix recency dataset, nothing on domain/forest functional level, no SQL
  edition-vs-core-count licensing signal, no static-IP-referenced-by-DNS-record check. **M**
- **N5 — Narrower scream-test rendering.** The 10-column `ConvertTo-MarkdownTable` call at
  `Discover-WindowsServer.psm1:367` renders unreadably wide; emit a per-function section. **S**
- **N6 — `-WhatIf`/dry-run mode** printing the collection plan and exiting, so an engineer can
  show a client exactly what will be touched before running. **S**

---

## Phased plan

| Phase | Item | Effort |
|---|---|---|
| ~~**1 — Security**~~ | ~~**F1** rewrite `valuePatterns`~~ | ✅ done |
| | ~~**N1** secret-corpus Pester test~~ | ✅ done |
| | ~~**F13** fix the broken assertion; get the suite green~~ | ✅ done |
| ~~**2 — Make the config honest**~~ | ~~**F3 + F4** generalise the resolver; wire the useful keys; delete the rest~~ | ✅ done |
| | ~~**F5** give `-IncludeRecycleBin` real meaning~~ · **F22** wire or drop `csv.delimiter` — *still open, moved to Phase 4* | ✅ / open |
| | ~~**F14** correct `OUTPUT-GUIDE.md`~~ | ✅ done |
| ~~**3 — Functional gaps**~~ | ~~**F2 + F18** implement ProjectType emphasis; wire `evidenceField`~~ | ✅ done |
| | ~~**F19** move fingerprint matching to post-collection synthesis~~ | ✅ done |
| | ~~**F7** route rule scope language + category→WBS map + 18-category scope coverage~~ | ✅ done |
| | ~~**F11** add rubric rows for OS currency, performance headroom, automation~~ | ✅ done |
| | **N3 (remaining)** author per-rule `suggestedScopeLanguage` for the other 72 rules — **owner content task**, see note below | M |
| ~~**4 — Correctness**~~ | ~~**F6, F8, F12, F15, F20, F22, F23, F24** cleanups~~ (F9, F16 done earlier) | ✅ done |
| | ~~**F10** bound the config scan~~ | ✅ done |
| | **F21** unused condition types (`datasetRowCountAtLeast`, `anyRowFieldNotEquals`) + the latent `$exists` bug — **still open**, deliberately: they are unreachable today (0 rules use them), so fixing is pre-emptive hardening rather than a live defect | S |
| **5 — Durability** | ~~**N2** self-check harness (163 checks) + `Invoke-AllChecks.ps1` single gate~~ | ✅ done |
| | ~~**F17** get the suite verified under real Pester~~ | ✅ done 2026-08-21 |
| | ~~**Git + CI**~~ — private repo `ghostinator/Discover-WindowsServer` created 2026-08-21. `Invoke-AllChecks.ps1` now runs as a real pre-commit hook **and** as a required GitHub Actions job on `windows-latest` under **both** PowerShell 7 and 5.1. | ✅ done |
| | ~~**F27–F30** the four defects the 5.1 CI job found on its first run~~ | ✅ done 2026-08-21 |
| **➡️ Windows validation** | ~~Step 1: `Invoke-AllChecks.ps1` under real Pester~~ ✅ · ~~Step 2: real Fast + Deep discovery~~ ✅ · ~~Step 3: the 8-item table~~ ✅ **4 confirmed, 1 partial-confirmed, 3 blocked on host** | **done on this host** |
| | **Remaining validation** — items 2, 3, 5, 7 need an **elevated** session on a real **Windows Server** with SQL and/or IIS and real user shares | open |
| | **Doc fix** — `WINDOWS-VALIDATION.md` item 6 cites a `collection-metadata.json` parameter block that does not exist; and Fast is 5 samples/log, not 50. Consider recording resolved effective parameters in that file. | open |
| ~~**Then**~~ | **N4** new rules (functional level, SQL core count - 3 of the 5 originally listed already existed) · **N5** narrower scream-test rendering (already done, this table was just stale) · **N6** dry-run mode · **F21** `anyRowFieldNotEquals`/`anyRowFieldMatches` now proven in real use (WID exclusion, N4 rules); `datasetRowCountAtLeast` still genuinely unused | ✅ done 2026-09-22 |

---

## Audit coverage & what's left to verify

**Read in full:** `Discover-WindowsServer.ps1`, `Discover-WindowsServer.psm1`, `Core.psm1`,
`Output.psm1`, `RiskEngine.psm1`, `DecommissionReadiness.psm1`, `ScopeLanguage.psm1`,
`ClientInterviewPack.psm1`, `EvidenceManifest.psm1`, `ConfigDependencyScan.psm1`,
`NPS_RADIUS.psm1`, `IIS.psm1`, all 8 config JSONs, all 5 docs, `Core.Tests.ps1`.

**Covered mechanically (AST/grep/contract diffs + safety sweep) but not read line-by-line:**
the remaining 18 collectors — notably `Network.psm1` (910 lines), `SystemInventory.psm1` (709),
`RolesFeatures.psm1` (416), `SecurityPosture.psm1` (212), `ServicesTasks.psm1` (191).

> ⚠️ A parallel deep-read audit of those 18 collectors was launched and **died on the account
> spend limit** — 8 of 8 line-by-line hunt agents failed, so no per-collector bug hunt completed.
> The 5 mapping agents did finish and contributed F18–F24 above. **A line-by-line read of those
> 18 collectors is the main remaining gap.**

**Reusable audit scripts** (rerun any time; fold into N2). Written to the audit machine's
scratchpad, not this repo — recreate or copy them in:
`diff-datasets.ps1`, `diff-fields.ps1`, `rules-audit.ps1`, `manifest-audit.ps1`,
`redaction-test3.ps1`, `e2e-harness.ps1`.
