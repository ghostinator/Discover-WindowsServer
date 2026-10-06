# HANDOFF - state of the work and what to do next

Written 2026-09-21 at a context-compaction point, updated 2026-09-22 after the run matrix, the non-elevated
run, the 2012 R2 dataset-gap fixes, the firewall truncation fix, the small-bug bundle, the report review, and
a first pass at task 8's features (items 1-7 below are now done, 8 partly). Read this first.

**Three docs now, not two** (split 2026-09-22, TODO.md had grown past 1300 lines mixing "still to do" with
"already fixed"): this file (HANDOFF.md) for lab state/procedures/gotchas/current priorities;
**[TODO.md](TODO.md)** for the short list of what's actually still open; **[HISTORY.md](HISTORY.md)** for the
detailed write-up of every defect found/fixed since the 2026-08-17 audit (newest sections first under
"Feature round" / "DNS records round" / "Report review round" / "Small-bug bundle" / "Firewall truncation
round" / "2012 R2 dataset-gap round" / "Non-elevated run round" / "Run matrix round" (all 2026-09-22) /
"Real-server test session (2026-09-21)"). This file has
**no credentials** on purpose (the repo may be committed); lab logins are in the user's private Claude
memory (`test-server-state.md`). If you do not have them, ask the user.

As of 2026-09-22 the working dir is a real git repo (`git status` works directly), pushed to
`github.com/ghostinator/Discover-WindowsServer` `main`. It had gone stale for a while (the dir is a zip
extraction, not a clone, so `.git` never carried over). This box has no `gh` CLI and no stored git
credentials - ask the user for a GitHub PAT each session to push.

## 1. Standing rules from the user (do not re-litigate)

- **DHCP:** never enable/activate DHCP for 192.168.0.0/24. The only scope is 10.99.99.0/24, Inactive.
- **No downloads without explicit approval** (state file, source, size). Approved so far: SQL Server Express,
  PowerShell 7.6.6 and 7.4.20 MSIs, VirtIO guest tools (from an ISO they attached), KB2999226.
- **No random restarts.** Anything that installs software must ask first and must not restart the machine.
  This is also a *product requirement* for `tools\Install-LegacyPrerequisites.ps1` (already built that way).
  For lab VMs, ask before rebooting unless it is inherent in a task the user asked for (domain join, rename).
- **Oldest supported OS is Windows Server 2012 R2.** The user does not want to go further back. PowerShell 7
  on 2012 R2 is acceptable.
- Full control of the lab otherwise: configure roles, install features, create data as needed for testing.
- The user is a working MSP engineer; this toolkit is run on *client production servers*, so **read-only,
  fail-soft, never hang, never leak a secret** are the priorities. Report honestly, including failures.
- **Never do per-node CSV / cluster-shared-volume work on this lab, in any form, without asking first and
  getting an explicit yes (2026-09-22).** A CSV on this exact cluster bugchecked the DC three times before it
  was removed (see gotchas below); the user will not accept that risk while scoping client work. This is why
  `Get-ClusterSharedVolumeState`/per-node CSV state stays permanently out of scope in TODO.md - do not re-raise
  it as a "next task" even though it is a reasonable feature idea in the abstract.

## 2. The lab (all in one lab AD domain - name kept out of the repo, see private lab notes - all Proxmox VMs on one physical host)

| Machine | IP | OS | Role in the lab |
|---|---|---|---|
| CLAUDEWIN2025DE (DNS name ClaudeWin2025Dev, 16 chars, NetBIOS truncated) | 192.168.0.172 static | Server 2025 | Forest-root **DC**, DNS, Enterprise CA (Corp-Lab-Root-CA), WSUS(WID), IIS, NPS, DHCP (inactive scope), DFS (broken root), print, RDS/ADFS roles installed, SQL Server Express (default + SQLEXPRESS) + WID, Hyper-V (3 test VMs), cluster node 1. **This is where the assistant runs**; repo is `C:\Users\Administrator\Desktop\Discover-WindowsServer-main`. PowerShell 7.6.6 installed. |
| LABVH02 | 192.168.0.167 | Server 2025 | Hyper-V + cluster node 2 (C: 62.8 GB after recovery-partition surgery), iSCSI initiator |
| LABFS01 | 192.168.0.190 | Server 2025 | File server + iSCSI target (LUNs `E:\iSCSI`), SMB shares, `F:` 4 TB (a 14 TB **USB HDD** on the host: avoid write-heavy/full-disk operations) |
| LABSRV16 | 192.168.0.188 | Server 2016 | plain member: IIS, file, print, a share, a service, a task |
| LABSRV19 | 192.168.0.189 | Server 2019 | same as 2016 |
| LABSRV12 | 192.168.0.124 | Server 2012 R2 (PS 4.0) | same roles; PowerShell **7.4.20** + KB2999226 installed via the legacy installer |
| Cluster LABCLUS01 | 192.168.0.191 | - | nodes DC + LABVH02, disk witness, **no CSV** (see gotchas), HA VM `LAB-HA01` (files on `\\LABFS01\VMStore`) |

Free addresses last checked (avoid `.180 .184 .187 .192` and the `.166-.170` neighbourhood, other devices):
`.185 .186 .193-.199`. The LAN router's DHCP serves that /24, so ask the user to reserve/exclude new addresses.

Other lab facts: Hyper-V VMs `LAB-APP01` (running, 2 checkpoints, a secret in its Notes on purpose),
`LAB-DIFF01` (saved state, differencing disk), `LAB-OLD01` (Gen1, config v8.0, ISO). Seeded secrets used to
test redaction: `Sup3rS3cret!`, `RadiusSecret123`, `hunter2public` and the lab passwords: **none may ever
appear in any output** (scan every run folder for them).

## 3. How to do the routine things

- **Reach a machine:** WinRM. Non-domain-joined targets need `TrustedHosts` on the DC (already set for the lab
  IPs) and `IP\Administrator`; joined machines use `CORP\Administrator` against the FQDN (Kerberos).
  Changing a target's network while connected drops the session: set static IP in one command, or via a
  scheduled task on the target. **Do not** switch DHCP to static remotely and keep working.
- **Run the toolkit on a remote machine:** `Copy-Item -ToSession` the repo to `C:\Discovery`, then run it as a
  **SYSTEM scheduled task** (`schtasks /Create ... /RU SYSTEM`) that writes to `C:\DiscoveryOut\...`.
  Background jobs and child processes die when the remoting session ends. Pull the result folder back with
  `Copy-Item -FromSession` into `C:\DiscoveryOut\...` on the DC. **The scheduled task's action must run
  a PowerShell that satisfies the engine's own `#Requires -Version 5.1`** - on a target below that (stock
  2012 R2 ships PowerShell 4.0, e.g. LABSRV12 before its legacy-installer run), point the task at
  `C:\Program Files\PowerShell\7\pwsh.exe` instead of `System32\WindowsPowerShell\v1.0\powershell.exe`.
  Get this wrong and the task still reports success (`#Requires` rejects the script before its body, and
  before any `*>`-redirected log, ever runs) - confirmed live against LABSRV12 via
  `Invoke-FleetDiscovery.ps1`, see TODO.md's 2026-09-26 entry for the full diagnosis. That tool now checks
  the target's PowerShell version and picks the right executable automatically; this manual procedure
  doesn't, so check it yourself first.
- **Verify a run:** `& .\tools\Verify-DiscoveryRun.ps1 -Path <run>[,<run2>] -ReportPath <file>` **in-process**
  (not via `powershell -File` with an array). Also scan the folder for the seeded secrets.
- **The gate (must stay green):** `.\tests\Invoke-AllChecks.ps1` under Windows PowerShell 5.1 **and**
  `& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File .\tests\Invoke-AllChecks.ps1`. Currently 207
  static checks + 388 Pester tests (2 skipped) + the output smoke test, on both.
- **Baseline for diffs:** `C:\Users\Administrator\Desktop\Discover-WindowsServer-original` (the untouched copy).
  `C:\DiscoveryOut\changed-files.txt` lists the 28 changed + 2 added files (line-ending-insensitive compare).
- **Downloads:** installers live in `C:\Installers` (PowerShell 7.6.6 / 7.4.20 MSIs, Microsoft-signed);
  SQL media in `C:\SQLSetup` (run installers from a scratch folder: they extract into the working directory).

## 4. Gotchas that cost real time (don't relearn them)

- **Tools:** in the Bash tool backslashes get mangled (`\\.\pipe`, `C:\x`) and heredocs with quotes break; use the
  PowerShell tool and write scripts with the file tool. The harness blocks `Remove-Item` on top-level `C:\`
  folders. **Never name a PowerShell function `H` or `R`** (aliases for Get-History/Invoke-History).
- **PowerShell 4 (2012 R2):** `*>` does not capture `Write-Host`; `#Requires -Version 5.1` gives a clean message.
- **Cluster rules learned the hard way:** run cluster cmdlets locally (remote `New-Cluster` fails on the AD double
  hop); create the cluster from the non-DC node, then `Add-ClusterNode` the DC; an **iSCSI Target Server cannot
  live on a cluster node**; Hyper-V cannot run VMs stored on an SMB share of the *same* server; creating an HA VM
  on an SMB share needs CredSSP from the DC to the node; live migration fails on nested virtualization (use
  `-MigrationType Quick`); **a domain controller as a cluster node bugchecked 3x (0x7E) after a CSV was added and
  the cluster quarantined it** (`Start-ClusterNode -ClearQuarantine`); the CSV was `Direct` on the non-DC node
  but `Unavailable` on the DC.
- An Internal vSwitch gives a DC a `vEthernet` adapter whose APIPA/extra address registers in DNS and breaks name
  resolution (`Start-VM` "could not be resolved"): static address + no DNS registration.
- IIS config-encryption key container is broken on the DC: set app-pool passwords by editing `applicationHost.config`.
- **PowerShell 7 on 2012 R2** hides every Windows module and its compat session needs WinPS 5.1. Fixed in Core
  (`Get-CommandAvailable` `-SkipEditionCheck` fallback; `Invoke-WindowsPowerShellJson`). Modules that cannot load
  there: ServerManager, WebAdministration, NetTCPIP, DnsClient.
- SQL services on the DC lose the boot race against AD: they use delayed auto-start.

## 5. What was built (details and evidence in `HISTORY.md`)

Bugs fixed: optional-hook probe across a module-name collision (Storage/ActiveDirectory), CriticalPaths merge, hidden
`$RECYCLE.BIN` (`-Force`), print queues as user shares, WID/SQL detection + deep query + backup/size, NPS parser,
GPO scope/FSMO match, `-OutputRoot` made absolute, central redaction net in `Add-DataSet`, `-ComputerName localhost`
for Hyper-V/DHCP/DNS (27 s -> 7 s), RDS and Licensing false positives, CD-ROM volume false "low free space",
TCP-only ephemeral filter, PowerShell-7-on-2012R2 module loading, role detection via Windows PowerShell.
Features/robustness: per-module deadline (`moduleTimeoutSeconds`), `tools\Install-LegacyPrerequisites.ps1`,
`#Requires -Version 5.1`, new datasets (CertificateAuthority, Cluster*, Iscsi*, richer HyperV*, SQL fields),
rules `RULE-SQL-007/008`, `RULE-HV-006/007`, `RULE-CL-002/003`, `RULE-ISCSI-001/002`, LogonScripts (NETLOGON + AD
scriptPath). Docs updated: README, MODULE-DEVELOPMENT (**collectors now run in a child runspace: read that section**),
OUTPUT-GUIDE, RISK-SCORING, FIELD-USAGE, SERVER-RUN.

## 6. Next tasks, in priority order

Each has an acceptance test. Do them in this order unless the user redirects.

1. ~~**Run matrix (never done end to end).**~~ ✅ **Done 2026-09-22.** Deep on LABSRV16/19/12, `-Mode Custom
   -IncludeModules ...`, `-ProjectType` across 6 of 7 values, `-ComplianceLens CMMC` and `GeneralSecurity`,
   `-SkipZip`/`-Quiet`/`-IncludeRecycleBin`, two clean same-box pairs differing only by `-ProjectType`. All
   accept criteria met (0 errors/warnings, verifier 0 FAIL, no seeded secret, identical findings across
   lenses) - but only after fixing a real bug it surfaced: the archive step was failing completely silently
   under a SYSTEM scheduled task. See HISTORY.md "Run matrix round (2026-09-22)" for the full account.
2. ~~**Non-elevated run.**~~ ✅ **Done 2026-09-22.** Ran as domain user `alice` (confirmed non-admin), non-elevated,
   headless on LABSRV19: 0 errors, 0 warnings, no hang, 12 clearly-labeled limitations, verifier all-PASS. Actual
   mechanism is graceful degradation per module (not a blanket skip) - see HISTORY.md "Non-elevated run round" for the
   nuance and for the one-off local-policy grant needed to make a non-admin scheduled task runnable at all (granted
   and reverted, same session).
3. ~~**2012 R2 gaps.**~~ ✅ **Done 2026-09-22.** `EstablishedConnections`/most of `ListeningPorts`: real bug, a
   double-array-wrap in `Network.psm1` was silently reducing the netstat fallback to at most one garbled row (not a
   missing-module issue at all - see HISTORY.md for the exact repro). `IisBindings`, `DnsClient`, `LocalGroups`: added
   the missing fallbacks (appcmd bindings parse, `Win32_NetworkAdapterConfiguration`, `Win32_Group`) the same way
   the rest of the codebase already does this. `AppliedGroupPolicy`: investigated - genuinely not a toolkit bug,
   this LABSRV12 box has no RSoP data even for a full Administrator right after `gpupdate /force` (confirmed by A/B
   against LABSRV19, which returns real GPOs for the identical command); fixed the toolkit to report that honestly
   instead of a silently-empty dataset. Fresh Deep run on LABSRV12 after all fixes: 0 errors, 0 warnings,
   `EstablishedConnections=6 ListeningPorts=33 LocalGroups=23` (all previously 0/1).
4. ~~**Firewall truncation.**~~ ✅ **Done 2026-09-22.** Root cause: `Get-NetFirewallPortFilter`/
   `-ApplicationFilter` piped one rule at a time each re-query the whole filter store per call
   (~190ms/rule -> 65s+ for 345 rules, exactly the "~62s" already on record). Both cmdlets cost the same
   queried once for everything, so fetch each once and join by `InstanceID` instead: 345 rules in 3.5s,
   every rule enriched, cap raised from 300 to 20000 as a sanity backstop only. Verified live end-to-end
   on the DC: `FirewallRules` = 345 rows, all enriched, `limitations.txt` empty.
5. ~~**Small-bug bundle.**~~ ✅ **Done 2026-09-22.** TimeSync: `SystemInventory.psm1` had its own leftover
   partial TimeSync collector predating the dedicated module - deleted (both wrote the same dataset name,
   `Add-DataSet` appends, hence "two rows"). The CMOS-clock rule never fired for *any* domain member: `TimeSync`
   ran before `ActiveDirectory` in `collectorModuleOrder`, so `DomainContext` was never available when it
   checked domain membership - swapped the order. HybridIdentity: a matched-but-not-running service now reports
   `Possible` not `Likely` (new `confidenceField` support in RiskEngine, matching the existing `evidenceField`
   pattern). ConfigDependencyScan: only the newest `C:\inetpub\history\CFGHISTORY_*` backup is scanned now (was
   all of them - same facts repeated). `publicKeyToken` (a public .NET assembly hash, never a secret) no longer
   gets redacted - fixed in both `redaction-patterns.json` and, since a real Deep run surfaced it, in
   `Verify-DiscoveryRun.ps1`'s own independent safety-net regex too (it briefly flagged the un-redacted values as
   a false-positive leak). Ephemeral UDP bloat: new `WorkbookRows` support on datasets (CSV/JSON keep every row;
   the workbook can see fewer) - `ListeningPorts` workbook worksheet went from 5183 to 160 rows on the DC, JSON
   still has all 5182. `NetworkAdapters` name field: checked across 4 real machines, always populated, not a bug.
6. ~~**Review the reports with your eyes.**~~ ✅ **Done 2026-09-22.** Not just cosmetics - found a real bug: the
   client report's per-item tables (`Shared folders`, `Shared printers`, `Third-party products installed`,
   `Business applications we recognised`, `Things worth your attention`) were silently collapsing every row into
   one garbled row (a PowerShell pipe-vs-assignment gotcha in `ReportBuilder.psm1` - see HISTORY.md for the exact
   mechanism). Also, on user feedback mid-review: `MSSQL$MICROSOFT##WID` (Windows Internal Database) was showing
   up in the High "SQL Server instance detected" finding as if it were a real customer instance - excluded via
   the `IsWindowsInternalDatabase` flag the SqlInstances dataset already carried. Client-safety check: no seeded
   secrets, no unexpected leaks - the private IPs that do appear are the server's own, surfaced as part of a
   validation question ("do other systems reference this server's static IP X?"), which is legitimate content.
7. ~~**Git housekeeping**~~ ✅ **Done 2026-09-22.** Working dir is now a real git repo (was a stale zip
   extraction with no `.git` at all - see the note near the top of this file), pushed to `main`. Line endings
   were renormalized to CRLF automatically via `.gitattributes` on `git add`, no manual pass needed.
8. **Features, partly done 2026-09-22.** Checked TODO.md's (now HISTORY.md's) "Then" phase (N4/N5/N6/F21)
   against the actual code first - N5 (scream-test rendering) turned out already done, and 3 of N4's 5 rule
   ideas already existed too. Added what was genuinely missing: **N6** `-WhatIf`/dry-run mode (prints the
   module plan, writes `discovery-plan.md`, exits before any collector runs - verified in 2.3s vs. ~6 min for a
   real Deep run); **N4** domain/forest functional level (via `RootDSE`, no RSAT needed) with `RULE-DC-003`
   flagging legacy levels; SQL edition-vs-core-count with `RULE-SQL-009` flagging Enterprise edition; and
   **DNS records that point at this server** (HANDOFF's own long-standing feature ask, and N4's 5th item -
   `DNS.psm1` previously only reported zone summaries, never record content). New
   `Get-DnsRecordsReferencingThisServer` walks every forward zone's A/CNAME records and matches against this
   server's own hostname/IPs, capped at 3000 records; new `RULE-DNS-002`. Unlike the other new rules, this one
   found **real positive matches** on the lab (14 records, including a seeded `intranet` CNAME and the
   cluster's own A record) - not just a clean true negative. See HISTORY.md "Feature round" / "DNS records
   round" for the full account, including a self-check failure the SQL fix hit and how it was fixed properly
   (AST-based field discovery, not `Add-Member`).

   **Decided 2026-09-22, will not be doing:**
   - **Per-node CSV state.** Hard no - see the standing rule in section 1. Do not re-raise.
   - **WMF 5.1 installer option for 2012 R2.** Originally justified by four dataset gaps
     (`IisBindings`/`EstablishedConnections`/`DnsClient`/`LocalGroups`) that all needed native PS5.1 cmdlets.
     All four are now closed via restart-free fallbacks (the 2012 R2 dataset-gap round, same day). The one
     still-empty 2012 R2 dataset (`IisApplications`/`IisVirtualDirectories`) is confirmed empty on LABSRV16/19
     too, which *do* have `WebAdministration` - so it's "nothing there in this lab," not a module gap. No
     remaining justification; see TODO.md's "Explicitly not doing" section for the full reasoning. Revisit only
     if a real client server surfaces a 2012 R2 gap a fallback genuinely can't close.

   **Next up: fixture-based collector tests** (TODO.md item 1). Worth being precise about how this differs from
   everything done today: today's verification was all *live-server integration testing* - the real toolkit
   against real lab VMs, checked with the standalone verifier + manual inspection. Thorough (it found several
   real bugs, including two genuine PowerShell gotchas no amount of code review would have caught without
   seeing real output), but each check was a one-off - nothing added today runs again automatically to catch a
   future regression, and live runs can only exercise whatever's actually configured in the lab right now (e.g.
   the DNS/ConfigDependencyScan/firewall record caps have never actually tripped here, because the lab isn't
   big enough). *Fixture-based* tests are Pester unit tests with mocked cmdlet output per collector - they
   test a collector's own parsing/filtering/cap logic in isolation, in milliseconds, become a permanent part of
   `tests\Pester\` (so `Invoke-AllChecks.ps1` runs them on every future gate check, forever), and can exercise
   edge cases the lab can't produce organically. They don't replace live testing - a fixture test only proves
   the code does what the fixture describes, not that the fixture accurately describes what a real server
   returns (this session repeatedly needed a live box to confirm exact field shapes, e.g. `RecordData.
   IPv4Address` for DNS A records) - the two are complementary, not either/or.

## 7. Lab housekeeping still owed to the user

- `C:\iSCSIVirtualDisks` on the DC holds two dead files (the harness blocks deleting top-level `C:\` folders; the user
  can delete it).
- Lab-only weakening left in place: WinRM TrustedHosts for the lab IPs and CredSSP (DC -> LABVH02). Offer to undo.
- The assistant saved the lab passwords in the user's private Claude memory; offer to strip them if asked.

## 8. Caveats on what is and is not proven

- The DC crash cause is *inferred* (CSV + DC node); removing the CSV stopped it (>45 min stable, 11-min Deep run
  survived), but no dump analysis was done.
- Live migration was not made to work on nested virtualization; the toolkit does not depend on it.
- Not exercised at all: Hyper-V replication, cluster shared volumes on a healthy 2-node cluster, pass-through disks,
  BitLocker with a TPM, real RDS deployment, AD FS configured, WSUS with downstream clients.
- Everything was validated on a lab of VMs; no client server has been touched.
