# Discover-WindowsServer — TODO

> **START HERE: [HANDOFF.md](HANDOFF.md)** has the lab inventory, standing rules, procedures and gotchas.
> **This file is just the open-items list** — nothing here has a write-up, just what's left and why. For the
> detailed history of every finding, bug, and fix (2026-08-17 through today), see **[HISTORY.md](HISTORY.md)**.
> Split off from a single 1300-line TODO.md on 2026-09-22 once "still to do" and "here's what we already
> fixed" had gotten mixed together.

**Gate (must stay green):** `.\tests\Invoke-AllChecks.ps1` under Windows PowerShell 5.1 **and**
`& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File .\tests\Invoke-AllChecks.ps1` — 218 static checks +
504 Pester tests (2 skipped) + the output smoke test + the demo engagement smoke test, on both, as of
2026-09-29 (full-module completeness audit + new server-technical compliance checks - see item 12).
(2026-09-25: the self-check's own PS5.1 array-unrolling-hazard rule
caught a real instance of the exact bug it exists to catch, in
`tools\Merge-FleetDiscoveryResults.ps1`'s `$serverSummaries = if (...) {...} else {...}` -
neither branch's own `@()` wrap protected the outer if/else assignment itself. Fixed by wrapping
the whole if/else expression in one `@()` instead of wrapping each branch separately.)

---

## Open items, in priority order

1. **GUI + delivery feature (2026-09-22) — visual/interactive verification confirmed by the user (2026-09-26/27).**
   [Discover-WindowsServer-GUI.ps1](Discover-WindowsServer-GUI.ps1) (optional WPF launcher: pick options, watch
   live progress via `evidence\status\progress.json`, optionally deliver the result) and
   [tools\Send-DiscoveryOutput.ps1](tools/Send-DiscoveryOutput.ps1) (SMTP / SMTP2GO / SendGrid / Postal / HTTPS
   upload, DPAPI-encrypted credential store). Before the user's own confirmation, everything had only been
   verified as thoroughly as a headless session allows (syntax parses; the XAML constructs headlessly with all
   named elements resolving; a direct non-dot-sourced run completes every setup step without error before
   blocking in `ShowDialog` as expected; `Build-DiscoveryArgumentList`, the actual argument-building logic, is a
   pure function with 11 Pester tests; all four delivery methods have 23 Pester tests with every network call
   mocked, request schemas checked against SendGrid/SMTP2GO/Postal's own docs/source). Three real bugs were
   already caught and fixed by those static/headless checks before this was ever run visually (`<ItemsControl>`
   has no `.Content` property, needed `<ContentControl>`; `$env:COMPUTERNAME_*` interpolation bug; a PS5.1
   array-unrolling hazard the toolkit's own self-check flagged) - the user has since run it on a real desktop,
   clicked through the tabs, and confirmed the layout and behavior are correct. This item is closed **for the
   GUI as it existed at that confirmation** - the Branding tab and the Fleet tab's "Compare vs another
   engagement..." button (2026-09-27) were added afterward and have only been verified the same headless way
   (XAML resolves, click-handler logic tested standalone against a scratch config) - not yet clicked through on
   a real desktop.

2. **Fleet Discovery (2026-09-25) — GUI's Fleet tab itself needs the user's own visual verification; the
   scripted plumbing underneath was verified live against this lab.** `tools\Invoke-FleetDiscovery.ps1`
   (AD enumeration via ADSI - no RSAT needed, a WinRM-port subnet scan, and per-target remote execution:
   stage via `Copy-Item -ToSession`, run as a SYSTEM scheduled task, poll, pull the result back via
   `Copy-Item -FromSession`, always clean up) and `tools\Merge-FleetDiscoveryResults.ps1` (merges N
   completed run folders into one combined risk register + `fleet-rollup.html`), wired into a new "Fleet"
   tab in the GUI. Domain credential is memory-only (never DPAPI-persisted like delivery credentials -
   see the header comment in `Invoke-FleetDiscovery.ps1` for why). **Superseded by the Fifth follow-up
   below:** the credential no longer reaches the remote-run step via `Start-Process -Credential`'s
   ambient identity - it's piped over the child process's stdin instead, and `New-PSSession` always
   gets an explicit `-Credential`. Left the rest of this entry as originally written for history; see
   the Fifth follow-up for why the design changed and what it replaced.
   **What was actually exercised against the lab domain (not just written):** `Get-AdServerCandidate`
   found all 7 real lab servers; the subnet scan (`192.168.0.0/24`) found all of them plus 2 extra hosts in
   under 4 seconds; `Merge-DiscoveryCandidate` correctly deduped 6 of 7 by IP (the DC itself is
   multi-homed, a lab-specific edge case, not a bug - see the function's own comment). Live testing against
   LABSRV19 caught and fixed **three** real bugs a code review alone would have missed:
   1. The scheduled task's action was built from `(Get-Process -Id $PID).Path` *inside a WinRM session*,
      which resolves to `wsmprovhost.exe`, not a real PowerShell - the task "ran" and exited having touched
      nothing, with no error at all. Fixed to a hardcoded `System32\WindowsPowerShell\v1.0\powershell.exe`.
   2. An early `return [pscustomobject]$result` from inside the `try` block snapshotted the result object
      before the `finally` block set `EndTime`, silently dropping it on the TimedOut/Failed paths -
      restructured so every path falls through to one `return` after `finally`.
   3. **The one that actually explains the 15-minute waits, once #1 was fixed:** the completion poll compared
      `(Get-ScheduledTask ...).State -eq 'Ready'` where `.State` was read *inside* an `Invoke-Command`
      scriptblock. That enum crosses PowerShell remoting as a raw `[int]` (confirmed live: `3`, not `Ready`
      or even a recognizable enum), so the comparison was **always false** - the poll loop never once
      detected a genuinely-finished task and silently fell through to the full timeout on every run,
      regardless of how fast the actual scan was. A real run that had already finished in under a minute on
      the target still reported `TimedOut` locally 15 minutes later. Fixed by casting to `[string]` *inside*
      the remote scriptblock, before it crosses the remoting boundary - confirmed live afterward
      (`-eq 'Ready'` now `True` where it was `False` before).

   Both the timeout path (fix #2) and the success path (fix #3) were confirmed live end to end, along with
   cleanup on both: a pre-fix-#3 run against LABSRV19 timed out as expected with `EndTime` correctly
   populated and the remote task + staging folder confirmed removed afterward; with all three fixes in
   place, a fresh run completed in 89 seconds (`Status: Succeeded`), pulled back 241 real files into a
   genuine `Discover-WindowsServer_LABSRV19_<timestamp>\` folder, and again left nothing behind on the
   target. `New-FleetRollupReport` was then run against that real (not fixture) folder -
   `fleet-rollup.json/.html/.csv` all generated correctly, 43 findings, one server. The one real-fixture
   gap left is a **multi-server** rollup (only ever run against 1 real folder + fixtures so far) - the
   per-run stamping/merge logic is unit-tested for the multi-server case, just not exercised against two
   real pulled-back folders at once. **The GUI's own Fleet tab has never been opened on screen** - same
   caveat as item 1 below: static checks (XAML is well-formed XML, all 56 named controls resolve, no
   variable-name collisions from dot-sourcing the two new tool scripts) all pass, but nobody has clicked
   "Query Active Directory" or watched the progress bar move yet.

   **Follow-up round, same day, from the user's first real click:** an unreachable target finishes in
   under a second and produces zero output - correct behavior, but the GUI launches the fleet process
   `-WindowStyle Hidden`, so the one thing that explains that (a console message) was invisible, and
   "Fleet run finished!" looked identical whether anything actually succeeded or not. Fixed: the
   completion handler now reads `fleet-run-results.json` and reports real per-target outcomes instead of
   trusting "the process exited"; and AD-only candidates (never probed before, unlike scan-sourced ones)
   now get a WinRM reachability check when the picker is built, so a dead server shows up greyed out
   with "WinRM not responding" before you waste a click on it, not after. Verified with a synthetic
   probe (one real reachable lab server + one fake hostname, correctly told apart).

   **Second follow-up, same day - opt-in WinRM bootstrap, per explicit user request.** A new
   `-EnableWinRmIfUnreachable` switch (GUI: an unchecked "Enable WinRM on unreachable targets" box) lets
   an unreachable target be brought up over WMI/DCOM (`Invoke-RemoteProcessViaDcom` ->
   `Enable-PSRemoting -Force` via `Win32_Process.Create`, since WinRM obviously can't turn itself on
   remotely) and reverted (`Disable-PSRemoting` + stop/disable the service + close the firewall rule -
   a bare `Disable-PSRemoting` alone does not remove the firewall exception, per Microsoft's own docs)
   immediately after that target's results are pulled back. Off by default; never touches a target that
   was already reachable. **Explicitly not exercised as a full enable-run-disable cycle against a real
   lab VM** - deliberately: every lab server currently has WinRM enabled and several other sessions'
   testing depends on that staying true, so disabling it just to prove it comes back felt like the wrong
   risk to take with shared lab state. What *was* verified live: the DCOM delivery channel itself
   (`Invoke-RemoteProcessViaDcom` against LABSRV16 with a harmless no-op command, using the same
   credential/session path the real enable/disable calls use) - `Enable-PSRemoting`/`Disable-PSRemoting`
   themselves are long-standing Microsoft cmdlets, not new code.

   **Third follow-up, same day - the user manually disabled PSRemoting on LABFS01 (.190) and asked for a
   real test.** Found and fixed two more real bugs in the process, neither visible from a code read:
   1. `New-PSSession` with no explicit `-Authentication` failed with "Access is denied" against LABFS01
      by its own FQDN, with a valid domain admin credential, right after `Enable-RemoteWinRm` had
      correctly brought WinRM up. Root cause: this machine's `WSMan:\localhost\Client\TrustedHosts` is
      non-empty (the lab-only weakening HANDOFF.md already documents), and having entries there changes
      how *unspecified* auth negotiation behaves even for targets not in that list. Forcing
      `-Authentication Kerberos` explicitly - which is what HANDOFF.md's manual procedure already said to
      do - fixed it immediately, confirmed by testing the same connection with no `-Authentication`
      (fails), `-Authentication Negotiate` (succeeds), and `-Authentication Kerberos` (succeeds) back to
      back against the same target.
   2. With that fix in place, a *fast* enable-then-connect cycle still failed the same way, while a
      *slower*, manually-staged one (enable, wait, then connect as a separate step) succeeded. Root
      cause: `Wait-ForWinRmPort` was polling `Test-WinRmPort` - a raw TCP connect - and the WinRM port
      starts accepting TCP connections *before* the WS-Man/authentication stack is actually ready to
      service a real session request, right after `Enable-PSRemoting` just registered a new listener.
      Switched the readiness check to `Test-WSMan` (a real protocol-level identify call) instead of a
      bare port probe.

   With both fixes in place, the full cycle against LABFS01 succeeded end to end: WinRM enabled via DCOM,
   a real Fast-mode discovery run completed (231 files pulled back into a genuine
   `Discover-WindowsServer_LABFS01_<timestamp>\` folder), and WinRM was confirmed back to `False`
   (unreachable) on LABFS01 immediately afterward - the exact case flagged as unverified above is now
   verified for real, not just plausible.

   **Fourth follow-up, same day - a much bigger bug, found from the user's own first real multi-server
   click.** Picking all 7 AD-found servers and clicking "Run on Selected" produced one result entry whose
   `ComputerName` was all 7 FQDNs glued together with commas, `Status: Unreachable`, "The RPC server is
   unavailable." Root cause, confirmed with a minimal repro: launching a script via `-File` does **not**
   re-parse its trailing arguments as PowerShell syntax the way an interactive prompt would -
   `pwsh -File s.ps1 -Foo a,b,c` binds a **one-element** array holding the literal text `"a,b,c"`, not
   three elements, for a `[string[]]$Foo` parameter. Both `Build-DiscoveryArgumentList` (`-IncludeModules`)
   and the Fleet tab (`-TargetComputerNames`) built their multi-value arguments as a single comma-joined
   token expecting normal array binding on the other side - which silently broke **Custom Mode for any 2+
   module selection** (a pre-existing bug, not something Fleet Discovery introduced - it just always
   "worked" for exactly one checked module, which is almost certainly why nobody had caught it) in
   addition to Fleet Discovery for any 2+ server selection.

   Fixed generically, not with a special case per call site: `ConvertTo-DiscoveryLauncherScript` in
   `Discover-WindowsServer-GUI.ps1` takes the existing flat argument list and a list of which `-Flag`
   names are array-valued, and writes a small temp **launcher .ps1** that invokes the real target script
   with those values as genuine `@('a','b','c')` PowerShell literals - since a script's own *contents* do
   get properly parsed when it runs, unlike `-File`'s trailing arguments. Both `Start-DiscoveryRun`
   (single-server) and the Fleet tab's launch now go through it. (Original version wrote to
   `%ProgramData%\...\launchers\` and self-deleted, because the Fleet launch ran it via
   `Start-Process -Credential` as a different domain account at the time - **both of those details were
   superseded by the Fifth follow-up below**, which writes to the operator's own `%TEMP%` and leaves
   cleanup to the caller instead.)

   Caught a second, self-inflicted bug while building the fix: the first version of
   `ConvertTo-DiscoveryLauncherScript` had the line that actually assembles `$command` go missing during
   an edit (a find-and-replace ate it), so every launcher it wrote contained only the self-delete
   statement and silently did nothing. Four new Pester tests actually *run* the generated launcher against
   a real fixture script rather than just inspecting its text - they would have caught that immediately.
   (The "self-deletes after running" assertion was itself later replaced - see Fifth follow-up.)
   Verified live end to end against two real servers (LABSRV19 + LABSRV16) via the exact same
   `ConvertTo-DiscoveryLauncherScript` -> `Start-Process` path the GUI uses: both completed as two
   **separate** result entries (not glued together), 241 real files pulled back for each. Also closes the
   "multi-server rollup only tested against fixtures" gap noted above - `New-FleetRollupReport` against
   these two real folders correctly combined them (`ServerCount: 2`, `FindingCount: 85`).

   **Fifth follow-up, same day - rollup visibility was lying by omission, and the ambient-identity
   credential design turned out to be unreliable.** The user ran a real 7-server fleet job and reported
   "it only ran on 3 servers out of all of them and the rollup report is weak" (screenshots showed 7
   checked, 3 findings, several columns blank). Two separate root causes:
   1. `New-FleetRollupReport` only ever read successful `Discover-WindowsServer_*` output folders - a
      target that failed or was skipped left **no trace in the report at all**, so "7 attempted, 4
      failed" rendered identically to "3 servers, nothing else exists." Fixed: `Get-FleetRunOutcome`
      now reads `fleet-run-results.json` (every attempted target, success or failure) and the rollup
      merges that with whatever folders did land, so every attempted server shows a row - failed ones
      red-highlighted with their real error message, plus an honest "X of Y succeeded" header line.
   2. Two of the four "missing" servers (`ClaudeWin2025Dev`, the DC, and `LABCLUS01`, a cluster network
      name that routes to it) failed with "no output folder was found" even though the run itself
      worked. Root cause: folder detection filtered on
      `"Discover-WindowsServer_${ComputerName}_*"`, but the engine names its own output folder from the
      target's *actual* `$env:COMPUTERNAME` - which diverges from the AD/connect name here
      (`ClaudeWin2025Dev` vs the real `CLAUDEWIN2025DE`, confirmed directly). Fixed by dropping the name
      requirement entirely - filter on `Discover-WindowsServer_*` + `CreationTime -ge $Since` only.
      Verified live: a ClaudeWin2025Dev retest now finds its folder correctly. (One target, LABSRV12 on
      2012 R2/PS4.0, still fails with "no output folder found" even with this fix and with scheduled-task
      output now redirected to a log file for diagnostics - the log itself never got created either,
      suggesting the scheduled task may not be executing at all on that specific box. Undiagnosed at the
      time; lower priority than the fixes below since it's now at least *visible* as a clear failure
      instead of silently absent. **Root-caused and fixed 2026-09-26 - see item 4 below.**)

   Separately, the user asked to test the opt-in WinRM-bootstrap feature for real ("I disabled
   PSRemoting on VM 102 (.190), you can test it against that" - i.e. LABFS01, already covered by the
   Third follow-up above). Re-running it exposed that the `Start-Process -Credential` design (ambient
   identity, no explicit `-Credential` on `New-PSSession`) is **not reliably equivalent** to an explicit
   credential for WinRM auth: isolated, back-to-back tests against the identical account/target/auth
   mode showed the ambient-identity path failing with "Access is denied" while an explicit `-Credential`
   in the same process succeeded immediately, every time. Redesigned credential delivery: the child
   process now launches as the **same identity as the GUI** (no `-Credential` on the launch), and the
   domain credential is written to the child's stdin instead (two lines - username, then a base64'd
   UTF8 password - via `[System.Diagnostics.Process]::Start` with `RedirectStandardInput`, never a
   command-line argument, which even a launcher script can't hide from `Get-Process`/WMI). New
   `-CredentialFromStdin` switch on `Invoke-FleetDiscovery.ps1`; the reconstruction itself lives in a
   separate pure function, `ConvertTo-CredentialFromEncodedLines`, with its own 2 Pester tests (matching
   this repo's convention of keeping testable logic out of the top-level execution guard). This also let
   `ConvertTo-DiscoveryLauncherScript` go back to writing under the operator's own `%TEMP%` instead of
   `%ProgramData%` (no more cross-account permission need), which in turn surfaced that the launcher's
   own self-delete was failing silently anyway due to mismatched NTFS inheritance flags on that
   `%ProgramData%` ACL (folder-only grants, not extending to files created inside) - removed self-delete
   from the launcher entirely; cleanup now happens in the GUI's own completion-timer handlers, under the
   identity that created the file.

   Even with the stdin redesign, a live end-to-end retest against LABFS01 **still** failed with "Access
   is denied." Isolated it down to a genuine timing gap, confirmed directly: force-disable WinRM on
   LABFS01, re-enable via `Enable-RemoteWinRm`, wait for `Wait-ForWinRmPort` (`Test-WSMan`) to succeed,
   then immediately try `New-PSSession -Credential $cred -Authentication Kerberos` - **fails** with
   "Access is denied" on the first attempt, **succeeds** on an identical retry 5 seconds later.
   `Test-WSMan` is an unauthenticated protocol-level identify call, so it can confirm the WS-Man layer is
   listening without being able to see that the authenticated/authorization path (session configuration
   registration) isn't fully settled yet - a further gap past the one the Third follow-up's
   `Test-WinRmPort` -> `Test-WSMan` switch already fixed. Fixed with a small retry loop around
   `New-PSSession` in `Invoke-RemoteDiscoveryRun`, gated on `$weEnabledWinRm` being true (an
   already-reachable target never needed this settling time, so it never retries) - up to 5 attempts,
   5 seconds apart. **Verified live end to end afterward**: LABFS01 confirmed unreachable beforehand,
   full run via `-EnableWinRmIfUnreachable -CredentialFromStdin` completed in ~3.5 minutes
   (`Status: Succeeded`, `WinRmEnabledByThisTool: true`, no "Access is denied"), and WinRM was confirmed
   reverted (`Test-WSMan` failing again) on LABFS01 immediately after.

3. **Internal report redesign (2026-09-25) — two new HTML formats, live-verified against a real
   local run on both PowerShell engines; needs the user's own visual sign-off.** The user's
   complaint: the internal report was "an insanely long list of stuff," findings and every
   dataset stacked as one continuously scrolling page with no way to jump to a section. Explored
   two redesign directions first as an Artifact mockup with sample data (a sidebar "command
   center" vs. a collapsed-by-default "executive brief") before touching real code, then built:
   1. **`reports\internal-engineering-report.html` restyled, not restructured** - same content,
      same order, as it always was (findings by severity, then every named dataset section, then
      unknowns/limitations/scope language/dataset index) - just visually reworked: a colored left
      stripe per severity instead of an inline dot badge, KPI tiles, a `@media print` block. Still
      exactly one linear page, meant to be printed or read start to finish.
   2. **`reports\internal-dashboard-report.html`, new** - the actual fix for "insanely long":
      a sidebar nav (grouped Overview / Findings / Datasets / Reference, each with a row count)
      swaps which pane is visible via a few lines of vanilla JS - no framework, since this file
      has to open standalone and sometimes offline. Every table sits in its own fixed-height
      scroll box with a sticky header row and a live text filter, instead of the page itself
      growing to hundreds of rows. Both files are still self-contained single-file HTML (system
      font stack only, no CDN/Google Fonts - these open on client sites that may be air-gapped).
   3. **Both renderers now share one content model**, `Get-InternalReportModel` in `Output.psm1`
      (findings sorted emphasis-first then by severity, the named-dataset section list, project-
      impact rollup, dataset index) - extracted specifically so the two formats can never drift
      apart and show different data for the same run, matching the same reasoning
      `Get-RbClientModel` already uses for the client report's HTML/Markdown pair.
   4. **Wired in everywhere a filename list needed to know about the new file**:
      `Write-DiscoveryOutputs` (generates + copies to `Paths['Internal']` alongside the existing
      report), `config\output-settings.json`'s `requiredOutputFiles` (the self-check's
      authoritative list), `EvidenceManifest.psm1`'s sensitivity classifier (so it's tagged
      `Internal`, not `SensitiveRedacted`), the run folder's own generated `README.txt`,
      `docs\OUTPUT-GUIDE.md`, `README.md`, and `tools\Verify-DiscoveryRun.ps1` (a new check for a
      closed file with a working nav, mirroring the existing internal-report check).
   5. **New Pester coverage** for `Get-InternalReportModel` (emphasis-first sort order, per-
      severity counts, a zero-row dataset correctly absent from the section list, project-impact
      grouping) and for both renderers (well-formed HTML, the same finding actually present in
      both files - proving the shared-model fix holds). **Verified live, not just unit-tested**:
      ran the real output smoke test end to end (a genuine `Discover-WindowsServer.psm1` pass,
      not a fixture) under both `pwsh` and Windows PowerShell 5.1, and opened both generated HTML
      files through a real local HTTP server (a `file://` open in this session's browser tool
      renders a static snapshot with JS disabled, which silently made the dashboard's nav clicks
      look broken at first - serving it over `http://localhost` instead showed the sidebar nav,
      pane switching, and the live table filter all working correctly).
   **Not yet done**: the client-facing report (`client-discovery-report.html`) was deliberately
   left alone this round - the user scoped this request to the internal report specifically. The
   GUI itself doesn't reference either report's filename anywhere (no code changes needed there),
   so the one thing left is the user actually opening both new files from a real run and confirming
   they look right on screen - same "needs eyes on it" caveat every UI-facing change in this repo
   gets until someone other than the assistant has looked at it.

4. **Fleet rollup Option A/B redesign, and the real LABSRV12 (2012 R2) root cause, found and
   fixed (2026-09-26) — both verified live against a real 7-server fleet run and a real
   previously-broken target.**
   1. **Fleet rollup gets the same two formats as the single-server report.** The user's
      own 7-server rollup (real run, 6/7 succeeded, LABSRV12 the one known failure) confirmed
      the rollup correctly compiled everything - "6 of 7 server(s) succeeded", LABSRV12 shown
      red with its real error message, 475 combined findings matching the CSV row count exactly.
      One side note surfaced while checking it, not a bug: `ClaudeWin2025Dev` and `LABCLUS01`
      both attribute their findings to `CLAUDEWIN2025DE` in the rollup - correct, not a
      duplicate, since LABCLUS01 is a cluster network name routing to that same physical DC (see
      the Fourth follow-up above) and each server-summary row is keyed off the run FOLDER's own
      `collection-metadata.json`, which always records the target's real `$env:COMPUTERNAME`.
      Applied the same redesign as the single-server internal report:
      `tools\Merge-FleetDiscoveryResults.ps1` now has `Get-FleetRollupModel` (server summaries,
      severity-grouped risk register, dependency hints, decomm/assumption/exclusion rollups) as
      the one shared source of truth, `Write-FleetRollupHtml` (restyled `fleet-rollup.html` -
      KPI tiles, severity-striped finding cards, same visual language as
      `internal-engineering-report.html`, still one linear printable page) and the new
      `Write-FleetDashboardReport` (`fleet-dashboard-report.html` - sidebar nav grouped by
      Overview/Findings/Reference, scrollable+filterable tables, identical Command Center
      layout/behavior to the single-server dashboard). The GUI's "Build Rollup Report" button
      now opens both. 5 new Pester tests.
   2. **LABSRV12's "no output folder found, no task log found either" failure - actually root-
      caused this time**, not just made visible. Three real, distinct bugs found in sequence,
      each confirmed by a live retest against the real box before moving to the next:
      - The scheduled-task poll loop's `-not $state` completion check couldn't tell "the task
        finished and Task Scheduler cleaned it up" apart from "the task was never registered at
        all" (none of the scheduled-task cmdlets had `-ErrorAction Stop`, so a registration
        failure would have logged a non-terminating error and silently continued). Fixed:
        every scheduled-task cmdlet now has `-ErrorAction Stop`, wrapped in its own try/catch
        with a clearly-labeled rethrow, plus an explicit existence check immediately after
        starting the task.
      - With that in place, LABSRV12 still failed the same way. Added a diagnostic (query the
        task's own `LastTaskResult` before cleanup) and found it: `1` - a generic "process
        exited with an error" code, with **neither an output folder nor a single byte in the
        `*>`-redirected log file**. That combination is the signature of the `-Command "..."`
        string itself failing to parse (the old approach embedded the whole invocation, redirect
        included, as one escaped-double-quote string) - not the engine erroring, since a real
        engine error would still have landed in the log via `*>`. Fixed by writing a real staged
        `.ps1` launcher file and invoking it with `-File` instead - the same fix already used
        elsewhere in this toolkit for `-File`'s own array-argument quirk
        (`ConvertTo-DiscoveryLauncherScript`).
      - Retested again: `LastTaskResult` now `0` (success), but still no output and no log,
        consistently finishing in under a minute regardless of what changed. Added one more
        diagnostic - a heartbeat marker written directly (not through `*>`) as the launcher's
        very first statement - and confirmed the marker DID get written, so `-File` was
        executing the launcher's body correctly. That narrowed it to the actual
        engine invocation, and a version check confirmed the real cause:
        **`Discover-WindowsServer.ps1`'s own `#Requires -Version 5.1` (line 1) rejects the
        script before its body runs - and before `*>`'s target file is ever created - and
        LABSRV12 is a real Windows Server 2012 R2 box running the stock PowerShell 4.0**
        (confirmed directly: `$PSVersionTable.PSVersion` = `4.0`). The engine's own header
        comment already documented this exact constraint ("2012 R2 ships PowerShell 4.0 and
        fails this check... install PowerShell 7 there, then run via pwsh.exe") -
        `Invoke-FleetDiscovery.ps1` just hadn't been written with that constraint in mind; its
        own comment chose Windows PowerShell specifically for being "guaranteed present," which
        is true but insufficient once the engine's own version floor is factored in. Fixed:
        before staging or registering anything, the target's Windows PowerShell version is
        checked; if it's below 5.1, `pwsh.exe` is used instead if present at its standard
        install path, and if neither meets the bar the run fails immediately with an actionable
        message ("install PowerShell 7 on the target first") instead of a 40-second dead end.
      **Verified live end to end**: LABSRV12 already had PowerShell 7 installed (from earlier,
      separate work), so once the fix picked it up correctly the fleet job **actually
      succeeded** - a genuine Fast-mode run (`PowerShellVersion: "7.4.20"` in its own
      collection-metadata.json, `IsAdmin`/`IsSystem` both true, 100 datasets exported, all
      reports including the new dashboard generated) - not just a cleaner failure message. Full
      gate (207 static checks + 388 Pester tests + the output smoke test) passes clean on both
      `pwsh` and Windows PowerShell 5.1.

5. **Parallel fleet execution, PS-version check surfaced in the picker, and a client-safe fleet
   summary (2026-09-26) — all three verified live against a real 7-server run (7/7 succeeded,
   including LABSRV12).** Also answered a scaling question: the Fleet tab's candidate list
   already scrolls correctly at 20+ servers (`ScrollViewer` around a 2-column `UniformGrid`) - no
   crash risk - but had no bulk-select, so "Select all"/"Select none" buttons were added too.
   1. **Targets now run through a bounded runspace pool** (`tools\Invoke-FleetDiscovery.ps1`,
      new `Invoke-FleetRunsInParallel`) instead of one at a time - a pool of size 1 (`-MaxConcurrency 1`,
      the default) is identical to the old sequential `foreach`, so there's one code path, not
      two that could drift apart. Each runspace dot-sources the script file itself by path
      (`. $ScriptPath`, safe the same way Pester/the GUI already dot-source it - the bottom
      "only runs when executed directly" guard checks `$MyInvocation.InvocationName`) since
      `Invoke-RemoteDiscoveryRun` depends on most of the file's other functions, not just one
      the way the lighter subnet-scan pool only needed `Test-WinRmPort`. `Update-FleetStatusFile`'s
      `CurrentTarget` became `CurrentTargets` (plural) since more than one can genuinely be
      running at once. GUI: a "Run up to N at once" combo (1/2/3/5/10/20) on the Fleet tab feeds
      `-MaxConcurrency` straight through. 3 new Pester tests against a fixture script (a fake
      `Invoke-RemoteDiscoveryRun` that just sleeps and returns a canned result, since the real
      one needs live WinRM) - one of them compares wall-clock time for concurrency 1 vs. 6 on
      the same workload rather than asserting an absolute cutoff, after a fixed-threshold version
      of that test flaked once already (runspace-pool startup overhead varies by machine).
   2. **A reachable target that can't actually run the engine now shows that in the picker**, not
      after a wasted run cycle - new `Get-FleetTargetPowerShellInfo` (same runspace-pool pattern,
      needs a real authenticated session per host so it only runs once a credential is set and
      only against already-WinRM-reachable candidates) checks each one's Windows PowerShell
      version and whether PowerShell 7 is installed, exactly what item 4 above found the hard
      way on LABSRV12. `Update-FleetCandidateList` shows an orange "needs PowerShell 7" label
      instead of the grey "WinRM not responding" one - a different problem, a different color,
      so the two are never confused. A probe failure (bad credential, Kerberos hiccup) reports
      `EngineCompatible = $null` rather than `$false`, so "couldn't tell" is never displayed as
      "confirmed incompatible."
   3. **`fleet-client-summary.html`/`.md`** - the client-safe fleet equivalent of
      `client-discovery-report.html`, generated every time `New-FleetRollupReport` runs (same
      "always produced, not opt-in" as the single-server client report). New
      `Get-FleetClientSafeDataset` reads each dataset's Visibility from the *specific server's
      own* `collection-metadata.json` rather than a hardcoded list, so it can never silently
      drift from what that server's own client report would have shown. Findings are the
      trickiest part: `ScopingRisks` itself is Internal-visibility, so `Get-FleetClientHeadlines`
      extracts only `Title` + `WhyItMattersForScoping` (never `Evidence`) for Critical/High
      findings - the identical safety contract `Get-RbClientHeadlines` already uses for the
      single-server report - then groups by title ACROSS the fleet ("SMBv1 enabled - affects
      SRV-A, SRV-B" as one line, not one repeated per server). A failed target is counted in the
      total but never shown with its internal error detail (a DCOM/Task Scheduler/WinRM message
      is Internal information about this toolkit's own mechanics, not a client-facing fact).
      5 new Pester tests specifically assert the safety contract (evidence text never appears in
      the model, the HTML, or the Markdown) using a fixture with real evidence-shaped strings
      planted in it, not just checking that *something* renders.
   **Verified live**: ran a real rollup against the user's own 7-server run (7/7 succeeded) -
   `fleet-client-summary.html` correctly showed 7 of 7 reviewed, 18 headlines, 7 servers flagged
   for no backup detected, and zero matches for evidence-shaped content (registry paths, service
   accounts, raw config strings) when grepped for directly. Full gate (207 static checks + 397
   Pester tests + the output smoke test) passes clean on both `pwsh` and Windows PowerShell 5.1 -
   catching, along the way, a real PS5.1-only bug the self-check doesn't cover: `[void]$expr |
   Out-Null` (both suppression techniques on the same runspace-pool `.AddArgument()` chain)
   throws `"Argument type cannot be System.Void"` on 5.1 but not on `pwsh` - fixed by keeping only
   the `[void]` prefix, matching the pattern the file's own pre-existing `Invoke-SubnetWinRmScan`
   already used correctly.

6. **Fleet concurrency bug found in real use (branch `fleet-concurrency-copy-fix`, PR #1), root
   cause confirmed and fixed (2026-09-26).** After item 5 shipped, the user ran a real 5-target
   fleet job with `-MaxConcurrency` and hit a live failure: two selected targets
   (`ClaudeWin2025Dev` and `LABCLUS01`, a cluster network name currently owned by that same
   physical DC) both failed with "no output folder found" and real "Could not find a part of the
   path" errors in the target's own log.
   1. **First cause, fixed:** `Invoke-RemoteDiscoveryRun` used the literal shared `C:\Discovery` /
      `C:\DiscoveryOut` for every target's staging/output path, so two concurrent runs against the
      same physical machine collided and overwrote each other's files mid-run. Fixed by scoping
      both paths by the already-generated per-run `$taskName`.
   2. That alone didn't fully fix it. A step-by-step trace file added to the launcher script
      pinpointed the real symptom: `Discover-WindowsServer.ps1` was missing from the target after
      `Copy-Item -ToSession` reported success — `Copy-Item -ToSession` is fragile when two
      instances run concurrently against sessions on the same physical endpoint (it works by
      injecting temporary helper functions into the target session to receive the byte stream).
      Fixed by serializing just the copy step across every concurrent runspace with a named
      `System.Threading.Mutex` (a named, not anonymous, mutex is required because each runspace
      dot-sources this script fresh — there's no shared script-scope variable a plain lock object
      could live in), plus a verify-and-retry loop with per-attempt timing/exception diagnostics
      as a second line of defense.
   3. **A red herring that briefly derailed the investigation, worth recording so it doesn't
      happen again:** a same-session test that ran a *single*, non-concurrent target through
      `Invoke-RemoteDiscoveryRun` directly also failed the same way, which looked like proof the
      bug had nothing to do with concurrency at all. It didn't — the test driver script itself
      computed `-LocalToolkitRoot` as `Split-Path -Parent $fleetScriptPath` (`...\tools`, since
      `$fleetScriptPath` is `...\tools\Invoke-FleetDiscovery.ps1`) instead of the actual repo
      root, so it was correctly reporting that the engine file was missing from a directory that
      never contained it in the first place. Fixed the test driver, reran: single target succeeds
      cleanly on its own.
   4. **Verified live, for real this time:** with the corrected test driver, the original bug
      scenario — `ClaudeWin2025Dev` and `LABCLUS01` (same physical machine) run concurrently at
      `-MaxConcurrency 2` via `Invoke-FleetRunsInParallel` — both completed with `Status =
      Succeeded` and a full, distinct evidence set each (spot-checked `evidence\data\json\` on
      both pulled-back folders). The mutex is confirmed necessary, not incidental complexity to
      remove — keep it.

7. **NinjaRMM deployment wrapper (2026-09-22) — needs a real NinjaOne environment to verify end to end.**
   [tools\Invoke-NinjaDiscovery.ps1](tools/Invoke-NinjaDiscovery.ps1): downloads the toolkit from this (private)
   GitHub repo, runs a scan with Ninja-parameter-selected options, optionally delivers via
   `Send-DiscoveryOutput.ps1`, cleans up local output after a successful delivery. Its pure logic (base64
   decoding, Postal target parsing, delivery-args construction) has 10 Pester tests, but the actual
   download-from-GitHub / run-as-SYSTEM / NinjaOne-parameter-binding path has never been exercised against a real
   NinjaOne tenant - this session only has repo access, not a Ninja environment. Before relying on it: paste it
   into an actual NinjaOne Automation script, set the parameters (see the script's own `.EXAMPLE`), and run it
   against one test endpoint first. Two things worth double-checking there specifically since they were
   confirmed only against NinjaOne's public docs, not tried live: that Ninja's parameter constraints (string-
   only, `& | ; $ > < \ !` rejected) are exactly as documented for your NinjaOne version, and that a SYSTEM-
   context script on your endpoints actually has outbound HTTPS to github.com (some client networks proxy or
   restrict that).

8. **Fixture-based collector tests — started 2026-09-22, fourteen collectors done, more to add.**
   `tests\Pester\DNS.Tests.ps1` (6), `tests\Pester\Network.Tests.ps1` (8), `tests\Pester\ServicesTasks.Tests.ps1`
   (25), `tests\Pester\SecurityPosture.Tests.ps1` (18), `tests\Pester\ConfigDependencyScan.Tests.ps1` (9),
   `tests\Pester\ActiveDirectory.Tests.ps1` (11), `tests\Pester\IIS.Tests.ps1` (13), `tests\Pester\AzureHybrid.Tests.ps1`
   (14), `tests\Pester\SQL.Tests.ps1` (12), `tests\Pester\SystemInventory.Tests.ps1` (22),
   `tests\Pester\RolesFeatures.Tests.ps1` (11), `tests\Pester\Applications.Tests.ps1` (6),
   `tests\Pester\UserProfiles.Tests.ps1` (6), `tests\Pester\TimeSync.Tests.ps1` (9) are done.
   ConfigDependencyScan surfaced three real Pester scoping gotchas, all documented in that file's header — read
   it before writing the next filesystem-walking collector's tests. SystemInventory was different from every
   collector tested so far: its richest logic (`Get-SIChassisType`, `Get-SIOsEdition`, `Get-SIEndOfLifeInfo`,
   `Get-SIPlatformDetection`) lives in functions the file itself marks `#region Private helpers` and deliberately
   does not export — unlike SQL's `Get-SqlServiceAccount`, this reads as intentional encapsulation, not an
   oversight, so nothing was added to `Export-ModuleMember`. Tested via `InModuleScope SystemInventory { ... }`
   instead, with a small `Invoke-SIPrivate` dispatcher helper in the test file to avoid repeating the
   `-Parameters` boilerplate per assertion. `Get-SIEndOfLifeInfo` was the actual target — it's the sole source of
   `OperatingSystem.IsEndOfLifeOrNear`, arguably the single most consequential boolean this toolkit produces for
   a decommission/refresh conversation, and had zero prior coverage despite explicit dated logic (Server 2016's
   "extended support ends 2027-01-12") that will go stale. Pattern proven across 10 modules now, two mocking
   styles depending on whether the target logic is exported (`Mock -CommandName X -ModuleName <Module>`) or
   private (`InModuleScope <Module> { ... }`).
   **RolesFeatures/Applications/UserProfiles/TimeSync added 2026-09-27**, picked by real business logic rather
   than an exhaustive sweep: `ConvertFrom-DismFeatureText` (two different `dism` output formats) and the
   regex-based role classifier feeding every report's "likely server role" line; `Get-FingerprintMatches`'
   Confirmed/Likely/Possible confidence scoring, which directly feeds the client report's "business applications
   we recognised" table; `Get-UpSidIsRealUser`'s well-known-SID filter (small, but wrong either leaks system
   accounts or drops real ones); `ConvertFrom-W32tmOffset`'s explicit "return `$null`, never `0`, when
   unparseable" contract. **A real, live footgun caught writing these**: `Get-FingerprintMatches` (like several
   `,@()`-returning functions in this codebase) is only safe via a BARE assignment
   (`$x = Get-FingerprintMatches ...`) — wrapping the *call itself* in `@(...)` nests the result one level deeper
   instead, the exact bug class that broke the fleet client summary's tables earlier this session
   (`Get-FleetClientSafeDataset`/`Merge-FleetDataset`, fixed 2026-09-26). The FIRST draft of
   `Applications.Tests.ps1` did this wrong and four tests silently "passed" anyway via PowerShell's
   array-vs-scalar comparison leniency, not because the logic was actually verified — caught only because one
   assertion on an *empty* result exposed it (`@(Get-Foo).Count` was 1, not 0). Fixed by following the bare-
   assign-then-`@()`-the-variable pattern `Invoke-DiscoveryFingerprintSynthesis`'s own code comment already
   documents. Worth remembering for every future test of a `,@()`-returning function in this repo.
   **Still uncovered:** ~19 more collectors, confirmed to be thin single-call wrappers around one CIM/registry/
   cmdlet call with no extra private logic (`BackupDR`, `Certificates`, `Cluster`, `DHCP`, `EventLogs`, `HyperV`,
   `Licensing`, `NPS_RADIUS`, `PerformanceSnapshot`, `PrintServer`, `RDS`, `Storage`, `VendorAgents`, plus the
   synthesis-only `ClientInterviewPack`/`DecommissionReadiness`/`EvidenceManifest`/`ReportBuilder`/
   `ScopeLanguage`) — lower priority than a collector with real parsing/classification logic. See HANDOFF.md for
   why fixtures complement rather than replace live testing.

9. ~~**`[IIS] Get-Website failed.` limitation has no reason suffix**~~ — **fixed 2026-09-29** (see item 12).

10. **`datasetRowCountAtLeast` condition type is still genuinely unused** (0 rules reference it) — not a
   defect, the engine already guards it correctly (see HISTORY.md's F21 entry), just nothing has needed it yet.
   Low priority; only worth touching if a future rule naturally wants a "≥ N rows" threshold.

11. ~~**A line-by-line read of 18 collectors never happened.**~~ — **closed 2026-09-29**: all 34 modules
   have now been read in full (see item 12), not just the original 6 plus automated contract checks.

12. **Full-module completeness audit + CMMC/GeneralSecurity coverage review (2026-09-29) — every module read
   in full, gaps fixed, verified on both runtimes.** The user asked whether every module was fully built out
   (no internal stubs/TODOs) and whether server-side CMMC/GeneralSecurity technical coverage was solid.
   Deliberately server-technical only, per explicit user instruction — no client-interview-question additions
   (that's the account manager/consultant's job, not this tool's).
   1. **Module completeness: solid.** All 34 `.psm1` files read start to finish (not just grepped) - no
      stubs, no dead-end collectors, no missing try/catch around a call that could throw on a non-elevated/
      2012 R2/role-not-installed box, no unexported functions, no redaction leak. `FunctionsToExport` vs
      actual exports and `ProducesDatasets` vs actual `Add-DataSet` calls matched exactly across all 34
      (self-check already asserts this mechanically; the full read confirmed it's not gaming the check).
   2. **Three real metadata-contract mismatches found and fixed** (module *worked*, its `Get-DiscoveryModuleMetadata`
      just claimed a capability it didn't exercise):
      - `DHCP.psm1`: `ProducesRisks` was `$true` but zero `risk-rules.json` rules ever referenced
        `DhcpScopes`/`DhcpReservations` (the real "hosts the DHCP role" finding, RULE-DHCP-001, is correctly
        sourced from `RolesFeatures` instead, since that module runs on every server and this one is
        role-gated). Corrected to `$false` rather than inventing a rule that would misfire on every non-DHCP
        server (no `risk-rules.json` rule keys a `datasetMissingOrEmpty`/similar condition off a role-gated
        module's own dataset anywhere in this codebase, for exactly that reason).
      - `DecommissionReadiness.psm1`: `ProducesFollowUpQuestions` was `$true` but the module never calls
        `Add-FollowUpQuestion` - its per-factor `ValidationNeeded` text never reaches the client interview
        pack. Corrected to `$false` (not wired to actually promote questions, since growing the
        interview-question surface was explicitly out of scope for this pass).
      - `EventLogs.psm1`: `ProducesRisks` was `$true` with no rule referencing it either - now genuinely
        true, fixed properly rather than flagged, via the audit policy work in (4) below.
   3. **Real bug found independently: `EventLogs.psm1` never actually read the Security log.** Its own log
      list (`$logs = @('System','Application')` plus a few optional operational logs) never included
      `'Security'`, despite a limitation message existing specifically for "Security log not accessible" -
      that branch was dead code, and the single most compliance-relevant log on the box went unsampled
      regardless of whether the run was elevated. Fixed: `'Security'` is now added to the log list when
      `Context.IsAdmin`, so the message is reachable and an elevated run actually samples it.
   4. **New: advanced audit policy collection**, closing a real CMMC/NIST AU-family gap that had zero
      coverage before. `Get-AuditPolicySettings` (`modules\EventLogs\EventLogs.psm1`) parses
      `auditpol /get /category:*` (format confirmed live against this session's own real Server 2025 box -
      category headers at column 0, subcategory lines indented two spaces) into the new `AuditPolicySettings`
      dataset; a curated critical-subcategory list (Logon, Account Lockout, Security State Change, Audit
      Policy Change, User/Security Group/Computer Account Management, Sensitive Privilege Use, ...) set to
      "No Auditing" derives `AuditPolicyGaps`, and `RULE-AUDIT-GAPS` fires a single aggregate High finding
      when any exist.
   5. **New: LDAP signing / channel binding check** (`modules\ActiveDirectory\ActiveDirectory.psm1`) - one of
      the most common real-world AD hardening gaps (Microsoft KB4520412 and the 2023 channel-binding
      advisory). Reads `NTDS\Parameters` (`LDAPServerIntegrity`, `LdapEnforceChannelBinding`) but ONLY when
      `$isDc` is true - a member server has no such registry key at all, so an ungated read would compute the
      same "not enforced" result on every non-DC in a fleet and misfire everywhere. `RULE-AD-LDAPSIGN`/
      `RULE-AD-LDAPCHANNELBIND` fire only on a real DC.
   6. **New SecurityPosture checks**, several of them free wins - fields the collector already gathered with
      no rule ever reading them:
      - `RULE-SEC-TLS11` - `Tls11Enabled` was already collected, never had a rule (only TLS 1.0 did).
      - `RULE-SEC-GUEST` - built-in Guest account enabled.
      - `RULE-SEC-SMBSIGN` - SMB server signing not required.
      - `RULE-SEC-NTLM` - `LmCompatibilityLevel` explicitly permits LM/NTLMv1 (absent/unconfigured is never
        flagged, matching `Test-TlsProtocolEnabled`'s existing "can't confirm -> don't over-claim" contract).
      - `RULE-SEC-PWNOEXPIRE` - `LocalUsers.PasswordNeverExpires` was already collected per-account, never
        had a rule; a new `Get-NonExpiringPasswordAccounts` pre-filters to enabled accounts only (the
        RiskEngine's condition language can only test one field per row - it can't express "Enabled=true AND
        PasswordNeverExpires=true" - so the collector does that filtering, same pattern already established
        for `ConfigDependencyHints`).
      - `RULE-SEC-USERRIGHTS` - `UserRightsAssignments` (secedit's `USER_RIGHTS` export) was already
        collected, never had a rule; a new `Get-SensitiveUserRightsGrants` flags a curated sensitive-rights
        list (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, ...) granted beyond a well-known-SID baseline.
        **Confirmed live** that `secedit /export /areas USER_RIGHTS` renders built-in groups as raw SIDs
        (`*S-1-5-32-544` for Administrators), not friendly names, only resolving to a plain name for a real
        custom/domain account - the baseline had to be SIDs, not names, or it would never have matched
        anything.
   7. **Test coverage**: 32 tests in `SecurityPosture.Tests.ps1` (was ~20), 4 new in
      `ActiveDirectory.Tests.ps1`, and a brand-new `EventLogs.Tests.ps1` (11 tests, first-ever coverage for
      that module) using a real captured `auditpol` output fixture. **Re-hit the `@(functionCall).Count`
      double-wrap footgun independently while writing these** (same class already documented for
      `Get-FingerprintMatches`) - `@(Get-SensitiveUserRightsGrants ...).Count` chained directly gave a wrong
      count on **pwsh 7, not just 5.1**, reproduced in a minimal repro outside Pester too; fixed by always
      assigning to a variable before wrapping in `@()`. Worth remembering this isn't 5.1-only.
   8. **Full gate**: 218 static checks + 504 Pester tests (2 skipped) + output smoke test + demo engagement,
      clean on both Windows PowerShell 5.1 and PowerShell 7.

## Explicitly not doing

- **Per-node CSV state** (`Get-ClusterSharedVolumeState`). **Hard no, standing rule (2026-09-22):** the only way
  to verify this is to put a CSV back on the lab cluster, and a CSV on this exact cluster bugchecked the DC
  three times before it was removed. The user will not accept that risk while scoping client work, full stop.
  Do not re-raise this.
- **WMF 5.1 installer option for 2012 R2.** Originally proposed so `IisBindings`, `EstablishedConnections`,
  `DnsClient` and `LocalGroups` could use their native PS5.1 cmdlets instead of fallbacks, and needed a restart
  (so `tools\Install-LegacyPrerequisites.ps1` would have to ask first). **All four of those gaps are now closed
  without it** — fixed via fallbacks in the 2026-09-22 "2012 R2 dataset-gap round" (appcmd for bindings, the
  netstat double-wrap fix for EstablishedConnections, `Win32_NetworkAdapterConfiguration`/`Win32_Group` CIM
  fallbacks for DnsClient/LocalGroups) — none of them need a restart. The one dataset that's still empty on
  2012 R2 (`IisApplications`/`IisVirtualDirectories`) is confirmed empty on LABSRV16/19 too, which *do* have
  the native `WebAdministration` module — so that's "nothing there to find in this lab," not a module gap WMF
  5.1 would fix either. Conclusion: no remaining justification for this feature. Revisit only if a *client*
  server surfaces a real 2012 R2 gap that a restart-free fallback genuinely can't close.

## Lab housekeeping still owed to the user

- `C:\iSCSIVirtualDisks` on the DC holds two dead files (the harness blocks deleting top-level `C:\` folders;
  the user can delete it).
- Lab-only weakening left in place: WinRM TrustedHosts for the lab IPs and CredSSP (DC → LABVH02). Offer to undo.
- The assistant saved the lab passwords in the user's private Claude memory; offer to strip them if asked.
