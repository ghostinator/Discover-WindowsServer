# Windows Validation & Resume Guide

Everything in this toolkit was reviewed and repaired on a **macOS** machine using PowerShell
7.6 for static analysis and for executing the platform-independent code paths. That verified a
great deal — but **none of the Windows-only collection code has ever actually executed**, and
the Pester suite has never run under real Pester.

This document is the handoff. Work top to bottom.

> ## Status as of 2026-08-21 — mostly executed
>
> This run-book **has now been worked** on a Windows 11 Enterprise workstation, not elevated.
> Full results, with measurements, are in the **Windows validation log** at the top of
> [TODO.md](TODO.md). Summary:
>
> - **Step 2 (the gate) passes on BOTH PowerShell 7.6.5 and Windows PowerShell 5.1** —
>   self-check 164/0, output smoke test pass, Pester **130 passed / 0 failed / 2 skipped**.
> - The project is now under git with CI running the gate on both runtimes:
>   `github.com/ghostinator/Discover-WindowsServer` (private).
> - **7 real defects were found and fixed** (F26–F32). Four of them were invisible to
>   PowerShell 7 and only appeared once 5.1 was in CI — including `datasetNotEmpty` never
>   firing for a single-row dataset, which silently disabled risk rules on the target runtime.
> - Section 4's table: **items 1, 4, 6, 8 CONFIRMED**; item 5 mechanism confirmed but its
>   matcher unexercised; **items 2, 3, 7 BLOCKED** — they need an **elevated session on a real
>   Windows Server** with SQL and/or IIS and real user shares.
>
> If you are picking this up on a server, jump to section 4 and do items 2, 3, 5 and 7.

---

## 1. Prerequisites on the Windows machine

```powershell
# From an elevated PowerShell 5.1 prompt, in the project folder:
$PSVersionTable.PSVersion          # expect 5.1.x - this is the target runtime
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck -MinimumVersion 5.0.0
```

Pester could not be installed on the review machine (no access to the PowerShell Gallery), so
the unit tests were executed through a hand-written offline shim. **Real Pester on Windows is
the first thing to run** — see step 2.

---

## 2. The one command that gates everything

```powershell
.\tests\Invoke-AllChecks.ps1
```

This runs three things and returns a single exit code:

| Check | What it proves | Status on macOS |
|---|---|---|
| `Invoke-ToolkitSelfCheck.ps1` | 162 static contract checks — parse, JSON, manifests, rule→dataset/field/token contract, fingerprint matchers, dead config, doc accuracy | ✅ 162/162 |
| `Invoke-OutputSmokeTest.ps1` | Runs the real synthesis + output chain on synthetic data; asserts every documented artifact is produced and well-formed | ✅ 0 failures |
| Pester suite | Unit tests for Core / Output / RiskEngine / redaction | ⚠️ **never run under real Pester** |

A check that cannot run now reports `NOT RUN` rather than `PASS`, so a missing Pester install
cannot masquerade as a green build.

### Expected result on Windows

All three should pass. **One known failure is expected to disappear on Windows:**
`Core.Tests.ps1` → `ConvertTo-SafeFileName` → *'replaces invalid characters'* fails on
macOS/Linux only, because `[System.IO.Path]::GetInvalidFileNameChars()` returns 2 characters on
Unix versus 41 on Windows (including `:`). On Windows it should pass. **If it still fails on
Windows, that is a real bug and not the known artifact.**

---

## 3. Then do a real discovery run

Static checks and synthetic data cannot exercise CIM, the registry, `secedit`, `appcmd`, or
`Get-SmbShare`. Run for real:

```powershell
# Safe first run - Fast mode is read-only and avoids the expensive paths
.\Discover-WindowsServer.ps1 -Mode Fast

# Then the deep path, which is where most of the repaired code lives
.\Discover-WindowsServer.ps1 -Mode Deep -ProjectType Decommission -GenerateEvidenceManifest

# And the emphasis lens on the same box, to compare
.\Discover-WindowsServer.ps1 -Mode Deep -ProjectType CMMCReadiness
```

Then open `internal-report.html` and skim `summary.md`, `draft-scope-language.md`,
`wbs-inputs.csv` and `scoping-risks.txt`.

---

## 4. What specifically needs Windows eyes

These changes are correct by inspection and covered by static checks, but the code has **never
run**. Ranked by risk.

| # | What to check | Where | How to tell it worked |
|---|---|---|---|
| 1 | **Redaction of real secrets.** The headline fix. | `config/redaction-patterns.json` | Search `csv\Services.csv`, `csv\ScheduledTasks.csv`, `csv\RunningProcesses.csv` for anything that looks like a live password. Every hit should read `[REDACTED]`. Then run `Invoke-Pester .\tests\Pester\Redaction.Tests.ps1` — 38 assertions. |
| 2 | **SQL `BinaryPath`** (new registry read of `SQLBinRoot`). | `modules/SQL/SQL.psm1` | On a box with SQL: `csv\SqlInstances.csv` has a populated `BinaryPath`, and `csv\CriticalPaths.csv` contains a row with `Source = SQL`. |
| 3 | **Recycle-bin exclusion** in the deep share crawl. | `modules/FileShares/FileShares.psm1` | Run `-Mode Deep`. `csv\NtfsAclSummary.csv` should show `RecycleBinIncluded = False` and a populated `RecycleBinSizeGB`. Re-run with `-IncludeRecycleBin` and confirm `TotalSizeGB` grows. |
| 4 | **Config-scan bounding** (`-Depth 8`, working caps). | `modules/ConfigDependencyScan/ConfigDependencyScan.psm1` | Run `-Mode Deep` on a server with large `Program Files`. It should finish in reasonable time. Check `limitations.txt` for the "Config scan stopped early" message if caps tripped. |
| 5 | **Fingerprint matching now post-collection.** | `modules/Applications/Applications.psm1` | On a box with SQL or IIS, `csv\ApplicationFingerprints.csv` should include them, sourced from `ListeningPorts` / `IisSites`. Those matchers could never fire before. |
| 6 | **Deep-mode event log depth.** ✅ CONFIRMED 2026-08-21 | `Discover-WindowsServer.ps1` | Measure it in the output — **neither `discovery-plan.md` nor `collection-metadata.json` records the resolved parameters**, so the check originally written here could not work. Count rows in `json/EventLogSamples.json`: Deep should reach **100 per log** over a **30-day** span; Fast is **5** per log (`EventLogs.psm1` caps Fast at `[math]::Min(5, $maxSamples)`, so Fast is 5, *not* 50) over 14 days. Measured: Fast 10 samples / max 5 per log / 3-day span; Deep 177 samples / max 100 per log / 2026-07-22→08-21 = exactly 30 days. |
| 7 | **`raw\` contents.** | `RolesFeatures`, `SecurityPosture` | `raw\RolesFeatures.raw.json` and `raw\userrights.inf` should exist on every run. Confirm `userrights.inf` contains only `Se*` privilege assignments and **no** secrets. |
| 8 | **ProjectType emphasis.** | `modules/RiskEngine/RiskEngine.psm1` | Compare the two Deep runs from step 3. Finding **count and severities must be identical**; only the priority section and ordering should differ. |

---

## 5. Resume prompt

Paste this into Claude Code from inside the project folder on the Windows machine.

```text
Read TODO.md and WINDOWS-VALIDATION.md in this folder first — they are the running handoff
from a multi-session audit and repair of this toolkit, done on macOS.

Context: Phases 1-4 of the plan in TODO.md are complete (security, config honesty, functional
gaps, correctness). Phase 5 is partly done. Everything was verified by static analysis and by
executing the platform-independent code paths, but no Windows-only collection code has ever
run, and the Pester suite has never run under real Pester.

Do this, in order, and stop after each step to report before continuing:

1. Install Pester 5.x if needed, then run .\tests\Invoke-AllChecks.ps1 and report the result.
   One failure is expected to VANISH on Windows: Core.Tests.ps1 'replaces invalid characters'
   fails only off-Windows because GetInvalidFileNameChars() returns 2 chars on Unix vs 41 on
   Windows. If it still fails here, treat it as a real bug.

2. Run a real Fast-mode discovery, then a Deep-mode one. Report any errors.txt / warnings.txt
   content and anything in limitations.txt that looks like a defect rather than an expected
   limitation.

3. Work through the table in section 4 of WINDOWS-VALIDATION.md ("What specifically needs
   Windows eyes") and confirm or refute each of the 8 items against the real output. Item 1
   (redaction of real secrets) is the highest priority — grep the generated CSVs for anything
   that looks like a live credential.

4. Only after the above: finish Phase 5 from TODO.md. Remaining items are N4 (add risk rules
   for OS currency vs target, hotfix recency, domain/forest functional level, SQL
   edition-vs-core-count licensing, static-IP-referenced-by-DNS), N5 (the scream-test plan
   renders as an unreadable 10-column markdown table — emit a per-function section instead),
   N6 (a -WhatIf/dry-run mode that prints the collection plan and exits), and F21 (two rule
   condition types are implemented but unused, and datasetRowCountAtLeast has a latent bug
   where a missing 'count' key would match an absent dataset).

Rules for this work:
- Keep TODO.md updated after every step. A spend limit ended an earlier session with no
  warning, so anything held only in conversation context gets lost.
- .\tests\Invoke-ToolkitSelfCheck.ps1 and .\tests\Invoke-OutputSmokeTest.ps1 must both stay
  green. Run them after every change.
- The toolkit is strictly read-only against the host. Never add anything that writes outside
  its own output folder.
- Do not report a check as passing if it did not run.
```

---

## 6. State of the work

Read `TODO.md` for the full detail. Summary:

- **Phase 1 (security):** F1 redaction rewrite + N1 corpus test (38 assertions), F13 broken test fixed.
- **Phase 2 (config honesty):** F3 numeric/string config resolution, F4 ~30 dead keys wired or deleted, F5 `-IncludeRecycleBin` made real, F14 `raw\` docs corrected.
- **Phase 3 (functional gaps):** F2+F18 `-ProjectType` emphasis implemented, F19 fingerprint ordering fixed, F7 rule scope language routed + 18-category coverage, F11 complexity rubric completed.
- **Phase 4 (correctness):** F6, F8, F9, F10, F12, F15, F16, F20, F22, F23, F24 plus 15 dead keys removed from `output-settings.json`.
- **Phase 5 (durability):** `Invoke-AllChecks.ps1` added. **N4, N5, N6 and F21 remain.**

There is no git repository and no CI here, so there is nowhere to hang a pre-commit hook —
`Invoke-AllChecks.ps1` is the substitute. Putting this folder under git would be a genuine
improvement, and would let the self-check run as an actual hook.
