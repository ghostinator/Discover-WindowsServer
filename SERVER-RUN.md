> **Status update (2026-09-21).** The statement below that everything was validated only on a Windows 11
> workstation is out of date. The toolkit has since been run elevated and as SYSTEM on a lab of real servers:
> Windows Server 2025 (workgroup member, then domain controller, Hyper-V host, cluster node),
> 2016, 2019, and 2012 R2 (under PowerShell 7). See `TODO.md` ("Real-server test session") for every
> defect found and fixed, and `HANDOFF.md` for the current state and next steps.
> Windows Server **2012 R2** needs PowerShell 5.1+ or 7: run `tools\Install-LegacyPrerequisites.ps1`
> (asks first, never restarts). The runbook below is kept for its still-valid procedure.

# Running this on a real server — deployment run-book

Everything so far has been validated on a **Windows 11 workstation, not elevated**. That leaves
four code paths that a workstation physically cannot exercise, plus one that has **never executed
anywhere**. This document is what to do on a real server to close that gap.

---

## 0. Do NOT install PowerShell 7

The toolkit targets **Windows PowerShell 5.1**, which ships with every Windows Server 2016+. The
full test gate now passes on both 5.1 and 7, and a side-by-side probe of all 21 collection cmdlets
returned **identical results** on both. Installing PS7 on a production server buys nothing and adds
change-management risk.

Needing nothing installed is one of this toolkit's actual selling points — `docs/README.md` promises
"no PowerShell 7 required; no internet; no Excel". Keep it that way.

If the server already happens to have PS7, either runtime is fine.

---

## 1. Before you start

| Requirement | Why |
|---|---|
| **Run elevated** (Administrator) | Not optional for this exercise. `secedit /export` (user rights), `vssadmin`, BitLocker and several registry/CIM reads all need it. A non-elevated run is what we already have. |
| Windows Server 2016+ | Server SKU is the point — `Get-WindowsFeature` only exists there. |
| ~200 MB free on the output volume | A Deep run with an evidence manifest produced ~30 MB on a workstation; a real file server will be larger. |
| Out-of-hours if it is a busy file server | See the timing warning in section 4. |

### Authorization

Discovery output contains real infrastructure detail — share paths, NTFS ACLs, service accounts,
listening ports, event-log samples, certificate subjects. The toolkit is strictly read-only and
collects no credentials, but the **output is client data**.

Prefer an internal or lab server for this validation. If you use a client production box, make sure
the engagement covers it. And see section 5 — you do **not** need to send the output itself.

---

## 2. Get the code onto the server

Pick whichever is easiest. The repo is private, so a plain `curl` of a zip will not work.

**Option A — copy from this machine (simplest, no auth on the server)**

Run locally, then copy the single zip over RDP or to a share:

```powershell
Compress-Archive -Path 'C:\Users\brandon.cook\OneDrive - San Luis Valley Industries\Development\GitHub\ghostinator\Discover-WindowsServer\*' -DestinationPath "$env:USERPROFILE\Desktop\Discover-WindowsServer.zip" -Force
```

**Option B — clone on the server** (needs git + credentials there)

```powershell
git clone https://github.com/ghostinator/Discover-WindowsServer.git C:\Discovery
```

**Option C — `gh` on the server**

```powershell
gh repo clone ghostinator/Discover-WindowsServer C:\Discovery
```

### Then, if the files arrived via zip or download — unblock them

Windows marks downloaded files, and PowerShell will refuse to load blocked modules. This is
read-only and affects only the extracted copy:

```powershell
Get-ChildItem -Path C:\Discovery -Recurse -File | Unblock-File
```

---

## 3. Launch without changing machine policy

Do **not** run `Set-ExecutionPolicy`. Scope the bypass to the single session instead:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Discovery\Discover-WindowsServer.ps1 -Mode Fast
```

Every command below assumes that pattern. Run them from an **elevated** prompt.

---

## 4. The runs

Do them in this order. Run 1 is a cheap safety check; runs 2 and 3 are the ones I need most.

```powershell
cd C:\Discovery

# 1. Fast baseline - quick, read-only, proves it runs cleanly here first.
powershell -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 `
    -Mode Fast -OutputRoot C:\DiscoveryOut

# 2. THE MAIN RUN - Deep, Decommission lens, with the evidence manifest.
powershell -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 `
    -Mode Deep -ProjectType Decommission -GenerateEvidenceManifest -OutputRoot C:\DiscoveryOut

# 3. Same box, different lens - proves emphasis changes presentation only.
powershell -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 `
    -Mode Deep -ProjectType CMMCReadiness -OutputRoot C:\DiscoveryOut
```

**If the server has real user file shares**, add this fourth run. It is the only way to prove the
recycle-bin exclusion works, by comparing against run 2:

```powershell
# 4. Only if there are user shares. Same as run 2 plus -IncludeRecycleBin.
powershell -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 `
    -Mode Deep -ProjectType Decommission -IncludeRecycleBin -OutputRoot C:\DiscoveryOut
```

**If the server runs SQL Server** and your account has rights, add `-AttemptSqlIntegratedAuth` to
run 2. That exercises the deep SQL enumeration path on top of the registry read.

### Timing warning

Deep mode took ~3–5 minutes on a workstation. On a real server it can take **considerably** longer,
because Deep enables two expensive things:

- the **deep file-share crawl**, which walks share contents to size them, and
- the **config dependency scan**, which reads files under `Program Files` / `ProgramData`.

Both are bounded (file cap 3000, hint cap 5000, `-Depth 8`) and both report in `limitations.txt`
when a cap trips, so it cannot run away. But on a file server with millions of files the share crawl
is real I/O. If that is a concern, either run out of hours or bound it further:

```powershell
# Lighter Deep run: shallower share walk.
... -Mode Deep -ProjectType Decommission -GenerateEvidenceManifest -MaxDepth 2
```

If you need to stop a run, Ctrl-C is safe — nothing outside the output folder is ever written.

---

## 5. What to send back — the report, not the data

You do **not** need to send me the output folders. Run the verifier instead. It reads the output and
emits counts, field-name presence and pass/fail verdicts — **no collected values, no host names, no
share or account names**:

```powershell
cd C:\Discovery

# Point it at the Deep runs. Two runs differing only by -ProjectType enables the
# emphasis comparison. Note the comma - that is a PowerShell array.
.\tools\Verify-DiscoveryRun.ps1 `
    -Path C:\DiscoveryOut\Discover-WindowsServer_<HOST>_<STAMP_run2>, C:\DiscoveryOut\Discover-WindowsServer_<HOST>_<STAMP_run3> `
    -ReportPath C:\DiscoveryOut\verification-report.txt
```

Tab-completion will fill in the folder names. Then **read `verification-report.txt` once** to
satisfy yourself it contains nothing sensitive, and send me its contents.

The one section worth a glance before sharing is *"7. LIMITATIONS REPORTED BY THE RUN"* — those are
toolkit-authored messages, but a module could in principle interpolate a path into one.

If it is a lab box you do not mind sharing wholesale, zipping the run folder is also fine and gives
me strictly more to work with. Your call.

---

## 6. What I will verify from that report

Four things a workstation could not test, plus one that has never run anywhere:

| # | What | Why a server is required |
|---|---|---|
| **NEW** | **`RolesFeatures` via `Get-WindowsFeature`** | That cmdlet is **Server-only**. Every run so far fell back to optional-features/DISM, so the *preferred* enumeration path — the one that yields canonical role names the risk rules key on — **has never executed**. Highest-value item here. |
| 2 | SQL `BinaryPath` → `CriticalPaths` | Needs SQL installed. `SqlInstances` was empty, so the `SQLBinRoot` registry read and the `CriticalPaths` SQL branch are unproven. |
| 3 | Recycle-bin exclusion in the deep share crawl | Needs real user shares. The workstation had only admin shares, so `NtfsAclSummary` was empty and the `RecycleBin*` fields never populated. |
| 5 | Fingerprint matchers keyed on `ListeningPorts` / `IisSites` | Needs SQL or IIS listening. The inputs are now populated (233 rows) but no such matcher has actually fired. |
| 7 | `raw\userrights.inf` | Needs elevation for `secedit /export`. Also confirms it holds only `Se*` privilege assignments and no secrets. |

I will also re-check, on server-shaped data, the defects fixed during validation: that no dataset is
silently empty from a failed cmdlet probe (F33), that risk rules fire for single-row datasets (F29),
and that every `json/` export is a valid array (F32).

---

## 6b. What the output looks like now

The run folder has two top-level folders, not a flat root. See `docs/OUTPUT-GUIDE.md`.

- `reports\internal-engineering-report.html` - the internal report (formerly
  `internal-report.html`). This is the one to read.
- `reports\client-discovery-report.html` - the client deliverable. Built only from
  client-safe datasets, so it is safe to send without a review pass.
- `evidence\` - logs, raw captures, live status, and every dataset as CSV and JSON.

The verifier understands both the new layout and the old one, so run folders produced
before this change still verify unchanged.

Four collectors are also new and have never executed on a server: `WindowsUpdate`,
`UserProfiles`, `TimeSync`, `AzureHybrid`. On a real server, check specifically that
`evidence\data\json\UpdatePosture.json` has a populated `NewestHotfixInstalledOn`, that
`MappedDrives.json` is non-empty if anyone has logged on interactively, and that
`TimeSync.json` shows a domain time source rather than the local CMOS clock.

## 7. If something goes wrong

- **`errors.txt` non-empty** — send me its contents. It should be empty; it was on all four runs so far.
- **A module reports "not available" for a cmdlet you know exists** — that is the F33 defect class.
  The verifier flags this explicitly under section 4.
- **The run appears to hang** — almost certainly the deep share crawl or config scan. Check
  `status\progress.json`, which is updated live. Ctrl-C is safe.
- **A module throws** — the toolkit logs a limitation and continues by design; the run should still
  complete and produce all artifacts.
