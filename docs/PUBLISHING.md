# Publishing to the PowerShell Gallery

Step-by-step checklist for releasing Discover-WindowsServer. Part 1 and the history reset in Part 2
apply to the **first public release only**. For later releases, skip to [Releasing an update](#releasing-an-update).

Who does each step: **[Claude]** = an assistant session can do it in the repo; **[You]** = needs your
accounts or a decision (GitHub, Gallery API key, the publish itself).

> Two things are permanent on the Gallery: a published version number can never be reused or
> deleted (only *unlisted*), and the module's GUID can never change. Get Part 1 right first.

---

## Part 1 — Finalize the module

### 1. Replace the placeholder GUID **[Claude]** ✅ done 2026-10-05
Real GUID in `Discover-WindowsServer.psd1`. A Pester test fails if the old placeholder ever returns.

### 2. Add a command that runs a scan **[Claude]** ✅ done 2026-10-05
`Invoke-DiscoverWindowsServer` (exported) runs `Discover-WindowsServer.ps1` from the installed
folder. Its parameters are mirrored from that script at runtime, so they can't drift; a Pester
test pins that.

### 3. Move saved branding out of the module folder **[Claude]** ✅ done 2026-10-05
The GUI now saves branding to `%ProgramData%\Discover-WindowsServer\branding\`, so it survives
`Update-Module` and needs no write access to Program Files. `config\` is still read as a fallback,
and the GUI copies old branding over once. `Invoke-FleetDiscovery.ps1` stages it into each target's
copy, and the Ninja wrapper's scratch folder moved to `...\Discover-WindowsServer\ninja\` so its
per-run wipe can't delete branding.

### 4. Ninja wrapper **[You → Claude]** ✅ kept; token now optional
The GitHub token is optional (empty = anonymous download of the public repo). It still has never
run in a real NinjaOne tenant, so test it there before relying on it. **If the public repo's
owner or name differs**, update `$RepoOwner`/`$RepoName` near the top of the script (step 10).

### 5. Version and release notes **[You]**
- `ModuleVersion`: `1.0.0`, or `0.9.0` if you want the first public build to read as a preview.
  (A true prerelease tag is `PrivateData.PSData.Prerelease = 'preview1'`; users then need
  `-AllowPrerelease` to install it.)
- `PrivateData.PSData.ReleaseNotes`: a short summary. The Gallery page shows this.
- Optional: `IconUri` (a public https URL to a PNG).

### 6. Static analysis **[Claude]** ✅ done 2026-10-05
The Gallery runs PSScriptAnalyzer on every package and shows its results on the module page.
Re-run it before every release:
```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```
Expect no output. `PSScriptAnalyzerSettings.psd1` lists the style rules excluded on purpose (with
reasons); credential rules stay on, with justified per-function suppressions. Under the Gallery's
own default settings, expect **0 errors** and roughly 500 warnings, all from those documented
design choices (mostly the intentional empty `catch` blocks of the fail-soft design).

### 7. Run the full gate on both runtimes **[Claude]**
```powershell
.\tests\Invoke-AllChecks.ps1                                          # PowerShell 7
powershell.exe -NoProfile -File .\tests\Invoke-AllChecks.ps1          # Windows PowerShell 5.1
```

### 8. Do a test install and a real scan **[Claude]**
Build the package exactly as in [Part 3, step 14](#14-build-the-staging-folder), publish it to a
throwaway local folder repository, install from it, then run a Fast scan from the installed copy
on a lab server (2012 R2 and 2025 at minimum). Confirm the scan completes, the reports render, and
`tools\Verify-DiscoveryRun.ps1 -Path <run folder>` passes.

---

## Part 2 — Clean history and make the repo public

### 9. Reset the git history **[You decide → Claude prepares → You push]**
The current *files* no longer mention the old company or lab-domain name. **The git history
still does**: 11 older commits contain it in their diffs, 6 are authored with the old work email,
and several commit messages name it. Making the existing repo public exposes all of that.

Recommended: publish a **single fresh commit** to a **new** public repo, and keep the current
private repo as your archive. HISTORY.md already preserves the full narrative. A new repo is safer
than force-pushing over the old one, because GitHub can keep serving old commits by SHA after a
force-push.

Claude can prepare it locally:
```powershell
git checkout --orphan public-main
git add -A
git commit -m "Discover-WindowsServer 1.0.0"
git log --all --format='%ae' public-main | Sort-Object -Unique   # should list only your current address
git grep -i -I "<old company name>" public-main                    # should print nothing
```

### 10. Create the public repo and push **[You]**
1. On GitHub: **New repository** → name it (e.g. `Discover-WindowsServer`) → **Public** → no README,
   license or .gitignore (the repo already has them).
2. If the name or owner differs from `ghostinator/Discover-WindowsServer`, have Claude update
   `ProjectUri` and `LicenseUri` in the manifest first. The Gallery page links to them.
3. Push from your own terminal. Git Credential Manager is installed on the lab DC, so `git push`
   opens a browser sign-in and no token is needed:
   ```powershell
   git remote add public https://github.com/<you>/Discover-WindowsServer.git
   git push public public-main:main
   ```
   *If you'd rather Claude push:* create a fine-grained token (GitHub → Settings → Developer
   settings → Personal access tokens → **Fine-grained** → *Only select repositories*: the new repo →
   *Repository permissions*: **Contents: Read and write** → expiry 7 days). Paste it into the
   session when asked. Claude doesn't keep tokens between sessions.
4. Open the repo in a private browser window and confirm the README, LICENSE, and that
   **Commits** shows the one commit.

### 11. Archive the old private repo **[You]**
GitHub → old repo → Settings → **Archive this repository**. Keep it private.

---

## Part 3 — Publish to the Gallery

### 12. Gallery account **[You]**
Sign in at <https://www.powershellgallery.com> with the Microsoft account you want listed as the
owner. Use a personal one if you don't want a company account attached to the listing.

### 13. API key **[You]**
powershellgallery.com → your name → **API Keys** → **Create**:
- Key name: `Discover-WindowsServer publish`
- Expires in: 365 days (or shorter)
- Select scopes: **Push** → *Push new packages and package versions*
- Glob pattern: `Discover-WindowsServer`

Copy it into your password manager. **Don't paste it into a chat session or commit it.** You'll
type it in step 16 yourself.

### 14. Build the staging folder
Publish uploads **every file in the folder** you point it at; `FileList` does not filter. So build a
folder that contains only the manifest's `FileList`. That excludes HANDOFF.md, TODO.md, tests\, docs\,
local branding and any stray run output.
```powershell
$repo  = 'C:\Users\Administrator\Desktop\Discover-WindowsServer-main'
$stage = Join-Path $env:TEMP 'psgallery-stage\Discover-WindowsServer'
Remove-Item (Split-Path $stage) -Recurse -Force -ErrorAction SilentlyContinue
$manifest = Import-PowerShellDataFile (Join-Path $repo 'Discover-WindowsServer.psd1')
foreach ($f in $manifest.FileList) {
    $dest = Join-Path $stage $f
    New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repo $f) -Destination $dest
}
Test-ModuleManifest (Join-Path $stage 'Discover-WindowsServer.psd1')
(Get-ChildItem $stage -Recurse -File).Count          # ~97 files at the time of writing
Get-ChildItem $stage -Recurse -File | Select-String -Pattern '<old company name>' -List   # must print nothing
```
(Tested 2026-10-05: 97 files, no HANDOFF/tests/branding.) Note that `FileList` includes
HISTORY.md, the full development log. Remove it from `FileList` if you'd rather not ship it.

### 15. Dry run **[You]**
```powershell
$key = Read-Host 'PSGallery API key'
Publish-PSResource -Path $stage -Repository PSGallery -ApiKey $key -WhatIf
```

### 16. Publish **[You]**
```powershell
Publish-PSResource -Path $stage -Repository PSGallery -ApiKey $key
Remove-Variable key
```
The Gallery validates and indexes it. It usually appears within a few minutes; the
PSScriptAnalyzer results can take longer.

### 17. Verify from a clean machine **[You or Claude]**
On a lab server that has never had the toolkit (e.g. LABSRV19):
```powershell
Find-PSResource Discover-WindowsServer -Repository PSGallery
Install-PSResource Discover-WindowsServer -Repository PSGallery -Scope AllUsers -TrustRepository
Import-Module Discover-WindowsServer
Get-Command -Module Discover-WindowsServer
Invoke-DiscoverWindowsServer -Mode Fast
```
On Windows PowerShell 5.1 machines without PSResourceGet, `Install-Module Discover-WindowsServer`
does the same.

### 18. Tag the release **[You or Claude]**
```powershell
git tag v1.0.0
git push public v1.0.0
```
Optionally create a GitHub Release from the tag, and paste in the release notes.

---

## Releasing an update
1. Bump `ModuleVersion` in `Discover-WindowsServer.psd1` (a version can only be published once).
2. Update `ReleaseNotes`; add a HISTORY.md entry.
3. If files were added or removed, update `FileList`. A Pester test fails if a listed file is
   missing, but nothing catches a **new** file left off the list. It would just be silently absent
   from the package.
4. Run step 7 (both runtimes) and step 8 (test install + real scan).
5. Steps 14 → 16 with the same API key (or a new one if it expired), then step 18 with the new tag.

To pull a bad version: powershellgallery.com → the package → **Manage** → **Unlist**. Unlisted
versions stay installable by exact version, so publish a fixed version as well.
