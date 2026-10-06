<#
.SYNOPSIS
    Runs every check for the toolkit and returns a single pass/fail. Run this before sharing
    the toolkit or handing it to an engineer.

.DESCRIPTION
    There is no git repository or CI pipeline behind this project, so there is nowhere to hang
    a pre-commit hook. This script is the substitute: one command, one exit code.

      1. Invoke-ToolkitSelfCheck.ps1  - static contract checks (fast, no side effects)
      2. Invoke-OutputSmokeTest.ps1   - runs the real synthesis + output chain on synthetic data
      3. Invoke-DemoEngagementSmokeTest.ps1 - runs tools\New-DemoEngagement.ps1 end to end
      4. Pester suite                 - unit tests, if Pester 5.x is installed

    Exit code 0 = everything that could run, passed. Non-zero = something failed.

    All four are read-only with respect to the host: the self-check only parses files, and the
    smoke tests write to a temp folder they remove afterwards. None of them collect anything
    from the machine.

.PARAMETER SkipPester
    Skip the Pester suite even if Pester is installed.

.PARAMETER ProjectType
    Project type for the smoke test run. Defaults to Decommission, which exercises the
    project-type emphasis path; GeneralDiscovery exercises the no-lens path.

.EXAMPLE
    .\tests\Invoke-AllChecks.ps1
.EXAMPLE
    .\tests\Invoke-AllChecks.ps1 -ProjectType CMMCReadiness
#>
[CmdletBinding()]
param(
    [switch]$SkipPester,
    [ValidateSet('GeneralDiscovery','ServerRefresh','HyperVRefresh','Decommission','AzureMigration','AppMigration','CMMCReadiness')]
    [string]$ProjectType = 'Decommission'
)

$ErrorActionPreference = 'Continue'
$here    = $PSScriptRoot
$results = [System.Collections.Generic.List[object]]::new()

function Write-Banner { param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Text) -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
}

# ---- 1. Static self-check --------------------------------------------------
Write-Banner 'Static contract self-check'
& (Join-Path $here 'Invoke-ToolkitSelfCheck.ps1') -Quiet
$results.Add([pscustomobject]@{ Name='Self-check'; Ok=($LASTEXITCODE -eq 0); Ran=$true; Note='' })

# ---- 2. Output smoke test --------------------------------------------------
Write-Banner ("Output smoke test (-ProjectType {0})" -f $ProjectType)
& (Join-Path $here 'Invoke-OutputSmokeTest.ps1') -ProjectType $ProjectType | Select-Object -Last 1 | Out-Host
$results.Add([pscustomobject]@{ Name='Output smoke test'; Ok=($LASTEXITCODE -eq 0); Ran=$true; Note='' })

# ---- 3. Demo engagement smoke test -----------------------------------------
Write-Banner 'Demo engagement smoke test'
& (Join-Path $here 'Invoke-DemoEngagementSmokeTest.ps1') | Select-Object -Last 1 | Out-Host
$results.Add([pscustomobject]@{ Name='Demo engagement'; Ok=($LASTEXITCODE -eq 0); Ran=$true; Note='' })

# ---- 4. Pester -------------------------------------------------------------
Write-Banner 'Pester suite'
if ($SkipPester) {
    Write-Host '  Skipped (-SkipPester).' -ForegroundColor Yellow
    $results.Add([pscustomobject]@{ Name='Pester suite'; Ok=$true; Note='skipped by request' })
} else {
    $pester = @(Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version.Major -ge 5 })
    if ($pester.Count -eq 0) {
        Write-Host '  Pester 5.x is not installed - the unit tests could not run.' -ForegroundColor Yellow
        Write-Host '  Install with: Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0' -ForegroundColor Yellow
        Write-Host '  NOTE: the other two checks above still ran. This is a gap in coverage, not a pass.' -ForegroundColor Yellow
        $results.Add([pscustomobject]@{ Name='Pester suite'; Ok=$true; Ran=$false; Note='Pester 5.x not installed' })
    } else {
        Import-Module Pester -MinimumVersion 5.0.0 -Force
        $cfg = New-PesterConfiguration
        $cfg.Run.Path = (Join-Path $here 'Pester')
        $cfg.Run.PassThru = $true
        $cfg.Output.Verbosity = 'Normal'
        $r = Invoke-Pester -Configuration $cfg
        $note = ("{0} passed, {1} failed, {2} skipped" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount)
        $results.Add([pscustomobject]@{ Name='Pester suite'; Ok=($r.FailedCount -eq 0); Ran=$true; Note=$note })
    }
}

# ---- Summary ---------------------------------------------------------------
Write-Banner 'Summary'
$failed = 0; $notRun = 0
foreach ($r in $results) {
    # A check that did not run is reported as NOT RUN, never as PASS - otherwise a missing
    # Pester install reads as a green build.
    if (-not $r.Ran)      { $tag = 'NOT RUN'; $col = 'Yellow'; $notRun++ }
    elseif ($r.Ok)        { $tag = 'PASS';    $col = 'Green' }
    else                  { $tag = 'FAIL';    $col = 'Red';    $failed++ }
    Write-Host ("  [{0,-7}] {1,-22} {2}" -f $tag, $r.Name, $r.Note) -ForegroundColor $col
}
Write-Host ''
if ($failed -gt 0) {
    Write-Host ("{0} CHECK(S) FAILED" -f $failed) -ForegroundColor Red
    exit 1
}
if ($notRun -gt 0) {
    Write-Host ("CHECKS PASSED, BUT {0} DID NOT RUN - coverage is incomplete." -f $notRun) -ForegroundColor Yellow
    exit 0
}
Write-Host 'ALL CHECKS PASSED' -ForegroundColor Green
exit 0
