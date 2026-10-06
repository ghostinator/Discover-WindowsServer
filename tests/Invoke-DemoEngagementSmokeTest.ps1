<#
.SYNOPSIS
    Smoke test for tools\New-DemoEngagement.ps1 - actually runs it (single persona, for speed)
    and asserts the expected run folder and its key report artifacts exist and are non-trivial.

.DESCRIPTION
    Running the real generator end-to-end IS the test, same principle as
    Invoke-OutputSmokeTest.ps1 proving the output pipeline by executing it rather than mocking
    it. Output goes to a temp folder removed afterwards unless -KeepOutput is passed.

.EXAMPLE
    .\tests\Invoke-DemoEngagementSmokeTest.ps1
#>
[CmdletBinding()]
param([switch]$KeepOutput)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
function Assert-That { param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host ("  [ ok ] {0}" -f $Name) -ForegroundColor DarkGray }
    else { Write-Host ("  [FAIL] {0}" -f $Name) -ForegroundColor Red; if ($Detail) { Write-Host ("         {0}" -f $Detail) -ForegroundColor Red }; $script:fail++ }
}

$out = Join-Path ([System.IO.Path]::GetTempPath()) ("dws-demo-smoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))

& (Join-Path $root 'tools\New-DemoEngagement.ps1') -OutputFolder $out -Personas 'AgingNearEol' | Out-Host

$runFolders = @(Get-ChildItem -LiteralPath $out -Directory -Filter 'Discover-WindowsServer_*' -Recurse -ErrorAction SilentlyContinue)
Assert-That -Name ("exactly one run folder was created ({0} found)" -f $runFolders.Count) -Ok ($runFolders.Count -eq 1)

if ($runFolders.Count -ge 1) {
    $runDir = $runFolders[0].FullName
    $htmlPath = Join-Path $runDir 'reports\internal-engineering-report.html'
    $clientPath = Join-Path $runDir 'reports\client-discovery-report.html'
    $zipPath = Join-Path $runDir 'archive\run.zip'

    Assert-That -Name 'internal-engineering-report.html exists and is non-trivial' -Ok ((Test-Path -LiteralPath $htmlPath) -and (Get-Item -LiteralPath $htmlPath).Length -gt 1000)
    Assert-That -Name 'client-discovery-report.html exists and is non-trivial' -Ok ((Test-Path -LiteralPath $clientPath) -and (Get-Item -LiteralPath $clientPath).Length -gt 500)
    Assert-That -Name 'archive\run.zip exists and is non-trivial' -Ok ((Test-Path -LiteralPath $zipPath) -and (Get-Item -LiteralPath $zipPath).Length -gt 1000)

    if (Test-Path -LiteralPath $htmlPath) {
        $html = Get-Content -LiteralPath $htmlPath -Raw
        Assert-That -Name 'report shows a readiness score (this persona is tuned to score low)' -Ok ($html -match 'Readiness \(')
        Assert-That -Name 'report renders at least one finding' -Ok ($html -match 'class="card')
    }
}

if ($KeepOutput) { Write-Host ''; Write-Host ("Output kept at: {0}" -f $out) -ForegroundColor Yellow }
else { try { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue } catch { } }

Write-Host ''
if ($fail -eq 0) { Write-Host 'DEMO ENGAGEMENT SMOKE TEST PASSED' -ForegroundColor Green; exit 0 }
Write-Host ("DEMO ENGAGEMENT SMOKE TEST FAILED - {0} assertion(s)" -f $fail) -ForegroundColor Red; exit 1
