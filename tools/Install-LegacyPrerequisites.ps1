#Requires -Version 3.0
<#
.SYNOPSIS
    Gets a Windows Server 2012 R2 machine (PowerShell 4.0) ready to run Discover-WindowsServer, with
    consent before every change and NEVER a restart.

.DESCRIPTION
    Discover-WindowsServer needs PowerShell 5.1 or 7. Windows Server 2012 R2 ships PowerShell 4.0.
    This script installs PowerShell 7 (side by side; it does not replace Windows PowerShell) plus the
    Universal C Runtime update PowerShell 7 needs on 2012 R2 (KB2999226), if that is missing.

    Guarantees, because this is meant for client servers:
      * It shows a plan first (what, why, source, size, whether a restart may be needed).
      * It asks "Install <item>? [y/N]" for EACH item. Nothing is installed without an explicit yes.
        -Yes answers the questions in advance for unattended use; it still cannot restart anything.
      * It NEVER restarts the machine. Installers run with /norestart. If Windows reports that a
        restart is pending, the script says so and stops there; you choose when to restart.
      * Every downloaded file must carry a valid Microsoft Authenticode signature or it is refused.
      * -PlanOnly changes nothing at all.

    Offline / no-internet servers: stage the two files on a share or USB and pass -SourceFolder.
    The signature check applies to staged files too.

    Written for PowerShell 3/4 syntax so that it can run on the machine it is preparing.

.PARAMETER SourceFolder
    Folder holding pre-downloaded installers (PowerShell-<version>-win-x64.msi,
    Windows8.1-KB2999226-x64.msu). Files found here are used instead of downloading.
.PARAMETER DownloadFolder
    Where downloads and the log are kept. Default: %TEMP%\dws-prereq.
.PARAMETER PowerShellVersion
    PowerShell 7 release to install. Default 7.4.20 (LTS; runs on 2012 R2).
.PARAMETER PlanOnly
    Show what would be done and exit. Makes no change.
.PARAMETER Yes
    Pre-approve every install in the plan (unattended). Does not allow restarts.

.EXAMPLE
    .\Install-LegacyPrerequisites.ps1 -PlanOnly
.EXAMPLE
    .\Install-LegacyPrerequisites.ps1
.EXAMPLE
    .\Install-LegacyPrerequisites.ps1 -SourceFolder \\fileserver\stage -Yes
#>
[CmdletBinding()]
param(
    [string]$SourceFolder,
    [string]$DownloadFolder = (Join-Path $env:TEMP 'dws-prereq'),
    [string]$PowerShellVersion = '7.4.20',
    [switch]$PlanOnly,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$script:LogFile = $null
function Say([string]$m, [string]$color = 'Gray') { Write-Host $m -ForegroundColor $color; if ($script:LogFile) { try { Add-Content -Path $script:LogFile -Value ("{0}  {1}" -f (Get-Date -Format s), $m) } catch { } } }

# ---- 1. What is this machine? -------------------------------------------------
$os   = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
$psv  = $PSVersionTable.PSVersion
$is64 = [Environment]::Is64BitOperatingSystem
$kernel = (Get-Item (Join-Path $env:windir 'System32\ntoskrnl.exe')).VersionInfo
$kernelRev = 0; try { $kernelRev = [int]($kernel.FileVersion -replace '^\d+\.\d+\.\d+\.(\d+).*', '$1') } catch { }
$ucrtPath = Join-Path $env:windir 'System32\ucrtbase.dll'
$hasUcrt  = Test-Path $ucrtPath
$pwsh     = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
$hasPwsh7 = Test-Path $pwsh
$pending  = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

if (-not (Test-Path $DownloadFolder)) { if (-not $PlanOnly) { New-Item -ItemType Directory -Path $DownloadFolder -Force | Out-Null } }
if (-not $PlanOnly) { $script:LogFile = Join-Path $DownloadFolder 'install.log' }

Say ''
Say '=== Discover-WindowsServer: prerequisite check ===' Cyan
Say ("Computer : {0}" -f $env:COMPUTERNAME)
Say ("OS       : {0}  (build {1}, {2})" -f $os.Caption, $build, $(if ($is64) { '64-bit' } else { '32-bit' }))
Say ("PowerShell: {0}   PowerShell 7 installed: {1}   Universal C Runtime: {2}" -f $psv, $hasPwsh7, $hasUcrt)
Say ''

if ($psv.Major -ge 5 -and ($psv.Major -gt 5 -or $psv.Minor -ge 1)) {
    Say 'This machine already runs PowerShell 5.1 or newer. Nothing to install.' Green
    Say ("Run:  powershell -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 -Mode Fast") Green
    return
}
if ($hasPwsh7) {
    Say 'PowerShell 7 is already installed. Nothing to install.' Green
    Say ("Run:  & '{0}' -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 -Mode Fast" -f $pwsh) Green
    return
}
if (-not $is64) { Say 'Refusing: PowerShell 7 needs a 64-bit Windows. Nothing was changed.' Red; return }
if ($build -lt 9200) { Say ('Refusing: Windows build {0} is older than Windows Server 2012. Nothing was changed.' -f $build) Red; return }

# ---- 2. What is missing? ------------------------------------------------------
$msiName = "PowerShell-$PowerShellVersion-win-x64.msi"
$msuName = 'Windows8.1-KB2999226-x64.msu'
$items = @()
if (-not $hasUcrt) {
    if ($build -eq 9600 -and $kernelRev -lt 17031) {
        Say 'The Universal C Runtime update (KB2999226) needs the April 2014 update (KB2919355) first, and this machine does not have it.' Yellow
        Say 'Install KB2919355 via Windows Update or your patch tool (it is a large, restart-requiring update, so this script will not do it), then run this script again. Nothing was changed.' Yellow
        return
    }
    $items += New-Object psobject -Property @{
        Key='ucrt'; Name='Universal C Runtime update (KB2999226)'; File=$msuName; Size='about 1 MB'
        Url='https://download.microsoft.com/download/D/1/3/D13E3150-3BB2-4B22-9D8A-47EE2D609FFF/Windows8.1-KB2999226-x64.msu'
        Why='PowerShell 7 cannot start on 2012 R2 without it.'; Restart='May ask for a restart. This script will NOT restart; you decide when.' }
}
$items += New-Object psobject -Property @{
    Key='pwsh'; Name=("PowerShell $PowerShellVersion (side by side, Windows PowerShell is untouched)"); File=$msiName; Size='about 105 MB'
    Url=("https://github.com/PowerShell/PowerShell/releases/download/v{0}/{1}" -f $PowerShellVersion, $msiName)
    Why='Discover-WindowsServer needs PowerShell 5.1 or 7; this machine has 4.0.'; Restart='No restart needed. Microsoft Update opt-in and remoting are left off.' }

Say 'Plan (nothing has been changed yet):' Cyan
$n = 0
foreach ($it in $items) {
    $n++
    $src = 'download from ' + $it.Url
    if ($SourceFolder -and (Test-Path (Join-Path $SourceFolder $it.File))) { $src = 'use staged file ' + (Join-Path $SourceFolder $it.File) }
    Say ("  {0}. {1}" -f $n, $it.Name)
    Say ("     why     : {0}" -f $it.Why)
    Say ("     source  : {0}   ({1})" -f $src, $it.Size)
    Say ("     restart : {0}" -f $it.Restart)
}
if ($pending) { Say 'NOTE: Windows already has a restart pending from earlier changes. This script will not restart the machine.' Yellow }
Say ''
if ($PlanOnly) { Say '-PlanOnly: stopping here. No changes were made.' Green; return }

# ---- 3. Helpers ---------------------------------------------------------------
function Confirm-Item($it) {
    if ($Yes) { Say ("Pre-approved (-Yes): {0}" -f $it.Name); return $true }
    try { $a = Read-Host ("Install {0}? [y/N]" -f $it.Name) } catch { Say 'No interactive prompt available and -Yes was not given. Skipping.' Yellow; return $false }
    return ($a -match '^(y|yes)$')
}
function Get-Installer($it) {
    $local = $null
    if ($SourceFolder -and (Test-Path (Join-Path $SourceFolder $it.File))) { $local = Join-Path $SourceFolder $it.File }
    if (-not $local) {
        $local = Join-Path $DownloadFolder $it.File
        if (-not (Test-Path $local)) {
            Say ("Downloading {0} ..." -f $it.Url)
            [Net.ServicePointManager]::SecurityProtocol = 3072    # TLS 1.2; the default on this .NET is older
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $it.Url -OutFile $local -UseBasicParsing
        }
    }
    $sig = Get-AuthenticodeSignature -FilePath $local
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw ("Refusing {0}: signature is '{1}' (signer: {2}). It was not run." -f $local, $sig.Status, $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'none' }))
    }
    Say ("Signature OK: {0} (Microsoft, {1} MB)" -f $it.File, [math]::Round((Get-Item $local).Length / 1MB, 1))
    return $local
}
$script:restartPending = $false
function Read-ExitCode($code, $what) {
    switch ($code) {
        0        { Say ("{0}: installed." -f $what) Green; return $true }
        3010     { Say ("{0}: installed. Windows reports a RESTART IS NEEDED to finish it (not done)." -f $what) Yellow; $script:restartPending = $true; return $true }
        1641     { Say ("{0}: installed. A restart was requested by the installer (suppressed; not done)." -f $what) Yellow; $script:restartPending = $true; return $true }
        2359302  { Say ("{0}: already installed." -f $what) Green; return $true }
        default  { Say ("{0}: installer returned {1}. Not treated as success." -f $what, $code) Red; return $false }
    }
}

# ---- 4. Do it, item by item ---------------------------------------------------
$failed = $false
foreach ($it in $items) {
    if (-not (Confirm-Item $it)) { Say ("Skipped: {0}" -f $it.Name) Yellow; $failed = $true; continue }
    try {
        $file = Get-Installer $it
        if ($it.Key -eq 'ucrt') {
            $p = Start-Process -FilePath 'wusa.exe' -ArgumentList ('"{0}" /quiet /norestart' -f $file) -Wait -PassThru
            if (-not (Read-ExitCode $p.ExitCode $it.Name)) { $failed = $true }
        } else {
            $msiArgs = '/i "{0}" /qn /norestart ADD_PATH=1 ENABLE_PSREMOTING=0 USE_MU=0 ENABLE_MU=0 REGISTER_MANIFEST=1' -f $file
            $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
            if (-not (Read-ExitCode $p.ExitCode $it.Name)) { $failed = $true }
        }
    } catch { Say ("FAILED: {0}: {1}" -f $it.Name, $_.Exception.Message) Red; $failed = $true }
}

# ---- 5. Verify, and say what is left for a human -------------------------------
Say ''
$ok = $false
if (Test-Path $pwsh) {
    try { $v = & $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'; if ($v) { Say ("PowerShell 7 starts and reports version {0}." -f $v) Green; $ok = $true } } catch { }
    if (-not $ok) { Say 'PowerShell 7 is installed but did not start. If a restart is pending (below), restart when convenient and run this script again to re-check.' Yellow }
}
if ($script:restartPending -or $pending) {
    Say 'RESTART PENDING: Windows needs a restart to finish what was installed. This script did NOT restart the machine. Restart at a time that suits you.' Yellow
}
if ($ok) {
    Say ''
    Say 'Ready. Run discovery with:' Cyan
    Say ("  & '{0}' -NoProfile -ExecutionPolicy Bypass -File .\Discover-WindowsServer.ps1 -Mode Fast" -f $pwsh) White
} elseif (-not $failed) {
    Say 'Installed, but PowerShell 7 could not be verified yet (see above).' Yellow
}
if ($failed) { Say 'One or more steps were skipped or failed; see above. Nothing was restarted.' Yellow }
Say ("Log: {0}" -f $script:LogFile)
