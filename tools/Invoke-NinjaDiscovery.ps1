<#
.SYNOPSIS
    NinjaRMM entry point: downloads this toolkit from its GitHub repo, runs a
    discovery scan with the options you pick in the Ninja parameter UI, and optionally
    emails or uploads the result - unattended, in one script deployment.

.DESCRIPTION
    Paste this ONE file into a NinjaOne "Automation" script (PowerShell). Nothing else
    needs to be pre-staged on the endpoint - it downloads the rest of the toolkit itself.
    Run it as SYSTEM (Ninja lets you pick the run-as context); every collector already
    supports that.

    WHY A DOWNLOAD STEP: Discover-WindowsServer.ps1 is not one file - it loads ~30
    module/config files relative to itself. NinjaOne script deployment is built around a
    single script body, so this wrapper's first job is fetching the rest of the toolkit
    (as a repo zip, since git is not reliably present on managed endpoints) before it can
    run it. The extracted copy is wiped and re-fetched on every run, so it's always the
    latest toolkit version - no separate update mechanism to maintain.

    NINJAONE PARAMETER CONSTRAINTS (confirmed against NinjaOne's own docs before writing
    this): script parameters are plain strings only - no booleans, no arrays, and these
    characters are rejected outright: & | ; $ > < \ !
    That breaks two real things this wrapper may need to pass through: a GitHub token (only for
    a private fork), and an upload URL (pre-signed S3/Azure Blob URLs are full of '&'-separated
    query parameters). Both are base64-encoded before being put in the Ninja parameter
    value and decoded here - base64's alphabet (A-Za-z0-9+/=) contains none of Ninja's
    blocked characters, so this sidesteps the restriction entirely rather than hoping a
    given value happens not to collide with it.

    SECURITY NOTE, read before using this in production: whatever you pass through Ninja's
    parameter UI - the repo token, the delivery credential - is visible in plaintext in
    NinjaOne's own Activities/run-history log (base64 is encoding, not encryption; anyone
    who can see the run history can trivially decode it). This was an explicit tradeoff
    the user chose over the alternatives (a secure NinjaOne custom field, or hardcoding the
    secret into this script body instead). Mitigate it:
      - RepoTokenB64: not needed for the public repo - leave it empty. Only for a private
        fork: use a fine-grained, READ-ONLY GitHub PAT scoped to ONLY that one repo, so a
        leak via Ninja's logs means "read this one repo," not more.
      - DeliveryCredentialB64: use a relay-only / least-privilege API key for whichever
        provider you pick (SendGrid/SMTP2GO/Postal all support scoping a key to
        send-only), not an account-wide key.
    If your NinjaOne plan has a secure/masked custom field or credential store, prefer
    that over a plain parameter for both values - swap the two ConvertFrom-NinjaBase64
    calls below for however you read that field instead.

    OUTPUT HANDLING: after a successful delivery, the local output folder is deleted -
    Ninja-managed endpoints are client infrastructure, and this toolkit's whole design
    philosophy is not leaving discovery output sitting around longer than it has to (see
    the repo README's "output is client data" section). If delivery is skipped (-DeliveryMethod
    None) or fails, the output is left in place so nothing is silently lost - check
    $env:ProgramData\Discover-WindowsServer\ninja\output on the endpoint.

.PARAMETER Mode
    Fast, Deep, or Custom (matches Discover-WindowsServer.ps1 -Mode exactly).

.PARAMETER ProjectType
    GeneralDiscovery, ServerRefresh, HyperVRefresh, Decommission, AzureMigration,
    AppMigration, or CMMCReadiness.

.PARAMETER ComplianceLens
    None, CMMC, or GeneralSecurity.

.PARAMETER DeliveryMethod
    None, Smtp2Go, SendGrid, Postal, or Upload. None just leaves the output on the
    endpoint (see OUTPUT HANDLING above).

.PARAMETER DeliveryTargetB64
    Base64-encoded. Meaning depends on -DeliveryMethod:
      Smtp2Go / SendGrid : comma-separated "To" address(es), e.g. "ops@msp.com"
      Postal             : "<server-url>|<to-address>", e.g. "https://postal.msp.com|ops@msp.com"
      Upload             : the destination URL (PUT by default - see tools\Send-DiscoveryOutput.ps1)

.PARAMETER DeliveryCredentialB64
    Base64-encoded API key (Smtp2Go/SendGrid/Postal) - ignored for Upload/None.

.PARAMETER RepoTokenB64
    Optional. Leave empty for the public repo. Only for a private fork: a base64-encoded GitHub
    PAT with read access to it - see the security note above (fine-grained, read-only, one repo).

.PARAMETER FromAddress
    Sender address for the three email delivery methods. Rarely needs to change per run,
    so it defaults to a constant below rather than costing you another Ninja parameter -
    edit $DefaultFromAddress in this file, or override it here if you do want it per-run.

.EXAMPLE
    # As entered in NinjaOne's automation parameter fields (already base64-encoded):
    -Mode Deep -ProjectType Decommission -ComplianceLens None `
      -DeliveryMethod SendGrid -DeliveryTargetB64 b3BzQG1zcC5jb20= `
      -DeliveryCredentialB64 U0cueHh4eHh4 -RepoTokenB64 Z2hwX3h4eHh4
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'DeliveryCredentialB64', Justification = 'NinjaOne script parameters are string-only')]
param(
    [ValidateSet('Fast', 'Deep', 'Custom')]
    [string]$Mode = 'Fast',

    [ValidateSet('GeneralDiscovery', 'ServerRefresh', 'HyperVRefresh', 'Decommission', 'AzureMigration', 'AppMigration', 'CMMCReadiness')]
    [string]$ProjectType = 'GeneralDiscovery',

    [ValidateSet('None', 'CMMC', 'GeneralSecurity')]
    [string]$ComplianceLens = 'None',

    [ValidateSet('None', 'Smtp2Go', 'SendGrid', 'Postal', 'Upload')]
    [string]$DeliveryMethod = 'None',

    [string]$DeliveryTargetB64 = '',
    [string]$DeliveryCredentialB64 = '',
    [string]$RepoTokenB64 = '',
    [string]$FromAddress = ''
)

$ErrorActionPreference = 'Stop'

# Edit this once for your MSP rather than passing -FromAddress on every deployment.
$DefaultFromAddress = 'discoveries@yourmsp.example.com'

# ---- Repo location: edit if you fork/rename this repo -------------------------
$RepoOwner = 'ghostinator'
$RepoName  = 'Discover-WindowsServer'
$RepoBranch = 'main'

function ConvertFrom-NinjaBase64 {
    <# Decodes a base64 Ninja parameter value; '' in, '' out (never errors on empty). #>
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    try { return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value)) }
    catch { throw "Parameter value is not valid base64. Got: $Value" }
}

function Get-PostalTargetParts {
    <#
        Splits a decoded Postal DeliveryTargetB64 ("<server-url>|<to-address>") into its two
        parts. Pure function, separated out so this specific parsing - the one part of this
        wrapper with real logic worth getting wrong - is unit-testable without a network call.
    #>
    param([Parameter(Mandatory)][string]$DecodedTarget)
    $parts = $DecodedTarget -split '\|', 2
    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
        throw "Postal delivery target must decode to '<server-url>|<to-address>'. Got: $DecodedTarget"
    }
    return [pscustomobject]@{ PostalServerUrl = $parts[0]; ToAddress = $parts[1] }
}

function Get-DeliveryInvocationArgs {
    <#
        Pure function: given the (already-decoded) method/target/credential/from, returns the
        hashtable to splat onto Invoke-DiscoveryDelivery. No network/file access - unit
        testable on its own, same reasoning as Discover-WindowsServer-GUI.ps1's
        Build-DiscoveryArgumentList.
    #>
    # NinjaOne script parameters are strings only, so the API key arrives as text; this is
    # where it becomes a PSCredential.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'NinjaOne script parameters are string-only')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'DecodedCredential', Justification = 'NinjaOne script parameters are string-only')]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$DecodedTarget,
        [string]$DecodedCredential,
        [Parameter(Mandatory)][string]$From,
        [string]$Subject = "Discover-WindowsServer output: $env:COMPUTERNAME"
    )
    $deliveryArgs = @{ ZipPath = $ZipPath; Method = $Method }
    switch ($Method) {
        'Upload' {
            $deliveryArgs['UploadUrl'] = $DecodedTarget
        }
        'Postal' {
            $p = Get-PostalTargetParts -DecodedTarget $DecodedTarget
            $deliveryArgs['PostalServerUrl'] = $p.PostalServerUrl
            $deliveryArgs['To'] = @($p.ToAddress)
            $deliveryArgs['From'] = $From
            $deliveryArgs['Subject'] = $Subject
            $deliveryArgs['Credential'] = [pscredential]::new('ApiKey', (ConvertTo-SecureString $DecodedCredential -AsPlainText -Force))
        }
        default {
            # Smtp2Go / SendGrid
            $deliveryArgs['To'] = @($DecodedTarget -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $deliveryArgs['From'] = $From
            $deliveryArgs['Subject'] = $Subject
            $deliveryArgs['Credential'] = [pscredential]::new('ApiKey', (ConvertTo-SecureString $DecodedCredential -AsPlainText -Force))
        }
    }
    return $deliveryArgs
}

# Only runs when executed directly - not when dot-sourced, matching the same convention
# tools\Send-DiscoveryOutput.ps1 and Discover-WindowsServer-GUI.ps1 use, so this file's pure
# functions above are unit-testable without triggering a real download-and-scan.
if ($MyInvocation.InvocationName -ne '.') {

$effectiveFrom = if ($FromAddress) { $FromAddress } else { $DefaultFromAddress }
$repoToken = ConvertFrom-NinjaBase64 $RepoTokenB64
$decodedTarget = ConvertFrom-NinjaBase64 $DeliveryTargetB64
$decodedCredential = ConvertFrom-NinjaBase64 $DeliveryCredentialB64

if ($DeliveryMethod -ne 'None' -and -not $decodedTarget) {
    Write-Host "FATAL: -DeliveryMethod $DeliveryMethod was given but -DeliveryTargetB64 is empty." -ForegroundColor Red
    exit 1
}

# ---- 1. Fetch the toolkit ------------------------------------------------------
# Its own subfolder: it's wiped at the start of every run, and the sibling branding\ folder
# (Core.psm1's Get-DiscoveryBrandingDirectory) must survive that.
$workRoot   = Join-Path $env:ProgramData 'Discover-WindowsServer\ninja'
$toolkitDir = Join-Path $workRoot 'toolkit'
$zipPath    = Join-Path $workRoot 'toolkit.zip'
Write-Host "Downloading $RepoOwner/$RepoName@$RepoBranch ..."
if (Test-Path -LiteralPath $workRoot) { Remove-Item -LiteralPath $workRoot -Recurse -Force }
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
try {
    # GitHub requires TLS 1.2; Windows PowerShell on 2012 R2/2016 defaults to Ssl3|Tls. Same logic
    # as Send-DiscoveryOutput.ps1's Enable-DiscoveryTls12 (not dot-sourced yet - it's in the download).
    $tlsNow = [int][Net.ServicePointManager]::SecurityProtocol
    if ($tlsNow -ne 0 -and -not ($tlsNow -band 3072)) { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]($tlsNow -bor 3072) }
    # The token is only needed for a private repo or fork; the public repo downloads anonymously.
    $headers = @{}
    if ($repoToken) { $headers['Authorization'] = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("x-access-token:$repoToken")) }
    Invoke-WebRequest -Uri "https://github.com/$RepoOwner/$RepoName/archive/refs/heads/$RepoBranch.zip" `
        -Headers $headers -OutFile $zipPath -UseBasicParsing
    Expand-Archive -LiteralPath $zipPath -DestinationPath $workRoot -Force
    # GitHub's archive convention: <RepoName>-<branch>\...
    $extracted = Join-Path $workRoot "$RepoName-$RepoBranch"
    Rename-Item -LiteralPath $extracted -NewName 'toolkit'
} catch {
    Write-Host "FATAL: could not download/extract the toolkit: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ---- 2. Run the scan ------------------------------------------------------------
Write-Host "Running Discover-WindowsServer.ps1 -Mode $Mode -ProjectType $ProjectType ..."
$outputRoot = Join-Path $workRoot 'output'
$engineScript = Join-Path $toolkitDir 'Discover-WindowsServer.ps1'
try {
    $outputPath = & $engineScript -Mode $Mode -ProjectType $ProjectType -ComplianceLens $ComplianceLens -OutputRoot $outputRoot -Quiet
} catch {
    Write-Host "FATAL: discovery run failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "Scan complete: $outputPath"

# ---- 3. Deliver, if configured ---------------------------------------------------
$deliveryOk = $true
if ($DeliveryMethod -ne 'None') {
    . (Join-Path $toolkitDir 'tools\Send-DiscoveryOutput.ps1')
    $zip = Find-DiscoveryRunZip -OutputPath $outputPath
    if (-not $zip) {
        Write-Host "FATAL: no .zip found under $outputPath\archive - nothing to deliver." -ForegroundColor Red
        $deliveryOk = $false
    } else {
        try {
            $deliveryArgs = Get-DeliveryInvocationArgs -ZipPath $zip -Method $DeliveryMethod `
                -DecodedTarget $decodedTarget -DecodedCredential $decodedCredential -From $effectiveFrom
            Invoke-DiscoveryDelivery @deliveryArgs | Out-Null
            Write-Host "Delivered via $DeliveryMethod."
        } catch {
            Write-Host "FATAL: delivery via $DeliveryMethod failed: $($_.Exception.Message)" -ForegroundColor Red
            $deliveryOk = $false
        }
    }
}

# ---- 4. Clean up local output once it's safely delivered ------------------------
if ($DeliveryMethod -ne 'None' -and $deliveryOk) {
    try { Remove-Item -LiteralPath $outputPath -Recurse -Force } catch { }
    Write-Host 'Local output removed after successful delivery.'
} else {
    Write-Host "Local output left in place: $outputPath"
}

if (-not $deliveryOk) { exit 1 }
exit 0

}
