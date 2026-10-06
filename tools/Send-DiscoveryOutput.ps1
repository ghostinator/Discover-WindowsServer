<#
.SYNOPSIS
    Sends or uploads a Discover-WindowsServer output archive (the zip under archive\,
    or any file you point it at) somewhere the requester can get it - email or an HTTPS upload.

.DESCRIPTION
    Deliberately separate from the discovery engine itself: Discover-WindowsServer.ps1 stays
    strictly read-only and writes only inside its own output folder (see the repo's safety
    contract in README.md). This script is an explicit, opt-in step you run AFTER a discovery
    completes, only when you choose to. It never runs on its own and the core engine never
    calls it.

    Four delivery methods, each a peer with its own native API (not one generic SMTP path
    wearing different names) - request schemas verified against each provider's own docs:
      Smtp      Any standard SMTP server (host/port/credential/TLS) via System.Net.Mail.
      Smtp2Go   SMTP2GO's HTTP API (api.smtp2go.com/v3/email/send).
      SendGrid  SendGrid's HTTP v3 Mail Send API (api.sendgrid.com/v3/mail/send).
      Postal    A self-hosted Postal server's HTTP API (<your-host>/api/v1/send/message) -
                "Custom Postal Server" because, unlike the other two, you supply the host.
      Upload    A plain HTTPS PUT (or POST) of the file to any URL you provide - e.g. a
                pre-signed S3/Azure Blob upload URL, or an internal file-drop endpoint.

    Credentials (SMTP password, or the API key for Smtp2Go/SendGrid/Postal) are never written
    into the discovery output and never appear in this repo. Resolution order per call:
      1. An explicit -Credential you pass in that run.
      2. A previously saved credential (DPAPI-encrypted via Export-Clixml, under
         %APPDATA%\Discover-WindowsServer\credentials\ - decryptable only by the same Windows
         user on the same machine; useless if copied elsewhere).
      3. An interactive prompt (Get-Credential) - offered to be saved with -SaveCredential,
         never persisted otherwise.
    For the three API-key providers, the "credential" is a PSCredential whose password field
    holds the key (username is ignored) - one storage mechanism for all four methods.

.PARAMETER ZipPath
    The file to send - normally the .zip under <output folder>\archive\ (Discover-WindowsServer_<host>_<stamp>.zip).

.PARAMETER Method
    Smtp, Smtp2Go, SendGrid, Postal, or Upload.

.PARAMETER CredentialName
    Logical name the credential is stored/retrieved under (e.g. 'SendGrid', 'ClientSmtp').
    Required for Smtp/Smtp2Go/SendGrid/Postal unless -Credential is supplied inline.

.EXAMPLE
    .\tools\Send-DiscoveryOutput.ps1 -ZipPath C:\Temp\...\archive\Discover-WindowsServer_SRV01_20260101_120000.zip -Method SendGrid `
        -CredentialName SendGrid -From reports@msp.com -To client@customer.com -SaveCredential
.EXAMPLE
    .\tools\Send-DiscoveryOutput.ps1 -ZipPath C:\Temp\...\archive\Discover-WindowsServer_SRV01_20260101_120000.zip -Method Upload `
        -UploadUrl 'https://storage.example.com/dropbox/run.zip?sig=...'
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialName', Justification = 'a credential-store key name, not a secret')]
param(
    [string]$ZipPath,
    [ValidateSet('Smtp', 'Smtp2Go', 'SendGrid', 'Postal', 'Upload')]
    [string]$Method,

    # Email - common
    [string]$From,
    [string[]]$To,
    [string]$Subject = 'Discover-WindowsServer output',
    [string]$Body = 'Discovery output is attached.',

    # Smtp (generic)
    [string]$SmtpServer,
    [int]$SmtpPort = 587,
    [bool]$UseSsl = $true,

    # Postal only: your self-hosted server's base URL, e.g. https://postal.example.com
    [string]$PostalServerUrl,

    # Upload
    [string]$UploadUrl,
    [ValidateSet('Put', 'Post')]
    [string]$UploadMethod = 'Put',

    # Credential resolution (see .DESCRIPTION)
    [string]$CredentialName,
    [pscredential]$Credential,
    [switch]$SaveCredential,

    [int]$MaxAttachmentSizeMB = 20
)

$ErrorActionPreference = 'Stop'

#region Credential storage (DPAPI via Export-Clixml; see .DESCRIPTION) --------

function Get-DiscoveryCredentialStorePath {
    <#
        Where a named credential lives on disk, encrypted. Creates the folder if needed.
        -BaseDirectory defaults to the real per-user store; tests override it to a disposable
        directory so they never touch this machine's actual %APPDATA%.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$BaseDirectory = (Join-Path $env:APPDATA 'Discover-WindowsServer\credentials')
    )
    if (-not (Test-Path -LiteralPath $BaseDirectory)) { New-Item -ItemType Directory -Path $BaseDirectory -Force | Out-Null }
    $safeName = ($Name -replace '[^\w.-]', '_')
    Join-Path $BaseDirectory ("{0}.credential.xml" -f $safeName)
}

function Get-StoredDeliveryCredential {
    <# Returns the stored PSCredential for $Name, or $null if none is saved. #>
    param([Parameter(Mandatory)][string]$Name, [string]$BaseDirectory)
    $path = if ($BaseDirectory) { Get-DiscoveryCredentialStorePath -Name $Name -BaseDirectory $BaseDirectory } else { Get-DiscoveryCredentialStorePath -Name $Name }
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Import-Clixml -LiteralPath $path) } catch { return $null }
}

function Save-DeliveryCredential {
    <# Persists a credential DPAPI-encrypted, readable only by this user on this machine. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][pscredential]$Credential, [string]$BaseDirectory)
    $path = if ($BaseDirectory) { Get-DiscoveryCredentialStorePath -Name $Name -BaseDirectory $BaseDirectory } else { Get-DiscoveryCredentialStorePath -Name $Name }
    $Credential | Export-Clixml -LiteralPath $path -Force
}

function Remove-DeliveryCredential {
    param([Parameter(Mandatory)][string]$Name, [string]$BaseDirectory)
    $path = if ($BaseDirectory) { Get-DiscoveryCredentialStorePath -Name $Name -BaseDirectory $BaseDirectory } else { Get-DiscoveryCredentialStorePath -Name $Name }
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}

function Get-OrPromptDeliveryCredential {
    <#
        Resolution order: explicit -Credential, then the DPAPI store, then an interactive
        prompt. Only ever writes to disk when -SaveCredential is passed.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [pscredential]$Credential,
        [switch]$SaveCredential,
        [string]$PromptUserName = 'ApiKey',
        [string]$PromptMessage,
        [string]$BaseDirectory
    )
    if ($Credential) {
        if ($SaveCredential) { Save-DeliveryCredential -Name $Name -Credential $Credential -BaseDirectory $BaseDirectory }
        return $Credential
    }
    $stored = Get-StoredDeliveryCredential -Name $Name -BaseDirectory $BaseDirectory
    if ($stored) { return $stored }
    if (-not $PromptMessage) { $PromptMessage = "Enter the credential for '$Name' (username is ignored for API-key providers - put the key in the password field)" }
    $cred = Get-Credential -UserName $PromptUserName -Message $PromptMessage
    if (-not $cred) { throw "No credential supplied for '$Name'." }
    if ($SaveCredential) { Save-DeliveryCredential -Name $Name -Credential $cred -BaseDirectory $BaseDirectory }
    return $cred
}

#endregion

#region Shared helpers ---------------------------------------------------------

function Test-DiscoveryAttachmentSize {
    <# Throws a clear error before attempting to email a file too large for the transport. #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxSizeMB = 20)
    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
    $sizeMB = (Get-Item -LiteralPath $Path).Length / 1MB
    if ($sizeMB -gt $MaxSizeMB) {
        throw ("'{0}' is {1:N1} MB, over the {2} MB email limit (-MaxAttachmentSizeMB). Use -Method Upload for a file this size." -f $Path, $sizeMB, $MaxSizeMB)
    }
}

function ConvertTo-Base64File {
    param([Parameter(Mandatory)][string]$Path)
    [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))
}

function Find-DiscoveryRunZip {
    <#
        The run's archive zip, or $null. The engine names it Discover-WindowsServer_<host>_<stamp>.zip
        (New-DemoEngagement and the smoke tests use run.zip), so match any .zip rather than one fixed
        name - a hardcoded 'run.zip' here once meant delivery never found a real run's archive.
    #>
    param([Parameter(Mandatory)][string]$OutputPath)
    $archiveDir = Join-Path $OutputPath 'archive'
    if (-not (Test-Path -LiteralPath $archiveDir)) { return $null }
    $zip = Get-ChildItem -LiteralPath $archiveDir -Filter '*.zip' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($zip) { return $zip.FullName }
    return $null
}

function Enable-DiscoveryTls12 {
    <#
        Windows PowerShell 5.1 on Server 2012 R2/2016 defaults to Ssl3|Tls (confirmed live on
        LABSRV12/LABSRV16), which SendGrid, SMTP2GO, Microsoft 365 SMTP and GitHub all refuse.
        Adds TLS 1.2 without removing anything. SystemDefault (0) is left alone: the OS already
        negotiates 1.2/1.3 there, and OR-ing in Tls12 would pin it to 1.2 and drop TLS 1.3.
    #>
    $current = [int][Net.ServicePointManager]::SecurityProtocol
    if ($current -ne 0 -and -not ($current -band 3072)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]($current -bor 3072)
    }
}

function Assert-DiscoveryHttpsUrl {
    <# Client discovery data (and Postal's API key header) must never travel over plain HTTP. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Url, [Parameter(Mandatory)][string]$Name)
    $parsed = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$parsed) -or $parsed.Scheme -ne 'https') {
        throw ("{0} must be an absolute https:// URL - refusing to send client discovery data over '{1}'." -f $Name, $Url)
    }
}

#endregion

#region Smtp (generic + the base every real SMTP relay, including SMTP2GO's own, can use) -----

function Send-ViaSmtpClient {
    <#
        Thin wrapper around System.Net.Mail so tests can Mock this exact function instead of
        needing to intercept .NET object construction (Pester's Mock only works on commands).
    #>
    param(
        [Parameter(Mandatory)][string]$SmtpServer,
        [int]$Port = 587,
        [bool]$UseSsl = $true,
        [pscredential]$Credential,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string]$Subject = '',
        [string]$Body = '',
        [string]$AttachmentPath
    )
    $client = [System.Net.Mail.SmtpClient]::new($SmtpServer, $Port)
    $msg = [System.Net.Mail.MailMessage]::new()
    $attachment = $null
    try {
        $client.EnableSsl = $UseSsl
        if ($Credential) { $client.Credentials = [System.Net.NetworkCredential]::new($Credential.UserName, $Credential.Password) }
        $msg.From = $From
        foreach ($addr in $To) { $msg.To.Add($addr) }
        $msg.Subject = $Subject
        $msg.Body = $Body
        if ($AttachmentPath) {
            $attachment = [System.Net.Mail.Attachment]::new($AttachmentPath)
            $msg.Attachments.Add($attachment)
        }
        $client.Send($msg)
    } finally {
        if ($attachment) { $attachment.Dispose() }
        $msg.Dispose()
        $client.Dispose()
    }
}

function Send-DiscoveryEmailSmtp {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$SmtpServer,
        [int]$Port = 587,
        [bool]$UseSsl = $true,
        [pscredential]$Credential,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string]$Subject = 'Discover-WindowsServer output',
        [string]$Body = 'Discovery output is attached.',
        [int]$MaxAttachmentSizeMB = 20
    )
    Test-DiscoveryAttachmentSize -Path $ZipPath -MaxSizeMB $MaxAttachmentSizeMB
    Send-ViaSmtpClient -SmtpServer $SmtpServer -Port $Port -UseSsl $UseSsl -Credential $Credential `
        -From $From -To $To -Subject $Subject -Body $Body -AttachmentPath $ZipPath
}

#endregion

#region Smtp2Go (HTTP API - api.smtp2go.com/v3/email/send) --------------------

function Send-DiscoveryEmailSmtp2Go {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][pscredential]$Credential,   # password = API key
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string]$Subject = 'Discover-WindowsServer output',
        [string]$Body = 'Discovery output is attached.',
        [int]$MaxAttachmentSizeMB = 20
    )
    Test-DiscoveryAttachmentSize -Path $ZipPath -MaxSizeMB $MaxAttachmentSizeMB
    $apiKey = $Credential.GetNetworkCredential().Password
    $payload = @{
        sender      = $From
        to          = @($To)
        subject     = $Subject
        text_body   = $Body
        attachments = @(@{
            filename = [System.IO.Path]::GetFileName($ZipPath)
            fileblob = (ConvertTo-Base64File -Path $ZipPath)
            mimetype = 'application/zip'
        })
    }
    Invoke-RestMethod -Method Post -Uri 'https://api.smtp2go.com/v3/email/send' `
        -Headers @{ 'X-Smtp2go-Api-Key' = $apiKey } -ContentType 'application/json' `
        -Body ($payload | ConvertTo-Json -Depth 6)
}

#endregion

#region SendGrid (HTTP v3 Mail Send API - api.sendgrid.com/v3/mail/send) ------

function Send-DiscoveryEmailSendGrid {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][pscredential]$Credential,   # password = API key
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string]$Subject = 'Discover-WindowsServer output',
        [string]$Body = 'Discovery output is attached.',
        [int]$MaxAttachmentSizeMB = 20
    )
    Test-DiscoveryAttachmentSize -Path $ZipPath -MaxSizeMB $MaxAttachmentSizeMB
    $apiKey = $Credential.GetNetworkCredential().Password
    $payload = @{
        personalizations = @(@{ to = @($To | ForEach-Object { @{ email = $_ } }) })
        from             = @{ email = $From }
        subject          = $Subject
        content          = @(@{ type = 'text/plain'; value = $Body })
        attachments      = @(@{
            content     = (ConvertTo-Base64File -Path $ZipPath)
            filename    = [System.IO.Path]::GetFileName($ZipPath)
            type        = 'application/zip'
            disposition = 'attachment'
        })
    }
    Invoke-RestMethod -Method Post -Uri 'https://api.sendgrid.com/v3/mail/send' `
        -Headers @{ Authorization = "Bearer $apiKey" } -ContentType 'application/json' `
        -Body ($payload | ConvertTo-Json -Depth 6)
}

#endregion

#region Postal (self-hosted - <host>/api/v1/send/message) ---------------------

function Send-DiscoveryEmailPostal {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$PostalServerUrl,
        [Parameter(Mandatory)][pscredential]$Credential,   # password = API key
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string]$Subject = 'Discover-WindowsServer output',
        [string]$Body = 'Discovery output is attached.',
        [int]$MaxAttachmentSizeMB = 20
    )
    Test-DiscoveryAttachmentSize -Path $ZipPath -MaxSizeMB $MaxAttachmentSizeMB
    Assert-DiscoveryHttpsUrl -Url $PostalServerUrl -Name 'PostalServerUrl'
    $apiKey = $Credential.GetNetworkCredential().Password
    $uri = ($PostalServerUrl.TrimEnd('/')) + '/api/v1/send/message'
    $payload = @{
        to         = @($To)
        from       = $From
        subject    = $Subject
        plain_body = $Body
        attachments = @(@{
            name         = [System.IO.Path]::GetFileName($ZipPath)
            content_type = 'application/zip'
            data         = (ConvertTo-Base64File -Path $ZipPath)
        })
    }
    Invoke-RestMethod -Method Post -Uri $uri `
        -Headers @{ 'X-Server-API-Key' = $apiKey } -ContentType 'application/json' `
        -Body ($payload | ConvertTo-Json -Depth 6)
}

#endregion

#region Upload (plain HTTPS PUT/POST of the raw file to a user-supplied URL) --

function Invoke-DiscoveryUpload {
    <#
        PUT (default) sends the raw file bytes as the body - matches most pre-signed upload
        URLs (S3 presigned PUT, Azure Blob SAS PUT). POST is available for endpoints that
        expect that verb instead. Neither wraps the body in multipart/form-data - a generic
        "upload URL" is far more often a direct-PUT target than a browser-style form post.
    #>
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$UploadUrl,
        [ValidateSet('Put', 'Post')][string]$UploadMethod = 'Put'
    )
    if (-not (Test-Path -LiteralPath $ZipPath)) { throw "File not found: $ZipPath" }
    Assert-DiscoveryHttpsUrl -Url $UploadUrl -Name 'UploadUrl'
    Invoke-WebRequest -Method $UploadMethod -Uri $UploadUrl -InFile $ZipPath -ContentType 'application/zip' -UseBasicParsing
}

#endregion

#region Dispatcher --------------------------------------------------------------

function Invoke-DiscoveryDelivery {
    <# Routes to the right sender based on -Method, resolving credentials as needed. #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialName', Justification = 'a credential-store key name, not a secret')]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][ValidateSet('Smtp', 'Smtp2Go', 'SendGrid', 'Postal', 'Upload')][string]$Method,
        [string]$From, [string[]]$To, [string]$Subject, [string]$Body,
        [string]$SmtpServer, [int]$SmtpPort = 587, [bool]$UseSsl = $true,
        [string]$PostalServerUrl,
        [string]$UploadUrl, [string]$UploadMethod = 'Put',
        [string]$CredentialName, [pscredential]$Credential, [switch]$SaveCredential,
        [int]$MaxAttachmentSizeMB = 20
    )
    # [string] parameters left unbound default to '' in PowerShell, not $null - so an explicit
    # -Credential passed without -CredentialName would otherwise crash Get-OrPromptDeliveryCredential's
    # Mandatory -Name binding on an empty string. Falling back to the method name keeps
    # -CredentialName truly optional (matching every -Credential-only test/usage) while still
    # giving each method its own stable store bucket when nothing more specific is given.
    $effectiveCredentialName = if ($CredentialName) { $CredentialName } else { $Method }
    Enable-DiscoveryTls12

    switch ($Method) {
        'Upload' {
            return Invoke-DiscoveryUpload -ZipPath $ZipPath -UploadUrl $UploadUrl -UploadMethod $UploadMethod
        }
        'Smtp' {
            $cred = $null
            if ($Credential -or $CredentialName) {
                $cred = Get-OrPromptDeliveryCredential -Name $effectiveCredentialName -Credential $Credential -SaveCredential:$SaveCredential -PromptUserName 'smtp-user'
            }
            return Send-DiscoveryEmailSmtp -ZipPath $ZipPath -SmtpServer $SmtpServer -Port $SmtpPort -UseSsl $UseSsl `
                -Credential $cred -From $From -To $To -Subject $Subject -Body $Body -MaxAttachmentSizeMB $MaxAttachmentSizeMB
        }
        'Smtp2Go' {
            $cred = Get-OrPromptDeliveryCredential -Name $effectiveCredentialName -Credential $Credential -SaveCredential:$SaveCredential -PromptUserName 'ApiKey'
            return Send-DiscoveryEmailSmtp2Go -ZipPath $ZipPath -Credential $cred -From $From -To $To -Subject $Subject -Body $Body -MaxAttachmentSizeMB $MaxAttachmentSizeMB
        }
        'SendGrid' {
            $cred = Get-OrPromptDeliveryCredential -Name $effectiveCredentialName -Credential $Credential -SaveCredential:$SaveCredential -PromptUserName 'ApiKey'
            return Send-DiscoveryEmailSendGrid -ZipPath $ZipPath -Credential $cred -From $From -To $To -Subject $Subject -Body $Body -MaxAttachmentSizeMB $MaxAttachmentSizeMB
        }
        'Postal' {
            $cred = Get-OrPromptDeliveryCredential -Name $effectiveCredentialName -Credential $Credential -SaveCredential:$SaveCredential -PromptUserName 'ApiKey'
            return Send-DiscoveryEmailPostal -ZipPath $ZipPath -PostalServerUrl $PostalServerUrl -Credential $cred -From $From -To $To -Subject $Subject -Body $Body -MaxAttachmentSizeMB $MaxAttachmentSizeMB
        }
    }
}

#endregion

# Only runs when the script is executed directly (.\Send-DiscoveryOutput.ps1 ... or
# pwsh -File ...) - not when dot-sourced (as Pester tests do, to reach the functions above
# without sending anything).
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $ZipPath -or -not $Method) {
        throw 'Both -ZipPath and -Method are required when running this script directly.'
    }
    Invoke-DiscoveryDelivery -ZipPath $ZipPath -Method $Method -From $From -To $To -Subject $Subject -Body $Body `
        -SmtpServer $SmtpServer -SmtpPort $SmtpPort -UseSsl $UseSsl -PostalServerUrl $PostalServerUrl `
        -UploadUrl $UploadUrl -UploadMethod $UploadMethod `
        -CredentialName $CredentialName -Credential $Credential -SaveCredential:$SaveCredential `
        -MaxAttachmentSizeMB $MaxAttachmentSizeMB
}
