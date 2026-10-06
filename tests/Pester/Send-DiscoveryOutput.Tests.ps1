#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Send-DiscoveryOutput.Tests.ps1 - fixture-based tests for tools\Send-DiscoveryOutput.ps1.

    Unlike every collector tested so far, this is a dot-sourced SCRIPT, not an Import-Module
    module - there is no module boundary, so Mock needs no -ModuleName here and none of the
    InModuleScope/native-function gotchas documented in ConfigDependencyScan.Tests.ps1's
    header apply. Dot-sourcing the script (as BeforeAll does) only defines its functions - the
    script's own "only run when invoked directly" guard (`$MyInvocation.InvocationName -ne '.'`)
    is exactly what makes that safe, and every test below is implicit proof it works: nothing
    here ever actually sends an email or performs a real upload.

    Every network call (Send-ViaSmtpClient, Invoke-RestMethod, Invoke-WebRequest) is mocked -
    this suite never contacts a real mail server or API, per the request/upload schemas
    verified against SendGrid/SMTP2GO/Postal's own docs and source when the script was written.

    Credential-store tests point -BaseDirectory at $TestDrive so they never touch this
    machine's real %APPDATA%\Discover-WindowsServer\credentials - the same "don't depend on
    real host state" lesson from AzureHybrid.Tests.ps1's unmocked-registry gotcha.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $Root 'tools\Send-DiscoveryOutput.ps1')

    function New-DsoTestZip {
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.zip')
        Set-Content -LiteralPath $path -Value 'not a real zip, just needs to exist and have a size' -NoNewline
        return $path
    }
}

Describe 'Credential store (DPAPI round-trip)' {
    It 'saves and retrieves a credential from the store' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'SG.testkey123' -AsPlainText -Force))
        Save-DeliveryCredential -Name 'UnitTestProvider' -Credential $cred -BaseDirectory $dir
        $back = Get-StoredDeliveryCredential -Name 'UnitTestProvider' -BaseDirectory $dir
        $back                                        | Should -Not -BeNullOrEmpty
        $back.GetNetworkCredential().Password         | Should -Be 'SG.testkey123'
    }

    It 'returns null for a credential that was never saved' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Get-StoredDeliveryCredential -Name 'NeverSaved' -BaseDirectory $dir | Should -BeNullOrEmpty
    }

    It 'removes a saved credential' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'x' -AsPlainText -Force))
        Save-DeliveryCredential -Name 'ToRemove' -Credential $cred -BaseDirectory $dir
        Remove-DeliveryCredential -Name 'ToRemove' -BaseDirectory $dir
        Get-StoredDeliveryCredential -Name 'ToRemove' -BaseDirectory $dir | Should -BeNullOrEmpty
    }

    It 'sanitizes the credential name into a safe filename' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Get-DiscoveryCredentialStorePath -Name 'weird/name:here' -BaseDirectory $dir
        Split-Path -Leaf $path | Should -Not -Match '[/:]'
    }
}

Describe 'Get-OrPromptDeliveryCredential resolution order' {
    It 'uses an explicit -Credential without touching the store or prompting' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -CommandName Get-Credential -MockWith { throw 'must not prompt when -Credential is supplied' }
        $explicit = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'explicit-key' -AsPlainText -Force))
        $result = Get-OrPromptDeliveryCredential -Name 'X' -Credential $explicit -BaseDirectory $dir
        $result.GetNetworkCredential().Password | Should -Be 'explicit-key'
    }

    It 'uses a previously stored credential without prompting' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $stored = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'stored-key' -AsPlainText -Force))
        Save-DeliveryCredential -Name 'Y' -Credential $stored -BaseDirectory $dir
        Mock -CommandName Get-Credential -MockWith { throw 'must not prompt when a credential is already stored' }
        $result = Get-OrPromptDeliveryCredential -Name 'Y' -BaseDirectory $dir
        $result.GetNetworkCredential().Password | Should -Be 'stored-key'
    }

    It 'prompts when nothing is stored and no explicit credential is given' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $prompted = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'prompted-key' -AsPlainText -Force))
        Mock -CommandName Get-Credential -MockWith { $prompted }
        $result = Get-OrPromptDeliveryCredential -Name 'Z' -BaseDirectory $dir
        $result.GetNetworkCredential().Password | Should -Be 'prompted-key'
    }

    It 'saves the prompted credential only when -SaveCredential is passed' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $prompted = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'save-me' -AsPlainText -Force))
        Mock -CommandName Get-Credential -MockWith { $prompted }
        Get-OrPromptDeliveryCredential -Name 'SaveTest' -BaseDirectory $dir -SaveCredential | Out-Null
        Get-StoredDeliveryCredential -Name 'SaveTest' -BaseDirectory $dir | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-DiscoveryAttachmentSize' {
    It 'does not throw for a file under the size cap' {
        $zip = New-DsoTestZip
        { Test-DiscoveryAttachmentSize -Path $zip -MaxSizeMB 20 } | Should -Not -Throw
    }
    It 'throws a clear error, naming -Method Upload, for a file over the size cap' {
        $zip = New-DsoTestZip
        { Test-DiscoveryAttachmentSize -Path $zip -MaxSizeMB 0 } | Should -Throw '*Upload*'
    }
}

Describe 'Send-DiscoveryEmailSmtp' {
    It 'passes the zip as the attachment and forwards server/credential settings unchanged' {
        $zip = New-DsoTestZip
        Mock -CommandName Send-ViaSmtpClient -MockWith { }
        $cred = [pscredential]::new('smtp-user', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
        Send-DiscoveryEmailSmtp -ZipPath $zip -SmtpServer 'mail.example.com' -Port 465 -UseSsl $true `
            -Credential $cred -From 'a@x.com' -To 'b@y.com' -Subject 'Subj' -Body 'Body text'
        Should -Invoke -CommandName Send-ViaSmtpClient -Times 1 -ParameterFilter {
            $SmtpServer -eq 'mail.example.com' -and $Port -eq 465 -and $AttachmentPath -eq $zip -and $From -eq 'a@x.com'
        }
    }
    It 'refuses to send an oversized attachment before ever calling the SMTP client' {
        $zip = New-DsoTestZip
        Mock -CommandName Send-ViaSmtpClient -MockWith { }
        { Send-DiscoveryEmailSmtp -ZipPath $zip -SmtpServer 's' -From 'a@x.com' -To 'b@y.com' -MaxAttachmentSizeMB 0 } | Should -Throw
        Should -Invoke -CommandName Send-ViaSmtpClient -Times 0
    }
}

Describe 'Send-DiscoveryEmailSmtp2Go' {
    It 'posts to the v3 email/send endpoint with the API key in the X-Smtp2go-Api-Key header, base64 attachment as fileblob' {
        $zip = New-DsoTestZip
        $captured = $null
        Mock -CommandName Invoke-RestMethod -MockWith { $script:captured = $Body; [pscustomobject]@{ data = @{ succeeded = @(1) } } }
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'S2G-key' -AsPlainText -Force))
        Send-DiscoveryEmailSmtp2Go -ZipPath $zip -Credential $cred -From 'a@x.com' -To 'b@y.com', 'c@y.com' -Subject 'Subj' -Body 'Body text'
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
            $Uri -eq 'https://api.smtp2go.com/v3/email/send' -and $Headers['X-Smtp2go-Api-Key'] -eq 'S2G-key'
        }
        $payload = $script:captured | ConvertFrom-Json
        $payload.sender               | Should -Be 'a@x.com'
        $payload.to                   | Should -Be @('b@y.com', 'c@y.com')
        $payload.attachments[0].mimetype | Should -Be 'application/zip'
        $payload.attachments[0].fileblob | Should -Not -BeNullOrEmpty
    }
}

Describe 'Send-DiscoveryEmailSendGrid' {
    It 'posts to the v3 mail/send endpoint with a Bearer token and the v3 personalizations shape' {
        $zip = New-DsoTestZip
        $captured = $null
        Mock -CommandName Invoke-RestMethod -MockWith { $script:captured = $Body; [pscustomobject]@{} }
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'SG.key' -AsPlainText -Force))
        Send-DiscoveryEmailSendGrid -ZipPath $zip -Credential $cred -From 'a@x.com' -To 'b@y.com' -Subject 'Subj' -Body 'Body text'
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
            $Uri -eq 'https://api.sendgrid.com/v3/mail/send' -and $Headers['Authorization'] -eq 'Bearer SG.key'
        }
        $payload = $script:captured | ConvertFrom-Json
        $payload.personalizations[0].to[0].email | Should -Be 'b@y.com'
        $payload.from.email                       | Should -Be 'a@x.com'
        $payload.attachments[0].disposition       | Should -Be 'attachment'
        $payload.attachments[0].content            | Should -Not -BeNullOrEmpty
    }
}

Describe 'Send-DiscoveryEmailPostal' {
    It 'posts to the server''s api/v1/send/message with X-Server-API-Key and the name/content_type/data attachment shape' {
        $zip = New-DsoTestZip
        $captured = $null
        $capturedUri = $null
        Mock -CommandName Invoke-RestMethod -MockWith { $script:captured = $Body; $script:capturedUri = $Uri; [pscustomobject]@{ status = 'success' } }
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'postal-key' -AsPlainText -Force))
        Send-DiscoveryEmailPostal -ZipPath $zip -PostalServerUrl 'https://postal.example.com/' -Credential $cred -From 'a@x.com' -To 'b@y.com'
        $script:capturedUri | Should -Be 'https://postal.example.com/api/v1/send/message'
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -ParameterFilter { $Headers['X-Server-API-Key'] -eq 'postal-key' }
        $payload = $script:captured | ConvertFrom-Json
        $payload.attachments[0].name         | Should -Match '\.zip$'
        $payload.attachments[0].content_type | Should -Be 'application/zip'
        $payload.attachments[0].data         | Should -Not -BeNullOrEmpty
    }

    It 'strips trailing slashes from the server URL so the path never doubles up' {
        $zip = New-DsoTestZip
        $capturedUri = $null
        Mock -CommandName Invoke-RestMethod -MockWith { $script:capturedUri = $Uri; [pscustomobject]@{} }
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'k' -AsPlainText -Force))
        Send-DiscoveryEmailPostal -ZipPath $zip -PostalServerUrl 'https://postal.example.com///' -Credential $cred -From 'a@x.com' -To 'b@y.com'
        $script:capturedUri | Should -Be 'https://postal.example.com/api/v1/send/message'
    }
}

Describe 'Invoke-DiscoveryUpload' {
    It 'PUTs the raw file to the given URL by default' {
        $zip = New-DsoTestZip
        Mock -CommandName Invoke-WebRequest -MockWith { }
        Invoke-DiscoveryUpload -ZipPath $zip -UploadUrl 'https://storage.example.com/drop/run.zip?sig=abc'
        Should -Invoke -CommandName Invoke-WebRequest -Times 1 -ParameterFilter {
            $Method -eq 'Put' -and $Uri -eq 'https://storage.example.com/drop/run.zip?sig=abc' -and $InFile -eq $zip
        }
    }
    It 'uses POST when -UploadMethod Post is requested' {
        $zip = New-DsoTestZip
        Mock -CommandName Invoke-WebRequest -MockWith { }
        Invoke-DiscoveryUpload -ZipPath $zip -UploadUrl 'https://storage.example.com/drop' -UploadMethod Post
        Should -Invoke -CommandName Invoke-WebRequest -Times 1 -ParameterFilter { $Method -eq 'Post' }
    }
    It 'throws before making any network call when the file does not exist' {
        Mock -CommandName Invoke-WebRequest -MockWith { throw 'must not be called for a missing file' }
        { Invoke-DiscoveryUpload -ZipPath (Join-Path $TestDrive 'nope.zip') -UploadUrl 'https://x' } | Should -Throw
    }
}

Describe 'Invoke-DiscoveryDelivery dispatcher' {
    It 'routes Method=Upload to Invoke-DiscoveryUpload without needing any credential' {
        $zip = New-DsoTestZip
        Mock -CommandName Invoke-DiscoveryUpload -MockWith { 'uploaded' }
        Mock -CommandName Get-OrPromptDeliveryCredential -MockWith { throw 'Upload must never resolve a credential' }
        Invoke-DiscoveryDelivery -ZipPath $zip -Method Upload -UploadUrl 'https://x' | Should -Be 'uploaded'
    }
    It 'routes Method=SendGrid to Send-DiscoveryEmailSendGrid with the resolved credential' {
        $zip = New-DsoTestZip
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'k' -AsPlainText -Force))
        Mock -CommandName Send-DiscoveryEmailSendGrid -MockWith { 'sent-sendgrid' }
        Invoke-DiscoveryDelivery -ZipPath $zip -Method SendGrid -Credential $cred -From 'a@x.com' -To 'b@y.com' | Should -Be 'sent-sendgrid'
        Should -Invoke -CommandName Send-DiscoveryEmailSendGrid -Times 1 -ParameterFilter { $Credential -eq $cred }
    }
    It 'routes Method=Postal to Send-DiscoveryEmailPostal, passing the server URL through' {
        $zip = New-DsoTestZip
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'k' -AsPlainText -Force))
        Mock -CommandName Send-DiscoveryEmailPostal -MockWith { 'sent-postal' }
        Invoke-DiscoveryDelivery -ZipPath $zip -Method Postal -Credential $cred -PostalServerUrl 'https://postal.x' -From 'a@x.com' -To 'b@y.com' | Should -Be 'sent-postal'
        Should -Invoke -CommandName Send-DiscoveryEmailPostal -Times 1 -ParameterFilter { $PostalServerUrl -eq 'https://postal.x' }
    }
    It 'routes Method=Smtp to Send-DiscoveryEmailSmtp' {
        $zip = New-DsoTestZip
        $cred = [pscredential]::new('u', (ConvertTo-SecureString 'p' -AsPlainText -Force))
        Mock -CommandName Send-DiscoveryEmailSmtp -MockWith { 'sent-smtp' }
        Invoke-DiscoveryDelivery -ZipPath $zip -Method Smtp -Credential $cred -SmtpServer 'mail.x' -From 'a@x.com' -To 'b@y.com' | Should -Be 'sent-smtp'
    }
}

Describe 'Find-DiscoveryRunZip' {
    # Regression: the GUI and Ninja wrapper looked for archive\run.zip, but the engine names the
    # archive Discover-WindowsServer_<host>_<stamp>.zip - so delivery never found a real run's zip.
    It "finds the engine's real archive name" {
        $run = Join-Path $TestDrive 'run1'
        New-Item -ItemType Directory -Path (Join-Path $run 'archive') -Force | Out-Null
        $zip = Join-Path $run 'archive\Discover-WindowsServer_SRV01_20260101_120000.zip'
        Set-Content -LiteralPath $zip -Value 'x'
        Find-DiscoveryRunZip -OutputPath $run | Should -Be $zip
    }
    It 'returns $null when there is no archive folder (e.g. -SkipZip)' {
        Find-DiscoveryRunZip -OutputPath (Join-Path $TestDrive 'no-such-run') | Should -BeNullOrEmpty
    }
}

Describe 'https-only delivery URLs' {
    It 'refuses an http:// upload URL before any network call' {
        $zip = New-DsoTestZip
        Mock -CommandName Invoke-WebRequest -MockWith { throw 'must not be called' }
        { Invoke-DiscoveryUpload -ZipPath $zip -UploadUrl 'http://storage.example.com/drop' } | Should -Throw '*https://*'
        Should -Invoke -CommandName Invoke-WebRequest -Times 0
    }
    It 'refuses an http:// Postal server before sending the API key' {
        $zip = New-DsoTestZip
        $cred = [pscredential]::new('ApiKey', (ConvertTo-SecureString 'k' -AsPlainText -Force))
        Mock -CommandName Invoke-RestMethod -MockWith { throw 'must not be called' }
        { Send-DiscoveryEmailPostal -ZipPath $zip -PostalServerUrl 'http://postal.example.com' -Credential $cred -From 'a@x.com' -To 'b@y.com' } | Should -Throw '*https://*'
        Should -Invoke -CommandName Invoke-RestMethod -Times 0
    }
}

Describe 'Enable-DiscoveryTls12' {
    BeforeEach { $script:SavedProtocol = [Net.ServicePointManager]::SecurityProtocol }
    AfterEach  { [Net.ServicePointManager]::SecurityProtocol = $script:SavedProtocol }

    It 'adds TLS 1.2 to the 2012 R2/2016 Windows PowerShell default (an explicit list without Tls12) without removing anything' {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls, Tls11'   # Ssl3 itself can't be set on .NET 8 (pwsh); any explicit list lacking Tls12 is the case
        Enable-DiscoveryTls12
        $p = [Net.ServicePointManager]::SecurityProtocol
        $p.HasFlag([Net.SecurityProtocolType]::Tls12) | Should -BeTrue
        $p.HasFlag([Net.SecurityProtocolType]::Tls)   | Should -BeTrue
    }
    It 'leaves SystemDefault alone so the OS can still negotiate TLS 1.3' {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::SystemDefault
        Enable-DiscoveryTls12
        [Net.ServicePointManager]::SecurityProtocol | Should -Be ([Net.SecurityProtocolType]::SystemDefault)
    }
}
