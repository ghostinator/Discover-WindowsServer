#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Invoke-NinjaDiscovery.Tests.ps1 - fixture-based tests for the NinjaRMM wrapper's pure
    logic: base64 parameter decoding, Postal target parsing, and delivery-args construction.

    Dot-sourcing is safe here for the same reason it's safe for Discover-WindowsServer-GUI.ps1
    and tools\Send-DiscoveryOutput.ps1: everything that actually downloads the toolkit, runs a
    scan, or sends anything is gated behind an "only run when invoked directly" guard. These
    tests never touch the network, never download the (private) repo, and never run a real
    discovery scan.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $Root 'tools\Invoke-NinjaDiscovery.ps1')
}

Describe 'ConvertFrom-NinjaBase64' {
    It 'decodes a base64 value back to its original string' {
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('ops@msp.com,second@msp.com'))
        ConvertFrom-NinjaBase64 -Value $encoded | Should -Be 'ops@msp.com,second@msp.com'
    }
    It 'returns empty string for empty input, rather than throwing' {
        ConvertFrom-NinjaBase64 -Value '' | Should -Be ''
    }
    It 'throws a clear error for a value that is not valid base64' {
        { ConvertFrom-NinjaBase64 -Value 'not valid base64 !!!' } | Should -Throw '*not valid base64*'
    }
}

Describe 'Get-PostalTargetParts' {
    It 'splits a pipe-delimited server-url/to-address pair into its two parts' {
        $p = Get-PostalTargetParts -DecodedTarget 'https://postal.msp.com|ops@msp.com'
        $p.PostalServerUrl | Should -Be 'https://postal.msp.com'
        $p.ToAddress       | Should -Be 'ops@msp.com'
    }
    It 'throws when there is no pipe separator at all' {
        { Get-PostalTargetParts -DecodedTarget 'https://postal.msp.com' } | Should -Throw
    }
    It 'throws when either side of the pipe is blank' {
        { Get-PostalTargetParts -DecodedTarget 'https://postal.msp.com|' } | Should -Throw
        { Get-PostalTargetParts -DecodedTarget '|ops@msp.com' }            | Should -Throw
    }
}

Describe 'Get-DeliveryInvocationArgs' {
    It 'builds Upload args from the decoded target URL alone, no credential needed' {
        $result = Get-DeliveryInvocationArgs -ZipPath 'C:\out\run.zip' -Method 'Upload' -DecodedTarget 'https://s3.example.com/drop?sig=abc&exp=123' -From 'a@x.com'
        $result.ZipPath   | Should -Be 'C:\out\run.zip'
        $result.UploadUrl | Should -Be 'https://s3.example.com/drop?sig=abc&exp=123'
        $result.Keys      | Should -Not -Contain 'Credential'
    }

    It 'builds Postal args with the server URL, single recipient, and a credential' {
        $result = Get-DeliveryInvocationArgs -ZipPath 'C:\out\run.zip' -Method 'Postal' -DecodedTarget 'https://postal.msp.com|ops@msp.com' -DecodedCredential 'postal-key' -From 'a@x.com'
        $result.PostalServerUrl                              | Should -Be 'https://postal.msp.com'
        $result.To                                           | Should -Be @('ops@msp.com')
        $result.From                                         | Should -Be 'a@x.com'
        $result.Credential.GetNetworkCredential().Password   | Should -Be 'postal-key'
    }

    It 'builds SendGrid/Smtp2Go args from a comma-separated recipient list, trimming whitespace' {
        $result = Get-DeliveryInvocationArgs -ZipPath 'C:\out\run.zip' -Method 'SendGrid' -DecodedTarget 'a@x.com, b@x.com ,c@x.com' -DecodedCredential 'SG.key' -From 'from@x.com'
        $result.To                                         | Should -Be @('a@x.com', 'b@x.com', 'c@x.com')
        $result.Credential.GetNetworkCredential().Password | Should -Be 'SG.key'
    }

    It 'includes a default Subject that names the computer' {
        $result = Get-DeliveryInvocationArgs -ZipPath 'C:\out\run.zip' -Method 'SendGrid' -DecodedTarget 'a@x.com' -DecodedCredential 'k' -From 'from@x.com'
        $result.Subject | Should -Match ([regex]::Escape($env:COMPUTERNAME))
    }
}
