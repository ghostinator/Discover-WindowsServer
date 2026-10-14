#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    ExchangeSmtp.Tests.ps1 - fixture-based tests for the Exchange / SMTP relay collector.

    The parsers run against small log files written to $TestDrive in the real Exchange formats
    (message tracking CSV, SMTP receive protocol CSV), so no Exchange server is needed. The core
    contract under test: the module may say "confirmed client" or "possible client", but it
    never turns missing, disabled or aged-out logging into "unused".
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                   -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1')               -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\ExchangeSmtp\ExchangeSmtp.psm1')   -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    $script:TrackingHeader = '#Fields: date-time,client-ip,client-hostname,server-ip,server-hostname,source-context,connector-id,source,event-id,internal-message-id,message-id,network-message-id,recipient-address,recipient-status,total-bytes,recipient-count,related-recipient-address,reference,message-subject,sender-address,return-path,message-info,directionality,tenant-id,original-client-ip,original-server-ip,custom-data'
    $script:ProtocolHeader = '#Fields: date-time,connector-id,session-id,sequence-number,local-endpoint,remote-endpoint,event,data,context'

    function New-LogFile {
        param([string]$Name, [string]$Header, [string[]]$Lines)
        $p = Join-Path $TestDrive $Name
        Set-Content -LiteralPath $p -Value (@('#Software: Microsoft Exchange Server', $Header) + $Lines) -Encoding UTF8
        return $p
    }
}

Describe 'Get-MessageTrackingClientSummary - grouping by client IP and connector' {
    BeforeAll {
        $script:Trk = New-LogFile -Name 'MSGTRK20261001-1.LOG' -Header $script:TrackingHeader -Lines @(
            '2026-10-01T10:00:00.000Z,10.0.0.50,MFP01,10.0.0.5,EX01,"08DC, a",EX01\Relay,SMTP,RECEIVE,1,<m1@x>,n1,ap@contoso.com;ar@contoso.com,,10,2,,,"Scan, page 1",scanner@contoso.com,scanner@contoso.com,,Originating,,,,'
            '2026-10-01T11:00:00.000Z,10.0.0.50,MFP01,10.0.0.5,EX01,,EX01\Relay,SMTP,RECEIVE,2,<m2@x>,n2,ap@contoso.com,,10,1,,,Scan,scanner@contoso.com,scanner@contoso.com,,Originating,,,,'
            '2026-10-01T11:30:00.000Z,10.0.0.60,APP02,10.0.0.5,EX01,,EX01\Default Frontend,SMTP,RECEIVE,3,<m3@x>,n3,ops@contoso.com,,10,1,,,Alert,alerts@contoso.com,alerts@contoso.com,,Originating,,,,'
            '2026-10-01T11:30:01.000Z,10.0.0.5,EX01,10.0.0.5,EX01,,,STOREDRIVER,DELIVER,3,<m3@x>,n3,ops@contoso.com,,10,1,,,Alert,alerts@contoso.com,alerts@contoso.com,,Originating,,,,'
        )
    }

    It 'produces one row per client IP + connector, counting only SMTP RECEIVE events' {
        $r = Get-MessageTrackingClientSummary -Files $script:Trk -Since ([datetime]'2026-09-01')
        @($r.Rows).Count | Should -Be 2
        ($r.Rows | Where-Object ClientIp -eq '10.0.0.50').MessagesReceived | Should -Be 2
        ($r.Rows | Where-Object ClientIp -eq '10.0.0.50').ConnectorId | Should -Be 'EX01\Relay'
        ($r.Rows | Where-Object ClientIp -eq '10.0.0.60').ConnectorId | Should -Be 'EX01\Default Frontend'
    }

    It 'parses quoted fields containing commas without shifting columns' {
        $r = Get-MessageTrackingClientSummary -Files $script:Trk -Since ([datetime]'2026-09-01')
        ($r.Rows | Where-Object ClientIp -eq '10.0.0.50').FirstSeen | Should -Be '2026-10-01T10:00:00.000Z'
    }

    It 'masks sender and recipient addresses to the domain by default' {
        $r = Get-MessageTrackingClientSummary -Files $script:Trk -Since ([datetime]'2026-09-01')
        $row = $r.Rows | Where-Object ClientIp -eq '10.0.0.50'
        $row.SampleSenders    | Should -Be '*@contoso.com'
        $row.SampleRecipients | Should -Not -Match 'ap@'
        $row.SampleMessageIds | Should -BeNullOrEmpty
    }

    It 'keeps full addresses and message IDs only when sensitive evidence is requested' {
        $r = Get-MessageTrackingClientSummary -Files $script:Trk -Since ([datetime]'2026-09-01') -Sensitive $true
        $row = $r.Rows | Where-Object ClientIp -eq '10.0.0.50'
        $row.SampleSenders    | Should -Be 'scanner@contoso.com'
        $row.SampleMessageIds | Should -Match 'm1@x'
    }

    It 'ignores records older than the lookback window' {
        # Log timestamps are UTC; pass a UTC cutoff so the test does not depend on the host time zone.
        $r = Get-MessageTrackingClientSummary -Files $script:Trk -Since ([datetime]::SpecifyKind([datetime]'2026-10-01T11:15:00', 'Utc'))
        @($r.Rows).Count | Should -Be 1
        $r.Rows[0].ClientIp | Should -Be '10.0.0.60'
    }
}

Describe 'Get-SmtpReceiveProtocolSummary - parsing by connector and remote endpoint' {
    BeforeAll {
        $script:Prt = New-LogFile -Name 'RECV20261001-1.LOG' -Header $script:ProtocolHeader -Lines @(
            '2026-10-01T10:00:00.000Z,EX01\Relay,S1,0,10.0.0.5:25,10.0.0.50:51000,+,,'
            '2026-10-01T10:00:00.010Z,EX01\Relay,S1,1,10.0.0.5:25,10.0.0.50:51000,<,EHLO MFP01,'
            '2026-10-01T10:00:00.020Z,EX01\Relay,S1,2,10.0.0.5:25,10.0.0.50:51000,<,MAIL FROM:<scanner@contoso.com>,'
            '2026-10-01T10:00:00.030Z,EX01\Relay,S1,3,10.0.0.5:25,10.0.0.50:51000,<,RCPT TO:<ap@contoso.com>,'
            '2026-10-01T10:00:00.040Z,EX01\Relay,S1,4,10.0.0.5:25,10.0.0.50:51000,>,"250 2.6.0 <m1@x> [InternalId=1, Hostname=EX01] Queued mail for delivery",'
            '2026-10-01T10:05:00.000Z,EX01\Relay,S2,0,10.0.0.5:25,10.0.0.50:51001,+,,'
            '2026-10-01T10:06:00.000Z,EX01\Default Frontend,S3,0,10.0.0.5:25,[fe80::9]:51002,+,,'
            '2026-10-01T10:06:00.010Z,EX01\Default Frontend,S3,1,10.0.0.5:25,[fe80::9]:51002,<,EHLO probe,'
            '2026-10-01T10:06:00.020Z,EX01\Default Frontend,S3,2,10.0.0.5:25,[fe80::9]:51002,>,550 5.7.54 Unable to relay,'
        )
    }

    It 'groups sessions per remote address and connector, stripping the source port' {
        $r = Get-SmtpReceiveProtocolSummary -Files $script:Prt -Since ([datetime]'2026-09-01')
        @($r.Rows).Count | Should -Be 2
        $relay = $r.Rows | Where-Object ClientIp -eq '10.0.0.50'
        $relay.Sessions | Should -Be 2
        $relay.ConnectorId | Should -Be 'EX01\Relay'
        ($r.Rows | Where-Object ClientIp -eq 'fe80::9').ConnectorId | Should -Be 'EX01\Default Frontend'
    }

    It 'counts EHLO identity, MAIL FROM, RCPT TO, accepted (250 2.6.0) and rejected (5xx) responses' {
        $r = Get-SmtpReceiveProtocolSummary -Files $script:Prt -Since ([datetime]'2026-09-01')
        $relay = $r.Rows | Where-Object ClientIp -eq '10.0.0.50'
        $relay.EhloIdentities   | Should -Be 'MFP01'
        $relay.MailFromCount    | Should -Be 1
        $relay.RcptToCount      | Should -Be 1
        $relay.AcceptedMessages | Should -Be 1
        ($r.Rows | Where-Object ClientIp -eq 'fe80::9').RejectedResponses | Should -Be 1
    }

    It 'correlates with message tracking: accepted mail is a confirmed client, connect-only is possible' {
        $t = Get-MessageTrackingClientSummary -Files @() -Since ([datetime]'2026-09-01')
        $p = Get-SmtpReceiveProtocolSummary -Files $script:Prt -Since ([datetime]'2026-09-01')
        $m = Merge-SmtpRelayEvidence -TrackingRows $t.Rows -ProtocolRows $p.Rows
        ($m | Where-Object ClientIp -eq '10.0.0.50').Classification | Should -Be 'Confirmed active SMTP client'
        ($m | Where-Object ClientIp -eq 'fe80::9').Classification   | Should -Be 'Possible SMTP client requiring validation'
        ($m | Where-Object ClientIp -eq 'fe80::9').Recommendation   | Should -Be 'Client IP requires identification'
    }

    It 'drops connect-only traffic from the server itself but keeps a local app that sent mail' {
        $p = @(
            [pscustomobject]@{ ClientIp='127.0.0.1'; Sessions=5; AcceptedMessages=0 }
            [pscustomobject]@{ ClientIp='10.0.0.9';  Sessions=9; AcceptedMessages=0 }
            [pscustomobject]@{ ClientIp='10.0.0.9x'; Sessions=1; AcceptedMessages=0 }
        )
        $t = @([pscustomobject]@{ ClientIp='10.0.0.9'; MessagesReceived=0 }, [pscustomobject]@{ ClientIp='127.0.0.2'; MessagesReceived=4 })
        $m = @(Merge-SmtpRelayEvidence -TrackingRows $t -ProtocolRows $p -SelfIps @('10.0.0.9'))
        ($m.ClientIp -join ',') | Should -Be '127.0.0.2,10.0.0.9x'
    }
}

Describe 'Get-SmtpRelayAssessment - never treats missing evidence as non-use' {
    It 'reports Exchange cmdlets unavailable as a condition' {
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $false -TrackingFiles 1 -FilesInWindow 1 -CoverageDays 7
        $a.Conditions | Should -Match 'Exchange cmdlets unavailable'
        $a.UsageProvenUnused | Should -BeFalse
    }

    It 'reports protocol logging disabled on a connector even when logs exist and no client was seen' {
        $rc = @([pscustomobject]@{ Name='Relay'; Enabled='True'; ProtocolLoggingLevel='None' })
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $true -ReceiveConnectors $rc -TrackingFiles 3 -FilesInWindow 3 -CoverageDays 7
        $a.Status | Should -Be 'Protocol logging disabled on the relevant connector'
        $a.ConnectorsWithoutProtocolLogging | Should -Be 'Relay'
        $a.Recommendation | Should -Match 'Connector logging not sufficient'
        $a.Recommendation | Should -Not -Match 'Safe to continue'
    }

    It 'reports logs unavailable (not unused) when no log files exist' {
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $true -TrackingFiles 0 -ProtocolFiles 0 -FilesInWindow 0
        $a.Status | Should -Be 'Logs unavailable'
        $a.Recommendation | Should -Match 'Observation window recommended'
        $a.UsageProvenUnused | Should -BeFalse
    }

    It 'reports logs aged out when files exist but none fall in the window' {
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $true -TrackingFiles 5 -FilesInWindow 0
        $a.Status | Should -Be 'Logs aged out'
    }

    It 'reports a permission failure distinctly' {
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $true -PermissionDenied $true
        $a.Status | Should -Be 'Permission failure'
    }

    It 'with logs present and zero clients says no usage found in available logs - and still recommends observation on short coverage' {
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $true -TrackingFiles 2 -FilesInWindow 2 -CoverageDays 3
        $a.Status | Should -Be 'No SMTP usage found in available logs'
        $a.Status | Should -Not -Match '(?i)\bunused\b'
        $a.Recommendation | Should -Match 'Observation window recommended'
        $a.UsageProvenUnused | Should -BeFalse
    }

    It 'only reaches Safe to continue decommission review with long, complete evidence and logging on' {
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $true -TrackingEnabled $true -TrackingFiles 30 -FilesInWindow 30 -CoverageDays 30 -LookbackDays 30
        $a.Recommendation | Should -Be 'Safe to continue decommission review'
        $a.UsageProvenUnused | Should -BeFalse
    }

    It 'confirmed clients override everything else' {
        $a = Get-SmtpRelayAssessment -ExchangeInstalled $true -CmdletsAvailable $false -TrackingFiles 1 -FilesInWindow 1 -ConfirmedClients 2 -CoverageDays 30
        $a.Status | Should -Be 'Confirmed active SMTP client'
        $a.Recommendation | Should -Match 'Active relay dependency found'
    }
}

Describe 'Get-RecentLogFiles' {
    It 'returns nothing (not an error) for a folder that does not exist' {
        $r = Get-RecentLogFiles -Folders @((Join-Path $TestDrive 'nope')) -Filter '*.LOG' -Since (Get-Date).AddDays(-7)
        @($r.All).Count | Should -Be 0
        $r.Denied | Should -BeFalse
    }
    It 'separates files in the window from older ones' {
        $d = Join-Path $TestDrive 'logs'; New-Item -ItemType Directory $d -Force | Out-Null
        $new = New-Item (Join-Path $d 'RECV1.LOG') -Force; $old = New-Item (Join-Path $d 'RECV0.LOG') -Force
        $old.LastWriteTime = (Get-Date).AddDays(-60)
        $r = Get-RecentLogFiles -Folders @($d) -Filter 'RECV*.LOG' -Since (Get-Date).AddDays(-7)
        @($r.All).Count | Should -Be 2
        @($r.InWindow).Count | Should -Be 1
    }
}

Describe 'Invoke-DiscoveryCollection - Exchange installed but cmdlets unavailable' {
    It 'records the limitation, still reports the server, and never claims non-use' {
        InModuleScope ExchangeSmtp -Parameters @{ Cfg = $script:Config; Drive = $TestDrive } {
            param($Cfg, $Drive)
            Mock Get-ExchangeInstallInfo { [pscustomobject]@{ RegistryVersionKey='v15'; Version='15.1.2507.6'; InstallPath=(Join-Path $Drive 'Exchange'); Roles=@('MailboxRole') } }
            Mock Get-ExchangeCmdletInventory { $null }
            $ctx = New-DiscoveryContext -Mode Fast -Config $Cfg -Parameters @{ ExchangeLogDays = 7 }
            $raw = Invoke-DiscoveryCollection -Context $ctx
            $raw.ExchangeServer[0].CmdletsAvailable | Should -BeFalse
            $raw.ExchangeServer[0].ProductName | Should -Be 'Exchange Server 2016'
            $raw.SmtpRelayAssessment[0].Status | Should -Be 'Logs unavailable'
            $raw.SmtpRelayAssessment[0].Conditions | Should -Match 'Exchange cmdlets unavailable'
            $raw.SmtpRelayAssessment[0].UsageProvenUnused | Should -BeFalse
            ($ctx.Limitations | Where-Object { $_.Message -match 'Exchange cmdlets unavailable' }) | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-ExchangeVersionInfo' {
    It 'maps builds to products and support state as of a given date' {
        (Get-ExchangeVersionInfo -Version '15.1.2507.6' -AsOf ([datetime]'2026-10-13')).IsUnsupported | Should -BeTrue
        (Get-ExchangeVersionInfo -Version '15.2.2562.17' -AsOf ([datetime]'2026-10-13')).ProductName | Should -Be 'Exchange Server Subscription Edition'
        (Get-ExchangeVersionInfo -Version '15.2.2562.17' -AsOf ([datetime]'2026-10-13')).IsUnsupported | Should -BeFalse
        (Get-ExchangeVersionInfo -Version '' ).ProductName | Should -Be ''
    }
}

Describe 'Test-DiscoveryPrerequisites' {
    It 'is NotApplicable on a server with no Exchange, IIS SMTP, listener or SMTP connection' {
        InModuleScope ExchangeSmtp -Parameters @{ Cfg = $script:Config } {
            param($Cfg)
            Mock Get-ExchangeInstallInfo { $null }
            $ctx = New-DiscoveryContext -Mode Fast -Config $Cfg
            (Test-DiscoveryPrerequisites -Context $ctx).Status | Should -Be 'NotApplicable'
        }
    }
    It 'runs when an SMTP listener is present even without Exchange' {
        InModuleScope ExchangeSmtp -Parameters @{ Cfg = $script:Config } {
            param($Cfg)
            Mock Get-ExchangeInstallInfo { $null }
            $ctx = New-DiscoveryContext -Mode Fast -Config $Cfg
            Add-DataSet -Context $ctx -Name 'ListeningPorts' -Rows @([pscustomobject]@{ Protocol='TCP'; LocalPort='25'; Process='inetinfo' }) | Out-Null
            (Test-DiscoveryPrerequisites -Context $ctx).CanRun | Should -BeTrue
        }
    }
}
