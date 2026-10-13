<#
    ExchangeSmtp.psm1 - Exchange Server inventory and SMTP relay usage evidence (read-only).

    Produces: ExchangeServer, ExchangeServices, ExchangeReceiveConnectors, ExchangeSendConnectors,
              ExchangeAcceptedDomains, ExchangeRemoteDomains, ExchangeHybrid, ExchangeCertificates,
              ExchangeQueues, ExchangeLogSettings, ExchangeIisApplications, ExchangeShares,
              SmtpRelayClients, SmtpRelayAssessment, SmtpConnections.

    Why: "what still sends mail through this server?" is the question that blocks every Exchange
    or relay-server decommission, and the honest answer depends entirely on what logging existed.
    This module summarises the evidence that ALREADY exists and states its limits.

    Safety:
      - Exchange cmdlets: Get-* only, run in a time-bounded Windows PowerShell child that loads the
        locally registered Exchange management snap-in. Nothing is set, enabled or restarted -
        protocol logging and message tracking are NEVER switched on by this tool.
      - Logs are opened read-only with FileShare.ReadWrite (Exchange keeps today's log open) and
        streamed record by record; only aggregates are kept.
      - Sender/recipient addresses are reduced to '*@domain' and message IDs are omitted unless
        -IncludeSensitiveEvidence. Raw logs are copied ONLY with -CopyExchangeRawLogs.
      - Absence of evidence is never reported as absence of use: SmtpRelayAssessment.Status names
        the evidence condition (logging disabled, logs unavailable, aged out, ...).
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='ExchangeSmtp'; DisplayName='Exchange Server & SMTP Relay'; Category='Mail'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('ExchangeServer','ExchangeServices','ExchangeReceiveConnectors','ExchangeSendConnectors','ExchangeAcceptedDomains','ExchangeRemoteDomains','ExchangeHybrid','ExchangeCertificates','ExchangeQueues','ExchangeLogSettings','ExchangeIisApplications','ExchangeShares','SmtpRelayClients','SmtpRelayAssessment','SmtpConnections')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

$script:SmtpPorts = @('25','465','587')

function Get-ExchangeInstallInfo {
    <# Registry-only Exchange detection: version, install path, configured roles. $null when Exchange is not installed. #>
    param()
    foreach ($v in @('v15','v14')) {
        $setup = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\$v\Setup"
        if (-not (Test-RegistryPathSafe $setup)) { continue }
        $parts = @('MsiProductMajor','MsiProductMinor','MsiBuildMajor','MsiBuildMinor' | ForEach-Object { Get-RegistryValueSafe -Path $setup -Name $_ })
        $roles = @()
        foreach ($r in @('MailboxRole','ClientAccessRole','HubTransportRole','UnifiedMessagingRole','EdgeTransportRole','FrontendTransportRole','CafeRole','AdminTools')) {
            if (Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\ExchangeServer\$v\$r" -Name 'ConfiguredVersion') { $roles += $r }
        }
        return [pscustomobject]@{
            RegistryVersionKey=$v; Version=$(if ($parts[0]) { ($parts | ForEach-Object { [string]$_ }) -join '.' } else { '' })
            InstallPath=[string](Get-RegistryValueSafe -Path $setup -Name 'MsiInstallPath'); Roles=$roles
        }
    }
    return $null
}

function Get-ExchangeVersionInfo {
    <# Pure: Exchange build -> product + support state. Exchange SE (15.2 build 2562+) is the supported successor of 2016/2019. #>
    param([string]$Version, [datetime]$AsOf = (Get-Date))
    $out = [pscustomobject]@{ ProductName=''; SupportEnd=''; IsUnsupported=$false }
    $p = @(([string]$Version).Split('.') | ForEach-Object { $n = 0; [void][int]::TryParse($_, [ref]$n); $n })
    if ($p.Count -lt 2 -or $p[0] -eq 0) { return $out }
    $build = if ($p.Count -ge 3) { $p[2] } else { 0 }
    if ($p[0] -eq 14) { $out.ProductName = 'Exchange Server 2010'; $out.SupportEnd = '2020-10-13' }
    elseif ($p[0] -eq 15 -and $p[1] -eq 0) { $out.ProductName = 'Exchange Server 2013'; $out.SupportEnd = '2023-04-11' }
    elseif ($p[0] -eq 15 -and $p[1] -eq 1) { $out.ProductName = 'Exchange Server 2016'; $out.SupportEnd = '2025-10-14' }
    elseif ($p[0] -eq 15 -and $p[1] -eq 2 -and $build -ge 2562) { $out.ProductName = 'Exchange Server Subscription Edition'; $out.SupportEnd = '' }
    elseif ($p[0] -eq 15 -and $p[1] -eq 2) { $out.ProductName = 'Exchange Server 2019'; $out.SupportEnd = '2025-10-14' }
    if ($out.SupportEnd) { $out.IsUnsupported = ([datetime]$out.SupportEnd -lt $AsOf) }
    return $out
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $why = @()
    if (Get-ExchangeInstallInfo) { $why += 'Exchange installed' }
    $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
    if (@($svcRows | Where-Object { $_.Name -eq 'SMTPSVC' }).Count) { $why += 'IIS SMTP service' }
    if ($Context.DataSets.Contains('ListeningPorts') -and @($Context.DataSets['ListeningPorts'].Rows | Where-Object { $_.Protocol -ne 'UDP' -and [string]$_.LocalPort -in $script:SmtpPorts }).Count) { $why += 'SMTP listener' }
    if ($Context.DataSets.Contains('EstablishedConnections') -and @($Context.DataSets['EstablishedConnections'].Rows | Where-Object { [string]$_.RemotePort -in $script:SmtpPorts -or [string]$_.LocalPort -in $script:SmtpPorts }).Count) { $why += 'SMTP connections' }
    if ($why.Count -gt 0) { return [pscustomobject]@{ ModuleName='ExchangeSmtp'; CanRun=$true; Status='Ready'; Reason=($why -join ', '); Limitations=@() } }
    [pscustomobject]@{ ModuleName='ExchangeSmtp'; CanRun=$false; Status='NotApplicable'; Reason='No Exchange install, IIS SMTP service, SMTP listener or SMTP connection detected.'; Limitations=@() }
}

#region Log parsing (pure, streaming) --------------------------------------------

function Protect-EmailAddress {
    <# '*@domain' unless sensitive evidence was requested. Never returns a local part by default. #>
    param([string]$Address, [bool]$Sensitive = $false)
    $a = ([string]$Address).Trim().Trim('<','>')
    if (-not $a) { return '' }
    if ($Sensitive) { return $a }
    $at = $a.LastIndexOf('@')
    if ($at -lt 0) { return '(withheld)' }
    return ('*' + $a.Substring($at))
}

function Read-DelimitedLogRecords {
    <#
        Streams a '#Fields:'-headed log (Exchange CSV or IIS W3C space-delimited) and invokes
        -OnRecord with a field-name -> value hashtable per record. Returns the record count, or
        -1 when the file has no #Fields header. Opened with FileShare.ReadWrite so the log
        Exchange is currently writing can still be read.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$OnRecord, [string]$Delimiter = ',')
    $fields = $null
    $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $sr = [System.IO.StreamReader]::new($fs)
    try {
        $n = 0
        while ($null -ne ($line = $sr.ReadLine())) {
            if ($line.StartsWith('#')) {
                if ($line.StartsWith('#Fields:')) { $fields = @($line.Substring(8).Trim() -split [regex]::Escape($Delimiter) | ForEach-Object { $_.Trim() }) }
                continue
            }
            if (-not $fields -or -not $line) { continue }
            $vals = @(if ($Delimiter -ne ',' -or $line.IndexOf('"') -lt 0) { $line.Split([char]$Delimiter) } else { Split-QuotedCsvLine -Line $line })
            $rec = @{}
            for ($i = 0; $i -lt $fields.Count -and $i -lt $vals.Count; $i++) { $rec[$fields[$i]] = $vals[$i] }
            & $OnRecord $rec
            $n++
        }
        if (-not $fields) { return -1 }
        return $n
    } finally { $sr.Dispose(); $fs.Dispose() }
}

function Split-QuotedCsvLine {
    <# Pure: one CSV line with "quoted, fields" and "" escapes -> field array. Only used for lines that contain a quote. #>
    param([string]$Line)
    $out = [System.Collections.Generic.List[string]]::new()
    $sb = [System.Text.StringBuilder]::new(); $inQ = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $ch = $Line[$i]
        if ($inQ) {
            if ($ch -eq '"') { if ($i + 1 -lt $Line.Length -and $Line[$i + 1] -eq '"') { [void]$sb.Append('"'); $i++ } else { $inQ = $false } }
            else { [void]$sb.Append($ch) }
        } elseif ($ch -eq '"') { $inQ = $true }
        elseif ($ch -eq ',') { $out.Add($sb.ToString()); [void]$sb.Clear() }
        else { [void]$sb.Append($ch) }
    }
    $out.Add($sb.ToString())
    # Plain return (unrolls): the only caller wraps it in @(), and a comma here would nest the array.
    return $out.ToArray()
}

function Get-EndpointAddress {
    <# Pure: '10.0.0.5:51234' / '[fe80::1]:25' -> the address part. #>
    param([string]$Endpoint)
    $e = ([string]$Endpoint).Trim()
    if ($e -match '^\[([^\]]+)\]') { return $Matches[1] }
    if (($e.Split(':')).Count -eq 2) { return $e.Split(':')[0] }
    return $e
}

function Get-MessageTrackingClientSummary {
    <#
        Groups SMTP RECEIVE events from message-tracking logs by client IP + connector: message
        count, first/last seen, sample (masked) senders/recipients, event IDs and sources.
        Returns @{ Rows; RecordsRead; FilesRead; FilesFailed; OldestRecord; NewestRecord }.
    #>
    param([string[]]$Files = @(), [datetime]$Since = [datetime]::MinValue, [bool]$Sensitive = $false, [int]$TimeBudgetSeconds = 300)
    $cut = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
    $agg = @{}; $stats = @{ Records = 0; Oldest = $null; Newest = $null }
    $failed = 0; $read = 0; $sw = [System.Diagnostics.Stopwatch]::StartNew(); $truncated = $false
    $on = {
        param($r)
        $t = [string]$r['date-time']
        if ($t) {
            if ($null -eq $stats.Oldest -or $t -lt $stats.Oldest) { $stats.Oldest = $t }
            if ($null -eq $stats.Newest -or $t -gt $stats.Newest) { $stats.Newest = $t }
            if ($t -lt $cut) { return }
        }
        $stats.Records++
        if ([string]$r['event-id'] -ne 'RECEIVE' -or [string]$r['source'] -ne 'SMTP') { return }
        $ip = [string]$r['original-client-ip']; if (-not $ip) { $ip = [string]$r['client-ip'] }
        if (-not $ip) { return }
        $key = '{0}|{1}' -f $ip, [string]$r['connector-id']
        $e = $agg[$key]
        if (-not $e) {
            $e = @{ Ip=$ip; Connector=[string]$r['connector-id']; Msgs=0; First=$t; Last=$t; Host=[string]$r['client-hostname']
                    Senders=[System.Collections.Generic.HashSet[string]]::new(); Recipients=[System.Collections.Generic.HashSet[string]]::new()
                    EventIds=[System.Collections.Generic.HashSet[string]]::new(); Sources=[System.Collections.Generic.HashSet[string]]::new(); MessageIds=[System.Collections.Generic.List[string]]::new() }
            $agg[$key] = $e
        }
        $e.Msgs++
        if ($t -and $t -lt $e.First) { $e.First = $t }
        if ($t -and $t -gt $e.Last) { $e.Last = $t }
        [void]$e.EventIds.Add([string]$r['event-id']); [void]$e.Sources.Add([string]$r['source'])
        if ($e.Senders.Count -lt 3 -and $r['sender-address']) { [void]$e.Senders.Add((Protect-EmailAddress -Address $r['sender-address'] -Sensitive $Sensitive)) }
        if ($e.Recipients.Count -lt 3 -and $r['recipient-address']) { foreach ($ra in (([string]$r['recipient-address']) -split ';')) { if ($e.Recipients.Count -lt 3 -and $ra) { [void]$e.Recipients.Add((Protect-EmailAddress -Address $ra -Sensitive $Sensitive)) } } }
        if ($Sensitive -and $e.MessageIds.Count -lt 2 -and $r['message-id']) { $e.MessageIds.Add([string]$r['message-id']) }
    }
    foreach ($f in $Files) {
        if ($sw.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) { $truncated = $true; break }
        try { [void](Read-DelimitedLogRecords -Path $f -OnRecord $on); $read++ } catch { $failed++ }
    }
    $rows = foreach ($e in $agg.Values) {
        [pscustomobject]@{ ClientIp=$e.Ip; ConnectorId=$e.Connector; ClientHostname=$e.Host; MessagesReceived=$e.Msgs; FirstSeen=$e.First; LastSeen=$e.Last
            SampleSenders=(@($e.Senders) -join '; '); SampleRecipients=(@($e.Recipients) -join '; '); EventIds=(@($e.EventIds) -join ', '); Sources=(@($e.Sources) -join ', '); SampleMessageIds=(@($e.MessageIds) -join '; ') }
    }
    return @{ Rows=@($rows); RecordsRead=$stats.Records; FilesRead=$read; FilesFailed=$failed; OldestRecord=$stats.Oldest; NewestRecord=$stats.Newest; Truncated=$truncated }
}

function Get-SmtpReceiveProtocolSummary {
    <#
        Groups SMTP receive protocol-log sessions by remote address + connector: sessions,
        first/last seen, EHLO/HELO identities, MAIL FROM / RCPT TO counts, accepted messages
        (250 2.6.0 queued) and 5xx rejections. Same return shape as Get-MessageTrackingClientSummary.
    #>
    param([string[]]$Files = @(), [datetime]$Since = [datetime]::MinValue, [bool]$Sensitive = $false, [int]$TimeBudgetSeconds = 300)
    $cut = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
    $agg = @{}; $stats = @{ Records = 0; Oldest = $null; Newest = $null }
    $failed = 0; $read = 0; $sw = [System.Diagnostics.Stopwatch]::StartNew(); $truncated = $false
    $on = {
        param($r)
        $t = [string]$r['date-time']
        if ($t) {
            if ($null -eq $stats.Oldest -or $t -lt $stats.Oldest) { $stats.Oldest = $t }
            if ($null -eq $stats.Newest -or $t -gt $stats.Newest) { $stats.Newest = $t }
            if ($t -lt $cut) { return }
        }
        $stats.Records++
        $ip = Get-EndpointAddress -Endpoint ([string]$r['remote-endpoint'])
        if (-not $ip) { return }
        $key = '{0}|{1}' -f $ip, [string]$r['connector-id']
        $e = $agg[$key]
        if (-not $e) {
            $e = @{ Ip=$ip; Connector=[string]$r['connector-id']; Sessions=[System.Collections.Generic.HashSet[string]]::new(); First=$t; Last=$t
                    Ehlo=[System.Collections.Generic.HashSet[string]]::new(); MailFrom=0; RcptTo=0; Accepted=0; Rejected=0; SampleFrom=[System.Collections.Generic.HashSet[string]]::new() }
            $agg[$key] = $e
        }
        [void]$e.Sessions.Add([string]$r['session-id'])
        if ($t -and $t -lt $e.First) { $e.First = $t }
        if ($t -and $t -gt $e.Last) { $e.Last = $t }
        $data = [string]$r['data']; $ev = [string]$r['event']
        if ($ev -eq '<') {
            if ($data -match '^(?i)(EHLO|HELO)\s+(\S+)') { if ($e.Ehlo.Count -lt 3) { [void]$e.Ehlo.Add($Matches[2]) } }
            elseif ($data -match '^(?i)MAIL FROM:\s*<?([^>\s]*)') { $e.MailFrom++; if ($e.SampleFrom.Count -lt 3 -and $Matches[1]) { [void]$e.SampleFrom.Add((Protect-EmailAddress -Address $Matches[1] -Sensitive $Sensitive)) } }
            elseif ($data -match '^(?i)RCPT TO:') { $e.RcptTo++ }
        } elseif ($ev -eq '>') {
            if ($data -match '^250 2\.6\.0') { $e.Accepted++ }
            elseif ($data -match '^5\d\d[ -]') { $e.Rejected++ }
        }
    }
    foreach ($f in $Files) {
        if ($sw.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) { $truncated = $true; break }
        try { [void](Read-DelimitedLogRecords -Path $f -OnRecord $on); $read++ } catch { $failed++ }
    }
    $rows = foreach ($e in $agg.Values) {
        [pscustomobject]@{ ClientIp=$e.Ip; ConnectorId=$e.Connector; Sessions=$e.Sessions.Count; FirstSeen=$e.First; LastSeen=$e.Last; EhloIdentities=(@($e.Ehlo) -join ', ')
            MailFromCount=$e.MailFrom; RcptToCount=$e.RcptTo; AcceptedMessages=$e.Accepted; RejectedResponses=$e.Rejected; SampleMailFrom=(@($e.SampleFrom) -join '; ') }
    }
    return @{ Rows=@($rows); RecordsRead=$stats.Records; FilesRead=$read; FilesFailed=$failed; OldestRecord=$stats.Oldest; NewestRecord=$stats.Newest; Truncated=$truncated }
}

function Get-IisSmtpLogSummary {
    <# IIS 6 SMTP service W3C logs (space-delimited): per client IP, connections (EHLO/HELO), MAIL FROM and RCPT TO counts. #>
    param([string[]]$Files = @(), [datetime]$Since = [datetime]::MinValue, [bool]$Sensitive = $false)
    $cut = $Since.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $agg = @{}; $stats = @{ Records = 0; Oldest = $null; Newest = $null }; $failed = 0; $read = 0
    $on = {
        param($r)
        $t = ('{0} {1}' -f $r['date'], $r['time']).Trim()
        if ($t) { if ($null -eq $stats.Oldest -or $t -lt $stats.Oldest) { $stats.Oldest = $t }; if ($null -eq $stats.Newest -or $t -gt $stats.Newest) { $stats.Newest = $t }; if ($t -lt $cut) { return } }
        $stats.Records++
        $ip = [string]$r['c-ip']; if (-not $ip) { return }
        $e = $agg[$ip]
        if (-not $e) { $e = @{ Ip=$ip; Connections=0; MailFrom=0; RcptTo=0; First=$t; Last=$t; SampleFrom=[System.Collections.Generic.HashSet[string]]::new() }; $agg[$ip] = $e }
        if ($t -lt $e.First) { $e.First = $t }; if ($t -gt $e.Last) { $e.Last = $t }
        $m = [string]$r['cs-method']
        if ($m -match '^(?i)(EHLO|HELO)$') { $e.Connections++ }
        elseif ($m -match '^(?i)MAIL$') { $e.MailFrom++; $q = [string]$r['cs-uri-query']; if ($e.SampleFrom.Count -lt 3 -and $q -match '(?i)FROM:<?([^>+\s]*)') { [void]$e.SampleFrom.Add((Protect-EmailAddress -Address $Matches[1] -Sensitive $Sensitive)) } }
        elseif ($m -match '^(?i)RCPT$') { $e.RcptTo++ }
    }
    foreach ($f in $Files) { try { [void](Read-DelimitedLogRecords -Path $f -OnRecord $on -Delimiter ' '); $read++ } catch { $failed++ } }
    $rows = foreach ($e in $agg.Values) { [pscustomobject]@{ ClientIp=$e.Ip; ConnectorId='IIS SMTP service'; Sessions=$e.Connections; FirstSeen=$e.First; LastSeen=$e.Last; EhloIdentities=''; MailFromCount=$e.MailFrom; RcptToCount=$e.RcptTo; AcceptedMessages=$e.MailFrom; RejectedResponses=0; SampleMailFrom=(@($e.SampleFrom) -join '; ') } }
    return @{ Rows=@($rows); RecordsRead=$stats.Records; FilesRead=$read; FilesFailed=$failed; OldestRecord=$stats.Oldest; NewestRecord=$stats.Newest; Truncated=$false }
}

function Merge-SmtpRelayEvidence {
    <#
        Pure: correlates message-tracking and protocol-log rows per client IP. A client is
        'Confirmed active SMTP client' when messages were accepted from it (tracking RECEIVE events
        or 250 2.6.0 responses); 'Possible SMTP client requiring validation' when it only connected.
    #>
    param([object[]]$TrackingRows = @(), [object[]]$ProtocolRows = @())
    $byIp = [ordered]@{}
    foreach ($r in @($TrackingRows) + @($ProtocolRows)) { if ($r -and $r.ClientIp -and -not $byIp.Contains([string]$r.ClientIp)) { $byIp[[string]$r.ClientIp] = $true } }
    $out = foreach ($ip in $byIp.Keys) {
        $t = @($TrackingRows | Where-Object { $_.ClientIp -eq $ip })
        $p = @($ProtocolRows | Where-Object { $_.ClientIp -eq $ip })
        $msgs = [int](($t | Measure-Object -Property MessagesReceived -Sum).Sum)
        $acc = [int](($p | Measure-Object -Property AcceptedMessages -Sum).Sum)
        $times = @(@($t.FirstSeen) + @($p.FirstSeen) + @($t.LastSeen) + @($p.LastSeen) | Where-Object { $_ } | Sort-Object)
        $confirmed = ($msgs -gt 0 -or $acc -gt 0)
        [pscustomobject]@{
            ClientIp=$ip
            ConnectorIds=((@($t.ConnectorId) + @($p.ConnectorId) | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            ClientIdentity=((@($t.ClientHostname) + @($p.EhloIdentities) | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            MessagesInTracking=$msgs; ProtocolSessions=[int](($p | Measure-Object -Property Sessions -Sum).Sum); AcceptedInProtocolLog=$acc
            RejectedResponses=[int](($p | Measure-Object -Property RejectedResponses -Sum).Sum)
            FirstSeen=$(if ($times.Count) { $times[0] } else { '' }); LastSeen=$(if ($times.Count) { $times[-1] } else { '' })
            SampleSenders=((@($t.SampleSenders) + @($p.SampleMailFrom) | Where-Object { $_ } | ForEach-Object { $_ -split '; ' } | Select-Object -Unique | Select-Object -First 3) -join '; ')
            SampleRecipients=((@($t.SampleRecipients) | Where-Object { $_ } | ForEach-Object { $_ -split '; ' } | Select-Object -Unique | Select-Object -First 3) -join '; ')
            EvidenceSources=((@($(if ($t.Count) { 'MessageTracking' }), $(if ($p.Count) { 'ProtocolLog' })) | Where-Object { $_ }) -join ' + ')
            Classification=$(if ($confirmed) { 'Confirmed active SMTP client' } else { 'Possible SMTP client requiring validation' })
            Confidence=$(if ($confirmed) { 'Confirmed' } else { 'Possible' })
            Recommendation=$(if ($confirmed) { 'Active relay dependency found - identify the device/application and migrate it to another SMTP method before decommission' } else { 'Client IP requires identification' })
        }
    }
    return ,@($out)
}

function Get-SmtpRelayAssessment {
    <#
        Pure: the evidence condition behind the client list. Never concludes "unused": the best
        possible outcome is 'No SMTP usage found in available logs', and its recommendation still
        depends on how many days of evidence actually existed and whether connector logging was on.
    #>
    param(
        [bool]$ExchangeInstalled, [bool]$CmdletsAvailable, [object[]]$ReceiveConnectors = @(), $TrackingEnabled = $null,
        [int]$TrackingFiles = 0, [int]$ProtocolFiles = 0, [int]$FilesInWindow = 0, [int]$FilesFailed = 0, [bool]$PermissionDenied = $false,
        [int]$ConfirmedClients = 0, [int]$PossibleClients = 0, [int]$LookbackDays = 7, [double]$CoverageDays = 0, $RetentionDays = $null
    )
    $conditions = [System.Collections.Generic.List[string]]::new()
    if ($ExchangeInstalled -and -not $CmdletsAvailable) { $conditions.Add('Exchange cmdlets unavailable') }
    $noLogConnectors = @($ReceiveConnectors | Where-Object { [string]$_.ProtocolLoggingLevel -eq 'None' -and [string]$_.Enabled -ne 'False' })
    if ($noLogConnectors.Count -gt 0) { $conditions.Add('Protocol logging disabled on the relevant connector') }
    if ($TrackingEnabled -eq $false) { $conditions.Add('Message tracking disabled') }
    if ($PermissionDenied) { $conditions.Add('Permission failure') }
    if (($TrackingFiles + $ProtocolFiles) -eq 0 -and -not $PermissionDenied) { $conditions.Add('Logs unavailable') }
    elseif ($FilesInWindow -eq 0 -and ($TrackingFiles + $ProtocolFiles) -gt 0) { $conditions.Add('Logs aged out') }
    if ($null -ne $RetentionDays -and [double]$RetentionDays -lt $LookbackDays) { $conditions.Add('Logs aged out') }
    if ($ConfirmedClients -gt 0) { $conditions.Add('Confirmed active SMTP client') }
    elseif ($PossibleClients -gt 0) { $conditions.Add('Possible SMTP client requiring validation') }
    elseif ($FilesInWindow -gt 0) { $conditions.Add('No SMTP usage found in available logs') }
    $unique = @($conditions | Select-Object -Unique)

    $status = if ($ConfirmedClients -gt 0) { 'Confirmed active SMTP client' }
              elseif ($PossibleClients -gt 0) { 'Possible SMTP client requiring validation' }
              elseif ($PermissionDenied) { 'Permission failure' }
              elseif ($unique -contains 'Logs unavailable') { 'Logs unavailable' }
              elseif ($unique -contains 'Logs aged out' -and $FilesInWindow -eq 0) { 'Logs aged out' }
              elseif ($noLogConnectors.Count -gt 0) { 'Protocol logging disabled on the relevant connector' }
              else { 'No SMTP usage found in available logs' }
    $rec = [System.Collections.Generic.List[string]]::new()
    if ($ConfirmedClients -gt 0) { $rec.Add('Active relay dependency found'); $rec.Add('Migrate device or application to another SMTP method') }
    if ($PossibleClients -gt 0) { $rec.Add('Client IP requires identification') }
    if ($noLogConnectors.Count -gt 0 -or $TrackingEnabled -eq $false) { $rec.Add('Connector logging not sufficient') }
    if ($CoverageDays -lt 14 -or $status -in @('Logs unavailable','Logs aged out','Permission failure','Protocol logging disabled on the relevant connector')) { $rec.Add('Observation window recommended') }
    if ($status -eq 'No SMTP usage found in available logs' -and $rec.Count -eq 0) { $rec.Add('Safe to continue decommission review') }
    [pscustomobject]@{
        Status=$status; Conditions=($unique -join '; '); Recommendation=(@($rec | Select-Object -Unique) -join '; ')
        UsageProvenUnused=$false   # by design: logs can show use, never prove absence
        ConnectorsWithoutProtocolLogging=(@($noLogConnectors | ForEach-Object { [string]$_.Name }) -join ', ')
        LookbackDays=$LookbackDays; EvidenceCoverageDays=[math]::Round($CoverageDays, 1); ConfirmedClients=$ConfirmedClients; PossibleClients=$PossibleClients
    }
}

#endregion

function Get-ExchangeCmdletInventory {
    <#
        Runs the Exchange Get-* cmdlets in a Windows PowerShell child with the locally registered
        management snap-in (works the same under PowerShell 7). Every value is flattened to text
        so the result survives JSON. Returns $null when the snap-in is missing or the call fails.
    #>
    param([int]$TimeoutSeconds = 240)
    $script = @'
$sn = Get-PSSnapin -Registered -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Microsoft.Exchange.Management.PowerShell.*' } | Sort-Object Name -Descending | Select-Object -First 1
if (-not $sn) { return [pscustomobject]@{ CmdletsAvailable=$false; Error='Exchange management snap-in is not registered on this server' } }
Add-PSSnapin $sn.Name -ErrorAction Stop
$me = $env:COMPUTERNAME
function J($x) { (@($x) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) -join '; ' }
function T($sb) { try { & $sb } catch { @() } }
$srv = T { Get-ExchangeServer -Identity $me -ErrorAction Stop }
$ts = T { if (Get-Command Get-TransportService -ErrorAction SilentlyContinue) { Get-TransportService -Identity $me -ErrorAction Stop } else { Get-TransportServer -Identity $me -ErrorAction Stop } }
$fe = T { Get-FrontendTransportService -Identity $me -ErrorAction Stop }
$mb = T { Get-MailboxTransportService -Identity $me -ErrorAction Stop }
$anon = @{}
foreach ($rc in @(T { Get-ReceiveConnector -Server $me -ErrorAction Stop })) {
    $anon[[string]$rc.Identity] = [bool](@(T { Get-ADPermission -Identity $rc.Identity -ErrorAction Stop | Where-Object { [string]$_.ExtendedRights -match 'Accept-Any-Recipient' -and [string]$_.User -match 'ANONYMOUS' -and -not $_.Deny } }).Count -gt 0)
}
[pscustomobject]@{
    CmdletsAvailable=$true; SnapIn=$sn.Name
    Server=@($srv | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Edition=[string]$_.Edition; AdminDisplayVersion=[string]$_.AdminDisplayVersion; ServerRole=[string]$_.ServerRole; Site=[string]$_.Site } })
    Receive=@(T { Get-ReceiveConnector -Server $me -ErrorAction Stop } | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Identity=[string]$_.Identity; Enabled=[string]$_.Enabled; TransportRole=[string]$_.TransportRole; Bindings=(J $_.Bindings); RemoteIPRanges=(J $_.RemoteIPRanges); PermissionGroups=[string]$_.PermissionGroups; AuthMechanism=[string]$_.AuthMechanism; Fqdn=[string]$_.Fqdn; Banner=[string]$_.Banner; ProtocolLoggingLevel=[string]$_.ProtocolLoggingLevel; AnonymousRelay=[string]$anon[[string]$_.Identity] } })
    Send=@(T { Get-SendConnector -ErrorAction Stop } | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Enabled=[string]$_.Enabled; AddressSpaces=(J $_.AddressSpaces); SmartHosts=(J $_.SmartHosts); SourceTransportServers=(J $_.SourceTransportServers); DNSRoutingEnabled=[string]$_.DNSRoutingEnabled; Fqdn=[string]$_.Fqdn; ProtocolLoggingLevel=[string]$_.ProtocolLoggingLevel; RequireTLS=[string]$_.RequireTLS } })
    Accepted=@(T { Get-AcceptedDomain -ErrorAction Stop } | ForEach-Object { [pscustomobject]@{ DomainName=[string]$_.DomainName; DomainType=[string]$_.DomainType; Default=[string]$_.Default } })
    Remote=@(T { Get-RemoteDomain -ErrorAction Stop } | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; DomainName=[string]$_.DomainName; IsInternal=[string]$_.IsInternal; TargetDeliveryDomain=[string]$_.TargetDeliveryDomain } })
    Hybrid=@(T { Get-HybridConfiguration -ErrorAction Stop } | ForEach-Object { [pscustomobject]@{ Domains=(J $_.Domains); Features=(J $_.Features); OnPremisesSmartHost=[string]$_.OnPremisesSmartHost; SendingTransportServers=(J $_.SendingTransportServers); ReceivingTransportServers=(J $_.ReceivingTransportServers); EdgeTransportServers=(J $_.EdgeTransportServers) } })
    Certs=@(T { Get-ExchangeCertificate -Server $me -ErrorAction Stop } | ForEach-Object { [pscustomobject]@{ Thumbprint=[string]$_.Thumbprint; Subject=[string]$_.Subject; Services=[string]$_.Services; NotAfter=[string]$_.NotAfter; IsSelfSigned=[string]$_.IsSelfSigned; CertificateDomains=(J $_.CertificateDomains) } })
    Queues=@(T { Get-Queue -Server $me -ErrorAction Stop } | ForEach-Object { [pscustomobject]@{ Identity=[string]$_.Identity; DeliveryType=[string]$_.DeliveryType; Status=[string]$_.Status; MessageCount=[string]$_.MessageCount; NextHopDomain=[string]$_.NextHopDomain } })
    Logs=@(
        @($ts | ForEach-Object { [pscustomobject]@{ Service='Transport'; MessageTrackingLogEnabled=[string]$_.MessageTrackingLogEnabled; MessageTrackingLogPath=[string]$_.MessageTrackingLogPath; MessageTrackingLogMaxAge=[string]$_.MessageTrackingLogMaxAge; ReceiveProtocolLogPath=[string]$_.ReceiveProtocolLogPath; ReceiveProtocolLogMaxAge=[string]$_.ReceiveProtocolLogMaxAge; SendProtocolLogPath=[string]$_.SendProtocolLogPath } })
        @($fe | ForEach-Object { [pscustomobject]@{ Service='FrontendTransport'; MessageTrackingLogEnabled=''; MessageTrackingLogPath=''; MessageTrackingLogMaxAge=''; ReceiveProtocolLogPath=[string]$_.ReceiveProtocolLogPath; ReceiveProtocolLogMaxAge=[string]$_.ReceiveProtocolLogMaxAge; SendProtocolLogPath=[string]$_.SendProtocolLogPath } })
        @($mb | ForEach-Object { [pscustomobject]@{ Service='MailboxTransport'; MessageTrackingLogEnabled=''; MessageTrackingLogPath=''; MessageTrackingLogMaxAge=''; ReceiveProtocolLogPath=[string]$_.ReceiveProtocolLogPath; ReceiveProtocolLogMaxAge=[string]$_.ReceiveProtocolLogMaxAge; SendProtocolLogPath=[string]$_.SendProtocolLogPath } })
    )
}
'@
    return Invoke-WindowsPowerShellJson -Script $script -TimeoutSeconds $TimeoutSeconds
}

function ConvertTo-DaysFromTimeSpanText {
    <# Pure: Exchange MaxAge text ('30.00:00:00') -> days, or $null. #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $ts = [timespan]::Zero
    if ([timespan]::TryParse($Text, [ref]$ts)) { return [math]::Round($ts.TotalDays, 1) }
    return $null
}

function Get-RecentLogFiles {
    <# Newest-first log files under the given folders (non-recursive per folder), capped. Splits in-window vs older. #>
    param([string[]]$Folders = @(), [string]$Filter = '*.log', [datetime]$Since, [int]$MaxFiles = 200)
    $all = [System.Collections.Generic.List[object]]::new(); $denied = $false
    foreach ($d in @($Folders | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            if (-not (Test-Path -LiteralPath $d)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter $Filter -File -ErrorAction Stop)) { $all.Add($f) }
        } catch [System.UnauthorizedAccessException] { $denied = $true } catch { if ($_.Exception.Message -match '(?i)denied') { $denied = $true } }
    }
    $sorted = @($all | Sort-Object LastWriteTime -Descending)
    $inWindow = @($sorted | Where-Object { $_.LastWriteTime -ge $Since } | Select-Object -First $MaxFiles)
    return @{ All=$sorted; InWindow=$inWindow; Denied=$denied; Capped=[bool](@($sorted | Where-Object { $_.LastWriteTime -ge $Since }).Count -gt $MaxFiles) }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $sensitive = [bool]$Context.Parameters['IncludeSensitiveEvidence']
    $days = [int]$Context.Parameters['ExchangeLogDays']; if ($days -le 0) { $days = 7 }
    $maxFiles = 200; try { $mf = $Context.Config.Default.defaults.exchangeLogMaxFiles; if ($mf) { $maxFiles = [int]$mf } } catch { }
    $budget = 300; try { $mt = $Context.Config.Default.defaults.moduleTimeoutSeconds; if ($mt) { $budget = [math]::Max(60, [int]([int]$mt / 3)) } } catch { }
    $since = (Get-Date).AddDays(-$days)
    $out = @{}
    foreach ($k in (Get-DiscoveryModuleMetadata).ProducesDatasets) { $out[$k] = @() }

    $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
    $install = Get-ExchangeInstallInfo
    $exInstalled = [bool]$install
    $inv = $null

    # ---- Exchange inventory ----
    if ($exInstalled) {
        $out.ExchangeServices = @($svcRows | Where-Object { $_.Name -like 'MSExchange*' -or $_.Name -in @('HostControllerService','FMS','SearchExchangeTracing') } | ForEach-Object { [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; Status=$_.Status; StartMode=$_.StartMode; StartName=$_.StartName } })
        $inv = Get-ExchangeCmdletInventory
        if (-not $inv -or -not $inv.CmdletsAvailable) {
            $why = if ($inv -and $inv.Error) { [string]$inv.Error } else { 'Exchange Management Shell snap-in could not be loaded or did not answer in time' }
            Add-Limitation -Context $Context -Module 'ExchangeSmtp' -Message ("Exchange cmdlets unavailable: {0}. Connector, certificate, queue and logging configuration were not read; log analysis uses default paths." -f $why) -Impact 'Partial Exchange inventory' | Out-Null
        }
        $vi = Get-ExchangeVersionInfo -Version $install.Version
        $srv = if ($inv -and $inv.CmdletsAvailable) { @($inv.Server)[0] } else { $null }
        $out.ExchangeServer = @([pscustomobject]@{
            ServerName=$env:COMPUTERNAME; ProductName=$vi.ProductName; Version=$install.Version; AdminDisplayVersion=$(if ($srv) { $srv.AdminDisplayVersion } else { '' })
            Edition=$(if ($srv) { $srv.Edition } else { '' }); ServerRole=$(if ($srv) { $srv.ServerRole } else { '' }); ConfiguredRoles=($install.Roles -join ', ')
            ManagementToolsOnly=[bool](@($install.Roles | Where-Object { $_ -ne 'AdminTools' }).Count -eq 0); InstallPath=$install.InstallPath
            SupportEnd=$vi.SupportEnd; IsUnsupportedVersion=$vi.IsUnsupported; CmdletsAvailable=[bool]($inv -and $inv.CmdletsAvailable)
            HybridConfigured=[bool]($inv -and $inv.CmdletsAvailable -and @($inv.Hybrid).Count -gt 0)
            ReceiveConnectorCount=$(if ($inv -and $inv.CmdletsAvailable) { @($inv.Receive).Count } else { $null })
            AnonymousRelayConnectors=$(if ($inv -and $inv.CmdletsAvailable) { (@($inv.Receive | Where-Object { $_.AnonymousRelay -eq 'True' } | ForEach-Object { $_.Name }) -join ', ') } else { '' })
        })
        if ($inv -and $inv.CmdletsAvailable) {
            $out.ExchangeReceiveConnectors = @($inv.Receive | Where-Object { $_ }); $out.ExchangeSendConnectors = @($inv.Send | Where-Object { $_ })
            $out.ExchangeAcceptedDomains = @($inv.Accepted | Where-Object { $_ }); $out.ExchangeRemoteDomains = @($inv.Remote | Where-Object { $_ })
            $out.ExchangeHybrid = @($inv.Hybrid | Where-Object { $_ }); $out.ExchangeCertificates = @($inv.Certs | Where-Object { $_ })
            $out.ExchangeQueues = @($inv.Queues | Where-Object { $_ }); $out.ExchangeLogSettings = @($inv.Logs | Where-Object { $_ })
            foreach ($rc in $out.ExchangeReceiveConnectors) {
                if ($rc.RemoteIPRanges) { Add-DependencyEdge -Context $Context -SourceType 'Receive connector' -SourceName $rc.Name -DependencyType 'AcceptsMailFrom' -Target $rc.RemoteIPRanges -Evidence ("Bindings {0}; auth {1}" -f $rc.Bindings, $rc.AuthMechanism) -Confidence 'Confirmed' -SourceDataset 'ExchangeReceiveConnectors' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Which devices and applications are inside these remote IP ranges, and where will they relay after the change?' | Out-Null }
            }
        }
        # Exchange virtual directories and shares, from what IIS and FileShares already collected.
        if ($Context.DataSets.Contains('IisApplications')) { $out.ExchangeIisApplications = @($Context.DataSets['IisApplications'].Rows | Where-Object { $_.Path -match '(?i)^/(owa|ecp|ews|mapi|rpc|oab|autodiscover|Microsoft-Server-ActiveSync|PowerShell)\b' -or $_.PhysicalPath -match '(?i)Exchange Server' }) }
        if ($Context.DataSets.Contains('SmbShares')) { $out.ExchangeShares = @($Context.DataSets['SmbShares'].Rows | Where-Object { $_.Path -and $install.InstallPath -and ([string]$_.Path).StartsWith(([string]$install.InstallPath).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or $_.Name -match '(?i)^Address$' }) }
    }

    # ---- Log locations: configured (cmdlets) first, Exchange defaults otherwise ----
    $trackingDirs = @(); $protocolDirs = @()
    if ($exInstalled) {
        $base = [string]$install.InstallPath
        foreach ($l in @($out.ExchangeLogSettings)) { if ($l.MessageTrackingLogPath) { $trackingDirs += $l.MessageTrackingLogPath }; if ($l.ReceiveProtocolLogPath) { $protocolDirs += $l.ReceiveProtocolLogPath } }
        if ($base) {
            if ($trackingDirs.Count -eq 0) { $trackingDirs += (Join-Path $base 'TransportRoles\Logs\MessageTracking') }
            if ($protocolDirs.Count -eq 0) { $protocolDirs += @((Join-Path $base 'TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpReceive'), (Join-Path $base 'TransportRoles\Logs\Hub\ProtocolLog\SmtpReceive'), (Join-Path $base 'TransportRoles\Logs\ProtocolLog\SmtpReceive')) }
        }
    }
    $trk = Get-RecentLogFiles -Folders $trackingDirs -Filter 'MSGTRK*.LOG' -Since $since -MaxFiles $maxFiles
    $prt = Get-RecentLogFiles -Folders $protocolDirs -Filter 'RECV*.LOG' -Since $since -MaxFiles $maxFiles
    $iisSmtp = @{ All=@(); InWindow=@(); Denied=$false; Capped=$false }
    if (@($svcRows | Where-Object { $_.Name -eq 'SMTPSVC' }).Count) {
        $iisDirs = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'System32\LogFiles') -Directory -Filter 'SmtpSvc*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $iisSmtp = Get-RecentLogFiles -Folders $iisDirs -Filter '*.log' -Since $since -MaxFiles $maxFiles
        if ($iisDirs.Count -eq 0) { Add-Limitation -Context $Context -Module 'ExchangeSmtp' -Message 'IIS SMTP service present but no SmtpSvc log folder found; IIS SMTP logging may be disabled.' | Out-Null }
    }
    foreach ($set in @($trk, $prt, $iisSmtp)) { if ($set.Capped) { Add-Limitation -Context $Context -Module 'ExchangeSmtp' -Message ("More than {0} log files fell inside the {1}-day window; only the newest {0} were analysed." -f $maxFiles, $days) -Impact 'Older days in the window not analysed' | Out-Null } }

    $tSum = Get-MessageTrackingClientSummary -Files @($trk.InWindow | ForEach-Object { $_.FullName }) -Since $since -Sensitive $sensitive -TimeBudgetSeconds $budget
    $pSum = Get-SmtpReceiveProtocolSummary -Files @($prt.InWindow | ForEach-Object { $_.FullName }) -Since $since -Sensitive $sensitive -TimeBudgetSeconds $budget
    $iSum = Get-IisSmtpLogSummary -Files @($iisSmtp.InWindow | ForEach-Object { $_.FullName }) -Since $since -Sensitive $sensitive
    foreach ($s in @($tSum, $pSum)) { if ($s.Truncated) { Add-Limitation -Context $Context -Module 'ExchangeSmtp' -Message ("SMTP log analysis stopped at its {0}s time budget; client counts are a lower bound." -f $budget) -Impact 'Partial SMTP evidence' | Out-Null } }
    $clients = Merge-SmtpRelayEvidence -TrackingRows $tSum.Rows -ProtocolRows (@($pSum.Rows) + @($iSum.Rows))
    foreach ($c in $clients) {
        if ($c.Confidence -eq 'Confirmed') { Add-DependencyEdge -Context $Context -SourceType 'SMTP client' -SourceName $c.ClientIp -DependencyType 'RelaysMailThrough' -Target $env:COMPUTERNAME -Evidence ("{0} message(s) in tracking, {1} accepted in protocol log ({2})" -f $c.MessagesInTracking, $c.AcceptedInProtocolLog, $c.ConnectorIds) -Confidence 'Confirmed' -SourceDataset 'SmtpRelayClients' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'What device or application is at this address, and how will it send mail after this server is retired?' | Out-Null }
    }
    $out.SmtpRelayClients = @($clients)

    # Coverage = how many days of evidence actually exist, not how many were asked for.
    $times = @(@($tSum.OldestRecord, $pSum.OldestRecord, $iSum.OldestRecord) | Where-Object { $_ } | ForEach-Object { try { [datetime]::Parse(($_ -replace 'Z$',''), [Globalization.CultureInfo]::InvariantCulture) } catch { } } | Sort-Object)
    $coverage = if ($times.Count) { [math]::Min($days, ((Get-Date).ToUniversalTime() - $times[0]).TotalDays) } else { 0 }
    $trackEnabled = $null
    $trackSetting = @($out.ExchangeLogSettings | Where-Object { $_.Service -eq 'Transport' } | Select-Object -First 1)
    if ($trackSetting.Count) { $trackEnabled = ([string]$trackSetting[0].MessageTrackingLogEnabled -eq 'True') }
    $retention = $null
    if ($trackSetting.Count) { $retention = ConvertTo-DaysFromTimeSpanText -Text $trackSetting[0].MessageTrackingLogMaxAge }
    $a = Get-SmtpRelayAssessment -ExchangeInstalled $exInstalled -CmdletsAvailable ([bool]($inv -and $inv.CmdletsAvailable)) -ReceiveConnectors @($out.ExchangeReceiveConnectors) -TrackingEnabled $trackEnabled `
        -TrackingFiles @($trk.All).Count -ProtocolFiles (@($prt.All).Count + @($iisSmtp.All).Count) -FilesInWindow (@($trk.InWindow).Count + @($prt.InWindow).Count + @($iisSmtp.InWindow).Count) `
        -FilesFailed ($tSum.FilesFailed + $pSum.FilesFailed + $iSum.FilesFailed) -PermissionDenied ([bool]($trk.Denied -or $prt.Denied -or $iisSmtp.Denied)) `
        -ConfirmedClients @($clients | Where-Object { $_.Confidence -eq 'Confirmed' }).Count -PossibleClients @($clients | Where-Object { $_.Confidence -eq 'Possible' }).Count `
        -LookbackDays $days -CoverageDays $coverage -RetentionDays $retention

    # ---- Optional, privacy-sensitive raw log copy ----
    $copied = 0; $copyPath = ''
    if ([bool]$Context.Parameters['CopyExchangeRawLogs']) {
        try {
            $copyPath = Join-Path $Context.Paths['Raw'] 'exchange-logs'
            $capBytes = [int64]2GB; $total = [int64]0
            foreach ($set in @(@{ N='MessageTracking'; F=$trk.InWindow }, @{ N='SmtpReceive'; F=$prt.InWindow }, @{ N='IisSmtp'; F=$iisSmtp.InWindow })) {
                $dest = Join-Path $copyPath $set.N
                foreach ($f in @($set.F)) {
                    if ($total + $f.Length -gt $capBytes) { Add-Limitation -Context $Context -Module 'ExchangeSmtp' -Message 'Raw Exchange log copy stopped at the 2 GB cap.' | Out-Null; break }
                    Ensure-Directory -Path $dest | Out-Null
                    # Read-shared copy: Exchange may be writing today's file.
                    $src = [System.IO.FileStream]::new($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try { $dst = [System.IO.File]::Create((Join-Path $dest $f.Name)); try { $src.CopyTo($dst) } finally { $dst.Dispose() } } finally { $src.Dispose() }
                    $total += $f.Length; $copied++
                }
            }
            Add-Limitation -Context $Context -Module 'ExchangeSmtp' -Message ("-CopyExchangeRawLogs: {0} raw log file(s) copied to evidence\raw\exchange-logs. They contain email addresses and message metadata - handle the run folder accordingly." -f $copied) -Impact 'Privacy-sensitive evidence present' | Out-Null
        } catch { Add-Limitation -Context $Context -Module 'ExchangeSmtp' -Message 'Raw Exchange log copy failed.' -Reason $_.Exception.Message | Out-Null }
    }

    $out.SmtpRelayAssessment = @([pscustomobject]@{
        ServerName=$env:COMPUTERNAME; ExchangeInstalled=$exInstalled; IisSmtpServicePresent=[bool](@($svcRows | Where-Object { $_.Name -eq 'SMTPSVC' }).Count)
        CmdletsAvailable=[bool]($inv -and $inv.CmdletsAvailable); MessageTrackingEnabled=$(if ($null -eq $trackEnabled) { 'Unknown' } else { [string]$trackEnabled }); MessageTrackingRetentionDays=$retention
        Status=$a.Status; Conditions=$a.Conditions; Recommendation=$a.Recommendation; UsageProvenUnused=$a.UsageProvenUnused
        ConnectorsWithoutProtocolLogging=$a.ConnectorsWithoutProtocolLogging; LookbackDays=$days; EvidenceCoverageDays=$a.EvidenceCoverageDays
        TrackingFilesAnalysed=$tSum.FilesRead; ProtocolFilesAnalysed=($pSum.FilesRead + $iSum.FilesRead); FilesFailed=($tSum.FilesFailed + $pSum.FilesFailed + $iSum.FilesFailed)
        RecordsInWindow=($tSum.RecordsRead + $pSum.RecordsRead + $iSum.RecordsRead); ConfirmedClients=$a.ConfirmedClients; PossibleClients=$a.PossibleClients
        SensitiveEvidenceIncluded=$sensitive; RawLogsCopied=$copied; RawLogCopyPath=$(if ($copied) { 'evidence\raw\exchange-logs' } else { '' })
    })

    # ---- SMTP connections open right now (point in time) ----
    if ($Context.DataSets.Contains('EstablishedConnections')) {
        $out.SmtpConnections = @($Context.DataSets['EstablishedConnections'].Rows | Where-Object { [string]$_.RemotePort -in $script:SmtpPorts -or [string]$_.LocalPort -in $script:SmtpPorts } | ForEach-Object {
            [pscustomobject]@{ Direction=$(if ([string]$_.LocalPort -in $script:SmtpPorts) { 'Inbound to this server' } else { 'Outbound from this server' }); LocalPort=$_.LocalPort; RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort; Process=$_.Process; ObservedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') } })
        foreach ($c in @($out.SmtpConnections | Where-Object { $_.Direction -like 'Outbound*' })) { Add-DependencyEdge -Context $Context -SourceType 'Process' -SourceName ([string]$c.Process) -DependencyType 'SendsMailVia' -Target ("{0}:{1}" -f $c.RemoteAddress, $c.RemotePort) -Evidence 'Established SMTP connection at collection time' -Confidence 'Likely' -SourceDataset 'SmtpConnections' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Does this application keep working if that SMTP relay changes?' | Out-Null }
    }

    if ($exInstalled -or $out.SmtpRelayClients.Count -gt 0) {
        Add-Unknown -Context $Context -Unknown ("SMTP relay evidence covers {0} day(s) ({1})." -f $a.EvidenceCoverageDays, $a.Status) -WhyItMatters 'Devices that send monthly or quarterly (scanners, billing runs, UPS alerts) do not appear in a short window; absence of evidence is not evidence of absence.' -Module 'ExchangeSmtp' -RecommendedValidationQuestion 'Which devices and applications are known to send mail through this server, and can an observation window cover month-end?' | Out-Null
    }
    return ,$out
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    $desc = @{
        ExchangeServer='Exchange server identity, version/support, roles, cmdlet availability.'; ExchangeServices='Exchange Windows services.'
        ExchangeReceiveConnectors='Receive connectors (bindings, remote IP ranges, auth, logging, anonymous relay).'; ExchangeSendConnectors='Send connectors (address spaces, smart hosts, source servers).'
        ExchangeAcceptedDomains='Accepted domains.'; ExchangeRemoteDomains='Remote domains.'; ExchangeHybrid='Hybrid configuration.'
        ExchangeCertificates='Exchange certificates and assigned services (no private keys).'; ExchangeQueues='Transport queues at collection time.'
        ExchangeLogSettings='Message tracking / protocol log paths and retention per transport service.'; ExchangeIisApplications='Exchange IIS virtual directories.'
        ExchangeShares='Exchange-related SMB shares.'; SmtpRelayClients='SMTP clients seen in existing logs (message tracking + protocol logs), correlated per IP.'
        SmtpRelayAssessment='SMTP relay evidence condition and recommendation (never asserts non-use).'; SmtpConnections='SMTP TCP connections open at collection time.'
    }
    # Literal names (not a loop over metadata) so the self-check can match them to ProducesDatasets.
    Add-DataSet -Context $Context -Name 'ExchangeServer' -Description $desc['ExchangeServer'] -Rows (& $get 'ExchangeServer') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeServices' -Description $desc['ExchangeServices'] -Rows (& $get 'ExchangeServices') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeReceiveConnectors' -Description $desc['ExchangeReceiveConnectors'] -Rows (& $get 'ExchangeReceiveConnectors') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeSendConnectors' -Description $desc['ExchangeSendConnectors'] -Rows (& $get 'ExchangeSendConnectors') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeAcceptedDomains' -Description $desc['ExchangeAcceptedDomains'] -Rows (& $get 'ExchangeAcceptedDomains') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeRemoteDomains' -Description $desc['ExchangeRemoteDomains'] -Rows (& $get 'ExchangeRemoteDomains') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeHybrid' -Description $desc['ExchangeHybrid'] -Rows (& $get 'ExchangeHybrid') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeCertificates' -Description $desc['ExchangeCertificates'] -Rows (& $get 'ExchangeCertificates') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeQueues' -Description $desc['ExchangeQueues'] -Rows (& $get 'ExchangeQueues') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeLogSettings' -Description $desc['ExchangeLogSettings'] -Rows (& $get 'ExchangeLogSettings') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeIisApplications' -Description $desc['ExchangeIisApplications'] -Rows (& $get 'ExchangeIisApplications') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'ExchangeShares' -Description $desc['ExchangeShares'] -Rows (& $get 'ExchangeShares') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'SmtpRelayClients' -Description $desc['SmtpRelayClients'] -Rows (& $get 'SmtpRelayClients') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'SmtpRelayAssessment' -Description $desc['SmtpRelayAssessment'] -Rows (& $get 'SmtpRelayAssessment') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
    Add-DataSet -Context $Context -Name 'SmtpConnections' -Description $desc['SmtpConnections'] -Rows (& $get 'SmtpConnections') -Visibility 'Internal' -SourceModule 'ExchangeSmtp' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('SmtpRelayAssessment') -and @($Context.DataSets['SmtpRelayAssessment'].Rows).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'Email' -Module 'ExchangeSmtp' -Audience 'Both' -Question 'Which copiers, scanners, line-of-business applications, alerts or scripts send email through this server, and who can confirm each one?' | Out-Null
        }
        if ($Context.DataSets.Contains('ExchangeServer') -and @($Context.DataSets['ExchangeServer'].Rows).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'Email' -Module 'ExchangeSmtp' -Audience 'Both' -Question 'Is any mailbox, public folder or recipient management still done on this Exchange server, and is a supported management path (Exchange management tools or the Exchange SE successor) agreed before it is removed?' | Out-Null
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions',
    'Get-ExchangeInstallInfo','Get-ExchangeVersionInfo','Protect-EmailAddress','Read-DelimitedLogRecords','Split-QuotedCsvLine','Get-EndpointAddress',
    'Get-MessageTrackingClientSummary','Get-SmtpReceiveProtocolSummary','Get-IisSmtpLogSummary','Merge-SmtpRelayEvidence','Get-SmtpRelayAssessment',
    'Get-ExchangeCmdletInventory','ConvertTo-DaysFromTimeSpanText','Get-RecentLogFiles'
