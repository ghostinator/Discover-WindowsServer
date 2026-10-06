<#
.SYNOPSIS
    Enumerates candidate servers (AD and/or a subnet scan) and runs Discover-WindowsServer.ps1
    against a chosen set of them remotely, pulling each result back to one local folder.

.DESCRIPTION
    Automates the manual remote-run procedure already documented and proven in HANDOFF.md
    ("Run the toolkit on a remote machine"): reach the target over WinRM (Kerberos - never
    CredSSP, never TrustedHosts manipulation; that combination is flagged in HANDOFF.md as a
    lab-only weakening, not something this tool does generally), stage the toolkit via
    Copy-Item -ToSession, run it as a SYSTEM scheduled task (a task, not a direct Invoke-Command
    scriptblock, because a job running inside a PSSession dies the moment that session closes -
    HANDOFF.md already learned this the hard way), poll for completion, pull the finished output
    folder back via Copy-Item -FromSession, then always clean up the remote staging/output/task
    regardless of outcome. The engine itself (Discover-WindowsServer.ps1) is untouched by any of
    this - still local-only, still read-only, still writes only inside its own output folder.
    By default this script never enables, configures, or otherwise touches WinRM on a target -
    an unreachable target is reported and skipped, not fixed. -EnableWinRmIfUnreachable is the
    one deliberate, explicit-opt-in exception: see "OPT-IN WINRM BOOTSTRAP" below before turning
    it on.

    OPT-IN WINRM BOOTSTRAP (-EnableWinRmIfUnreachable, off by default): WinRM can't turn itself
    on remotely - if a target has no listener, there's no remoting channel to run
    Enable-PSRemoting through in the first place. When this switch is on, an unreachable target
    is instead bootstrapped over WMI/DCOM (port 135 + dynamic RPC, not 5985 - see
    Invoke-RemoteProcessViaDcom), which is enabled by default on stock Windows. Worth knowing
    plainly: remotely creating a process via WMI is also a well-known lateral-movement technique
    (MITRE ATT&CK T1047) that EDR/SIEM tooling commonly watches for - harmless in your own lab,
    but on a real client engagement this is worth a heads-up in the scoping conversation, not a
    surprise on their security team's dashboard. WinRM is reverted (disabled, service stopped,
    firewall rule closed) immediately after that target's results are pulled back - never left
    enabled longer than that one target's own run, and never touched at all on a target that was
    already reachable to begin with.

    TWO WAYS THIS FILE IS USED:
      1. Dot-sourced, for the pure discovery functions (Get-AdServerCandidate,
         Invoke-SubnetWinRmScan, Merge-DiscoveryCandidate) - this is how the GUI's Fleet tab
         builds its candidate picker in-process, and how Pester reaches them for testing.
      2. Run directly with -TargetComputerNames, which does the actual remote-execution loop
         against the operator-chosen list.

    CREDENTIAL HANDLING - memory-only, deliberately not reusing tools\Send-DiscoveryOutput.ps1's
    DPAPI credential store: a leaked domain admin credential is a much bigger blast radius than
    a leaked delivery API key, so this one is never written to disk. The GUI prompts via
    Get-Credential and holds the result only in a script-scoped variable for that session.

    HOW THE CREDENTIAL REACHES THE REMOTE-RUN LOOP WITHOUT EVER TOUCHING A FILE OR A COMMAND
    LINE - -CredentialFromStdin: read two lines from standard input (username, then a base64'd
    UTF8 password) and reconstruct -DomainCredential from them, instead of taking it as a normal
    parameter. The GUI writes those two lines to this process's stdin right after starting it -
    in memory only, never a file, never a command-line argument (which even a launcher-script
    can't avoid exposing, since Get-Process/WMI can read a live process's command line, but not
    what was piped to its stdin).

    THIS REPLACED AN EARLIER, LESS RELIABLE DESIGN worth knowing about: launching this script as
    a child process via `Start-Process -Credential $domainCredential` (no -DomainCredential
    parameter at all, relying on the child's own ambient identity for every downstream
    New-PSSession) avoids the stdin plumbing entirely, and DOES work for the DCOM/WMI calls
    -EnableWinRmIfUnreachable makes. But tested live against this lab: the identical account,
    identical target, identical -Authentication Kerberos, failed with "Access is denied" when
    authenticating via that ambient identity while succeeding immediately with an EXPLICIT
    -Credential every time. WinRM's authorization check apparently doesn't treat a
    CreateProcessWithLogonW-derived token in that scheduled/impersonated context as equivalent to
    one obtained via an explicit credential, even though both resolve to the same account - this
    isn't the double-hop problem (there's no second hop here), just an observed reliability gap
    in that specific token path. Explicit credential is reliable; ambient identity is not - so
    that's what this script insists on now.

.PARAMETER TargetComputerNames
    One or more resolved computer names/FQDNs to run the discovery engine against. Required
    when running this script directly.

.PARAMETER EngagementFolder
    Where each target's pulled-back output folder (and the fleet status/results files) land -
    e.g. C:\Temp\FleetRuns\AcmeCorp_20260925_120000\.

.EXAMPLE
    # Dot-source for the picker functions only (no remote execution):
    . .\tools\Invoke-FleetDiscovery.ps1
    $ad = Get-AdServerCandidate -DomainCredential $cred
    $scan = Invoke-SubnetWinRmScan -HostList (ConvertTo-CidrHostRange -Cidr '10.0.5.0/24')
    Merge-DiscoveryCandidate -AdResults $ad -ScanResults $scan

.EXAMPLE
    # Actually run against two chosen targets - typically launched by the GUI with
    # -CredentialFromStdin (see the CREDENTIAL HANDLING note above); shown here with
    # -DomainCredential directly for CLI use from an already-elevated domain admin prompt:
    .\tools\Invoke-FleetDiscovery.ps1 -TargetComputerNames 'labsrv19.corp.local','labsrv16.corp.local' `
        -EngagementFolder 'C:\Temp\FleetRuns\Acme_20260925' -Mode Deep -DomainCredential $cred
#>
[CmdletBinding()]
param(
    [string[]]$TargetComputerNames,
    [string]$EngagementFolder,
    [pscredential]$DomainCredential,
    [switch]$CredentialFromStdin,
    [string]$Mode = 'Fast',
    [string]$ProjectType = 'GeneralDiscovery',
    [string]$ComplianceLens = 'None',
    [int]$TimeoutMinutes = 60,
    [switch]$EnableWinRmIfUnreachable,
    # 1 (the default) is plain sequential execution - identical behavior to before this existed,
    # since a runspace pool of size 1 can only ever run one job at a time anyway. Raise it to run
    # several targets at once; see Invoke-FleetRunsInParallel's own comment for why one pool
    # handles both cases rather than branching into two separate code paths.
    [int]$MaxConcurrency = 1
)

$ErrorActionPreference = 'Stop'

#region Enumeration (pure-ish - network/AD I/O, but no local state mutation) -----

function ConvertTo-CidrHostRange {
    <#
        Expands an IPv4 CIDR (e.g. "10.0.5.0/24") to its usable host addresses (network and
        broadcast excluded). Refuses anything larger than a /22 (1022 hosts) - a guardrail
        against a fat-fingered /8 turning a subnet scan into a scan of the internet.
    #>
    param([Parameter(Mandatory)][string]$Cidr)
    # [regex]::Match(), not -match/$Matches - the automatic $Matches variable turned out not to
    # be reliably fresh across repeated calls to this function in the same session (seen when
    # this was tested back-to-back under Pester: a second call's $Matches read stale state from
    # the first). Capturing the Match object directly sidesteps that entirely.
    $m = [regex]::Match($Cidr, '^(?<addr>\d{1,3}(\.\d{1,3}){3})/(?<prefix>\d{1,2})$')
    if (-not $m.Success) {
        throw "'$Cidr' is not a valid IPv4 CIDR (expected e.g. 10.0.5.0/24)."
    }
    $prefix = [int]$m.Groups['prefix'].Value
    if ($prefix -lt 22 -or $prefix -gt 32) {
        throw "CIDR prefix /$prefix is outside the supported /22-/32 range - refusing to expand anything broader than a /22 as a safeguard."
    }
    $addrBytes = [System.Net.IPAddress]::Parse($m.Groups['addr'].Value).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($addrBytes) }
    # Int64 throughout (not [uint32]) so the shift/mask arithmetic below can't overflow into a
    # negative value PowerShell then refuses to convert back to [uint32] - only the final
    # per-address byte conversion casts down, once each value is already known to be in range.
    $addrInt = [int64]([BitConverter]::ToUInt32($addrBytes, 0))
    $hostBits = 32 - $prefix
    $fullMask = [int64]4294967295
    $networkInt = $addrInt -band (($fullMask -shl $hostBits) -band $fullMask)
    $hostCount = [int64]([Math]::Pow(2, $hostBits))
    $firstHost = if ($hostBits -le 1) { $networkInt } else { $networkInt + 1 }
    $lastHost  = if ($hostBits -le 1) { $networkInt + $hostCount - 1 } else { $networkInt + $hostCount - 2 }
    $addresses = for ($i = $firstHost; $i -le $lastHost; $i++) {
        $bytes = [BitConverter]::GetBytes([uint32]$i)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        [System.Net.IPAddress]::new($bytes).ToString()
    }
    return ,@($addresses)
}

function Get-AdServerCandidate {
    <#
        Queries Active Directory for computer objects that look like servers, without needing
        the RSAT ActiveDirectory module on the operator's workstation - matches this repo's own
        "nothing to pre-stage" philosophy (modules\UserProfiles\UserProfiles.psm1 already uses
        [adsisearcher] the same way, for a different query). Authenticates as the explicitly
        supplied credential, not whatever identity the workstation is running as - the whole
        point is to run this as a domain admin account distinct from the operator's own logon.
    #>
    param(
        [Parameter(Mandatory)][pscredential]$DomainCredential,
        [string]$SearchBase
    )
    $plainPassword = $DomainCredential.GetNetworkCredential().Password
    $rootDse = $null; $searchRoot = $null; $searcher = $null; $results = $null
    try {
        $rootDse = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE', $DomainCredential.UserName, $plainPassword)
        $effectiveBase = if ($SearchBase) { $SearchBase } else { [string]$rootDse.Properties['defaultNamingContext'][0] }
        $searchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$effectiveBase", $DomainCredential.UserName, $plainPassword)
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($searchRoot)
        $searcher.Filter = '(&(objectCategory=computer)(operatingSystem=*Server*))'
        $searcher.PageSize = 1000
        [void]$searcher.PropertiesToLoad.AddRange(@('name', 'dNSHostName', 'operatingSystem'))
        $results = $searcher.FindAll()
        return ,@(foreach ($entry in $results) {
            $props = $entry.Properties
            $name = if ($props['name'].Count -gt 0) { [string]$props['name'][0] } else { '' }
            $fqdn = if ($props['dnshostname'].Count -gt 0) { [string]$props['dnshostname'][0] } else { $name }
            $os   = if ($props['operatingsystem'].Count -gt 0) { [string]$props['operatingsystem'][0] } else { '' }
            # Forward-resolved once here (not left to Merge-DiscoveryCandidate) so that function
            # stays pure. Matching a subnet-scan hit by IP rather than by FQDN string matters in
            # practice - tested live against this lab, 2 of 7 domain-joined hosts had reverse
            # DNS that didn't match their AD FQDN, which silently under-merged the picker list
            # until IP became the primary match key.
            $ip = $null
            try { $ip = ([System.Net.Dns]::GetHostAddresses($fqdn) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).ToString() } catch { }
            [pscustomobject]@{ Name = $name; FQDN = $fqdn; OperatingSystem = $os; Source = 'AD'; IPAddress = $ip }
        })
    } finally {
        if ($results)    { $results.Dispose() }
        if ($searcher)   { $searcher.Dispose() }
        if ($searchRoot) { $searchRoot.Dispose() }
        if ($rootDse)    { $rootDse.Dispose() }
    }
}

function Test-WinRmPort {
    <#
        Raw TCP-connect probe for the WinRM port - not ICMP. Many client networks block ping
        but allow WinRM as the standard admin channel, so port-reachable is the actually
        relevant signal for "can we run against this," and this avoids the raw-socket
        privileges ICMP sometimes needs.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$Port = 5985,
        [int]$TimeoutMs = 400
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs) -and $client.Connected) {
            $client.EndConnect($asyncResult)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Invoke-SubnetWinRmScan {
    <#
        Fans Test-WinRmPort out across a host list via a runspace pool - PowerShell 5.1
        compatible (no ForEach-Object -Parallel, since the operator's own workstation isn't
        guaranteed to have PS7). Imports Test-WinRmPort's own definition into each runspace
        rather than duplicating the probe logic here.
    #>
    param(
        # Not Mandatory: PowerShell's parameter binder rejects an explicit empty array against a
        # Mandatory array parameter outright ("Cannot bind argument... because it is an empty
        # array") before this function body ever runs - which would defeat the empty-list guard
        # below. Defaulting to @() keeps "nothing to scan" a normal, non-throwing case.
        [string[]]$HostList = @(),
        [int]$Port = 5985,
        [int]$MaxConcurrency = 32,
        [int]$TimeoutMs = 400
    )
    if (@($HostList).Count -eq 0) { return ,@() }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $funcEntry = [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Test-WinRmPort', (Get-Command Test-WinRmPort).Definition)
    $iss.Commands.Add($funcEntry)
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $MaxConcurrency), $iss, $Host)
    $pool.Open()
    try {
        $handles = foreach ($h in $HostList) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($ComputerName, $Port, $TimeoutMs)
                [pscustomobject]@{ ComputerName = $ComputerName; Reachable = (Test-WinRmPort -ComputerName $ComputerName -Port $Port -TimeoutMs $TimeoutMs) }
            }).AddArgument($h).AddArgument($Port).AddArgument($TimeoutMs)
            [pscustomobject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
        }
        $results = foreach ($h in $handles) {
            try { $h.PowerShell.EndInvoke($h.Handle) } finally { $h.PowerShell.Dispose() }
        }
    } finally {
        $pool.Close(); $pool.Dispose()
    }
    # Reverse-resolve just the hits (not all 254 probed addresses) for a nicer display name -
    # IPAddress (the literal probed address, always known) is what Merge-DiscoveryCandidate
    # actually dedupes on, since reverse DNS not matching an AD FQDN is common enough that
    # name-based matching alone under-merges (see Get-AdServerCandidate's comment).
    return ,@($results | Where-Object { $_.Reachable } | ForEach-Object {
        $resolvedName = $_.ComputerName
        try { $resolvedName = ([System.Net.Dns]::GetHostEntry($_.ComputerName)).HostName } catch { }
        [pscustomobject]@{ Name = ($resolvedName -split '\.')[0]; FQDN = $resolvedName; OperatingSystem = ''; Source = 'Scan'; IPAddress = $_.ComputerName }
    })
}

function Get-FleetTargetPowerShellInfo {
    <#
        Probes each already-WinRM-reachable candidate for whether it can actually run the
        engine: its Windows PowerShell version, and whether PowerShell 7 is installed as a
        fallback - the same two facts Invoke-RemoteDiscoveryRun itself checks right before
        staging, surfaced here instead so the operator sees "needs PowerShell 7" in the picker
        before clicking Run, not after a wasted cycle. Confirmed live (LABSRV12, a real 2012 R2
        box): a target can answer WinRM and still fail every run because the engine's own
        #Requires -Version 5.1 silently rejects a target running the stock PowerShell 4.0.

        Needs a real authenticated session per host, unlike the anonymous TCP probe in
        Invoke-SubnetWinRmScan, so this is meaningfully slower and only worth running once a
        credential is set and only against hosts already known to answer on WinRM - probing a
        dead host here would just add a connection timeout per host for no new information.
        Runspace-pooled for the same reason as that TCP probe: PowerShell 5.1 compatible, no
        ForEach-Object -Parallel.
    #>
    param(
        [string[]]$HostList = @(),
        [Parameter(Mandatory)][pscredential]$Credential,
        [int]$MaxConcurrency = 10,
        [int]$TimeoutSeconds = 15
    )
    if (@($HostList).Count -eq 0) { return ,@() }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $MaxConcurrency))
    $pool.Open()
    try {
        $jobs = foreach ($h in $HostList) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($ComputerName, [pscredential]$Credential, $TimeoutSeconds)
                try {
                    $opt = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000)
                    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -Authentication Kerberos -SessionOption $opt -ErrorAction Stop
                    try {
                        $info = Invoke-Command -Session $session -ScriptBlock {
                            $pwshPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
                            [pscustomobject]@{
                                WindowsPowerShellVersion = $PSVersionTable.PSVersion.ToString()
                                Pwsh7Present = Test-Path -LiteralPath $pwshPath
                            }
                        }
                        [pscustomobject]@{
                            ComputerName = $ComputerName
                            WindowsPowerShellVersion = $info.WindowsPowerShellVersion
                            Pwsh7Present = [bool]$info.Pwsh7Present
                            EngineCompatible = (([version]$info.WindowsPowerShellVersion) -ge [version]'5.1') -or [bool]$info.Pwsh7Present
                            ProbeError = ''
                        }
                    } finally { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
                } catch {
                    # A probe failure here (bad credential, Kerberos hiccup, target went away
                    # between the TCP check and now) is NOT the same claim as "needs PowerShell
                    # 7" - EngineCompatible stays $null (unknown) rather than $false, so the
                    # picker can tell "confirmed incompatible" apart from "couldn't tell."
                    [pscustomobject]@{ ComputerName = $ComputerName; WindowsPowerShellVersion = ''; Pwsh7Present = $false; EngineCompatible = $null; ProbeError = $_.Exception.Message }
                }
            }).AddArgument($h).AddArgument($Credential).AddArgument($TimeoutSeconds)
            [pscustomobject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
        }
        $results = foreach ($j in $jobs) {
            try { $j.PowerShell.EndInvoke($j.Handle) } finally { $j.PowerShell.Dispose() }
        }
    } finally {
        $pool.Close(); $pool.Dispose()
    }
    return ,@($results)
}

function Merge-DiscoveryCandidate {
    <#
        Pure - no DNS I/O here. Dedupes on whatever the caller's candidate objects already
        carry: IPAddress when present (Get-AdServerCandidate/Invoke-SubnetWinRmScan both set
        it), falling back to FQDN string only when it isn't. IP is the primary key because
        reverse DNS not matching a host's real AD FQDN is common enough in practice that
        FQDN-string matching alone silently under-merges the picker list.
    #>
    param(
        [object[]]$AdResults = @(),
        [object[]]$ScanResults = @()
    )
    $byKey = [ordered]@{}
    $getKey = {
        param($item)
        if ($item.PSObject.Properties['IPAddress'] -and $item.IPAddress) { return 'ip:' + $item.IPAddress }
        return 'fqdn:' + ([string]$item.FQDN).ToLowerInvariant()
    }
    foreach ($item in @($AdResults)) {
        if (-not $item.FQDN) { continue }
        $key = & $getKey $item
        $byKey[$key] = [pscustomobject]@{ Name = $item.Name; FQDN = $item.FQDN; OperatingSystem = $item.OperatingSystem; Source = $item.Source; IPAddress = $item.IPAddress }
    }
    foreach ($item in @($ScanResults)) {
        if (-not $item.FQDN) { continue }
        $key = & $getKey $item
        if ($byKey.Contains($key)) { $byKey[$key].Source = 'Both' }
        else { $byKey[$key] = [pscustomobject]@{ Name = $item.Name; FQDN = $item.FQDN; OperatingSystem = $item.OperatingSystem; Source = $item.Source; IPAddress = $item.IPAddress } }
    }
    return ,@($byKey.Values)
}

#endregion

#region Opt-in WinRM bootstrap (WMI/DCOM) -----------------------------------------

# Everything in this region is OFF unless the caller explicitly passes
# -EnableWinRmIfUnreachable to Invoke-RemoteDiscoveryRun (surfaced in the GUI as an unchecked
# "Enable WinRM on unreachable targets" box). WinRM can't turn itself on remotely - if
# New-PSSession/Invoke-Command already worked, the target would already be reachable and none
# of this would run. Win32_Process.Create over WMI/DCOM (port 135 + dynamic RPC, not 5985) is
# the standard way to bootstrap it instead, since DCOM is enabled by default on stock Windows.
# WORTH KNOWING PLAINLY: remotely creating a process via WMI is also a well-known
# lateral-movement technique (MITRE ATT&CK T1047) that EDR/SIEM tooling commonly watches for -
# harmless for your own lab, but on a real client engagement this is the kind of thing worth a
# heads-up in the scoping conversation, not a surprise on their security team's dashboard.

function Invoke-RemoteProcessViaDcom {
    <#
        Fire-and-forget remote process creation over WMI/DCOM. Win32_Process.Create is
        inherently async - it returns as soon as the process is launched, not when it finishes -
        so the caller has to observe completion some other way (see Wait-ForWinRmPort below).
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        [Parameter(Mandatory)][string]$CommandLine
    )
    $cimSession = $null
    try {
        # -Protocol Dcom is the whole point here - New-CimSession defaults to WSMan, which is
        # exactly the channel that isn't available yet on a target this is being used for.
        # -Credential stays optional for the same reason it's optional on Invoke-RemoteDiscoveryRun
        # (see this file's header): the calling process is normally already running as the
        # domain admin via Start-Process -Credential, so DCOM's own ambient identity is enough.
        $option = New-CimSessionOption -Protocol Dcom
        $sessionArgs = @{ ComputerName = $ComputerName; SessionOption = $option; ErrorAction = 'Stop' }
        if ($Credential) { $sessionArgs['Credential'] = $Credential }
        $cimSession = New-CimSession @sessionArgs
        $result = Invoke-CimMethod -CimSession $cimSession -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $CommandLine } -ErrorAction Stop
        if ($result.ReturnValue -ne 0) {
            throw "Win32_Process.Create on $ComputerName returned code $($result.ReturnValue) (nonzero = failure - see Win32_Process.Create's documented return codes)."
        }
    } finally {
        if ($cimSession) { Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue }
    }
}

function Enable-RemoteWinRm {
    <# Bootstraps WinRM on a target with none reachable yet. Never call this on a target that's already reachable. #>
    param([Parameter(Mandatory)][string]$ComputerName, [pscredential]$Credential)
    Invoke-RemoteProcessViaDcom -ComputerName $ComputerName -Credential $Credential `
        -CommandLine 'powershell.exe -NoProfile -Command "Enable-PSRemoting -Force -SkipNetworkProfileCheck"'
}

function Disable-RemoteWinRm {
    <#
        Reverts Enable-RemoteWinRm - only ever called on a target THIS tool just turned on, never
        one that already had WinRM running before the run started. Goes a step further than a
        bare Disable-PSRemoting: Microsoft's own docs note Disable-PSRemoting does not remove the
        firewall exception Enable-PSRemoting added, so a bare disable would leave the inbound
        port open even with the listener gone. This also stops+disables the service and closes
        the firewall rule, closer to "as it was before" than the cmdlet name alone implies.
    #>
    param([Parameter(Mandatory)][string]$ComputerName, [pscredential]$Credential)
    $cmd = 'powershell.exe -NoProfile -Command "Disable-PSRemoting -Force; ' +
        'Stop-Service WinRM -Force -ErrorAction SilentlyContinue; ' +
        'Set-Service WinRM -StartupType Disabled -ErrorAction SilentlyContinue; ' +
        'Disable-NetFirewallRule -Name WINRM-HTTP-In-TCP -ErrorAction SilentlyContinue"'
    Invoke-RemoteProcessViaDcom -ComputerName $ComputerName -Credential $Credential -CommandLine $cmd
}

function Wait-ForWinRmPort {
    <#
        Polls until the target actually answers a WS-Man identify call - not just until its TCP
        port accepts a connection - since Win32_Process.Create doesn't wait for Enable-PSRemoting
        to finish. Test-WSMan (not Test-WinRmPort) deliberately: tested live, the TCP port can
        start accepting connections before the WS-Man/authentication stack is actually ready to
        service a real session request, right after Enable-PSRemoting just registered a new
        listener - a real run failed with "Access is denied" on the very first connection attempt
        immediately after the port came up, while the identical connection succeeded moments
        later once things had settled. Test-WSMan is an unauthenticated protocol-level identify
        call, so it's a real readiness signal rather than a bare "is something listening" check.
    #>
    param([Parameter(Mandatory)][string]$ComputerName, [int]$TimeoutSeconds = 60, [int]$PollIntervalSeconds = 3)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try { if (Test-WSMan -ComputerName $ComputerName -ErrorAction Stop) { return $true } } catch { }
        Start-Sleep -Seconds $PollIntervalSeconds
    } while ((Get-Date) -lt $deadline)
    return $false
}

function ConvertTo-CredentialFromEncodedLines {
    <#
        Turns the two stdin lines -CredentialFromStdin reads (plain username, then a
        base64'd UTF8 password) into a PSCredential. Pulled out as its own function so the
        encoding/decoding round trip is unit-testable without piping real stdin.
    #>
    # The password arrives over stdin as text by design (it never touches a command line or
    # file - see the header); this is the one place it becomes a SecureString.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'stdin hand-off is plain text by design; converted immediately')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'decodes the stdin hand-off into a PSCredential')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordBase64', Justification = 'stdin hand-off is plain text by design; converted immediately')]
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$PasswordBase64)
    $secure = ConvertTo-SecureString -String ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PasswordBase64))) -AsPlainText -Force
    [pscredential]::new($UserName, $secure)
}

#endregion

#region Remote execution ---------------------------------------------------------

function Invoke-RemoteDiscoveryRun {
    <#
        One target, start to finish: reachability probe, stage, run as a SYSTEM scheduled task,
        poll, pull results back, always clean up. See this file's own header comment for why a
        scheduled task (not a direct Invoke-Command scriptblock) and why -Credential is
        optional. Never aborts the caller's loop - failures come back as a Status, not a throw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        [Parameter(Mandatory)][string]$LocalOutputRoot,
        [Parameter(Mandatory)][string]$LocalToolkitRoot,
        [string]$Mode = 'Fast',
        [string]$ProjectType = 'GeneralDiscovery',
        [string]$ComplianceLens = 'None',
        [string]$RemoteStagingPath = 'C:\Discovery',
        [string]$RemoteOutputRoot = 'C:\DiscoveryOut',
        [int]$TimeoutMinutes = 60,
        [int]$PollIntervalSeconds = 15,
        [switch]$EnableWinRmIfUnreachable,
        [string]$FleetStatusDir
    )
    $startTime = Get-Date
    $result = [ordered]@{
        ComputerName = $ComputerName; Status = 'Failed'; LocalResultPath = $null
        ErrorMessage = ''; StartTime = $startTime; EndTime = $null; WinRmEnabledByThisTool = $false
    }

    $weEnabledWinRm = $false
    if (-not (Test-WinRmPort -ComputerName $ComputerName)) {
        if (-not $EnableWinRmIfUnreachable) {
            $result.Status = 'Unreachable'
            $result.ErrorMessage = 'WinRM port 5985 did not respond.'
            $result.EndTime = Get-Date
            return [pscustomobject]$result
        }
        # Opt-in path only - see this file's header note on WMI/DCOM bootstrap and its
        # lateral-movement-technique signature before turning this on for a real engagement.
        try {
            Enable-RemoteWinRm -ComputerName $ComputerName -Credential $Credential
            $weEnabledWinRm = $true
        } catch {
            $result.Status = 'Unreachable'
            $result.ErrorMessage = "WinRM was unreachable and enabling it remotely failed: $($_.Exception.Message)"
            $result.EndTime = Get-Date
            return [pscustomobject]$result
        }
        if (-not (Wait-ForWinRmPort -ComputerName $ComputerName -TimeoutSeconds 60)) {
            $result.Status = 'Unreachable'
            $result.ErrorMessage = 'Enabled WinRM remotely, but it did not become reachable within 60 seconds.'
            $result.EndTime = Get-Date
            # Still attempt to revert - Enable-PSRemoting may have partially succeeded even
            # though the port never answered (e.g. behind a firewall this tool can't see past).
            try { Disable-RemoteWinRm -ComputerName $ComputerName -Credential $Credential } catch { }
            return [pscustomobject]$result
        }
        $result.WinRmEnabledByThisTool = $true
    }

    $session = $null
    $remoteResultInfo = $null
    $taskName = 'DiscoverWindowsServer_{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 8))
    # Per-run subfolder of the caller's staging/output roots, not the bare roots themselves.
    # Confirmed live with -MaxConcurrency > 1: two targets that resolve to the SAME physical
    # machine (a cluster network name and its owning node, e.g. LABCLUS01 and the DC that owns
    # it - exactly the aliasing this file's folder-detection already had to account for once
    # before) ran concurrently, both writing their staged toolkit copy and launcher/heartbeat
    # files into the identical literal C:\Discovery, and both racing over the identical
    # C:\DiscoveryOut. One job's cleanup or in-flight writes stepped on the other's files mid-run
    # - real errors surfaced ("Could not find a part of the path ...\evidence\data\csv\....csv")
    # for datasets that were then missing entirely, and the OTHER job's heartbeat file got
    # checked and came back empty because it had already been overwritten or removed. Scoping
    # both paths by $taskName - already a fresh GUID-based name, generated once per target -
    # gives every concurrent run of this function its own isolated working directory on the
    # target, whether or not two targets happen to be the same physical machine.
    $RemoteStagingPath = Join-Path $RemoteStagingPath $taskName
    $RemoteOutputRoot = Join-Path $RemoteOutputRoot $taskName
    try {
        # -Authentication Kerberos explicitly, not left to WinRM's own default negotiation -
        # tested live against this lab and confirmed the difference matters: with no
        # -Authentication specified, New-PSSession failed with "Access is denied" against a
        # domain-joined target by its own FQDN, using a valid domain admin credential, while
        # -Authentication Kerberos (or Negotiate) against the exact same target immediately
        # succeeded. Root cause: this machine's WSMan:\localhost\Client\TrustedHosts is
        # non-empty (the lab-only weakening HANDOFF.md already documents for a couple of
        # non-domain targets), and having any entries there changes how the unspecified/default
        # auth negotiation behaves even for targets not in that list. Forcing Kerberos - which is
        # what HANDOFF.md's own manual procedure already says to use for domain-joined targets -
        # sidesteps whatever that negotiation quirk is rather than depending on it not mattering.
        $sessionArgs = @{ ComputerName = $ComputerName; ErrorAction = 'Stop'; Authentication = 'Kerberos' }
        if ($Credential) { $sessionArgs['Credential'] = $Credential }

        if ($weEnabledWinRm) {
            # Retry only in this specific case - a target that was ALREADY reachable doesn't
            # need it, and blindly retrying every connection would hide real, persistent auth
            # failures behind a slow multi-attempt loop. Confirmed live: right after
            # Enable-PSRemoting finishes, Test-WSMan (unauthenticated - just "is the WS-Man
            # protocol layer responding") succeeds well before the AUTHENTICATED path is actually
            # ready - an immediate New-PSSession with a valid credential still got "Access is
            # denied", while the identical call 5 seconds later succeeded. This is a genuine
            # settling gap in what Enable-PSRemoting sets up (likely the session configuration's
            # own authorization registration lagging the raw listener), not a credential or
            # auth-mode problem - Test-WSMan simply can't detect it because it never authenticates
            # at all.
            $sessionAttempts = 0
            do {
                $sessionAttempts++
                try { $session = New-PSSession @sessionArgs }
                catch {
                    if ($sessionAttempts -ge 5) { throw }
                    Start-Sleep -Seconds 5
                }
            } while (-not $session -and $sessionAttempts -lt 5)
        } else {
            $session = New-PSSession @sessionArgs
        }

        Invoke-Command -Session $session -ScriptBlock {
            param($Staging, $OutRoot)
            foreach ($p in @($Staging, $OutRoot)) { if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }
        } -ArgumentList $RemoteStagingPath, $RemoteOutputRoot

        # The engine itself requires PowerShell 5.1 (Discover-WindowsServer.ps1's own #Requires
        # line and header comment: stock 2012 R2 ships 4.0, and the documented fix is installing
        # PowerShell 7 side by side via tools\Install-LegacyPrerequisites.ps1 and running via
        # pwsh.exe - NOT lowering the engine's own version floor). Confirmed live against
        # LABSRV12 (a real 2012 R2 / PS4.0 box): running the engine there via Windows
        # PowerShell "succeeds" from Task Scheduler's own point of view (LastTaskResult 0,
        # confirmed the launcher script's own body did start) while producing literally nothing
        # - not even to the *> log redirect - because #Requires rejects the script before its
        # body, and thus its own error handling, ever runs. Checking the target's actual
        # PowerShell version upfront, before staging or registering anything, turns that into an
        # immediate, specific error instead of a silent ~40-second dead end. Picking pwsh.exe
        # when it's present and Windows PowerShell falls short of 5.1 fixes the case where
        # someone already ran Install-LegacyPrerequisites.ps1 on this target.
        $hostCheck = Invoke-Command -Session $session -ScriptBlock {
            $pwshPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
            [pscustomobject]@{
                WindowsPowerShellVersion = $PSVersionTable.PSVersion.ToString()
                Pwsh7Path = if (Test-Path -LiteralPath $pwshPath) { $pwshPath } else { $null }
            }
        }
        $enginePsExe = $null
        if ([version]$hostCheck.WindowsPowerShellVersion -ge [version]'5.1') {
            $enginePsExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        } elseif ($hostCheck.Pwsh7Path) {
            $enginePsExe = $hostCheck.Pwsh7Path
        } else {
            throw ("Target's Windows PowerShell is {0}, but the engine requires 5.1 or higher, and PowerShell 7 is not installed there either. Install PowerShell 7 on the target first (tools\Install-LegacyPrerequisites.ps1), then retry." -f $hostCheck.WindowsPowerShellVersion)
        }

        # Copy-Item -ToSession confirmed LIVE to be unsafe to run from two sessions AT THE SAME
        # TIME against the SAME physical machine: under -MaxConcurrency > 1, with two sessions to
        # one target each copying the toolkit to their own per-run destination folder (so this
        # isn't the earlier, already-fixed destination-path collision), the cmdlet returned
        # without error while Discover-WindowsServer.ps1 itself was missing from the target -
        # confirmed via a step-trace showing the scheduled task's own CommandNotFoundException
        # for that exact path. Retrying a few seconds later did NOT reliably recover it either
        # (still incomplete after 3 attempts, 3 seconds apart), meaning this isn't a brief timing
        # blip a short retry can paper over - it's a persistent conflict in the cmdlet's own
        # internal transfer mechanism (it works by injecting temporary helper functions into the
        # target session to receive the byte stream) when two instances of it run concurrently
        # against the same endpoint. The launcher/heartbeat files, written via a simple
        # same-session Set-Content rather than this heavier cross-session recursive transfer,
        # were completely unaffected - confirming it's specifically Copy-Item -ToSession that's
        # fragile under concurrent WinRM load, not the orchestration around it.
        #
        # Fix: serialize just the copy step across every concurrent runspace in this fleet run
        # via a named mutex, while everything else (session setup, waiting for the scan to
        # finish, pulling results back, cleanup) still runs fully in parallel. A NAMED (not
        # anonymous) mutex is required specifically because each concurrent runspace dot-sources
        # this script file fresh (see Invoke-FleetRunsInParallel's own comment) - there is no
        # shared script-scope variable a plain object reference could live in, only an OS-level
        # named synchronization object is visible across all of them. The retry loop stays too,
        # as a second line of defense against a genuinely slow/flaky transfer even once
        # concurrent copies can no longer interfere with each other.
        $copyMutex = [System.Threading.Mutex]::new($false, 'DiscoverWindowsServerFleetCopyLock')
        $engineRemotePath = Join-Path $RemoteStagingPath 'Discover-WindowsServer.ps1'
        $copyAttempts = 0
        $copyConfirmed = $false
        $copyDiagLines = [System.Collections.Generic.List[string]]::new()
        try {
            $waitSw = [System.Diagnostics.Stopwatch]::StartNew()
            $mutexAcquired = $copyMutex.WaitOne()
            $waitSw.Stop()
            [void]$copyDiagLines.Add("mutex acquired=$mutexAcquired after $($waitSw.Elapsed.TotalSeconds)s")
            do {
                $copyAttempts++
                $copySw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    Copy-Item -Path (Join-Path $LocalToolkitRoot '*') -Destination $RemoteStagingPath -ToSession $session -Recurse -Force -ErrorAction Stop
                    $copySw.Stop()
                    [void]$copyDiagLines.Add("attempt $copyAttempts Copy-Item returned normally after $($copySw.Elapsed.TotalSeconds)s")
                } catch {
                    $copySw.Stop()
                    [void]$copyDiagLines.Add("attempt $copyAttempts Copy-Item THREW after $($copySw.Elapsed.TotalSeconds)s: $($_.Exception.GetType().FullName): $($_.Exception.Message)")
                }
                $copyConfirmed = Invoke-Command -Session $session -ScriptBlock { param($p) Test-Path -LiteralPath $p } -ArgumentList $engineRemotePath
                [void]$copyDiagLines.Add("attempt $copyAttempts verify Test-Path result=$copyConfirmed for $engineRemotePath")
                if (-not $copyConfirmed -and $copyAttempts -lt 3) { Start-Sleep -Seconds 3 }
            } while (-not $copyConfirmed -and $copyAttempts -lt 3)
        } finally {
            $copyMutex.ReleaseMutex()
            $copyMutex.Dispose()
        }
        if (-not $copyConfirmed) {
            throw "Toolkit copy to the target appears incomplete after $copyAttempts attempt(s) - Discover-WindowsServer.ps1 is missing from the staged copy at $engineRemotePath. Diagnostic trail: $($copyDiagLines -join ' | ')"
        }

        # This machine's branding lives in %ProgramData% (see Core.psm1's Get-DiscoveryBrandingDirectory),
        # outside the toolkit folder copied above. Stage it into the remote copy's config\, which the
        # engine falls back to, so per-server reports carry the same brand. Cosmetic: never fails the run.
        $localBrandingDir = Join-Path $env:ProgramData 'Discover-WindowsServer\branding'
        if (Test-Path -LiteralPath (Join-Path $localBrandingDir 'branding.local.json')) {
            try {
                Get-ChildItem -LiteralPath $localBrandingDir -File -ErrorAction Stop |
                    Where-Object { $_.Name -eq 'branding.local.json' -or $_.Name -like 'branding-logo.*' } |
                    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $RemoteStagingPath 'config') -ToSession $session -Force -ErrorAction Stop }
            } catch { }
        }

        $remoteLogPath = Join-Path $RemoteOutputRoot 'fleet-task-log.txt'
        $remoteHeartbeatPath = Join-Path $RemoteStagingPath 'run-discovery.started'
        $remoteTracePath = Join-Path $RemoteStagingPath 'run-discovery.trace'
        # This whole step gets its own try/catch, not just the outer one, so a registration/start
        # failure surfaces as its own clearly-labeled error instead of falling through silently to
        # the generic "no output folder was found" message the poll loop reports otherwise.
        try {
            $taskConfirmedStarted = Invoke-Command -Session $session -ScriptBlock {
                param($TaskName, $Staging, $OutRoot, $Mode, $ProjectType, $ComplianceLens, $LogPath, $PsExe)
                $engine = Join-Path $Staging 'Discover-WindowsServer.ps1'
                # NOT (Get-Process -Id $PID).Path - inside a WinRM session that resolves to
                # wsmprovhost.exe (the remoting host process), not a real PowerShell interpreter.
                # Registering a scheduled task to run wsmprovhost.exe with engine arguments is a
                # silent no-op: the task "runs" and exits without ever touching the engine, which is
                # exactly what happened testing this live against LABSRV19 - 15 minutes, no output
                # folder, no error, because nothing that could produce one ever actually ran.
                # $PsExe was already picked by the caller (Windows PowerShell if it's 5.1+, else
                # pwsh.exe if present, else this whole run already failed fast before staging
                # even started) - see that selection's own comment for why Windows PowerShell
                # alone isn't safe to assume on every supported target.
                $psExe = $PsExe
                # A real staged .ps1 launcher run via -File, NOT a -Command string with escaped
                # inner double quotes. Confirmed live against LABSRV12 (2012 R2): the old
                # -Command "..." approach produced Task Scheduler's own LastTaskResult = 1 (a
                # generic "process exited with an error" code) with NEITHER an output folder NOR
                # a single byte in the *> log file - meaning the failure happened before the
                # engine, and before the redirect inside the command string, ever took effect.
                # That's the signature of the COMMAND LINE ITSELF failing to parse (the escaped-
                # quote string is exactly the kind of thing that's fragile across different
                # cmd.exe/Task Scheduler argument-parsing behavior), not the engine erroring -
                # if the engine had run and thrown, *> would have caught it, same as it already
                # does for LABSRV19-class engine failures. Writing real script content to a file
                # and invoking it with -File sidesteps that whole class of quoting fragility -
                # the same fix already used elsewhere in this toolkit for -File's own array-
                # argument parsing quirk (see ConvertTo-DiscoveryLauncherScript in the GUI).
                $launcherPath = Join-Path $Staging 'run-discovery.ps1'
                $heartbeatPath = Join-Path $Staging 'run-discovery.started'
                $tracePath = Join-Path $Staging 'run-discovery.trace'
                # Step-by-step trace via Add-Content (a separate open/write/close per line, more
                # resistant to losing everything if the process gets torn down mid-run than the
                # single buffered *> redirect on the engine call is) - added specifically to
                # diagnose the concurrency case: two targets that alias to the SAME physical
                # machine both got a correctly-written heartbeat (proving -File/the launcher's
                # own body runs fine even under concurrency) yet BOTH still produced neither an
                # output folder nor a single byte in *>'s own log file, with Task Scheduler
                # still reporting a clean LastTaskResult of 0. That combination - heartbeat yes,
                # everything after it no, no error anywhere - means whatever kills this off
                # happens between the heartbeat and the engine call finishing, silently enough
                # that even *> never gets a chance to flush. This trace exists to find exactly
                # which of those points it is.
                # Plain double-quoted-here-string interpolation, not -f - mixing -f's {0}
                # placeholders with this script's own literal try/catch braces means every
                # literal brace has to be doubled ({{/}}) to avoid being read as a placeholder,
                # which is exactly the kind of thing that's easy to get wrong (an early version
                # of this had a bare, undoubled `try {` that would have thrown a FormatException
                # on the very next line, caught before it ever ran live). Direct interpolation of
                # already-in-scope variables ($tracePath, $engine, ...) needs no such care -
                # only $PID/$LASTEXITCODE/$_ are backtick-escaped, since those must stay literal
                # in the written-out file and only get a real value when THAT script later runs.
                $nowStamp = (Get-Date).ToString('o')
                $launcherContent = @"
try {
    ('$nowStamp STEP1 launcher started PID=' + `$PID) | Add-Content -LiteralPath '$tracePath'
    '$nowStamp' | Set-Content -LiteralPath '$heartbeatPath'
    ((Get-Date).ToString('o') + ' STEP2 heartbeat written, invoking engine') | Add-Content -LiteralPath '$tracePath'
    & '$engine' -Mode $Mode -ProjectType $ProjectType -ComplianceLens $ComplianceLens -OutputRoot '$OutRoot' *> '$LogPath'
    ((Get-Date).ToString('o') + " STEP3 engine call returned, LASTEXITCODE=`$LASTEXITCODE") | Add-Content -LiteralPath '$tracePath'
} catch {
    ((Get-Date).ToString('o') + " STEP-ERROR " + `$_.Exception.GetType().FullName + ': ' + `$_.Exception.Message) | Add-Content -LiteralPath '$tracePath'
}
((Get-Date).ToString('o') + ' STEP4 launcher finished') | Add-Content -LiteralPath '$tracePath'
"@
                Set-Content -LiteralPath $launcherPath -Value $launcherContent -Encoding UTF8 -ErrorAction Stop
                $argLine = '-NoProfile -File "{0}"' -f $launcherPath
                $action = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -ErrorAction Stop
                $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ErrorAction Stop
                $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -ErrorAction Stop
                Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force -ErrorAction Stop | Out-Null
                Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
                # Belt-and-suspenders, independent of the launcher-file fix above: every
                # scheduled-task cmdlet now has -ErrorAction Stop (none did before), so a real
                # registration/start failure throws all the way out to this function's own
                # try/catch below instead of logging a non-terminating error and silently
                # continuing - and this existence check closes the gap for the case where the
                # cmdlets all return successfully but Task Scheduler still doesn't show the task:
                # a task that isn't visible immediately after being told to start never
                # legitimately reaches 'Ready' or 'Running' on its own, so returning nothing here
                # is always a genuine failure to report, never a race with real completion.
                [string](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State
            } -ArgumentList $taskName, $RemoteStagingPath, $RemoteOutputRoot, $Mode, $ProjectType, $ComplianceLens, $remoteLogPath, $enginePsExe
        } catch {
            throw "Failed to register or start the scheduled task on the target: $($_.Exception.Message)"
        }
        if (-not $taskConfirmedStarted) {
            throw 'Scheduled task was registered without error, but does not appear in Task Scheduler on the target immediately afterward.'
        }

        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        $finished = $false
        do {
            Start-Sleep -Seconds $PollIntervalSeconds
            # [string](...) INSIDE the remote scriptblock, not after - .State is an enum, and
            # PowerShell remoting deserializes remote enum values into a proxy type on the way
            # back that DISPLAYS as "Ready" (Select-Object/Format-* call .ToString() same as any
            # object) but does not '-eq' a literal string correctly. That silently broke
            # completion detection end to end: tested live, the poll loop never once detected a
            # genuinely-finished task and always fell through to the timeout, even though
            # Get-ScheduledTask run directly in a fresh session showed State: Ready seconds after
            # the task actually finished. Casting to string before it crosses the remoting
            # boundary avoids the deserialization entirely.
            $state = Invoke-Command -Session $session -ScriptBlock {
                param($TaskName)
                [string](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State
            } -ArgumentList $taskName
            if ($state -eq 'Ready' -or -not $state) { $finished = $true }
            # Best-effort live-phase relay: read THIS target's own evidence\status\status.json
            # (the same file Core.psm1's Update-StatusFile writes locally on every run, single-
            # server or fleet) off the target over the session already open for the task-state
            # poll above - no extra connection - and drop it in the shared fleet-status folder so
            # the orchestrating runspace (a different one; this poll loop runs inside its own
            # per-target runspace under Invoke-FleetRunsInParallel) can pick it up and relay it
            # into the GUI's progress.json. The run folder's name isn't known in advance (it's
            # timestamped by the target itself), so this reuses the same CreationTime-scoped
            # wildcard lookup the completion path below uses once the run is done. Never fatal -
            # a target still staging/reaching has no run folder yet, and that's an expected,
            # silent no-op tick, not an error.
            if ($FleetStatusDir) {
                try {
                    $liveStatus = Invoke-Command -Session $session -ScriptBlock {
                        param($OutRoot, $Since)
                        $candidate = Get-ChildItem -LiteralPath $OutRoot -Directory -Filter 'Discover-WindowsServer_*' -ErrorAction SilentlyContinue |
                            Where-Object { $_.CreationTime -ge $Since } | Sort-Object CreationTime -Descending | Select-Object -First 1
                        if (-not $candidate) { return $null }
                        $statusFile = Join-Path $candidate.FullName 'evidence\status\status.json'
                        if (-not (Test-Path -LiteralPath $statusFile)) { return $null }
                        Get-Content -LiteralPath $statusFile -Raw -ErrorAction SilentlyContinue
                    } -ArgumentList $RemoteOutputRoot, $startTime
                    if ($liveStatus) {
                        $parsed = $liveStatus | ConvertFrom-Json
                        if (-not (Test-Path -LiteralPath $FleetStatusDir)) { New-Item -ItemType Directory -Path $FleetStatusDir -Force | Out-Null }
                        $safeName = ($ComputerName -replace '[^A-Za-z0-9._-]', '_')
                        [pscustomobject]@{
                            ComputerName = $ComputerName; Phase = $parsed.Phase; CurrentModule = $parsed.CurrentModule
                            PercentComplete = $parsed.PercentComplete
                        } | ConvertTo-Json | Out-File -LiteralPath (Join-Path $FleetStatusDir "$safeName.json") -Encoding UTF8 -Force
                    }
                } catch { }
            }
        } while (-not $finished -and (Get-Date) -lt $deadline)
        if ($FleetStatusDir) {
            $safeName = ($ComputerName -replace '[^A-Za-z0-9._-]', '_')
            Remove-Item -LiteralPath (Join-Path $FleetStatusDir "$safeName.json") -Force -ErrorAction SilentlyContinue
        }

        # Every remaining step is nested under $finished/$remoteResultInfo rather than an early
        # `return` from inside this try - a `return [pscustomobject]$result` here would snapshot
        # $result into a NEW object before `finally` below sets EndTime, silently dropping it
        # from what the caller sees. Falling through to the single `return` after finally avoids
        # that (caught by hand: EndTime came back $null on the TimedOut path tested live).
        if (-not $finished) {
            $result.Status = 'TimedOut'
            $result.ErrorMessage = "No completion within $TimeoutMinutes minutes."
        } else {
            # Matches on "Discover-WindowsServer_*" + CreationTime only - deliberately NOT also
            # requiring the folder's computer-name segment to match $ComputerName. Confirmed live
            # that the two can genuinely diverge: a cluster network name (LABCLUS01) routes to
            # whichever node currently owns it, so the engine's own $env:COMPUTERNAME is that
            # node's real name, not the cluster name connected to; separately, this lab's own DC
            # has an AD dNSHostName ("ClaudeWin2025Dev") that doesn't even match its real
            # $env:COMPUTERNAME ("CLAUDEWIN2025DE") - a plain renamed-machine mismatch, no cluster
            # involved. Both looked identical to "the task ran and produced nothing" until this
            # was loosened - the real output folder was sitting right there the whole time, just
            # under a name this code wasn't looking for. CreationTime -ge $Since is still enough
            # to scope this to "created during my own request," which is what actually matters.
            $remoteResultInfo = Invoke-Command -Session $session -ScriptBlock {
                param($OutRoot, $Since)
                $candidate = Get-ChildItem -LiteralPath $OutRoot -Directory -Filter 'Discover-WindowsServer_*' -ErrorAction SilentlyContinue |
                    Where-Object { $_.CreationTime -ge $Since } | Sort-Object CreationTime -Descending | Select-Object -First 1
                if (-not $candidate) { return $null }
                [pscustomobject]@{ FullName = $candidate.FullName; Name = $candidate.Name }
            } -ArgumentList $RemoteOutputRoot, $startTime

            if (-not $remoteResultInfo) {
                # Queried BEFORE cleanup (the finally block below unregisters this task
                # regardless of outcome) - Windows' own recorded result for the task's LAST run
                # is the one piece of evidence that can actually distinguish "the action never
                # launched at all" (LastTaskResult non-zero - a real Win32 error code, e.g.
                # access-denied or a launch failure) from "it launched but the engine itself
                # produced nothing," which registering/starting without error and a task log
                # that's also missing can't tell apart on its own. First confirmed case of this
                # exact failure (LABSRV12) had neither an output folder nor a log file despite
                # the task registering, starting, and being confirmed present immediately
                # afterward - i.e. Task Scheduler thought everything was fine, so whatever went
                # wrong happened inside the action itself, before or during the *> redirect.
                $taskInfo = Invoke-Command -Session $session -ScriptBlock {
                    param($TaskName)
                    try { Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop | Select-Object LastRunTime, LastTaskResult, NumberOfMissedRuns }
                    catch { $null }
                } -ArgumentList $taskName
                $logTail = Invoke-Command -Session $session -ScriptBlock {
                    param($LogPath)
                    if (Test-Path -LiteralPath $LogPath) { (Get-Content -LiteralPath $LogPath -Tail 25 -ErrorAction SilentlyContinue) -join "`n" }
                } -ArgumentList $remoteLogPath
                # Distinguishes "the launcher .ps1's own body never started running" (heartbeat
                # absent - written directly, not through *>, as the launcher's very first
                # statement) from "it started but the engine call inside it produced nothing."
                $heartbeatSeen = Invoke-Command -Session $session -ScriptBlock {
                    param($HeartbeatPath)
                    if (Test-Path -LiteralPath $HeartbeatPath) { Get-Content -LiteralPath $HeartbeatPath -Raw -ErrorAction SilentlyContinue }
                } -ArgumentList $remoteHeartbeatPath
                $traceContent = Invoke-Command -Session $session -ScriptBlock {
                    param($TracePath)
                    if (Test-Path -LiteralPath $TracePath) { (Get-Content -LiteralPath $TracePath -ErrorAction SilentlyContinue) -join ' | ' }
                } -ArgumentList $remoteTracePath
                $result.Status = 'Failed'
                $resultCodeNote = if ($taskInfo) {
                    "Task Scheduler's own LastTaskResult for this run: {0} (0 = success reported; a non-zero value is a real Win32 error code even though the task registered and started without error)." -f $taskInfo.LastTaskResult
                } else {
                    "Could not query the task's own LastTaskResult either (task may already be gone)."
                }
                $heartbeatNote = if ($heartbeatSeen) {
                    "The launcher script's own heartbeat marker WAS written (at $($heartbeatSeen.Trim())), so it did start running - whatever went wrong happened inside the engine call itself, after that point."
                } else {
                    "The launcher script's own heartbeat marker was NEVER written - its body never started running at all, despite Task Scheduler reporting the task ran successfully."
                }
                $traceNote = if ($traceContent) { "Step trace: $traceContent" } else { 'No step trace was found either (the launcher never even reached its own finally-equivalent last line).' }
                $result.ErrorMessage = if ($logTail) {
                    "Scheduled task finished but no output folder was found on the target. $resultCodeNote $heartbeatNote $traceNote Last lines of its own output:`n$logTail"
                } else {
                    "Scheduled task finished but no output folder was found on the target, and no task log was found either. $resultCodeNote $heartbeatNote $traceNote"
                }
            } else {
                if (-not (Test-Path -LiteralPath $LocalOutputRoot)) { New-Item -ItemType Directory -Path $LocalOutputRoot -Force | Out-Null }
                Copy-Item -Path $remoteResultInfo.FullName -Destination $LocalOutputRoot -FromSession $session -Recurse -Force -ErrorAction Stop
                $result.Status = 'Succeeded'
                $result.LocalResultPath = Join-Path $LocalOutputRoot $remoteResultInfo.Name
            }
        }
    } catch {
        $result.ErrorMessage = $_.Exception.Message
    } finally {
        if ($session) {
            try {
                Invoke-Command -Session $session -ScriptBlock {
                    param($TaskName, $Staging, $OutRoot)
                    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue
                    # The whole per-run output root (this also removes fleet-task-log.txt inside
                    # it, so no separate cleanup step is needed for that) - safe to remove
                    # unconditionally, success or failure, now that it's scoped by $taskName
                    # rather than being the shared C:\DiscoveryOut every run used to write into,
                    # so there's no risk of deleting a DIFFERENT target's output.
                    Remove-Item -LiteralPath $OutRoot -Recurse -Force -ErrorAction SilentlyContinue
                } -ArgumentList $taskName, $RemoteStagingPath, $RemoteOutputRoot -ErrorAction SilentlyContinue
            } catch { }
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
        if ($weEnabledWinRm) {
            # Immediately, not deferred to end-of-fleet - see this file's header note: the whole
            # point of gating this behind an explicit opt-in is keeping the exposure window as
            # small as possible. Best-effort: a failed revert is recorded, not thrown, so it
            # doesn't mask whatever the actual scan result was.
            try { Disable-RemoteWinRm -ComputerName $ComputerName -Credential $Credential }
            catch { $result.ErrorMessage = (@($result.ErrorMessage, "WinRM revert failed - it may still be enabled on this target: $($_.Exception.Message)") -ne '') -join ' | ' }
        }
        $result.EndTime = Get-Date
    }
    return [pscustomobject]$result
}

function Update-FleetStatusFile {
    <#
        Mirrors Update-StatusFile's progress.json shape (modules\Core\Core.psm1) with
        Target-flavored field names in place of the per-module ones, so the GUI's existing
        progress-polling code needs only a field rename to drive this, not new logic.
        CurrentTargets is plural (not CurrentTarget) - with -MaxConcurrency > 1 more than one
        target can genuinely be running at once, and collapsing that to a single name would just
        show whichever one happened to be reported last.

        TargetPhases carries each still-running target's OWN current engine stage (Phase,
        CurrentModule, PercentComplete - read from that target's remote evidence\status\
        status.json by Invoke-RemoteDiscoveryRun's poll loop) so the engineer watching the GUI
        sees "SRV1: Synthesizing RiskEngine (62%)" instead of just "SRV1 is running" for however
        long that target takes. Optional and best-effort: a target whose status file hasn't
        appeared yet (still staging/reaching) or couldn't be read this tick simply has no entry.
    #>
    param(
        [Parameter(Mandatory)][string]$StatusPath,
        [Parameter(Mandatory)][string]$Phase,
        [string[]]$CurrentTargets = @(),
        [Parameter(Mandatory)][int]$CompletedTargets,
        [Parameter(Mandatory)][int]$TotalTargets,
        [object[]]$Targets = @(),
        [object[]]$TargetPhases = @()
    )
    $pct = 0
    if ($TotalTargets -gt 0) { $pct = [math]::Round(($CompletedTargets / $TotalTargets) * 100, 0) }
    $progress = [ordered]@{
        Phase = $Phase; CurrentTargets = @($CurrentTargets); CompletedTargets = $CompletedTargets
        TotalTargets = $TotalTargets; PercentComplete = $pct; UpdatedTime = (Get-Date).ToString('o')
        Targets = @($Targets | ForEach-Object { [ordered]@{ Name = $_.ComputerName; Status = $_.Status; ErrorMessage = $_.ErrorMessage } })
        TargetPhases = @($TargetPhases | ForEach-Object { [ordered]@{ ComputerName = $_.ComputerName; Phase = $_.Phase; CurrentModule = $_.CurrentModule; PercentComplete = $_.PercentComplete } })
    }
    $dir = Split-Path -Parent $StatusPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try { ($progress | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $StatusPath -Encoding UTF8 -Force } catch { }
}

function Invoke-FleetRunsInParallel {
    <#
        Runs Invoke-RemoteDiscoveryRun for every target through one bounded runspace pool,
        sized 1 through -MaxConcurrency - a pool of size 1 behaves identically to the old plain
        `foreach` loop, so this replaces it outright rather than branching into two separate
        "sequential" and "parallel" code paths that could drift apart.

        Each runspace dot-sources THIS SAME script file (by path) rather than importing one
        function's definition the way the lighter-weight Invoke-SubnetWinRmScan does above -
        Invoke-RemoteDiscoveryRun depends on most of the other functions in this file
        (Test-WinRmPort, Enable-RemoteWinRm, Wait-ForWinRmPort, Disable-RemoteWinRm,
        Invoke-RemoteProcessViaDcom, ...), so importing just one definition wouldn't be enough.
        Dot-sourcing with no arguments is safe here the same way it already is for Pester/the
        GUI: the "only runs when executed directly" guard at the bottom checks
        $MyInvocation.InvocationName -eq '.', so it only ever defines functions, never starts a
        second, nested fleet run.

        A [pscredential] argument crosses runspace-pool boundaries by reference, not by
        serialization, unlike a PSRemoting session - these are local runspaces in the same
        process, so passing $Credential directly (rather than the stdin/base64 dance
        -CredentialFromStdin uses for the CROSS-PROCESS boundary) is safe.
    #>
    param(
        [Parameter(Mandatory)][string[]]$TargetComputerNames,
        [pscredential]$Credential,
        [Parameter(Mandatory)][string]$LocalOutputRoot,
        [Parameter(Mandatory)][string]$LocalToolkitRoot,
        [string]$Mode = 'Fast',
        [string]$ProjectType = 'GeneralDiscovery',
        [string]$ComplianceLens = 'None',
        [int]$TimeoutMinutes = 60,
        [switch]$EnableWinRmIfUnreachable,
        [int]$MaxConcurrency = 1,
        [string]$ScriptPath,
        [string]$FleetStatusPath,
        [string]$FleetStatusDir
    )
    $poolSize = [Math]::Max(1, $MaxConcurrency)
    $pool = [runspacefactory]::CreateRunspacePool(1, $poolSize)
    $pool.Open()
    $results = [System.Collections.Generic.List[object]]::new()
    # Local helper, not a top-level function - reads whatever per-target phase files
    # Invoke-RemoteDiscoveryRun's poll loop has dropped in $FleetStatusDir for the targets still
    # running. Best-effort: a target with no file yet (still staging/reaching) just has no entry.
    $getTargetPhases = {
        param($Dir, $RunningNames)
        if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) { return @() }
        @($RunningNames | ForEach-Object {
            $safeName = ($_ -replace '[^A-Za-z0-9._-]', '_')
            $f = Join-Path $Dir "$safeName.json"
            if (Test-Path -LiteralPath $f) {
                try { Get-Content -LiteralPath $f -Raw | ConvertFrom-Json } catch { $null }
            }
        } | Where-Object { $_ })
    }
    try {
        $jobs = foreach ($target in $TargetComputerNames) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($ScriptPath, $ComputerName, [pscredential]$Credential, $LocalOutputRoot, $LocalToolkitRoot, $Mode, $ProjectType, $ComplianceLens, $TimeoutMinutes, $EnableWinRmIfUnreachable, $FleetStatusDir)
                . $ScriptPath
                Invoke-RemoteDiscoveryRun -ComputerName $ComputerName -Credential $Credential `
                    -LocalOutputRoot $LocalOutputRoot -LocalToolkitRoot $LocalToolkitRoot `
                    -Mode $Mode -ProjectType $ProjectType -ComplianceLens $ComplianceLens -TimeoutMinutes $TimeoutMinutes `
                    -EnableWinRmIfUnreachable:$EnableWinRmIfUnreachable -FleetStatusDir $FleetStatusDir
            }).AddArgument($ScriptPath).AddArgument($target).AddArgument($Credential).AddArgument($LocalOutputRoot).AddArgument($LocalToolkitRoot).AddArgument($Mode).AddArgument($ProjectType).AddArgument($ComplianceLens).AddArgument($TimeoutMinutes).AddArgument([bool]$EnableWinRmIfUnreachable).AddArgument($FleetStatusDir)
            [pscustomobject]@{ ComputerName = $target; PowerShell = $ps; Handle = $ps.BeginInvoke(); Done = $false }
        }

        $total = @($jobs).Count
        if ($FleetStatusPath) {
            Update-FleetStatusFile -StatusPath $FleetStatusPath -Phase 'Running' -CurrentTargets $TargetComputerNames -CompletedTargets 0 -TotalTargets $total -Targets @()
        }
        # Poll rather than EndInvoke-in-submission-order: with concurrency > 1, jobs finish out
        # of order, and EndInvoke on an earlier, still-running handle would block the loop from
        # ever reporting a LATER job that already finished.
        $lastPhaseWrite = Get-Date
        while (@($jobs | Where-Object { -not $_.Done }).Count -gt 0) {
            foreach ($job in $jobs) {
                if ($job.Done -or -not $job.Handle.IsCompleted) { continue }
                $job.Done = $true
                try {
                    $r = $job.PowerShell.EndInvoke($job.Handle)
                    if ($job.PowerShell.HadErrors -and -not $r) {
                        # Invoke-RemoteDiscoveryRun's own contract is "failures come back as a
                        # Status, not a throw" - HadErrors with no result means something broke
                        # OUTSIDE that contract (a runspace-level problem), so this is the one
                        # place a synthetic Failed result gets built instead of trusting the
                        # function's own return.
                        $errText = ($job.PowerShell.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '
                        $results.Add([pscustomobject]@{ ComputerName = $job.ComputerName; Status = 'Failed'; LocalResultPath = $null; ErrorMessage = "Unexpected runspace error: $errText"; StartTime = Get-Date; EndTime = Get-Date; WinRmEnabledByThisTool = $false })
                    } else {
                        $results.Add($r)
                    }
                } finally {
                    $job.PowerShell.Dispose()
                }
                if ($FleetStatusPath) {
                    $running = @($jobs | Where-Object { -not $_.Done } | ForEach-Object { $_.ComputerName })
                    $phases = & $getTargetPhases $FleetStatusDir $running
                    Update-FleetStatusFile -StatusPath $FleetStatusPath -Phase 'Running' -CurrentTargets $running -CompletedTargets $results.Count -TotalTargets $total -Targets $results -TargetPhases $phases
                    $lastPhaseWrite = Get-Date
                }
            }
            # Independently of any target completing, refresh progress.json every few seconds so
            # a still-running target's OWN phase (read from its status file by the poll loop in
            # Invoke-RemoteDiscoveryRun, which only ticks every -PollIntervalSeconds) reaches the
            # GUI without waiting for the next target to finish - which, for a single slow target,
            # could otherwise be the entire rest of the run.
            if ($FleetStatusPath -and ((Get-Date) - $lastPhaseWrite) -ge [TimeSpan]::FromSeconds(3)) {
                $running = @($jobs | Where-Object { -not $_.Done } | ForEach-Object { $_.ComputerName })
                $phases = & $getTargetPhases $FleetStatusDir $running
                Update-FleetStatusFile -StatusPath $FleetStatusPath -Phase 'Running' -CurrentTargets $running -CompletedTargets $results.Count -TotalTargets $total -Targets $results -TargetPhases $phases
                $lastPhaseWrite = Get-Date
            }
            if (@($jobs | Where-Object { -not $_.Done }).Count -gt 0) { Start-Sleep -Milliseconds 500 }
        }
    } finally {
        $pool.Close(); $pool.Dispose()
    }
    return ,@($results)
}

#endregion

# Only runs when executed directly (not dot-sourced) - see this file's header for the two
# invocation modes. TargetComputerNames is what distinguishes "just wanted the functions" from
# "actually run the fleet."
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $TargetComputerNames -or $TargetComputerNames.Count -eq 0) {
        throw '-TargetComputerNames is required when running this script directly (one or more resolved computer names/FQDNs).'
    }
    if (-not $EngagementFolder) { throw '-EngagementFolder is required when running this script directly.' }

    if ($CredentialFromStdin) {
        # See CREDENTIAL HANDLING in this file's own header for why this exists instead of just
        # taking -DomainCredential directly, or relying on Start-Process -Credential's ambient
        # identity. Two lines, read as two separate ReadLine calls specifically so neither field
        # needs a delimiter that a real username or password might collide with.
        $stdinUserName = [Console]::In.ReadLine()
        $stdinPasswordB64 = [Console]::In.ReadLine()
        if (-not $stdinUserName -or -not $stdinPasswordB64) {
            throw '-CredentialFromStdin was specified but stdin did not provide both a username and a password line.'
        }
        $DomainCredential = ConvertTo-CredentialFromEncodedLines -UserName $stdinUserName -PasswordBase64 $stdinPasswordB64
    }

    $localToolkitRoot = Split-Path -Parent $PSScriptRoot
    $fleetStatusDir = Join-Path $EngagementFolder 'fleet-status'
    $fleetStatusPath = Join-Path $fleetStatusDir 'progress.json'
    $total = $TargetComputerNames.Count

    $results = Invoke-FleetRunsInParallel -TargetComputerNames $TargetComputerNames -Credential $DomainCredential `
        -LocalOutputRoot $EngagementFolder -LocalToolkitRoot $localToolkitRoot `
        -Mode $Mode -ProjectType $ProjectType -ComplianceLens $ComplianceLens -TimeoutMinutes $TimeoutMinutes `
        -EnableWinRmIfUnreachable:$EnableWinRmIfUnreachable -MaxConcurrency $MaxConcurrency `
        -ScriptPath $PSCommandPath -FleetStatusPath $fleetStatusPath -FleetStatusDir $fleetStatusDir
    $done = @($results).Count

    Update-FleetStatusFile -StatusPath $fleetStatusPath -Phase 'Complete' -CompletedTargets $done -TotalTargets $total -Targets $results

    if (-not (Test-Path -LiteralPath $EngagementFolder)) { New-Item -ItemType Directory -Path $EngagementFolder -Force | Out-Null }
    ($results | ConvertTo-Json -Depth 6) | Out-File -LiteralPath (Join-Path $EngagementFolder 'fleet-run-results.json') -Encoding UTF8 -Force

    $failed = @($results | Where-Object { $_.Status -ne 'Succeeded' })
    if ($failed.Count -gt 0) {
        Write-Host ("Fleet run finished: {0}/{1} succeeded. Not all targets completed - see fleet-run-results.json." -f ($total - $failed.Count), $total) -ForegroundColor Yellow
    } else {
        Write-Host ("Fleet run finished: {0}/{0} succeeded." -f $total) -ForegroundColor Green
    }
}
