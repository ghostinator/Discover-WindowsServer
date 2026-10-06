<#
    Network.psm1
    Ultimate Modular Windows Server Discovery Toolkit - Network collector module.

    Owns datasets:
      NetworkAdapters, IPConfiguration, Routes, DnsClient,
      ListeningPorts, EstablishedConnections, FirewallRules.

    Design rules:
      - Windows PowerShell 5.1 compatible. No PS7-only syntax.
      - STRICTLY READ-ONLY. Only Get-*/query cmdlets and read-only external tools
        (netstat -ano, route print) are used. Nothing here changes the system.
      - Defensive: every collection block is wrapped in try/catch so a single
        failure never stops the module. Missing cmdlets fall back to CIM / CLI.
      - Emits canonical dataset field names so the RiskEngine rules can key off them.

    NOTE: StrictMode is intentionally NOT enabled (dynamic CIM / .NET objects).
#>

#region Metadata & prerequisites ----------------------------------------------

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'Network'
        DisplayName               = 'Network Configuration & Connections'
        Category                  = 'Network'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Low'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('NetworkAdapters','IPConfiguration','Routes','DnsClient','ListeningPorts','EstablishedConnections','FirewallRules')
        ProducesRisks             = $true
        ProducesFollowUpQuestions = $true
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    # Network telemetry is available on every Windows host (cmdlets or CIM/CLI
    # fallbacks). No role/admin gate is required to run this collector.
    [pscustomobject]@{ ModuleName='Network'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

#endregion

#region Shared helpers --------------------------------------------------------

function Get-NwProcessMap {
    <# Builds a best-effort ProcessId(int) -> ProcessName map. Never throws. #>
    param()
    $map = @{}
    try {
        foreach ($p in (Get-Process -ErrorAction Stop)) {
            try { $map[[int]$p.Id] = [string]$p.ProcessName } catch { }
        }
    } catch { }
    return $map
}

function Get-NwServiceMap {
    <# Builds a best-effort ProcessId(int) -> 'svc1,svc2' service-name map. #>
    param([object]$Context)
    $map = @{}
    try {
        $svcs = Invoke-CimSafe -ClassName 'Win32_Service' -Property @('Name','ProcessId','State')
        foreach ($s in $svcs) {
            try {
                $procId = 0
                if ($null -ne $s.ProcessId) { $procId = [int]$s.ProcessId }
                if ($procId -gt 0 -and $s.Name) {
                    if ($map.ContainsKey($procId)) { $map[$procId] = ($map[$procId] + ',' + [string]$s.Name) }
                    else { $map[$procId] = [string]$s.Name }
                }
            } catch { }
        }
    } catch { }
    return $map
}

function Split-NwEndpoint {
    <# Splits 'addr:port' (incl. bracketed IPv6 '[::]:445') into address/port. #>
    param([string]$Endpoint)
    $result = @{ Address = ''; Port = '' }
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { return $result }
    $idx = $Endpoint.LastIndexOf(':')
    if ($idx -lt 0) { $result.Address = $Endpoint; return $result }
    $addr = $Endpoint.Substring(0, $idx)
    $port = $Endpoint.Substring($idx + 1)
    $addr = $addr.Trim('[').Trim(']')
    $result.Address = $addr
    $result.Port = $port
    return $result
}

function ConvertTo-NwPrefixLength {
    <# Converts a dotted IPv4 subnet mask (255.255.255.0) to a prefix length. #>
    param([string]$Mask)
    try {
        if ([string]::IsNullOrWhiteSpace($Mask)) { return $null }
        $octets = $Mask.Split('.')
        if ($octets.Count -ne 4) { return $null }
        $bits = 0
        foreach ($o in $octets) {
            $n = 0
            if (-not [int]::TryParse($o, [ref]$n)) { return $null }
            $binary = [Convert]::ToString($n, 2)
            foreach ($ch in $binary.ToCharArray()) { if ($ch -eq '1') { $bits++ } }
        }
        return $bits
    } catch { return $null }
}

function Get-NwNetstatRows {
    <#
        READ-ONLY fallback: parses 'netstat -ano' into structured rows when the
        Get-NetTCPConnection / Get-NetUDPEndpoint cmdlets are unavailable.
    #>
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        $res = Invoke-CommandLineSafe -FilePath 'netstat.exe' -Arguments @('-ano') -TimeoutSeconds 45
        if (-not $res -or -not $res.StdOut) { return ,@($rows) }
        $lines = $res.StdOut -split "`r?`n"
        foreach ($line in $lines) {
            $t = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            $tokens = @($t -split '\s+' | Where-Object { $_ -ne '' })
            if ($tokens.Count -lt 4) { continue }
            $proto = $tokens[0].ToUpperInvariant()
            if ($proto -ne 'TCP' -and $proto -ne 'UDP') { continue }
            $local = $tokens[1]
            $state = ''
            $procId = 0
            if ($proto -eq 'TCP') {
                if ($tokens.Count -lt 5) { continue }
                $state = $tokens[3]
                [void][int]::TryParse($tokens[4], [ref]$procId)
                $remote = $tokens[2]
            } else {
                # UDP has no state column: PROTO LOCAL FOREIGN PID
                $remote = $tokens[2]
                [void][int]::TryParse($tokens[$tokens.Count - 1], [ref]$procId)
            }
            $le = Split-NwEndpoint -Endpoint $local
            $re = Split-NwEndpoint -Endpoint $remote
            $rows.Add([pscustomobject]@{
                Protocol        = $proto
                LocalAddress    = $le.Address
                LocalPort       = $le.Port
                RemoteAddress   = $re.Address
                RemotePort      = $re.Port
                State           = $state
                OwningProcessId = $procId
            })
        }
    } catch {
        Write-Log -Level WARN -Message 'netstat parsing failed.' -Module 'Network' -Exception $_ -Context $Context
    }
    return ,@($rows)
}

#endregion

#region Collectors ------------------------------------------------------------

function Get-NwAdapterRows {
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()
    if (Get-CommandAvailable -Name 'Get-NetAdapter') {
        try {
            $adapters = @(Get-NetAdapter -ErrorAction Stop)
            foreach ($a in $adapters) {
                try {
                    $isVirtual = $false
                    try { $isVirtual = [bool]$a.Virtual } catch { $isVirtual = $false }
                    $rows.Add([pscustomobject]@{
                        InterfaceAlias       = [string]$a.Name
                        InterfaceDescription = [string]$a.InterfaceDescription
                        MacAddress           = [string]$a.MacAddress
                        Status               = [string]$a.Status
                        LinkSpeed            = [string]$a.LinkSpeed
                        MediaType            = [string]$a.MediaType
                        InterfaceIndex       = [int]$a.ifIndex
                        DriverVersion        = [string]$a.DriverVersion
                        IsVirtual            = $isVirtual
                    })
                } catch { }
            }
            return ,@($rows)
        } catch {
            Write-Log -Level WARN -Message 'Get-NetAdapter failed; falling back to CIM.' -Module 'Network' -Exception $_ -Context $Context
        }
    }
    # Fallback: Win32_NetworkAdapter (physical/connected adapters).
    try {
        $cim = Invoke-CimSafe -ClassName 'Win32_NetworkAdapter' -Filter 'PhysicalAdapter=TRUE'
        if (-not $cim -or @($cim).Count -eq 0) { $cim = Invoke-CimSafe -ClassName 'Win32_NetworkAdapter' }
        foreach ($a in $cim) {
            try {
                $speed = $null
                if ($a.Speed) { try { $speed = [string]([math]::Round(([double]$a.Speed)/1MB,0)) + ' Mbps' } catch { $speed = [string]$a.Speed } }
                $status = ''
                switch ([string]$a.NetConnectionStatus) {
                    '2' { $status = 'Up' }
                    '7' { $status = 'Disconnected' }
                    default { $status = [string]$a.NetConnectionStatus }
                }
                $rows.Add([pscustomobject]@{
                    InterfaceAlias       = [string]$a.NetConnectionID
                    InterfaceDescription = [string]$a.Name
                    MacAddress           = [string]$a.MACAddress
                    Status               = $status
                    LinkSpeed            = $speed
                    MediaType            = [string]$a.AdapterType
                    InterfaceIndex       = ($(if ($null -ne $a.InterfaceIndex) { [int]$a.InterfaceIndex } else { -1 }))
                    DriverVersion        = ''
                    IsVirtual            = $false
                })
            } catch { }
        }
    } catch {
        Write-Log -Level WARN -Message 'Win32_NetworkAdapter fallback failed.' -Module 'Network' -Exception $_ -Context $Context
    }
    return ,@($rows)
}

function Get-NwIpConfigRows {
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()

    $haveModern = (Get-CommandAvailable -Name 'Get-NetIPAddress')
    if ($haveModern) {
        try {
            # Build enrichment maps once.
            $adapterMap = @{}   # ifIndex -> adapter object
            try { foreach ($a in (Get-NetAdapter -ErrorAction Stop)) { $adapterMap[[int]$a.ifIndex] = $a } } catch { }

            $gatewayMap = @{}   # ifIndex -> gateway string
            try {
                if (Get-CommandAvailable -Name 'Get-NetRoute') {
                    foreach ($r in (Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' })) {
                        $nh = [string]$r.NextHop
                        if ($nh -and $nh -ne '0.0.0.0' -and $nh -ne '::') {
                            $gi = [int]$r.ifIndex
                            if ($gatewayMap.ContainsKey($gi)) { if ($gatewayMap[$gi] -notmatch [regex]::Escape($nh)) { $gatewayMap[$gi] = ($gatewayMap[$gi] + ', ' + $nh) } }
                            else { $gatewayMap[$gi] = $nh }
                        }
                    }
                }
            } catch { }

            $dnsMap = @{}       # ifIndex -> dns servers joined
            try {
                if (Get-CommandAvailable -Name 'Get-DnsClientServerAddress') {
                    foreach ($d in (Get-DnsClientServerAddress -ErrorAction Stop)) {
                        $servers = @($d.ServerAddresses | Where-Object { $_ })
                        if ($servers.Count -gt 0) {
                            $di = [int]$d.InterfaceIndex
                            if ($dnsMap.ContainsKey($di)) { $dnsMap[$di] = ($dnsMap[$di] + ', ' + ($servers -join ', ')) }
                            else { $dnsMap[$di] = ($servers -join ', ') }
                        }
                    }
                }
            } catch { }

            $dhcpMap = @{}      # ifIndex -> isStatic bool
            $metricMap = @{}    # ifIndex -> interface metric
            try {
                if (Get-CommandAvailable -Name 'Get-NetIPInterface') {
                    foreach ($i in (Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop)) {
                        $ii = [int]$i.InterfaceIndex
                        $dhcpMap[$ii] = ([string]$i.Dhcp -eq 'Disabled')
                        try { $metricMap[$ii] = [int]$i.InterfaceMetric } catch { }
                    }
                }
            } catch { }

            $suffixMap = @{}    # ifAlias -> connection-specific suffix
            try {
                if (Get-CommandAvailable -Name 'Get-DnsClient') {
                    foreach ($c in (Get-DnsClient -ErrorAction Stop)) {
                        if ($c.ConnectionSpecificSuffix) { $suffixMap[[string]$c.InterfaceAlias] = [string]$c.ConnectionSpecificSuffix }
                    }
                }
            } catch { }

            # Group IP addresses by interface.
            $allIps = @(Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notlike 'Loopback Pseudo-Interface*' })
            $groups = $allIps | Group-Object -Property InterfaceIndex
            foreach ($g in $groups) {
                try {
                    $ifIndex = [int]$g.Name
                    $alias = [string]($g.Group[0].InterfaceAlias)
                    $v4 = @($g.Group | Where-Object { [string]$_.AddressFamily -eq 'IPv4' })
                    $v6 = @($g.Group | Where-Object { [string]$_.AddressFamily -eq 'IPv6' })

                    $v4Addresses = @($v4 | ForEach-Object { [string]$_.IPAddress })
                    $v6Addresses = @($v6 | ForEach-Object { [string]$_.IPAddress })

                    # Primary IPv4: prefer a non-APIPA address.
                    $primaryV4 = $null
                    foreach ($a in $v4) { if (([string]$a.IPAddress) -notlike '169.254.*') { $primaryV4 = $a; break } }
                    if (-not $primaryV4 -and $v4.Count -gt 0) { $primaryV4 = $v4[0] }

                    # Primary IPv6: prefer a non-link-local address.
                    $primaryV6 = $null
                    foreach ($a in $v6) { if (([string]$a.IPAddress) -notlike 'fe80:*') { $primaryV6 = $a; break } }
                    if (-not $primaryV6 -and $v6.Count -gt 0) { $primaryV6 = $v6[0] }

                    $prefixLen = $null
                    if ($primaryV4) { try { $prefixLen = [int]$primaryV4.PrefixLength } catch { } }

                    # IsStatic: prefer NetIPInterface DHCP flag, else address PrefixOrigin.
                    $isStatic = $false
                    if ($dhcpMap.ContainsKey($ifIndex)) { $isStatic = [bool]$dhcpMap[$ifIndex] }
                    elseif ($primaryV4) {
                        $po = [string]$primaryV4.PrefixOrigin
                        if ($po -eq 'Manual') { $isStatic = $true } elseif ($po -eq 'Dhcp') { $isStatic = $false }
                    }

                    $mac = ''
                    if ($adapterMap.ContainsKey($ifIndex)) { $mac = [string]$adapterMap[$ifIndex].MacAddress }
                    $desc = ''
                    if ($adapterMap.ContainsKey($ifIndex)) { $desc = [string]$adapterMap[$ifIndex].InterfaceDescription }

                    $gw = ''
                    if ($gatewayMap.ContainsKey($ifIndex)) { $gw = [string]$gatewayMap[$ifIndex] }
                    $dns = ''
                    if ($dnsMap.ContainsKey($ifIndex)) { $dns = [string]$dnsMap[$ifIndex] }
                    $metric = $null
                    if ($metricMap.ContainsKey($ifIndex)) { $metric = $metricMap[$ifIndex] }
                    $suffix = ''
                    if ($suffixMap.ContainsKey($alias)) { $suffix = [string]$suffixMap[$alias] }

                    $rows.Add([pscustomobject]@{
                        InterfaceAlias    = $alias
                        Description       = $desc
                        MacAddress        = $mac
                        IPv4Address       = ($(if ($primaryV4) { [string]$primaryV4.IPAddress } else { '' }))
                        IPv6Address       = ($(if ($primaryV6) { [string]$primaryV6.IPAddress } else { '' }))
                        PrefixLength      = $prefixLen
                        DefaultGateway    = $gw
                        DnsServers        = $dns
                        DnsSuffix         = $suffix
                        IsStatic          = $isStatic
                        InterfaceMetric   = $metric
                        AllIPv4Addresses  = ($v4Addresses -join ', ')
                        AllIPv6Addresses  = ($v6Addresses -join ', ')
                        InterfaceIndex    = $ifIndex
                    })
                } catch { }
            }
            return ,@($rows)
        } catch {
            Write-Log -Level WARN -Message 'Get-NetIPAddress path failed; falling back to CIM.' -Module 'Network' -Exception $_ -Context $Context
        }
    }

    # Fallback: Win32_NetworkAdapterConfiguration (IP-enabled only).
    try {
        $cfgs = Invoke-CimSafe -ClassName 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=TRUE'
        foreach ($c in $cfgs) {
            try {
                $ipAll = @($c.IPAddress)
                $v4 = @($ipAll | Where-Object { $_ -and $_ -notmatch ':' })
                $v6 = @($ipAll | Where-Object { $_ -and $_ -match ':' })
                $prefixLen = $null
                $subnet = @($c.IPSubnet)
                if ($subnet.Count -gt 0) { $prefixLen = ConvertTo-NwPrefixLength -Mask ([string]$subnet[0]) }
                $gw = ''
                if ($c.DefaultIPGateway) { $gw = (@($c.DefaultIPGateway) -join ', ') }
                $dns = ''
                if ($c.DNSServerSearchOrder) { $dns = (@($c.DNSServerSearchOrder) -join ', ') }
                $isStatic = $false
                try { $isStatic = (-not [bool]$c.DHCPEnabled) } catch { $isStatic = $false }

                $rows.Add([pscustomobject]@{
                    InterfaceAlias    = [string]$c.Description
                    Description       = [string]$c.Description
                    MacAddress        = [string]$c.MACAddress
                    IPv4Address       = ($(if ($v4.Count -gt 0) { [string]$v4[0] } else { '' }))
                    IPv6Address       = ($(if ($v6.Count -gt 0) { [string]$v6[0] } else { '' }))
                    PrefixLength      = $prefixLen
                    DefaultGateway    = $gw
                    DnsServers        = $dns
                    DnsSuffix         = [string]$c.DNSDomain
                    IsStatic          = $isStatic
                    InterfaceMetric   = $null
                    AllIPv4Addresses  = ($v4 -join ', ')
                    AllIPv6Addresses  = ($v6 -join ', ')
                    InterfaceIndex    = ($(if ($null -ne $c.InterfaceIndex) { [int]$c.InterfaceIndex } else { -1 }))
                })
            } catch { }
        }
    } catch {
        Write-Log -Level WARN -Message 'Win32_NetworkAdapterConfiguration fallback failed.' -Module 'Network' -Exception $_ -Context $Context
    }
    return ,@($rows)
}

function Get-NwRouteRows {
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()
    $cap = 1000
    if (Get-CommandAvailable -Name 'Get-NetRoute') {
        try {
            $routes = @(Get-NetRoute -ErrorAction Stop)
            $count = 0
            foreach ($r in $routes) {
                if ($count -ge $cap) { break }
                try {
                    $dest = [string]$r.DestinationPrefix
                    $destAddr = $dest
                    $prefix = $null
                    if ($dest -match '/') {
                        $parts = $dest.Split('/')
                        $destAddr = $parts[0]
                        [int]$tmp = 0
                        if ([int]::TryParse($parts[1], [ref]$tmp)) { $prefix = $tmp }
                    }
                    $rows.Add([pscustomobject]@{
                        Destination    = $destAddr
                        PrefixLength   = $prefix
                        NextHop        = [string]$r.NextHop
                        InterfaceAlias = [string]$r.InterfaceAlias
                        Metric         = ($(if ($null -ne $r.RouteMetric) { [int]$r.RouteMetric } else { $null }))
                    })
                    $count++
                } catch { }
            }
            if ($routes.Count -gt $cap) {
                Add-Limitation -Context $Context -Module 'Network' -Message ("Route table truncated to {0} of {1} routes." -f $cap, $routes.Count) -Impact 'Some routes not captured.' | Out-Null
            }
            return ,@($rows)
        } catch {
            Write-Log -Level WARN -Message 'Get-NetRoute failed; falling back to route print.' -Module 'Network' -Exception $_ -Context $Context
        }
    }
    # Fallback: parse 'route print -4' (READ-ONLY).
    try {
        $res = Invoke-CommandLineSafe -FilePath 'route.exe' -Arguments @('print','-4') -TimeoutSeconds 30
        if ($res -and $res.StdOut) {
            $lines = $res.StdOut -split "`r?`n"
            $inActive = $false
            foreach ($line in $lines) {
                $t = $line.Trim()
                if ($t -match 'Active Routes:') { $inActive = $true; continue }
                if ($t -match 'Persistent Routes:') { $inActive = $false; continue }
                if (-not $inActive) { continue }
                if ($t -match '^Network Destination') { continue }
                if ([string]::IsNullOrWhiteSpace($t)) { continue }
                if ($t -match '^=+$') { continue }
                $tokens = @($t -split '\s+' | Where-Object { $_ -ne '' })
                if ($tokens.Count -lt 5) { continue }
                if ($tokens[0] -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
                $prefix = ConvertTo-NwPrefixLength -Mask $tokens[1]
                $metric = $null
                [int]$mtmp = 0
                if ([int]::TryParse($tokens[4], [ref]$mtmp)) { $metric = $mtmp }
                $rows.Add([pscustomobject]@{
                    Destination    = $tokens[0]
                    PrefixLength   = $prefix
                    NextHop        = $tokens[2]
                    InterfaceAlias = $tokens[3]
                    Metric         = $metric
                })
            }
        }
    } catch {
        Write-Log -Level WARN -Message 'route print fallback failed.' -Module 'Network' -Exception $_ -Context $Context
    }
    return ,@($rows)
}

function Get-NwDnsRows {
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()

    # Suffix search list (global).
    try {
        if (Get-CommandAvailable -Name 'Get-DnsClientGlobalSetting') {
            $g = Get-DnsClientGlobalSetting -ErrorAction Stop
            $i = 0
            foreach ($s in @($g.SuffixSearchList)) {
                if ($s) {
                    $rows.Add([pscustomobject]@{ EntryType='SuffixSearchList'; InterfaceAlias=''; Value=[string]$s; Notes=("Order {0}" -f $i) })
                    $i++
                }
            }
        } else {
            $sl = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'SearchList'
            if ($sl) {
                foreach ($s in ([string]$sl -split '[,; ]')) {
                    if ($s) { $rows.Add([pscustomobject]@{ EntryType='SuffixSearchList'; InterfaceAlias=''; Value=[string]$s; Notes='registry SearchList' }) }
                }
            }
        }
    } catch { Write-Log -Level WARN -Message 'DNS suffix search list collection failed.' -Module 'Network' -Exception $_ -Context $Context }

    # Per-interface DNS servers.
    try {
        if (Get-CommandAvailable -Name 'Get-DnsClientServerAddress') {
            foreach ($d in (Get-DnsClientServerAddress -ErrorAction Stop)) {
                $servers = @($d.ServerAddresses | Where-Object { $_ })
                if ($servers.Count -gt 0) {
                    $rows.Add([pscustomobject]@{
                        EntryType      = 'InterfaceDns'
                        InterfaceAlias = [string]$d.InterfaceAlias
                        Value          = ($servers -join ', ')
                        Notes          = [string]$d.AddressFamily
                    })
                }
            }
        } else {
            # DnsClient module unavailable (e.g. PS7 on 2012 R2, no WinPS 5.1 compat session).
            # Win32_NetworkAdapterConfiguration is CIM-based and works everywhere.
            foreach ($nc in (Invoke-CimSafe -ClassName 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = True')) {
                $servers = @($nc.DNSServerSearchOrder | Where-Object { $_ })
                if ($servers.Count -gt 0) {
                    $rows.Add([pscustomobject]@{
                        EntryType      = 'InterfaceDns'
                        InterfaceAlias = [string]$nc.Description
                        Value          = ($servers -join ', ')
                        Notes          = 'Win32_NetworkAdapterConfiguration'
                    })
                }
            }
        }
    } catch { Write-Log -Level WARN -Message 'Per-interface DNS collection failed.' -Module 'Network' -Exception $_ -Context $Context }

    # Hosts file entries.
    try {
        $hostsPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\etc\hosts'
        if (Test-Path -LiteralPath $hostsPath) {
            $hostLines = Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue
            foreach ($hl in $hostLines) {
                $t = ([string]$hl).Trim()
                if ([string]::IsNullOrWhiteSpace($t)) { continue }
                if ($t.StartsWith('#')) { continue }
                $tokens = @($t -split '\s+' | Where-Object { $_ -ne '' })
                if ($tokens.Count -lt 2) { continue }
                $ip = $tokens[0]
                $names = @($tokens[1..($tokens.Count - 1)]) -join ', '
                $rows.Add([pscustomobject]@{ EntryType='HostsFileEntry'; InterfaceAlias=''; Value=$ip; Notes=$names })
            }
        }
    } catch { Write-Log -Level WARN -Message 'Hosts file collection failed.' -Module 'Network' -Exception $_ -Context $Context }

    return ,@($rows)
}

function Get-NwListeningRows {
    param([object]$Context, [hashtable]$ProcMap, [hashtable]$SvcMap, [object]$Netstat)
    $rows = [System.Collections.Generic.List[object]]::new()
    if (-not $ProcMap) { $ProcMap = @{} }
    if (-not $SvcMap) { $SvcMap = @{} }

    $resolve = {
        param($procId)
        $pn = ''
        $sn = ''
        try { if ($procId -gt 0 -and $ProcMap.ContainsKey([int]$procId)) { $pn = [string]$ProcMap[[int]$procId] } } catch { }
        try { if ($procId -gt 0 -and $SvcMap.ContainsKey([int]$procId)) { $sn = [string]$SvcMap[[int]$procId] } } catch { }
        return @{ Process = $pn; Service = $sn }
    }

    if (Get-CommandAvailable -Name 'Get-NetTCPConnection') {
        try {
            foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
                try {
                    $procId = 0
                    if ($null -ne $c.OwningProcess) { $procId = [int]$c.OwningProcess }
                    $r = & $resolve $procId
                    # >= 49152 is the IANA ephemeral/dynamic floor. Flagged, not dropped: the raw
                    # export stays complete and consumers (workbook filter, edge builder) decide.
                    $portNum = 0
                    [void][int]::TryParse([string]$c.LocalPort, [ref]$portNum)
                    $rows.Add([pscustomobject]@{
                        Protocol        = 'TCP'
                        LocalAddress    = [string]$c.LocalAddress
                        LocalPort       = [string]$c.LocalPort
                        State           = 'Listen'
                        OwningProcessId = $procId
                        Process         = $r.Process
                        ServiceName     = $r.Service
                        IsEphemeral     = ($portNum -ge 49152)
                    })
                } catch { }
            }
        } catch { Write-Log -Level WARN -Message 'Get-NetTCPConnection (Listen) failed.' -Module 'Network' -Exception $_ -Context $Context }

        try {
            if (Get-CommandAvailable -Name 'Get-NetUDPEndpoint') {
                foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) {
                    try {
                        $procId = 0
                        if ($null -ne $u.OwningProcess) { $procId = [int]$u.OwningProcess }
                        $r = & $resolve $procId
                        $portNum = 0
                        [void][int]::TryParse([string]$u.LocalPort, [ref]$portNum)
                        $rows.Add([pscustomobject]@{
                            Protocol        = 'UDP'
                            LocalAddress    = [string]$u.LocalAddress
                            LocalPort       = [string]$u.LocalPort
                            State           = 'Listen'
                            OwningProcessId = $procId
                            Process         = $r.Process
                            ServiceName     = $r.Service
                            IsEphemeral     = ($portNum -ge 49152)
                        })
                    } catch { }
                }
            }
        } catch { Write-Log -Level WARN -Message 'Get-NetUDPEndpoint failed.' -Module 'Network' -Exception $_ -Context $Context }

        return ,@($rows)
    }

    # Fallback: netstat rows.
    try {
        foreach ($n in @($Netstat)) {
            $isListening = ($n.Protocol -eq 'TCP' -and $n.State -match 'LISTEN') -or ($n.Protocol -eq 'UDP')
            if (-not $isListening) { continue }
            $procId = 0
            try { $procId = [int]$n.OwningProcessId } catch { }
            $r = & $resolve $procId
            $portNum = 0
            [void][int]::TryParse([string]$n.LocalPort, [ref]$portNum)
            $rows.Add([pscustomobject]@{
                Protocol        = [string]$n.Protocol
                LocalAddress    = [string]$n.LocalAddress
                LocalPort       = [string]$n.LocalPort
                State           = 'Listen'
                OwningProcessId = $procId
                Process         = $r.Process
                ServiceName     = $r.Service
                IsEphemeral     = ($portNum -ge 49152)
            })
        }
    } catch { Write-Log -Level WARN -Message 'netstat listening fallback failed.' -Module 'Network' -Exception $_ -Context $Context }

    return ,@($rows)
}

function Get-NwEstablishedRows {
    param([object]$Context, [hashtable]$ProcMap, [object]$Netstat)
    $rows = [System.Collections.Generic.List[object]]::new()
    if (-not $ProcMap) { $ProcMap = @{} }
    $cap = 300

    if (Get-CommandAvailable -Name 'Get-NetTCPConnection') {
        try {
            $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop)
            $count = 0
            foreach ($c in $conns) {
                if ($count -ge $cap) { break }
                try {
                    $procId = 0
                    if ($null -ne $c.OwningProcess) { $procId = [int]$c.OwningProcess }
                    $pn = ''
                    if ($procId -gt 0 -and $ProcMap.ContainsKey($procId)) { $pn = [string]$ProcMap[$procId] }
                    $rows.Add([pscustomobject]@{
                        LocalAddress    = [string]$c.LocalAddress
                        LocalPort       = [string]$c.LocalPort
                        RemoteAddress   = [string]$c.RemoteAddress
                        RemotePort      = [string]$c.RemotePort
                        OwningProcessId = $procId
                        Process         = $pn
                    })
                    $count++
                } catch { }
            }
            if ($conns.Count -gt $cap) {
                Add-Limitation -Context $Context -Module 'Network' -Message ("Established connections truncated to {0} of {1}." -f $cap, $conns.Count) -Impact 'Some active connections not captured.' | Out-Null
            }
            return ,@($rows)
        } catch { Write-Log -Level WARN -Message 'Get-NetTCPConnection (Established) failed.' -Module 'Network' -Exception $_ -Context $Context }
    }

    # Fallback: netstat rows.
    try {
        $count = 0
        foreach ($n in @($Netstat)) {
            if ($count -ge $cap) { break }
            if ($n.Protocol -ne 'TCP' -or $n.State -notmatch 'ESTABLISHED') { continue }
            $procId = 0
            try { $procId = [int]$n.OwningProcessId } catch { }
            $pn = ''
            if ($procId -gt 0 -and $ProcMap.ContainsKey($procId)) { $pn = [string]$ProcMap[$procId] }
            $rows.Add([pscustomobject]@{
                LocalAddress    = [string]$n.LocalAddress
                LocalPort       = [string]$n.LocalPort
                RemoteAddress   = [string]$n.RemoteAddress
                RemotePort      = [string]$n.RemotePort
                OwningProcessId = $procId
                Process         = $pn
            })
            $count++
        }
    } catch { Write-Log -Level WARN -Message 'netstat established fallback failed.' -Module 'Network' -Exception $_ -Context $Context }

    return ,@($rows)
}

function Get-NwFirewallRows {
    param([object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()

    if (-not (Get-CommandAvailable -Name 'Get-NetFirewallRule')) {
        Add-Limitation -Context $Context -Module 'Network' -Message 'Get-NetFirewallRule not available; firewall rules not enumerated.' -Reason 'Cmdlet/service unavailable.' | Out-Null
        return ,@($rows)
    }

    # Safety cap only - not a performance workaround. Enrichment below is two bulk cmdlet calls
    # regardless of rule count (see next comment), so there is no per-rule cost to cap against;
    # this just bounds memory/output size on a host with an implausibly large rule store.
    $maxRules = 20000
    try { if ($Context.Parameters -and $Context.Parameters.ContainsKey('MaxFirewallRules') -and $Context.Parameters['MaxFirewallRules']) { $maxRules = [int]$Context.Parameters['MaxFirewallRules'] } } catch { }

    try {
        $all = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { ([string]$_.Enabled -eq 'True') -and ([string]$_.Action -eq 'Allow') })
        $total = $all.Count
        $subset = @($all | Select-Object -First $maxRules)

        # Get-NetFirewallPortFilter/-ApplicationFilter piped one rule at a time each re-query the
        # whole filter store per call (~190ms/rule measured - 345 rules took 65s+, which is what
        # the old per-rule time budget was actually working around). Fetching every filter once
        # and joining by InstanceID (shared with the owning rule's InstanceID/Name) is the same
        # data in ~200ms total regardless of rule count, so every rule gets full enrichment.
        $pfMap = @{}
        try { foreach ($f in (Get-NetFirewallPortFilter -ErrorAction Stop)) { $pfMap[$f.InstanceID] = $f } } catch { }
        $afMap = @{}
        try { foreach ($f in (Get-NetFirewallApplicationFilter -ErrorAction Stop)) { $afMap[$f.InstanceID] = $f } } catch { }

        foreach ($r in $subset) {
            $proto = ''
            $localPort = ''
            $program = ''
            $pf = $pfMap[$r.InstanceID]
            if ($pf) { $proto = [string]$pf.Protocol; $localPort = (@($pf.LocalPort) -join ',') }
            $af = $afMap[$r.InstanceID]
            if ($af) { $program = [string]$af.Program }
            $rows.Add([pscustomobject]@{
                Name         = [string]$r.DisplayName
                RuleName     = [string]$r.Name
                DisplayGroup = [string]$r.DisplayGroup
                Direction    = [string]$r.Direction
                Action       = [string]$r.Action
                Protocol     = $proto
                LocalPort    = $localPort
                Program      = $program
                Profile      = [string]$r.Profile
                Enabled      = $true
            })
        }

        if ($total -gt $maxRules) {
            Add-Limitation -Context $Context -Module 'Network' -Message ("Enabled/allow firewall rules truncated to {0} of {1}." -f $maxRules, $total) -Impact 'Some firewall rules not captured.' | Out-Null
        }
    } catch {
        Add-Limitation -Context $Context -Module 'Network' -Message 'Firewall rule enumeration failed.' -Reason ([string]$_.Exception.Message) | Out-Null
        Write-Log -Level WARN -Message 'Get-NetFirewallRule enumeration failed.' -Module 'Network' -Exception $_ -Context $Context
    }
    return ,@($rows)
}

#endregion

#region Six-function contract -------------------------------------------------

function Invoke-DiscoveryCollection {
    param([object]$Context)
    Write-SectionStatus -Title 'Network' -Status 'Collecting' -Context $Context

    $procMap = @{}
    $svcMap = @{}
    try { $procMap = Get-NwProcessMap } catch { }
    try { $svcMap = Get-NwServiceMap -Context $Context } catch { }

    $netstat = @()
    if (-not (Get-CommandAvailable -Name 'Get-NetTCPConnection')) {
        # Get-NwNetstatRows already returns a clean array via ',@(...)' - wrapping it again in
        # @() here double-wraps into a 1-element array containing the real array as its only
        # element, so every consumer's foreach ran once over the whole array via member
        # enumeration instead of once per row (silently near-empty ListeningPorts/
        # EstablishedConnections wherever this fallback is actually exercised).
        try { $netstat = Get-NwNetstatRows -Context $Context } catch { $netstat = @() }
    }

    $raw = @{
        NetworkAdapters        = @()
        IPConfiguration        = @()
        Routes                 = @()
        DnsClient              = @()
        ListeningPorts         = @()
        EstablishedConnections = @()
        FirewallRules          = @()
    }

    # NOTE: helpers already return clean arrays via ',@(...)'. Do NOT wrap the call
    # in @() here - that would double-wrap into a 1-element array containing the array.
    try { $raw.NetworkAdapters        = Get-NwAdapterRows -Context $Context } catch { Write-Log -Level WARN -Message 'NetworkAdapters collection failed.' -Module 'Network' -Exception $_ -Context $Context }
    try { $raw.IPConfiguration        = Get-NwIpConfigRows -Context $Context } catch { Write-Log -Level WARN -Message 'IPConfiguration collection failed.' -Module 'Network' -Exception $_ -Context $Context }
    try { $raw.Routes                 = Get-NwRouteRows -Context $Context } catch { Write-Log -Level WARN -Message 'Routes collection failed.' -Module 'Network' -Exception $_ -Context $Context }
    try { $raw.DnsClient              = Get-NwDnsRows -Context $Context } catch { Write-Log -Level WARN -Message 'DnsClient collection failed.' -Module 'Network' -Exception $_ -Context $Context }
    try { $raw.ListeningPorts         = Get-NwListeningRows -Context $Context -ProcMap $procMap -SvcMap $svcMap -Netstat $netstat } catch { Write-Log -Level WARN -Message 'ListeningPorts collection failed.' -Module 'Network' -Exception $_ -Context $Context }
    try { $raw.EstablishedConnections = Get-NwEstablishedRows -Context $Context -ProcMap $procMap -Netstat $netstat } catch { Write-Log -Level WARN -Message 'EstablishedConnections collection failed.' -Module 'Network' -Exception $_ -Context $Context }
    try { $raw.FirewallRules          = Get-NwFirewallRows -Context $Context } catch { Write-Log -Level WARN -Message 'FirewallRules collection failed.' -Module 'Network' -Exception $_ -Context $Context }

    return $raw
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if ($null -eq $RawData) {
        Add-Limitation -Context $Context -Module 'Network' -Message 'No raw network data was returned by collection.' -Reason 'Collection returned null.' | Out-Null
        $RawData = @{}
    }

    $get = {
        param($key)
        if ($RawData -is [hashtable] -and $RawData.ContainsKey($key) -and $RawData[$key]) { @($RawData[$key]) } else { @() }
    }

    Add-DataSet -Context $Context -Name 'NetworkAdapters' -Description 'Physical/virtual network adapters and link status.' -Rows (& $get 'NetworkAdapters') -Visibility 'Both' -SourceModule 'Network' | Out-Null
    Add-DataSet -Context $Context -Name 'IPConfiguration' -Description 'Per-interface IP configuration (addresses, gateway, DNS, static/DHCP).' -Rows (& $get 'IPConfiguration') -Visibility 'Both' -SourceModule 'Network' | Out-Null
    Add-DataSet -Context $Context -Name 'Routes' -Description 'IP routing table entries.' -Rows (& $get 'Routes') -Visibility 'Internal' -SourceModule 'Network' | Out-Null
    Add-DataSet -Context $Context -Name 'DnsClient' -Description 'DNS suffix search list, per-interface DNS servers, and hosts file entries.' -Rows (& $get 'DnsClient') -Visibility 'Both' -SourceModule 'Network' | Out-Null
    # Ephemeral UDP sockets (a DNS server's query-response pool) can outnumber real listeners
    # 50:1 (5008 of 5145 rows measured on a lab DC) and are never scoping evidence. CSV/JSON keep
    # every row; the workbook worksheet drops non-TCP ephemerals so it doesn't bury the ~105
    # actionable listeners under thousands of transient sockets. A TCP listener on a high port is
    # still real (a named SQL instance's dynamic port, an app on a random port), so only UDP is cut.
    $listeningPorts = & $get 'ListeningPorts'
    $listeningPortsForWorkbook = @($listeningPorts | Where-Object { -not ($_.IsEphemeral -and $_.Protocol -ne 'TCP') })
    Add-DataSet -Context $Context -Name 'ListeningPorts' -Description 'Listening TCP/UDP endpoints correlated to processes/services.' -Rows $listeningPorts -WorkbookRows $listeningPortsForWorkbook -Visibility 'Internal' -SourceModule 'Network' | Out-Null
    Add-DataSet -Context $Context -Name 'EstablishedConnections' -Description 'Established outbound/inbound TCP connections (sampled).' -Rows (& $get 'EstablishedConnections') -Visibility 'Internal' -SourceModule 'Network' | Out-Null
    Add-DataSet -Context $Context -Name 'FirewallRules' -Description 'Enabled allow firewall rules (inbound/outbound) summary.' -Rows (& $get 'FirewallRules') -Visibility 'Internal' -SourceModule 'Network' | Out-Null
}

function Invoke-DiscoveryRiskAnalysis {
    param([object]$Context)

    # Server -> DNS servers and Server -> gateways dependency edges.
    try {
        if ($Context.DataSets.Contains('IPConfiguration')) {
            $dnsSeen = @{}
            $gwSeen = @{}
            foreach ($row in @($Context.DataSets['IPConfiguration'].Rows)) {
                try {
                    if ($row.DnsServers) {
                        foreach ($d in ([string]$row.DnsServers -split ',')) {
                            $dv = $d.Trim()
                            if ($dv -and -not $dnsSeen.ContainsKey($dv)) {
                                $dnsSeen[$dv] = $true
                                Add-DependencyEdge -Context $Context -SourceType 'Server' -SourceName $Context.ComputerName -DependencyType 'DNS' -Target $dv `
                                    -Evidence ("Configured DNS server on interface '{0}'." -f $row.InterfaceAlias) -Confidence 'Confirmed' -SourceDataset 'IPConfiguration' `
                                    -ProjectImpact 'Name resolution dependency; relevant to cutover/decommission.' `
                                    -ValidationQuestion 'Is this DNS server being retained or migrated?' | Out-Null
                            }
                        }
                    }
                    if ($row.DefaultGateway) {
                        foreach ($g in ([string]$row.DefaultGateway -split ',')) {
                            $gv = $g.Trim()
                            if ($gv -and -not $gwSeen.ContainsKey($gv)) {
                                $gwSeen[$gv] = $true
                                Add-DependencyEdge -Context $Context -SourceType 'Server' -SourceName $Context.ComputerName -DependencyType 'Gateway' -Target $gv `
                                    -Evidence ("Default gateway on interface '{0}'." -f $row.InterfaceAlias) -Confidence 'Confirmed' -SourceDataset 'IPConfiguration' `
                                    -ProjectImpact 'Upstream routing dependency.' | Out-Null
                            }
                        }
                    }
                } catch { }
            }
        }
    } catch { Write-Log -Level WARN -Message 'DNS/gateway dependency edge analysis failed.' -Module 'Network' -Exception $_ -Context $Context }

    # Service/Process -> listening port dependency edges (deduped, capped).
    try {
        if ($Context.DataSets.Contains('ListeningPorts')) {
            $seen = @{}
            $edgeCount = 0
            $edgeCap = 150
            foreach ($row in @($Context.DataSets['ListeningPorts'].Rows)) {
                if ($edgeCount -ge $edgeCap) { break }
                # Ephemeral sockets (dns on a DC emitted 5008 of 5145 rows) are not listening
                # services; without this filter they consume the 150-edge cap and crowd out
                # the actionable listeners. Rows lacking the flag read as $null = keep.
                # Only non-TCP ephemerals are noise: a TCP listener on a high port is a real service
                # (a named SQL instance's dynamic port, an app on a random port) clients connect to.
                if ($row.IsEphemeral -and $row.Protocol -ne 'TCP') { continue }
                try {
                    $srcName = ''
                    $srcType = 'Process'
                    if ($row.ServiceName) { $srcName = [string]$row.ServiceName; $srcType = 'Service' }
                    elseif ($row.Process) { $srcName = [string]$row.Process; $srcType = 'Process' }
                    if (-not $srcName) { continue }
                    $portKey = ("{0}/{1}/{2}" -f $srcName, $row.Protocol, $row.LocalPort)
                    if ($seen.ContainsKey($portKey)) { continue }
                    $seen[$portKey] = $true
                    Add-DependencyEdge -Context $Context -SourceType $srcType -SourceName $srcName -DependencyType 'ListeningPort' `
                        -Target ("{0}/{1}" -f $row.Protocol, $row.LocalPort) `
                        -Evidence ("Listening on {0} port {1} ({2})." -f $row.Protocol, $row.LocalPort, $row.LocalAddress) -Confidence 'Likely' -SourceDataset 'ListeningPorts' `
                        -ProjectImpact 'Other systems may connect to this port; relevant to migration/decommission.' | Out-Null
                    $edgeCount++
                } catch { }
            }
        }
    } catch { Write-Log -Level WARN -Message 'Listening-port dependency edge analysis failed.' -Module 'Network' -Exception $_ -Context $Context }
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)

    try {
        $hasStatic = $false
        if ($Context.DataSets.Contains('IPConfiguration')) {
            foreach ($row in @($Context.DataSets['IPConfiguration'].Rows)) { if ($row.IsStatic) { $hasStatic = $true; break } }
        }
        if ($hasStatic) {
            Add-FollowUpQuestion -Context $Context -Question 'This server uses one or more static IP addresses - are these referenced by other systems, firewall rules, or DNS records that must be updated during a migration?' -Category 'Network' -Module 'Network' -Audience 'Both' | Out-Null
        }
    } catch { }

    try {
        $listenCount = 0
        if ($Context.DataSets.Contains('ListeningPorts')) { $listenCount = @($Context.DataSets['ListeningPorts'].Rows).Count }
        if ($listenCount -gt 0) {
            Add-FollowUpQuestion -Context $Context -Question 'Which client systems or applications connect to the services listening on this server? Confirm consumers before any cutover or decommission.' -Category 'Network' -Module 'Network' -Audience 'Both' | Out-Null
        }
    } catch { }

    try {
        Add-FollowUpQuestion -Context $Context -Question 'Are there any hardcoded IP addresses or server names (in application configs, firewall/DNS records, or third-party integrations) that point at this server?' -Category 'Network' -Module 'Network' -Audience 'Internal' | Out-Null
    } catch { }
}

#endregion

Export-ModuleMember -Function `
    'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection', `
    'ConvertTo-DiscoveryDatasets','Invoke-DiscoveryRiskAnalysis','Get-DiscoveryFollowUpQuestions', `
    'Get-NwProcessMap','Get-NwServiceMap','Split-NwEndpoint','ConvertTo-NwPrefixLength','Get-NwNetstatRows', `
    'Get-NwAdapterRows','Get-NwIpConfigRows','Get-NwRouteRows','Get-NwDnsRows', `
    'Get-NwListeningRows','Get-NwEstablishedRows','Get-NwFirewallRows'
