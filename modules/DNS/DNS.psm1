<#
    DNS.psm1 - DNS Server role discovery (read-only, summary only). Role-gated.
    DnsRecordsReferencingThisServer: A/CNAME records in this server's own zones whose target
    is this server's own hostname/IP - the records that break if this server is renamed,
    re-IPed, or retired. Forward zones only, capped, read-only (never touches a zone's data).
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='DNS'; DisplayName='DNS Server'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole='DNS'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('DnsServerSettings','DnsZones','DnsRecordsReferencingThisServer')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DnsPresent {
    if (Get-CommandAvailable -Name 'Get-DnsServerZone') { return $true }
    if (Get-Service -Name 'DNS' -ErrorAction SilentlyContinue) { return $true }
    return $false
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    if (Test-DnsPresent) { return [pscustomobject]@{ ModuleName='DNS'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='DNS'; CanRun=$false; Status='NotApplicable'; Reason='DNS Server role not present.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    # Default cmdlets resolve $env:COMPUTERNAME through DNS on every call (~1 s each; 20-30x slower than 'localhost'), and a resolution failure is swallowed by -ErrorAction SilentlyContinue as an empty result.
    $PSDefaultParameterValues = @{ 'Get-DnsServer*:ComputerName' = 'localhost' }
    $settings=[System.Collections.Generic.List[object]]::new(); $zones=[System.Collections.Generic.List[object]]::new()
    if (-not (Get-CommandAvailable -Name 'Get-DnsServerZone')) { Add-Limitation -Context $Context -Module 'DNS' -Message 'DnsServer module not available; DNS present but not enumerable.' | Out-Null; return ,@{ DnsServerSettings=@(); DnsZones=@(); DnsRecordsReferencingThisServer=@() } }
    try {
        $fwd = ''
        try { $fwd = ((Get-DnsServerForwarder -ErrorAction SilentlyContinue).IPAddress -join ', ') } catch { }
        $settings.Add([pscustomobject]@{ Item='Forwarders'; Value=$fwd })
    } catch { }
    try {
        foreach ($z in (Get-DnsServerZone -ErrorAction SilentlyContinue)) {
            $zones.Add([pscustomobject]@{ ZoneName=$z.ZoneName; ZoneType=[string]$z.ZoneType; IsDsIntegrated=$z.IsDsIntegrated; IsReverse=$z.IsReverseLookupZone; DynamicUpdate=[string]$z.DynamicUpdate; IsAutoCreated=$z.IsAutoCreated })
        }
    } catch { Add-Limitation -Context $Context -Module 'DNS' -Message 'DNS zone enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    $selfRefs = Get-DnsRecordsReferencingThisServer -Context $Context -Zones $zones

    return ,@{ DnsServerSettings=@($settings); DnsZones=@($zones); DnsRecordsReferencingThisServer=@($selfRefs) }
}

function Get-DnsRecordsReferencingThisServer {
    <#
        A/CNAME records (forward zones only) whose target is this server's own hostname/IP -
        the records that break if this server is renamed, re-IPed, or retired. Bounded by
        $recordCap total records examined, so a very large zone cannot run away.
    #>
    param([object]$Context, [object[]]$Zones)
    $rows = [System.Collections.Generic.List[object]]::new()
    $recordCap = 3000
    $examined = 0
    $capped = $false

    $myNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$myNames.Add($env:COMPUTERNAME)
    if ($env:USERDNSDOMAIN) { [void]$myNames.Add(("{0}.{1}" -f $env:COMPUTERNAME, $env:USERDNSDOMAIN)) }

    $myIPs = [System.Collections.Generic.HashSet[string]]::new()
    try {
        if ($Context.DataSets.Contains('IPConfiguration')) {
            foreach ($ipc in @($Context.DataSets['IPConfiguration'].Rows)) {
                foreach ($ip in (([string]$ipc.AllIPv4Addresses) -split ',')) { $t = $ip.Trim(); if ($t) { [void]$myIPs.Add($t) } }
                if ($ipc.IPv4Address) { [void]$myIPs.Add([string]$ipc.IPv4Address) }
            }
        }
    } catch { }
    if ($myIPs.Count -eq 0) { return ,@($rows) }

    foreach ($z in ($Zones | Where-Object { -not $_.IsReverse })) {
        if ($capped) { break }
        try {
            foreach ($r in (Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction Stop)) {
                if ($examined -ge $recordCap) { $capped = $true; break }
                $examined++
                $matchTarget = ''
                if ($r.RecordType -eq 'A' -and $r.RecordData.IPv4Address) {
                    $ip = $r.RecordData.IPv4Address.ToString()
                    if ($myIPs.Contains($ip)) { $matchTarget = $ip }
                } elseif ($r.RecordType -eq 'CNAME' -and $r.RecordData.HostNameAlias) {
                    $alias = ([string]$r.RecordData.HostNameAlias).TrimEnd('.')
                    if ($myNames.Contains($alias)) { $matchTarget = $alias }
                }
                if ($matchTarget) {
                    $fqName = if ($r.HostName -eq '@') { $z.ZoneName } else { ("{0}.{1}" -f $r.HostName, $z.ZoneName) }
                    $rows.Add([pscustomobject]@{ ZoneName=$z.ZoneName; RecordType=[string]$r.RecordType; RecordName=$fqName; PointsTo=$matchTarget })
                }
            }
        } catch { Add-Limitation -Context $Context -Module 'DNS' -Message ("Record enumeration failed for zone '{0}'." -f $z.ZoneName) -Reason $_.Exception.Message | Out-Null }
    }
    if ($capped) { Add-Limitation -Context $Context -Module 'DNS' -Message ("DNS record scan stopped early (cap {0} records examined); some zones may not have been fully checked." -f $recordCap) -Impact 'Coverage capped' | Out-Null }
    return ,@($rows)
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'DnsServerSettings' -Description 'DNS server settings (forwarders).' -Rows (& $get 'DnsServerSettings') -Visibility 'Internal' -SourceModule 'DNS' | Out-Null
    Add-DataSet -Context $Context -Name 'DnsZones'          -Description 'DNS zones summary.'                -Rows (& $get 'DnsZones')          -Visibility 'Internal' -SourceModule 'DNS' | Out-Null
    Add-DataSet -Context $Context -Name 'DnsRecordsReferencingThisServer' -Description 'A/CNAME records (forward zones) whose target is this server''s own hostname or IP.' -Rows (& $get 'DnsRecordsReferencingThisServer') -Visibility 'Internal' -SourceModule 'DNS' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Test-DnsPresent','Get-DnsRecordsReferencingThisServer'
