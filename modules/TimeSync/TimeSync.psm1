<#
    TimeSync.psm1 - Windows Time service configuration and hierarchy (read-only).

    Produces: TimeSync.

    Why this module exists: time is a hard dependency for Kerberos, for certificate
    validation, for database replication and for every log an incident is later
    reconstructed from. A server that is the authoritative time source for a domain
    cannot be retired without moving that role, and a server whose offset has drifted
    will start failing authentication in ways that look like everything except a clock.
    Neither fact was previously discoverable anywhere in the toolkit.

    Uses 'w32tm /query' with READ-ONLY verbs only (/status, /source, /configuration,
    /peers). Never runs /resync, /register, /unregister, or any /config write.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='TimeSync'; DisplayName='Time Synchronization'; Category='System'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('TimeSync')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    if (Get-CommandAvailable -Name 'w32tm.exe') {
        return [pscustomobject]@{ ModuleName='TimeSync'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
    }
    [pscustomobject]@{ ModuleName='TimeSync'; CanRun=$false; Status='NotApplicable'; Reason='w32tm.exe not present.'; Limitations=@() }
}

function ConvertFrom-W32tmOffset {
    <#
        Parses the 'Phase Offset: 0.0012345s' line from w32tm /status into seconds.
        Returns $null when the value is absent or unparseable - an unknown offset is
        reported as unknown rather than silently becoming zero, because zero reads as
        'healthy' and would be a lie.
    #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, '(?im)^\s*Phase Offset:\s*(-?[\d\.]+)s')
    if (-not $m.Success) { return $null }
    $v = 0.0
    if ([double]::TryParse($m.Groups[1].Value, [ref]$v)) { return [math]::Round($v, 4) }
    return $null
}

function Get-W32tmField {
    param([string]$Text, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $m = [regex]::Match($Text, ('(?im)^\s*' + [regex]::Escape($Label) + ':\s*(.+)$'))
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return ''
}

function Invoke-DiscoveryCollection {
    param([object]$Context)

    $statusText = ''
    $sourceText = ''

    try { $r = Invoke-CommandLineSafe -FilePath 'w32tm.exe' -Arguments @('/query','/status') -TimeoutSeconds 30; if ($r.Succeeded) { $statusText = $r.StdOut } } catch { }
    try { $r = Invoke-CommandLineSafe -FilePath 'w32tm.exe' -Arguments @('/query','/source') -TimeoutSeconds 30; if ($r.Succeeded) { $sourceText = ($r.StdOut).Trim() } } catch { }

    if (-not $statusText) {
        Add-Limitation -Context $Context -Module 'TimeSync' `
            -Message 'w32tm /query /status returned nothing (the Windows Time service may be stopped).' `
            -Impact 'Time sync state unknown' | Out-Null
    }

    $source  = if ($sourceText) { $sourceText } else { Get-W32tmField -Text $statusText -Label 'Source' }
    $stratum = Get-W32tmField -Text $statusText -Label 'Stratum'
    $lastSync = Get-W32tmField -Text $statusText -Label 'Last Successful Sync Time'
    $offset  = ConvertFrom-W32tmOffset -Text $statusText

    # NtpServer / Type come from policy or local config and are what an engineer has to
    # reproduce on the replacement server.
    $ntpServer = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name 'NtpServer'
    $syncType  = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name 'Type'
    $announce  = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name 'AnnounceFlags'
    $ntpEnabled = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer' -Name 'Enabled'

    $svcState = ''
    $svcStart = ''
    try {
        $svc = Invoke-CimSafe -ClassName 'Win32_Service' -Filter "Name='W32Time'" | Select-Object -First 1
        if ($svc) { $svcState = [string]$svc.State; $svcStart = [string]$svc.StartMode }
    } catch { }

    # AnnounceFlags 5 (or any value with bit 2 set) means this host advertises itself as
    # a reliable time source - i.e. other machines follow its clock.
    $isAuthoritative = $false
    try { if ($null -ne $announce) { $isAuthoritative = [bool](([int]$announce -band 4) -ne 0) } } catch { }

    # A local-CMOS source on a domain member is the classic broken-time-hierarchy signature.
    $isDomainMember = $false
    try {
        if ($Context.DataSets.Contains('DomainContext')) {
            $isDomainMember = [bool](@($Context.DataSets['DomainContext'].Rows | Where-Object { $_.PartOfDomain -eq $true }).Count -gt 0)
        }
    } catch { }
    $usesLocalClock = [bool]($source -match '(?i)local cmos clock|free-?running')

    # Computed before the object literal: 'try' is a statement, not an expression, so it
    # cannot be inlined into a hashtable value in Windows PowerShell 5.1.
    $tzId = ''
    try { $tzId = [string](Get-TimeZone -ErrorAction SilentlyContinue).Id } catch { }
    if (-not $tzId) { try { $tzId = [string](Invoke-CimSafe -ClassName 'Win32_TimeZone' | Select-Object -First 1).StandardName } catch { } }

    $row = [pscustomobject]@{
        TimeSource              = [string]$source
        Stratum                 = [string]$stratum
        LastSuccessfulSync      = [string]$lastSync
        PhaseOffsetSeconds      = $offset
        OffsetUnknown           = [bool]($null -eq $offset)
        OffsetExceedsKerberosSkew = [bool](($null -ne $offset) -and ([math]::Abs($offset) -gt 300))
        ConfiguredNtpServer     = [string]$ntpServer
        SyncType                = [string]$syncType
        NtpServerProviderEnabled = [bool]($ntpEnabled -eq 1)
        AnnounceFlags           = [string]$announce
        IsAuthoritativeTimeSource = $isAuthoritative
        UsesLocalClockOnly      = $usesLocalClock
        BrokenDomainTimeHierarchy = [bool]($isDomainMember -and $usesLocalClock)
        ServiceState            = $svcState
        ServiceStartMode        = $svcStart
        LocalTime               = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        TimeZone                = $tzId
        Note                    = 'Kerberos rejects tickets beyond a default five-minute skew; a drifted clock presents as authentication failure, not as a clock problem.'
    }

    if ($source -and -not $usesLocalClock) {
        Add-DependencyEdge -Context $Context -SourceType 'Server' -SourceName $Context.ComputerName `
            -DependencyType 'SynchronisesTimeWith' -Target ([string]$source) -Evidence 'w32tm /query /source' `
            -Confidence 'Confirmed' -SourceDataset 'TimeSync' -ProjectImpact 'Cutover Complexity' `
            -ValidationQuestion 'Does this time source survive the migration, and does the replacement server inherit the same hierarchy?' | Out-Null
    }

    if ($isAuthoritative) {
        Add-Unknown -Context $Context -Unknown 'This server advertises itself as a reliable time source; which machines follow it is not discoverable from here.' `
            -WhyItMatters 'Retiring an authoritative time source drifts every client that follows it, and the symptom is failed authentication.' `
            -Module 'TimeSync' -RecommendedValidationQuestion 'Which systems take their time from this server, and where will they take it from afterwards?' | Out-Null
    }

    return ,@{ TimeSync=@($row) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    $rows = @(if ($RawData -and $RawData.TimeSync) { @($RawData.TimeSync) } else { @() })
    Add-DataSet -Context $Context -Name 'TimeSync' -Description 'Windows Time service source, hierarchy, and offset.' -Rows $rows -Visibility 'Internal' -SourceModule 'TimeSync' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','ConvertFrom-W32tmOffset','Get-W32tmField'
