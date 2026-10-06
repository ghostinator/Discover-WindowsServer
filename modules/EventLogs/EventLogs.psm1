<#
    EventLogs.psm1 - event log summary/samples and audit policy configuration (read-only).
    Never clears logs. Produces: EventLogSummary, EventLogSamples, AuditPolicySettings,
    AuditPolicyGaps. Optional full export with -FullEventLogExport.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='EventLogs'; DisplayName='Event Logs'; Category='System'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('EventLogSummary','EventLogSamples','AuditPolicySettings','AuditPolicyGaps')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

# Advanced audit subcategories worth flagging specifically when set to "No Auditing" - not
# exhaustive (auditpol reports ~60 subcategories total), just the ones most directly tied to
# "can we tell who logged on, who was added to an admin group, or who changed the audit policy
# itself" - the baseline questions an incident investigation or compliance review asks first.
# Matched by exact name as auditpol.exe itself prints it (confirmed live against a real
# Server 2025 box's `auditpol /get /category:*` output).
$script:CriticalAuditSubcategories = @(
    'Logon', 'Account Lockout', 'Special Logon',
    'Security State Change', 'Audit Policy Change', 'Authentication Policy Change',
    'Sensitive Privilege Use',
    'User Account Management', 'Security Group Management', 'Computer Account Management'
)

function Get-AuditPolicySettings {
    <#
        Parses `auditpol /get /category:*` into one row per subcategory. Real output has
        category headers at column 0 ("Logon/Logoff") followed by subcategory lines indented
        two spaces ("  Logon                    Success and Failure") - the indentation, not
        the text, is what tells them apart, confirmed against real output on a live Server
        2025 box (the two header lines "System audit policy" and "Category/Subcategory ...
        Setting" also start at column 0, so they're explicitly excluded from being read as a
        category name).
    #>
    $rows = [System.Collections.Generic.List[object]]::new()
    if (-not (Get-CommandAvailable -Name 'auditpol.exe')) { return ,@($rows) }
    try {
        $r = Invoke-CommandLineSafe -FilePath 'auditpol.exe' -Arguments @('/get', '/category:*') -TimeoutSeconds 30
        if (-not $r.Succeeded -or -not $r.StdOut) { return ,@($rows) }
        $category = ''
        foreach ($ln in ($r.StdOut -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($ln)) { continue }
            if ($ln -match '^\s{2,}(.+?)\s{2,}(No Auditing|Success and Failure|Success|Failure)\s*$') {
                $rows.Add([pscustomobject]@{ Category = $category; Subcategory = $Matches[1].Trim(); Setting = $Matches[2] })
            } elseif ($ln -notmatch 'audit policy' -and $ln -notmatch 'Category/Subcategory') {
                $category = $ln.Trim()
            }
        }
    } catch { }
    return ,@($rows)
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='EventLogs'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $summary=[System.Collections.Generic.List[object]]::new(); $samples=[System.Collections.Generic.List[object]]::new()
    $days = [int]$Context.Parameters['EventLogDays']; if ($days -le 0) { $days = 14 }
    $maxSamples = [int]$Context.Parameters['MaxEventSamplesPerLog']; if ($maxSamples -le 0) { $maxSamples = 50 }
    if ($Context.Mode -eq 'Fast' -and $maxSamples -gt 25) { $maxSamples = 25 }
    $since = (Get-Date).AddDays(-$days)
    $deep = ($Context.Mode -eq 'Deep')

    $logs = @('System','Application')
    # 'Security' requires elevation to read (Get-WinEvent throws Access Denied otherwise) - it
    # used to never be attempted at all despite a limitation message below specifically for it
    # failing, which meant that message could never actually fire and the single most
    # compliance-relevant log on the box went untouched regardless of whether this ran
    # elevated. Gating on IsAdmin fixes both: the message is now reachable, and an elevated run
    # actually samples it.
    if ($Context.IsAdmin) { $logs += 'Security' }
    foreach ($opt in @('DNS Server','Directory Service','DFS Replication','Microsoft-Windows-Hyper-V-VMMS-Admin','Microsoft-Windows-Dhcp-Server/Operational')) {
        try { if (Get-WinEvent -ListLog $opt -ErrorAction SilentlyContinue) { $logs += $opt } } catch { }
    }

    # Each log is queried for ONLY the events reported on - critical/error/warning (levels 1-3), or
    # for Security, audit failures (Level 0 + the AuditFailure keyword; Security has essentially no
    # level 1-3 events) - newest first, capped at $maxQueryEvents. Pulling every event in the window
    # instead blew the 600s module deadline on a lab DC with only 180k Security records (losing
    # this module's data, audit policy included); a busy client DC has millions. Filtered, the same
    # DC takes ~5s total.
    $maxQueryEvents = 20000
    $auditFailureKeyword = 4503599627370496
    $recordsInLog = @{}
    try { foreach ($l in @(Get-WinEvent -ListLog $logs -ErrorAction SilentlyContinue)) { if ($l.LogName) { $recordsInLog[$l.LogName] = $l.RecordCount } } } catch { }
    $sampleCount = if ($deep) { $maxSamples } else { [math]::Min(5, $maxSamples) }

    foreach ($log in $logs) {
        $isSecurity = ($log -eq 'Security')
        $filter = if ($isSecurity) { @{ LogName=$log; StartTime=$since; Keywords=$auditFailureKeyword } } else { @{ LogName=$log; StartTime=$since; Level=1,2,3 } }
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $maxQueryEvents -ErrorAction Stop)
        } catch {
            # A filtered query matching nothing throws NoMatchingEventsFound - that's a clean zero, not a failure.
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                if ($isSecurity) { Add-Limitation -Context $Context -Module 'EventLogs' -Message 'Security log query failed even though this run was elevated.' -Reason $_.Exception.Message | Out-Null }
                else { Write-Log -Level DEBUG -Message ("Event log '{0}' query skipped: {1}" -f $log, $_.Exception.Message) -Module 'EventLogs' -Context $Context }
                continue
            }
        }
        $flagged = @(if ($isSecurity) { $events } else { $events | Where-Object { $_.Level -in @(1,2) } })
        $topRec = (($flagged | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "Id $($_.Name) x$($_.Count)" }) -join '; ')
        $summary.Add([pscustomobject]@{
            LogName=$log; DaysWindow=$days; RecordsInLog=$recordsInLog[$log]
            CriticalCount     = if ($isSecurity) { $null } else { @($events | Where-Object { $_.Level -eq 1 }).Count }
            ErrorCount        = if ($isSecurity) { $null } else { @($events | Where-Object { $_.Level -eq 2 }).Count }
            WarningCount      = if ($isSecurity) { $null } else { @($events | Where-Object { $_.Level -eq 3 }).Count }
            AuditFailureCount = if ($isSecurity) { $events.Count } else { $null }
            QueryCapped=($events.Count -ge $maxQueryEvents); TopRecurring=$topRec
        })
        foreach ($e in ($flagged | Select-Object -First $sampleCount)) {
            $msg = ''
            try { $msg = if ($e.Message) { $e.Message.Substring(0, [math]::Min(300, $e.Message.Length)) } else { '' } } catch { }
            $level = if ($isSecurity) { 'Audit Failure' } else { [string]$e.LevelDisplayName }
            $samples.Add([pscustomobject]@{ LogName=$log; TimeCreated=(Normalize-DateTime $e.TimeCreated); Id=$e.Id; Level=$level; ProviderName=$e.ProviderName; Message=(Redact-SensitiveValue -InputString $msg -Context $Context) })
        }
    }
    if (-not $Context.IsAdmin) { Add-Limitation -Context $Context -Module 'EventLogs' -Message 'Security log not sampled (requires elevation).' -Impact 'No audit-relevant event data' | Out-Null }

    # ---- Audit policy configuration ----
    $auditRows = Get-AuditPolicySettings
    $auditGaps = @($auditRows | Where-Object { $script:CriticalAuditSubcategories -contains $_.Subcategory -and $_.Setting -eq 'No Auditing' })
    if ($auditRows.Count -eq 0) { Add-Limitation -Context $Context -Module 'EventLogs' -Message 'Audit policy (auditpol) could not be read; audit configuration gaps cannot be assessed.' | Out-Null }

    # ---- Full export (opt-in only; exports copies, never clears) ----
    if ([bool]$Context.Parameters['FullEventLogExport']) {
        $rawDir = $Context.Paths['Raw']
        if ($rawDir -and (Get-CommandAvailable -Name 'wevtutil.exe')) {
            Add-Limitation -Context $Context -Module 'EventLogs' -Message 'Full event log export requested: raw\ output may be large.' -Impact 'Output size' | Out-Null
            foreach ($log in @('System','Application')) {
                try { Invoke-CommandLineSafe -FilePath 'wevtutil.exe' -Arguments @('epl', $log, ("`"" + (Join-Path $rawDir ("{0}.evtx" -f ($log -replace '[\\/]','_'))) + "`"")) -TimeoutSeconds 120 | Out-Null } catch { }
            }
        }
    }

    return ,@{ EventLogSummary=@($summary); EventLogSamples=@($samples); AuditPolicySettings=@($auditRows); AuditPolicyGaps=@($auditGaps) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'EventLogSummary'    -Description 'Event log critical/error/warning counts (audit failures for Security) and top recurring events.' -Rows (& $get 'EventLogSummary')    -Visibility 'Internal' -SourceModule 'EventLogs' | Out-Null
    Add-DataSet -Context $Context -Name 'EventLogSamples'    -Description 'Sample critical/error events (redacted).'                                 -Rows (& $get 'EventLogSamples')    -Visibility 'Internal' -SourceModule 'EventLogs' | Out-Null
    Add-DataSet -Context $Context -Name 'AuditPolicySettings' -Description 'Advanced audit policy (auditpol) - every subcategory and its setting.'    -Rows (& $get 'AuditPolicySettings') -Visibility 'Internal' -SourceModule 'EventLogs' | Out-Null
    Add-DataSet -Context $Context -Name 'AuditPolicyGaps'     -Description 'Critical audit subcategories set to No Auditing.'                          -Rows (& $get 'AuditPolicyGaps')     -Visibility 'Internal' -SourceModule 'EventLogs' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-AuditPolicySettings'
