<#
    PerformanceSnapshot.psm1 - lightweight point-in-time performance (read-only).
    Produces: PerformanceSnapshot. NOT trend data.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='PerformanceSnapshot'; DisplayName='Performance Snapshot'; Category='Performance'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('PerformanceSnapshot')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='PerformanceSnapshot'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $cpu = $null; $memPct = $null; $pagefilePct = $null; $uptimeHours = $null
    $topCpu = ''; $topMem = ''; $diskFree = ''

    try {
        $cpu = $null
        try { $cpu = [math]::Round(((Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue),1) } catch { }
        if ($null -eq $cpu) { $lp = (Invoke-CimSafe -ClassName 'Win32_Processor' | Measure-Object -Property LoadPercentage -Average).Average; if ($lp) { $cpu = [math]::Round([double]$lp,1) } }
    } catch { }

    try {
        $os = Invoke-CimSafe -ClassName 'Win32_OperatingSystem' | Select-Object -First 1
        if ($os) {
            $total = [double]$os.TotalVisibleMemorySize; $free = [double]$os.FreePhysicalMemory
            if ($total -gt 0) { $memPct = [math]::Round((($total - $free) / $total) * 100, 1) }
            try { $uptimeHours = [math]::Round(((Get-Date) - ([Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime))).TotalHours, 1) } catch { }
        }
    } catch { }

    try {
        $pf = Invoke-CimSafe -ClassName 'Win32_PageFileUsage' | Select-Object -First 1
        if ($pf -and $pf.AllocatedBaseSize -gt 0) { $pagefilePct = [math]::Round(($pf.CurrentUsage / $pf.AllocatedBaseSize) * 100, 1) }
    } catch { }

    try { $topCpu = ((Get-Process -ErrorAction SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', ') } catch { }
    try { $topMem = ((Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | ForEach-Object { "{0}({1}MB)" -f $_.Name, [math]::Round($_.WorkingSet64/1MB,0) }) -join ', ') } catch { }
    try {
        if ($Context.DataSets.Contains('Volumes')) { $diskFree = (($Context.DataSets['Volumes'].Rows | ForEach-Object { "{0}:{1}%" -f $_.DriveLetter, $_.PercentFree }) -join ', ') }
    } catch { }

    $row = [pscustomobject]@{
        CpuPercent=$cpu; MemoryUsedPercent=$memPct; PageFileUsagePercent=$pagefilePct; UptimeHours=$uptimeHours
        TopCpuProcesses=$topCpu; TopMemoryProcesses=$topMem; DiskFreeSummary=$diskFree
        Note='Point-in-time snapshot only, not trend data.'
    }
    if ($null -eq $cpu) { Add-Limitation -Context $Context -Module 'PerformanceSnapshot' -Message 'CPU counter unavailable; used fallback or none.' | Out-Null }
    return ,@{ PerformanceSnapshot=@($row) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    $rows = @(if ($RawData -and $RawData.PerformanceSnapshot) { @($RawData.PerformanceSnapshot) } else { @() })
    Add-DataSet -Context $Context -Name 'PerformanceSnapshot' -Description 'Point-in-time CPU/memory/disk snapshot.' -Rows $rows -Visibility 'Internal' -SourceModule 'PerformanceSnapshot' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets'
