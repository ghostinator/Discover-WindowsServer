<#
    WorkloadProfile.psm1 - one row per server describing its resources and workload footprint,
    for target-capacity and workload-placement comparison across a fleet (read-only).

    Produces: WorkloadProfile.

    Built almost entirely from datasets the other collectors already produced (runs last), plus
    one live free-memory read. It does NOT recommend a VM size: the performance data here is a
    point-in-time snapshot, and sizing needs sustained counters and an explicit sizing workflow.
    tools\Merge-FleetDiscoveryResults.ps1 compares these rows between source and target servers.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='WorkloadProfile'; DisplayName='Workload & Target-Capacity Profile'; Category='Performance'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Minimal'; CanRunAsSystem=$true
        ProducesDatasets=@('WorkloadProfile')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='WorkloadProfile'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Get-WorkloadProfileRow {
    <#
        Pure apart from -FreeMemoryGB (passed in): builds the profile from a dataset accessor.
        Unknown stays $null, never 0 - a missing share scan is "not measured", not "no data".
    #>
    param([Parameter(Mandatory)][scriptblock]$GetRows, [string]$ComputerName = $env:COMPUTERNAME, $FreeMemoryGB = $null, [string[]]$Functions = @())
    $first = { param($n) @(& $GetRows $n) | Select-Object -First 1 }
    $sum = { param($rows, $prop) $m = (@($rows) | Where-Object { $null -ne $_.$prop -and [string]$_.$prop -ne '' } | Measure-Object -Property $prop -Sum); if ($m.Count -gt 0) { [math]::Round([double]$m.Sum, 2) } else { $null } }

    $os = & $first 'OperatingSystem'; $hw = & $first 'Hardware'; $pv = & $first 'PhysicalVirtualDetection'; $perf = & $first 'PerformanceSnapshot'
    $procs = @(& $GetRows 'Processors')
    $vols = @(& $GetRows 'Volumes' | Where-Object { $_.DriveType -ne 'Removable' })
    $disks = @(& $GetRows 'Disks')
    $apps = @(& $GetRows 'InstalledApplications' | Where-Object { -not $_.SystemComponent })
    $sqlSum = & $first 'SqlServerSummary'
    $sqlInst = @(& $GetRows 'SqlInstances' | Where-Object { -not $_.IsWindowsInternalDatabase })
    $shares = @(& $GetRows 'SmbShares' | Where-Object { $_.IsUserShare })
    $scans = @(& $GetRows 'NtfsAclSummary')
    $ports = @(& $GetRows 'ListeningPorts' | Where-Object { $_.Protocol -ne 'UDP' -and -not $_.IsEphemeral })
    $agents = @(& $GetRows 'VendorAgents')
    $backup = @(& $GetRows 'BackupDiscovery')
    $stacks = @(& $GetRows 'AppStackSummary')
    $vms = @(& $GetRows 'HyperVVMs')

    $totalGB = & $sum $vols 'SizeGB'; $freeGB = & $sum $vols 'FreeGB'
    $memGB = if ($hw) { $hw.TotalPhysicalMemoryGB } else { $null }
    $dbRows = @(& $GetRows 'SqlDatabases')
    $sqlGB = if ($sqlSum -and $null -ne $sqlSum.TotalDatabaseSizeGB) { $sqlSum.TotalDatabaseSizeGB } else { & $sum $dbRows 'SizeGB' }
    [pscustomobject]@{
        ComputerName=$ComputerName
        OperatingSystem=$(if ($os) { [string]$os.Caption } else { '' })
        Platform=$(if ($pv) { [string]$pv.Platform } else { '' }); IsVirtual=$(if ($pv) { [bool]$pv.IsVirtual } else { $null })
        CpuModel=((@($procs | ForEach-Object { [string]$_.Name } | Select-Object -Unique)) -join '; ')
        Sockets=$procs.Count; PhysicalCores=$(& $sum $procs 'NumberOfCores'); LogicalProcessors=$(if ($hw) { $hw.LogicalProcessors } else { & $sum $procs 'NumberOfLogicalProcessors' })
        TotalMemoryGB=$memGB; AvailableMemoryGB=$FreeMemoryGB
        CpuPercentSnapshot=$(if ($perf) { $perf.CpuPercent } else { $null }); MemoryUsedPercentSnapshot=$(if ($perf) { $perf.MemoryUsedPercent } else { $null })
        VolumeCount=$vols.Count; TotalCapacityGB=$totalGB; FreeCapacityGB=$freeGB
        UsedCapacityGB=$(if ($null -ne $totalGB -and $null -ne $freeGB) { [math]::Round($totalGB - $freeGB, 2) } else { $null })
        DiskTypes=((@($disks | ForEach-Object { [string]$_.BusType } | Where-Object { $_ } | Select-Object -Unique)) -join ', ')
        DetectedRoles=($Functions -join '; ')
        InstalledApplicationCount=$apps.Count
        SqlInstanceCount=$sqlInst.Count; SqlDataGB=$sqlGB; SqlVersions=$(if ($sqlSum) { [string]$sqlSum.ProductVersions } else { '' })
        IisSiteCount=@(& $GetRows 'IisSites').Count
        UserShareCount=$shares.Count; ShareDataGB=$(if ($scans.Count) { & $sum $scans 'TotalSizeGB' } else { $null })
        ShareDataMeasured=[bool]($scans.Count -gt 0); ShareSizeUnknown=[bool]($shares.Count -gt 0 -and $scans.Count -eq 0)
        ListeningTcpPorts=((@($ports | ForEach-Object { [string]$_.LocalPort } | Select-Object -Unique | Sort-Object { [int]$_ })) -join ', ')
        HostedVmCount=$vms.Count
        ApplicationStacks=((@($stacks | ForEach-Object { '{0} ({1})' -f $_.Stack, $_.HostRole })) -join '; ')
        BackupIndicators=((@($backup | ForEach-Object { [string]$_.Product }) + @($agents | Where-Object { $_.Category -eq 'Backup' } | ForEach-Object { [string]$_.AgentName }) | Select-Object -Unique) -join ', ')
        MonitoringIndicators=((@($agents | Where-Object { $_.Category -in @('RMM','Monitoring','CloudMgmt') } | ForEach-Object { [string]$_.AgentName }) | Select-Object -Unique) -join ', ')
        SecurityAgentIndicators=((@($agents | Where-Object { $_.Category -eq 'EDR/AV' } | ForEach-Object { [string]$_.AgentName }) | Select-Object -Unique) -join ', ')
        PerformanceEvidence='Point-in-time snapshot only'
        SizingNote='Not a sizing recommendation: collect sustained CPU/memory/disk counters before choosing a target size.'
    }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $free = $null
    try { $os = Invoke-CimSafe -ClassName 'Win32_OperatingSystem' | Select-Object -First 1; if ($os -and $os.FreePhysicalMemory) { $free = [math]::Round(([double]$os.FreePhysicalMemory * 1KB) / 1GB, 2) } } catch { }
    $funcs = @()
    try { $funcs = @(Get-LikelyServerFunctions -Context $Context) } catch { }
    $getRows = { param($name) if ($Context.DataSets.Contains($name)) { @($Context.DataSets[$name].Rows) } else { @() } }
    $row = Get-WorkloadProfileRow -GetRows $getRows -ComputerName $Context.ComputerName -FreeMemoryGB $free -Functions $funcs
    return ,@{ WorkloadProfile=@($row) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    $rows = @(if ($RawData -and $RawData.WorkloadProfile) { @($RawData.WorkloadProfile) } else { @() })
    Add-DataSet -Context $Context -Name 'WorkloadProfile' -Description 'Server resources and workload footprint for target-capacity comparison (not a sizing recommendation).' -Rows $rows -Visibility 'Internal' -SourceModule 'WorkloadProfile' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-WorkloadProfileRow'
