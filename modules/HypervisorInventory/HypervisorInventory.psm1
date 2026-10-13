<#
    HypervisorInventory.psm1 - imports an externally supplied hypervisor inventory (a VMware /
    vCenter export, an RMM VM list, a spreadsheet) for decommissioning analysis. Read-only: it
    reads ONE local file named by -HypervisorInventoryPath and never connects to a hypervisor,
    so no hypervisor credential is ever needed or stored.

    Produces: ExternalHypervisorVMs, ExternalHypervisorDatastores, ExternalHypervisorFiles,
              HypervisorInventorySummary.

    Input: CSV or JSON (array of objects). Columns (case-insensitive; unknown columns DROPPED so
    free-text fields such as VM notes never reach the output):
      RecordType   VM (default) | Datastore | File
      VM rows:        VMName*, PowerState*, HostName, Cluster, Datastore, VMPath, GuestOS,
                      GuestHostName, CpuCount, MemoryGB, ProvisionedGB, UsedGB, SnapshotCount,
                      IsoAttached, Source
      Datastore rows: Name*, CapacityGB, FreeGB, HostName, Source
      File rows:      Path*, Datastore, FileType, SizeGB, IsOrphaned, Source
    'Source' names where a row came from (e.g. 'vCenter', 'RMM'); when two sources disagree on
    the VM count for a host, that is reported as a count conflict.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='HypervisorInventory'; DisplayName='Hypervisor Inventory Import (VMware / RMM)'; Category='Virtualization'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Minimal'; CanRunAsSystem=$true
        ProducesDatasets=@('ExternalHypervisorVMs','ExternalHypervisorDatastores','ExternalHypervisorFiles','HypervisorInventorySummary')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $p = [string]$Context.Parameters['HypervisorInventoryPath']
    if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { return [pscustomobject]@{ ModuleName='HypervisorInventory'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    if ($p) { return [pscustomobject]@{ ModuleName='HypervisorInventory'; CanRun=$false; Status='NotApplicable'; Reason=("Hypervisor inventory file not found: {0}" -f $p); Limitations=@(("-HypervisorInventoryPath '{0}' does not exist." -f $p)) } }
    [pscustomobject]@{ ModuleName='HypervisorInventory'; CanRun=$false; Status='NotApplicable'; Reason='No -HypervisorInventoryPath supplied.'; Limitations=@() }
}

$script:HvColumns = @{
    VM        = @('VMName','PowerState','HostName','Cluster','Datastore','VMPath','GuestOS','GuestHostName','CpuCount','MemoryGB','ProvisionedGB','UsedGB','SnapshotCount','IsoAttached','Source')
    Datastore = @('Name','CapacityGB','FreeGB','HostName','Source')
    File      = @('Path','Datastore','FileType','SizeGB','IsOrphaned','Source')
}

function ConvertTo-HypervisorInventory {
    <# Pure: raw imported rows -> @{ VMs; Datastores; Files; Rejected } keeping only schema columns. #>
    param([object[]]$Rows = @())
    $out = @{ VM = [System.Collections.Generic.List[object]]::new(); Datastore = [System.Collections.Generic.List[object]]::new(); File = [System.Collections.Generic.List[object]]::new(); Rejected = 0 }
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $props = @{}; foreach ($p in $r.PSObject.Properties) { $props[$p.Name.ToLowerInvariant()] = $p.Value }
        $type = [string]$props['recordtype']; if (-not $type) { $type = 'VM' }
        $type = (Get-Culture).TextInfo.ToTitleCase($type.ToLowerInvariant())
        if (-not $script:HvColumns.ContainsKey($type)) { $out.Rejected++; continue }
        $row = [ordered]@{}
        foreach ($c in $script:HvColumns[$type]) { $row[$c] = $props[$c.ToLowerInvariant()] }
        $key = $script:HvColumns[$type][0]
        if (-not $row[$key]) { $out.Rejected++; continue }
        if ($type -eq 'VM') {
            $state = [string]$row['PowerState']
            $row['IsRunning'] = [bool]($state -match '(?i)^(on|poweredon|running)$')
            $row['IsPoweredOff'] = [bool]($state -match '(?i)^(off|poweredoff|stopped|saved|suspended)$')
            $snap = 0; [void][int]::TryParse([string]$row['SnapshotCount'], [ref]$snap); $row['HasSnapshots'] = [bool]($snap -gt 0)
        }
        if ($type -eq 'File') { $row['IsIso'] = [bool]([string]$row['Path'] -match '(?i)\.iso$' -or [string]$row['FileType'] -match '(?i)iso') }
        $out[$type].Add([pscustomobject]$row)
    }
    return $out
}

function Get-HypervisorCountConflicts {
    <# Pure: per host, VM counts by Source; returns one row per host where two or more sources disagree. #>
    param([object[]]$VMs = @())
    $rows = foreach ($g in (@($VMs | Where-Object { $_.Source }) | Group-Object HostName)) {
        $bySource = @($g.Group | Group-Object Source | ForEach-Object { [pscustomobject]@{ Source = $_.Name; Count = $_.Count } })
        if ($bySource.Count -lt 2) { continue }
        if (@($bySource | ForEach-Object { $_.Count } | Select-Object -Unique).Count -le 1) { continue }   # sources agree
        [pscustomobject]@{ HostName=$g.Name; CountsBySource=((@($bySource | ForEach-Object { '{0}={1}' -f $_.Source, $_.Count })) -join '; ') }
    }
    return ,@($rows)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $path = [string]$Context.Parameters['HypervisorInventoryPath']
    $raw = @()
    try {
        if ($path -match '(?i)\.json$') { $parsed = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json; $raw = @($parsed) }
        else { $raw = @(Import-Csv -LiteralPath $path -ErrorAction Stop) }
    } catch {
        Add-Limitation -Context $Context -Module 'HypervisorInventory' -Message ("Hypervisor inventory file could not be parsed: {0}" -f $path) -Reason $_.Exception.Message | Out-Null
        return ,@{ ExternalHypervisorVMs=@(); ExternalHypervisorDatastores=@(); ExternalHypervisorFiles=@(); HypervisorInventorySummary=@() }
    }
    $inv = ConvertTo-HypervisorInventory -Rows $raw
    if ($inv.Rejected -gt 0) { Add-Limitation -Context $Context -Module 'HypervisorInventory' -Message ("{0} imported row(s) were skipped (unknown RecordType or missing key column)." -f $inv.Rejected) | Out-Null }
    $vms = @($inv.VM); $files = @($inv.File)
    $conflicts = Get-HypervisorCountConflicts -VMs $vms
    $summary = @([pscustomobject]@{
        SourceFile=(Split-Path -Leaf $path); Sources=((@($vms | ForEach-Object { [string]$_.Source } | Where-Object { $_ } | Select-Object -Unique)) -join ', ')
        Hosts=((@($vms | ForEach-Object { [string]$_.HostName } | Where-Object { $_ } | Select-Object -Unique)) -join ', ')
        RegisteredVMs=$vms.Count; RunningVMs=@($vms | Where-Object { $_.IsRunning }).Count; PoweredOffVMs=@($vms | Where-Object { $_.IsPoweredOff }).Count
        VMsWithSnapshots=@($vms | Where-Object { $_.HasSnapshots }).Count; Datastores=@($inv.Datastore).Count
        IsoFiles=@($files | Where-Object { $_.IsIso }).Count; OrphanedFiles=@($files | Where-Object { [string]$_.IsOrphaned -match '(?i)^(true|yes|1)$' }).Count
        CountConflicts=@($conflicts).Count; CountConflictDetail=((@($conflicts | ForEach-Object { '{0}: {1}' -f $_.HostName, $_.CountsBySource })) -join ' | ')
        Note='Imported from an external file; accuracy is only as good as that export and its date.'
    })
    return ,@{ ExternalHypervisorVMs=$vms; ExternalHypervisorDatastores=@($inv.Datastore); ExternalHypervisorFiles=$files; HypervisorInventorySummary=$summary }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'ExternalHypervisorVMs'        -Description 'VMs from an imported hypervisor/RMM inventory file.' -Rows (& $get 'ExternalHypervisorVMs') -Visibility 'Internal' -SourceModule 'HypervisorInventory' | Out-Null
    Add-DataSet -Context $Context -Name 'ExternalHypervisorDatastores' -Description 'Datastores from an imported hypervisor inventory file.' -Rows (& $get 'ExternalHypervisorDatastores') -Visibility 'Internal' -SourceModule 'HypervisorInventory' | Out-Null
    Add-DataSet -Context $Context -Name 'ExternalHypervisorFiles'      -Description 'Datastore files (ISOs, orphaned disks) from an imported inventory file.' -Rows (& $get 'ExternalHypervisorFiles') -Visibility 'Internal' -SourceModule 'HypervisorInventory' | Out-Null
    Add-DataSet -Context $Context -Name 'HypervisorInventorySummary'   -Description 'Imported hypervisor inventory summary, incl. VM-count conflicts between sources.' -Rows (& $get 'HypervisorInventorySummary') -Visibility 'Internal' -SourceModule 'HypervisorInventory' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','ConvertTo-HypervisorInventory','Get-HypervisorCountConflicts'
