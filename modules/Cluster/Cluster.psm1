<#
    Cluster.psm1 - failover cluster discovery (read-only). Role-gated. Never alters cluster state.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='Cluster'; DisplayName='Failover Cluster'; Category='Virtualization'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$true; RequiresDomainContext=$false
        RequiresRole='Failover-Clustering'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('ClusterDiscovery','ClusterResources','ClusterNodes','ClusterNetworks','ClusterGroups','ClusterSharedVolumes')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $present = (Get-CommandAvailable -Name 'Get-Cluster') -or (Get-Service -Name 'ClusSvc' -ErrorAction SilentlyContinue)
    if ($present) { return [pscustomobject]@{ ModuleName='Cluster'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='Cluster'; CanRun=$false; Status='NotApplicable'; Reason='Failover Clustering (Get-Cluster / ClusSvc) not present.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $disc=[System.Collections.Generic.List[object]]::new(); $res=[System.Collections.Generic.List[object]]::new()
    $cnodes=[System.Collections.Generic.List[object]]::new(); $cnets=[System.Collections.Generic.List[object]]::new(); $cgroups=[System.Collections.Generic.List[object]]::new(); $ccsv=[System.Collections.Generic.List[object]]::new()
    if (-not (Get-CommandAvailable -Name 'Get-Cluster')) { Add-Limitation -Context $Context -Module 'Cluster' -Message 'FailoverClusters module not available.' | Out-Null; return ,@{ ClusterDiscovery=@(); ClusterResources=@(); ClusterNodes=@(); ClusterNetworks=@(); ClusterGroups=@(); ClusterSharedVolumes=@() } }
    try {
        $cl = Get-Cluster -ErrorAction SilentlyContinue
        if ($cl) {
            $nodes = ''; $quorum=''; $witness=''; $nets=''
            try { $nodes = ((Get-ClusterNode -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ') } catch { }
            try { $q = Get-ClusterQuorum -ErrorAction SilentlyContinue; $quorum = [string]$q.QuorumType; $witness = [string]$q.QuorumResource } catch { }
            try { $nets = ((Get-ClusterNetwork -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ') } catch { }
            $disc.Add([pscustomobject]@{ ClusterName=$cl.Name; Nodes=$nodes; QuorumType=$quorum; WitnessResource=$witness; Networks=$nets })
            try { foreach ($r in (Get-ClusterResource -ErrorAction SilentlyContinue)) { $res.Add([pscustomobject]@{ Name=$r.Name; State=[string]$r.State; OwnerGroup=[string]$r.OwnerGroup; ResourceType=[string]$r.ResourceType; OwnerNode=[string]$r.OwnerNode }) } } catch { }
            # Health and workload detail: a node or network that is not Up, and the roles (VMs, file servers)
            # and CSVs that have to be moved, are the facts a migration or retirement plan is built on.
            try { foreach ($n in (Get-ClusterNode -ErrorAction SilentlyContinue)) { $cnodes.Add([pscustomobject]@{ Name=$n.Name; State=[string]$n.State; NodeWeight=$n.NodeWeight; DynamicWeight=$n.DynamicWeight }) } } catch { }
            try { foreach ($n in (Get-ClusterNetwork -ErrorAction SilentlyContinue)) { $cnets.Add([pscustomobject]@{ Name=$n.Name; Address=$n.Address; AddressMask=$n.AddressMask; Role=[string]$n.Role; State=[string]$n.State }) } } catch { }
            try { foreach ($g in (Get-ClusterGroup -ErrorAction SilentlyContinue)) { $cgroups.Add([pscustomobject]@{ Name=$g.Name; GroupType=[string]$g.GroupType; OwnerNode=[string]$g.OwnerNode; State=[string]$g.State }) } } catch { }
            try { foreach ($v in (Get-ClusterSharedVolume -ErrorAction SilentlyContinue)) { $ccsv.Add([pscustomobject]@{ Name=$v.Name; OwnerNode=[string]$v.OwnerNode; State=[string]$v.State; Path=[string]$v.SharedVolumeInfo.FriendlyVolumeName }) } } catch { }
        }
    } catch { Add-Limitation -Context $Context -Module 'Cluster' -Message 'Cluster query failed.' -Reason $_.Exception.Message | Out-Null }
    return ,@{ ClusterDiscovery=@($disc); ClusterResources=@($res); ClusterNodes=@($cnodes); ClusterNetworks=@($cnets); ClusterGroups=@($cgroups); ClusterSharedVolumes=@($ccsv) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'ClusterDiscovery' -Description 'Failover cluster summary.' -Rows (& $get 'ClusterDiscovery') -Visibility 'Internal' -SourceModule 'Cluster' | Out-Null
    Add-DataSet -Context $Context -Name 'ClusterResources' -Description 'Cluster resources.'        -Rows (& $get 'ClusterResources') -Visibility 'Internal' -SourceModule 'Cluster' | Out-Null
    Add-DataSet -Context $Context -Name 'ClusterNodes'     -Description 'Cluster nodes with state and quorum weight.' -Rows (& $get 'ClusterNodes')    -Visibility 'Internal' -SourceModule 'Cluster' | Out-Null
    Add-DataSet -Context $Context -Name 'ClusterNetworks'  -Description 'Cluster networks with role and state.'      -Rows (& $get 'ClusterNetworks') -Visibility 'Internal' -SourceModule 'Cluster' | Out-Null
    Add-DataSet -Context $Context -Name 'ClusterGroups'    -Description 'Cluster roles (VMs, file servers, ...).'      -Rows (& $get 'ClusterGroups')   -Visibility 'Internal' -SourceModule 'Cluster' | Out-Null
    Add-DataSet -Context $Context -Name 'ClusterSharedVolumes' -Description 'Cluster Shared Volumes.'                   -Rows (& $get 'ClusterSharedVolumes') -Visibility 'Internal' -SourceModule 'Cluster' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets'
