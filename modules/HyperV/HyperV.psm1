<#
    HyperV.psm1 - Hyper-V host, switches, VMs, disks, replication (read-only).
    Role-gated. NEVER changes VM state or creates checkpoints.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='HyperV'; DisplayName='Hyper-V'; Category='Virtualization'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$true; RequiresDomainContext=$false
        RequiresRole='Hyper-V'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('HyperVHost','HyperVVirtualSwitches','HyperVVMs','HyperVDisks','HyperVReplication')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $present = (Get-CommandAvailable -Name 'Get-VM') -or (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue)
    if ($present) { return [pscustomobject]@{ ModuleName='HyperV'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='HyperV'; CanRun=$false; Status='NotApplicable'; Reason='Hyper-V (Get-VM / vmms) not present.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    # Default cmdlets resolve $env:COMPUTERNAME through DNS on every call (~1 s each; 20-30x slower than 'localhost'), and a resolution failure is swallowed by -ErrorAction SilentlyContinue as an empty result.
    $PSDefaultParameterValues = @{ 'Get-VM*:ComputerName' = 'localhost'; 'Get-VHD:ComputerName' = 'localhost' }
    $host_=[System.Collections.Generic.List[object]]::new(); $sw=[System.Collections.Generic.List[object]]::new()
    $vms=[System.Collections.Generic.List[object]]::new(); $disks=[System.Collections.Generic.List[object]]::new(); $repl=[System.Collections.Generic.List[object]]::new()
    if (-not (Get-CommandAvailable -Name 'Get-VM')) { Add-Limitation -Context $Context -Module 'HyperV' -Message 'Hyper-V PowerShell module not available; cannot enumerate VMs.' | Out-Null; return ,@{ HyperVHost=@(); HyperVVirtualSwitches=@(); HyperVVMs=@(); HyperVDisks=@(); HyperVReplication=@() } }
    try { $h = Get-VMHost -ErrorAction SilentlyContinue; if ($h) { $host_.Add([pscustomobject]@{ ComputerName=$h.Name; VirtualHardDiskPath=$h.VirtualHardDiskPath; VirtualMachinePath=$h.VirtualMachinePath; LogicalProcessorCount=$h.LogicalProcessorCount; MemoryGB=(Convert-BytesToGB $h.MemoryCapacity) }) } } catch { }
    try { foreach ($s in (Get-VMSwitch -ErrorAction SilentlyContinue)) { $sw.Add([pscustomobject]@{ Name=$s.Name; SwitchType=[string]$s.SwitchType; NetAdapter=$s.NetAdapterInterfaceDescription }) } } catch { }
    # The host's default VM config version: a VM below it was built on older Hyper-V and
    # needs a version upgrade (one-way) once moved to a newer host.
    $hostDefaultVer = $null
    try { $hostDefaultVer = [version](Get-VMHostSupportedVersion -Default -ErrorAction Stop).Version } catch { }
    try {
        foreach ($v in (Get-VM -ErrorAction SilentlyContinue)) {
            $snapCount = 0
            try { $snapCount = @(Get-VMSnapshot -VMName $v.Name -ErrorAction SilentlyContinue).Count } catch { }
            $iso = $false
            try { $iso = [bool](@(Get-VMDvdDrive -VMName $v.Name -ErrorAction SilentlyContinue | Where-Object { $_.Path }).Count -gt 0) } catch { }
            $switches = ''
            try { $switches = (@(Get-VMNetworkAdapter -VMName $v.Name -ErrorAction SilentlyContinue | ForEach-Object { if ($_.SwitchName) { $_.SwitchName } else { '(not connected)' } }) -join '; ') } catch { }
            # (MemoryMinimum/Maximum are 512 MB / 1 TB placeholders unless dynamic memory is on, so they are only reported then.)
            $behind = $false
            try { if ($hostDefaultVer -and ([version]$v.Version -lt $hostDefaultVer)) { $behind = $true } } catch { }
            $vms.Add([pscustomobject]@{ Name=$v.Name; State=[string]$v.State; Generation=$v.Generation; ProcessorCount=$v.ProcessorCount; MemoryAssignedGB=(Convert-BytesToGB $v.MemoryAssigned); MemoryMinimumGB=$(if ($v.DynamicMemoryEnabled) { Convert-BytesToGB $v.MemoryMinimum } else { $null }); MemoryMaximumGB=$(if ($v.DynamicMemoryEnabled) { Convert-BytesToGB $v.MemoryMaximum } else { $null }); DynamicMemoryEnabled=$v.DynamicMemoryEnabled; Version=$v.Version; VersionBehindHostDefault=$behind; HasCheckpoints=([bool]($snapCount -gt 0)); CheckpointCount=$snapCount; AutomaticStartAction=[string]$v.AutomaticStartAction; IsoMounted=$iso; SwitchNames=$switches; VMPath=$v.Path; Notes=$v.Notes })
            try {
                foreach ($d in (Get-VMHardDiskDrive -VMName $v.Name -ErrorAction SilentlyContinue)) {
                    # Size/type/parent come from the VHD itself; a locked or missing file must not lose the row.
                    $vhd = $null; try { if ($d.Path) { $vhd = Get-VHD -Path $d.Path -ErrorAction Stop } } catch { }
                    $parent = if ($vhd) { [string]$vhd.ParentPath } else { '' }
                    $disks.Add([pscustomobject]@{
                        VMName=$v.Name; Path=$d.Path; ControllerType=[string]$d.ControllerType; PassThrough=([bool]($null -ne $d.DiskNumber))
                        VhdType=$(if ($vhd) { [string]$vhd.VhdType } else { '' }); MaxSizeGB=$(if ($vhd) { Convert-BytesToGB $vhd.Size } else { $null }); FileSizeGB=$(if ($vhd) { Convert-BytesToGB $vhd.FileSize } else { $null })
                        ParentPath=$parent; IsDifferencing=([bool]($parent -or ([string]$d.Path -match '(?i)\.avhdx?$')))   # .avhd(x) = checkpoint child even if Get-VHD failed
                    })
                }
            } catch { }
            try { $r = Get-VMReplication -VMName $v.Name -ErrorAction SilentlyContinue; if ($r) { $repl.Add([pscustomobject]@{ VMName=$v.Name; State=[string]$r.State; Health=[string]$r.Health; Mode=[string]$r.ReplicationMode }) } } catch { }
        }
    } catch { Add-Limitation -Context $Context -Module 'HyperV' -Message 'VM enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    return ,@{ HyperVHost=@($host_); HyperVVirtualSwitches=@($sw); HyperVVMs=@($vms); HyperVDisks=@($disks); HyperVReplication=@($repl) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'HyperVHost'            -Description 'Hyper-V host settings.'    -Rows (& $get 'HyperVHost')            -Visibility 'Internal' -SourceModule 'HyperV' | Out-Null
    Add-DataSet -Context $Context -Name 'HyperVVirtualSwitches' -Description 'Virtual switches.'         -Rows (& $get 'HyperVVirtualSwitches') -Visibility 'Internal' -SourceModule 'HyperV' | Out-Null
    Add-DataSet -Context $Context -Name 'HyperVVMs'             -Description 'Virtual machine inventory.'-Rows (& $get 'HyperVVMs')             -Visibility 'Both'     -SourceModule 'HyperV' | Out-Null
    Add-DataSet -Context $Context -Name 'HyperVDisks'           -Description 'VM virtual disks.'         -Rows (& $get 'HyperVDisks')           -Visibility 'Internal' -SourceModule 'HyperV' | Out-Null
    Add-DataSet -Context $Context -Name 'HyperVReplication'     -Description 'VM replication status.'    -Rows (& $get 'HyperVReplication')     -Visibility 'Internal' -SourceModule 'HyperV' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try { if ($Context.DataSets.Contains('HyperVVMs') -and @($Context.DataSets['HyperVVMs'].Rows).Count -gt 0) { Add-FollowUpQuestion -Context $Context -Category 'Critical systems' -Module 'HyperV' -Audience 'Both' -Question 'Is every VM on this Hyper-V host inventoried, backed up, and accounted for in the migration/refresh plan?' | Out-Null } } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions'
