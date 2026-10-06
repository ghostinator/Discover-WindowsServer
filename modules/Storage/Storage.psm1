<#
    Storage.psm1 - disks, volumes, partitions, storage pools, shadow copies, BitLocker (read-only).
    Produces: Disks, Volumes, Partitions, StoragePools, ShadowCopies, BitLocker.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='Storage'; DisplayName='Storage'; Category='Storage'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('Disks','Volumes','Partitions','StoragePools','ShadowCopies','BitLocker','IscsiTargets','IscsiVirtualDisks','IscsiInitiatorConnections')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='Storage'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $volumes = [System.Collections.Generic.List[object]]::new()
    $disks = [System.Collections.Generic.List[object]]::new()
    $parts = [System.Collections.Generic.List[object]]::new()
    $pools = [System.Collections.Generic.List[object]]::new()
    $shadows = [System.Collections.Generic.List[object]]::new()
    $bitlocker = [System.Collections.Generic.List[object]]::new()

    # ---- Volumes ----
    try {
        if (Get-CommandAvailable -Name 'Get-Volume') {
            foreach ($v in (Get-Volume -ErrorAction SilentlyContinue)) {
                # A mounted ISO / optical drive is read-only and always 100% full: it is not storage, and it
                # made every VM with an attached ISO raise a "low free space" finding.
                if ([string]$v.DriveType -eq 'CD-ROM') { continue }
                try {
                    $size = [double]($v.Size); $free = [double]($v.SizeRemaining)
                    $pct = if ($size -gt 0) { [math]::Round(($free / $size) * 100, 1) } else { 0 }
                    $volumes.Add([pscustomobject]@{
                        DriveLetter=([string]$v.DriveLetter); FileSystemLabel=$v.FileSystemLabel; FileSystem=$v.FileSystem
                        SizeGB=(Convert-BytesToGB $size); FreeGB=(Convert-BytesToGB $free); PercentFree=$pct
                        HealthStatus=[string]$v.HealthStatus; DriveType=[string]$v.DriveType
                    })
                } catch { }
            }
        } else {
            foreach ($d in (Invoke-CimSafe -ClassName 'Win32_LogicalDisk' -Filter 'DriveType=3')) {
                try {
                    $size=[double]$d.Size; $free=[double]$d.FreeSpace
                    $pct = if ($size -gt 0) { [math]::Round(($free/$size)*100,1) } else { 0 }
                    $volumes.Add([pscustomobject]@{
                        DriveLetter=($d.DeviceID -replace ':',''); FileSystemLabel=$d.VolumeName; FileSystem=$d.FileSystem
                        SizeGB=(Convert-BytesToGB $size); FreeGB=(Convert-BytesToGB $free); PercentFree=$pct
                        HealthStatus='Unknown'; DriveType='Fixed'
                    })
                } catch { }
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'Storage' -Message 'Volume enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Disks ----
    try {
        if (Get-CommandAvailable -Name 'Get-Disk') {
            foreach ($d in (Get-Disk -ErrorAction SilentlyContinue)) {
                $disks.Add([pscustomobject]@{ Number=$d.Number; Model=$d.FriendlyName; SerialNumber=$d.SerialNumber; SizeGB=(Convert-BytesToGB $d.Size); BusType=[string]$d.BusType; HealthStatus=[string]$d.HealthStatus; PartitionStyle=[string]$d.PartitionStyle; OperationalStatus=[string]$d.OperationalStatus })
            }
        } else {
            foreach ($d in (Invoke-CimSafe -ClassName 'Win32_DiskDrive')) {
                $disks.Add([pscustomobject]@{ Number=$d.Index; Model=$d.Model; SerialNumber=($d.SerialNumber -replace '\s',''); SizeGB=(Convert-BytesToGB $d.Size); BusType=$d.InterfaceType; HealthStatus=$d.Status; PartitionStyle=''; OperationalStatus=$d.Status })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'Storage' -Message 'Disk enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Physical disk health (for predictive-failure hints) ----
    try {
        if (Get-CommandAvailable -Name 'Get-PhysicalDisk') {
            foreach ($p in (Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
                $disks.Add([pscustomobject]@{ Number=("phys-" + $p.DeviceId); Model=$p.FriendlyName; SerialNumber=$p.SerialNumber; SizeGB=(Convert-BytesToGB $p.Size); BusType=[string]$p.BusType; HealthStatus=[string]$p.HealthStatus; PartitionStyle=[string]$p.MediaType; OperationalStatus=([string]$p.OperationalStatus) })
            }
        }
    } catch { }

    # ---- Partitions ----
    try {
        if (Get-CommandAvailable -Name 'Get-Partition') {
            foreach ($p in (Get-Partition -ErrorAction SilentlyContinue)) {
                $parts.Add([pscustomobject]@{ DiskNumber=$p.DiskNumber; DriveLetter=([string]$p.DriveLetter); SizeGB=(Convert-BytesToGB $p.Size); Type=[string]$p.Type; IsBoot=$p.IsBoot; IsSystem=$p.IsSystem })
            }
        }
    } catch { }

    # ---- Storage pools ----
    try {
        if (Get-CommandAvailable -Name 'Get-StoragePool') {
            foreach ($sp in (Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $_.IsPrimordial -eq $false })) {
                $pools.Add([pscustomobject]@{ FriendlyName=$sp.FriendlyName; HealthStatus=[string]$sp.HealthStatus; SizeGB=(Convert-BytesToGB $sp.Size); AllocatedGB=(Convert-BytesToGB $sp.AllocatedSize) })
            }
        }
    } catch { }

    # ---- Shadow copies ----
    try {
        foreach ($sc in (Invoke-CimSafe -ClassName 'Win32_ShadowCopy')) {
            $shadows.Add([pscustomobject]@{ VolumeName=$sc.VolumeName; InstallDate=(Normalize-DateTime $sc.InstallDate); Id=$sc.ID })
        }
    } catch { }

    # ---- BitLocker (status only; NEVER recovery keys) ----
    try {
        if (Get-CommandAvailable -Name 'Get-BitLockerVolume') {
            foreach ($b in (Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
                $bitlocker.Add([pscustomobject]@{ MountPoint=[string]$b.MountPoint; ProtectionStatus=[string]$b.ProtectionStatus; EncryptionMethod=[string]$b.EncryptionMethod; VolumeStatus=[string]$b.VolumeStatus; EncryptionPercentage=$b.EncryptionPercentage })
            }
        }
    } catch { }

    # ---- iSCSI ----
    # Target side: LUNs other servers boot from or keep data on. Initiator side: the external
    # target/portal THIS server's disks depend on. Neither shows up in any service or share list.
    $iscsiTargets = [System.Collections.Generic.List[object]]::new(); $iscsiDisks = [System.Collections.Generic.List[object]]::new(); $iscsiInit = [System.Collections.Generic.List[object]]::new()
    try {
        # The cmdlets ship on every server; only a host with the Target Server service (WinTarget) can answer them.
        if ((Get-Service -Name 'WinTarget' -ErrorAction SilentlyContinue) -and (Get-CommandAvailable -Name 'Get-IscsiServerTarget')) {
            foreach ($t in (Get-IscsiServerTarget -ErrorAction SilentlyContinue)) {
                $luns = @($t.LunMappings | ForEach-Object { [string]$_.Path })
                $iscsiTargets.Add([pscustomobject]@{ TargetName=[string]$t.TargetName; Status=[string]$t.Status; LunCount=$luns.Count; LunPaths=($luns -join '; '); InitiatorCount=@($t.InitiatorIds).Count; InitiatorIds=((@($t.InitiatorIds) | ForEach-Object { [string]$_.Value }) -join '; ') })
            }
            foreach ($d in (Get-IscsiVirtualDisk -ErrorAction SilentlyContinue)) {
                $iscsiDisks.Add([pscustomobject]@{ Path=[string]$d.Path; SizeGB=(Convert-BytesToGB $d.Size); Status=[string]$d.Status })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'Storage' -Message 'iSCSI target enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    try {
        if (Get-CommandAvailable -Name 'Get-IscsiTarget') {
            $portals = (@(Get-IscsiTargetPortal -ErrorAction SilentlyContinue) | ForEach-Object { [string]$_.TargetPortalAddress }) -join ', '
            $sessions = @(Get-IscsiSession -ErrorAction SilentlyContinue)
            foreach ($t in (Get-IscsiTarget -ErrorAction SilentlyContinue)) {
                $ses = @($sessions | Where-Object { $_.TargetNodeAddress -eq $t.NodeAddress }) | Select-Object -First 1
                $row = [pscustomobject]@{ TargetNodeAddress=[string]$t.NodeAddress; PortalAddresses=$portals; IsConnected=[bool]$t.IsConnected; IsPersistent=$(if ($ses) { [bool]$ses.IsPersistent } else { $false }) }
                $iscsiInit.Add($row)
                if ($row.IsConnected) {
                    Add-DependencyEdge -Context $Context -SourceType 'iSCSI initiator' -SourceName $env:COMPUTERNAME -DependencyType 'UsesRemoteStorage' -Target ("{0} via {1}" -f $row.TargetNodeAddress, $portals) -Evidence 'Connected iSCSI target' -Confidence 'Confirmed' -SourceDataset 'IscsiInitiatorConnections' -ProjectImpact 'Data Migration' -ValidationQuestion 'Which disks and workloads on this server live on that iSCSI target, and does its portal address change?' | Out-Null
                }
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'Storage' -Message 'iSCSI initiator enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    return ,@{ Volumes=@($volumes); Disks=@($disks); Partitions=@($parts); StoragePools=@($pools); ShadowCopies=@($shadows); BitLocker=@($bitlocker); IscsiTargets=@($iscsiTargets); IscsiVirtualDisks=@($iscsiDisks); IscsiInitiatorConnections=@($iscsiInit) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'Volumes'      -Description 'Logical volumes with capacity and free space.'   -Rows (& $get 'Volumes')      -Visibility 'Both'     -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'Disks'        -Description 'Physical/virtual disks and health.'              -Rows (& $get 'Disks')        -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'Partitions'   -Description 'Disk partitions.'                                -Rows (& $get 'Partitions')   -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'StoragePools' -Description 'Storage Spaces pools.'                           -Rows (& $get 'StoragePools') -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'ShadowCopies' -Description 'Volume Shadow Copy snapshots.'                   -Rows (& $get 'ShadowCopies') -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'BitLocker'    -Description 'BitLocker protection status (no recovery keys).'-Rows (& $get 'BitLocker')    -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'IscsiTargets'  -Description 'iSCSI Target Server targets, LUN backing files and allowed initiators.' -Rows (& $get 'IscsiTargets')  -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'IscsiVirtualDisks' -Description 'iSCSI virtual disks (LUN backing files) hosted by this server.'  -Rows (& $get 'IscsiVirtualDisks') -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
    Add-DataSet -Context $Context -Name 'IscsiInitiatorConnections' -Description 'iSCSI targets this server connects to as an initiator.' -Rows (& $get 'IscsiInitiatorConnections') -Visibility 'Internal' -SourceModule 'Storage' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets'
