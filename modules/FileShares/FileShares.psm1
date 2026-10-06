<#
    FileShares.psm1 - SMB shares, permissions, optional deep crawl, DFS (read-only).
    Produces: SmbShares, SharePermissions, NtfsAclSummary, FileShareSummary, DfsDiscovery.
    Fast mode: no crawl. Deep / -DeepFileShareScan: bounded folder/size/age analysis.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='FileShares'; DisplayName='File Shares & DFS'; Category='File'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('SmbShares','SharePermissions','NtfsAclSummary','FileShareSummary','DfsDiscovery')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='FileShares'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $shares = [System.Collections.Generic.List[object]]::new()
    $perms = [System.Collections.Generic.List[object]]::new()
    $acls = [System.Collections.Generic.List[object]]::new()
    $dfs = [System.Collections.Generic.List[object]]::new()
    $deep = ([bool]$Context.Parameters['DeepFileShareScan'])

    # ---- Shares ----
    try {
        if (Get-CommandAvailable -Name 'Get-SmbShare') {
            foreach ($s in (Get-SmbShare -ErrorAction SilentlyContinue)) {
                $isUser = (-not ($s.Name.EndsWith('$'))) -and ([string]$s.ShareType -eq 'FileSystemDirectory')   # not print queues / IPC / devices
                $shares.Add([pscustomobject]@{ Name=$s.Name; Path=$s.Path; Description=$s.Description; ShareType=[string]$s.ShareType; IsUserShare=$isUser; FolderEnumerationMode=[string]$s.FolderEnumerationMode; EncryptData=$s.EncryptData })
                if ($isUser) {
                    try { foreach ($a in (Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)) { $perms.Add([pscustomobject]@{ Share=$s.Name; Account=$a.AccountName; AccessRight=[string]$a.AccessRight; AccessType=[string]$a.AccessControlType }) } } catch { }
                }
            }
        } else {
            foreach ($s in (Invoke-CimSafe -ClassName 'Win32_Share')) {
                $isUser = (-not ($s.Name.EndsWith('$'))) -and (([uint32]$s.Type -band 0x7FFFFFFF) -eq 0)   # Win32_Share Type 0 = disk share
                $shares.Add([pscustomobject]@{ Name=$s.Name; Path=$s.Path; Description=$s.Description; ShareType=[string]$s.Type; IsUserShare=$isUser; FolderEnumerationMode=''; EncryptData=$null })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'FileShares' -Message 'Share enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Deep crawl (only when enabled) ----
    if ($deep) {
        $maxDepth = [int]$Context.Parameters['MaxDepth']; if ($maxDepth -le 0) { $maxDepth = 3 }
        $largeGB = [double]$Context.Parameters['LargeFileThresholdGB']; if ($largeGB -le 0) { $largeGB = 5 }
        $oldYears = [int]$Context.Parameters['OldFileYears']; if ($oldYears -le 0) { $oldYears = 7 }
        $cutoff = (Get-Date).AddYears(-$oldYears)
        # Recycle-bin contents are excluded from share size/age totals by default: deleted
        # data is not migration payload, and counting it silently inflates the data-volume
        # estimate a quote is built from. -IncludeRecycleBin folds it back in. Either way the
        # recycled volume is reported separately, since it is reclaimable space worth knowing.
        $includeRecycleBin = ([bool]$Context.Parameters['IncludeRecycleBin'])
        $recyclePattern = '(?i)[\\/]\$Recycle\.Bin[\\/]'
        foreach ($s in ($shares | Where-Object { $_.IsUserShare -and $_.Path -and (Test-Path -LiteralPath $_.Path) })) {
            try {
                $topFolders = @(Get-ChildItem -LiteralPath $s.Path -Directory -ErrorAction SilentlyContinue)
                $allFiles = @(Get-ChildItem -LiteralPath $s.Path -File -Recurse -Force -Depth ($maxDepth) -ErrorAction SilentlyContinue)   # -Force: $RECYCLE.BIN is Hidden+System, invisible without it
                $recycled = @($allFiles | Where-Object { $_.FullName -match $recyclePattern })
                $files = @(if ($includeRecycleBin) { $allFiles } else { @($allFiles | Where-Object { $_.FullName -notmatch $recyclePattern }) })
                $totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
                $recycledBytes = ($recycled | Measure-Object -Property Length -Sum).Sum
                $largeFiles = @($files | Where-Object { $_.Length -ge ($largeGB * 1GB) }).Count
                $oldFiles = @($files | Where-Object { $_.LastWriteTime -lt $cutoff }).Count
                $recent = @($files | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-30) }).Count
                $acls.Add([pscustomobject]@{
                    Share=$s.Name; Path=$s.Path; TopLevelFolders=$topFolders.Count
                    FileCount=$files.Count; TotalSizeGB=(Convert-BytesToGB $totalBytes)
                    LargeFilesOverThreshold=$largeFiles; OldFilesOverYears=$oldFiles; RecentlyModified30d=$recent; MaxDepthScanned=$maxDepth
                    RecycleBinIncluded=$includeRecycleBin; RecycleBinFilesFound=$recycled.Count; RecycleBinSizeGB=(Convert-BytesToGB $recycledBytes)
                })
            } catch { Add-Limitation -Context $Context -Module 'FileShares' -Message ("Deep scan of share '{0}' failed or was partial." -f $s.Name) -Reason $_.Exception.Message | Out-Null }
        }
    }

    # ---- DFS ----
    try {
        if (Get-CommandAvailable -Name 'Get-DfsnRoot') { foreach ($r in (Get-DfsnRoot -ErrorAction SilentlyContinue)) { $dfs.Add([pscustomobject]@{ Type='Namespace'; Name=$r.Path; Detail=[string]$r.State }) } }
        if (Get-CommandAvailable -Name 'Get-DfsReplicationGroup') { foreach ($g in (Get-DfsReplicationGroup -ErrorAction SilentlyContinue)) { $dfs.Add([pscustomobject]@{ Type='Replication'; Name=$g.GroupName; Detail=$g.Description }) } }
        $dfsr = Get-Service -Name 'DFSR' -ErrorAction SilentlyContinue
        if ($dfsr) { $dfs.Add([pscustomobject]@{ Type='Service'; Name='DFSR'; Detail=[string]$dfsr.Status }) }
    } catch { }

    $summary = @([pscustomobject]@{
        DeepScanPerformed=$deep
        ShareCount=@($shares).Count
        UserShareCount=@($shares | Where-Object { $_.IsUserShare }).Count
        DeepScannedShares=@($acls).Count
    })

    return ,@{ SmbShares=@($shares); SharePermissions=@($perms); NtfsAclSummary=@($acls); FileShareSummary=$summary; DfsDiscovery=@($dfs) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'SmbShares'        -Description 'SMB shares (user vs administrative).'         -Rows (& $get 'SmbShares')       -Visibility 'Both'     -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'SharePermissions' -Description 'Share-level permissions for user shares.'      -Rows (& $get 'SharePermissions')-Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'NtfsAclSummary'   -Description 'Deep-scan folder/size/age summary per share.'  -Rows (& $get 'NtfsAclSummary')  -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'FileShareSummary' -Description 'File share scan summary (DeepScanPerformed).'  -Rows (& $get 'FileShareSummary')-Visibility 'Both'     -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'DfsDiscovery'     -Description 'DFS namespace/replication indicators.'         -Rows (& $get 'DfsDiscovery')    -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    # Dependency edges for user shares
    foreach ($s in (& $get 'SmbShares')) {
        if ($s.IsUserShare) { Add-DependencyEdge -Context $Context -SourceType 'SmbShare' -SourceName $s.Name -DependencyType 'ServesPath' -Target $s.Path -Evidence 'Shared folder' -Confidence 'Confirmed' -SourceDataset 'SmbShares' -ProjectImpact 'Data Migration' -ValidationQuestion 'Who uses this share and is it referenced by server name/UNC?' | Out-Null }
    }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets'
