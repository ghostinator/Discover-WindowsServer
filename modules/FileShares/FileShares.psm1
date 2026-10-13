<#
    FileShares.psm1 - SMB shares, permissions, activity, DFS, Azure File Sync and optional deep
    crawl (read-only).
    Produces: SmbShares, SharePermissions, ShareRootAcl, SmbSessions, ShareActivity,
              NtfsAclSummary, FileShareSummary, DfsDiscovery, AzureFileSync.
    Fast mode: no crawl. Deep / -DeepFileShareScan: bounded (depth + per-share time budget),
    metadata-only crawl - file CONTENTS are never opened, and tiered/offline files are counted,
    never recalled. Session user names are withheld unless -IncludeSensitiveEvidence.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='FileShares'; DisplayName='File Shares, DFS & Migration Readiness'; Category='File'; Version='1.1.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('SmbShares','SharePermissions','ShareRootAcl','SmbSessions','ShareActivity','NtfsAclSummary','FileShareSummary','DfsDiscovery','AzureFileSync')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='FileShares'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Get-ShareMigrationFlags {
    <# Pure: name/path heuristics that change how a share is migrated. Indicators only. #>
    param([string]$Name, [string]$Path, [string]$Description)
    $hay = '{0} {1} {2}' -f $Name, $Path, $Description
    [pscustomobject]@{
        IsProfileOrRedirectedShare = [bool]($hay -match '(?i)\b(profiles?|users?|home(dirs?)?|redirect(ed|ion)?|my ?documents|desktops?|folder ?redirection)\b')
        PathOnSystemDrive          = [bool]($Path -and $Path -match ('^(?i)' + [regex]::Escape(($env:SystemDrive + '\'))))
        # Letter boundaries, not \b: '_' is a word character, so \bold\b misses 'Data_old'.
        PossiblePriorMigrationCopy = [bool]($hay -match '(?i)(^|[^a-z])(old|bak|backup|copy|migrat[a-z]*|archive|legacy|retired|temp)([^a-z]|$)|[_-](19|20)\d{2}[01]\d[0-3]\d\b')
    }
}

function Get-ShareDeepScanStats {
    <#
        Streaming, metadata-only crawl of one share root. Never builds a full file list in memory:
        each directory is enumerated once, folded into running totals, and released. Stops at
        -MaxDepth and at -TimeoutSeconds, and says so (ScanStatus/IncompleteReason) rather than
        returning a quietly-partial total. Reparse points are counted but not followed (they can
        loop or leave the volume); offline/recall-on-access (tiered) files are counted, never read.
        -ChildEnumerator exists so tests can simulate access-denied directories.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxDepth = 3,
        [double]$LargeFileThresholdGB = 5,
        [datetime]$OldCutoff = (Get-Date).AddYears(-7),
        [bool]$IncludeRecycleBin = $false,
        [int]$TimeoutSeconds = 180,
        [scriptblock]$ChildEnumerator = { param($dir) ([System.IO.DirectoryInfo]$dir).EnumerateFileSystemInfos() }
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $largeBytes = [int64]($LargeFileThresholdGB * 1GB)
    $recentCutoff = (Get-Date).AddDays(-30)
    $s = @{ Files=0; Bytes=[int64]0; Large=0; Old=0; Recent=0; Oldest=$null; Newest=$null; LongPaths=0; Denied=0; Reparse=0; Offline=0
            RecycleFiles=0; RecycleBytes=[int64]0; TopFolders=0; DepthLimited=$false; TimedOut=$false }
    $offlineMask = [int]([System.IO.FileAttributes]::Offline) -bor 0x400000 -bor 0x40000   # Offline | RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue(@($Path, 0, $false))
    while ($queue.Count -gt 0) {
        if ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $s.TimedOut = $true; break }
        $item = $queue.Dequeue(); $dir = $item[0]; $depth = [int]$item[1]; $inRecycle = [bool]$item[2]
        $children = $null
        try { $children = & $ChildEnumerator $dir } catch { $s.Denied++; continue }
        try {
            foreach ($c in $children) {
                $attr = [int]$c.Attributes
                if ($c.FullName.Length -ge 260) { $s.LongPaths++ }
                if ($c -is [System.IO.DirectoryInfo]) {
                    if ($depth -eq 0 -and -not ($c.Name -match '^\$RECYCLE\.BIN$')) { $s.TopFolders++ }
                    if ($attr -band [int][System.IO.FileAttributes]::ReparsePoint) { $s.Reparse++; continue }
                    if ($depth + 1 -gt $MaxDepth) { $s.DepthLimited = $true; continue }
                    $queue.Enqueue(@($c.FullName, ($depth + 1), ($inRecycle -or ($c.Name -match '^\$RECYCLE\.BIN$'))))
                    continue
                }
                if ($attr -band $offlineMask) { $s.Offline++ }
                if ($attr -band [int][System.IO.FileAttributes]::ReparsePoint) { $s.Reparse++ }
                $len = [int64]$c.Length
                if ($inRecycle) { $s.RecycleFiles++; $s.RecycleBytes += $len; if (-not $IncludeRecycleBin) { continue } }
                $s.Files++; $s.Bytes += $len
                if ($len -ge $largeBytes) { $s.Large++ }
                $w = $c.LastWriteTime
                if ($w -lt $OldCutoff) { $s.Old++ }
                if ($w -ge $recentCutoff) { $s.Recent++ }
                if ($null -eq $s.Oldest -or $w -lt $s.Oldest) { $s.Oldest = $w }
                if ($null -eq $s.Newest -or $w -gt $s.Newest) { $s.Newest = $w }
            }
        } catch {
            # Enumeration is lazy: a directory can fail part-way through (access denied on a child,
            # a path too long for .NET Framework). Count it and keep going with the rest.
            if ($_.Exception -is [System.IO.PathTooLongException] -or $_.Exception.InnerException -is [System.IO.PathTooLongException]) { $s.LongPaths++ } else { $s.Denied++ }
        }
    }
    $sw.Stop()
    $reasons = @()
    if ($s.TimedOut) { $reasons += ("time budget of {0}s reached" -f $TimeoutSeconds) }
    if ($s.Denied -gt 0) { $reasons += ("{0} folder(s) could not be read" -f $s.Denied) }
    $status = if ($s.TimedOut -or $s.Denied -gt 0) { 'Incomplete' } elseif ($s.DepthLimited) { 'DepthLimited' } else { 'Complete' }
    [pscustomobject]@{
        TopLevelFolders=$s.TopFolders; FileCount=$s.Files; TotalSizeGB=(Convert-BytesToGB $s.Bytes)
        LargeFilesOverThreshold=$s.Large; OldFilesOverYears=$s.Old; RecentlyModified30d=$s.Recent; MaxDepthScanned=$MaxDepth
        RecycleBinIncluded=$IncludeRecycleBin; RecycleBinFilesFound=$s.RecycleFiles; RecycleBinSizeGB=(Convert-BytesToGB $s.RecycleBytes)
        OldestWriteTime=(Normalize-DateTime $s.Oldest); NewestWriteTime=(Normalize-DateTime $s.Newest)
        LongPathCount=$s.LongPaths; AccessDeniedCount=$s.Denied; ReparsePointCount=$s.Reparse; OfflineFileCount=$s.Offline
        ScanDurationSeconds=[math]::Round($sw.Elapsed.TotalSeconds, 1); ScanStatus=$status; IncompleteReason=($reasons -join '; ')
    }
}

function Get-ShareRootAclSummary {
    <# Root NTFS ACL shape for one share path (Get-Acl is a read). Counts only - the full ACL stays on the server. #>
    param([string]$Share, [string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = @($acl.Access)
    $explicit = @($rules | Where-Object { -not $_.IsInherited })
    $unresolved = @($rules | Where-Object { [string]$_.IdentityReference -match '^S-1-' })
    $everyone = @($rules | Where-Object { [string]$_.IdentityReference -match '(?i)^Everyone$|\\Everyone$' -and [string]$_.AccessControlType -eq 'Allow' })
    $complexity = if ($explicit.Count -gt 15 -or $unresolved.Count -gt 0) { 'High' } elseif ($explicit.Count -gt 5 -or $acl.AreAccessRulesProtected) { 'Medium' } else { 'Low' }
    [pscustomobject]@{
        Share=$Share; Path=$Path; Owner=[string]$acl.Owner; AceCount=$rules.Count; ExplicitAceCount=$explicit.Count
        InheritanceDisabled=[bool]$acl.AreAccessRulesProtected; UnresolvedSidCount=$unresolved.Count
        EveryoneAllowed=[bool]($everyone.Count -gt 0); PermissionComplexity=$complexity
    }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $shares = [System.Collections.Generic.List[object]]::new()
    $perms = [System.Collections.Generic.List[object]]::new()
    $rootAcl = [System.Collections.Generic.List[object]]::new()
    $sessions = [System.Collections.Generic.List[object]]::new()
    $activity = [System.Collections.Generic.List[object]]::new()
    $acls = [System.Collections.Generic.List[object]]::new()
    $dfs = [System.Collections.Generic.List[object]]::new()
    $afs = [System.Collections.Generic.List[object]]::new()
    $deep = ([bool]$Context.Parameters['DeepFileShareScan'])
    $sensitive = ([bool]$Context.Parameters['IncludeSensitiveEvidence'])

    $newShare = {
        param($name, $path, $desc, $type, $isUser, $enumMode, $encrypt)
        $fl = Get-ShareMigrationFlags -Name $name -Path $path -Description $desc
        [pscustomobject]@{ Name=$name; Path=$path; Description=$desc; ShareType=$type; IsUserShare=$isUser; FolderEnumerationMode=$enumMode; EncryptData=$encrypt
            IsSpecialShare=[bool](-not $isUser); PermissionEntryCount=$null; EveryoneShareAccess=$false
            IsProfileOrRedirectedShare=$fl.IsProfileOrRedirectedShare; PathOnSystemDrive=$fl.PathOnSystemDrive; UserShareOnSystemDrive=[bool]($isUser -and $fl.PathOnSystemDrive); PossiblePriorMigrationCopy=$fl.PossiblePriorMigrationCopy
            ActiveSessionCount=$null; OpenFileCount=$null; InUseDuringCollection=$null }
    }

    # ---- Shares ----
    try {
        if (Get-CommandAvailable -Name 'Get-SmbShare') {
            foreach ($s in (Get-SmbShare -ErrorAction SilentlyContinue)) {
                $isUser = (-not ($s.Name.EndsWith('$'))) -and ([string]$s.ShareType -eq 'FileSystemDirectory')   # not print queues / IPC / devices
                $row = & $newShare $s.Name $s.Path $s.Description ([string]$s.ShareType) $isUser ([string]$s.FolderEnumerationMode) $s.EncryptData
                $shares.Add($row)
                if ($isUser) {
                    try {
                        $acc = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)
                        foreach ($a in $acc) { $perms.Add([pscustomobject]@{ Share=$s.Name; Account=$a.AccountName; AccessRight=[string]$a.AccessRight; AccessType=[string]$a.AccessControlType }) }
                        $row.PermissionEntryCount = $acc.Count
                        $row.EveryoneShareAccess = [bool](@($acc | Where-Object { [string]$_.AccountName -match '(?i)^Everyone$|\\Everyone$' -and [string]$_.AccessControlType -eq 'Allow' }).Count -gt 0)
                    } catch { }
                }
            }
        } else {
            foreach ($s in (Invoke-CimSafe -ClassName 'Win32_Share')) {
                $isUser = (-not ($s.Name.EndsWith('$'))) -and (([uint32]$s.Type -band 0x7FFFFFFF) -eq 0)   # Win32_Share Type 0 = disk share
                $shares.Add((& $newShare $s.Name $s.Path $s.Description ([string]$s.Type) $isUser '' $null))
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'FileShares' -Message 'Share enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Root NTFS ACL shape (user shares) ----
    foreach ($s in ($shares | Where-Object { $_.IsUserShare -and $_.Path })) {
        try { $rootAcl.Add((Get-ShareRootAclSummary -Share $s.Name -Path $s.Path)) }
        catch { Add-Limitation -Context $Context -Module 'FileShares' -Message ("Root ACL of share '{0}' could not be read." -f $s.Name) -Reason $_.Exception.Message | Out-Null }
    }

    # ---- Live SMB activity: sessions + open-file counts (point in time) ----
    try {
        if (Get-CommandAvailable -Name 'Get-SmbSession') {
            foreach ($ss in @(Get-SmbSession -ErrorAction Stop)) {
                $user = [string]$ss.ClientUserName
                if (-not $sensitive -and $user) { $user = (($user -split '\\')[0]) + '\(withheld - use -IncludeSensitiveEvidence)' }
                $sessions.Add([pscustomobject]@{ ClientComputerName=[string]$ss.ClientComputerName; ClientUserName=$user; NumOpens=$ss.NumOpens; SecondsExists=$ss.SecondsExists; Dialect=[string]$ss.Dialect })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'FileShares' -Message 'SMB sessions could not be read (requires elevation).' -Reason $_.Exception.Message | Out-Null }
    try {
        if (Get-CommandAvailable -Name 'Get-SmbOpenFile') {
            $open = @(Get-SmbOpenFile -ErrorAction Stop)
            foreach ($s in ($shares | Where-Object { $_.IsUserShare -and $_.Path })) {
                $root = ([string]$s.Path).TrimEnd('\') + '\'
                $hits = @($open | Where-Object { ([string]$_.Path).StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or [string]$_.Path -ieq $s.Path })
                $clients = @($hits | ForEach-Object { [string]$_.ClientComputerName } | Select-Object -Unique)
                $s.OpenFileCount = $hits.Count; $s.ActiveSessionCount = $clients.Count; $s.InUseDuringCollection = [bool]($hits.Count -gt 0)
                $activity.Add([pscustomobject]@{ Share=$s.Name; OpenFileCount=$hits.Count; DistinctClientComputers=$clients.Count; ClientComputers=($clients -join ', '); InUseDuringCollection=[bool]($hits.Count -gt 0); ObservedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'FileShares' -Message 'SMB open files could not be read (requires elevation); share activity unknown.' -Reason $_.Exception.Message | Out-Null }

    # ---- Deep crawl (only when enabled) ----
    if ($deep) {
        $maxDepth = [int]$Context.Parameters['MaxDepth']; if ($maxDepth -le 0) { $maxDepth = 3 }
        $largeGB = [double]$Context.Parameters['LargeFileThresholdGB']; if ($largeGB -le 0) { $largeGB = 5 }
        $oldYears = [int]$Context.Parameters['OldFileYears']; if ($oldYears -le 0) { $oldYears = 7 }
        $budget = 180
        try { $bv = $Context.Config.Default.defaults.fileScanShareTimeoutSeconds; if ($bv) { $budget = [int]$bv } } catch { }
        # Recycle-bin contents are excluded from share size/age totals by default: deleted
        # data is not migration payload, and counting it silently inflates the data-volume
        # estimate a quote is built from. -IncludeRecycleBin folds it back in. Either way the
        # recycled volume is reported separately, since it is reclaimable space worth knowing.
        $includeRecycleBin = ([bool]$Context.Parameters['IncludeRecycleBin'])
        foreach ($s in ($shares | Where-Object { $_.IsUserShare -and $_.Path -and (Test-Path -LiteralPath $_.Path) })) {
            try {
                $st = Get-ShareDeepScanStats -Path $s.Path -MaxDepth $maxDepth -LargeFileThresholdGB $largeGB -OldCutoff ((Get-Date).AddYears(-$oldYears)) -IncludeRecycleBin $includeRecycleBin -TimeoutSeconds $budget
                $row = [ordered]@{ Share=$s.Name; Path=$s.Path }
                foreach ($p in $st.PSObject.Properties) { $row[$p.Name] = $p.Value }
                $acls.Add([pscustomobject]$row)
                if ($st.ScanStatus -eq 'Incomplete') { Add-Limitation -Context $Context -Module 'FileShares' -Message ("Deep scan of share '{0}' is incomplete: {1}." -f $s.Name, $st.IncompleteReason) -Impact 'Share size/age totals are a lower bound' | Out-Null }
            } catch { Add-Limitation -Context $Context -Module 'FileShares' -Message ("Deep scan of share '{0}' failed or was partial." -f $s.Name) -Reason $_.Exception.Message | Out-Null }
        }
    }

    # ---- DFS ----
    try {
        if (Get-CommandAvailable -Name 'Get-DfsnRoot') { foreach ($r in (Get-DfsnRoot -ErrorAction SilentlyContinue)) { $dfs.Add([pscustomobject]@{ Type='Namespace'; Name=$r.Path; Detail=[string]$r.State }) } }
        if (Get-CommandAvailable -Name 'Get-DfsReplicationGroup') { foreach ($g in (Get-DfsReplicationGroup -ErrorAction SilentlyContinue)) { $dfs.Add([pscustomobject]@{ Type='Replication'; Name=$g.GroupName; Detail=$g.Description }) } }
        if (Get-CommandAvailable -Name 'Get-DfsReplicatedFolder') { foreach ($f in (Get-DfsReplicatedFolder -ErrorAction SilentlyContinue)) { $dfs.Add([pscustomobject]@{ Type='ReplicatedFolder'; Name=('{0}\{1}' -f $f.GroupName, $f.FolderName); Detail=[string]$f.DfsnPath }) } }
        $dfsr = Get-Service -Name 'DFSR' -ErrorAction SilentlyContinue
        if ($dfsr) { $dfs.Add([pscustomobject]@{ Type='Service'; Name='DFSR'; Detail=[string]$dfsr.Status }) }
    } catch { }

    # ---- Azure File Sync (agent + registration indicators; nothing is queried in Azure) ----
    try {
        $svc = Get-Service -Name 'FileSyncSvc' -ErrorAction SilentlyContinue
        $agentApp = @(if ($Context.DataSets.Contains('InstalledApplications')) { @($Context.DataSets['InstalledApplications'].Rows | Where-Object { $_.DisplayName -match '(?i)Storage Sync Agent|Azure File Sync' }) } else { @() })
        $regPresent = Test-RegistryPathSafe 'HKLM:\SOFTWARE\Microsoft\Azure\StorageSync'
        if ($svc -or $agentApp.Count -gt 0 -or $regPresent) {
            $afs.Add([pscustomobject]@{ Item='Agent'; Value=$(if ($agentApp.Count) { '{0} {1}' -f $agentApp[0].DisplayName, $agentApp[0].DisplayVersion } else { 'Not in installed applications' }); Evidence='InstalledApplications'; Confidence=$(if ($agentApp.Count) { 'Confirmed' } else { 'Possible' }) })
            $afs.Add([pscustomobject]@{ Item='Sync service (FileSyncSvc)'; Value=$(if ($svc) { [string]$svc.Status } else { 'Not present' }); Evidence='Get-Service'; Confidence=$(if ($svc) { 'Confirmed' } else { 'NotDetected' }) })
            $afs.Add([pscustomobject]@{ Item='Registration registry key'; Value=[string]$regPresent; Evidence='HKLM:\SOFTWARE\Microsoft\Azure\StorageSync'; Confidence=$(if ($regPresent) { 'Likely' } else { 'NotDetected' }) })
            Add-Unknown -Context $Context -Unknown 'Azure File Sync agent indicators are present; sync groups, cloud endpoints and cloud tiering policy live in Azure and were not queried.' -WhyItMatters 'Tiered files exist only as stubs locally; a file-level copy recalls or breaks them, and the server endpoint must be re-registered on a target.' -Module 'FileShares' -RecommendedValidationQuestion 'Which sync groups and server endpoints use this server, and is cloud tiering enabled?' | Out-Null
        }
    } catch { }

    $summary = @([pscustomobject]@{
        DeepScanPerformed=$deep
        ShareCount=@($shares).Count
        UserShareCount=@($shares | Where-Object { $_.IsUserShare }).Count
        DeepScannedShares=@($acls).Count
        IncompleteDeepScans=@($acls | Where-Object { $_.ScanStatus -eq 'Incomplete' }).Count
        TotalScannedGB=$(if ($acls.Count) { [math]::Round([double](($acls | Measure-Object -Property TotalSizeGB -Sum).Sum), 2) } else { $null })
        SharesInUseDuringCollection=@($shares | Where-Object { $_.InUseDuringCollection }).Count
        ActiveSmbSessions=$sessions.Count
        DfsInUse=[bool](@($dfs | Where-Object { $_.Type -ne 'Service' }).Count -gt 0)
        AzureFileSyncIndicators=[bool]($afs.Count -gt 0)
    })

    return ,@{ SmbShares=@($shares); SharePermissions=@($perms); ShareRootAcl=@($rootAcl); SmbSessions=@($sessions); ShareActivity=@($activity); NtfsAclSummary=@($acls); FileShareSummary=$summary; DfsDiscovery=@($dfs); AzureFileSync=@($afs) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'SmbShares'        -Description 'SMB shares (user vs administrative) with migration flags.' -Rows (& $get 'SmbShares') -Visibility 'Both' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'SharePermissions' -Description 'Share-level permissions for user shares.'      -Rows (& $get 'SharePermissions')-Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'ShareRootAcl'     -Description 'Root NTFS ACL shape per user share (counts, inheritance, unresolved SIDs).' -Rows (& $get 'ShareRootAcl') -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'SmbSessions'      -Description 'SMB sessions at collection time (user names withheld unless -IncludeSensitiveEvidence).' -Rows (& $get 'SmbSessions') -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'ShareActivity'    -Description 'Open-file counts per share at collection time (point in time, not usage history).' -Rows (& $get 'ShareActivity') -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'NtfsAclSummary'   -Description 'Deep-scan folder/size/age summary per share (opt-in, bounded).' -Rows (& $get 'NtfsAclSummary') -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'FileShareSummary' -Description 'File share scan summary (DeepScanPerformed).'  -Rows (& $get 'FileShareSummary')-Visibility 'Both'     -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'DfsDiscovery'     -Description 'DFS namespace/replication indicators.'         -Rows (& $get 'DfsDiscovery')    -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    Add-DataSet -Context $Context -Name 'AzureFileSync'    -Description 'Azure File Sync agent / registration indicators.' -Rows (& $get 'AzureFileSync') -Visibility 'Internal' -SourceModule 'FileShares' | Out-Null
    # Dependency edges for user shares
    foreach ($s in (& $get 'SmbShares')) {
        if ($s.IsUserShare) { Add-DependencyEdge -Context $Context -SourceType 'SmbShare' -SourceName $s.Name -DependencyType 'ServesPath' -Target $s.Path -Evidence 'Shared folder' -Confidence 'Confirmed' -SourceDataset 'SmbShares' -ProjectImpact 'Data Migration' -ValidationQuestion 'Who uses this share and is it referenced by server name/UNC?' | Out-Null }
    }
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('SmbShares') -and @($Context.DataSets['SmbShares'].Rows | Where-Object { $_.IsUserShare }).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'File shares' -Module 'FileShares' -Audience 'Both' -Question 'For each shared folder: who owns the data, is any of it no longer needed, and is it reached by drive mapping, DFS path or this server''s name?' | Out-Null
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-ShareMigrationFlags','Get-ShareDeepScanStats','Get-ShareRootAclSummary'
