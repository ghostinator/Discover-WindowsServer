<#
    ConfigDependencyScan.psm1 - scan safe config files for hardcoded dependencies (read-only).
    Gated: runs only in Deep mode or with -IncludeConfigDependencyScan.
    Produces: ConfigDependencyHints, CriticalPaths. Redacts secrets; reports where, never the value.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='ConfigDependencyScan'; DisplayName='Config Dependency Scan'; Category='Applications'; Version='1.0.0'
        DefaultInFast=$false; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Medium'; CanRunAsSystem=$true
        ProducesDatasets=@('ConfigDependencyHints','CriticalPaths')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $enabled = ($Context.Mode -eq 'Deep') -or ([bool]$Context.Parameters['IncludeConfigDependencyScan'])
    if ($enabled) { return [pscustomobject]@{ ModuleName='ConfigDependencyScan'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='ConfigDependencyScan'; CanRun=$false; Status='NotApplicable'; Reason='Enable with -IncludeConfigDependencyScan or Deep mode.'; Limitations=@() }
}

function Get-ConfigScanRoots {
    param([object]$Context)
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($r in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, 'C:\inetpub')) { if ($r -and (Test-Path -LiteralPath $r)) { [void]$roots.Add($r) } }
    # Install dirs discovered from apps/services
    try {
        if ($Context.DataSets.Contains('InstalledApplications')) {
            foreach ($a in @($Context.DataSets['InstalledApplications'].Rows)) { if ($a.InstallLocation -and (Test-Path -LiteralPath $a.InstallLocation)) { [void]$roots.Add($a.InstallLocation) } }
        }
    } catch { }
    return ,@($roots | Select-Object -Unique)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $hints=[System.Collections.Generic.List[object]]::new(); $critical=[System.Collections.Generic.List[object]]::new()
    $maxMB = [int]$Context.Parameters['ConfigScanMaxFileSizeMB']; if ($maxMB -le 0) { $maxMB = 10 }
    $maxBytes = $maxMB * 1MB
    $exts = @('.config','.ini','.json','.xml','.yml','.yaml','.properties','.udl','.dsn','.env','.bat','.cmd','.ps1','.vbs')
    $fileCap = 3000; $scanned = 0; $capped = $false
    $hintCap = 5000
    # Bound the recursion. Without -Depth, Get-ChildItem -Recurse walks entire install trees
    # before the loop even starts, so $fileCap (which limits files PARSED) could not stop the
    # expensive part. Config files of interest live near the top of an install directory.
    $scanDepth = 8
    $winRoot = ($env:SystemRoot); if (-not $winRoot) { $winRoot = 'C:\Windows' }
    $usersRoot = 'C:\Users'

    # IIS auto-backs up its whole config into a new C:\inetpub\history\CFGHISTORY_nnnnnnnnnn
    # folder on every change and keeps many of them - each one a near-complete duplicate of the
    # last, so scanning all of them just re-finds the same facts repeatedly (measured: ~19% of
    # all hints on a lab box with just 6 backups). Keep only the newest one; the folder name's
    # numeric suffix is IIS's own ordering.
    $historyRoot = 'C:\inetpub\history'
    $latestHistoryDir = ''
    if (Test-Path -LiteralPath $historyRoot) {
        try {
            $latest = Get-ChildItem -LiteralPath $historyRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
            if ($latest) { $latestHistoryDir = $latest.FullName.ToLowerInvariant() }
        } catch { }
    }

    $indicators = @(
        @{ Type='SqlServer'; Rx='(?i)(server|data source)\s*=' }, @{ Type='Database'; Rx='(?i)(initial catalog|database)\s*=' },
        @{ Type='ConnectionString'; Rx='(?i)connectionstring' }, @{ Type='JDBC'; Rx='(?i)jdbc:' }, @{ Type='ODBC'; Rx='(?i)\bodbc\b' },
        @{ Type='SMTP'; Rx='(?i)smtp' }, @{ Type='LDAP'; Rx='(?i)ldap://|ldaps://' }, @{ Type='HTTP'; Rx='(?i)https?://' },
        @{ Type='UNCPath'; Rx='\\\\[A-Za-z0-9._-]+\\[^\s"'']+' }, @{ Type='IPAddress'; Rx='\b(\d{1,3}\.){3}\d{1,3}\b' },
        @{ Type='Secret'; Rx='(?i)(password|secret|api[_ ]?key|token|user id|username|license)\s*[:=]' }, @{ Type='LicenseServer'; Rx='(?i)license.?server|lmgrd|flexlm|@\d' }
    )

    $roots = Get-ConfigScanRoots -Context $Context
    foreach ($root in $roots) {
        if ($capped) { break }
        try {
            $files = Get-ChildItem -LiteralPath $root -Recurse -Depth $scanDepth -File -ErrorAction SilentlyContinue | Where-Object { $exts -contains $_.Extension.ToLower() }
            foreach ($f in $files) {
                if ($scanned -ge $fileCap) { $capped = $true; break }
                try {
                    if ($f.Length -gt $maxBytes) { continue }
                    $lower = $f.FullName.ToLowerInvariant()
                    if ((-not [bool]$Context.Parameters['IncludeWindowsFolder']) -and $lower.StartsWith($winRoot.ToLowerInvariant())) { continue }
                    if ((-not [bool]$Context.Parameters['IncludeUserProfiles']) -and $lower.StartsWith($usersRoot.ToLowerInvariant())) { continue }
                    if ($lower.StartsWith(($historyRoot + '\').ToLowerInvariant()) -and (-not $lower.StartsWith($latestHistoryDir))) { continue }
                    $scanned++
                    $lines = Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue
                    $ln = 0
                    foreach ($line in $lines) {
                        $ln++
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }
                        foreach ($ind in $indicators) {
                            if ($line -match $ind.Rx) {
                                $redacted = Redact-SensitiveValue -InputString ($line.Trim()) -Context $Context
                                if ($redacted.Length -gt 300) { $redacted = $redacted.Substring(0,300) }
                                $hints.Add([pscustomobject]@{ FilePath=$f.FullName; FileType=$f.Extension; IndicatorType=$ind.Type; RedactedLine=$redacted; RelatedApp=(Split-Path (Split-Path $f.FullName -Parent) -Leaf); Confidence='Likely'; LineNumber=$ln })
                                break
                            }
                        }
                        if ($hints.Count -ge $hintCap) { $capped = $true; break }
                    }
                } catch { }
                if ($capped) { break }   # hint cap reached - stop opening further files
            }
        } catch { Add-Limitation -Context $Context -Module 'ConfigDependencyScan' -Message ("Scan of '{0}' failed or partial." -f $root) -Reason $_.Exception.Message | Out-Null }
    }
    if ($capped) { Add-Limitation -Context $Context -Module 'ConfigDependencyScan' -Message ("Config scan stopped early (file cap {0}, hint cap {1}, max depth {2}); results may be incomplete." -f $fileCap, $hintCap, $scanDepth) -Impact 'Coverage capped' | Out-Null }

    # ---- Critical paths from datasets ----
    try {
        $addPath = {
            param($path,$src,$reason,$related,$impact)
            if ([string]::IsNullOrWhiteSpace($path)) { return }
            $exists = $false; try { $exists = Test-Path -LiteralPath $path } catch { }
            $critical.Add([pscustomobject]@{ Path=$path; Source=$src; ReasonItMatters=$reason; Exists=$exists; SizeIfSafe=''; RelatedServiceOrApp=$related; Confidence='Likely'; PotentialProjectImpact=$impact })
        }
        if ($Context.DataSets.Contains('Services')) { foreach ($s in @($Context.DataSets['Services'].Rows | Where-Object { $_.ExecutablePath })) { & $addPath $s.ExecutablePath 'Service' 'Service executable location' $s.Name 'Cutover Complexity' } }
        if ($Context.DataSets.Contains('SmbShares')) { foreach ($s in @($Context.DataSets['SmbShares'].Rows | Where-Object { $_.IsUserShare })) { & $addPath $s.Path 'SmbShare' 'Shared data location' $s.Name 'Data Migration' } }
        if ($Context.DataSets.Contains('IisSites')) { foreach ($s in @($Context.DataSets['IisSites'].Rows | Where-Object { $_.PhysicalPath })) { & $addPath $s.PhysicalPath 'IIS' 'Web content location' $s.Name 'Cutover Complexity' } }
    } catch { }

    return ,@{ ConfigDependencyHints=@($hints); CriticalPaths=@($critical) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'ConfigDependencyHints' -Description 'Hardcoded dependencies found in config files (secrets redacted).' -Rows (& $get 'ConfigDependencyHints') -Visibility 'Internal' -SourceModule 'ConfigDependencyScan' | Out-Null
    Add-DataSet -Context $Context -Name 'CriticalPaths'         -Description 'Paths critical to app/service function.'                     -Rows (& $get 'CriticalPaths')         -Visibility 'Internal' -SourceModule 'ConfigDependencyScan' | Out-Null
    # Dependency edges from config hints: ONE aggregate edge per indicator type, not one edge
    # per hint. A busy server yields thousands of per-hint edges (5000 of 5156 edges = 97% of
    # the graph on the first real Deep run), all with empty Target, burying the actionable
    # Service/Process/Server edges. Per-file detail remains complete in ConfigDependencyHints.
    $byType = @{}
    foreach ($h in (& $get 'ConfigDependencyHints')) {
        $t = [string]$h.IndicatorType
        if (-not $byType.ContainsKey($t)) { $byType[$t] = @{ Count = 0; Files = @{} } }
        $byType[$t].Count++
        if ($h.FilePath) { $byType[$t].Files[[string]$h.FilePath] = $true }
    }
    foreach ($t in ($byType.Keys | Sort-Object)) {
        try { Add-DependencyEdge -Context $Context -SourceType 'ConfigFile' -SourceName ("{0} config file(s)" -f $byType[$t].Files.Count) -DependencyType $t -Target '' -Evidence ("{0} '{1}' hint(s) across {2} config file(s); per-file detail in the ConfigDependencyHints dataset." -f $byType[$t].Count, $t, $byType[$t].Files.Count) -Confidence 'Likely' -SourceDataset 'ConfigDependencyHints' -ProjectImpact 'Data Migration' -ValidationQuestion 'Do these dependencies still exist after migration, and who can update them?' | Out-Null } catch { }
    }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-ConfigScanRoots'
