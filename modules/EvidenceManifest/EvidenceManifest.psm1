<#
    EvidenceManifest.psm1
    Synthesis module (runs LAST, after all output files are written). When
    -GenerateEvidenceManifest is set, produces SHA256 hashes and evidence metadata
    for completed output files. Never hashes files before they are complete.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'EvidenceManifest'
        DisplayName               = 'Evidence Manifest'
        Category                  = 'Synthesis'
        Version                   = '1.0.0'
        DefaultInFast             = $false
        DefaultInDeep             = $false
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Low'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('EvidenceManifest')
        ProducesRisks             = $false
        ProducesFollowUpQuestions = $false
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $true
        IsSynthesis               = $true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='EvidenceManifest'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Get-FileSensitivity {
    param([string]$RelativePath)
    $rp = $RelativePath.ToLowerInvariant().Replace('/','\')
    # Ordered most-specific first. The client deliverable and the client-safe copies are
    # the only things in a run folder that are safe to send outside the delivery team.
    if ($rp -like 'reports\client-discovery-report*') { return 'ClientSafe' }
    if ($rp -like '*client-safe\*') { return 'ClientSafe' }
    if ($rp -like 'evidence\raw\*' -or $rp -like 'evidence\logs\*' -or $rp -like '*internal\*') { return 'Internal' }
    if ($rp -like 'reports\internal-engineering-report*' -or $rp -like 'reports\internal-dashboard-report*') { return 'Internal' }
    return 'SensitiveRedacted'
}

function Test-FileIsLiveDuringManifest {
    <#
        True for output files that are still written to after the manifest is generated,
        so their hash would be stale the moment it is recorded. Excluded from the manifest
        and reported in its place, because an unexplained hash mismatch is indistinguishable
        from tampering.
    #>
    param([string]$RelativePath)
    $rp = $RelativePath.ToLowerInvariant().Replace('/','\')
    # Paths updated for the two-folder layout: the live status and log directories moved
    # under evidence\. Matching only the old top-level 'status\' and 'logs\' here would
    # have silently stopped excluding them, reintroducing the stale-hash problem this
    # guard exists to prevent. Both spellings are accepted so an older run folder still
    # verifies cleanly.
    return ($rp -like 'status\*' -or $rp -like 'logs\*' -or
            $rp -like 'evidence\status\*' -or $rp -like 'evidence\logs\*')
}

function Invoke-DiscoveryEvidenceManifest {
    <# Hashes completed output files and writes the evidence manifest. #>
    param([object]$Context)
    Write-SectionStatus -Title 'Evidence Manifest' -Status 'Hashing' -Context $Context
    $evidenceDir = $Context.Paths['Evidence']
    $root = $Context.OutputPath
    if (-not $evidenceDir -or -not (Test-Path -LiteralPath $root)) { return }

    $manifest = [System.Collections.Generic.List[object]]::new()
    $hashLines = [System.Collections.Generic.List[string]]::new()

    try {
        $files = Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
            # Do not hash the evidence outputs themselves (they are still being written).
            ($_.DirectoryName -notlike (Join-Path $root 'evidence\manifest*')) -and
            # Nor anything still being appended to after this point. Update-StatusFile rewrites
            # status\*.json during the Archiving and Complete phases, and Write-Log keeps
            # appending to logs\, both of which run AFTER the manifest. Hashing them produced
            # 3 attested hashes that never matched on verification - and a recipient cannot
            # tell a known-stale hash from tampering, which defeats the manifest's purpose.
            # Hashing them last is not an option: the writes continue past any ordering.
            (-not (Test-FileIsLiveDuringManifest -RelativePath ($_.FullName.Substring($root.Length).TrimStart('\','/'))))
        }
        foreach ($file in $files) {
            try {
                $rel = $file.FullName.Substring($root.Length).TrimStart('\','/')
                $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                $row = [pscustomobject]@{
                    FileName     = $file.Name
                    RelativePath = $rel
                    SHA256       = $hash
                    CreatedTime  = (Normalize-DateTime -Value $file.CreationTime)
                    Description  = 'Discovery output file'
                    Sensitivity  = (Get-FileSensitivity -RelativePath $rel)
                }
                $manifest.Add($row)
                $hashLines.Add(("{0} *{1}" -f $hash, $rel))
            } catch { }
        }
    } catch {
        Write-Log -Level WARN -Message 'Evidence manifest enumeration failed.' -Module 'EvidenceManifest' -Exception $_ -Context $Context
    }

    # Resolved effective parameters - what makes the run reproducible, and exactly the kind of
    # thing an evidence manifest should attest. Sorted so two runs diff cleanly.
    $effective = [ordered]@{}
    if ($Context.Parameters) {
        foreach ($k in @($Context.Parameters.Keys | Sort-Object)) { $effective[[string]$k] = $Context.Parameters[$k] }
    }

    $collectionMeta = [ordered]@{
        RunId=$Context.RunId; ComputerName=$Context.ComputerName; Mode=$Context.Mode
        ProjectType=$Context.ProjectType; ComplianceLens=$Context.ComplianceLens
        StartTime=$Context.StartTime.ToString('o'); GeneratedTime=(Get-Date).ToString('o')
        PowerShellVersion=$Context.PowerShellVersion; IsAdmin=$Context.IsAdmin; IsSystem=$Context.IsSystem
        EffectiveParameters=$effective
        IncludedModules=@($Context.IncludedModules); ExcludedModules=@($Context.ExcludedModules)
        FindingCount=$Context.Findings.Count; DatasetCount=$Context.DataSets.Count
        FileCount=$manifest.Count
        UnhashedPaths=@('evidence\status\','evidence\logs\','evidence\manifest\')
        UnhashedReason='Still being written when the manifest is generated, so any hash recorded here would be stale on arrival. Absence from the manifest is expected and is not evidence of tampering.'
    }

    try { ($collectionMeta | ConvertTo-Json -Depth 6) | Out-File -LiteralPath (Join-Path $evidenceDir 'collection-metadata.json') -Encoding UTF8 -Force } catch { }
    try { Write-ObjectListToCsv -Rows @($manifest) -Path (Join-Path $evidenceDir 'evidence-manifest.csv') | Out-Null } catch { }
    try { ($hashLines -join [Environment]::NewLine) | Out-File -LiteralPath (Join-Path $evidenceDir 'hashes.sha256') -Encoding UTF8 -Force } catch { }

    Add-DataSet -Context $Context -Name 'EvidenceManifest' -Description 'SHA256 hashes and sensitivity of completed output files.' -Rows @($manifest) -Visibility 'Internal' -IncludeInWorkbook $false -SourceModule 'EvidenceManifest' | Out-Null

    # This module deliberately runs after Export-DiscoveryDatasets (it must hash finished
    # files), so the generic per-dataset export has already been and gone. Write this one
    # dataset's csv/json here to honour the "one CSV per dataset" promise in OUTPUT-GUIDE.md.
    try {
        $delim = Get-CsvDelimiter -Context $Context
        $safe  = ConvertTo-SafeFileName -Name 'EvidenceManifest'
        if ($Context.Paths.Contains('Csv'))  { Write-ObjectListToCsv  -Rows @($manifest) -Path (Join-Path $Context.Paths['Csv']  ("{0}.csv"  -f $safe)) -Delimiter $delim | Out-Null }
        if ($Context.Paths.Contains('Json')) { Write-ObjectListToJson -InputObject @($manifest) -Path (Join-Path $Context.Paths['Json'] ("{0}.json" -f $safe)) | Out-Null }
    } catch { }

    Write-Log -Level INFO -Message ("Evidence manifest hashed {0} file(s)." -f $manifest.Count) -Module 'EvidenceManifest' -Context $Context
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryEvidenceManifest'
