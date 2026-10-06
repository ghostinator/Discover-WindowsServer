<#
    Applications.psm1 - installed applications, running processes, and application
    fingerprint matching (read-only).
    Produces: InstalledApplications, RunningProcesses (during collection),
              ApplicationFingerprints (AFTER all collectors - see below).

    ORDERING: fingerprint matchers in config\application-fingerprints.json reference
    datasets owned by other modules - ListeningPorts (Network), IisSites (IIS),
    SqlInstances (SQL). Applications runs 4th of 25 collectors, so those datasets do not
    exist yet while this module is collecting. Matching therefore runs post-collection via
    Invoke-DiscoveryFingerprintSynthesis, which the orchestrator calls after every collector
    and before the RiskEngine. Do not move it back into ConvertTo-DiscoveryDatasets: any
    matcher whose source is collected later would silently never fire.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='Applications'; DisplayName='Installed Applications & Fingerprints'; Category='Applications'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('InstalledApplications','RunningProcesses','ApplicationFingerprints')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='Applications'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Get-InstalledAppsFromKey {
    param([string]$Path, [string]$Arch, [object]$Context)
    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return ,@($rows) }
        foreach ($k in (Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            try {
                $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if (-not $p.DisplayName) { continue }
                $legacy = ([bool]($p.DisplayName -match '(?i)\.NET Framework [1-3]\.|Visual C\+\+ 20(05|08|10)|Java(\s|.*)(SE 6|SE 7|Runtime.*(6|7)\.)|Silverlight|Adobe (Flash|Shockwave|AIR)|Microsoft Visual Basic 6|PowerBuilder|Crystal Reports (X|9|10|11)'))
                $rows.Add([pscustomobject]@{
                    DisplayName=$p.DisplayName; DisplayVersion=$p.DisplayVersion; Publisher=$p.Publisher
                    InstallDate=$p.InstallDate; InstallLocation=$p.InstallLocation
                    UninstallString=(Redact-SensitiveValue -InputString $p.UninstallString -Context $Context)
                    EstimatedSizeMB=([math]::Round(([double]($p.EstimatedSize) / 1024), 1))
                    SystemComponent=([bool]($p.SystemComponent)); RegistrySource=$Path; ArchitectureHint=$Arch
                    Is32Bit=([bool]($Arch -eq '32')); IsLegacyRuntime=$legacy; UnknownPublisher=([bool]([string]::IsNullOrWhiteSpace($p.Publisher)))
                })
            } catch { }
        }
    } catch { }
    return ,@($rows)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $apps = [System.Collections.Generic.List[object]]::new()
    $procs = [System.Collections.Generic.List[object]]::new()

    # ---- Installed applications ----
    try {
        foreach ($r in (Get-InstalledAppsFromKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Arch '64' -Context $Context)) { $apps.Add($r) }
        foreach ($r in (Get-InstalledAppsFromKey -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -Arch '32' -Context $Context)) { $apps.Add($r) }
        foreach ($r in (Get-InstalledAppsFromKey -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Arch 'user' -Context $Context)) { $apps.Add($r) }
        if ($Context.IsSystem) { Add-Limitation -Context $Context -Module 'Applications' -Message 'Running as SYSTEM: per-user (HKCU) installed applications may be invisible.' -Impact 'Incomplete app inventory' | Out-Null }
    } catch { Add-Limitation -Context $Context -Module 'Applications' -Message 'Installed application enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Running processes ----
    try {
        $cimProcs = @{}
        foreach ($cp in (Invoke-CimSafe -ClassName 'Win32_Process')) { $cimProcs[[int]$cp.ProcessId] = $cp }
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            try {
                $cp = $cimProcs[[int]$p.Id]
                $cmd = if ($cp) { Redact-SensitiveValue -InputString $cp.CommandLine -Context $Context } else { '' }
                $path = ''
                try { $path = $p.Path } catch { }
                if (-not $path -and $cp) { $path = $cp.ExecutablePath }
                $procs.Add([pscustomobject]@{
                    Name=$p.Name; Id=$p.Id; Path=$path; CommandLine=$cmd
                    ParentProcessId=($(if ($cp) { $cp.ParentProcessId } else { $null }))
                    Company=$p.Company; Product=$p.Product
                    StartTime=($(try { Normalize-DateTime $p.StartTime } catch { $null }))
                    WorkingSetMB=([math]::Round($p.WorkingSet64 / 1MB, 1))
                })
            } catch { }
        }
    } catch { Add-Limitation -Context $Context -Module 'Applications' -Message 'Process enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    return ,@{ InstalledApplications=@($apps); RunningProcesses=@($procs) }
}

function Get-FingerprintMatches {
    param([object]$Context)
    $results = [System.Collections.Generic.List[object]]::new()
    $fpConfig = $null
    try { $fpConfig = $Context.Config.Fingerprints } catch { }
    if (-not $fpConfig -or -not $fpConfig.fingerprints) { return ,@($results) }
    # confidenceModel is config-driven; fall back to sane defaults if absent.
    $strong = @('Services','InstalledApplications','SqlInstances','IisSites')
    $labelMultiple = 'Confirmed'; $labelStrong = 'Likely'; $labelWeak = 'Possible'
    try {
        $cm = $fpConfig.confidenceModel
        if ($cm) {
            if ($cm.strongSources)    { $strong = @($cm.strongSources) }
            if ($cm.multipleMatches)  { $labelMultiple = [string]$cm.multipleMatches }
            if ($cm.oneStrongMatch)   { $labelStrong   = [string]$cm.oneStrongMatch }
            if ($cm.oneWeakMatch)     { $labelWeak     = [string]$cm.oneWeakMatch }
        }
    } catch { }
    foreach ($fp in $fpConfig.fingerprints) {
        try {
            $hitSources = [System.Collections.Generic.List[string]]::new()
            $hitEvidence = [System.Collections.Generic.List[string]]::new()
            $strongHit = $false
            foreach ($mchr in @($fp.matchers)) {
                $src = $mchr.source
                if (-not $Context.DataSets.Contains($src)) { continue }
                $rows = @($Context.DataSets[$src].Rows)
                foreach ($row in $rows) {
                    $val = Get-RowValue -Row $row -Column $mchr.field
                    if ($null -ne $val -and ([string]$val -match $mchr.pattern)) {
                        if (-not $hitSources.Contains($src)) { $hitSources.Add($src) }
                        if ($hitEvidence.Count -lt 3) { $hitEvidence.Add(("{0}.{1}='{2}'" -f $src, $mchr.field, ([string]$val))) }
                        if ($strong -contains $src) { $strongHit = $true }
                        break
                    }
                }
            }
            if ($hitSources.Count -eq 0) { continue }
            $confidence = if ($hitSources.Count -ge 2) { $labelMultiple } elseif ($strongHit) { $labelStrong } else { $labelWeak }
            $results.Add([pscustomobject]@{
                ApplicationName=$fp.applicationName; Vendor=$fp.vendor; Category=$fp.category
                EvidenceSource=($hitSources -join '; '); Evidence=($hitEvidence -join ' | '); Confidence=$confidence
                LikelyDependencyType=$fp.likelyDependencyType
                PotentialProjectImpact=(@($fp.potentialProjectImpact) -join '; ')
                SuggestedValidationQuestion=$fp.suggestedValidationQuestion
            })
        } catch { }
    }
    return ,@($results)
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $apps = @(if ($RawData.InstalledApplications) { @($RawData.InstalledApplications) } else { @() })
    $procs = @(if ($RawData.RunningProcesses) { @($RawData.RunningProcesses) } else { @() })
    Add-DataSet -Context $Context -Name 'InstalledApplications' -Description 'Installed software from uninstall registry keys.' -Rows $apps -Visibility 'Internal' -SourceModule 'Applications' | Out-Null
    Add-DataSet -Context $Context -Name 'RunningProcesses' -Description 'Running processes with paths and (redacted) command lines.' -Rows $procs -Visibility 'Internal' -SourceModule 'Applications' | Out-Null
    # ApplicationFingerprints is deliberately NOT built here - see the ORDERING note at the
    # top of this file. It is built by Invoke-DiscoveryFingerprintSynthesis after all
    # collectors have run, so every matcher source dataset exists.
}

function Invoke-DiscoveryFingerprintSynthesis {
    <#
        Post-collection entry point. Runs fingerprint matching once every collector has
        contributed its datasets, then raises the follow-up questions the matches imply.
        Invoked by the orchestrator between the collection and synthesis phases.
    #>
    param([object]$Context)
    Write-SectionStatus -Title 'Application Fingerprints' -Status 'Matching' -Context $Context
    # Get-FingerprintMatches returns ,@($results) - the unary-comma idiom that stops an empty
    # array unrolling to $null. Assign it BARE: wrapping the call in @() would nest the
    # returned array one level deeper, giving a single "row" that is itself the whole array.
    $fps = $null
    try { $fps = Get-FingerprintMatches -Context $Context }
    catch { Write-Log -Level WARN -Message 'Application fingerprint matching failed.' -Module 'Applications' -Exception $_ -Context $Context }
    if ($null -eq $fps) { $fps = @() }
    Add-DataSet -Context $Context -Name 'ApplicationFingerprints' -Description 'Detected business/vendor applications via fingerprint matching (evaluated after all collectors).' -Rows @($fps) -Visibility 'Both' -SourceModule 'Applications' | Out-Null
    try {
        foreach ($fp in @($fps | Where-Object { $_.Confidence -in @('Confirmed','Likely') })) {
            if ($fp.SuggestedValidationQuestion) {
                Add-FollowUpQuestion -Context $Context -Category 'Applications' -Module 'Applications' -Audience 'Both' -Question $fp.SuggestedValidationQuestion | Out-Null
            }
        }
    } catch { }
    Write-Log -Level INFO -Message ("Application fingerprinting matched {0} application(s)." -f @($fps).Count) -Module 'Applications' -Context $Context
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Invoke-DiscoveryFingerprintSynthesis','Get-FingerprintMatches'
