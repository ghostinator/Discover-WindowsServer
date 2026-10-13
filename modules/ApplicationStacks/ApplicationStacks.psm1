<#
    ApplicationStacks.psm1 - evidence-based detection of multi-component application stacks
    (server engine, clients, drivers, DSNs, services, tasks, shares, SQL instances, IIS sites,
    processes) defined in config\application-stacks.json. Read-only: it only reads datasets
    the other collectors already produced.

    Produces: AppStackEvidence (one row per evidence hit, each with an EvidenceId) and
              AppStackSummary (one row per detected stack: roles present, server/client
              versions, host role, and the EvidenceIds behind every conclusion).

    Versions are REPORTED, never interpreted: a server/client version difference raises a
    "vendor validation required" flag, and identical versions are not called compatible.
    Fleet-wide correlation (which server hosts the engine, which RDS hosts carry clients,
    candidate source/target servers) is done by tools\Merge-FleetDiscoveryResults.ps1.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='ApplicationStacks'; DisplayName='Application Stacks (Sage, Actian, ...)'; Category='Applications'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Minimal'; CanRunAsSystem=$true
        ProducesDatasets=@('AppStackEvidence','AppStackSummary')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    if ($Context.Config -and $Context.Config.AppStacks -and @($Context.Config.AppStacks.stacks).Count -gt 0) {
        return [pscustomobject]@{ ModuleName='ApplicationStacks'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
    }
    [pscustomobject]@{ ModuleName='ApplicationStacks'; CanRun=$false; Status='NotApplicable'; Reason='config\application-stacks.json is missing or defines no stacks.'; Limitations=@() }
}

function Find-AppStackEvidence {
    <#
        Pure: evaluates stack definitions against datasets supplied by -GetRows (a scriptblock
        taking a dataset name and returning its rows). Returns one evidence row per matching
        dataset row per source, numbered EV-0001...
    #>
    param([object[]]$Stacks = @(), [Parameter(Mandatory)][scriptblock]$GetRows)
    $out = [System.Collections.Generic.List[object]]::new()
    $n = 0
    foreach ($st in $Stacks) {
        foreach ($c in @($st.components)) {
            foreach ($src in @($c.sources)) {
                $rows = @(& $GetRows ([string]$src.dataset))
                foreach ($r in $rows) {
                    $v = Get-RowValue -Row $r -Column ([string]$src.field)
                    if ($null -eq $v -or -not ([string]$v -match [string]$src.pattern)) { continue }
                    $n++
                    $ver = ''
                    if ($src.versionField) { $vv = Get-RowValue -Row $r -Column ([string]$src.versionField); if ($vv) { $ver = [string]$vv } }
                    # Item: the matched row's own name (DSN, service, task, instance, share, ...), so a
                    # DSN matched on ApplicationHint is still listed by its DSN name.
                    $item = ''
                    foreach ($f in @('DsnName','InstanceName','TaskName','Name','DisplayName','Path','ProviderName','LocalPort')) { $iv = Get-RowValue -Row $r -Column $f; if ($iv) { $item = [string]$iv; break } }
                    $out.Add([pscustomobject]@{
                        EvidenceId=('EV-{0:D4}' -f $n); Stack=[string]$st.name; Vendor=[string]$st.vendor; Component=[string]$c.component; Role=[string]$c.role
                        Version=$ver; Confidence=$(if ($src.confidence) { [string]$src.confidence } else { 'Possible' })
                        SourceDataset=[string]$src.dataset; SourceField=[string]$src.field; MatchedValue=[string]$v
                        Item=$item; Bitness=[string](Get-RowValue -Row $r -Column 'Bitness')
                    })
                }
            }
        }
    }
    return ,@($out)
}

function Get-AppStackSummary {
    <# Pure: one summary row per stack with evidence. Host role is derived from the strongest server/client evidence. #>
    param([object[]]$Evidence = @(), [object[]]$Stacks = @(), [bool]$IsRdsHost = $false)
    $rows = foreach ($st in $Stacks) {
        $ev = @($Evidence | Where-Object { $_.Stack -eq $st.name })
        if ($ev.Count -eq 0) { continue }
        $server = @($ev | Where-Object { $_.Role -eq 'Server' })
        $client = @($ev | Where-Object { $_.Role -eq 'Client' })
        $sv = @($server | Where-Object { $_.Version } | ForEach-Object { $_.Version } | Select-Object -Unique)
        $cv = @($client | Where-Object { $_.Version } | ForEach-Object { '{0} {1}' -f $_.MatchedValue, $_.Version } | Select-Object -Unique)
        $cvOnly = @($client | Where-Object { $_.Version -and $_.Component -notmatch '(?i)Aatrix' } | ForEach-Object { $_.Version } | Select-Object -Unique)
        $hostRole = if ($server.Count -and $client.Count) { 'Server and client' } elseif ($server.Count) { 'Server' } elseif ($client.Count) { 'Client' } else { 'Related components only' }
        $best = if (@($ev | Where-Object { $_.Role -in @('Server','Client') -and $_.Confidence -eq 'Confirmed' }).Count) { 'Confirmed' }
                elseif (@($ev | Where-Object { $_.Confidence -in @('Confirmed','Likely') }).Count) { 'Likely' } else { 'Possible' }
        $differ = [bool]($sv.Count -gt 0 -and $cvOnly.Count -gt 0 -and @($cvOnly | Where-Object { $sv -notcontains $_ }).Count -gt 0)
        [pscustomobject]@{
            Stack=[string]$st.name; Vendor=[string]$st.vendor; HostRole=$hostRole; Confidence=$best
            RolesPresent=((@($ev | ForEach-Object { $_.Role } | Select-Object -Unique)) -join ', ')
            ServerVersions=($sv -join ', '); ClientVersions=($cv -join '; ')
            LocalServerClientVersionsDiffer=$differ; MultipleServerVersions=[bool]($sv.Count -gt 1)
            IsRdsHost=$IsRdsHost; RdsHostWithClient=[bool]($IsRdsHost -and $client.Count -gt 0)
            EvidenceCount=$ev.Count; EvidenceIds=((@($ev | ForEach-Object { $_.EvidenceId })) -join ', ')
            ValidationNote='Version numbers are reported, not judged: confirm server/client compatibility with the vendor for these exact builds.'
        }
    }
    return ,@($rows)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $stacks = @($Context.Config.AppStacks.stacks)
    $getRows = { param($name) if ($name -and $Context.DataSets.Contains($name)) { @($Context.DataSets[$name].Rows) } else { @() } }
    $evidence = Find-AppStackEvidence -Stacks $stacks -GetRows $getRows
    $isRds = [bool]($Context.DataSets.Contains('RdsDiscovery') -and @($Context.DataSets['RdsDiscovery'].Rows).Count -gt 0)
    $summary = Get-AppStackSummary -Evidence $evidence -Stacks $stacks -IsRdsHost $isRds
    foreach ($s in $summary) {
        Add-DependencyEdge -Context $Context -SourceType 'Application stack' -SourceName $s.Stack -DependencyType 'HostsStackComponents' -Target $Context.ComputerName -Evidence ("{0} evidence record(s): {1}" -f $s.EvidenceCount, $s.EvidenceIds) -Confidence $s.Confidence -SourceDataset 'AppStackSummary' -ProjectImpact 'Vendor Dependency' -ValidationQuestion ("Which server hosts the {0} engine, which machines run its client, and has the vendor confirmed the target version?" -f $s.Stack) | Out-Null
    }
    return ,@{ AppStackEvidence=@($evidence); AppStackSummary=@($summary) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'AppStackEvidence' -Description 'Application-stack evidence records (component, role, version, source dataset/field, EvidenceId).' -Rows (& $get 'AppStackEvidence') -Visibility 'Internal' -SourceModule 'ApplicationStacks' | Out-Null
    Add-DataSet -Context $Context -Name 'AppStackSummary'  -Description 'Detected application stacks per server: host role, server/client versions, cited evidence.' -Rows (& $get 'AppStackSummary') -Visibility 'Both' -SourceModule 'ApplicationStacks' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('AppStackSummary')) {
            foreach ($s in @($Context.DataSets['AppStackSummary'].Rows)) {
                Add-FollowUpQuestion -Context $Context -Category 'Applications' -Module 'ApplicationStacks' -Audience 'Both' -Question ("{0} components were found on this server ({1}). Who supports it, which version is licensed, and has the vendor confirmed the server and client versions for the target environment?" -f $s.Stack, $s.HostRole) | Out-Null
            }
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Find-AppStackEvidence','Get-AppStackSummary'
