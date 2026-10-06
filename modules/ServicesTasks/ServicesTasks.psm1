<#
    ServicesTasks.psm1 - Windows services and scheduled tasks (read-only).
    Produces: Services, ServiceDependencies, ScheduledTasks. Adds dependency edges.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='ServicesTasks'; DisplayName='Services and Scheduled Tasks'; Category='System'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('Services','ServiceDependencies','ScheduledTasks')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='ServicesTasks'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Get-ServiceExePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return '' }
    $p = $PathName.Trim()
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 1) { return $p.Substring(1, $end - 1) }
    }
    # Unquoted: take up to the first token ending in .exe (case-insensitive), else first whitespace.
    $m = [regex]::Match($p, '^(.*?\.exe)\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $sp = $p.IndexOf(' ')
    if ($sp -gt 0) { return $p.Substring(0, $sp) }
    return $p
}

function Test-DomainAccount {
    param([string]$Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return $false }
    $a = $Account.Trim()
    if ($a -notmatch '^[^\\@]+\\[^\\@]+$') {
        # Could be UPN form user@domain
        if ($a -match '^[^\\@]+@[^\\@]+$') { return $true }
        return $false
    }
    $domain = ($a -split '\\')[0]
    $wellKnown = @('NT AUTHORITY','NT SERVICE','BUILTIN','.', $env:COMPUTERNAME, 'LOCALSYSTEM','APPLICATION')
    if ($wellKnown -contains $domain) { return $false }
    return $true
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $services = [System.Collections.Generic.List[object]]::new()
    $deps = [System.Collections.Generic.List[object]]::new()
    $tasks = [System.Collections.Generic.List[object]]::new()
    $winRoot = $env:SystemRoot
    if (-not $winRoot) { $winRoot = 'C:\Windows' }

    # ---- Services ----
    try {
        $svc = Invoke-CimSafe -ClassName 'Win32_Service'
        foreach ($s in $svc) {
            try {
                $exe = Get-ServiceExePath -PathName $s.PathName
                $exists = $false
                if ($exe) { try { $exists = Test-Path -LiteralPath $exe } catch { $exists = $false } }
                $unquoted = $false
                if ($s.PathName -and ($s.PathName.Trim() -notmatch '^\s*"') -and ($exe -match '\s') ) { $unquoted = $true }
                $underWin = ($exe -and $exe.ToLowerInvariant().StartsWith($winRoot.ToLowerInvariant()))
                $auto = ($s.StartMode -eq 'Auto' -or $s.StartMode -eq 'Automatic')
                $nonMsAuto = ($auto -and $exe -and -not $underWin)
                $inProfile = ([bool]($exe -match '(?i)\\Users\\'))
                $onNetwork = ([bool]($exe -match '^\\\\'))
                $services.Add([pscustomobject]@{
                    Name=$s.Name; DisplayName=$s.DisplayName; Status=$s.State; StartMode=$s.StartMode
                    StartName=$s.StartName; PathName=(Redact-SensitiveValue -InputString $s.PathName -Context $Context)
                    Description=$s.Description; ServiceType=$s.ServiceType; ProcessId=$s.ProcessId
                    ExecutablePath=$exe; PathExists=$exists; UnquotedPathWithSpaces=$unquoted; IsNonMicrosoftAutoStart=$nonMsAuto
                    RunsFromUserProfile=$inProfile; RunsFromNetworkPath=$onNetwork
                })
            } catch { }
        }
    } catch { Add-Limitation -Context $Context -Module 'ServicesTasks' -Message 'Service enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Service dependencies (best-effort via Get-Service) ----
    try {
        foreach ($g in (Get-Service -ErrorAction SilentlyContinue)) {
            try {
                foreach ($d in @($g.ServicesDependedOn)) { $deps.Add([pscustomobject]@{ Service=$g.Name; DependsOn=$d.Name; Direction='DependsOn' }) }
            } catch { }
        }
    } catch { }

    # ---- Scheduled tasks ----
    if (Get-CommandAvailable -Name 'Get-ScheduledTask') {
        try {
            foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                try {
                    $info = $null
                    try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue } catch { }
                    $actionsText = ''
                    try {
                        $parts = foreach ($a in @($t.Actions)) { (@($a.Execute, $a.Arguments) | Where-Object { $_ }) -join ' ' }
                        $actionsText = ($parts -join ' | ')
                    } catch { }
                    $actionsText = Redact-SensitiveValue -InputString $actionsText -Context $Context
                    $principal = ''
                    try { $principal = if ($t.Principal.UserId) { $t.Principal.UserId } else { $t.Principal.GroupId } } catch { }
                    $ltr = if ($info) { $info.LastTaskResult } else { $null }
                    $failed = $false
                    if ($null -ne $ltr) { $failed = (($ltr -ne 0) -and ($ltr -ne 267011) -and ($ltr -ne 267009)) }
                    $tasks.Add([pscustomobject]@{
                        TaskName=$t.TaskName; TaskPath=$t.TaskPath; State=[string]$t.State; Principal=$principal
                        RunLevel=[string]$t.Principal.RunLevel; ActionsText=$actionsText
                        LastTaskResult=$ltr; LastRunTime=(Normalize-DateTime ($info.LastRunTime)); NextRunTime=(Normalize-DateTime ($info.NextRunTime))
                        UsesUncPath=([bool]($actionsText -match '\\\\[^\\]')); LastRunFailed=$failed
                        RunsAsDomainAccount=(Test-DomainAccount -Account $principal)
                        RunsScript=([bool]($actionsText -match '(?i)\.(ps1|bat|cmd|vbs|py|js|jar)\b|powershell|cscript|wscript|python|java')); PerformsBackupExportImport=([bool]($actionsText -match '(?i)backup|export|import|robocopy|\bbcp\b|sqlcmd|\bdump\b'))
                    })
                } catch { }
            }
        } catch { Add-Limitation -Context $Context -Module 'ServicesTasks' -Message 'Scheduled task enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    } else {
        # Fallback: schtasks.exe (READ-ONLY query)
        try {
            $r = Invoke-CommandLineSafe -FilePath 'schtasks.exe' -Arguments @('/query','/fo','CSV','/v') -TimeoutSeconds 90
            if ($r.Succeeded -and $r.StdOut) {
                $csv = $r.StdOut | ConvertFrom-Csv
                foreach ($row in $csv) {
                    if ($row.TaskName -and $row.TaskName -ne 'TaskName') {
                        $actionsText = Redact-SensitiveValue -InputString ([string]$row.'Task To Run') -Context $Context
                        $principal = [string]$row.'Run As User'
                        $tasks.Add([pscustomobject]@{
                            TaskName=$row.TaskName; TaskPath=''; State=[string]$row.Status; Principal=$principal
                            RunLevel=''; ActionsText=$actionsText; LastTaskResult=$row.'Last Result'
                            LastRunTime=$row.'Last Run Time'; NextRunTime=$row.'Next Run Time'
                            UsesUncPath=([bool]($actionsText -match '\\\\[^\\]')); LastRunFailed=$false
                            RunsAsDomainAccount=(Test-DomainAccount -Account $principal)
                            RunsScript=([bool]($actionsText -match '(?i)\.(ps1|bat|cmd|vbs|py|js|jar)\b|powershell|cscript|wscript|python|java')); PerformsBackupExportImport=([bool]($actionsText -match '(?i)backup|export|import|robocopy|\bbcp\b|sqlcmd|\bdump\b'))
                        })
                    }
                }
            } else { Add-Limitation -Context $Context -Module 'ServicesTasks' -Message 'schtasks fallback did not return data.' | Out-Null }
        } catch { Add-Limitation -Context $Context -Module 'ServicesTasks' -Message 'Scheduled task fallback failed.' -Reason $_.Exception.Message | Out-Null }
    }

    return ,@{ Services=@($services); ServiceDependencies=@($deps); ScheduledTasks=@($tasks) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $svc = @(if ($RawData.Services) { @($RawData.Services) } else { @() })
    $deps = @(if ($RawData.ServiceDependencies) { @($RawData.ServiceDependencies) } else { @() })
    $tasks = @(if ($RawData.ScheduledTasks) { @($RawData.ScheduledTasks) } else { @() })
    Add-DataSet -Context $Context -Name 'Services' -Description 'Windows services with logon accounts, paths, and heuristics.' -Rows $svc -Visibility 'Internal' -SourceModule 'ServicesTasks' | Out-Null
    Add-DataSet -Context $Context -Name 'ServiceDependencies' -Description 'Service dependency relationships.' -Rows $deps -Visibility 'Internal' -SourceModule 'ServicesTasks' | Out-Null
    Add-DataSet -Context $Context -Name 'ScheduledTasks' -Description 'Scheduled tasks with principals, actions (redacted), and results.' -Rows $tasks -Visibility 'Internal' -SourceModule 'ServicesTasks' | Out-Null

    # Dependency edges
    foreach ($s in $svc) {
        try {
            if (Test-DomainAccount -Account $s.StartName) {
                Add-DependencyEdge -Context $Context -SourceType 'Service' -SourceName $s.Name -DependencyType 'RunsAs' -Target $s.StartName -Evidence 'Service logon account' -Confidence 'Confirmed' -SourceDataset 'Services' -ProjectImpact 'Cutover Complexity' -ValidationQuestion ("Who owns the service account {0}?" -f $s.StartName) | Out-Null
            }
        } catch { }
    }
    foreach ($t in $tasks) {
        try {
            if ($t.UsesUncPath) {
                Add-DependencyEdge -Context $Context -SourceType 'ScheduledTask' -SourceName $t.TaskName -DependencyType 'UsesPath' -Target 'UNC path' -Evidence $t.ActionsText -Confidence 'Confirmed' -SourceDataset 'ScheduledTasks' -ProjectImpact 'Data Migration' -ValidationQuestion 'Does this UNC path dependency still exist after migration?' | Out-Null
            }
        } catch { }
    }
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    # RiskEngine covers most; add one summarizing question if domain-account services exist.
    try {
        if ($Context.DataSets.Contains('Services')) {
            $domSvc = @($Context.DataSets['Services'].Rows | Where-Object { Test-DomainAccount -Account $_.StartName })
            if ($domSvc.Count -gt 0) {
                Add-FollowUpQuestion -Context $Context -Category 'Service accounts' -Module 'ServicesTasks' -Audience 'Both' -Question 'For each service running under a domain account, who owns the account and where is its password/gMSA configuration documented?' | Out-Null
            }
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-ServiceExePath','Test-DomainAccount'
