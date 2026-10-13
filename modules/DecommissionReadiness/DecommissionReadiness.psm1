<#
    DecommissionReadiness.psm1
    Synthesis module. Assesses "Can this server be shut off?" using all collected
    datasets. Produces the DecommissionReadiness and ScreamTestPlan datasets.

    IMPORTANT: Never states an absolute "safe to shut down" recommendation. Output
    is classified apparent dependency plus explicit validation needs.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'DecommissionReadiness'
        DisplayName               = 'Decommission Readiness Analysis'
        Category                  = 'Synthesis'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Minimal'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('DecommissionReadiness','ScreamTestPlan','DecommissionStates')
        ProducesRisks             = $false
        # $false, not a placeholder: this module's per-factor ValidationNeeded text and the
        # Scream Test Plan's WhoMustValidate/RecommendedPowerOffTestWindow fields live only in
        # the DecommissionReadiness/ScreamTestPlan dataset rows - unlike RiskEngine's
        # SuggestedValidationQuestion, nothing here is ever promoted into
        # Context.FollowUpQuestions (ClientInterviewPack.psm1 only reads Finding objects), so
        # no question this module "asks" ever actually reaches the client interview pack today.
        ProducesFollowUpQuestions = $false
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $false
        IsSynthesis               = $true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='DecommissionReadiness'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function New-ReadinessFactor {
    param([string]$Factor, [string]$Status, [string]$Confidence, [string]$Evidence, [string]$WhyItMatters, [string]$ValidationNeeded, [bool]$IsHighWeight = $false)
    [pscustomobject]@{
        Factor=$Factor; Status=$Status; Confidence=$Confidence; Evidence=$Evidence
        WhyItMatters=$WhyItMatters; ValidationNeeded=$ValidationNeeded; IsHighWeight=$IsHighWeight
    }
}

function Build-DecommissionReadiness {
    param([object]$Context)

    $ds = { param($n) ($Context.DataSets.Contains($n) -and @($Context.DataSets[$n].Rows).Count -gt 0) }
    $rolePresent = { param($p) (Test-RoleFeaturePresent -Context $Context -Pattern $p) }
    $fieldTrue = { param($n,$f) (Test-DatasetFieldTrue -Context $Context -Dataset $n -Field $f) }

    $factors = [System.Collections.Generic.List[object]]::new()

    $isDc = (& $rolePresent '(?i)AD-Domain|ADDS') -or (& $fieldTrue 'DomainContext' 'IsDomainController')
    $factors.Add((New-ReadinessFactor -Factor 'Active Directory Domain Controller' -Status ($(if($isDc){'Present'}else{'NotDetected'})) -Confidence ($(if($isDc){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($isDc){'AD DS role / DC context detected.'}else{'No DC role detected.'})) -WhyItMatters 'A DC cannot simply be powered off; roles must be transferred/demoted.' -ValidationNeeded ($(if($isDc){'Confirm redundancy and demotion plan.'}else{'Confirm this is not a hidden/secondary directory role.'})) -IsHighWeight $isDc))

    $dns = (& $rolePresent '(?i)^DNS$|DNS-Server')
    $factors.Add((New-ReadinessFactor -Factor 'DNS Server' -Status ($(if($dns){'Present'}else{'NotDetected'})) -Confidence ($(if($dns){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($dns){'DNS role detected.'}else{'No DNS role detected.'})) -WhyItMatters 'DNS is an infrastructure dependency for auth and app resolution.' -ValidationNeeded 'Confirm client/forwarder cutover plan.' -IsHighWeight $dns))

    $dhcp = (& $rolePresent '(?i)^DHCP$|DHCP-Server')
    $factors.Add((New-ReadinessFactor -Factor 'DHCP Server' -Status ($(if($dhcp){'Present'}else{'NotDetected'})) -Confidence ($(if($dhcp){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($dhcp){'DHCP role detected.'}else{'No DHCP role detected.'})) -WhyItMatters 'Scopes/reservations/options must be migrated and re-authorized.' -ValidationNeeded 'Confirm DHCP failover / migration plan.' -IsHighWeight $dhcp))

    $shares = (& $fieldTrue 'SmbShares' 'IsUserShare')
    $factors.Add((New-ReadinessFactor -Factor 'File shares' -Status ($(if($shares){'Present'}else{'NotDetected'})) -Confidence ($(if($shares){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($shares){'Non-administrative SMB shares detected.'}else{'No user shares detected.'})) -WhyItMatters 'Users/apps may depend on server name and UNC paths.' -ValidationNeeded 'Confirm who uses shares and how they are referenced.' -IsHighWeight $shares))

    $print = (& $fieldTrue 'Printers' 'Shared')
    $factors.Add((New-ReadinessFactor -Factor 'Print queues' -Status ($(if($print){'Present'}else{'NotDetected'})) -Confidence ($(if($print){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($print){'Shared printers detected.'}else{'No shared printers detected.'})) -WhyItMatters 'Print server retirement affects users and label workflows.' -ValidationNeeded 'Confirm printer mapping and driver availability.' -IsHighWeight $print))

    $sql = (& $ds 'SqlInstances') -or (& $ds 'OtherDatabaseEngines')
    $factors.Add((New-ReadinessFactor -Factor 'SQL / database' -Status ($(if($sql){'Present'}else{'NotDetected'})) -Confidence ($(if($sql){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($sql){'Database engine detected.'}else{'No database engine detected.'})) -WhyItMatters 'Databases usually back critical applications.' -ValidationNeeded 'Confirm which apps depend on the database(s).' -IsHighWeight $sql))

    $iis = (& $ds 'IisSites')
    $factors.Add((New-ReadinessFactor -Factor 'IIS / web apps' -Status ($(if($iis){'Present'}else{'NotDetected'})) -Confidence ($(if($iis){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($iis){'IIS sites detected.'}else{'No IIS sites detected.'})) -WhyItMatters 'Web apps carry binding/cert/host-header dependencies.' -ValidationNeeded 'Confirm web app owners and dependencies.' -IsHighWeight $iis))

    $hv = (& $ds 'HyperVVMs')
    $factors.Add((New-ReadinessFactor -Factor 'Hyper-V VMs' -Status ($(if($hv){'Present'}else{'NotDetected'})) -Confidence ($(if($hv){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($hv){'Guest VMs detected.'}else{'No guest VMs detected.'})) -WhyItMatters 'Host retirement affects all guest workloads.' -ValidationNeeded 'Confirm VM inventory, storage, and backup coverage.' -IsHighWeight $hv))

    $rds = (& $ds 'RdsDiscovery')
    $factors.Add((New-ReadinessFactor -Factor 'RDS' -Status ($(if($rds){'Present'}else{'NotDetected'})) -Confidence ($(if($rds){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($rds){'RDS role detected.'}else{'No RDS role detected.'})) -WhyItMatters 'RDS has licensing, cert, and profile dependencies.' -ValidationNeeded 'Confirm licensing and user session impact.' -IsHighWeight $rds))

    $nps = (& $ds 'NpsRadiusDiscovery')
    $factors.Add((New-ReadinessFactor -Factor 'NPS / RADIUS / MFA' -Status ($(if($nps){'Present'}else{'NotDetected'})) -Confidence ($(if($nps){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($nps){'NPS/RADIUS detected.'}else{'No NPS/RADIUS detected.'})) -WhyItMatters 'Authenticates network/VPN/Wi-Fi access; may integrate MFA.' -ValidationNeeded 'Confirm which devices authenticate here.' -IsHighWeight $nps))

    $ca = (& $rolePresent '(?i)AD-Certificate|ADCS')
    $factors.Add((New-ReadinessFactor -Factor 'CA / PKI' -Status ($(if($ca){'Present'}else{'NotDetected'})) -Confidence ($(if($ca){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($ca){'AD CS role detected.'}else{'No CA role detected.'})) -WhyItMatters 'A CA issues/validates certificates domain-wide.' -ValidationNeeded 'Confirm CA usage and migration/retirement plan.' -IsHighWeight $ca))

    $backup = (& $ds 'BackupDiscovery') -or (& $ds 'VendorAgents')
    $factors.Add((New-ReadinessFactor -Factor 'Backup / monitoring agents' -Status ($(if($backup){'Present'}else{'NotDetected'})) -Confidence ($(if($backup){'Likely'}else{'NotDetected'})) -Evidence ($(if($backup){'Backup/monitoring agent indicators detected.'}else{'No backup/monitoring agents detected.'})) -WhyItMatters 'Agents must be transitioned/cleaned up and recovery validated.' -ValidationNeeded 'Confirm backup currency and agent handling.' -IsHighWeight $false))

    $ports = (& $ds 'ListeningPorts')
    $factors.Add((New-ReadinessFactor -Factor 'Active listening ports' -Status ($(if($ports){'Present'}else{'NotDetected'})) -Confidence ($(if($ports){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($ports){("{0} listening port record(s)." -f @($Context.DataSets['ListeningPorts'].Rows).Count)}else{'No listening ports collected.'})) -WhyItMatters 'Listening ports imply other systems may connect in.' -ValidationNeeded 'Confirm which clients connect to this server.' -IsHighWeight $false))

    $tasks = (& $ds 'ScheduledTasks')
    $factors.Add((New-ReadinessFactor -Factor 'Scheduled tasks' -Status ($(if($tasks){'Present'}else{'NotDetected'})) -Confidence ($(if($tasks){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($tasks){'Scheduled tasks detected.'}else{'No scheduled tasks detected.'})) -WhyItMatters 'Automations may need recreation on a replacement server.' -ValidationNeeded 'Confirm which tasks are still required.' -IsHighWeight $false))

    $nonMs = (& $fieldTrue 'Services' 'IsNonMicrosoftAutoStart')
    $factors.Add((New-ReadinessFactor -Factor 'Non-Microsoft services' -Status ($(if($nonMs){'Present'}else{'NotDetected'})) -Confidence ($(if($nonMs){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($nonMs){'Non-Microsoft auto-start services detected.'}else{'No non-Microsoft auto-start services detected.'})) -WhyItMatters 'Indicates installed apps/agents in use.' -ValidationNeeded 'Confirm ownership of non-Microsoft services.' -IsHighWeight $false))

    $config = (& $ds 'ConfigDependencyHints')
    $factors.Add((New-ReadinessFactor -Factor 'Config file dependencies' -Status ($(if($config){'Present'}else{'Unknown'})) -Confidence ($(if($config){'Likely'}else{'Unknown'})) -Evidence ($(if($config){'Hardcoded dependencies found in config files.'}else{'Config scan not run or found nothing.'})) -WhyItMatters 'Hardcoded dependencies are common hidden blockers.' -ValidationNeeded 'Run/enable config dependency scan and validate hits.' -IsHighWeight $false))

    $lic = (& $ds 'Licensing')
    $factors.Add((New-ReadinessFactor -Factor 'License services / apps' -Status ($(if($lic){'Present'}else{'Unknown'})) -Confidence ($(if($lic){'Likely'}else{'Unknown'})) -Evidence ($(if($lic){'Licensing indicators detected.'}else{'No licensing indicators collected.'})) -WhyItMatters 'License managers/dongles may bind to this host.' -ValidationNeeded 'Confirm license reactivation requirements.' -IsHighWeight $false))

    # Migration-scoping factors added with the Exchange/SMTP, application-stack and Entra Connect collectors.
    $rows = { param($n) @(if ($Context.DataSets.Contains($n)) { @($Context.DataSets[$n].Rows) } else { @() }) }
    $exch = (& $ds 'ExchangeServer')
    $factors.Add((New-ReadinessFactor -Factor 'Exchange Server' -Status ($(if($exch){'Present'}else{'NotDetected'})) -Confidence ($(if($exch){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($exch){'Exchange installed (see ExchangeServer).'}else{'No Exchange install detected.'})) -WhyItMatters 'Exchange holds recipient management and often SMTP relay; it is removed by uninstall, never by power-off.' -ValidationNeeded 'Confirm mailbox/hybrid state and the supported uninstall path.' -IsHighWeight $exch))
    $smtp = @(& $rows 'SmtpRelayAssessment' | Select-Object -First 1)
    $smtpState = if ($smtp.Count -eq 0) { 'NotDetected' } elseif ($smtp[0].Status -eq 'Confirmed active SMTP client') { 'Present' } elseif ($smtp[0].Status -eq 'No SMTP usage found in available logs') { 'NotDetected' } else { 'Unknown' }
    $factors.Add((New-ReadinessFactor -Factor 'SMTP relay clients' -Status $smtpState -Confidence ($(if($smtp.Count){ if ($smtpState -eq 'Present') {'Confirmed'} else {'Unknown'} }else{'NotDetected'})) -Evidence ($(if($smtp.Count){ '{0} ({1} day(s) of evidence)' -f $smtp[0].Status, $smtp[0].EvidenceCoverageDays }else{'No SMTP role detected.'})) -WhyItMatters 'Devices and applications relaying through this server fail silently when it goes away; "no evidence" in a short window is not proof of no use.' -ValidationNeeded 'Identify every relay client; extend the observation window if evidence is thin.' -IsHighWeight ($smtpState -eq 'Present')))
    $stacks = @(& $rows 'AppStackSummary' | Where-Object { $_.HostRole -in @('Server','Server and client') })
    $factors.Add((New-ReadinessFactor -Factor 'Line-of-business application engine' -Status ($(if($stacks.Count){'Present'}else{'NotDetected'})) -Confidence ($(if($stacks.Count){ [string]$stacks[0].Confidence }else{'NotDetected'})) -Evidence ($(if($stacks.Count){ ($stacks | ForEach-Object { '{0} [{1}]' -f $_.Stack, $_.EvidenceIds }) -join '; ' }else{'No application-stack server components detected.'})) -WhyItMatters 'Client machines and RDS hosts point at the engine on this server.' -ValidationNeeded 'Confirm vendor-supported move/upgrade path and every client that connects.' -IsHighWeight ([bool]$stacks.Count)))
    $entra = @(& $rows 'EntraConnectDetail' | Where-Object { $_.SyncEngineInstalled })
    $factors.Add((New-ReadinessFactor -Factor 'Entra Connect sync' -Status ($(if($entra.Count){'Present'}else{'NotDetected'})) -Confidence ($(if($entra.Count){'Confirmed'}else{'NotDetected'})) -Evidence ($(if($entra.Count){ 'Staging mode: {0}; service {1}' -f $entra[0].StagingModeEnabled, $entra[0].SyncServiceState }else{'No Entra Connect sync engine detected.'})) -WhyItMatters 'Directory synchronisation for the whole tenant stops if the active sync server goes away.' -ValidationNeeded 'Stand up a staging server, switch over, then retire this one.' -IsHighWeight ([bool]$entra.Count)))

    $unknowns = (@($Context.Unknowns).Count -gt 0)
    $factors.Add((New-ReadinessFactor -Factor 'Unknowns that matter' -Status ($(if($unknowns){'Present'}else{'NotDetected'})) -Confidence 'Unknown' -Evidence ($(if($unknowns){("{0} unknown(s) recorded." -f @($Context.Unknowns).Count)}else{'No unknowns recorded.'})) -WhyItMatters 'Unresolved unknowns increase decommission risk.' -ValidationNeeded 'Resolve unknowns before any power-off decision.' -IsHighWeight $false))

    Add-DataSet -Context $Context -Name 'DecommissionReadiness' -Description 'Per-factor apparent-dependency assessment for decommission readiness.' -Rows @($factors) -Visibility 'Both' -SourceModule 'DecommissionReadiness' | Out-Null

    # Overall classification (indicator only, never absolute).
    $highWeightPresent = @($factors | Where-Object { $_.IsHighWeight -and $_.Status -eq 'Present' }).Count
    $anyPresent = @($factors | Where-Object { $_.Status -eq 'Present' }).Count
    $classification = if ($highWeightPresent -gt 0) { 'High apparent dependency' }
                      elseif ($anyPresent -ge 3) { 'Medium apparent dependency' }
                      elseif ($anyPresent -gt 0) { 'Low apparent dependency' }
                      else { 'Manual validation required' }
    $Context.Paths['_DecommissionClassification'] = $classification  # stash for report
    return $classification
}

function Build-DecommissionStates {
    <#
        Named decommissioning states with the evidence behind each. Several can apply at once; the
        last one always applies, because powering off is never the end of a decommission.
        'Ready for final dependency review' is the best state this tool ever reports - never "safe".
    #>
    param([object]$Context)
    $rows = { param($n) @(if ($Context.DataSets.Contains($n)) { @($Context.DataSets[$n].Rows) } else { @() }) }
    $vms = @(& $rows 'HyperVVMs'); $ext = @(& $rows 'ExternalHypervisorVMs')
    $running = @($vms | Where-Object { [string]$_.State -eq 'Running' }) + @($ext | Where-Object { $_.IsRunning })
    $off = @($vms | Where-Object { [string]$_.State -in @('Off','Saved','Paused') }) + @($ext | Where-Object { $_.IsPoweredOff })
    $files = @(& $rows 'HyperVUnattachedFiles') + @(& $rows 'ExternalHypervisorFiles')
    $snap = @($vms | Where-Object { $_.HasCheckpoints }) + @($ext | Where-Object { $_.HasSnapshots })
    $backup = @(& $rows 'BackupDiscovery') + @(& $rows 'VendorAgents' | Where-Object { $_.Category -eq 'Backup' })
    $monitor = @(& $rows 'VendorAgents' | Where-Object { $_.Category -in @('RMM','Monitoring') })
    $smtp = @(& $rows 'SmtpRelayAssessment' | Where-Object { $_.Status -eq 'Confirmed active SMTP client' })
    $conflict = @(& $rows 'HypervisorInventorySummary' | Where-Object { $_.CountConflicts -gt 0 })
    $highWeight = @(& $rows 'DecommissionReadiness' | Where-Object { $_.IsHighWeight -and $_.Status -eq 'Present' })
    $list = [System.Collections.Generic.List[object]]::new()
    $add = { param($state, $applies, $evidence, $next) $list.Add([pscustomobject]@{ State=$state; Applies=[bool]$applies; Evidence=$evidence; NextStep=$next }) }
    & $add 'Active VMs remain' ($running.Count -gt 0) ("{0} running VM(s)" -f $running.Count) 'Migrate or retire every running VM before the host is touched.'
    & $add 'Powered-off VMs require disposition' ($off.Count -gt 0) ("{0} powered-off/saved VM(s)" -f $off.Count) 'Get a keep/archive/delete decision for each one in writing.'
    & $add 'Datastore contents require review' (($files.Count + $snap.Count) -gt 0) ("{0} unattached/ISO file(s), {1} VM(s) with checkpoints/snapshots" -f $files.Count, $snap.Count) 'Review leftover disks, ISOs and snapshots; nothing is deleted by this tool.'
    & $add 'Hypervisor inventory conflict' ($conflict.Count -gt 0) ($(if ($conflict.Count) { [string]$conflict[0].CountConflictDetail } else { 'No source disagreement' })) 'Reconcile RMM-reported VM counts with the hypervisor before scoping.'
    & $add 'Backup dependency remains' ($backup.Count -gt 0) ((@($backup | ForEach-Object { if ($_.Product) { $_.Product } else { $_.AgentName } }) | Select-Object -Unique) -join ', ') 'Retire or retarget backup jobs/agents and keep restore capability for the retention period.'
    & $add 'Monitoring dependency remains' ($monitor.Count -gt 0) ((@($monitor | ForEach-Object { $_.AgentName }) | Select-Object -Unique) -join ', ') 'Remove the device from RMM/monitoring after retirement so alerts do not go stale.'
    & $add 'SMTP relay dependency remains' ($smtp.Count -gt 0) ($(if ($smtp.Count) { '{0} confirmed client(s)' -f $smtp[0].ConfirmedClients } else { '' })) 'Move every relay client to another SMTP path.'
    $blocked = @($list | Where-Object { $_.Applies }).Count -gt 0 -or $highWeight.Count -gt 0
    & $add 'Ready for final dependency review' (-not $blocked) ($(if ($blocked) { 'Blocking states or high-weight roles are present.' } else { 'No blocking state detected by this run.' })) 'Run the scream-test plan and obtain owner sign-off; this is not a "safe to power off" statement.'
    & $add 'Physical removal or data destruction requires separate approval' $true 'Always applies.' 'Disk wiping, certificate of destruction and hardware disposal are separate, approved steps.'
    Add-DataSet -Context $Context -Name 'DecommissionStates' -Description 'Named decommissioning states (multiple can apply) with evidence and next step.' -Rows @($list) -Visibility 'Both' -SourceModule 'DecommissionReadiness' | Out-Null
}

function Build-ScreamTestPlan {
    param([object]$Context)
    $functions = @(Get-LikelyServerFunctions -Context $Context)
    if ($functions.Count -eq 0) { $functions = @('Undetermined role') }
    $rows = foreach ($fn in $functions) {
        [pscustomobject]@{
            System                        = $Context.ComputerName
            DetectedFunction              = $fn
            ReadinessConcern              = 'Dependent clients/applications may rely on this function without documentation.'
            RecommendedPowerOffTestWindow = '<TBD - agree an approved low-impact maintenance window with the client>'
            RollbackRequirement           = 'Validated, recent backup or documented ability to power the server back on quickly.'
            WhoMustValidate               = '<Client business owner + application/vendor contact for this function>'
            WhatToMonitor                 = 'User reports, application/service availability, authentication, dependent connections, and error logs.'
            WhatWouldConstituteAScream    = 'Any user or system reporting loss of access, failed logins, broken app function, or missing data tied to this server.'
            MinimumEvidenceBeforeRetirement = 'No screams during the agreed observation window and confirmed backup/rollback capability.'
            Confidence                    = 'Possible'
        }
    }
    Add-DataSet -Context $Context -Name 'ScreamTestPlan' -Description 'Structured power-off (scream) test plan per detected function. Uses placeholders, not real windows.' -Rows @($rows) -Visibility 'Both' -SourceModule 'DecommissionReadiness' | Out-Null
}

function Invoke-DiscoverySynthesis {
    param([object]$Context)
    Write-SectionStatus -Title 'Decommission Readiness' -Status 'Analyzing' -Context $Context
    try { Build-DecommissionReadiness -Context $Context | Out-Null } catch { Write-Log -Level WARN -Message 'Decommission readiness build failed.' -Module 'DecommissionReadiness' -Exception $_ -Context $Context }
    try { Build-DecommissionStates -Context $Context } catch { Write-Log -Level WARN -Message 'Decommission states build failed.' -Module 'DecommissionReadiness' -Exception $_ -Context $Context }
    try { Build-ScreamTestPlan -Context $Context } catch { Write-Log -Level WARN -Message 'Scream test plan build failed.' -Module 'DecommissionReadiness' -Exception $_ -Context $Context }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis','Build-DecommissionReadiness','Build-ScreamTestPlan','Build-DecommissionStates'
