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
        ProducesDatasets          = @('DecommissionReadiness','ScreamTestPlan')
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
    try { Build-ScreamTestPlan -Context $Context } catch { Write-Log -Level WARN -Message 'Scream test plan build failed.' -Module 'DecommissionReadiness' -Exception $_ -Context $Context }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis','Build-DecommissionReadiness','Build-ScreamTestPlan'
