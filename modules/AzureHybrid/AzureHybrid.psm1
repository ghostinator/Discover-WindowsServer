<#
    AzureHybrid.psm1 - hybrid identity and cloud-attachment discovery (read-only).

    Produces: HybridIdentity, AzureAttachment.

    Why this module exists: "is this server doing anything for Microsoft 365?" is a
    question every migration, refresh and decommission conversation reaches within
    about ten minutes, and the toolkit had no answer. Entra Connect (Azure AD Connect)
    in particular is the classic decommission landmine - it looks like an ordinary
    member server, it holds a role nothing else holds, and turning it off stops
    directory synchronisation for the whole tenant with no error anyone notices until
    password changes stop replicating.

    Detects: Entra Connect / Azure AD Connect (incl. the lightweight sync agents),
    AD FS, Entra Connect Health, Azure Arc, Azure App Proxy connectors, Entra hybrid
    join state via 'dsregcmd /status', and Azure/M365 endpoints already recorded by
    other collectors.

    Reads only. dsregcmd is invoked with /status, which is a read verb. No tenant IDs,
    device certificates, or tokens are exported - only whether a state is configured.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='AzureHybrid'; DisplayName='Hybrid Identity & Cloud Attachment'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('HybridIdentity','AzureAttachment')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='AzureHybrid'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Test-AhEvidence {
    <#
        Looks for a component across the Services and InstalledApplications datasets
        that earlier collectors already produced, plus an optional registry path.
        Returns @{ Found; Evidence; Running } so every row carries why it fired and
        whether the strongest evidence was an actually-running service, as opposed to
        a role/feature that was installed (service present, registry key present) but
        never configured into a working instance - a real and common gap (e.g. AD FS
        installed for lab/test coverage with no farm ever created).
    #>
    param([object]$Context, [string]$Pattern, [string[]]$RegistryPaths = @())
    $ev = @()
    $running = $false
    try {
        if ($Context.DataSets.Contains('Services')) {
            $hit = @($Context.DataSets['Services'].Rows | Where-Object { $_.DisplayName -match $Pattern -or $_.Name -match $Pattern })
            if ($hit.Count -gt 0) {
                $ev += ('service:' + $hit[0].Name)
                $running = [bool]($hit | Where-Object { [string]$_.Status -eq 'Running' })
            }
        }
        if ($Context.DataSets.Contains('InstalledApplications')) {
            $hit = @($Context.DataSets['InstalledApplications'].Rows | Where-Object { $_.DisplayName -match $Pattern })
            if ($hit.Count -gt 0) { $ev += ('app:' + $hit[0].DisplayName) }
        }
    } catch { }
    foreach ($rp in $RegistryPaths) {
        if ($rp -and (Test-RegistryPathSafe $rp)) { $ev += ('registry:' + $rp) }
    }
    return @{ Found = [bool]($ev.Count -gt 0); Evidence = ($ev -join '; '); Running = $running }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)

    $hybrid = [System.Collections.Generic.List[object]]::new()
    $attach = [System.Collections.Generic.List[object]]::new()

    $catalog = @(
        @{ Name='Entra Connect (Azure AD Connect)'; Role='Directory synchronisation'
           Pattern='(?i)Microsoft Azure AD Sync|ADSync|Azure AD Connect|Entra Connect'
           Reg=@('HKLM:\SOFTWARE\Microsoft\Azure AD Connect','HKLM:\SYSTEM\CurrentControlSet\Services\ADSync')
           WhyItMatters='This server synchronises on-premises identities to the cloud tenant. Only one active sync server exists per tenant; stopping it silently stops synchronisation, including password writeback and hash sync.'
           Question='Is this the active Entra Connect / Azure AD Connect server for the tenant, is staging mode in use, and where does synchronisation move to?' }

        @{ Name='Entra Connect Health agent'; Role='Monitoring'
           Pattern='(?i)Azure AD Connect Health|AzureADConnectHealth'
           Reg=@(); WhyItMatters='Health reporting for sync/AD FS; re-registers against the tenant when the host changes.'
           Question='Who owns the Entra Connect Health registration for this server?' }

        @{ Name='Entra Connect cloud sync / provisioning agent'; Role='Directory synchronisation'
           Pattern='(?i)Microsoft Azure AD Connect Provisioning Agent|AADConnectProvisioningAgent'
           Reg=@(); WhyItMatters='Lightweight cloud sync agent; the same tenant-wide dependency as Entra Connect but far easier to overlook.'
           Question='Is cloud sync provisioning running from this server, and is there a second agent for redundancy?' }

        @{ Name='Active Directory Federation Services (AD FS)'; Role='Federated authentication'
           Pattern='(?i)^adfssrv$|Active Directory Federation Services'
           Reg=@('HKLM:\SOFTWARE\Microsoft\ADFS')
           WhyItMatters='AD FS authenticates federated sign-in. Retiring or moving it breaks sign-in for every relying party, and its token-signing certificates and farm configuration must move with it.'
           Question='Which applications rely on this AD FS farm, and is a migration to managed authentication planned?' }

        @{ Name='Entra Application Proxy connector'; Role='Published application access'
           Pattern='(?i)Microsoft AAD Application Proxy Connector|WAPCSvc|ApplicationProxyConnector'
           Reg=@(); WhyItMatters='Publishes internal applications to the internet through the tenant; removing the connector takes those applications offline externally.'
           Question='Which internal applications are published through the Application Proxy connector on this server?' }

        @{ Name='Web Application Proxy (WAP)'; Role='Reverse proxy'
           Pattern='(?i)Web Application Proxy|appproxysvc'
           Reg=@(); WhyItMatters='Edge reverse proxy, usually paired with AD FS; part of the same authentication path.'
           Question='Is this WAP server paired with AD FS, and does it sit in a DMZ with firewall rules that must be reproduced?' }

        @{ Name='Azure Arc connected machine agent'; Role='Cloud management'
           Pattern='(?i)Azure Connected Machine|himds|GCArcService'
           Reg=@('HKLM:\SOFTWARE\Microsoft\AzureConnectedMachineAgent')
           WhyItMatters='The server is projected into Azure for policy, monitoring or update management; the Arc resource does not follow a rebuild automatically.'
           Question='What is this server enrolled in Azure Arc for, and who owns the Arc resource?' }

        @{ Name='Microsoft Entra Private Access / Global Secure Access connector'; Role='Network access'
           Pattern='(?i)Global Secure Access|Microsoft Entra Private Access'
           Reg=@(); WhyItMatters='Network access broker; removing it cuts the access path it brokers.'
           Question='Which access paths depend on this connector?' }

        @{ Name='Microsoft 365 / Exchange hybrid components'; Role='Mail hybrid'
           Pattern='(?i)Microsoft Exchange|Hybrid Configuration'
           Reg=@('HKLM:\SOFTWARE\Microsoft\ExchangeServer')
           WhyItMatters='An on-premises Exchange presence, even a management-only hybrid server, holds recipient management authority and cannot simply be powered off.'
           Question='Is Exchange here a full mailbox server or a hybrid management server, and what is the decommission plan?' }
    )

    foreach ($c in $catalog) {
        $res = Test-AhEvidence -Context $Context -Pattern $c.Pattern -RegistryPaths $c.Reg
        if (-not $res.Found) { continue }

        # A service that's merely present (installed but stopped/disabled, or evidence limited
        # to a registry key/app entry) means the role exists on the box, not that it's an active,
        # configured instance - those are two very different things to hand a client as fact.
        $confidence = if ($res.Running) { 'Likely' } else { 'Possible' }

        $hybrid.Add([pscustomobject]@{
            Component    = $c.Name
            Role         = $c.Role
            Evidence     = $res.Evidence
            Confidence   = $confidence
            WhyItMatters = $c.WhyItMatters
            ValidationQuestion = $c.Question
        })

        Add-DependencyEdge -Context $Context -SourceType 'HybridIdentity' -SourceName $c.Name `
            -DependencyType 'ConnectsTo' -Target 'Microsoft cloud tenant' -Evidence $res.Evidence `
            -Confidence $confidence -SourceDataset 'HybridIdentity' -ProjectImpact 'Architecture Decision' `
            -ValidationQuestion $c.Question | Out-Null

        Add-Unknown -Context $Context -Unknown ("{0} is present on this server; the tenant-side configuration behind it is not discoverable locally." -f $c.Name) `
            -WhyItMatters $c.WhyItMatters -Module 'AzureHybrid' -RecommendedValidationQuestion $c.Question | Out-Null
    }

    # ---- Device join state via dsregcmd (read verb) -------------------------
    # Booleans only. The tenant ID, device ID and certificate thumbprints that
    # dsregcmd also prints are deliberately not collected - join STATE is the
    # scoping fact; the identifiers are tenant data with no scoping value.
    try {
        if (Get-CommandAvailable -Name 'dsregcmd.exe') {
            $r = Invoke-CommandLineSafe -FilePath 'dsregcmd.exe' -Arguments @('/status') -TimeoutSeconds 45
            if ($r.Succeeded -and $r.StdOut) {
                $get = {
                    param($label)
                    $m = [regex]::Match($r.StdOut, ('(?im)^\s*' + [regex]::Escape($label) + '\s*:\s*(\S+)\s*$'))
                    if ($m.Success) { return $m.Groups[1].Value } else { return '' }
                }
                $attach.Add([pscustomobject]@{
                    Item='Entra joined';        Value=(& $get 'AzureAdJoined');    Evidence='dsregcmd /status'
                    WhyItMatters='Indicates the device identity lives in the cloud tenant rather than only in AD.' })
                $attach.Add([pscustomobject]@{
                    Item='Domain joined';       Value=(& $get 'DomainJoined');     Evidence='dsregcmd /status'
                    WhyItMatters='Combined with Entra joined, distinguishes hybrid join from pure on-premises.' })
                $attach.Add([pscustomobject]@{
                    Item='Enterprise joined';   Value=(& $get 'EnterpriseJoined'); Evidence='dsregcmd /status'
                    WhyItMatters='On-premises DRS join, relevant to conditional access paths.' })
                $attach.Add([pscustomobject]@{
                    Item='Workplace joined';    Value=(& $get 'WorkplaceJoined');  Evidence='dsregcmd /status'
                    WhyItMatters='Registered rather than joined; affects how policy applies.' })
            } else {
                Add-Limitation -Context $Context -Module 'AzureHybrid' -Message 'dsregcmd /status returned no usable output.' | Out-Null
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'AzureHybrid' -Message 'dsregcmd query failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Cloud endpoints already seen by the config scan -------------------
    # Reuses ConfigDependencyHints rather than rescanning: if a config file points at
    # a Microsoft cloud endpoint, that is a cloud attachment worth surfacing here.
    try {
        if ($Context.DataSets.Contains('ConfigDependencyHints')) {
            $cloudRx = '(?i)(login\.microsoftonline\.com|\.onmicrosoft\.com|graph\.microsoft\.com|\.blob\.core\.windows\.net|\.azurewebsites\.net|\.database\.windows\.net|outlook\.office365\.com)'
            $hits = @($Context.DataSets['ConfigDependencyHints'].Rows | Where-Object { $_.RedactedLine -match $cloudRx })
            if ($hits.Count -gt 0) {
                $attach.Add([pscustomobject]@{
                    Item='Microsoft cloud endpoints referenced in configuration files'
                    Value=("{0} configuration line(s) across {1} file(s)" -f $hits.Count, (@($hits | Select-Object -ExpandProperty FilePath -Unique)).Count)
                    Evidence='ConfigDependencyHints'
                    WhyItMatters='An application on this server talks to a cloud service directly; that integration has to be re-pointed or re-authorised after a move.'
                })
            }
        }
    } catch { }

    return ,@{ HybridIdentity=@($hybrid); AzureAttachment=@($attach) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'HybridIdentity'  -Description 'Hybrid identity components (Entra Connect, AD FS, connectors).' -Rows (& $get 'HybridIdentity')  -Visibility 'Both'     -SourceModule 'AzureHybrid' | Out-Null
    Add-DataSet -Context $Context -Name 'AzureAttachment' -Description 'Cloud join state and cloud endpoint attachment indicators.'     -Rows (& $get 'AzureAttachment') -Visibility 'Internal' -SourceModule 'AzureHybrid' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('HybridIdentity') -and @($Context.DataSets['HybridIdentity'].Rows).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'Critical systems' -Module 'AzureHybrid' -Audience 'Both' `
                -Question 'This server appears to connect your on-premises environment to Microsoft 365 / Azure. Who administers the cloud tenant, and has anyone confirmed what stops working if this server is changed or retired?' | Out-Null
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Test-AhEvidence'
