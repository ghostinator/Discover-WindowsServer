<#
    VendorAgents.psm1 - vendor / RMM / EDR / backup / monitoring / hardware agents (read-only).
    Produces: VendorAgents. NEVER collects SNMP community strings.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='VendorAgents'; DisplayName='Vendor / RMM / Security Agents'; Category='Vendor'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('VendorAgents')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='VendorAgents'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $rows=[System.Collections.Generic.List[object]]::new()
    $catalog = @(
        @{ Name='Datto RMM'; Cat='RMM'; Pattern='(?i)Datto RMM|CentraStage|AEM Agent' },
        @{ Name='ConnectWise Automate'; Cat='RMM'; Pattern='(?i)ConnectWise Automate|LabTech' },
        @{ Name='ConnectWise ScreenConnect/Control'; Cat='RemoteAccess'; Pattern='(?i)ScreenConnect|ConnectWise Control' },
        @{ Name='Auvik'; Cat='Network'; Pattern='(?i)Auvik' },
        @{ Name='Huntress'; Cat='EDR/AV'; Pattern='(?i)Huntress' },
        @{ Name='SentinelOne'; Cat='EDR/AV'; Pattern='(?i)SentinelOne|Sentinel Agent' },
        @{ Name='CrowdStrike Falcon'; Cat='EDR/AV'; Pattern='(?i)CrowdStrike|CSFalcon|CSAgent' },
        @{ Name='Sophos'; Cat='EDR/AV'; Pattern='(?i)Sophos' },
        @{ Name='Bitdefender'; Cat='EDR/AV'; Pattern='(?i)Bitdefender' },
        @{ Name='Webroot'; Cat='EDR/AV'; Pattern='(?i)Webroot' },
        @{ Name='Defender for Endpoint'; Cat='EDR/AV'; Pattern='(?i)Windows Defender Advanced Threat|Sense$|MsSense' },
        @{ Name='Veeam'; Cat='Backup'; Pattern='(?i)Veeam' },
        @{ Name='Acronis'; Cat='Backup'; Pattern='(?i)Acronis' },
        @{ Name='Azure Arc'; Cat='CloudMgmt'; Pattern='(?i)Azure Connected Machine|himds|GCArcService' },
        @{ Name='Azure Monitor Agent'; Cat='Monitoring'; Pattern='(?i)Azure Monitor Agent|AzureMonitorAgent' },
        @{ Name='Log Analytics / MMA'; Cat='Monitoring'; Pattern='(?i)Microsoft Monitoring Agent|HealthService' },
        @{ Name='Windows Admin Center'; Cat='CloudMgmt'; Pattern='(?i)Windows Admin Center|ServerManagementGateway' },
        @{ Name='SNMP Service'; Cat='Network'; Pattern='(?i)^SNMP$|SNMP Service' },
        @{ Name='APC PowerChute'; Cat='UPS'; Pattern='(?i)PowerChute|APC' },
        @{ Name='Eaton IPP'; Cat='UPS'; Pattern='(?i)Eaton|Intelligent Power' },
        @{ Name='Dell OpenManage'; Cat='Hardware'; Pattern='(?i)OpenManage|Dell EMC' },
        @{ Name='HPE Management'; Cat='Hardware'; Pattern='(?i)HP(E)? (Insight|System|iLO|Smart)' },
        @{ Name='Lenovo XClarity/OneCLI'; Cat='Hardware'; Pattern='(?i)XClarity|OneCLI|ThinkSystem' }
    )
    try {
        $svcRows = @(if ($Context.DataSets.Contains('Services')) { @($Context.DataSets['Services'].Rows) } else { @() })
        $appRows = @(if ($Context.DataSets.Contains('InstalledApplications')) { @($Context.DataSets['InstalledApplications'].Rows) } else { @() })
        foreach ($c in $catalog) {
            $ev=@()
            $sh = @($svcRows | Where-Object { $_.DisplayName -match $c.Pattern -or $_.Name -match $c.Pattern })
            $ah = @($appRows | Where-Object { $_.DisplayName -match $c.Pattern })
            if ($sh.Count) { $ev += ('service:' + $sh[0].Name) }
            if ($ah.Count) { $ev += ('app:' + $ah[0].DisplayName) }
            if ($ev.Count) {
                $rows.Add([pscustomobject]@{ AgentName=$c.Name; Category=$c.Cat; Evidence=($ev -join '; '); Confidence='Likely' })
                if ($c.Name -eq 'SNMP Service') { Add-Unknown -Context $Context -Unknown 'SNMP is configured; community string is intentionally not collected.' -WhyItMatters 'SNMP community/monitoring config must be re-coordinated on migration.' -Module 'VendorAgents' | Out-Null }
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'VendorAgents' -Message 'Vendor agent detection failed.' -Reason $_.Exception.Message | Out-Null }
    return ,@{ VendorAgents=@($rows) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    $rows = @(if ($RawData -and $RawData.VendorAgents) { @($RawData.VendorAgents) } else { @() })
    Add-DataSet -Context $Context -Name 'VendorAgents' -Description 'Detected vendor/RMM/EDR/backup/monitoring/hardware agents.' -Rows $rows -Visibility 'Both' -SourceModule 'VendorAgents' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('VendorAgents')) {
            $edr = @($Context.DataSets['VendorAgents'].Rows | Where-Object { $_.Category -eq 'EDR/AV' })
            if ($edr.Count -gt 0) { Add-FollowUpQuestion -Context $Context -Category 'Vendor support' -Module 'VendorAgents' -Audience 'Both' -Question ('Security agents are present ({0}). Discovery activity may raise alerts - who manages these consoles, and how are the agents handled during migration/decommission?' -f (($edr | ForEach-Object { $_.AgentName }) -join ', ')) | Out-Null }
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions'
