<#
    IIS.psm1 - IIS sites, bindings, app pools, applications, virtual directories (read-only).
    Role-gated. Produces: IisSites, IisBindings, IisAppPools, IisApplications, IisVirtualDirectories.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='IIS'; DisplayName='IIS / Web Server'; Category='Web'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole='Web-Server'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('IisSites','IisBindings','IisAppPools','IisApplications','IisVirtualDirectories')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Get-IisAppCmdPath { $p = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'; if (Test-Path $p) { return $p } return $null }

function Test-IisPresent {
    if (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue) { return $true }
    if (Get-IisAppCmdPath) { return $true }
    if (Get-ModuleAvailable -Name 'WebAdministration') { return $true }
    return $false
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    if (Test-IisPresent) { return [pscustomobject]@{ ModuleName='IIS'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='IIS'; CanRun=$false; Status='NotApplicable'; Reason='IIS (W3SVC / appcmd / WebAdministration) not present.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $sites=[System.Collections.Generic.List[object]]::new(); $bindings=[System.Collections.Generic.List[object]]::new()
    $pools=[System.Collections.Generic.List[object]]::new(); $apps=[System.Collections.Generic.List[object]]::new(); $vdirs=[System.Collections.Generic.List[object]]::new()

    $useWA = (Get-ModuleAvailable -Name 'WebAdministration')
    if ($useWA) { try { Import-Module WebAdministration -ErrorAction SilentlyContinue } catch { $useWA=$false } }

    if ($useWA -and (Get-CommandAvailable -Name 'Get-Website')) {
        try {
            foreach ($s in (Get-Website -ErrorAction SilentlyContinue)) {
                $bindText = ''
                try { $bindText = (($s.bindings.Collection | ForEach-Object { $_.protocol + ' ' + $_.bindingInformation }) -join '; ') } catch { }
                $sites.Add([pscustomobject]@{ Name=$s.Name; State=[string]$s.State; Bindings=$bindText; PhysicalPath=$s.physicalPath; ApplicationPool=$s.applicationPool })
                try {
                    foreach ($b in $s.bindings.Collection) {
                        $thumb = ''
                        try { if ($b.certificateHash) { $thumb = ($b.certificateHash) } } catch { }
                        $bindings.Add([pscustomobject]@{ Site=$s.Name; Protocol=$b.protocol; BindingInformation=$b.bindingInformation; CertificateHash=$thumb })
                    }
                } catch { }
                if ($s.physicalPath) { Add-DependencyEdge -Context $Context -SourceType 'IIS Site' -SourceName $s.Name -DependencyType 'UsesPath' -Target $s.physicalPath -Evidence 'Site physical path' -Confidence 'Confirmed' -SourceDataset 'IisSites' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Does this physical path move with the site?' | Out-Null }
            }
        } catch { Add-Limitation -Context $Context -Module 'IIS' -Message 'Get-Website failed; site enumeration may require elevation.' -Reason $_.Exception.Message | Out-Null }
        try {
            foreach ($ap in (Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue)) {
                $idType=''; $user=''
                try { $idType=[string]$ap.processModel.identityType; $user=[string]$ap.processModel.userName } catch { }
                $custom = ($idType -eq 'SpecificUser' -or ($user -and (Test-IisIdentityIsDomainAccount $user)))
                $pools.Add([pscustomobject]@{ Name=$ap.Name; ManagedRuntimeVersion=[string]$ap.managedRuntimeVersion; ManagedPipelineMode=[string]$ap.managedPipelineMode; IdentityType=$idType; UserName=$user; UsesCustomIdentity=$custom; IsLegacyDotNet=([bool]([string]$ap.managedRuntimeVersion -match '^v[12]\.')) })
                if ($custom -and $user) { Add-DependencyEdge -Context $Context -SourceType 'IIS AppPool' -SourceName $ap.Name -DependencyType 'RunsAs' -Target $user -Evidence 'App pool identity' -Confidence 'Confirmed' -SourceDataset 'IisAppPools' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Who owns this app pool identity?' | Out-Null }
            }
        } catch { }
        try { foreach ($a in (Get-WebApplication -ErrorAction SilentlyContinue)) { $apps.Add([pscustomobject]@{ Site=$a.GetParentElement().Attributes['name'].Value; Path=$a.path; AppPool=$a.applicationPool; PhysicalPath=$a.PhysicalPath }) } } catch { }
        try { foreach ($v in (Get-WebVirtualDirectory -ErrorAction SilentlyContinue)) { $vdirs.Add([pscustomobject]@{ Path=$v.path; PhysicalPath=$v.physicalPath }) } } catch { }
    } else {
        # appcmd text parse (READ-ONLY list)
        $appcmd = Get-IisAppCmdPath
        if ($appcmd) {
            try {
                $r = Invoke-CommandLineSafe -FilePath $appcmd -Arguments @('list','site') -TimeoutSeconds 45
                foreach ($ln in ($r.StdOut -split "`r?`n")) {
                    # Non-greedy up to ",state:" - a site can have several comma-separated
                    # protocol/bindingInformation tokens before state (e.g. http and https).
                    $m = [regex]::Match($ln, 'SITE\s+"([^"]+)"\s+\(id:(\d+),bindings:(.+?),state:(\w+)')
                    if ($m.Success) {
                        $siteName = $m.Groups[1].Value
                        $bindText = $m.Groups[3].Value
                        $sites.Add([pscustomobject]@{ Name=$siteName; State=$m.Groups[4].Value; Bindings=$bindText; PhysicalPath=''; ApplicationPool='' })
                        foreach ($tok in ($bindText -split ',')) {
                            $slash = $tok.IndexOf('/')
                            if ($slash -gt 0) {
                                $bindings.Add([pscustomobject]@{ Site=$siteName; Protocol=$tok.Substring(0,$slash); BindingInformation=$tok.Substring($slash+1); CertificateHash='' })
                            }
                        }
                    }
                }
                $rp = Invoke-CommandLineSafe -FilePath $appcmd -Arguments @('list','apppool') -TimeoutSeconds 45
                foreach ($ln in ($rp.StdOut -split "`r?`n")) {
                    $m = [regex]::Match($ln, 'APPPOOL\s+"([^"]+)"\s+\(MgdVersion:([^,]*),MgdMode:([^,]*),state:(\w+)')
                    if ($m.Success) { $pools.Add([pscustomobject]@{ Name=$m.Groups[1].Value; ManagedRuntimeVersion=$m.Groups[2].Value; ManagedPipelineMode=$m.Groups[3].Value; IdentityType=''; UserName=''; UsesCustomIdentity=$false; IsLegacyDotNet=([bool]($m.Groups[2].Value -match '^v[12]\.')) }) }
                }
            } catch { Add-Limitation -Context $Context -Module 'IIS' -Message 'appcmd parse failed.' -Reason $_.Exception.Message | Out-Null }
        } else { Add-Limitation -Context $Context -Module 'IIS' -Message 'No IIS management tooling available to enumerate sites.' | Out-Null }
    }

    return ,@{ IisSites=@($sites); IisBindings=@($bindings); IisAppPools=@($pools); IisApplications=@($apps); IisVirtualDirectories=@($vdirs) }
}

# True when an app-pool identity looks like DOMAIN\user rather than a built-in account.
function Test-IisIdentityIsDomainAccount { param([string]$acct) if ([string]::IsNullOrWhiteSpace($acct)) { return $false }; return ($acct -match '^[^\\@]+\\[^\\@]+$' -and $acct -notmatch '^(NT AUTHORITY|NT SERVICE|BUILTIN|IIS APPPOOL)\\') }

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'IisSites'              -Description 'IIS websites.'            -Rows (& $get 'IisSites')              -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisBindings'           -Description 'IIS bindings + cert hashes.'-Rows (& $get 'IisBindings')          -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisAppPools'           -Description 'IIS application pools.'    -Rows (& $get 'IisAppPools')           -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisApplications'       -Description 'IIS applications.'         -Rows (& $get 'IisApplications')       -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisVirtualDirectories' -Description 'IIS virtual directories.'  -Rows (& $get 'IisVirtualDirectories') -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try { if ($Context.DataSets.Contains('IisSites') -and @($Context.DataSets['IisSites'].Rows).Count -gt 0) { Add-FollowUpQuestion -Context $Context -Category 'Applications' -Module 'IIS' -Audience 'Both' -Question 'Who owns each IIS-hosted web application, and are its certificate, host-header, and connection-string dependencies documented?' | Out-Null } } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Test-IisPresent','Get-IisAppCmdPath','Test-IisIdentityIsDomainAccount'
