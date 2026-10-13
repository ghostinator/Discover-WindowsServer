<#
    IIS.psm1 - IIS sites, bindings, app pools, applications, virtual directories and
    authentication modes (read-only). Role-gated.
    Produces: IisSites, IisBindings, IisAppPools, IisApplications, IisVirtualDirectories,
              IisAuthentication.
    Only Get-* / appcmd LIST verbs are used. No IIS configuration is ever changed, and app-pool
    passwords are never read (identity user NAME only).
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='IIS'; DisplayName='IIS / Web Server'; Category='Web'; Version='1.1.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole='Web-Server'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('IisSites','IisBindings','IisAppPools','IisApplications','IisVirtualDirectories','IisAuthentication')
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

function ConvertFrom-IisBindingInformation {
    <# Pure: 'IP:Port:HostHeader' (IPv6 addresses arrive bracketed) -> its three parts. Non-HTTP bindings (net.tcp '808:*') keep the raw text. #>
    param([string]$BindingInformation)
    $out = [pscustomobject]@{ IPAddress=''; Port=''; HostHeader='' }
    if ([string]::IsNullOrWhiteSpace($BindingInformation)) { return $out }
    $m = [regex]::Match($BindingInformation, '^(\[[^\]]*\]|[^:]*):(\d+):(.*)$')
    if ($m.Success) { $out.IPAddress = $m.Groups[1].Value; $out.Port = $m.Groups[2].Value; $out.HostHeader = $m.Groups[3].Value }
    else { $p = [regex]::Match($BindingInformation, '^(\d+):'); if ($p.Success) { $out.Port = $p.Groups[1].Value } }
    return $out
}

function Get-IisPathAssessment {
    <#
        Pure apart from one Test-Path: where a site/app/vdir physical path lives and whether it
        still exists. Environment variables (%SystemDrive%) are expanded first. Standard roots are
        inetpub and the Exchange/IIS install folders; anything else must be found and moved by hand.
    #>
    param([string]$Path)
    $out = [pscustomobject]@{ ExpandedPath=''; PathExists=$null; PathIsUnc=$false; PathOutsideWebRoot=$false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $out }
    $x = [Environment]::ExpandEnvironmentVariables($Path)
    $out.ExpandedPath = $x
    $out.PathIsUnc = [bool]($x -match '^\\\\')
    # Standard roots include the folders Microsoft roles install their own web apps into (WSUS, RD Web, AD FS).
    $out.PathOutsideWebRoot = [bool]($x -notmatch '(?i)\\inetpub\\|\\Microsoft\\Exchange Server\\|\\inetsrv\\|\\Windows\\Microsoft\.NET\\|\\Update Services\\|\\Windows\\Web\\|\\ADFS\\|\\WsusContent\\?|\\System32\\')
    try { $out.PathExists = [bool](Test-Path -LiteralPath $x) } catch { $out.PathExists = $null }
    return $out
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $sites=[System.Collections.Generic.List[object]]::new(); $bindings=[System.Collections.Generic.List[object]]::new()
    $pools=[System.Collections.Generic.List[object]]::new(); $apps=[System.Collections.Generic.List[object]]::new(); $vdirs=[System.Collections.Generic.List[object]]::new()
    $auth=[System.Collections.Generic.List[object]]::new()

    $newSite = {
        param($name, $id, $state, $bindText, $phys, $pool, $autoStart)
        $pa = Get-IisPathAssessment -Path $phys
        [pscustomobject]@{ Name=$name; State=[string]$state; Bindings=$bindText; PhysicalPath=$phys; ApplicationPool=$pool
            Id=$id; ServerAutoStart=$autoStart; IsStopped=[bool]([string]$state -match '(?i)Stopped')
            PathExists=$pa.PathExists; PathIsUnc=$pa.PathIsUnc; PathOutsideWebRoot=$pa.PathOutsideWebRoot }
    }
    $newBinding = {
        param($site, $proto, $info, $thumb, $store, $sslFlags)
        $bi = ConvertFrom-IisBindingInformation -BindingInformation $info
        [pscustomobject]@{ Site=$site; Protocol=$proto; BindingInformation=$info; CertificateHash=$thumb
            IPAddress=$bi.IPAddress; Port=$bi.Port; HostHeader=$bi.HostHeader; CertificateStore=$store; SslFlags=$sslFlags
            IsHttps=[bool]($proto -eq 'https'); IsSpecificIp=[bool]($bi.IPAddress -and $bi.IPAddress -ne '*') }
    }
    $newApp = {
        param($site, $path, $pool, $phys)
        $pa = Get-IisPathAssessment -Path $phys
        [pscustomobject]@{ Site=$site; Path=$path; AppPool=$pool; PhysicalPath=$phys; PathExists=$pa.PathExists; PathIsUnc=$pa.PathIsUnc; PathOutsideWebRoot=$pa.PathOutsideWebRoot }
    }

    $useWA = (Get-ModuleAvailable -Name 'WebAdministration')
    if ($useWA) { try { Import-Module WebAdministration -ErrorAction SilentlyContinue } catch { $useWA=$false } }

    if ($useWA -and (Get-CommandAvailable -Name 'Get-Website')) {
        try {
            foreach ($s in (Get-Website -ErrorAction SilentlyContinue)) {
                $bindText = ''
                try { $bindText = (($s.bindings.Collection | ForEach-Object { $_.protocol + ' ' + $_.bindingInformation }) -join '; ') } catch { }
                $auto = $null; try { $auto = [bool]$s.serverAutoStart } catch { }
                $sites.Add((& $newSite $s.Name $s.id $s.State $bindText $s.physicalPath $s.applicationPool $auto))
                try {
                    foreach ($b in $s.bindings.Collection) {
                        $thumb = ''; $store = ''; $flags = ''
                        try { if ($b.certificateHash) { $thumb = [string]$b.certificateHash; $store = [string]$b.certificateStoreName } } catch { }
                        try { $flags = [string]$b.sslFlags } catch { }
                        $bindings.Add((& $newBinding $s.Name $b.protocol $b.bindingInformation $thumb $store $flags))
                    }
                } catch { }
                if ($s.physicalPath) { Add-DependencyEdge -Context $Context -SourceType 'IIS Site' -SourceName $s.Name -DependencyType 'UsesPath' -Target $s.physicalPath -Evidence 'Site physical path' -Confidence 'Confirmed' -SourceDataset 'IisSites' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Does this physical path move with the site?' | Out-Null }
                # Authentication modes per site (read-only property reads).
                try {
                    $row = [ordered]@{ Site=$s.Name }
                    foreach ($mode in @('anonymous','windows','basic','digest')) {
                        $v = $null
                        try { $v = (Get-WebConfigurationProperty -PSPath 'IIS:\' -Location $s.Name -Filter ("system.webServer/security/authentication/{0}Authentication" -f $mode) -Name 'enabled' -ErrorAction Stop).Value } catch { }
                        $row[('{0}Enabled' -f ((Get-Culture).TextInfo.ToTitleCase($mode)))] = $v
                    }
                    $auth.Add([pscustomobject]$row)
                } catch { }
            }
        } catch { Add-Limitation -Context $Context -Module 'IIS' -Message 'Get-Website failed; site enumeration may require elevation.' -Reason $_.Exception.Message | Out-Null }
        try {
            foreach ($ap in (Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue)) {
                $idType=''; $user=''
                try { $idType=[string]$ap.processModel.identityType; $user=[string]$ap.processModel.userName } catch { }
                $custom = ($idType -eq 'SpecificUser' -or ($user -and (Test-IisIdentityIsDomainAccount $user)))
                $state = ''; $autoStart = $null; $startMode = ''
                try { $state = [string]$ap.state; $autoStart = [bool]$ap.autoStart; $startMode = [string]$ap.startMode } catch { }
                $pools.Add([pscustomobject]@{ Name=$ap.Name; ManagedRuntimeVersion=[string]$ap.managedRuntimeVersion; ManagedPipelineMode=[string]$ap.managedPipelineMode; IdentityType=$idType; UserName=$user; UsesCustomIdentity=$custom; IsLegacyDotNet=([bool]([string]$ap.managedRuntimeVersion -match '^v[12]\.'))
                    State=$state; AutoStart=$autoStart; StartMode=$startMode; IsElevatedIdentity=[bool]($idType -eq 'LocalSystem') })
                if ($custom -and $user) { Add-DependencyEdge -Context $Context -SourceType 'IIS AppPool' -SourceName $ap.Name -DependencyType 'RunsAs' -Target $user -Evidence 'App pool identity' -Confidence 'Confirmed' -SourceDataset 'IisAppPools' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Who owns this app pool identity?' | Out-Null }
            }
        } catch { }
        try { foreach ($a in (Get-WebApplication -ErrorAction SilentlyContinue)) { $apps.Add((& $newApp ($a.GetParentElement().Attributes['name'].Value) $a.path $a.applicationPool $a.PhysicalPath)) } } catch { }
        try { foreach ($v in (Get-WebVirtualDirectory -ErrorAction SilentlyContinue)) { $pa = Get-IisPathAssessment -Path $v.physicalPath; $vdirs.Add([pscustomobject]@{ Path=$v.path; PhysicalPath=$v.physicalPath; PathExists=$pa.PathExists; PathIsUnc=$pa.PathIsUnc; PathOutsideWebRoot=$pa.PathOutsideWebRoot }) } } catch { }
    } else {
        # appcmd text parse (READ-ONLY list)
        $appcmd = Get-IisAppCmdPath
        if ($appcmd) {
            try {
                # Root virtual directories give each site/app its physical path (appcmd list site does not).
                $vdirPaths = @{}
                $rv = Invoke-CommandLineSafe -FilePath $appcmd -Arguments @('list','vdir') -TimeoutSeconds 45
                foreach ($ln in ([string]$rv.StdOut -split "`r?`n")) {
                    $m = [regex]::Match($ln, 'VDIR\s+"([^"]+)"\s+\(physicalPath:([^)]*)\)')
                    if ($m.Success) {
                        $vdirPaths[$m.Groups[1].Value] = $m.Groups[2].Value
                        $pa = Get-IisPathAssessment -Path $m.Groups[2].Value
                        $vdirs.Add([pscustomobject]@{ Path=$m.Groups[1].Value; PhysicalPath=$m.Groups[2].Value; PathExists=$pa.PathExists; PathIsUnc=$pa.PathIsUnc; PathOutsideWebRoot=$pa.PathOutsideWebRoot })
                    }
                }
                $sitePools = @{}
                $ra = Invoke-CommandLineSafe -FilePath $appcmd -Arguments @('list','app') -TimeoutSeconds 45
                foreach ($ln in ([string]$ra.StdOut -split "`r?`n")) {
                    $m = [regex]::Match($ln, 'APP\s+"([^"/]+)(/[^"]*)"\s+\(applicationPool:([^)]*)\)')
                    if ($m.Success) {
                        $appPath = $m.Groups[2].Value
                        if ($appPath -eq '/') { $sitePools[$m.Groups[1].Value] = $m.Groups[3].Value }
                        $apps.Add((& $newApp $m.Groups[1].Value $appPath $m.Groups[3].Value ([string]$vdirPaths[($m.Groups[1].Value + $appPath + $(if ($appPath.EndsWith('/')) { '' } else { '/' }))])))
                    }
                }
                $r = Invoke-CommandLineSafe -FilePath $appcmd -Arguments @('list','site') -TimeoutSeconds 45
                foreach ($ln in ($r.StdOut -split "`r?`n")) {
                    # Non-greedy up to ",state:" - a site can have several comma-separated
                    # protocol/bindingInformation tokens before state (e.g. http and https).
                    $m = [regex]::Match($ln, 'SITE\s+"([^"]+)"\s+\(id:(\d+),bindings:(.+?),state:(\w+)')
                    if ($m.Success) {
                        $siteName = $m.Groups[1].Value
                        $bindText = $m.Groups[3].Value
                        $sites.Add((& $newSite $siteName $m.Groups[2].Value $m.Groups[4].Value $bindText ([string]$vdirPaths["$siteName/"]) ([string]$sitePools[$siteName]) $null))
                        foreach ($tok in ($bindText -split ',')) {
                            $slash = $tok.IndexOf('/')
                            if ($slash -gt 0) {
                                $bindings.Add((& $newBinding $siteName $tok.Substring(0,$slash) $tok.Substring($slash+1) '' '' ''))
                            }
                        }
                    }
                }
                $rp = Invoke-CommandLineSafe -FilePath $appcmd -Arguments @('list','apppool') -TimeoutSeconds 45
                foreach ($ln in ($rp.StdOut -split "`r?`n")) {
                    $m = [regex]::Match($ln, 'APPPOOL\s+"([^"]+)"\s+\(MgdVersion:([^,]*),MgdMode:([^,]*),state:(\w+)')
                    if ($m.Success) { $pools.Add([pscustomobject]@{ Name=$m.Groups[1].Value; ManagedRuntimeVersion=$m.Groups[2].Value; ManagedPipelineMode=$m.Groups[3].Value; IdentityType=''; UserName=''; UsesCustomIdentity=$false; IsLegacyDotNet=([bool]($m.Groups[2].Value -match '^v[12]\.')); State=$m.Groups[4].Value; AutoStart=$null; StartMode=''; IsElevatedIdentity=$false }) }
                }
            } catch { Add-Limitation -Context $Context -Module 'IIS' -Message 'appcmd parse failed.' -Reason $_.Exception.Message | Out-Null }
            if ($sites.Count -gt 0) { Add-Limitation -Context $Context -Module 'IIS' -Message 'IIS enumerated via appcmd (WebAdministration unavailable): app-pool identities and authentication modes were not read.' -Impact 'Partial IIS detail' | Out-Null }
        } else { Add-Limitation -Context $Context -Module 'IIS' -Message 'No IIS management tooling available to enumerate sites.' | Out-Null }
    }

    return ,@{ IisSites=@($sites); IisBindings=@($bindings); IisAppPools=@($pools); IisApplications=@($apps); IisVirtualDirectories=@($vdirs); IisAuthentication=@($auth) }
}

# True when an app-pool identity looks like DOMAIN\user rather than a built-in account.
function Test-IisIdentityIsDomainAccount { param([string]$acct) if ([string]::IsNullOrWhiteSpace($acct)) { return $false }; return ($acct -match '^[^\\@]+\\[^\\@]+$' -and $acct -notmatch '^(NT AUTHORITY|NT SERVICE|BUILTIN|IIS APPPOOL)\\') }

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'IisSites'              -Description 'IIS websites (state, path checks).' -Rows (& $get 'IisSites')       -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisBindings'           -Description 'IIS bindings (IP/port/host header) + cert hashes.' -Rows (& $get 'IisBindings') -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisAppPools'           -Description 'IIS application pools (runtime, identity, state).' -Rows (& $get 'IisAppPools') -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisApplications'       -Description 'IIS applications.'         -Rows (& $get 'IisApplications')       -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisVirtualDirectories' -Description 'IIS virtual directories.'  -Rows (& $get 'IisVirtualDirectories') -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
    Add-DataSet -Context $Context -Name 'IisAuthentication'     -Description 'Per-site authentication modes (anonymous/windows/basic/digest).' -Rows (& $get 'IisAuthentication') -Visibility 'Internal' -SourceModule 'IIS' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try { if ($Context.DataSets.Contains('IisSites') -and @($Context.DataSets['IisSites'].Rows).Count -gt 0) { Add-FollowUpQuestion -Context $Context -Category 'Applications' -Module 'IIS' -Audience 'Both' -Question 'Who owns each IIS-hosted web application, and are its certificate, host-header, and connection-string dependencies documented?' | Out-Null } } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Test-IisPresent','Get-IisAppCmdPath','Test-IisIdentityIsDomainAccount','ConvertFrom-IisBindingInformation','Get-IisPathAssessment'
