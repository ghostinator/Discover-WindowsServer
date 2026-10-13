<#
    ActiveDirectory.psm1 - domain context and (if a DC) directory role details (read-only).
    Produces: DomainContext, AppliedGroupPolicy, DomainControllerDiscovery.
    Uses built-in methods first; uses the ActiveDirectory module only if present.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='ActiveDirectory'; DisplayName='Active Directory & Migration Readiness'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('DomainContext','AppliedGroupPolicy','DomainControllerDiscovery','AdDomainControllers','AdFsmoRoles','AdReplicationSummary','AdHealthChecks')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='ActiveDirectory'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function ConvertTo-AdFunctionalLevelName {
    <# Maps the numeric domainFunctionality/forestFunctionality RootDSE attribute to its name. #>
    param($Level)
    if ($null -eq $Level) { return '' }
    $names = @{ 0='Windows2000'; 1='Windows2003Interim'; 2='Windows2003'; 3='Windows2008'; 4='Windows2008R2'; 5='Windows2012'; 6='Windows2012R2'; 7='Windows2016'; 10='Windows2025' }
    $n = 0
    if ([int]::TryParse([string]$Level, [ref]$n) -and $names.ContainsKey($n)) { return $names[$n] }
    return ("Level{0}" -f $Level)
}

function Test-AdDcOsUnsupported {
    <# Pure: true when a DC's operatingSystem string is past Microsoft extended support as of -AsOf. Unknown text is never called unsupported. #>
    param([string]$OperatingSystem, [datetime]$AsOf = (Get-Date))
    $ends = [ordered]@{ '2003'='2015-07-14'; '2008'='2020-01-14'; '2012'='2023-10-10'; '2016'='2027-01-12'; '2019'='2029-01-09'; '2022'='2031-10-14' }
    foreach ($k in $ends.Keys) { if ($OperatingSystem -match ("Server\D*{0}" -f $k)) { return ([datetime]$ends[$k] -lt $AsOf) } }
    return $false
}

function ConvertFrom-NetdomFsmo {
    <# Pure: netdom query fsmo text -> one row per role with whole-host-label ownership matching. #>
    param([string]$Text, [string[]]$MyNames = @($env:COMPUTERNAME))
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($ln in ([string]$Text -split "`r?`n")) {
        $m = [regex]::Match($ln, '^\s*(Schema master|Domain naming master|PDC|RID pool manager|Infrastructure master)\s+(\S+)\s*$', 'IgnoreCase')
        if (-not $m.Success) { continue }
        $holder = $m.Groups[2].Value
        $mine = $false
        foreach ($n in @($MyNames | Where-Object { $_ })) { if ($holder -match ('(?i)^' + [regex]::Escape($n) + '(\.|$)')) { $mine = $true } }
        $rows.Add([pscustomobject]@{ Role=$m.Groups[1].Value; Holder=$holder; HeldByThisServer=$mine })
    }
    return ,@($rows)
}

function ConvertFrom-RepadminReplSummary {
    <# Pure: repadmin /replsummary text -> one row per source/destination DSA. #>
    param([string]$Text)
    $rows = [System.Collections.Generic.List[object]]::new()
    $direction = ''
    foreach ($ln in ([string]$Text -split "`r?`n")) {
        if ($ln -match '^\s*Source DSA') { $direction = 'Source'; continue }
        if ($ln -match '^\s*Destination DSA') { $direction = 'Destination'; continue }
        if (-not $direction) { continue }
        # The delta column can contain a space ('>60 days'), so it is matched lazily.
        $m = [regex]::Match($ln, '^\s*(\S+)\s+(.+?)\s+(\d+)\s*/\s*(\d+)\s+\d+\s*(.*)$')
        if ($m.Success) { $rows.Add([pscustomobject]@{ Direction=$direction; Dsa=$m.Groups[1].Value; LargestDelta=$m.Groups[2].Value; Fails=[int]$m.Groups[3].Value; Total=[int]$m.Groups[4].Value; Error=$m.Groups[5].Value.Trim() }) }
    }
    return ,@($rows)
}

function Get-AdDcInventory {
    <#
        Every DC in the domain via plain LDAP reads (no RSAT / ActiveDirectory module): computer
        objects in the DC/RODC primary groups for name + OS, then nTDSDSA objects in the
        configuration partition for site and Global Catalog. Returns $null when the directory
        cannot be read, so callers can tell "no DCs found" from "could not ask".
    #>
    param()
    try {
        $root = [ADSI]'LDAP://RootDSE'
        $defaultNc = [string]$root.Properties['defaultNamingContext'][0]
        $configNc = [string]$root.Properties['configurationNamingContext'][0]
        if (-not $defaultNc) { return $null }
        $byName = @{}
        $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNc", '(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))')
        $s.PageSize = 200; $s.ClientTimeout = [TimeSpan]::FromSeconds(30)
        foreach ($p in 'name','dNSHostName','operatingSystem','operatingSystemVersion','primaryGroupID') { [void]$s.PropertiesToLoad.Add($p) }
        foreach ($r in $s.FindAll()) {
            $n = [string]$r.Properties['name'][0]
            $byName[$n.ToUpperInvariant()] = [pscustomobject]@{
                Name=$n; DnsHostName=[string]$r.Properties['dnshostname'][0]; OperatingSystem=[string]$r.Properties['operatingsystem'][0]
                OperatingSystemVersion=[string]$r.Properties['operatingsystemversion'][0]; Site=''; IsGlobalCatalog=$false
                IsReadOnly=[bool]([int]$r.Properties['primarygroupid'][0] -eq 521); IsThisServer=[bool]($n -ieq $env:COMPUTERNAME)
                IsUnsupportedOs=(Test-AdDcOsUnsupported -OperatingSystem ([string]$r.Properties['operatingsystem'][0]))
            }
        }
        if ($configNc) {
            $d = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Sites,$configNc", '(objectCategory=nTDSDSA)')
            $d.PageSize = 200; $d.ClientTimeout = [TimeSpan]::FromSeconds(30)
            [void]$d.PropertiesToLoad.Add('distinguishedName'); [void]$d.PropertiesToLoad.Add('options')
            foreach ($r in $d.FindAll()) {
                $m = [regex]::Match([string]$r.Properties['distinguishedname'][0], '^CN=NTDS Settings,CN=([^,]+),CN=Servers,CN=([^,]+),')
                if (-not $m.Success) { continue }
                $dc = $byName[$m.Groups[1].Value.ToUpperInvariant()]
                if ($dc) { $dc.Site = $m.Groups[2].Value; $dc.IsGlobalCatalog = [bool](([int]$r.Properties['options'][0]) -band 1) }
            }
        }
        return ,@($byName.Values | Sort-Object Name)
    } catch { return $null }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $ctxRows = [System.Collections.Generic.List[object]]::new()
    $gpos = [System.Collections.Generic.List[object]]::new()
    $dcs = [System.Collections.Generic.List[object]]::new()
    $fsmoRows = @(); $replRows = @(); $health = [System.Collections.Generic.List[object]]::new(); $dcInventory = @()
    $sysvolReplication = ''

    $cs = Invoke-CimSafe -ClassName 'Win32_ComputerSystem' | Select-Object -First 1
    $domainRole = if ($cs) { [int]$cs.DomainRole } else { -1 }
    $roleName = switch ($domainRole) { 0 {'Standalone Workstation'} 1 {'Member Workstation'} 2 {'Standalone Server'} 3 {'Member Server'} 4 {'Backup Domain Controller'} 5 {'Primary Domain Controller'} default {'Unknown'} }
    $isDc = ($domainRole -eq 4 -or $domainRole -eq 5)
    $partOfDomain = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
    $domainName = if ($cs) { $cs.Domain } else { $env:USERDNSDOMAIN }

    $holdsFsmo = $false
    $fsmoDetail = ''
    if ($isDc) {
        try {
            $r = Invoke-CommandLineSafe -FilePath 'netdom.exe' -Arguments @('query','fsmo') -TimeoutSeconds 45
            if ($r.Succeeded -and $r.StdOut) {
                $fsmoRows = ConvertFrom-NetdomFsmo -Text $r.StdOut -MyNames @($env:COMPUTERNAME, $cs.DNSHostName)
                $me = $env:COMPUTERNAME
                $fsmoDetail = ($r.StdOut -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch 'command completed' } | ForEach-Object { $_.Trim() -replace '\s{2,}',': ' } | Select-Object -First 6) -join '; '
                # Whole host label, NetBIOS or DNS name: a bare substring match let DC1 "hold" DC10's roles.
                foreach ($n in @($me, $cs.DNSHostName) | Where-Object { $_ }) { if ($r.StdOut -match ('(?im)(^|[\s:])' + [regex]::Escape($n) + '(\.|\s|$)')) { $holdsFsmo = $true } }
            }
        } catch { }
        # SYSVOL / NETLOGON presence
        try {
            $sysvol = $false; $netlogon = $false
            if (Get-CommandAvailable -Name 'Get-SmbShare') {
                $sh = Get-SmbShare -ErrorAction SilentlyContinue
                $sysvol = [bool]($sh | Where-Object { $_.Name -eq 'SYSVOL' })
                $netlogon = [bool]($sh | Where-Object { $_.Name -eq 'NETLOGON' })
            }
            $dcs.Add([pscustomobject]@{ DcName=$env:COMPUTERNAME; Item='LocalDC'; Detail=("SYSVOL={0}; NETLOGON={1}; FSMO={2}" -f $sysvol, $netlogon, $fsmoDetail) })
        } catch { }
        # Replication health (read-only summary verbs).
        try {
            $rr = Invoke-CommandLineSafe -FilePath 'repadmin.exe' -Arguments @('/replsummary') -TimeoutSeconds 120
            if ($rr.Succeeded -or $rr.StdOut) { $replRows = ConvertFrom-RepadminReplSummary -Text $rr.StdOut }
            else { Add-Limitation -Context $Context -Module 'ActiveDirectory' -Message 'repadmin /replsummary returned nothing; replication health unknown.' | Out-Null }
        } catch { }
        # SYSVOL replication engine: 'Eliminated' = DFSR; anything earlier means FRS is still in play.
        try {
            $rm = Invoke-CommandLineSafe -FilePath 'dfsrmig.exe' -Arguments @('/getmigrationstate') -TimeoutSeconds 60
            $sysvolReplication = if ($rm.StdOut -match '(?i)Eliminated') { 'DFSR' } elseif ($rm.StdOut -match '(?i)\b(Start|Prepared|Redirected)\b') { 'FRS (migration incomplete)' } elseif ($rm.StdOut -match '(?i)not.*initiated|has not') { 'FRS' } else { 'Unknown' }
        } catch { $sysvolReplication = 'Unknown' }
        # dcdiag runs every default test and can take minutes on a large forest: Deep mode only, quiet (failures only).
        if ($Context.Mode -eq 'Deep') {
            try {
                $rd = Invoke-CommandLineSafe -FilePath 'dcdiag.exe' -Arguments @('/q') -TimeoutSeconds 240
                if ($rd.TimedOut) { Add-Limitation -Context $Context -Module 'ActiveDirectory' -Message 'dcdiag /q did not finish within 240 seconds.' | Out-Null }
                else {
                    $lines = @(($rd.StdOut -split "`r?`n") | Where-Object { $_.Trim() })
                    $failed = @($lines | Where-Object { $_ -match '(?i)failed test' } | Select-Object -First 50)
                    if ($lines.Count -eq 0) { $health.Add([pscustomobject]@{ Check='dcdiag /q'; Result='No failures reported'; Detail='' }) }
                    elseif ($failed.Count -gt 0) { foreach ($f in $failed) { $health.Add([pscustomobject]@{ Check=($f.Trim() -replace '(?i)^.*failed test\s*',''); Result='Failed'; Detail=$f.Trim() }) } }
                    else { $health.Add([pscustomobject]@{ Check='dcdiag /q'; Result='Errors reported (no failed test line)'; Detail=(($lines | Select-Object -First 4 | ForEach-Object { $_.Trim() }) -join ' | ') }) }
                }
            } catch { }
        } else { Add-Unknown -Context $Context -Unknown 'dcdiag was not run (Fast mode).' -WhyItMatters 'Latent DC health problems surface during role transfer and demotion.' -Module 'ActiveDirectory' -RecommendedValidationQuestion 'Run in Deep mode, or provide recent dcdiag output, before planning DC changes.' | Out-Null }
        if (-not $holdsFsmo -and -not $fsmoDetail) { Add-Unknown -Context $Context -Unknown 'FSMO role ownership could not be determined.' -WhyItMatters 'FSMO roles must be transferred before a DC is retired.' -Module 'ActiveDirectory' -RecommendedValidationQuestion 'Which DC holds the FSMO roles?' | Out-Null }
    }

    # LDAP signing / channel binding - DC-only registry keys under NTDS\Parameters, so these
    # simply don't exist on a member server. Deliberately short-circuited on $isDc rather than
    # just reading the (absent) registry value everywhere: a member server would otherwise
    # compute the same "not enforced" result as a genuinely unhardened DC, which would be a
    # real false positive on every non-DC in a fleet scan. Absent-on-a-real-DC IS flagged
    # (both values default to the weaker setting when unconfigured, per Microsoft's own 2020/
    # 2023 LDAP hardening advisories - KB4520412), matching the same "flag the unconfigured
    # default, don't require proof of the weak value" contract used for LmCompatibilityLevel
    # in SecurityPosture.psm1's NtlmLegacyCompatibilityAllowed.
    $ldapSigningNotEnforced = $false
    $ldapChannelBindingNotEnforced = $false
    if ($isDc) {
        $ldapIntegrity = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'
        $ldapChannelBinding = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding'
        $ldapSigningNotEnforced = ($null -eq $ldapIntegrity) -or ([int]$ldapIntegrity -lt 2)
        $ldapChannelBindingNotEnforced = ($null -eq $ldapChannelBinding) -or ([int]$ldapChannelBinding -lt 1)
    }

    $logonServer = $env:LOGONSERVER
    $site = ''
    try { $rs = Invoke-CommandLineSafe -FilePath 'nltest.exe' -Arguments @('/dsgetsite') -TimeoutSeconds 20; if ($rs.Succeeded) { $site = ($rs.StdOut -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch 'completed' } | Select-Object -First 1) } } catch { }

    # Domain/forest functional level via RootDSE - an LDAP bind any domain-joined machine can
    # do (no RSAT/ActiveDirectory module needed, unlike Get-ADDomain/Get-ADForest).
    $domainFuncLevel = ''
    $forestFuncLevel = ''
    if ($partOfDomain) {
        try {
            $rootDse = [ADSI]'LDAP://RootDSE'
            $domainFuncLevel = ConvertTo-AdFunctionalLevelName -Level $rootDse.Properties['domainFunctionality'][0]
            $forestFuncLevel = ConvertTo-AdFunctionalLevelName -Level $rootDse.Properties['forestFunctionality'][0]
        } catch { }
    }

    # DC inventory from any domain member: single-DC environments, unsupported DC operating systems.
    if ($partOfDomain) {
        $inv = Get-AdDcInventory
        if ($null -eq $inv) { Add-Limitation -Context $Context -Module 'ActiveDirectory' -Message 'Domain controller inventory could not be read over LDAP.' | Out-Null }
        else { $dcInventory = @($inv) }
    }
    $dcCount = if ($dcInventory.Count -gt 0) { $dcInventory.Count } else { $null }
    $replFailures = (@($replRows | Where-Object { $_.Direction -eq 'Destination' }) | Measure-Object -Property Fails -Sum).Sum

    $ctxRows.Add([pscustomobject]@{
        DomainName=$domainName; DomainRole=$roleName; PartOfDomain=$partOfDomain; IsDomainController=$isDc
        HoldsFsmoRole=$holdsFsmo; LogonServer=$logonServer; AdSite=($site -as [string]); DnsDomain=$env:USERDNSDOMAIN
        FsmoDetail=$fsmoDetail; DomainFunctionalLevel=$domainFuncLevel; ForestFunctionalLevel=$forestFuncLevel
        LdapSigningNotEnforced=$ldapSigningNotEnforced; LdapChannelBindingNotEnforced=$ldapChannelBindingNotEnforced
        DomainControllerCount=$dcCount; IsOnlyDomainController=[bool]($isDc -and $dcCount -eq 1)
        FsmoRolesHeld=@($fsmoRows | Where-Object { $_.HeldByThisServer }).Count; HoldsAllFsmoRoles=[bool](@($fsmoRows | Where-Object { $_.HeldByThisServer }).Count -ge 5)
        UnsupportedDcCount=@($dcInventory | Where-Object { $_.IsUnsupportedOs }).Count
        ReplicationFailures=$(if ($isDc -and $replRows.Count -gt 0) { [int]$replFailures } else { $null }); SysvolReplication=$sysvolReplication
        SysvolOnFrs=[bool]($sysvolReplication -match '^FRS')
    })

    # ---- DC discovery (member or DC) ----
    if ($partOfDomain) {
        try {
            $rd = Invoke-CommandLineSafe -FilePath 'nltest.exe' -Arguments @(("/dclist:" + $domainName)) -TimeoutSeconds 30
            if ($rd.Succeeded) {
                foreach ($ln in ($rd.StdOut -split "`r?`n")) {
                    if ($ln -match '^\s*([\w.-]+)\s+\[') { $dcs.Add([pscustomobject]@{ DcName=$Matches[1]; Item='DomainController'; Detail=$ln.Trim() }) }
                }
            }
        } catch { }
    }

    # ---- Applied GPOs via gpresult /r (read-only) ----
    try {
        # Computer scope only: user-scope RSOP describes whoever runs the script (and is empty
        # under SYSTEM), not the server. The old no-scope call also mislabelled every GPO 'User'.
        $rg = Invoke-CommandLineSafe -FilePath 'gpresult.exe' -Arguments @('/scope','computer','/r') -TimeoutSeconds 60
        if ($rg.Succeeded -and $rg.StdOut) {
            $lines = $rg.StdOut -split "`r?`n"
            $capture = $false; $sawHeader = $false; $scope = 'Computer'
            foreach ($ln in $lines) {
                if ($ln -match 'Applied Group Policy Objects') { $capture = $true; $sawHeader = $true; continue }
                if ($capture) {
                    if ($ln.Trim() -match '^-{3,}') { continue }
                    if ([string]::IsNullOrWhiteSpace($ln)) { $capture = $false; continue }
                    if ($ln -match 'not have|N/A|The following') { $capture = $false; continue }
                    $gpos.Add([pscustomobject]@{ Scope=$scope; PolicyName=$ln.Trim() })
                }
            }
            if (-not $sawHeader) {
                # gpresult can exit 0 with no "Applied Group Policy Objects" section at all - e.g.
                # "does not have RSoP data" (seen on a real 2012 R2 box even right after a
                # successful gpupdate /force) - as distinct from a genuine zero-GPO result, which
                # still prints the header followed by "N/A". Surface the tool's own first line
                # instead of silently reporting nothing.
                $firstLine = ($lines | Where-Object { $_ -match '\S' } | Select-Object -First 1)
                Add-Limitation -Context $Context -Module 'ActiveDirectory' -Message ("gpresult produced no Applied Group Policy Objects section: {0}" -f $firstLine) | Out-Null
            }
        } else {
            Add-Limitation -Context $Context -Module 'ActiveDirectory' -Message 'gpresult did not return applied GPOs (may require user context / elevation).' | Out-Null
        }
    } catch { Add-Limitation -Context $Context -Module 'ActiveDirectory' -Message 'gpresult failed.' -Reason $_.Exception.Message | Out-Null }

    return ,@{ DomainContext=@($ctxRows); AppliedGroupPolicy=@($gpos); DomainControllerDiscovery=@($dcs); AdDomainControllers=@($dcInventory); AdFsmoRoles=@($fsmoRows); AdReplicationSummary=@($replRows); AdHealthChecks=@($health) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'DomainContext'             -Description 'Domain membership and directory role context.' -Rows (& $get 'DomainContext')             -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'AppliedGroupPolicy'        -Description 'Applied Group Policy Objects (gpresult).'      -Rows (& $get 'AppliedGroupPolicy')        -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'DomainControllerDiscovery' -Description 'Domain controller discovery.'                  -Rows (& $get 'DomainControllerDiscovery') -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'AdDomainControllers'  -Description 'Every DC in the domain (LDAP): OS, site, GC, read-only, support status.' -Rows (& $get 'AdDomainControllers') -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'AdFsmoRoles'          -Description 'FSMO role holders (netdom query fsmo, DCs only).' -Rows (& $get 'AdFsmoRoles') -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'AdReplicationSummary' -Description 'repadmin /replsummary per DSA (DCs only).' -Rows (& $get 'AdReplicationSummary') -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'AdHealthChecks'       -Description 'dcdiag /q failures (DCs, Deep mode only).' -Rows (& $get 'AdHealthChecks') -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','ConvertTo-AdFunctionalLevelName','Test-AdDcOsUnsupported','ConvertFrom-NetdomFsmo','ConvertFrom-RepadminReplSummary','Get-AdDcInventory'
