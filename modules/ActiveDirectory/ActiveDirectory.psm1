<#
    ActiveDirectory.psm1 - domain context and (if a DC) directory role details (read-only).
    Produces: DomainContext, AppliedGroupPolicy, DomainControllerDiscovery.
    Uses built-in methods first; uses the ActiveDirectory module only if present.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='ActiveDirectory'; DisplayName='Active Directory / Domain Context'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('DomainContext','AppliedGroupPolicy','DomainControllerDiscovery')
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
    $names = @{ 0='Windows2000'; 1='Windows2003Interim'; 2='Windows2003'; 3='Windows2008'; 4='Windows2008R2'; 5='Windows2012'; 6='Windows2012R2'; 7='Windows2016' }
    $n = 0
    if ([int]::TryParse([string]$Level, [ref]$n) -and $names.ContainsKey($n)) { return $names[$n] }
    return ("Level{0}" -f $Level)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $ctxRows = [System.Collections.Generic.List[object]]::new()
    $gpos = [System.Collections.Generic.List[object]]::new()
    $dcs = [System.Collections.Generic.List[object]]::new()

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

    $ctxRows.Add([pscustomobject]@{
        DomainName=$domainName; DomainRole=$roleName; PartOfDomain=$partOfDomain; IsDomainController=$isDc
        HoldsFsmoRole=$holdsFsmo; LogonServer=$logonServer; AdSite=($site -as [string]); DnsDomain=$env:USERDNSDOMAIN
        FsmoDetail=$fsmoDetail; DomainFunctionalLevel=$domainFuncLevel; ForestFunctionalLevel=$forestFuncLevel
        LdapSigningNotEnforced=$ldapSigningNotEnforced; LdapChannelBindingNotEnforced=$ldapChannelBindingNotEnforced
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

    return ,@{ DomainContext=@($ctxRows); AppliedGroupPolicy=@($gpos); DomainControllerDiscovery=@($dcs) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'DomainContext'             -Description 'Domain membership and directory role context.' -Rows (& $get 'DomainContext')             -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'AppliedGroupPolicy'        -Description 'Applied Group Policy Objects (gpresult).'      -Rows (& $get 'AppliedGroupPolicy')        -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
    Add-DataSet -Context $Context -Name 'DomainControllerDiscovery' -Description 'Domain controller discovery.'                  -Rows (& $get 'DomainControllerDiscovery') -Visibility 'Internal' -SourceModule 'ActiveDirectory' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','ConvertTo-AdFunctionalLevelName'
