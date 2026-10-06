<#
    SecurityPosture.psm1 - security configuration snapshot (read-only).
    Produces: SecurityPosture, LocalUsers, LocalGroups, LocalGroupMembers,
              FirewallProfiles, UserRightsAssignments, LocalAccountsWithNonExpiringPasswords,
              SensitiveUserRightsGrants.
    NEVER collects password hashes, keys, or secrets.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='SecurityPosture'; DisplayName='Security Posture'; Category='Security'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('SecurityPosture','LocalUsers','LocalGroups','LocalGroupMembers','FirewallProfiles','UserRightsAssignments','LocalAccountsWithNonExpiringPasswords','SensitiveUserRightsGrants')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $lim = @()
    if (-not $Context.IsAdmin) { $lim = @('Not elevated: some security posture data may be incomplete.') }
    [pscustomobject]@{ ModuleName='SecurityPosture'; CanRun=$true; Status='Ready'; Reason=''; Limitations=$lim }
}

function Get-LocalAdministrators {
    $members = [System.Collections.Generic.List[object]]::new()
    try {
        if (Get-CommandAvailable -Name 'Get-LocalGroupMember') {
            $grp = $null
            try { $grp = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue } catch { }
            if (-not $grp) { try { $grp = Get-LocalGroup -Name 'Administrators' -ErrorAction SilentlyContinue } catch { } }
            if ($grp) {
                foreach ($m in (Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue)) {
                    $members.Add([pscustomobject]@{ Group='Administrators'; Member=$m.Name; ObjectClass=[string]$m.ObjectClass; PrincipalSource=[string]$m.PrincipalSource })
                }
            }
        }
        if ($members.Count -eq 0) {
            $r = Invoke-CommandLineSafe -FilePath 'net.exe' -Arguments @('localgroup','Administrators') -TimeoutSeconds 30
            if ($r.Succeeded) {
                $lines = $r.StdOut -split "`r?`n"
                $capture = $false
                foreach ($ln in $lines) {
                    if ($ln -match '^-{3,}') { $capture = $true; continue }
                    if ($capture) {
                        if ($ln -match 'command completed') { break }
                        if ($ln.Trim()) { $members.Add([pscustomobject]@{ Group='Administrators'; Member=$ln.Trim(); ObjectClass=''; PrincipalSource='' }) }
                    }
                }
            }
        }
    } catch { }
    return ,@($members)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $users = [System.Collections.Generic.List[object]]::new()
    $groups = [System.Collections.Generic.List[object]]::new()
    $members = [System.Collections.Generic.List[object]]::new()
    $fwProfiles = [System.Collections.Generic.List[object]]::new()
    $rights = [System.Collections.Generic.List[object]]::new()

    # ---- Local users / groups ----
    try {
        if (Get-CommandAvailable -Name 'Get-LocalUser') {
            foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue)) {
                $users.Add([pscustomobject]@{ Name=$u.Name; Enabled=$u.Enabled; LastLogon=(Normalize-DateTime $u.LastLogon); PasswordLastSet=(Normalize-DateTime $u.PasswordLastSet); PasswordNeverExpires=$u.PasswordNeverExpires; Description=$u.Description })
            }
        } else {
            foreach ($u in (Invoke-CimSafe -ClassName 'Win32_UserAccount' -Filter 'LocalAccount=True')) {
                $users.Add([pscustomobject]@{ Name=$u.Name; Enabled=(-not $u.Disabled); LastLogon=$null; PasswordLastSet=$null; PasswordNeverExpires=$u.PasswordExpires -eq $false; Description=$u.Description })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'SecurityPosture' -Message 'Local user enumeration failed.' -Reason $_.Exception.Message | Out-Null }

    try {
        if (Get-CommandAvailable -Name 'Get-LocalGroup') {
            foreach ($g in (Get-LocalGroup -ErrorAction SilentlyContinue)) { $groups.Add([pscustomobject]@{ Name=$g.Name; Description=$g.Description }) }
        } else {
            # LocalAccounts module needs WMF 5.1+ (e.g. absent on 2012 R2). Win32_Group is CIM-based.
            foreach ($g in (Invoke-CimSafe -ClassName 'Win32_Group' -Filter 'LocalAccount = True')) {
                $groups.Add([pscustomobject]@{ Name=[string]$g.Name; Description=[string]$g.Description })
            }
        }
    } catch { }

    $admins = Get-LocalAdministrators
    foreach ($a in $admins) { $members.Add($a) }
    # A few other sensitive groups
    foreach ($gname in @('Remote Desktop Users','Backup Operators','Hyper-V Administrators')) {
        try {
            if (Get-CommandAvailable -Name 'Get-LocalGroupMember') {
                foreach ($m in (Get-LocalGroupMember -Group $gname -ErrorAction SilentlyContinue)) {
                    $members.Add([pscustomobject]@{ Group=$gname; Member=$m.Name; ObjectClass=[string]$m.ObjectClass; PrincipalSource=[string]$m.PrincipalSource })
                }
            } else {
                # Same LocalAccounts-module gap as Get-LocalAdministrators; same net.exe fallback.
                $r = Invoke-CommandLineSafe -FilePath 'net.exe' -Arguments @('localgroup', "`"$gname`"") -TimeoutSeconds 30
                if ($r.Succeeded) {
                    $capture = $false
                    foreach ($ln in ($r.StdOut -split "`r?`n")) {
                        if ($ln -match '^-{3,}') { $capture = $true; continue }
                        if ($capture) {
                            if ($ln -match 'command completed') { break }
                            if ($ln.Trim()) { $members.Add([pscustomobject]@{ Group=$gname; Member=$ln.Trim(); ObjectClass=''; PrincipalSource='' }) }
                        }
                    }
                }
            }
        } catch { }
    }

    # ---- Firewall profiles ----
    try {
        if (Get-CommandAvailable -Name 'Get-NetFirewallProfile') {
            foreach ($p in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                $fwProfiles.Add([pscustomobject]@{ Name=$p.Name; Enabled=([bool]$p.Enabled); DefaultInbound=[string]$p.DefaultInboundAction; DefaultOutbound=[string]$p.DefaultOutboundAction })
            }
        } else {
            foreach ($prof in @('DomainProfile','StandardProfile','PublicProfile')) {
                $v = Get-RegistryValueSafe -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{0}" -f $prof) -Name 'EnableFirewall'
                $nm = switch ($prof) { 'DomainProfile' {'Domain'} 'StandardProfile' {'Private'} 'PublicProfile' {'Public'} }
                $fwProfiles.Add([pscustomobject]@{ Name=$nm; Enabled=([bool]($v -eq 1)); DefaultInbound=''; DefaultOutbound='' })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'SecurityPosture' -Message 'Firewall profile query failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- User rights (optional, read-only export via secedit) ----
    try {
        $rawDir = $Context.Paths['Raw']
        if ($rawDir -and (Get-CommandAvailable -Name 'secedit.exe')) {
            $cfg = Join-Path $rawDir 'userrights.inf'
            $r = Invoke-CommandLineSafe -FilePath 'secedit.exe' -Arguments @('/export','/cfg',("`"$cfg`""),'/areas','USER_RIGHTS') -TimeoutSeconds 60
            if ((Test-Path $cfg)) {
                foreach ($ln in (Get-Content -LiteralPath $cfg -ErrorAction SilentlyContinue)) {
                    if ($ln -match '^(Se\w+)\s*=\s*(.+)$') { $rights.Add([pscustomobject]@{ Right=$Matches[1]; Principals=$Matches[2].Trim() }) }
                }
            } else { Add-Limitation -Context $Context -Module 'SecurityPosture' -Message 'User rights export not available.' | Out-Null }
        }
    } catch { Add-Limitation -Context $Context -Module 'SecurityPosture' -Message 'User rights collection failed.' -Reason $_.Exception.Message | Out-Null }

    # ---- Posture summary (one row) ----
    $posture = New-PostureRow -Context $Context -FirewallProfiles $fwProfiles -AdminCount $admins.Count -Users $users

    # ---- Derived datasets for findings the generic rule engine can't express directly ----
    $nonExpiring = Get-NonExpiringPasswordAccounts -Users $users
    $sensitiveGrants = Get-SensitiveUserRightsGrants -Rights $rights

    return ,@{
        SecurityPosture=@($posture); LocalUsers=@($users); LocalGroups=@($groups); LocalGroupMembers=@($members)
        FirewallProfiles=@($fwProfiles); UserRightsAssignments=@($rights)
        LocalAccountsWithNonExpiringPasswords=@($nonExpiring); SensitiveUserRightsGrants=@($sensitiveGrants)
    }
}

function Get-NonExpiringPasswordAccounts {
    <#
        Enabled local accounts whose password never expires. Split out as its own pure function
        (rather than an inline Where-Object in Invoke-DiscoveryCollection) specifically so it's
        directly testable - the RiskEngine's condition language only ever tests ONE field per
        row (see Test-RuleCondition in RiskEngine.psm1), so it cannot express "Enabled=true AND
        PasswordNeverExpires=true" as a single declarative rule. The collector does that
        filtering here instead (same pattern RiskEngine.psm1's own doc-comment endorses for
        ConfigDependencyHints) and exposes only the already-filtered rows; a plain
        datasetNotEmpty rule then does the rest.
    #>
    param([object[]]$Users = @())
    return ,@($Users | Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
}

function Get-SensitiveUserRightsGrants {
    <#
        Sensitive rights where a grant to anything beyond the expected built-in set is worth a
        human look - not an exhaustive privilege list, just the ones most directly tied to local
        privilege escalation or credential theft if handed to the wrong account. Baseline is
        WELL-KNOWN SIDS, not friendly names - confirmed live that `secedit /export /areas
        USER_RIGHTS` renders built-in groups as raw SIDs (e.g. "*S-1-5-32-544" for
        Administrators), only resolving to a plain name for an actual custom/domain account (a
        real service account name showed up unresolved in the same export). That distinction is
        exactly what makes this check work: anything that ISN'T one of these well-known SIDs is,
        by construction, a real named principal worth a second look. Same "one field per rule"
        engine limitation as Get-NonExpiringPasswordAccounts above is why this filtering lives
        in the collector rather than risk-rules.json.
    #>
    param([object[]]$Rights = @())
    $sensitiveRightsBaseline = @{
        'SeDebugPrivilege'         = @('S-1-5-32-544')                                 # Administrators
        'SeTakeOwnershipPrivilege' = @('S-1-5-32-544')                                 # Administrators
        'SeLoadDriverPrivilege'    = @('S-1-5-32-544', 'S-1-5-32-550')                 # Administrators, Print Operators
        'SeTcbPrivilege'           = @()                                               # nobody, by default
        'SeBackupPrivilege'        = @('S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-551') # Administrators, Server Operators, Backup Operators
        'SeRestorePrivilege'       = @('S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-551')
    }
    $sensitiveGrants = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Rights) {
        if (-not $sensitiveRightsBaseline.ContainsKey($r.Right)) { continue }
        $expected = $sensitiveRightsBaseline[$r.Right]
        $principals = @($r.Principals -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
        $unexpected = @($principals | Where-Object { $expected -notcontains $_ })
        if ($unexpected.Count -gt 0) {
            $sensitiveGrants.Add([pscustomobject]@{ Right = $r.Right; UnexpectedPrincipals = ($unexpected -join ', '); AllPrincipals = $r.Principals })
        }
    }
    return ,@($sensitiveGrants)
}

function New-PostureRow {
    param([object]$Context, $FirewallProfiles, [int]$AdminCount, [object[]]$Users = @())
    $regGet = { param($p,$n) Get-RegistryValueSafe -Path $p -Name $n }

    # SMBv1
    $smb1 = $false
    try {
        if (Get-CommandAvailable -Name 'Get-SmbServerConfiguration') { $smb1 = [bool]((Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol) }
        else { $v = & $regGet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'; if ($null -ne $v) { $smb1 = [bool]($v -ne 0) } }
    } catch { }

    # RDP + NLA
    $fDeny = & $regGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $rdpEnabled = ($fDeny -eq 0)
    $ua = & $regGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    $nla = ($ua -eq 1)

    # Defender / AV / EDR
    $defender = $false
    try { if (Get-CommandAvailable -Name 'Get-MpComputerStatus') { $st = Get-MpComputerStatus -ErrorAction SilentlyContinue; $defender = [bool]($st.AntivirusEnabled -or $st.RealTimeProtectionEnabled) } } catch { }
    $thirdAv = $false
    try { foreach ($av in (Invoke-CimSafe -ClassName 'AntiVirusProduct' -Namespace 'root/SecurityCenter2')) { if ($av.displayName -and $av.displayName -notmatch 'Defender') { $thirdAv = $true } } } catch { }
    $edrSvc = $false
    try {
        if ($Context.DataSets.Contains('Services')) {
            $edrSvc = (@($Context.DataSets['Services'].Rows | Where-Object { $_.DisplayName -match '(?i)SentinelOne|CrowdStrike|CSFalcon|Cylance|Carbon Black|Huntress|Sophos|Bitdefender|Defender for Endpoint|Sense' }).Count -gt 0)
        }
    } catch { }
    $anyAv = ($defender -or $thirdAv -or $edrSvc)

    # UAC
    $uac = (( & $regGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1)

    # TLS 1.0 / 1.1 (client+server 'Enabled' value; absent => OS default, report as unknown->assume enabled on older OS)
    $tls10 = Test-TlsProtocolEnabled -Protocol 'TLS 1.0'
    $tls11 = Test-TlsProtocolEnabled -Protocol 'TLS 1.1'

    # WinRM
    $winrm = $false
    try { $ws = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue; $winrm = ($ws -and $ws.Status -eq 'Running') } catch { }

    # LAPS
    $laps = $false
    try { if ((Test-RegistryPathSafe 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') -or (Test-RegistryPathSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS')) { $laps = $true } } catch { }

    # BitLocker
    $bl = $false
    try { if (Get-CommandAvailable -Name 'Get-BitLockerVolume') { $bl = (@(Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.ProtectionStatus -eq 'On' }).Count -gt 0) } } catch { }

    # Guest account - built-in, well-known name on every Windows install (may be renamed by
    # policy, but an unrenamed "Guest" is the common case and the one worth flagging cheaply).
    $guestEnabled = $false
    try { $guestEnabled = [bool](@($Users | Where-Object { $_.Name -eq 'Guest' -and $_.Enabled }).Count -gt 0) } catch { }

    # SMB signing (server side - this box acting as a file/print server for others, the
    # relevant direction for an MSP scoping THIS server). Same cmdlet-first/registry-fallback
    # shape as the SMBv1 check above; RequireSecuritySignature is the same property/value on
    # both surfaces.
    $smbSigningRequired = $false
    try {
        if (Get-CommandAvailable -Name 'Get-SmbServerConfiguration') { $smbSigningRequired = [bool]((Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature) }
        else { $v = & $regGet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'; if ($null -ne $v) { $smbSigningRequired = [bool]($v -ne 0) } }
    } catch { }

    # NTLM - LmCompatibilityLevel below 3 permits LM/NTLMv1, both long-deprecated and
    # crackable/relayable. Absent (not explicitly configured) is left $null and NOT flagged -
    # same "cannot confirm -> don't over-claim" contract Test-TlsProtocolEnabled already uses,
    # since the real OS default varies by version and this toolkit never assumes worse than it
    # can prove.
    $lmLevel = & $regGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    $ntlmLegacyAllowed = ($null -ne $lmLevel) -and ([int]$lmLevel -lt 3)

    [pscustomobject]@{
        Smb1Enabled=$smb1; RdpEnabled=$rdpEnabled; NlaEnabled=$nla; RdpEnabledNoNla=($rdpEnabled -and -not $nla)
        DefenderEnabled=$defender; ThirdPartyAvPresent=$thirdAv; AnyAvOrEdrDetected=$anyAv
        UacEnabled=$uac; Tls10Enabled=$tls10; Tls11Enabled=$tls11; WinRmEnabled=$winrm
        LapsDetected=$laps; BitLockerAnyProtected=$bl; LocalAdminCount=$AdminCount
        GuestAccountEnabled=$guestEnabled; SmbServerSigningRequired=$smbSigningRequired
        LmCompatibilityLevel=$(if ($null -ne $lmLevel) { [int]$lmLevel } else { $null }); NtlmLegacyCompatibilityAllowed=$ntlmLegacyAllowed
    }
}

function Test-TlsProtocolEnabled {
    param([string]$Protocol)
    try {
        $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
        $en = Get-RegistryValueSafe -Path $base -Name 'Enabled'
        if ($null -ne $en) { return [bool]($en -ne 0) }
        # Not explicitly configured -> cannot confirm; report false (NotDetected) to avoid over-claiming.
        return $false
    } catch { return $false }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'SecurityPosture'       -Description 'Security configuration snapshot (booleans + admin count).' -Rows (& $get 'SecurityPosture')       -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
    Add-DataSet -Context $Context -Name 'LocalUsers'            -Description 'Local user accounts (no hashes).'                        -Rows (& $get 'LocalUsers')            -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
    Add-DataSet -Context $Context -Name 'LocalGroups'           -Description 'Local groups.'                                          -Rows (& $get 'LocalGroups')           -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
    Add-DataSet -Context $Context -Name 'LocalGroupMembers'     -Description 'Members of sensitive local groups.'                     -Rows (& $get 'LocalGroupMembers')     -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
    Add-DataSet -Context $Context -Name 'FirewallProfiles'      -Description 'Windows Firewall profile states.'                       -Rows (& $get 'FirewallProfiles')      -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
    Add-DataSet -Context $Context -Name 'UserRightsAssignments' -Description 'User rights assignments (secedit export).'              -Rows (& $get 'UserRightsAssignments') -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
    Add-DataSet -Context $Context -Name 'LocalAccountsWithNonExpiringPasswords' -Description 'Enabled local accounts with a non-expiring password.' -Rows (& $get 'LocalAccountsWithNonExpiringPasswords') -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
    Add-DataSet -Context $Context -Name 'SensitiveUserRightsGrants' -Description 'Sensitive user rights (SeDebugPrivilege and similar) granted beyond the expected built-in accounts.' -Rows (& $get 'SensitiveUserRightsGrants') -Visibility 'Internal' -SourceModule 'SecurityPosture' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','New-PostureRow','Test-TlsProtocolEnabled','Get-LocalAdministrators','Get-NonExpiringPasswordAccounts','Get-SensitiveUserRightsGrants'
