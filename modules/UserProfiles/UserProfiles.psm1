<#
    UserProfiles.psm1 - user-context dependencies the machine-context collectors miss.

    Produces: UserProfiles, MappedDrives, UserOdbcDsns, LogonScripts.

    Why this module exists: several existing collectors record a limitation that
    user-context data (mapped drives, per-user ODBC DSNs, HKCU installs) is invisible
    when discovery runs as SYSTEM - but nothing ever went and got it. The loaded and
    unloaded user hives under HKEY_USERS are readable, offline, without impersonating
    anyone, so the dependency can be recovered instead of just disclaimed.

    Profile SIZING is gated behind -IncludeUserProfiles because walking every profile
    on an RDS host is the same expensive I/O as the deep share crawl. Without the
    switch the module still enumerates profiles and reads their hives; it just does
    not measure them.

    Reads only. Never loads, unloads, modifies, or deletes a user hive that was not
    already loaded, and never touches profile contents.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='UserProfiles'; DisplayName='User Profiles & User-Context Dependencies'; Category='System'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('UserProfiles','MappedDrives','UserOdbcDsns','LogonScripts')
        ProducesRisks=$true; ProducesFollowUpQuestions=$true; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    $lim = @()
    if (-not $Context.IsAdmin) { $lim = @('Not elevated: profiles belonging to other users, and their registry hives, will not be readable.') }
    [pscustomobject]@{ ModuleName='UserProfiles'; CanRun=$true; Status='Ready'; Reason=''; Limitations=$lim }
}

function Get-UpSidIsRealUser {
    <# Filters out the built-in service SIDs so the output is actual people. #>
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
    if ($Sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')) { return $false }   # SYSTEM / LOCAL SERVICE / NETWORK SERVICE
    if ($Sid -match '_Classes$') { return $false }
    return ($Sid -match '^S-1-5-21-')
}

function Get-UpLoadedUserHives {
    <# Returns the SIDs whose hives are currently loaded under HKEY_USERS. #>
    param()
    $sids = [System.Collections.Generic.List[string]]::new()
    try {
        if (-not (Test-Path -LiteralPath 'Registry::HKEY_USERS')) { return ,@($sids) }
        foreach ($k in (Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
            if (Get-UpSidIsRealUser -Sid $k.PSChildName) { [void]$sids.Add($k.PSChildName) }
        }
    } catch { }
    return ,@($sids)
}

function Invoke-DiscoveryCollection {
    param([object]$Context)

    $profiles = [System.Collections.Generic.List[object]]::new()
    $drives   = [System.Collections.Generic.List[object]]::new()
    $dsns     = [System.Collections.Generic.List[object]]::new()
    $scripts  = [System.Collections.Generic.List[object]]::new()

    $measure = ([bool]$Context.Parameters['IncludeUserProfiles'])
    $loaded  = @(Get-UpLoadedUserHives)

    # ---- Profiles -----------------------------------------------------------
    try {
        foreach ($p in (Invoke-CimSafe -ClassName 'Win32_UserProfile')) {
            try {
                $sid = [string]$p.SID
                if (-not (Get-UpSidIsRealUser -Sid $sid)) { continue }

                $account = ''
                try {
                    $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                } catch { $account = '<unresolved SID>' }

                $sizeGB = $null
                $fileCount = $null
                if ($measure -and $p.LocalPath -and (Test-Path -LiteralPath $p.LocalPath)) {
                    try {
                        $files = @(Get-ChildItem -LiteralPath $p.LocalPath -File -Recurse -ErrorAction SilentlyContinue)
                        $fileCount = $files.Count
                        $sizeGB = Convert-BytesToGB (($files | Measure-Object -Property Length -Sum).Sum)
                    } catch { }
                }

                $profiles.Add([pscustomobject]@{
                    Account          = $account
                    Sid              = $sid
                    LocalPath        = [string]$p.LocalPath
                    IsRoaming        = [bool]$p.RoamingConfigured
                    RoamingPath      = [string]$p.RoamingPath
                    IsLoaded         = [bool]($loaded -contains $sid)
                    LastUseTime      = (Normalize-DateTime $p.LastUseTime)
                    IsSpecial        = [bool]$p.Special
                    Status           = [string]$p.Status
                    SizeGB           = $sizeGB
                    FileCount        = $fileCount
                    SizeMeasured     = $measure
                })

                if ($p.RoamingConfigured -and $p.RoamingPath) {
                    Add-DependencyEdge -Context $Context -SourceType 'UserProfile' -SourceName $account `
                        -DependencyType 'RoamsTo' -Target ([string]$p.RoamingPath) -Evidence 'Roaming profile path' `
                        -Confidence 'Confirmed' -SourceDataset 'UserProfiles' -ProjectImpact 'Data Migration' `
                        -ValidationQuestion 'Does the roaming profile share survive the migration?' | Out-Null
                }
            } catch { }
        }
    } catch {
        Add-Limitation -Context $Context -Module 'UserProfiles' -Message 'User profile enumeration failed.' -Reason $_.Exception.Message | Out-Null
    }

    if (-not $measure -and $profiles.Count -gt 0) {
        Add-Limitation -Context $Context -Module 'UserProfiles' `
            -Message 'Profile sizes were not measured (enable with -IncludeUserProfiles).' `
            -Impact 'Profile data volume unknown' | Out-Null
    }

    # ---- Mapped drives + user ODBC DSNs + logon scripts, per loaded hive ----
    # A drive letter mapped by a user is the single most common undocumented reason a
    # server rename breaks someone's morning, and it is invisible to every
    # machine-context collector in this toolkit.
    foreach ($sid in $loaded) {
        $account = ''
        try { $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $account = $sid }

        # Mapped network drives
        try {
            $netPath = "Registry::HKEY_USERS\$sid\Network"
            if (Test-Path -LiteralPath $netPath) {
                foreach ($k in (Get-ChildItem -LiteralPath $netPath -ErrorAction SilentlyContinue)) {
                    $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                    if ($props -and $props.RemotePath) {
                        $drives.Add([pscustomobject]@{
                            Account=$account; DriveLetter=$k.PSChildName; RemotePath=[string]$props.RemotePath
                            ProviderName=[string]$props.ProviderName; UserName=[string]$props.UserName
                        })
                        Add-DependencyEdge -Context $Context -SourceType 'MappedDrive' -SourceName ("{0}:{1}" -f $account, $k.PSChildName) `
                            -DependencyType 'ConnectsTo' -Target ([string]$props.RemotePath) -Evidence 'HKU Network mapping' `
                            -Confidence 'Confirmed' -SourceDataset 'MappedDrives' -ProjectImpact 'Cutover Complexity' `
                            -ValidationQuestion 'Is this mapped path referenced by server name, and does that name change?' | Out-Null
                    }
                }
            }
        } catch { }

        # Per-user ODBC DSNs - the 32-bit ones in particular are easy to miss and are
        # exactly where a legacy line-of-business app hides its database target.
        foreach ($odbcRel in @('Software\ODBC\ODBC.INI', 'Software\WOW6432Node\ODBC\ODBC.INI')) {
            try {
                $odbcPath = "Registry::HKEY_USERS\$sid\$odbcRel"
                if (-not (Test-Path -LiteralPath $odbcPath)) { continue }
                $bitness = if ($odbcRel -match 'WOW6432Node') { '32' } else { '64' }
                foreach ($k in (Get-ChildItem -LiteralPath $odbcPath -ErrorAction SilentlyContinue)) {
                    if ($k.PSChildName -eq 'ODBC Data Sources') { continue }
                    $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                    $dsns.Add([pscustomobject]@{
                        Account=$account; DsnName=$k.PSChildName; Driver=[string]$props.Driver
                        Server=[string]$props.Server; Database=[string]$props.Database; Scope='User'; Bitness=$bitness
                    })
                    if ($props.Server) {
                        Add-DependencyEdge -Context $Context -SourceType 'ODBC DSN (user)' -SourceName $k.PSChildName `
                            -DependencyType 'ConnectsTo' -Target ("{0}/{1}" -f $props.Server, $props.Database) -Evidence 'Per-user ODBC DSN' `
                            -Confidence 'Confirmed' -SourceDataset 'UserOdbcDsns' -ProjectImpact 'Data Migration' `
                            -ValidationQuestion 'Which application uses this user DSN, and does its target change after migration?' | Out-Null
                    }
                }
            } catch { }
        }
    }

    if ($loaded.Count -eq 0 -and $profiles.Count -gt 0) {
        Add-Limitation -Context $Context -Module 'UserProfiles' `
            -Message 'No user registry hives were loaded at scan time, so mapped drives and per-user DSNs could not be read.' `
            -Impact 'User-context dependencies under-reported' | Out-Null
        Add-Unknown -Context $Context -Unknown 'Mapped drives and per-user ODBC DSNs could not be enumerated (no user hives loaded).' `
            -WhyItMatters 'Users and applications frequently reach this server through a mapped drive that nothing on the server records.' `
            -Module 'UserProfiles' -RecommendedValidationQuestion 'Do users map drives to this server, and are any of those paths hardcoded in applications or shortcuts?' | Out-Null
    }

    # ---- Startup / logon script indicators ---------------------------------
    try {
        $startupPaths = @(
            (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'),
            (Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Scripts\Startup'),
            (Join-Path $env:SystemRoot 'System32\GroupPolicy\User\Scripts\Logon')
        ) + @(Get-ChildItem -Path (Join-Path $env:SystemRoot 'SYSVOL\sysvol\*\scripts') -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)   # NETLOGON on a DC
        # Users whose AD scriptPath points at a logon script (DC only; ADSI, so no AD module needed).
        try {
            if ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole -ge 4) {
                $ds = [adsisearcher]'(&(objectCategory=person)(objectClass=user)(scriptPath=*))'
                $ds.PropertiesToLoad.AddRange(@('samaccountname','scriptpath')); $ds.PageSize = 500
                foreach ($u in $ds.FindAll()) {
                    $scripts.Add([pscustomobject]@{ Scope='AD user scriptPath'; Name=[string]$u.Properties['scriptpath'][0]; Path=('AD user: ' + [string]$u.Properties['samaccountname'][0]); LastWriteTime=''; SizeKB='' })
                }
            }
        } catch { }
        foreach ($sp in $startupPaths) {
            if (-not $sp -or -not (Test-Path -LiteralPath $sp)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $sp -File -ErrorAction SilentlyContinue)) {
                $scripts.Add([pscustomobject]@{
                    Scope=(Split-Path $sp -Leaf); Name=$f.Name; Path=$f.FullName
                    LastWriteTime=(Normalize-DateTime $f.LastWriteTime); SizeKB=([math]::Round($f.Length/1KB,1))
                })
            }
        }
    } catch { }

    return ,@{
        UserProfiles=@($profiles); MappedDrives=@($drives); UserOdbcDsns=@($dsns); LogonScripts=@($scripts)
    }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'UserProfiles' -Description 'Local/roaming user profiles on this server.'                -Rows (& $get 'UserProfiles') -Visibility 'Internal' -SourceModule 'UserProfiles' | Out-Null
    Add-DataSet -Context $Context -Name 'MappedDrives' -Description 'Drive letters mapped by users (from loaded HKU hives).'     -Rows (& $get 'MappedDrives') -Visibility 'Both'     -SourceModule 'UserProfiles' | Out-Null
    Add-DataSet -Context $Context -Name 'UserOdbcDsns' -Description 'Per-user ODBC DSNs (32/64-bit) from loaded HKU hives.'      -Rows (& $get 'UserOdbcDsns') -Visibility 'Internal' -SourceModule 'UserProfiles' | Out-Null
    Add-DataSet -Context $Context -Name 'LogonScripts' -Description 'Startup / logon script files present on this server.'       -Rows (& $get 'LogonScripts') -Visibility 'Internal' -SourceModule 'UserProfiles' | Out-Null
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        if ($Context.DataSets.Contains('MappedDrives') -and @($Context.DataSets['MappedDrives'].Rows).Count -gt 0) {
            Add-FollowUpQuestion -Context $Context -Category 'Mapped drives / UNC' -Module 'UserProfiles' -Audience 'Both' `
                -Question 'Mapped drives pointing at network paths were found in user profiles on this server. Who maintains those mappings, and are they created by logon script or Group Policy?' | Out-Null
        }
        if ($Context.DataSets.Contains('UserProfiles') -and @($Context.DataSets['UserProfiles'].Rows).Count -gt 3) {
            Add-FollowUpQuestion -Context $Context -Category 'Daily/periodic usage' -Module 'UserProfiles' -Audience 'ClientSafe' `
                -Question 'Several people have profiles on this server, which suggests they log on to it directly. Who uses it interactively, and what do they do there?' | Out-Null
        }
    } catch { }
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-UpSidIsRealUser','Get-UpLoadedUserHives'
