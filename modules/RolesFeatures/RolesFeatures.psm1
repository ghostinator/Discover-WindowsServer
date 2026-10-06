<#
    RolesFeatures.psm1
    Collector module: Windows Roles and Features (System category).

    Owns the canonical 'RolesFeatures' dataset consumed by the RiskEngine
    (config/risk-rules.json uses anyRowFieldMatches on the 'Name' field) and by
    the synthesis/report layers (Test-RoleFeaturePresent / Get-LikelyServerFunctions
    in Output.psm1). Both of those match on Name/DisplayName WITHOUT inspecting
    InstallState, so this module places ONLY installed roles/features into the
    canonical dataset. Notable roles that exist in the catalog but are NOT installed
    are surfaced separately in 'AvailableRolesFeatures' (informational, Internal)
    so they never cause false-positive role-presence findings.

    Enumeration strategy (read-only, defensive):
      1. Get-WindowsFeature            (ServerManager; Server SKUs) - preferred,
                                        already uses canonical Windows role Names.
      2. Get-WindowsOptionalFeature -Online  (client SKU / Server Core edge).
      3. dism.exe /online /get-features /format:table  (READ-ONLY get-features only).

    Design rules: Windows PowerShell 5.1 compatible; read-only; no Set-StrictMode;
    every collection block wrapped in try/catch; generic collections via ::new().
#>

# ---------------------------------------------------------------------------
# Notable server-role catalog. Canonical Windows feature Names / fragments.
# Used to (a) curate the informational not-installed list and (b) build the
# consolidated detected-functions summary finding.
# ---------------------------------------------------------------------------
$script:RolesFeatures_NotableRolePatterns = @(
    'AD-Domain-Services','ADDS-Domain-Controller','^DNS$','^DHCP$',
    'AD-Certificate','ADCS','^Web-Server$','^Hyper-V$',
    'FS-FileServer','FS-DFS-Namespace','FS-DFS-Replication','FS-iSCSITarget-Server',
    'Print-Services','^Print-Server$','RDS-','^Remote-Desktop-Services$',
    '^NPAS$','Failover-Clustering','^WDS$','WDS-Deployment',
    'DirectAccess-VPN','Routing','Remote-Access',
    'AD-Federation-Services','^ADFS','^ADLDS$','UpdateServices'
)

# Ordered pattern -> friendly server-function label (regex; -match is
# case-insensitive by default in PowerShell).
$script:RolesFeatures_FunctionMap = @(
    [pscustomobject]@{ Pattern = 'AD-Domain-Services|ADDS-Domain-Controller'; Label = 'Active Directory Domain Services (Domain Controller)' }
    [pscustomobject]@{ Pattern = '^DNS$';                                     Label = 'DNS Server' }
    [pscustomobject]@{ Pattern = '^DHCP$';                                    Label = 'DHCP Server' }
    [pscustomobject]@{ Pattern = 'AD-Certificate|ADCS';                       Label = 'Active Directory Certificate Services (CA)' }
    [pscustomobject]@{ Pattern = '^Web-Server$';                              Label = 'IIS Web Server' }
    [pscustomobject]@{ Pattern = '^Hyper-V$';                                 Label = 'Hyper-V Virtualization Host' }
    [pscustomobject]@{ Pattern = '^FS-FileServer$';                           Label = 'File Server' }
    [pscustomobject]@{ Pattern = 'FS-DFS';                                    Label = 'DFS (Namespaces / Replication)' }
    [pscustomobject]@{ Pattern = 'Print-Services|^Print-Server$';             Label = 'Print Services' }
    [pscustomobject]@{ Pattern = 'RDS-|^Remote-Desktop-Services$';            Label = 'Remote Desktop Services (RDS)' }
    [pscustomobject]@{ Pattern = '^NPAS$';                                    Label = 'Network Policy and Access Services (NPS / RADIUS)' }
    [pscustomobject]@{ Pattern = 'Failover-Clustering';                       Label = 'Failover Clustering' }
    [pscustomobject]@{ Pattern = 'UpdateServices';                            Label = 'Windows Server Update Services (WSUS)' }
    [pscustomobject]@{ Pattern = 'AD-Federation-Services|^ADFS';              Label = 'Active Directory Federation Services (ADFS)' }
    [pscustomobject]@{ Pattern = 'Remote-Access|DirectAccess-VPN|^Routing$';  Label = 'Remote Access (VPN / DirectAccess / Routing)' }
)

#region Helpers ---------------------------------------------------------------

function ConvertFrom-DismFeatureText {
    <#
        Parses the output of 'dism /online /get-features'. Handles both the
        table format ('Feature Name | State') and the classic pair format
        ('Feature Name : X' followed by 'State : Y'). Always returns an array.
    #>
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    $items = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@($items) }
    $lines = $Text -split "`r?`n"

    # Attempt 1: table format (columns separated by '|').
    foreach ($line in $lines) {
        if ($line -notmatch '\|') { continue }
        $parts = $line -split '\|'
        if ($parts.Count -lt 2) { continue }
        $name  = $parts[0].Trim()
        $state = $parts[1].Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name -match '^-+$' -or $state -match '^-+$') { continue }
        if ($name -match '^Feature Name$') { continue }
        if ($state -notmatch '^(Enabled|Disabled)') { continue }
        $items.Add([pscustomobject]@{ Name = $name; State = $state })
    }
    if ($items.Count -gt 0) { return ,@($items) }

    # Attempt 2: 'Feature Name :' / 'State :' pair format.
    $currentName = $null
    foreach ($line in $lines) {
        if ($line -match '^\s*Feature Name\s*:\s*(.+?)\s*$') { $currentName = $Matches[1].Trim(); continue }
        if ($line -match '^\s*State\s*:\s*(.+?)\s*$' -and $currentName) {
            $items.Add([pscustomobject]@{ Name = $currentName; State = $Matches[1].Trim() })
            $currentName = $null
        }
    }
    return ,@($items)
}

function Get-RolesFeaturesDetectedFunctions {
    <#
        Maps installed RolesFeatures rows to friendly server-function labels.
        Returns a (possibly empty) array of unique labels, order preserved.
    #>
    [CmdletBinding()]
    param([object[]]$Rows)

    $labels = [System.Collections.Generic.List[string]]::new()
    if (-not $Rows -or $Rows.Count -eq 0) { return ,@($labels) }
    foreach ($map in $script:RolesFeatures_FunctionMap) {
        $hit = $false
        foreach ($r in $Rows) {
            if ($null -eq $r) { continue }
            $n = [string]$r.Name
            $d = [string]$r.DisplayName
            if (($n -match $map.Pattern) -or ($d -match $map.Pattern)) { $hit = $true; break }
        }
        if ($hit -and -not $labels.Contains($map.Label)) { $labels.Add($map.Label) }
    }
    return ,@($labels)
}

#endregion

#region Six-function contract -------------------------------------------------

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'RolesFeatures'
        DisplayName               = 'Windows Roles and Features'
        Category                  = 'System'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Low'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('RolesFeatures','AvailableRolesFeatures')
        ProducesRisks             = $true
        ProducesFollowUpQuestions = $true
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)

    $canRun      = $true
    $status      = 'Ready'
    $reason      = ''
    $limitations = @()

    $hasWf   = $false; $hasWof = $false; $hasDism = $false
    try { $hasWf   = (Get-CommandAvailable -Name 'Get-WindowsFeature') -or (Test-WindowsPowerShellModule -Name 'ServerManager') } catch { }
    try { $hasWof  = Get-CommandAvailable -Name 'Get-WindowsOptionalFeature' } catch { }
    try { $hasDism = Get-CommandAvailable -Name 'dism.exe' }                   catch { }

    if (-not ($hasWf -or $hasWof -or $hasDism)) {
        $canRun = $false
        $status = 'NotApplicable'
        $reason = 'No roles/features enumeration source available (Get-WindowsFeature, Get-WindowsOptionalFeature, and dism.exe all absent).'
    } elseif (-not $hasWf) {
        $limitations = @('Get-WindowsFeature not present (non-Server SKU or ServerManager unavailable); using optional-features / DISM fallback. Feature Names may not match canonical Windows Server role names.')
    }

    [pscustomobject]@{ ModuleName='RolesFeatures'; CanRun=$canRun; Status=$status; Reason=$reason; Limitations=@($limitations) }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)

    $module   = 'RolesFeatures'
    $features = [System.Collections.Generic.List[object]]::new()
    $errors   = [System.Collections.Generic.List[string]]::new()
    $method   = 'None'

    # --- Primary: Get-WindowsFeature (ServerManager; canonical role Names) ---
    # Under PowerShell 7 on Windows Server 2012 R2 ServerManager cannot load (needs .NET Framework types and the
    # 5.1-only compatibility session); Windows PowerShell 4 on the same box can run it, so ask that instead.
    $viaWinPS = (-not (Get-CommandAvailable -Name 'Get-WindowsFeature')) -and (Test-WindowsPowerShellModule -Name 'ServerManager')
    if ((Get-CommandAvailable -Name 'Get-WindowsFeature') -or $viaWinPS) {
        try {
            Write-Log -Level DEBUG -Message ('Enumerating roles/features via Get-WindowsFeature{0}.' -f $(if ($viaWinPS) { ' (in Windows PowerShell)' } else { '' })) -Module $module -Context $Context
            $wf = @(if ($viaWinPS) { Invoke-WindowsPowerShellJson -Script 'Import-Module ServerManager; Get-WindowsFeature | Select-Object Name,DisplayName,@{n=''InstallState'';e={[string]$_.InstallState}},@{n=''FeatureType'';e={[string]$_.FeatureType}},Parent,Path' } else { Get-WindowsFeature -ErrorAction Stop })
            foreach ($f in $wf) {
                if ($null -eq $f) { continue }
                $state = [string]$f.InstallState
                $features.Add([pscustomobject]@{
                    Name         = [string]$f.Name
                    DisplayName  = [string]$f.DisplayName
                    InstallState = $state
                    FeatureType  = [string]$f.FeatureType
                    Parent       = [string]$f.Parent
                    Path         = [string]$f.Path
                    IsInstalled  = ($state -eq 'Installed')
                })
            }
            if ($features.Count -gt 0) { $method = 'Get-WindowsFeature' }
        } catch {
            $errors.Add(("Get-WindowsFeature failed: {0}" -f $_.Exception.Message))
            Write-Log -Level WARN -Message 'Get-WindowsFeature failed; attempting fallback.' -Module $module -Exception $_ -Context $Context
        }
    }

    # --- Fallback 1: Get-WindowsOptionalFeature -Online (read-only) ---
    if ($method -eq 'None' -and (Get-CommandAvailable -Name 'Get-WindowsOptionalFeature')) {
        try {
            Write-Log -Level DEBUG -Message 'Enumerating optional features via Get-WindowsOptionalFeature -Online.' -Module $module -Context $Context
            $of = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)
            foreach ($f in $of) {
                if ($null -eq $f) { continue }
                $st        = [string]$f.State
                $installed = ($st -eq 'Enabled')
                $features.Add([pscustomobject]@{
                    Name         = [string]$f.FeatureName
                    DisplayName  = [string]$f.FeatureName
                    InstallState = $(if ($installed) { 'Installed' } else { 'Available' })
                    FeatureType  = 'OptionalFeature'
                    Parent       = ''
                    Path         = ''
                    IsInstalled  = $installed
                })
            }
            if ($features.Count -gt 0) { $method = 'Get-WindowsOptionalFeature' }
        } catch {
            $errors.Add(("Get-WindowsOptionalFeature failed: {0}" -f $_.Exception.Message))
            Write-Log -Level WARN -Message 'Get-WindowsOptionalFeature failed; attempting DISM fallback.' -Module $module -Exception $_ -Context $Context
        }
    }

    # --- Fallback 2: dism.exe /online /get-features (READ-ONLY get-features) ---
    if ($method -eq 'None' -and (Get-CommandAvailable -Name 'dism.exe')) {
        try {
            Write-Log -Level DEBUG -Message 'Enumerating optional features via dism.exe /online /get-features.' -Module $module -Context $Context
            $dism = Invoke-CommandLineSafe -FilePath 'dism.exe' -Arguments @('/online','/get-features','/format:table') -TimeoutSeconds 120
            if ($dism -and $dism.StdOut) {
                $parsed = @(ConvertFrom-DismFeatureText -Text $dism.StdOut)
                foreach ($p in $parsed) {
                    if ($null -eq $p) { continue }
                    $installed = ([string]$p.State -match '^Enabled')
                    $features.Add([pscustomobject]@{
                        Name         = [string]$p.Name
                        DisplayName  = [string]$p.Name
                        InstallState = $(if ($installed) { 'Installed' } else { 'Available' })
                        FeatureType  = 'OptionalFeature'
                        Parent       = ''
                        Path         = ''
                        IsInstalled  = $installed
                    })
                }
            }
            if ($features.Count -gt 0) {
                $method = 'DISM'
            } elseif ($dism -and $dism.TimedOut) {
                $errors.Add('dism.exe /get-features timed out.')
            } elseif ($dism -and -not $dism.Succeeded) {
                $errors.Add(("dism.exe returned exit code {0}." -f $dism.ExitCode))
            }
        } catch {
            $errors.Add(("DISM enumeration failed: {0}" -f $_.Exception.Message))
            Write-Log -Level WARN -Message 'DISM feature enumeration failed.' -Module $module -Exception $_ -Context $Context
        }
    }

    Write-Log -Level INFO -Message ("Roles/features enumeration method: {0} ({1} record(s))." -f $method, $features.Count) -Module $module -Context $Context

    # Optional raw dump for evidence (read-only file write into toolkit output).
    if ($Context -and $Context.Paths -and $Context.Paths.Contains('Raw') -and $features.Count -gt 0) {
        try {
            $rawFile = Join-Path -Path $Context.Paths['Raw'] -ChildPath 'RolesFeatures.raw.json'
            (@($features) | ConvertTo-Json -Depth 4) | Out-File -LiteralPath $rawFile -Encoding UTF8 -Force
        } catch { }
    }

    return @{
        Method   = $method
        Features = @($features)
        Errors   = @($errors)
    }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)

    $module   = 'RolesFeatures'
    $method   = 'None'
    $features = @()
    $errors   = @()

    if ($RawData -is [hashtable]) {
        if ($RawData.ContainsKey('Method'))   { $method   = [string]$RawData['Method'] }
        if ($RawData.ContainsKey('Features')) { $features = @($RawData['Features']) }
        if ($RawData.ContainsKey('Errors'))   { $errors   = @($RawData['Errors']) }
    }

    # --- Canonical dataset: RolesFeatures (INSTALLED ONLY) ---
    # Rules and role-presence tests match on Name/DisplayName regardless of
    # InstallState, so only genuinely-installed roles belong here.
    $installedRows = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $features) {
        if ($null -eq $f) { continue }
        if (-not ($f.IsInstalled -eq $true)) { continue }
        $installedRows.Add([pscustomobject]@{
            Name         = [string]$f.Name
            DisplayName  = [string]$f.DisplayName
            InstallState = [string]$f.InstallState
            FeatureType  = [string]$f.FeatureType
            Parent       = [string]$f.Parent
            Path         = [string]$f.Path
        })
    }

    Add-DataSet -Context $Context -Name 'RolesFeatures' `
        -Description 'Installed Windows roles, role services, and features. Canonical Windows feature Names are preserved so RiskEngine role rules and role-presence detection match accurately.' `
        -Rows @($installedRows) -Visibility 'Both' -IncludeInWorkbook $true -IncludeInClientReport $true -SourceModule $module | Out-Null

    # --- Secondary dataset: notable NOT-installed roles (informational only) ---
    $availableRows = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $features) {
        if ($null -eq $f) { continue }
        if ($f.IsInstalled -eq $true) { continue }
        $n = [string]$f.Name
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        $isNotable = $false
        foreach ($pat in $script:RolesFeatures_NotableRolePatterns) {
            if ($n -match $pat) { $isNotable = $true; break }
        }
        if (-not $isNotable) { continue }
        $availableRows.Add([pscustomobject]@{
            Name         = $n
            DisplayName  = [string]$f.DisplayName
            InstallState = [string]$f.InstallState
            FeatureType  = [string]$f.FeatureType
        })
    }

    Add-DataSet -Context $Context -Name 'AvailableRolesFeatures' `
        -Description 'Notable server roles present in the catalog but NOT installed. Informational only; deliberately excluded from role-presence detection to avoid false-positive role findings.' `
        -Rows @($availableRows) -Visibility 'Internal' -IncludeInWorkbook $true -IncludeInClientReport $false -SourceModule $module | Out-Null

    # --- Limitations ---
    if ($method -eq 'None' -or $installedRows.Count -eq 0) {
        $reason = if ($errors.Count -gt 0) { ($errors -join ' | ') } else { 'No roles/features enumeration source returned data.' }
        Add-Limitation -Context $Context -Module $module `
            -Message 'Windows roles/features could not be fully enumerated; role-based findings may be incomplete.' `
            -Impact 'Role detection (DC/DNS/DHCP/ADCS/IIS/Hyper-V/RDS/etc.) may be understated.' `
            -Reason $reason | Out-Null
    }
    if ($method -eq 'Get-WindowsOptionalFeature' -or $method -eq 'DISM') {
        Add-Limitation -Context $Context -Module $module `
            -Message 'Roles enumerated via optional-features fallback (client SKU or ServerManager unavailable); feature Names may not match canonical Windows Server role names.' `
            -Impact 'Server-role rules that key off canonical role Names may not match optional-feature Names.' `
            -Reason ("Enumeration method: {0}" -f $method) | Out-Null
    }
}

function Invoke-DiscoveryRiskAnalysis {
    param([object]$Context)

    $module = 'RolesFeatures'
    if (-not ($Context -and $Context.DataSets -and $Context.DataSets.Contains('RolesFeatures'))) { return }

    $rows      = @($Context.DataSets['RolesFeatures'].Rows)
    # Helper returns a clean array via ',@(...)'; do NOT re-wrap in @() (that would
    # double-wrap into a single-element array whose element is the real array).
    $functions = Get-RolesFeaturesDetectedFunctions -Rows $rows
    if ($null -eq $functions) { $functions = @() }

    # Light, consolidated summary. The RiskEngine emits the per-role
    # (DC/DNS/DHCP/ADCS/IIS/Hyper-V) high-severity findings from this dataset;
    # this is an informational roll-up only.
    if ($functions.Count -gt 0) {
        Add-Finding -Context $Context -Category 'Server Role' -Severity 'Info' -Confidence 'Confirmed' `
            -Title ('Server hosts {0} standard infrastructure/application role(s)' -f $functions.Count) `
            -EvidenceSource 'Windows roles and features enumeration' `
            -Evidence ('Detected roles: ' + ($functions -join ', ')) `
            -WhyItMattersForScoping 'Installed server roles indicate infrastructure/application functions that must be inventoried, sequenced, and validated during any migration, refresh, or decommission. The RiskEngine emits per-role detail; this is a consolidated summary.' `
            -PotentialProjectImpact @('Architecture Decision','Cutover Complexity','Client Coordination') `
            -SuggestedValidationQuestion 'For each detected role, is there redundancy elsewhere, and what is the migration/retirement plan and owner?' `
            -SourceModule $module -SourceDataset 'RolesFeatures' | Out-Null
    } else {
        Add-Finding -Context $Context -Category 'Server Role' -Severity 'Info' -Confidence 'Likely' `
            -Title 'No standard infrastructure/application server roles detected' `
            -EvidenceSource 'Windows roles and features enumeration' `
            -Evidence ('Installed role/feature record count: {0}' -f $rows.Count) `
            -WhyItMattersForScoping 'The server does not appear to host common infrastructure roles (DC/DNS/DHCP/ADCS/IIS/Hyper-V/RDS/etc.); it may be a member or application server whose purpose should be confirmed from other datasets (services, listening ports, installed applications).' `
            -SuggestedValidationQuestion 'What is the primary purpose of this server if it hosts no standard Windows roles?' `
            -SourceModule $module -SourceDataset 'RolesFeatures' | Out-Null
    }
}

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)

    $module = 'RolesFeatures'
    if (-not ($Context -and $Context.DataSets -and $Context.DataSets.Contains('RolesFeatures'))) { return }

    $rows      = @($Context.DataSets['RolesFeatures'].Rows)
    # Helper returns a clean array via ',@(...)'; do NOT re-wrap in @() (that would
    # double-wrap into a single-element array whose element is the real array).
    $functions = Get-RolesFeaturesDetectedFunctions -Rows $rows
    if ($null -eq $functions) { $functions = @() }
    if ($functions.Count -gt 0) {
        Add-FollowUpQuestion -Context $Context `
            -Question ('This server hosts the following roles: {0}. Is each role redundant elsewhere, and who owns the migration/retirement plan for each?' -f ($functions -join ', ')) `
            -Category 'Roles & Features' -Module $module -Audience 'Both' | Out-Null
    }
}

#endregion

Export-ModuleMember -Function `
    'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection', `
    'ConvertTo-DiscoveryDatasets','Invoke-DiscoveryRiskAnalysis','Get-DiscoveryFollowUpQuestions', `
    'ConvertFrom-DismFeatureText','Get-RolesFeaturesDetectedFunctions'
