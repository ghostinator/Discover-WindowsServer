<#
    Core.psm1
    Ultimate Modular Windows Server Discovery Toolkit - Core module.

    Provides the runtime context, structured logging, safety wrappers (CIM /
    registry / command-line), redaction, the standard Finding / Dataset /
    FollowUpQuestion / Limitation / Dependency object models, and the Add-* helpers
    that collector modules use to contribute results to the shared context.

    Design rules:
      - PowerShell 5.1 compatible.
      - Read-only. Nothing in Core changes the system except writing toolkit output.
      - Defensive: every external call is wrapped so one failure never stops discovery.
#>

# NOTE: StrictMode is intentionally NOT enabled. Collectors work with highly
# dynamic CIM / registry / .NET objects whose properties are frequently absent;
# strict mode would turn benign missing-property reads into terminating errors,
# which conflicts with the "one failure must never stop discovery" rule. We rely
# on explicit -ErrorAction handling and try/catch for defensiveness instead.

# Enumerations used for light validation of the object model.
$script:ValidSeverities   = @('Info','Low','Medium','High','Critical')
$script:ValidConfidence   = @('Confirmed','Likely','Possible','NotDetected','Unknown')
$script:ValidImpacts      = @('Labor','Licensing','Downtime','Vendor Dependency','Security/Compliance','Data Migration','Cutover Complexity','Client Coordination','Architecture Decision','Rollback Planning')
$script:ValidVisibility   = @('Internal','ClientSafe','Both','SensitiveRedacted')

#region Configuration loading -------------------------------------------------

function Import-DiscoveryConfig {
    <# Reads a single JSON config file safely. Returns $null on failure. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Write-Warning ("Failed to load config '{0}': {1}" -f $Path, $_.Exception.Message)
        return $null
    }
}

function Get-DiscoveryConfigBundle {
    <# Loads every known config file from the config directory into one object. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigDirectory,
        # Tests pass a disposable directory so they never read this machine's real branding.
        [string]$BrandingDirectory = (Get-DiscoveryBrandingDirectory -ConfigDirectory $ConfigDirectory)
    )
    $join = { param($n) Join-Path -Path $ConfigDirectory -ChildPath $n }
    return [pscustomobject]@{
        Default       = Import-DiscoveryConfig -Path (& $join 'default.discovery.json')
        Fast          = Import-DiscoveryConfig -Path (& $join 'fast.discovery.json')
        Deep          = Import-DiscoveryConfig -Path (& $join 'deep.discovery.json')
        Redaction     = Import-DiscoveryConfig -Path (& $join 'redaction-patterns.json')
        RiskRules     = Import-DiscoveryConfig -Path (& $join 'risk-rules.json')
        Fingerprints  = Import-DiscoveryConfig -Path (& $join 'application-fingerprints.json')
        Compliance    = Import-DiscoveryConfig -Path (& $join 'compliance-lenses.json')
        Output        = Merge-LocalBranding -Output (Import-DiscoveryConfig -Path (& $join 'output-settings.json')) -BrandingDirectory $BrandingDirectory
        ConfigDir     = $ConfigDirectory
        BrandingDir   = $BrandingDirectory
    }
}

function Get-DiscoveryBrandingDirectory {
    <#
        Where this machine's own branding (branding.local.json + its logo, saved by the GUI's
        Branding tab) lives. %ProgramData%\Discover-WindowsServer\branding first: outside the
        module folder, so it survives Update-Module (which installs each version into a new
        folder) and saving it doesn't need write access to Program Files. Falls back to the
        config directory: the pre-move location, and where Invoke-FleetDiscovery stages it on
        remote targets. Merge-FleetDiscoveryResults.ps1, Invoke-FleetDiscovery.ps1 and the GUI
        mirror this path on purpose (none of them import Core).
    #>
    param(
        [Parameter(Mandatory)][string]$ConfigDirectory,
        [string]$ProgramDataDirectory = (Join-Path $env:ProgramData 'Discover-WindowsServer\branding')
    )
    if (Test-Path -LiteralPath (Join-Path $ProgramDataDirectory 'branding.local.json')) { return $ProgramDataDirectory }
    if (Test-Path -LiteralPath (Join-Path $ConfigDirectory 'branding.local.json')) { return $ConfigDirectory }
    return $ProgramDataDirectory
}

function Merge-LocalBranding {
    <#
        Overlays branding.local.json's html block onto output-settings.json's. The local file is
        per-machine (never in git, never in the Gallery package) and holds the real client-facing
        brand, so the tracked output-settings.json keeps generic defaults and its shared keys
        still sync via git. Merge-FleetDiscoveryResults.ps1's Get-FleetBranding mirrors this.
    #>
    param([object]$Output, [Parameter(Mandatory)][string]$BrandingDirectory)
    $local = Import-DiscoveryConfig -Path (Join-Path $BrandingDirectory 'branding.local.json')
    if (-not $Output -or -not $local -or -not $local.html) { return $Output }
    if (-not $Output.html) { $Output | Add-Member -NotePropertyName html -NotePropertyValue ([pscustomobject]@{}) -Force }
    foreach ($p in $local.html.PSObject.Properties) { $Output.html | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force }
    return $Output
}

function Get-DiscoveryBranding {
    <#
        Single source of truth for report branding (single-server AND fleet reports go through
        this or its local duplicate - see Merge-FleetDiscoveryResults.ps1's Get-FleetBranding,
        which can't import this module and mirrors this logic on purpose). Fail-soft throughout:
        a missing/malformed config, or a missing/oversized/unreadable logo file, degrades to no
        branding rather than throwing - report generation must never fail because of a cosmetic
        setting.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    $result = [ordered]@{
        Title       = 'Windows Server Discovery - Internal Engineering Report'
        Brand       = 'Your Company'
        Accent      = '#1F4E79'
        LogoDataUri = $null
    }
    try {
        $html = $Context.Config.Output.html
        if ($html) {
            if ($html.title)          { $result.Title  = [string]$html.title }
            if ($html.brandName)      { $result.Brand   = [string]$html.brandName }
            if ($html.accentColorHex) { $result.Accent  = [string]$html.accentColorHex }
            if ($html.logoPath) {
                # Branding directory first (where the GUI saves the logo), then the config directory.
                foreach ($dir in @($Context.Config.BrandingDir, $Context.Config.ConfigDir)) {
                    if (-not $dir) { continue }
                    $result.LogoDataUri = Get-DiscoveryLogoDataUri -ConfigDirectory $dir -LogoPath ([string]$html.logoPath)
                    if ($result.LogoDataUri) { break }
                }
            }
        }
    } catch { }
    return [pscustomobject]$result
}

function Get-DiscoveryLogoDataUri {
    <#
        Reads a logo image (relative to the config directory) and returns it as a base64 data:
        URI, or $null if the file is missing, too large (a report shouldn't balloon because of an
        accidentally huge image), or an unrecognized type. Shared by Get-DiscoveryBranding and
        Merge-FleetDiscoveryResults.ps1's Get-FleetBranding.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigDirectory, [Parameter(Mandatory)][string]$LogoPath)
    $mimeByExtension = @{ '.png' = 'image/png'; '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'; '.gif' = 'image/gif'; '.svg' = 'image/svg+xml' }
    try {
        $fullPath = Join-Path -Path $ConfigDirectory -ChildPath $LogoPath
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { return $null }
        $ext = [System.IO.Path]::GetExtension($fullPath).ToLowerInvariant()
        if (-not $mimeByExtension.ContainsKey($ext)) { return $null }
        $bytes = [System.IO.File]::ReadAllBytes($fullPath)
        if ($bytes.Length -gt 512KB) { return $null }
        return ('data:{0};base64,{1}' -f $mimeByExtension[$ext], [Convert]::ToBase64String($bytes))
    } catch { return $null }
}

#endregion

#region Runtime context -------------------------------------------------------

function New-DiscoveryContext {
    <#
        Builds the central runtime context object shared across modules.
        Reference-type collections (Lists / ordered dictionaries) mutate in place,
        so modules never need global state.
    #>
    [CmdletBinding()]
    param(
        [string]$Mode = 'Fast',
        [string]$ProjectType = 'GeneralDiscovery',
        [string]$ComplianceLens = 'None',
        [string]$OutputRoot = 'C:\Temp',
        [string]$OutputPath,
        [bool]$IsAdmin = $false,
        [bool]$IsSystem = $false,
        [hashtable]$Parameters = @{},
        [object]$Config,
        [bool]$Quiet = $false,
        [bool]$VerboseLogging = $false
    )

    $script:RedactMemo = @{}   # per-run: the redaction patterns come from this context's config
    $ctx = [ordered]@{
        RunId               = ([guid]::NewGuid()).Guid
        StartTime           = (Get-Date)
        EndTime             = $null
        ComputerName        = $env:COMPUTERNAME
        Mode                = $Mode
        ProjectType         = $ProjectType
        ComplianceLens      = $ComplianceLens
        OutputRoot          = $OutputRoot
        OutputPath          = $OutputPath
        Paths               = [ordered]@{}
        LogPaths            = [ordered]@{}
        IsAdmin             = $IsAdmin
        IsSystem            = $IsSystem
        Quiet               = $Quiet
        VerboseLogging      = $VerboseLogging
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
        Parameters          = $Parameters
        Config              = $Config
        IncludedModules     = @()
        ExcludedModules     = @()
        ModuleStatuses      = [System.Collections.Generic.List[object]]::new()
        ModuleMetadata      = [System.Collections.Generic.List[object]]::new()
        DataSets            = [ordered]@{}
        Findings            = [System.Collections.Generic.List[object]]::new()
        FollowUpQuestions   = [System.Collections.Generic.List[object]]::new()
        ScopeLanguage       = [System.Collections.Generic.List[object]]::new()
        Limitations         = [System.Collections.Generic.List[object]]::new()
        Unknowns            = [System.Collections.Generic.List[object]]::new()
        DependencyEdges     = [System.Collections.Generic.List[object]]::new()
        Logs                = [System.Collections.Generic.List[object]]::new()
        Counters            = [ordered]@{ Findings = 0; Errors = 0; Warnings = 0; Limitations = 0; Questions = 0 }
    }
    return $ctx
}

#endregion

#region Filesystem & safety helpers -------------------------------------------

function Ensure-Directory {
    <# Creates a directory (and parents) if missing. Returns the path. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-Warning ("Ensure-Directory failed for '{0}': {1}" -f $Path, $_.Exception.Message)
    }
    return $Path
}

function ConvertTo-SafeFileName {
    <# Replaces characters that are invalid in Windows file names. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [string]$Replacement = '_'
    )
    if ([string]::IsNullOrEmpty($Name)) { return 'unnamed' }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Name.ToCharArray()) {
        if ($invalid -contains $ch) { [void]$sb.Append($Replacement) } else { [void]$sb.Append($ch) }
    }
    $result = $sb.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($result)) { return 'unnamed' }
    return $result
}

function Test-IsAdministrator {
    <# True if the current process token is in the local Administrators role. #>
    [CmdletBinding()] param()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-IsSystem {
    <# True if running as the LocalSystem (S-1-5-18) account. #>
    [CmdletBinding()] param()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return ($id.User.Value -eq 'S-1-5-18')
    } catch { return $false }
}

function Test-WindowsPowerShellModule {
    <# True when this is PowerShell Core AND Windows PowerShell has the named module on disk: i.e. the module cannot be loaded here but a powershell.exe child could run it. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($PSVersionTable.PSEdition -ne 'Core') { return $false }
    return (Test-Path -LiteralPath (Join-Path $env:windir "System32\WindowsPowerShell\v1.0\Modules\$Name"))
}

function Invoke-WindowsPowerShellJson {
    <#
        Runs a READ-ONLY snippet in Windows PowerShell (powershell.exe) and returns its output parsed
        from JSON, or $null on any failure. For cmdlets PowerShell 7 cannot load on this host (e.g.
        ServerManager's Get-WindowsFeature on Windows Server 2012 R2, where PowerShell 7's own
        compatibility session is unavailable because it needs Windows PowerShell 5.1). Time-bounded via
        Invoke-CommandLineSafe. The script travels as -EncodedCommand, so quoting cannot break it.
    #>
    param([Parameter(Mandatory)][string]$Script, [int]$TimeoutSeconds = 120)
    $exe = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return $null }
    $cmd = "`$ErrorActionPreference = 'Stop'; & { $Script } | ConvertTo-Json -Compress -Depth 3"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $r = Invoke-CommandLineSafe -FilePath $exe -Arguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) -TimeoutSeconds $TimeoutSeconds
    if (-not $r.Succeeded -or [string]::IsNullOrWhiteSpace($r.StdOut)) { return $null }
    try { return ($r.StdOut | ConvertFrom-Json) } catch { return $null }
}

function Get-CommandAvailable {
    <#
        True if a command / cmdlet / exe is available.

        This gates optional collection in 17 modules across 57 call sites, so a false
        negative here silently skips a whole dataset - usually while logging a
        "cmdlet not available" limitation that is simply untrue.

        It used to call $ExecutionContext.InvokeCommand.GetCommands(), chosen because it
        returns an empty set for a missing name instead of polluting $Error with a
        CommandNotFound. That was the right goal but the wrong mechanism: GetCommands()
        does NOT trigger module auto-loading, so any cmdlet in a module that has not been
        imported yet reads as absent. Measured on a Windows 11 host, in a fresh session,
        7 of 14 probed cmdlets were false negatives - and inconsistently so WITHIN the
        same module (Get-Disk found, Get-Partition not; Get-Printer found,
        Get-PrinterDriver not), because the result depends on module-analysis-cache state
        and on which module happened to be auto-loaded first. Real cost on one Deep run:
        FirewallRules 0 rows instead of 557, ListeningPorts 1 instead of 42, LocalGroups
        0 instead of 22, Partitions 0 instead of 4, PrinterDrivers 0 instead of 9,
        SharePermissions 0 instead of 3.

        Get-Command DOES auto-load. The trick is -ErrorAction Ignore rather than
        SilentlyContinue: Ignore suppresses the CommandNotFoundException without
        recording it, so $Error stays clean and the original design goal is preserved.
        (Measured: probing 7 absent commands leaves $Error.Count at 0 with Ignore, and
        at 6 with SilentlyContinue.)

        Callers must still guard the actual invocation - a cmdlet can exist and then fail,
        e.g. Get-VM is present whenever the Hyper-V module is installed even if Hyper-V
        itself is not enabled.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    try { if (Get-Command -Name $Name -ErrorAction Ignore) { return $true } } catch { }
    if (Import-WindowsModuleForCommand -Name $Name) { try { return [bool](Get-Command -Name $Name -ErrorAction Ignore) } catch { return $false } }
    return $false
}

$script:CoreCompatMap = $null
$script:CoreCompatTried = @{}
function Import-WindowsModuleForCommand {
    <#
        PowerShell 7 will not auto-load a Windows PowerShell module whose manifest lacks
        CompatiblePSEditions (every one of them on Windows Server 2012 R2), and its compatibility
        session needs Windows PowerShell 5.1, which 2012 R2 does not have. So on 2012 R2 under
        PowerShell 7, Get-NetFirewallRule / Get-SmbShare / Get-Volume ... read as "not available"
        and whole datasets silently come back empty. Many of those modules are CIM-based and load
        fine with -SkipEditionCheck; those that are not (they need .NET Framework types) simply fail
        to import and stay unavailable. Only acts under PowerShell Core, only after Get-Command has
        already failed, and tries each module once.
    #>
    param([string]$Name)
    if ($PSVersionTable.PSEdition -ne 'Core') { return $false }
    if ($null -eq $script:CoreCompatMap) {
        $script:CoreCompatMap = @{}
        try {
            foreach ($m in (Get-Module -ListAvailable -SkipEditionCheck -ErrorAction SilentlyContinue 2>$null)) {
                foreach ($c in @($m.ExportedCommands.Keys)) { if (-not $script:CoreCompatMap.ContainsKey($c)) { $script:CoreCompatMap[$c] = $m.Name } }
            }
        } catch { }
    }
    $mod = $script:CoreCompatMap[$Name]
    if (-not $mod -or $script:CoreCompatTried.ContainsKey($mod)) { return $false }
    $script:CoreCompatTried[$mod] = $true
    try { Import-Module -Name $mod -SkipEditionCheck -Global -DisableNameChecking -ErrorAction Stop -WarningAction SilentlyContinue 2>$null 3>$null | Out-Null; return $true } catch { return $false }
}

function Get-ModuleAvailable {
    <# True if a PowerShell module is installed (loaded or available). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    try {
        if (Get-Module -Name $Name -ErrorAction SilentlyContinue) { return $true }
        return [bool](Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)
    } catch { return $false }
}

function Get-RegistryValueSafe {
    <# Reads a single registry value, returning $null instead of throwing. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Test-RegistryPathSafe {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    try { return (Test-Path -LiteralPath $Path) } catch { return $false }
}

function Invoke-CimSafe {
    <#
        Wrapper around Get-CimInstance with automatic WMI fallback and full
        error suppression. Always returns an array (possibly empty).
    #>
    [CmdletBinding()]
    param(
        [string]$ClassName,
        [string]$Namespace = 'root/cimv2',
        [string]$Filter,
        [string]$Query,
        [string[]]$Property
    )
    try {
        $params = @{ ErrorAction = 'Stop' }
        if ($Query)     { $params['Query'] = $Query }
        elseif ($ClassName) { $params['ClassName'] = $ClassName; if ($Namespace) { $params['Namespace'] = $Namespace } }
        else { return @() }
        if ($Filter)   { $params['Filter'] = $Filter }
        if ($Property) { $params['Property'] = $Property }
        $result = Get-CimInstance @params
        if ($null -eq $result) { return @() }
        return @($result)
    } catch {
        # Fallback to legacy WMI for older hosts / edge cases.
        try {
            $wmi = @{ ErrorAction = 'Stop' }
            if ($Query) { $wmi['Query'] = $Query } elseif ($ClassName) { $wmi['Class'] = $ClassName; if ($Namespace) { $wmi['Namespace'] = $Namespace } } else { return @() }
            if ($Filter) { $wmi['Filter'] = $Filter }
            $res2 = Get-WmiObject @wmi
            if ($null -eq $res2) { return @() }
            return @($res2)
        } catch { return @() }
    }
}

function Invoke-CommandLineSafe {
    <#
        Runs a read-only external command (e.g. gpresult, slmgr, dism, appcmd)
        capturing stdout/stderr with a timeout. Never throws. Returns a result
        object with ExitCode, StdOut, StdErr, TimedOut, and Succeeded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 60
    )
    $result = [pscustomobject]@{
        FilePath = $FilePath; Arguments = ($Arguments -join ' ')
        ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $false; Succeeded = $false; Error = $null
    }
    $proc = $null
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = ($Arguments -join ' ')
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $stdOutTask = $proc.StandardOutput.ReadToEndAsync()
        $stdErrTask = $proc.StandardError.ReadToEndAsync()
        if ($proc.WaitForExit($TimeoutSeconds * 1000)) {
            $result.ExitCode  = $proc.ExitCode
            $result.StdOut    = $stdOutTask.Result
            $result.StdErr    = $stdErrTask.Result
            $result.Succeeded = ($proc.ExitCode -eq 0)
        } else {
            $result.TimedOut = $true
            try { $proc.Kill() } catch { }
        }
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        if ($proc) { try { $proc.Dispose() } catch { } }
    }
    return $result
}

#endregion

#region Conversion helpers ----------------------------------------------------

function Convert-BytesToGB {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowNull()]$Bytes, [int]$Decimals = 2)
    if ($null -eq $Bytes) { return $null }
    try { return [math]::Round(([double]$Bytes) / 1GB, $Decimals) } catch { return $null }
}

function Convert-BytesToMB {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowNull()]$Bytes, [int]$Decimals = 2)
    if ($null -eq $Bytes) { return $null }
    try { return [math]::Round(([double]$Bytes) / 1MB, $Decimals) } catch { return $null }
}

function Normalize-DateTime {
    <# Returns a consistent 'yyyy-MM-dd HH:mm:ss' string, or $null. #>
    [CmdletBinding()] param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
        # Attempt DMTF / string conversion.
        $dt = $null
        if ([datetime]::TryParse([string]$Value, [ref]$dt)) { return $dt.ToString('yyyy-MM-dd HH:mm:ss') }
        try { $dt = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$Value); return $dt.ToString('yyyy-MM-dd HH:mm:ss') } catch { }
        return [string]$Value
    } catch { return $null }
}

#endregion

#region Redaction -------------------------------------------------------------

function Test-SensitiveKeyLabel {
    <# True if a key/label name looks sensitive per redaction-patterns.json. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [object]$Context
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $labels = @('password','passwd','pwd','secret','token','apikey','api key','client secret','private key','shared secret','snmp community','bearer','sas token','access key','connection string password','bitlocker recovery key','credential')
    if ($Context -and $Context.Config -and $Context.Config.Redaction -and $Context.Config.Redaction.keyLabels) {
        $labels = $Context.Config.Redaction.keyLabels
    }
    $lower = $Name.ToLowerInvariant()
    foreach ($l in $labels) { if ($lower -like ("*{0}*" -f ([string]$l).ToLowerInvariant())) { return $true } }
    return $false
}

function Redact-SensitiveValue {
    <#
        Redacts sensitive-looking substrings from a string using the value
        patterns in redaction-patterns.json. Conservative by default: only
        obvious secrets are replaced, structure is preserved where configured.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()]$InputString,
        [object]$Context
    )
    if ($null -eq $InputString) { return $null }
    $text = [string]$InputString
    if ([string]::IsNullOrEmpty($text)) { return $text }

    $replacement = '[REDACTED - sensitive-looking value detected]'
    $patterns = $null
    if ($Context -and $Context.Config -and $Context.Config.Redaction) {
        if ($Context.Config.Redaction.replacement) { $replacement = $Context.Config.Redaction.replacement }
        $patterns = $Context.Config.Redaction.valuePatterns
    }
    if (-not $patterns) {
        # Minimal built-in fallback patterns.
        $patterns = @(
            [pscustomobject]@{ name='Pwd'; pattern='(?i)(password|pwd)\s*=\s*[^;\r\n"'']+'; keepStructure=$true; structureReplacement='$1=[REDACTED]' }
        )
    }
    foreach ($p in $patterns) {
        try {
            if ($p.keepStructure -and $p.structureReplacement) {
                $text = [regex]::Replace($text, $p.pattern, $p.structureReplacement)
            } else {
                $text = [regex]::Replace($text, $p.pattern, $replacement)
            }
        } catch { }
    }
    return $text
}

$script:RedactMemo = @{}

function Protect-DatasetRows {
    <#
        Safety net run by Add-DataSet on every dataset: redacts string cells with the same patterns
        as Redact-SensitiveValue. Redaction used to be opt-in per field in five collectors, so any
        free-text field elsewhere leaked (a Hyper-V VM's Notes held a plaintext password in the CSV,
        JSON and workbook). Memoised - many cells repeat - and cells that already carry a
        redaction marker are left alone so the pass is idempotent.
    #>
    param($Rows, [object]$Context)
    foreach ($row in @($Rows)) {
        if ($row -isnot [pscustomobject]) { continue }
        foreach ($p in $row.PSObject.Properties) {
            $v = $p.Value
            if ($v -isnot [string] -or $v.Length -lt 8 -or $v.Contains('[REDACTED')) { continue }
            $red = $script:RedactMemo[$v]
            if ($null -eq $red) { $red = Redact-SensitiveValue -InputString $v -Context $Context; $script:RedactMemo[$v] = $red }
            if ($red -ne $v) { try { $p.Value = $red } catch { } }
        }
    }
}

#endregion

#region Structured logging ----------------------------------------------------

function Write-Log {
    <#
        Structured logging.
          - summary.txt : INFO / WARN / ERROR
          - errors.txt  : ERROR only
          - warnings.txt: WARN only
          - debug.log   : DEBUG only when VerboseLogging is enabled
        Console output is concise unless VerboseLogging; Quiet suppresses
        nonessential console output but never suppresses files.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO',
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [string]$Module = 'Core',
        [object]$Exception,
        [object]$Context
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $exText = ''
    if ($Exception) {
        if ($Exception -is [System.Management.Automation.ErrorRecord]) {
            $exText = " | Exception: {0}" -f $Exception.Exception.Message
        } elseif ($Exception -is [System.Exception]) {
            $exText = " | Exception: {0}" -f $Exception.Message
        } else {
            $exText = " | Exception: {0}" -f ([string]$Exception)
        }
    }
    $line = "{0} [{1}] [{2}] {3}{4}" -f $ts, $Level, $Module, $Message, $exText

    if ($Context) {
        try {
            $Context.Logs.Add([pscustomobject]@{ Timestamp=$ts; Level=$Level; Module=$Module; Message=$Message; Exception=$exText.TrimStart(' |') })
            if ($Level -eq 'ERROR') { $Context.Counters.Errors++ }
            elseif ($Level -eq 'WARN') { $Context.Counters.Warnings++ }
        } catch { }
    }

    # File targets.
    $logPaths = $null
    if ($Context -and $Context.LogPaths) { $logPaths = $Context.LogPaths }
    if ($logPaths) {
        try {
            if ($Level -in @('INFO','WARN','ERROR') -and $logPaths.Summary) { Add-Content -LiteralPath $logPaths.Summary -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue }
            if ($Level -eq 'ERROR' -and $logPaths.Errors) { Add-Content -LiteralPath $logPaths.Errors -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue }
            if ($Level -eq 'WARN'  -and $logPaths.Warnings) { Add-Content -LiteralPath $logPaths.Warnings -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue }
            $verbose = $false
            if ($Context) { $verbose = [bool]$Context.VerboseLogging }
            if ($Level -eq 'DEBUG' -and $verbose -and $logPaths.Debug) { Add-Content -LiteralPath $logPaths.Debug -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue }
        } catch { }
    }

    # Console.
    $quiet = $false; $verbose = $false
    if ($Context) { $quiet = [bool]$Context.Quiet; $verbose = [bool]$Context.VerboseLogging }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { if (-not $quiet) { Write-Host $line -ForegroundColor Yellow } }
        'DEBUG' { if ($verbose) { Write-Host $line -ForegroundColor DarkGray } }
        default { if ($verbose) { Write-Host $line -ForegroundColor Gray } elseif (-not $quiet) { Write-Host ("  {0}" -f $Message) -ForegroundColor Gray } }
    }
}

function Write-SectionStatus {
    <# Concise console banner announcing a module/section. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Status = '',
        [object]$Context
    )
    $quiet = $false
    if ($Context) { $quiet = [bool]$Context.Quiet }
    if (-not $quiet) {
        $msg = if ($Status) { "==> {0} [{1}]" -f $Title, $Status } else { "==> {0}" -f $Title }
        Write-Host $msg -ForegroundColor Cyan
    }
}

#endregion

#region Object model factories ------------------------------------------------

function New-DiscoveryDataset {
    <# Builds a normalized dataset object. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Description = '',
        $Rows = @(),
        [ValidateSet('Internal','ClientSafe','Both','SensitiveRedacted')][string]$Visibility = 'Internal',
        [bool]$IncludeInWorkbook = $true,
        [bool]$IncludeInClientReport = $false,
        [string]$SourceModule = '',
        # Optional, smaller row set for the workbook only (e.g. dropping thousands of ephemeral
        # UDP sockets from ListeningPorts). CSV/JSON always export the full $Rows - "raw export
        # stays complete" - only the workbook view is reduced. Defaults to $Rows: every existing
        # caller is unaffected.
        $WorkbookRows = $null
    )
    if ($null -eq $Rows) { $Rows = @() }
    if ($null -eq $WorkbookRows) { $WorkbookRows = $Rows }
    return [pscustomobject]@{
        Name                  = $Name
        Description           = $Description
        Rows                  = @($Rows)
        WorkbookRows          = @($WorkbookRows)
        Visibility            = $Visibility
        IncludeInWorkbook     = $IncludeInWorkbook
        IncludeInClientReport = $IncludeInClientReport
        SourceModule          = $SourceModule
        RowCount              = @($Rows).Count
    }
}

function New-DiscoveryFinding {
    <# Builds a standard finding object (no context side effects). #>
    [CmdletBinding()]
    param(
        [string]$FindingId = '',
        [Parameter(Mandatory)][string]$Category,
        [ValidateSet('Info','Low','Medium','High','Critical')][string]$Severity = 'Info',
        [ValidateSet('Confirmed','Likely','Possible','NotDetected','Unknown')][string]$Confidence = 'Unknown',
        [Parameter(Mandatory)][string]$Title,
        [string]$EvidenceSource = '',
        [string]$Evidence = '',
        [string]$WhyItMattersForScoping = '',
        [string[]]$PotentialProjectImpact = @(),
        [string]$SuggestedValidationQuestion = '',
        [string]$SuggestedScopeLanguage = '',
        [string[]]$LikelyAffectedWBSAreas = @(),
        [string[]]$ComplianceRelevance = @(),
        [string]$Subject = '',
        [bool]$IsEmphasized = $false,
        [string]$EmphasisReason = '',
        [string]$SourceModule = '',
        [string]$SourceDataset = ''
    )
    return [pscustomobject]@{
        FindingId                   = $FindingId
        Category                    = $Category
        Severity                    = $Severity
        Confidence                  = $Confidence
        Title                       = $Title
        EvidenceSource              = $EvidenceSource
        Evidence                    = $Evidence
        WhyItMattersForScoping      = $WhyItMattersForScoping
        PotentialProjectImpact      = @($PotentialProjectImpact)
        SuggestedValidationQuestion = $SuggestedValidationQuestion
        SuggestedScopeLanguage      = $SuggestedScopeLanguage
        LikelyAffectedWBSAreas      = @($LikelyAffectedWBSAreas)
        ComplianceRelevance         = @($ComplianceRelevance)
        # Subject is the row's primary identifier (service name, task name, application, ...)
        # so a per-row finding is machine-readable without parsing the Evidence string.
        Subject                     = $Subject
        # Emphasis is presentation only: it reorders and surfaces findings that matter most for
        # the active -ProjectType. It deliberately does NOT change Severity - see
        # docs\RISK-SCORING.md ("Do not exaggerate severity").
        IsEmphasized                = $IsEmphasized
        EmphasisReason              = $EmphasisReason
        SourceModule                = $SourceModule
        SourceDataset               = $SourceDataset
    }
}

function New-ScopingRisk {
    <# Alias-style factory returning a finding shaped as a scoping risk. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Category = 'Scoping',
        [string]$Severity = 'Medium',
        [string]$Confidence = 'Likely',
        [string]$Evidence = '',
        [string]$WhyItMattersForScoping = '',
        [string[]]$PotentialProjectImpact = @(),
        [string]$SuggestedValidationQuestion = '',
        [string]$SourceModule = ''
    )
    return New-DiscoveryFinding -Title $Title -Category $Category -Severity $Severity -Confidence $Confidence `
        -Evidence $Evidence -WhyItMattersForScoping $WhyItMattersForScoping -PotentialProjectImpact $PotentialProjectImpact `
        -SuggestedValidationQuestion $SuggestedValidationQuestion -SourceModule $SourceModule
}

function New-FollowUpQuestion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [string]$Category = 'General',
        [string]$Module = '',
        [string]$RelatedFinding = '',
        [ValidateSet('Internal','ClientSafe','Both')][string]$Audience = 'Both'
    )
    return [pscustomobject]@{
        Category       = $Category
        Question       = $Question
        Module         = $Module
        RelatedFinding = $RelatedFinding
        Audience       = $Audience
    }
}

function New-DependencyEdge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceType,
        [Parameter(Mandatory)][string]$SourceName,
        [Parameter(Mandatory)][string]$DependencyType,
        [string]$Target = '',
        [string]$Evidence = '',
        [string]$Confidence = 'Likely',
        [string]$SourceDataset = '',
        [string]$ProjectImpact = '',
        [string]$ValidationQuestion = ''
    )
    return [pscustomobject]@{
        SourceType         = $SourceType
        SourceName         = $SourceName
        DependencyType     = $DependencyType
        Target             = $Target
        Evidence           = $Evidence
        Confidence         = $Confidence
        SourceDataset      = $SourceDataset
        ProjectImpact      = $ProjectImpact
        ValidationQuestion = $ValidationQuestion
    }
}

#endregion

#region Context mutators (Add-*) ----------------------------------------------

function Add-DataSet {
    <# Adds or merges a dataset into the context. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Name,
        [string]$Description = '',
        $Rows = @(),
        [ValidateSet('Internal','ClientSafe','Both','SensitiveRedacted')][string]$Visibility = 'Internal',
        [bool]$IncludeInWorkbook = $true,
        [bool]$IncludeInClientReport = $false,
        [string]$SourceModule = '',
        $WorkbookRows = $null
    )
    if ($null -eq $Rows) { $Rows = @() }
    if ($null -eq $WorkbookRows) { $WorkbookRows = $Rows }
    Protect-DatasetRows -Rows $Rows -Context $Context
    if (-not [object]::ReferenceEquals($WorkbookRows, $Rows)) { Protect-DatasetRows -Rows $WorkbookRows -Context $Context }
    if ($Context.DataSets.Contains($Name)) {
        # Merge rows into the existing dataset.
        $existing = $Context.DataSets[$Name]
        $merged = @($existing.Rows) + @($Rows)
        $existing.Rows = $merged
        $existing.RowCount = $merged.Count
        $existing.WorkbookRows = @($existing.WorkbookRows) + @($WorkbookRows)
        return $existing
    }
    $ds = New-DiscoveryDataset -Name $Name -Description $Description -Rows $Rows -Visibility $Visibility `
        -IncludeInWorkbook $IncludeInWorkbook -IncludeInClientReport $IncludeInClientReport -SourceModule $SourceModule `
        -WorkbookRows $WorkbookRows
    $Context.DataSets[$Name] = $ds
    return $ds
}

function Add-Finding {
    <# Creates a finding, assigns a sequential FindingId, and appends it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Category,
        [ValidateSet('Info','Low','Medium','High','Critical')][string]$Severity = 'Info',
        [ValidateSet('Confirmed','Likely','Possible','NotDetected','Unknown')][string]$Confidence = 'Unknown',
        [Parameter(Mandatory)][string]$Title,
        [string]$EvidenceSource = '',
        [string]$Evidence = '',
        [string]$WhyItMattersForScoping = '',
        [string[]]$PotentialProjectImpact = @(),
        [string]$SuggestedValidationQuestion = '',
        [string]$SuggestedScopeLanguage = '',
        [string[]]$LikelyAffectedWBSAreas = @(),
        [string[]]$ComplianceRelevance = @(),
        [string]$Subject = '',
        [bool]$IsEmphasized = $false,
        [string]$EmphasisReason = '',
        [string]$SourceModule = '',
        [string]$SourceDataset = ''
    )
    $Context.Counters.Findings++
    $id = "FIND-{0:D4}" -f $Context.Counters.Findings
    $finding = New-DiscoveryFinding -FindingId $id -Category $Category -Severity $Severity -Confidence $Confidence `
        -Title $Title -EvidenceSource $EvidenceSource -Evidence $Evidence -WhyItMattersForScoping $WhyItMattersForScoping `
        -PotentialProjectImpact $PotentialProjectImpact -SuggestedValidationQuestion $SuggestedValidationQuestion `
        -SuggestedScopeLanguage $SuggestedScopeLanguage -LikelyAffectedWBSAreas $LikelyAffectedWBSAreas `
        -ComplianceRelevance $ComplianceRelevance -Subject $Subject -IsEmphasized $IsEmphasized -EmphasisReason $EmphasisReason `
        -SourceModule $SourceModule -SourceDataset $SourceDataset
    $Context.Findings.Add($finding)
    return $finding
}

function Add-Limitation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$Message,
        [string]$Impact = '',
        [string]$Reason = ''
    )
    $Context.Counters.Limitations++
    $lim = [pscustomobject]@{ Module=$Module; Message=$Message; Impact=$Impact; Reason=$Reason; Timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
    $Context.Limitations.Add($lim)
    return $lim
}

function Add-Unknown {
    <# Adds an 'unknown that matters' entry (distinct from errors/limitations). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Unknown,
        [string]$WhyItMatters = '',
        [string]$Evidence = '',
        [string]$RecommendedValidationQuestion = '',
        [string]$Module = ''
    )
    $u = [pscustomobject]@{
        Unknown = $Unknown; WhyItMatters = $WhyItMatters; Evidence = $Evidence
        RecommendedValidationQuestion = $RecommendedValidationQuestion; Module = $Module
    }
    $Context.Unknowns.Add($u)
    return $u
}

function Add-FollowUpQuestion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Question,
        [string]$Category = 'General',
        [string]$Module = '',
        [string]$RelatedFinding = '',
        [ValidateSet('Internal','ClientSafe','Both')][string]$Audience = 'Both'
    )
    $Context.Counters.Questions++
    $q = New-FollowUpQuestion -Question $Question -Category $Category -Module $Module -RelatedFinding $RelatedFinding -Audience $Audience
    $Context.FollowUpQuestions.Add($q)
    return $q
}

function Add-ScopeLanguage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('Assumption','Exclusion','ClientResponsibility','VendorResponsibility','ChangeOrderTrigger','Cutover','Validation','Licensing','Credential','BackupRollback')][string]$Type = 'Assumption',
        [string]$Module = '',
        [string]$RelatedFinding = ''
    )
    $s = [pscustomobject]@{ Type=$Type; Text=$Text; Module=$Module; RelatedFinding=$RelatedFinding }
    $Context.ScopeLanguage.Add($s)
    return $s
}

function Add-DependencyEdge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$SourceType,
        [Parameter(Mandatory)][string]$SourceName,
        [Parameter(Mandatory)][string]$DependencyType,
        [string]$Target = '',
        [string]$Evidence = '',
        [string]$Confidence = 'Likely',
        [string]$SourceDataset = '',
        [string]$ProjectImpact = '',
        [string]$ValidationQuestion = ''
    )
    $edge = New-DependencyEdge -SourceType $SourceType -SourceName $SourceName -DependencyType $DependencyType `
        -Target $Target -Evidence $Evidence -Confidence $Confidence -SourceDataset $SourceDataset `
        -ProjectImpact $ProjectImpact -ValidationQuestion $ValidationQuestion
    $Context.DependencyEdges.Add($edge)
    return $edge
}

function Add-ModuleStatus {
    <# Records a module's prerequisite / run status for the discovery plan. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ModuleName,
        [bool]$CanRun = $true,
        [string]$Status = 'Ready',
        [string]$Reason = '',
        [string[]]$Limitations = @(),
        [string]$Outcome = 'Pending',
        [int]$DurationMs = 0
    )
    $ms = [pscustomobject]@{
        ModuleName=$ModuleName; CanRun=$CanRun; Status=$Status; Reason=$Reason
        Limitations=@($Limitations); Outcome=$Outcome; DurationMs=$DurationMs
    }
    $Context.ModuleStatuses.Add($ms)
    return $ms
}

#endregion

#region Status files ----------------------------------------------------------

function Update-StatusFile {
    <#
        Writes the live status/progress/findings JSON files for the future GUI.
        Called after each module completes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [string]$Phase = 'Collecting',
        [string]$CurrentModule = '',
        [int]$CompletedModules = 0,
        [int]$TotalModules = 0
    )
    if (-not $Context.Paths -or -not $Context.Paths.Contains('Status')) { return }
    $statusDir = $Context.Paths['Status']
    $pct = 0
    if ($TotalModules -gt 0) { $pct = [math]::Round(($CompletedModules / $TotalModules) * 100, 0) }

    $status = [ordered]@{
        RunId=$Context.RunId; ComputerName=$Context.ComputerName; Mode=$Context.Mode
        ProjectType=$Context.ProjectType; ComplianceLens=$Context.ComplianceLens
        Phase=$Phase; CurrentModule=$CurrentModule; PercentComplete=$pct
        StartTime=$Context.StartTime.ToString('o'); UpdatedTime=(Get-Date).ToString('o')
        FindingCount=$Context.Findings.Count; ErrorCount=$Context.Counters.Errors
        WarningCount=$Context.Counters.Warnings; LimitationCount=$Context.Limitations.Count
        DatasetCount=$Context.DataSets.Count
    }
    $progress = [ordered]@{
        Phase=$Phase; CurrentModule=$CurrentModule; CompletedModules=$CompletedModules
        TotalModules=$TotalModules; PercentComplete=$pct; UpdatedTime=(Get-Date).ToString('o')
        Modules=@($Context.ModuleStatuses | ForEach-Object { [ordered]@{ Name=$_.ModuleName; Status=$_.Status; Outcome=$_.Outcome; DurationMs=$_.DurationMs } })
    }
    $findingsLive = @($Context.Findings | ForEach-Object {
        [ordered]@{ FindingId=$_.FindingId; Severity=$_.Severity; Confidence=$_.Confidence; Category=$_.Category; Title=$_.Title; SourceModule=$_.SourceModule }
    })

    try { ($status       | ConvertTo-Json -Depth 6) | Out-File -LiteralPath (Join-Path $statusDir 'status.json')        -Encoding UTF8 -Force } catch { }
    try { ($progress     | ConvertTo-Json -Depth 6) | Out-File -LiteralPath (Join-Path $statusDir 'progress.json')      -Encoding UTF8 -Force } catch { }
    try { ($findingsLive | ConvertTo-Json -Depth 6) | Out-File -LiteralPath (Join-Path $statusDir 'findings-live.json') -Encoding UTF8 -Force } catch { }
}

#endregion

Export-ModuleMember -Function `
    'Import-DiscoveryConfig','Get-DiscoveryConfigBundle','Get-DiscoveryBrandingDirectory','Merge-LocalBranding','Get-DiscoveryBranding','Get-DiscoveryLogoDataUri','New-DiscoveryContext', `
    'Ensure-Directory','ConvertTo-SafeFileName','Test-IsAdministrator','Test-IsSystem', `
    'Get-CommandAvailable','Get-ModuleAvailable','Get-RegistryValueSafe','Test-RegistryPathSafe', `
    'Invoke-CimSafe','Invoke-CommandLineSafe','Invoke-WindowsPowerShellJson','Test-WindowsPowerShellModule','Convert-BytesToGB','Convert-BytesToMB','Normalize-DateTime', `
    'Test-SensitiveKeyLabel','Redact-SensitiveValue','Write-Log','Write-SectionStatus', `
    'New-DiscoveryDataset','New-DiscoveryFinding','New-ScopingRisk','New-FollowUpQuestion','New-DependencyEdge', `
    'Add-DataSet','Add-Finding','Add-Limitation','Add-Unknown','Add-FollowUpQuestion','Add-ScopeLanguage', `
    'Add-DependencyEdge','Add-ModuleStatus','Update-StatusFile'
