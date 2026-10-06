<#
    SystemInventory.psm1
    Ultimate Modular Windows Server Discovery Toolkit - System Inventory collector.

    Owns datasets:
      ExecutionContext, OperatingSystem, Hardware, BiosFirmware, Processors,
      Memory, PageFile, PendingReboot, PhysicalVirtualDetection, HardwareVendor.
      (TimeSync is owned by the dedicated TimeSync module - see modules\TimeSync.)

    Design rules (enforced throughout this module):
      - Windows PowerShell 5.1 compatible. No PS7-only syntax.
      - STRICTLY READ-ONLY. Only CIM/registry reads, read-only cmdlets, and
        read-only command-line tools (w32tm /query). Nothing changes the system.
      - Defensive: every collection block is wrapped in try/catch so a single
        failure never stops the module. No Set-StrictMode.
      - Emits the canonical dataset field names the RiskEngine rules depend on
        (OperatingSystem.IsEndOfLifeOrNear, ExecutionContext.IsAdmin,
         PendingReboot.RebootPending) as real booleans.
#>

#region Private helpers -------------------------------------------------------

function Get-SIFirst {
    <# Returns the first element of a possibly-null/empty array, or $null. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    $arr = @($Value)
    if ($arr.Count -gt 0) { return $arr[0] }
    return $null
}

function ConvertTo-SIBool {
    <# Coerces a CIM/registry value to a real [bool], with a default for $null. #>
    param($Value, [bool]$Default = $false)
    if ($null -eq $Value) { return $Default }
    try { return [bool]$Value } catch { return $Default }
}

function Get-SIString {
    <# Trims a value to a clean string; $null becomes ''. #>
    param($Value)
    if ($null -eq $Value) { return '' }
    try { return ([string]$Value).Trim() } catch { return '' }
}

function Get-SIDatasetRow {
    <# Returns the first row of a named dataset, or $null. #>
    param([object]$Context, [string]$Name)
    try {
        if ($Context -and $Context.DataSets -and $Context.DataSets.Contains($Name)) {
            $rows = @($Context.DataSets[$Name].Rows)
            if ($rows.Count -gt 0) { return $rows[0] }
        }
    } catch { }
    return $null
}

function Get-SIChassisType {
    <# Maps a Win32_SystemEnclosure ChassisTypes code to a friendly label. #>
    param($Codes)
    $map = @{
        1='Other';2='Unknown';3='Desktop';4='Low Profile Desktop';5='Pizza Box';
        6='Mini Tower';7='Tower';8='Portable';9='Laptop';10='Notebook';11='Hand Held';
        12='Docking Station';13='All in One';14='Sub Notebook';15='Space-Saving';
        16='Lunch Box';17='Main System Chassis';18='Expansion Chassis';19='SubChassis';
        20='Bus Expansion Chassis';21='Peripheral Chassis';22='Storage Chassis';
        23='Rack Mount Chassis';24='Sealed-Case PC';28='Blade';29='Blade Enclosure';
        32='Tablet';35='Convertible';36='Detachable'
    }
    $first = Get-SIFirst $Codes
    if ($null -eq $first) { return '' }
    $key = 0
    if ([int]::TryParse([string]$first, [ref]$key) -and $map.ContainsKey($key)) { return $map[$key] }
    return ("Code {0}" -f $first)
}

function Get-SIOsEdition {
    <# Best-effort friendly OS edition from Caption keyword, then SKU fallback. #>
    param([string]$Caption, $Sku)
    $cap = Get-SIString $Caption
    foreach ($w in @('Datacenter','Enterprise','Essentials','Foundation','Standard','Web','Education','Professional','Ultimate','Business','Home','Pro')) {
        if ($cap -match ('(?i)\b' + [regex]::Escape($w) + '\b')) { return $w }
    }
    $skuMap = @{
        7='Standard Server';8='Datacenter Server';10='Enterprise Server';
        12='Datacenter Server Core';13='Standard Server Core';14='Enterprise Server Core';
        4='Enterprise';27='Enterprise (N)';48='Professional';49='Professional (N)';
        101='Home';161='Pro for Workstations';175='Enterprise for Virtual Desktops'
    }
    if ($null -ne $Sku) {
        $skuInt = 0
        if ([int]::TryParse([string]$Sku, [ref]$skuInt) -and $skuMap.ContainsKey($skuInt)) { return $skuMap[$skuInt] }
    }
    return ''
}

function Get-SIEndOfLifeInfo {
    <#
        Conservative end-of-life / near-end-of-life determination from OS caption.
        Returns @{ IsEol=[bool]; Known=[bool]; Evidence=[string] }.
        If the OS cannot be classified, Known=$false and IsEol=$false (caller
        records an Unknown rather than guessing).
    #>
    param([string]$Caption, [string]$BuildNumber)
    $cap = Get-SIString $Caption
    $result = @{ IsEol = $false; Known = $true; Evidence = '' }
    if ([string]::IsNullOrWhiteSpace($cap)) { $result.Known = $false; return $result }

    $isServer = ($cap -match '(?i)server')
    if ($isServer) {
        if ($cap -match '(?i)(2000|2003|2008|2012)') {
            $result.IsEol = $true
            $result.Evidence = ("'{0}' is a Windows Server release (2003/2008/2008 R2/2012/2012 R2 or older) that is past Microsoft end of support." -f $cap)
        } elseif ($cap -match '(?i)2016') {
            $result.IsEol = $true
            $result.Evidence = ("'{0}' (Windows Server 2016) extended support ends 2027-01-12 - within the near-end-of-life window." -f $cap)
        } elseif ($cap -match '(?i)(2019|2022|2025)') {
            $result.IsEol = $false
            $result.Evidence = ("'{0}' is a currently supported Windows Server release." -f $cap)
        } else {
            $result.Known = $false
            $result.Evidence = ("Could not confidently classify support status of server OS '{0}'." -f $cap)
        }
    } else {
        if ($cap -match '(?i)(Windows XP|Windows Vista|Windows 7|Windows 8)') {
            $result.IsEol = $true
            $result.Evidence = ("'{0}' is a client Windows release (XP/Vista/7/8/8.1) that is past Microsoft end of support." -f $cap)
        } elseif ($cap -match '(?i)Windows 10') {
            $result.IsEol = $true
            $result.Evidence = ("'{0}' (Windows 10) reached end of support on 2025-10-14 (excluding paid ESU)." -f $cap)
        } elseif ($cap -match '(?i)Windows 11') {
            $result.IsEol = $false
            $result.Evidence = ("'{0}' (Windows 11) is currently supported." -f $cap)
        } else {
            $result.Known = $false
            $result.Evidence = ("Could not confidently classify support status of client OS '{0}'." -f $cap)
        }
    }
    return $result
}

function Get-SIPlatformDetection {
    <#
        Infers physical vs. virtual platform from manufacturer/model/BIOS strings
        and the SMBIOS asset tag. Returns @{ Platform; Evidence; Confidence }.
    #>
    param([string]$Manufacturer, [string]$Model, [string]$BiosManufacturer, [string]$BiosVersion, [string]$AssetTag)
    $mfg   = Get-SIString $Manufacturer
    $model = Get-SIString $Model
    $bMfg  = Get-SIString $BiosManufacturer
    $bVer  = Get-SIString $BiosVersion
    $tag   = Get-SIString $AssetTag
    $hay   = ("{0} | {1} | {2} | {3}" -f $mfg, $model, $bMfg, $bVer)
    $evidence = ("Manufacturer='{0}'; Model='{1}'; BIOS='{2} {3}'" -f $mfg, $model, $bMfg, $bVer)

    # Azure uses a well-known SMBIOS chassis asset tag.
    if ($tag -eq '7783-7084-3265-9085-8269-3286-77') {
        return @{ Platform='Azure (Hyper-V)'; Evidence=("Azure well-known SMBIOS asset tag detected. {0}" -f $evidence); Confidence='Confirmed' }
    }
    if ($hay -match '(?i)VMware')                    { return @{ Platform='VMware';        Evidence=$evidence; Confidence='Confirmed' } }
    if ($hay -match '(?i)VirtualBox|innotek')        { return @{ Platform='VirtualBox';    Evidence=$evidence; Confidence='Confirmed' } }
    if ($hay -match '(?i)QEMU|KVM')                  { return @{ Platform='KVM/QEMU';      Evidence=$evidence; Confidence='Confirmed' } }
    if ($hay -match '(?i)Xen')                       { return @{ Platform='Xen';           Evidence=$evidence; Confidence='Confirmed' } }
    if ($hay -match '(?i)Parallels')                 { return @{ Platform='Parallels';     Evidence=$evidence; Confidence='Confirmed' } }
    if ($hay -match '(?i)Amazon|EC2')                { return @{ Platform='AWS EC2';       Evidence=$evidence; Confidence='Confirmed' } }
    if ($hay -match '(?i)Google')                    { return @{ Platform='Google Compute Engine'; Evidence=$evidence; Confidence='Confirmed' } }
    if ($mfg -match '(?i)Microsoft' -and $model -match '(?i)Virtual Machine') {
        return @{ Platform='Hyper-V'; Evidence=("Microsoft 'Virtual Machine' model detected. {0}" -f $evidence); Confidence='Likely' }
    }
    if ($hay -match '(?i)Virtual') {
        return @{ Platform='Virtual (unspecified)'; Evidence=("Generic virtual marker detected. {0}" -f $evidence); Confidence='Possible' }
    }
    return @{ Platform='Physical'; Evidence=("No virtualization markers detected. {0}" -f $evidence); Confidence='Likely' }
}

#endregion

#region Contract: metadata & prerequisites ------------------------------------

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'SystemInventory'
        DisplayName               = 'System Inventory'
        Category                  = 'System'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Low'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('ExecutionContext','OperatingSystem','Hardware','BiosFirmware','Processors','Memory','PageFile','PendingReboot','PhysicalVirtualDetection','HardwareVendor')
        ProducesRisks             = $true
        ProducesFollowUpQuestions = $true
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    # System inventory relies on core CIM/registry which are always present.
    # It runs (with reduced completeness) even without elevation, so it is always Ready.
    $limitations = @()
    if ($Context -and -not $Context.IsAdmin) {
        $limitations += 'Not elevated: Secure Boot / TPM / some firmware details may be unavailable.'
    }
    [pscustomobject]@{
        ModuleName  = 'SystemInventory'
        CanRun      = $true
        Status      = 'Ready'
        Reason      = ''
        Limitations = @($limitations)
    }
}

#endregion

#region Contract: collection --------------------------------------------------

function Invoke-DiscoveryCollection {
    param([object]$Context)
    Write-SectionStatus -Title 'System Inventory' -Status 'Collecting' -Context $Context

    $raw = @{
        ExecutionContext         = $null
        OperatingSystem          = $null
        Hardware                 = $null
        BiosFirmware             = $null
        Processors               = @()
        Memory                   = @()
        PageFile                 = @()
        PendingReboot            = $null
        PhysicalVirtualDetection = $null
        HardwareVendor           = $null
    }

    # --- Shared CIM reads (each never throws; returns @()) --------------------
    $cs        = Get-SIFirst (Invoke-CimSafe -ClassName 'Win32_ComputerSystem')
    $os        = Get-SIFirst (Invoke-CimSafe -ClassName 'Win32_OperatingSystem')
    $bios      = Get-SIFirst (Invoke-CimSafe -ClassName 'Win32_BIOS')
    $enclosure = Get-SIFirst (Invoke-CimSafe -ClassName 'Win32_SystemEnclosure')
    $baseboard = Get-SIFirst (Invoke-CimSafe -ClassName 'Win32_BaseBoard')
    $procs     = @(Invoke-CimSafe -ClassName 'Win32_Processor')
    $mem       = @(Invoke-CimSafe -ClassName 'Win32_PhysicalMemory')
    $pagefiles = @(Invoke-CimSafe -ClassName 'Win32_PageFileUsage')

    if (-not $os) { Add-Limitation -Context $Context -Module 'SystemInventory' -Message 'Win32_OperatingSystem was unavailable; OS details may be incomplete.' -Impact 'Reduced OS detail' | Out-Null }
    if (-not $cs) { Add-Limitation -Context $Context -Module 'SystemInventory' -Message 'Win32_ComputerSystem was unavailable; hardware details may be incomplete.' -Impact 'Reduced hardware detail' | Out-Null }

    # --- ExecutionContext -----------------------------------------------------
    try {
        $currentUser = ''
        try { $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $currentUser = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) }
        $curDir = ''
        try { $curDir = (Get-Location).Path } catch { $curDir = '' }
        $culture = ''
        try { $culture = (Get-Culture).Name } catch { $culture = '' }
        $tzName = ''
        try {
            if (Get-CommandAvailable -Name 'Get-TimeZone') { $tzName = (Get-TimeZone).DisplayName }
            else { $tzName = Get-SIString (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -Name 'TimeZoneKeyName') }
        } catch { $tzName = '' }

        $raw.ExecutionContext = [pscustomobject]([ordered]@{
            IsAdmin           = (ConvertTo-SIBool $Context.IsAdmin)
            IsSystem          = (ConvertTo-SIBool $Context.IsSystem)
            PowerShellVersion = (Get-SIString $Context.PowerShellVersion)
            CurrentUser       = $currentUser
            CurrentDirectory  = $curDir
            Culture           = $culture
            TimeZone          = $tzName
            RunId             = (Get-SIString $Context.RunId)
            Mode              = (Get-SIString $Context.Mode)
            ProjectType       = (Get-SIString $Context.ProjectType)
            ComputerName      = (Get-SIString $Context.ComputerName)
        })
    } catch { Write-Log -Level WARN -Message 'ExecutionContext collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- OperatingSystem ------------------------------------------------------
    try {
        if ($os) {
            $caption = Get-SIString $os.Caption
            $build   = Get-SIString $os.BuildNumber
            $eol     = Get-SIEndOfLifeInfo -Caption $caption -BuildNumber $build
            $raw.OperatingSystem = [pscustomobject]([ordered]@{
                Caption              = $caption
                Version              = (Get-SIString $os.Version)
                BuildNumber          = $build
                Edition              = (Get-SIOsEdition -Caption $caption -Sku $os.OperatingSystemSKU)
                OperatingSystemSKU   = (Get-SIString $os.OperatingSystemSKU)
                Architecture         = (Get-SIString $os.OSArchitecture)
                InstallDate          = (Normalize-DateTime $os.InstallDate)
                LastBootTime         = (Normalize-DateTime $os.LastBootUpTime)
                RegisteredOrg        = (Get-SIString $os.Organization)
                IsEndOfLifeOrNear    = [bool]$eol.IsEol
                EndOfLifeKnown       = [bool]$eol.Known
                EndOfLifeEvidence    = (Get-SIString $eol.Evidence)
            })
        }
    } catch { Write-Log -Level WARN -Message 'OperatingSystem collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- Hardware -------------------------------------------------------------
    try {
        if ($cs -or $enclosure) {
            $raw.Hardware = [pscustomobject]([ordered]@{
                Manufacturer         = (Get-SIString $cs.Manufacturer)
                Model                = (Get-SIString $cs.Model)
                SystemType           = (Get-SIString $cs.SystemType)
                TotalPhysicalMemoryGB= (Convert-BytesToGB $cs.TotalPhysicalMemory)
                SerialNumber         = (Get-SIString $enclosure.SerialNumber)
                AssetTag             = (Get-SIString $enclosure.SMBIOSAssetTag)
                ChassisType          = (Get-SIChassisType $enclosure.ChassisTypes)
                PhysicalProcessors   = $cs.NumberOfProcessors
                LogicalProcessors    = $cs.NumberOfLogicalProcessors
            })
        }
    } catch { Write-Log -Level WARN -Message 'Hardware collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- BiosFirmware (BIOS, baseboard, Secure Boot, TPM) ---------------------
    try {
        $biosVersion = ''
        if ($bios -and $bios.BIOSVersion) { $biosVersion = (@($bios.BIOSVersion) -join '; ') }

        # Secure Boot (read-only). Confirm-SecureBootUEFI throws on legacy BIOS.
        $secureBoot = $null
        if (Get-CommandAvailable -Name 'Confirm-SecureBootUEFI') {
            try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = $null }
        }

        # TPM (read-only): prefer Get-Tpm, fall back to the microsofttpm WMI namespace.
        $tpmPresent = $false; $tpmEnabled = $null; $tpmSpec = ''
        if (Get-CommandAvailable -Name 'Get-Tpm') {
            try {
                $tpm = Get-Tpm -ErrorAction Stop
                if ($tpm) {
                    if ($null -ne $tpm.TpmPresent) { $tpmPresent = [bool]$tpm.TpmPresent }
                    elseif ($null -ne $tpm.TpmReady) { $tpmPresent = [bool]$tpm.TpmReady }
                    if ($null -ne $tpm.TpmEnabled) { $tpmEnabled = [bool]$tpm.TpmEnabled }
                }
            } catch { }
        }
        if (-not $tpmPresent) {
            try {
                $wtpm = Get-SIFirst (Invoke-CimSafe -Namespace 'root/cimv2/security/microsofttpm' -ClassName 'Win32_Tpm')
                if ($wtpm) {
                    $tpmPresent = $true
                    if ($null -ne $wtpm.IsEnabled_InitialValue) { $tpmEnabled = [bool]$wtpm.IsEnabled_InitialValue }
                    $tpmSpec = Get-SIString $wtpm.SpecVersion
                }
            } catch { }
        }

        $raw.BiosFirmware = [pscustomobject]([ordered]@{
            Manufacturer          = (Get-SIString $bios.Manufacturer)
            SMBIOSBIOSVersion     = (Get-SIString $bios.SMBIOSBIOSVersion)
            BIOSVersion           = (Get-SIString $biosVersion)
            ReleaseDate           = (Normalize-DateTime $bios.ReleaseDate)
            BaseBoardManufacturer = (Get-SIString $baseboard.Manufacturer)
            BaseBoardProduct      = (Get-SIString $baseboard.Product)
            BaseBoardVersion      = (Get-SIString $baseboard.Version)
            SecureBootEnabled     = $secureBoot
            TpmPresent            = [bool]$tpmPresent
            TpmEnabled            = $tpmEnabled
            TpmSpecVersion        = (Get-SIString $tpmSpec)
        })
    } catch { Write-Log -Level WARN -Message 'BiosFirmware collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- Processors -----------------------------------------------------------
    try {
        $socketCount = @($procs).Count
        $procRows = [System.Collections.Generic.List[object]]::new()
        foreach ($p in @($procs)) {
            $procRows.Add([pscustomobject]([ordered]@{
                Name                     = (Get-SIString $p.Name)
                Manufacturer             = (Get-SIString $p.Manufacturer)
                SocketDesignation        = (Get-SIString $p.SocketDesignation)
                NumberOfCores            = $p.NumberOfCores
                NumberOfLogicalProcessors= $p.NumberOfLogicalProcessors
                MaxClockSpeed            = $p.MaxClockSpeed
                SocketCount              = $socketCount
            }))
        }
        $raw.Processors = @($procRows)
    } catch { Write-Log -Level WARN -Message 'Processors collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- Memory ---------------------------------------------------------------
    try {
        $memRows = [System.Collections.Generic.List[object]]::new()
        foreach ($m in @($mem)) {
            $memRows.Add([pscustomobject]([ordered]@{
                DeviceLocator = (Get-SIString $m.DeviceLocator)
                CapacityGB    = (Convert-BytesToGB $m.Capacity)
                Speed         = $m.Speed
                Manufacturer  = (Get-SIString $m.Manufacturer)
                PartNumber    = (Get-SIString $m.PartNumber)
                FormFactor    = $m.FormFactor
            }))
        }
        $raw.Memory = @($memRows)
    } catch { Write-Log -Level WARN -Message 'Memory collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- PageFile -------------------------------------------------------------
    try {
        $autoManaged = $false
        if ($cs -and $null -ne $cs.AutomaticManagedPagefile) { $autoManaged = [bool]$cs.AutomaticManagedPagefile }
        $pfRows = [System.Collections.Generic.List[object]]::new()
        foreach ($pf in @($pagefiles)) {
            $pfRows.Add([pscustomobject]([ordered]@{
                Name                = (Get-SIString $pf.Name)
                AllocatedBaseSizeMB = $pf.AllocatedBaseSize
                CurrentUsageMB      = $pf.CurrentUsage
                PeakUsageMB         = $pf.PeakUsage
                AutomaticManaged    = [bool]$autoManaged
            }))
        }
        if ($pfRows.Count -eq 0) {
            # No explicit page file usage entries; still record the managed state.
            $pfRows.Add([pscustomobject]([ordered]@{
                Name                = ''
                AllocatedBaseSizeMB = $null
                CurrentUsageMB      = $null
                PeakUsageMB         = $null
                AutomaticManaged    = [bool]$autoManaged
            }))
        }
        $raw.PageFile = @($pfRows)
    } catch { Write-Log -Level WARN -Message 'PageFile collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- PendingReboot (registry only, read-only) -----------------------------
    try {
        $cbs = Test-RegistryPathSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $wu  = Test-RegistryPathSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $pfr = $false
        $pfrVal = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
        if ($null -ne $pfrVal -and @($pfrVal | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) { $pfr = $true }
        $renamePending = $false
        try {
            $active = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName'
            $pendName = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName'
            if ($active -and $pendName -and ([string]$active -ne [string]$pendName)) { $renamePending = $true }
        } catch { }

        $indicators = [System.Collections.Generic.List[string]]::new()
        if ($cbs)           { $indicators.Add('Component Based Servicing (RebootPending)') }
        if ($wu)            { $indicators.Add('Windows Update (RebootRequired)') }
        if ($pfr)           { $indicators.Add('PendingFileRenameOperations') }
        if ($renamePending) { $indicators.Add('Pending computer rename') }

        $rebootPending = ($cbs -or $wu -or $pfr -or $renamePending)
        $raw.PendingReboot = [pscustomobject]([ordered]@{
            RebootPending               = [bool]$rebootPending
            ComponentBasedServicing     = [bool]$cbs
            WindowsUpdateRebootRequired = [bool]$wu
            PendingFileRenameOperations = [bool]$pfr
            PendingComputerRename       = [bool]$renamePending
            Indicators                  = (@($indicators) -join '; ')
        })
    } catch { Write-Log -Level WARN -Message 'PendingReboot collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- PhysicalVirtualDetection --------------------------------------------
    try {
        $biosVerForDetect = ''
        if ($bios -and $bios.BIOSVersion) { $biosVerForDetect = (@($bios.BIOSVersion) -join ' ') }
        $det = Get-SIPlatformDetection -Manufacturer $cs.Manufacturer -Model $cs.Model -BiosManufacturer $bios.Manufacturer -BiosVersion ("{0} {1}" -f (Get-SIString $bios.SMBIOSBIOSVersion), $biosVerForDetect) -AssetTag $enclosure.SMBIOSAssetTag
        $raw.PhysicalVirtualDetection = [pscustomobject]([ordered]@{
            Platform   = (Get-SIString $det.Platform)
            IsVirtual  = [bool]($det.Platform -and $det.Platform -notmatch '(?i)^Physical$')
            Evidence   = (Get-SIString $det.Evidence)
            Confidence = (Get-SIString $det.Confidence)
        })
    } catch { Write-Log -Level WARN -Message 'PhysicalVirtualDetection collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # --- HardwareVendor -------------------------------------------------------
    try {
        $controllers = @(Invoke-CimSafe -ClassName 'Win32_SCSIController')
        $ctrlNames = @($controllers | ForEach-Object { Get-SIString $_.Name } | Where-Object { $_ } | Select-Object -Unique)
        $disks = @(Invoke-CimSafe -ClassName 'Win32_DiskDrive')
        $diskModels = @($disks | ForEach-Object { Get-SIString $_.Model } | Where-Object { $_ } | Select-Object -Unique)

        # Vendor management tool hints (service names). Read-only lookup only.
        $vendorHints = [System.Collections.Generic.List[string]]::new()
        try {
            $svcNames = @(Invoke-CimSafe -ClassName 'Win32_Service' -Property @('Name','DisplayName') | ForEach-Object { "{0} {1}" -f (Get-SIString $_.Name), (Get-SIString $_.DisplayName) })
            $svcBlob = ($svcNames -join ' | ')
            if ($svcBlob -match '(?i)iDRAC|OpenManage|Dell')      { $vendorHints.Add('Dell (iDRAC/OpenManage) service indicators present') }
            if ($svcBlob -match '(?i)iLO|Insight|HPE?|ProLiant')  { $vendorHints.Add('HPE (iLO/Insight/ProLiant) service indicators present') }
            if ($svcBlob -match '(?i)XClarity|IMM|ThinkSystem|Lenovo') { $vendorHints.Add('Lenovo (XClarity/XCC/ThinkSystem) service indicators present') }
        } catch { }

        $raw.HardwareVendor = [pscustomobject]([ordered]@{
            Manufacturer          = (Get-SIString $cs.Manufacturer)
            Model                 = (Get-SIString $cs.Model)
            SerialNumber          = (Get-SIString $enclosure.SerialNumber)
            StorageControllers    = (@($ctrlNames) -join '; ')
            DiskDriveModels       = (@($diskModels) -join '; ')
            VendorManagementHints = (@($vendorHints) -join '; ')
            WarrantyStatus        = 'Unknown (requires vendor lookup; not performed - read-only, no internet access)'
        })
    } catch { Write-Log -Level WARN -Message 'HardwareVendor collection failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    return $raw
}

#endregion

#region Contract: dataset conversion ------------------------------------------

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)

    # Always emit ExecutionContext (RULE-CORE-NOTADMIN depends on it), even if
    # collection produced nothing - reconstruct from the context as a fallback.
    try {
        $ecRow = $null
        if ($RawData -and $RawData.ExecutionContext) { $ecRow = $RawData.ExecutionContext }
        if (-not $ecRow) {
            $cu = ''
            try { $cu = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $cu = $env:USERNAME }
            $ecRow = [pscustomobject]([ordered]@{
                IsAdmin           = (ConvertTo-SIBool $Context.IsAdmin)
                IsSystem          = (ConvertTo-SIBool $Context.IsSystem)
                PowerShellVersion = (Get-SIString $Context.PowerShellVersion)
                CurrentUser       = $cu
                CurrentDirectory  = ''
                Culture           = ''
                TimeZone          = ''
                RunId             = (Get-SIString $Context.RunId)
                Mode              = (Get-SIString $Context.Mode)
                ProjectType       = (Get-SIString $Context.ProjectType)
                ComputerName      = (Get-SIString $Context.ComputerName)
            })
        }
        Add-DataSet -Context $Context -Name 'ExecutionContext' -Description 'Runtime execution context of this discovery run (privilege level, user, mode).' -Rows @($ecRow) -Visibility 'Internal' -SourceModule 'SystemInventory' | Out-Null
    } catch { Write-Log -Level WARN -Message 'ExecutionContext dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    if ($null -eq $RawData) {
        Add-Limitation -Context $Context -Module 'SystemInventory' -Message 'No raw system inventory data was returned; only a fallback ExecutionContext row was emitted.' -Impact 'Reduced system detail' | Out-Null
        return
    }

    # OperatingSystem
    try {
        if ($RawData.OperatingSystem) {
            Add-DataSet -Context $Context -Name 'OperatingSystem' -Description 'Operating system identity, build, install/boot dates, and end-of-life assessment.' -Rows @($RawData.OperatingSystem) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
            if (-not $RawData.OperatingSystem.EndOfLifeKnown) {
                Add-Unknown -Context $Context -Unknown ("Support/end-of-life status of OS '{0}' could not be determined automatically." -f (Get-SIString $RawData.OperatingSystem.Caption)) -WhyItMatters 'An unsupported OS materially affects migration urgency, security posture, and scoping.' -Evidence (Get-SIString $RawData.OperatingSystem.EndOfLifeEvidence) -RecommendedValidationQuestion 'What is the support/lifecycle status of this operating system, and is a migration already planned?' -Module 'SystemInventory' | Out-Null
            }
        }
    } catch { Write-Log -Level WARN -Message 'OperatingSystem dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # Hardware
    try {
        if ($RawData.Hardware) {
            Add-DataSet -Context $Context -Name 'Hardware' -Description 'Chassis, manufacturer/model, serial/asset tag, and total physical memory.' -Rows @($RawData.Hardware) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'Hardware dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # BiosFirmware
    try {
        if ($RawData.BiosFirmware) {
            Add-DataSet -Context $Context -Name 'BiosFirmware' -Description 'BIOS/UEFI, baseboard, Secure Boot, and TPM firmware details.' -Rows @($RawData.BiosFirmware) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'BiosFirmware dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # Processors
    try {
        Add-DataSet -Context $Context -Name 'Processors' -Description 'Physical processor sockets with core/logical/clock details.' -Rows @($RawData.Processors) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
    } catch { Write-Log -Level WARN -Message 'Processors dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # Memory
    try {
        Add-DataSet -Context $Context -Name 'Memory' -Description 'Installed physical memory modules (per DIMM slot).' -Rows @($RawData.Memory) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
    } catch { Write-Log -Level WARN -Message 'Memory dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # PageFile
    try {
        Add-DataSet -Context $Context -Name 'PageFile' -Description 'Page file configuration and usage.' -Rows @($RawData.PageFile) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
    } catch { Write-Log -Level WARN -Message 'PageFile dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # PendingReboot
    try {
        if ($RawData.PendingReboot) {
            Add-DataSet -Context $Context -Name 'PendingReboot' -Description 'Pending-reboot indicators from Component Based Servicing, Windows Update, and file-rename operations.' -Rows @($RawData.PendingReboot) -Visibility 'Internal' -SourceModule 'SystemInventory' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'PendingReboot dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # PhysicalVirtualDetection
    try {
        if ($RawData.PhysicalVirtualDetection) {
            Add-DataSet -Context $Context -Name 'PhysicalVirtualDetection' -Description 'Inferred physical vs. virtual/cloud platform for this server.' -Rows @($RawData.PhysicalVirtualDetection) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'PhysicalVirtualDetection dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    # HardwareVendor
    try {
        if ($RawData.HardwareVendor) {
            Add-DataSet -Context $Context -Name 'HardwareVendor' -Description 'Hardware vendor, serial, storage controllers, and management-tool hints (no warranty lookup).' -Rows @($RawData.HardwareVendor) -Visibility 'Both' -SourceModule 'SystemInventory' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'HardwareVendor dataset build failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

}

#endregion

#region Contract: risk analysis (light) ---------------------------------------

function Invoke-DiscoveryRiskAnalysis {
    param([object]$Context)
    # EOL OS is handled by RiskEngine rule RULE-OS-EOL (keyed off
    # OperatingSystem.IsEndOfLifeOrNear), so this stays light and only records
    # dependency/unknown context the rule engine does not derive.
    try {
        $pv = Get-SIDatasetRow -Context $Context -Name 'PhysicalVirtualDetection'
        if ($pv -and (ConvertTo-SIBool $pv.IsVirtual)) {
            Add-DependencyEdge -Context $Context -SourceType 'Server' -SourceName $Context.ComputerName -DependencyType 'HostedOn' -Target (Get-SIString $pv.Platform) -Evidence (Get-SIString $pv.Evidence) -Confidence (Get-SIString $pv.Confidence) -SourceDataset 'PhysicalVirtualDetection' -ProjectImpact 'Architecture Decision' -ValidationQuestion 'Which host/cluster or cloud subscription runs this VM, and is that platform in scope for the project?' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'Virtualization dependency edge failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    try {
        $hv = Get-SIDatasetRow -Context $Context -Name 'HardwareVendor'
        $pv = Get-SIDatasetRow -Context $Context -Name 'PhysicalVirtualDetection'
        $isPhysical = (-not $pv) -or (-not (ConvertTo-SIBool $pv.IsVirtual))
        if ($hv -and $isPhysical) {
            Add-Unknown -Context $Context -Unknown 'Hardware warranty / vendor support status cannot be determined from the server itself.' -WhyItMatters 'Out-of-warranty hardware affects migration urgency, risk tolerance, and whether hardware replacement belongs in scope.' -Evidence ("Manufacturer='{0}'; Model='{1}'; Serial='{2}'." -f (Get-SIString $hv.Manufacturer), (Get-SIString $hv.Model), (Get-SIString $hv.SerialNumber)) -RecommendedValidationQuestion 'What is the current warranty/support status for this hardware (by make/model/serial)?' -Module 'SystemInventory' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'Warranty unknown record failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }
}

#endregion

#region Contract: follow-up questions -----------------------------------------

function Get-DiscoveryFollowUpQuestions {
    param([object]$Context)
    try {
        $pv = Get-SIDatasetRow -Context $Context -Name 'PhysicalVirtualDetection'
        if ($pv -and (ConvertTo-SIBool $pv.IsVirtual)) {
            Add-FollowUpQuestion -Context $Context -Question ("This server appears to run on '{0}'. Which host/cluster or cloud platform is it on, and is that platform in scope?" -f (Get-SIString $pv.Platform)) -Category 'Infrastructure' -Module 'SystemInventory' -Audience 'Both' | Out-Null
        } elseif ($pv) {
            Add-FollowUpQuestion -Context $Context -Question 'This server appears to be physical hardware. What is its warranty/support status and expected refresh timeline?' -Category 'Infrastructure' -Module 'SystemInventory' -Audience 'Both' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'Follow-up question generation failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }

    try {
        $os = Get-SIDatasetRow -Context $Context -Name 'OperatingSystem'
        if ($os -and (ConvertTo-SIBool $os.IsEndOfLifeOrNear)) {
            Add-FollowUpQuestion -Context $Context -Question ("The operating system '{0}' is at or near end of support. Is a migration or upgrade already planned, and by when?" -f (Get-SIString $os.Caption)) -Category 'Operating System' -Module 'SystemInventory' -Audience 'Both' | Out-Null
        }
    } catch { Write-Log -Level WARN -Message 'OS follow-up question generation failed.' -Module 'SystemInventory' -Exception $_ -Context $Context }
}

#endregion

Export-ModuleMember -Function `
    'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection', `
    'ConvertTo-DiscoveryDatasets','Invoke-DiscoveryRiskAnalysis','Get-DiscoveryFollowUpQuestions'
