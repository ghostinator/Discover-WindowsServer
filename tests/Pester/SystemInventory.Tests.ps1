#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    SystemInventory.Tests.ps1 - fixture-based tests for the private helper functions in
    SystemInventory.psm1's "Private helpers" region.

    Tenth collector covered. Unlike every other module tested so far, these helpers
    (Get-SIChassisType, Get-SIOsEdition, Get-SIEndOfLifeInfo, Get-SIPlatformDetection, ...)
    are deliberately kept out of Export-ModuleMember - the file itself marks them
    "#region Private helpers". That's a real encapsulation boundary the author drew on
    purpose (unlike SQL.psm1's Get-SqlServiceAccount, which had every hallmark of an
    oversight and was exported in the previous commit). So instead of exporting them, every
    test below calls them through InModuleScope, which runs the call from inside the module's
    own scope without changing its public surface at all.

    Get-SIEndOfLifeInfo is the actual reason this module was picked: it is the single source
    of the OperatingSystem.IsEndOfLifeOrNear signal - arguably the single most consequential
    boolean this entire toolkit produces for a decommission/refresh conversation - and had
    zero prior test coverage despite explicit, dated support-window logic (e.g. Server 2016's
    "extended support ends 2027-01-12" comment) that WILL go stale and needs a test harness
    that can catch the day someone updates the OS-name matching without also checking the
    still-supported list.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                       -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\SystemInventory\SystemInventory.psm1') -Force -DisableNameChecking

    # Calls a private (unexported) SystemInventory function from inside the module's own
    # scope, so tests never need to touch Export-ModuleMember to reach it.
    function Invoke-SIPrivate {
        param([string]$FunctionName, [hashtable]$Arguments = @{})
        InModuleScope SystemInventory {
            param($fn, $fnArgs)
            & $fn @fnArgs
        } -Parameters @{ fn = $FunctionName; fnArgs = $Arguments }
    }
}

Describe 'Get-SIChassisType' {
    It 'maps a known chassis type code to its friendly label' {
        Invoke-SIPrivate 'Get-SIChassisType' @{ Codes = 23 } | Should -Be 'Rack Mount Chassis'
    }
    It 'falls back to a generic "Code N" label for an unmapped code' {
        Invoke-SIPrivate 'Get-SIChassisType' @{ Codes = 999 } | Should -Be 'Code 999'
    }
    It 'uses the first element when given an array of codes' {
        Invoke-SIPrivate 'Get-SIChassisType' @{ Codes = @(17, 3) } | Should -Be 'Main System Chassis'
    }
    It 'returns empty for a null/empty code' {
        Invoke-SIPrivate 'Get-SIChassisType' @{ Codes = $null } | Should -Be ''
    }
}

Describe 'Get-SIOsEdition' {
    It 'matches a known edition keyword in the caption before consulting the SKU' {
        Invoke-SIPrivate 'Get-SIOsEdition' @{ Caption = 'Microsoft Windows Server 2019 Datacenter'; Sku = 7 } | Should -Be 'Datacenter'
    }
    It 'falls back to the SKU map when the caption has no recognizable edition keyword' {
        Invoke-SIPrivate 'Get-SIOsEdition' @{ Caption = 'Microsoft Windows Server'; Sku = 8 } | Should -Be 'Datacenter Server'
    }
    It 'returns empty when neither the caption nor the SKU is recognizable' {
        Invoke-SIPrivate 'Get-SIOsEdition' @{ Caption = 'Some Unknown OS'; Sku = 9999 } | Should -Be ''
    }
}

Describe 'Get-SIEndOfLifeInfo' {
    It 'flags Server 2012 R2 as past end of support' {
        $r = Invoke-SIPrivate 'Get-SIEndOfLifeInfo' @{ Caption = 'Microsoft Windows Server 2012 R2 Standard'; BuildNumber = '9600' }
        $r.Known | Should -BeTrue
        $r.IsEol | Should -BeTrue
    }
    It 'flags Server 2016 as within the near-end-of-life window' {
        $r = Invoke-SIPrivate 'Get-SIEndOfLifeInfo' @{ Caption = 'Microsoft Windows Server 2016 Standard'; BuildNumber = '14393' }
        $r.Known | Should -BeTrue
        $r.IsEol | Should -BeTrue
        $r.Evidence | Should -Match '2027-01-12'
    }
    It 'does not flag Server 2019/2022/2025 as end of life' {
        foreach ($year in '2019', '2022', '2025') {
            $r = Invoke-SIPrivate 'Get-SIEndOfLifeInfo' @{ Caption = "Microsoft Windows Server $year Standard"; BuildNumber = '' }
            $r.IsEol | Should -BeFalse -Because "Server $year is currently supported"
            $r.Known | Should -BeTrue
        }
    }
    It 'reports Known=false rather than guessing for an unrecognized server caption' {
        $r = Invoke-SIPrivate 'Get-SIEndOfLifeInfo' @{ Caption = 'Microsoft Windows Server Vaporware Edition'; BuildNumber = '' }
        $r.Known | Should -BeFalse
        $r.IsEol | Should -BeFalse -Because 'an unclassifiable OS must never be silently reported as end-of-life or as supported'
    }
    It 'flags Windows 10 client as end of life' {
        $r = Invoke-SIPrivate 'Get-SIEndOfLifeInfo' @{ Caption = 'Microsoft Windows 10 Pro'; BuildNumber = '19045' }
        $r.IsEol | Should -BeTrue
        $r.Evidence | Should -Match '2025-10-14'
    }
    It 'does not flag Windows 11 client as end of life' {
        $r = Invoke-SIPrivate 'Get-SIEndOfLifeInfo' @{ Caption = 'Microsoft Windows 11 Pro'; BuildNumber = '22631' }
        $r.IsEol | Should -BeFalse
    }
    It 'reports Known=false for a blank caption' {
        $r = Invoke-SIPrivate 'Get-SIEndOfLifeInfo' @{ Caption = ''; BuildNumber = '' }
        $r.Known | Should -BeFalse
    }
}

Describe 'Get-SIPlatformDetection' {
    It 'recognizes the well-known Azure SMBIOS asset tag with Confirmed confidence' {
        $r = Invoke-SIPrivate 'Get-SIPlatformDetection' @{ Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine'; BiosManufacturer = 'Microsoft'; BiosVersion = 'Hyper-V'; AssetTag = '7783-7084-3265-9085-8269-3286-77' }
        $r.Platform   | Should -Be 'Azure (Hyper-V)'
        $r.Confidence | Should -Be 'Confirmed'
    }
    It 'recognizes VMware from manufacturer/model strings with Confirmed confidence' {
        $r = Invoke-SIPrivate 'Get-SIPlatformDetection' @{ Manufacturer = 'VMware, Inc.'; Model = 'VMware7,1'; BiosManufacturer = 'Phoenix Technologies LTD'; BiosVersion = '6.00'; AssetTag = '' }
        $r.Platform   | Should -Be 'VMware'
        $r.Confidence | Should -Be 'Confirmed'
    }
    It 'recognizes a Microsoft "Virtual Machine" model as Hyper-V with Likely confidence, not Confirmed' {
        $r = Invoke-SIPrivate 'Get-SIPlatformDetection' @{ Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine'; BiosManufacturer = 'American Megatrends Inc.'; BiosVersion = '090008'; AssetTag = '' }
        $r.Platform   | Should -Be 'Hyper-V'
        $r.Confidence | Should -Be 'Likely'
    }
    It 'downgrades to Possible confidence for a generic, unspecific "Virtual" marker' {
        $r = Invoke-SIPrivate 'Get-SIPlatformDetection' @{ Manufacturer = 'Generic Virtual Hardware Co'; Model = 'Virtual Box 9000'; BiosManufacturer = ''; BiosVersion = ''; AssetTag = '' }
        $r.Platform   | Should -Be 'Virtual (unspecified)'
        $r.Confidence | Should -Be 'Possible'
    }
    It 'reports Physical with Likely confidence when no virtualization markers are present' {
        $r = Invoke-SIPrivate 'Get-SIPlatformDetection' @{ Manufacturer = 'Dell Inc.'; Model = 'PowerEdge R740'; BiosManufacturer = 'Dell Inc.'; BiosVersion = '2.15.0'; AssetTag = '' }
        $r.Platform   | Should -Be 'Physical'
        $r.Confidence | Should -Be 'Likely'
    }
}

Describe 'ConvertTo-SIBool / Get-SIString / Get-SIFirst' {
    It 'ConvertTo-SIBool coerces a truthy CIM value and uses the default for null' {
        Invoke-SIPrivate 'ConvertTo-SIBool' @{ Value = 1 }    | Should -BeTrue
        Invoke-SIPrivate 'ConvertTo-SIBool' @{ Value = $null; Default = $true } | Should -BeTrue
    }
    It 'Get-SIString trims whitespace and turns null into an empty string' {
        Invoke-SIPrivate 'Get-SIString' @{ Value = '  padded  ' } | Should -Be 'padded'
        Invoke-SIPrivate 'Get-SIString' @{ Value = $null }        | Should -Be ''
    }
    It 'Get-SIFirst returns the first element of an array and null for empty/null input' {
        Invoke-SIPrivate 'Get-SIFirst' @{ Value = @('a', 'b') } | Should -Be 'a'
        Invoke-SIPrivate 'Get-SIFirst' @{ Value = $null }       | Should -BeNullOrEmpty
    }
}
