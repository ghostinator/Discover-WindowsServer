@{
    RootModule        = 'HypervisorInventory.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '4c922d9c-1cce-45aa-8c64-f7f5c87e2537'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'HypervisorInventory collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','ConvertTo-HypervisorInventory','Get-DiscoveryModuleMetadata','Get-HypervisorCountConflicts','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}