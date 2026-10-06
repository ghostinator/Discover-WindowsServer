@{
    RootModule        = 'ActiveDirectory.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'b1c0a0e1-1018-4a10-9f01-000000001018'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'ActiveDirectory collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-AdFunctionalLevelName','ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
