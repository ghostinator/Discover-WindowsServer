@{
    RootModule        = 'Storage.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1015-4a10-9f01-000000001015'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Storage collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
