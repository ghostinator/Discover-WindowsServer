@{
    RootModule        = 'TimeSync.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1037-4a10-9f01-000000001037'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'TimeSync collector module (w32tm source, hierarchy, offset) for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertFrom-W32tmOffset','ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Get-W32tmField','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
