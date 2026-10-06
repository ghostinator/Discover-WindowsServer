@{
    RootModule        = 'ConfigDependencyScan.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-1030-4a10-9f01-000000001030'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'ConfigDependencyScan collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-ConfigScanRoots','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
