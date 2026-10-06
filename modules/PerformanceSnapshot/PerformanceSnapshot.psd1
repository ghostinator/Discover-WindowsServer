@{
    RootModule        = 'PerformanceSnapshot.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1033-4a10-9f01-000000001033'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'PerformanceSnapshot collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
