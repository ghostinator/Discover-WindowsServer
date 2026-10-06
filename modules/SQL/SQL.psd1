@{
    RootModule        = 'SQL.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'b1c0a0e1-1022-4a10-9f01-000000001022'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'SQL collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Get-SqlServiceAccount','Invoke-DiscoveryCollection','Invoke-SqlIntegratedQuery','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
