@{
    RootModule        = 'SystemInventory.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-1010-4a10-9f01-000000001010'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'SystemInventory collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Invoke-DiscoveryRiskAnalysis','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
