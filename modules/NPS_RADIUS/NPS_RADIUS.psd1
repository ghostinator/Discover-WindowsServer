@{
    RootModule        = 'NPS_RADIUS.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1026-4a10-9f01-000000001026'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'NPS_RADIUS collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites','Test-NpsPresent')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
