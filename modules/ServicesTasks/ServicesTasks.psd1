@{
    RootModule        = 'ServicesTasks.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1012-4a10-9f01-000000001012'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'ServicesTasks collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Get-ServiceExePath','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites','Test-DomainAccount')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
