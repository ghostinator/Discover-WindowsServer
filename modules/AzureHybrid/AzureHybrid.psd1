@{
    RootModule        = 'AzureHybrid.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-1038-4a10-9f01-000000001038'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'AzureHybrid collector module (Entra Connect, AD FS, connectors, cloud join state) for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-AhEvidence','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
