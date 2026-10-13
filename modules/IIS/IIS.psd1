@{
    RootModule        = 'IIS.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'b1c0a0e1-1021-4a10-9f01-000000001021'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'IIS collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertFrom-IisBindingInformation','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Get-IisAppCmdPath','Get-IisPathAssessment','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites','Test-IisIdentityIsDomainAccount','Test-IisPresent')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
