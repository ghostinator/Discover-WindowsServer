@{
    RootModule        = 'ApplicationStacks.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '954e42f8-829f-488b-9555-40812d5aecaf'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'ApplicationStacks collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Find-AppStackEvidence','Get-AppStackSummary','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}