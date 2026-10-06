@{
    RootModule        = 'RolesFeatures.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1011-4a10-9f01-000000001011'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Read-only collector for installed Windows roles, role services, and features (produces the canonical RolesFeatures dataset).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection',
        'ConvertTo-DiscoveryDatasets','Invoke-DiscoveryRiskAnalysis','Get-DiscoveryFollowUpQuestions',
        'ConvertFrom-DismFeatureText','Get-RolesFeaturesDetectedFunctions'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
