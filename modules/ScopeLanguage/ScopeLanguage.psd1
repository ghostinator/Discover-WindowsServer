@{
    RootModule        = 'ScopeLanguage.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-0005-4a10-9f01-000000000005'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Draft scope language (assumptions, exclusions, responsibilities) synthesis.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
