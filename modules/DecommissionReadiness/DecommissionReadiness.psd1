@{
    RootModule        = 'DecommissionReadiness.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-0004-4a10-9f01-000000000004'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Decommission readiness assessment and scream-test planning synthesis.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis','Build-DecommissionReadiness','Build-ScreamTestPlan')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
