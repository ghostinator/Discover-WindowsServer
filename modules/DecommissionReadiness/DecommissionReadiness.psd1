@{
    RootModule        = 'DecommissionReadiness.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-0004-4a10-9f01-000000000004'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Decommission readiness assessment and scream-test planning synthesis.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Build-DecommissionReadiness','Build-DecommissionStates','Build-ScreamTestPlan','Get-DiscoveryModuleMetadata','Invoke-DiscoverySynthesis','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
