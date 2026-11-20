@{
    RootModule        = 'RoleUsage.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-0040-4a10-9f01-000000000040'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Per-role usage evidence synthesis: is an installed role actually in use?'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Build-RoleUsage','Get-DiscoveryModuleMetadata','Get-RoleUsageVerdict','Invoke-DiscoverySynthesis','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
