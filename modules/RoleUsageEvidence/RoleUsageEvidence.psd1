@{
    RootModule        = 'RoleUsageEvidence.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-0041-4a10-9f01-000000000041'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Read-only usage signals for SQL, RDS and domain controller roles.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Get-EventUsageSummary','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
