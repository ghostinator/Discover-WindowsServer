@{
    RootModule        = 'ClientInterviewPack.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-0006-4a10-9f01-000000000006'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Tailored client interview / validation question pack synthesis.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
