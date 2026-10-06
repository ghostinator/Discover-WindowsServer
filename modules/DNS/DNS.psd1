@{
    RootModule        = 'DNS.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-1019-4a10-9f01-000000001019'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'DNS collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Get-DnsRecordsReferencingThisServer','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites','Test-DnsPresent')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
