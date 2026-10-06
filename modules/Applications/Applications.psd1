@{
    RootModule        = 'Applications.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-1013-4a10-9f01-000000001013'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Applications collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Get-FingerprintMatches','Invoke-DiscoveryCollection','Invoke-DiscoveryFingerprintSynthesis','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
