@{
    RootModule        = 'SecurityPosture.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-1017-4a10-9f01-000000001017'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'SecurityPosture collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Get-LocalAdministrators','Get-NonExpiringPasswordAccounts','Get-SensitiveUserRightsGrants','Invoke-DiscoveryCollection','New-PostureRow','Test-DiscoveryPrerequisites','Test-TlsProtocolEnabled')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
