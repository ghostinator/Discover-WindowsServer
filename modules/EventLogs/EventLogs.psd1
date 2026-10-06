@{
    RootModule        = 'EventLogs.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1034-4a10-9f01-000000001034'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'EventLogs collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-AuditPolicySettings','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
