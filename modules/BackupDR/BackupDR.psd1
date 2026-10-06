@{
    RootModule        = 'BackupDR.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1028-4a10-9f01-000000001028'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'BackupDR collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
