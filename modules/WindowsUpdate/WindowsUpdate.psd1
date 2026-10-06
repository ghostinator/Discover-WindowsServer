@{
    RootModule        = 'WindowsUpdate.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1035-4a10-9f01-000000001035'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'WindowsUpdate collector module (patch currency, update source, WSUS role) for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Get-WuAutoUpdateModeLabel','Get-WuLastActionTime','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
