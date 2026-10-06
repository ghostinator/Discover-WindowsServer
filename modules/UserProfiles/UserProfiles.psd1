@{
    RootModule        = 'UserProfiles.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-1036-4a10-9f01-000000001036'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'UserProfiles collector module (profiles, mapped drives, per-user DSNs, logon scripts) for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Get-UpLoadedUserHives','Get-UpSidIsRealUser','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
