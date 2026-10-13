@{
    RootModule        = 'WorkloadProfile.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '952d3444-b215-4397-b086-b92b6e8522cd'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'WorkloadProfile collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','Get-DiscoveryModuleMetadata','Get-WorkloadProfileRow','Invoke-DiscoveryCollection','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}