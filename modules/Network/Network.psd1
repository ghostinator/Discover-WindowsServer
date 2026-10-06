@{
    RootModule        = 'Network.psm1'
    ModuleVersion     = '1.3.0'
    GUID              = 'b1c0a0e1-1014-4a10-9f01-000000001014'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Network collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DiscoveryDatasets','ConvertTo-NwPrefixLength','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Get-NwAdapterRows','Get-NwDnsRows','Get-NwEstablishedRows','Get-NwFirewallRows','Get-NwIpConfigRows','Get-NwListeningRows','Get-NwNetstatRows','Get-NwProcessMap','Get-NwRouteRows','Get-NwServiceMap','Invoke-DiscoveryCollection','Invoke-DiscoveryRiskAnalysis','Split-NwEndpoint','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
