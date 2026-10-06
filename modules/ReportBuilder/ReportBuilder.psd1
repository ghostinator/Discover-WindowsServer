@{
    RootModule        = 'ReportBuilder.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-0008-4a10-9f01-000000000008'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Builds the two finished deliverables: the internal engineering report and the client-facing discovery report.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryReportBuild','Write-InternalMarkdownReport','Write-ClientHtmlReport','Write-ClientMarkdownReport','Get-RbClientModel','Get-RbClientHeadlines','Get-RbRows','Test-RbClientSafeDataset','Get-RbClientCss','Get-RbLogoHtml')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
