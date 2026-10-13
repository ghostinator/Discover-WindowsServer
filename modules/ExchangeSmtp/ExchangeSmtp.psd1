@{
    RootModule        = 'ExchangeSmtp.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '1ea52ed5-5b55-4af4-83d7-eb0bf06eb77e'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'ExchangeSmtp collector module for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('ConvertTo-DaysFromTimeSpanText','ConvertTo-DiscoveryDatasets','Get-DiscoveryFollowUpQuestions','Get-DiscoveryModuleMetadata','Get-EndpointAddress','Get-ExchangeCmdletInventory','Get-ExchangeInstallInfo','Get-ExchangeVersionInfo','Get-IisSmtpLogSummary','Get-MessageTrackingClientSummary','Get-RecentLogFiles','Get-SmtpReceiveProtocolSummary','Get-SmtpRelayAssessment','Invoke-DiscoveryCollection','Merge-SmtpRelayEvidence','Protect-EmailAddress','Read-DelimitedLogRecords','Split-QuotedCsvLine','Test-DiscoveryPrerequisites')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}