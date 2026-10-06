@{
    RootModule        = 'Output.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'b1c0a0e1-0002-4a10-9f01-000000000002'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Output writers (CSV, JSON, Excel 2003 XML workbook, static HTML report, Markdown pack, discovery plan, ZIP) for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'ConvertTo-DisplayString','Get-DatasetColumns','Get-RowValue',
        'Escape-CsvValue','Get-CsvDelimiter','Write-ObjectListToCsv','Write-ObjectListToJson',
        'Escape-XmlText','Sanitize-WorksheetName','Get-ExcelXmlType','Get-ExcelXmlValue',
        'ConvertTo-ExcelXmlWorksheet','Write-ExcelXmlWorkbook',
        'Write-MarkdownFile','ConvertTo-MarkdownTable','Compress-Folder','Get-CompressFolderLastError','Export-DiscoveryDatasets',
        'Write-DiscoveryPlan','Write-HtmlReport','Write-DashboardHtmlReport','Get-InternalReportModel',
        'ConvertTo-HtmlTable','Get-LikelyServerFunctions','Get-DependencyDiagramSvg',
        'Test-DatasetHasRows','Test-RoleFeaturePresent','Test-DatasetFieldTrue'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
