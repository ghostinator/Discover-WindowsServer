@{
    RootModule        = 'RiskEngine.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'b1c0a0e1-0003-4a10-9f01-000000000003'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Data-driven risk analysis engine, compliance lens application, and migration-complexity / WBS / dependency-graph synthesis.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryRiskAnalysis',
        'Invoke-DiscoverySynthesis','Test-RuleCondition','Expand-RuleTokens','Get-ComplianceRelevanceForFinding',
        'Test-RuleEmphasizedForProjectType','Get-WbsAreasForCategory',
        'Build-MigrationComplexity','Build-WbsInputs','Build-DependencyGraph','Build-ReadinessScore'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
