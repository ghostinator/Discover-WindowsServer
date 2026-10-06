@{
    RootModule        = 'Core.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b1c0a0e1-0001-4a10-9f01-000000000001'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Core runtime context, logging, safety wrappers, redaction, and the standard Finding/Dataset object model for the Windows Server Discovery Toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Import-DiscoveryConfig','Get-DiscoveryConfigBundle','Get-DiscoveryBrandingDirectory','Merge-LocalBranding','Get-DiscoveryBranding','Get-DiscoveryLogoDataUri','New-DiscoveryContext',
        'Ensure-Directory','ConvertTo-SafeFileName','Test-IsAdministrator','Test-IsSystem',
        'Get-CommandAvailable','Get-ModuleAvailable','Get-RegistryValueSafe','Test-RegistryPathSafe',
        'Invoke-CimSafe','Invoke-CommandLineSafe','Invoke-WindowsPowerShellJson','Test-WindowsPowerShellModule','Convert-BytesToGB','Convert-BytesToMB','Normalize-DateTime',
        'Test-SensitiveKeyLabel','Redact-SensitiveValue','Write-Log','Write-SectionStatus',
        'New-DiscoveryDataset','New-DiscoveryFinding','New-ScopingRisk','New-FollowUpQuestion','New-DependencyEdge',
        'Add-DataSet','Add-Finding','Add-Limitation','Add-Unknown','Add-FollowUpQuestion','Add-ScopeLanguage',
        'Add-DependencyEdge','Add-ModuleStatus','Update-StatusFile'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
