@{
    RootModule        = 'EvidenceManifest.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c0a0e1-0007-4a10-9f01-000000000007'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Description       = 'Evidence manifest generation (SHA256 hashes and sensitivity) for completed output files.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryEvidenceManifest')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
