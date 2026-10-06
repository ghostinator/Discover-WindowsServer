@{
    RootModule        = 'Discover-WindowsServer.psm1'
    ModuleVersion     = '1.0.1'
    GUID              = '5bdced7d-d9b8-4d26-a073-8dc010b90c8f'
    Author            = 'Brandon Cook'
    CompanyName       = 'Brandon Cook'
    Copyright         = '(c) 2026 Brandon Cook. Read-only discovery toolkit.'
    Description       = 'Orchestration engine for the Ultimate Modular Windows Server Discovery Toolkit. The interactive entry point is Discover-WindowsServer.ps1; this module exposes the engine functions it drives.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-Discovery','Get-AllModuleMetadata','Resolve-ModuleSelection','Invoke-CollectorModule',
        'Invoke-SynthesisModule','Write-DiscoveryOutputs','Import-DiscoveryModuleFile','Remove-DiscoveryModuleFile',
        'Build-ApplicationValidationMatrix','Build-ContextListDatasets','Get-OutputTargetRoot','Save-EvidenceLogFile',
        'Start-DiscoverWindowsServerGui','Invoke-DiscoverWindowsServer'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    # Everything outside this module's own root that the toolkit needs at runtime but that isn't
    # a module member - the GUI, the fleet/drift/delivery tools, and the config files every
    # collector reads. Install-Module bundles the whole directory tree regardless, but an
    # explicit FileList is what PSGallery validates against and shows on the module's own page -
    # generated from the actual repo tree (modules\*\*.psd1/.psm1, tools\*.ps1, config\*) rather
    # than hand-typed, so it can't silently drift from what's really there.
    FileList          = @(
        'Discover-WindowsServer.psm1','Discover-WindowsServer.psd1','Discover-WindowsServer.ps1',
        'Discover-WindowsServer-GUI.ps1','LICENSE','README.md','HISTORY.md',
        'modules\ActiveDirectory\ActiveDirectory.psd1',
        'modules\ActiveDirectory\ActiveDirectory.psm1',
        'modules\Applications\Applications.psd1',
        'modules\Applications\Applications.psm1',
        'modules\AzureHybrid\AzureHybrid.psd1',
        'modules\AzureHybrid\AzureHybrid.psm1',
        'modules\BackupDR\BackupDR.psd1',
        'modules\BackupDR\BackupDR.psm1',
        'modules\Certificates\Certificates.psd1',
        'modules\Certificates\Certificates.psm1',
        'modules\ClientInterviewPack\ClientInterviewPack.psd1',
        'modules\ClientInterviewPack\ClientInterviewPack.psm1',
        'modules\Cluster\Cluster.psd1',
        'modules\Cluster\Cluster.psm1',
        'modules\ConfigDependencyScan\ConfigDependencyScan.psd1',
        'modules\ConfigDependencyScan\ConfigDependencyScan.psm1',
        'modules\Core\Core.psd1',
        'modules\Core\Core.psm1',
        'modules\DHCP\DHCP.psd1',
        'modules\DHCP\DHCP.psm1',
        'modules\DNS\DNS.psd1',
        'modules\DNS\DNS.psm1',
        'modules\DecommissionReadiness\DecommissionReadiness.psd1',
        'modules\DecommissionReadiness\DecommissionReadiness.psm1',
        'modules\EventLogs\EventLogs.psd1',
        'modules\EventLogs\EventLogs.psm1',
        'modules\EvidenceManifest\EvidenceManifest.psd1',
        'modules\EvidenceManifest\EvidenceManifest.psm1',
        'modules\FileShares\FileShares.psd1',
        'modules\FileShares\FileShares.psm1',
        'modules\HyperV\HyperV.psd1',
        'modules\HyperV\HyperV.psm1',
        'modules\IIS\IIS.psd1',
        'modules\IIS\IIS.psm1',
        'modules\Licensing\Licensing.psd1',
        'modules\Licensing\Licensing.psm1',
        'modules\NPS_RADIUS\NPS_RADIUS.psd1',
        'modules\NPS_RADIUS\NPS_RADIUS.psm1',
        'modules\Network\Network.psd1',
        'modules\Network\Network.psm1',
        'modules\Output\Output.psd1',
        'modules\Output\Output.psm1',
        'modules\PerformanceSnapshot\PerformanceSnapshot.psd1',
        'modules\PerformanceSnapshot\PerformanceSnapshot.psm1',
        'modules\PrintServer\PrintServer.psd1',
        'modules\PrintServer\PrintServer.psm1',
        'modules\RDS\RDS.psd1',
        'modules\RDS\RDS.psm1',
        'modules\ReportBuilder\ReportBuilder.psd1',
        'modules\ReportBuilder\ReportBuilder.psm1',
        'modules\RiskEngine\RiskEngine.psd1',
        'modules\RiskEngine\RiskEngine.psm1',
        'modules\RolesFeatures\RolesFeatures.psd1',
        'modules\RolesFeatures\RolesFeatures.psm1',
        'modules\SQL\SQL.psd1',
        'modules\SQL\SQL.psm1',
        'modules\ScopeLanguage\ScopeLanguage.psd1',
        'modules\ScopeLanguage\ScopeLanguage.psm1',
        'modules\SecurityPosture\SecurityPosture.psd1',
        'modules\SecurityPosture\SecurityPosture.psm1',
        'modules\ServicesTasks\ServicesTasks.psd1',
        'modules\ServicesTasks\ServicesTasks.psm1',
        'modules\Storage\Storage.psd1',
        'modules\Storage\Storage.psm1',
        'modules\SystemInventory\SystemInventory.psd1',
        'modules\SystemInventory\SystemInventory.psm1',
        'modules\TimeSync\TimeSync.psd1',
        'modules\TimeSync\TimeSync.psm1',
        'modules\UserProfiles\UserProfiles.psd1',
        'modules\UserProfiles\UserProfiles.psm1',
        'modules\VendorAgents\VendorAgents.psd1',
        'modules\VendorAgents\VendorAgents.psm1',
        'modules\WindowsUpdate\WindowsUpdate.psd1',
        'modules\WindowsUpdate\WindowsUpdate.psm1',
        'tools\Compare-DiscoveryRuns.ps1',
        'tools\Install-LegacyPrerequisites.ps1',
        'tools\Invoke-FleetDiscovery.ps1',
        'tools\Invoke-NinjaDiscovery.ps1',
        'tools\Merge-FleetDiscoveryResults.ps1',
        'tools\New-DemoEngagement.ps1',
        'tools\Send-DiscoveryOutput.ps1',
        'tools\Verify-DiscoveryRun.ps1',
        'config\application-fingerprints.json',
        'config\compliance-lenses.json',
        'config\deep.discovery.json',
        'config\default.discovery.json',
        'config\fast.discovery.json',
        'config\output-settings.json',
        'config\redaction-patterns.json',
        'config\risk-rules.json'
    )
    PrivateData       = @{
        PSData = @{
            Tags         = @('Discovery','WindowsServer','MSP','Scoping','Migration','ReadOnly')
            LicenseUri   = 'https://github.com/ghostinator/Discover-WindowsServer/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/ghostinator/Discover-WindowsServer'
            ReleaseNotes = '1.0.1: GUI fixes - the Branding accent-color swatch now shows the saved color on launch, and the Delivery tab note names the real archive. See HISTORY.md for the full history.'
        }
    }
}
