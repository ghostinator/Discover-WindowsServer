<#
    ScopeLanguage.psm1
    Synthesis module. Generates DRAFT scope language (assumptions, exclusions,
    responsibilities) grounded in findings, limitations, and unknowns. All output
    is clearly labeled draft and only generated when supported by evidence.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'ScopeLanguage'
        DisplayName               = 'Draft Scope Language'
        Category                  = 'Synthesis'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Minimal'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('ScopeAssumptions','ScopeExclusions')
        ProducesRisks             = $false
        ProducesFollowUpQuestions = $false
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $false
        IsSynthesis               = $true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='ScopeLanguage'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Test-AnyFindingCategory {
    param([object]$Context, [string[]]$Categories)
    return (@($Context.Findings | Where-Object { $Categories -contains $_.Category }).Count -gt 0)
}

function Invoke-DiscoverySynthesis {
    param([object]$Context)
    Write-SectionStatus -Title 'Scope Language' -Status 'Drafting' -Context $Context

    # The scope-language text below names the acting party inline via a literal '{Brand}' token
    # ("{Brand} assumes...") since that reads naturally once substituted in a real document -
    # swapped for the configured brand name (the same config/output-settings.json value every
    # report header already uses) right before each string is used, so anyone running this under
    # their own company name gets their own name in draft-scope-language.md, not a placeholder
    # or (worse) someone else's. A plain string .Replace (not -replace) is a no-op for any entry
    # that doesn't happen to contain the token.
    $brandName = (Get-DiscoveryBranding -Context $Context).Brand
    $brandText = { param([string]$Text) $Text.Replace('{Brand}', $brandName) }

    # Always-present baseline (clearly draft).
    Add-ScopeLanguage -Context $Context -Type 'Assumption' -Module 'ScopeLanguage' -Text (& $brandText '{Brand} assumes all required application installers, license keys, service account credentials, and vendor support contacts will be provided before migration activities begin.') | Out-Null
    Add-ScopeLanguage -Context $Context -Type 'Exclusion' -Module 'ScopeLanguage' -Text 'Scope does not include vendor application upgrades, application-level troubleshooting, or remediation of pre-existing application issues unless separately quoted.' | Out-Null
    Add-ScopeLanguage -Context $Context -Type 'Validation' -Module 'ScopeLanguage' -Text (& $brandText '{Brand} assumes the client will provide validation contacts and confirm application/data functionality after migration during an agreed validation window.') | Out-Null

    # Finding-driven assumptions/exclusions, one entry per finding category that fired.
    #
    # This table covers every category used by config\risk-rules.json. Previously only six
    # categories were covered, so a run whose findings were all Security / Network / Web /
    # Hyper-V (etc.) produced no category-specific scope language at all. All text is DRAFT
    # and must be reviewed before it goes near a statement of work.
    #
    # A rule may also carry its own suggestedScopeLanguage, which the RiskEngine contributes
    # directly; that is for language specific to one finding rather than a whole category.
    $byCategory = @(
        @{ Cats=@('Service Account');    Type='Credential';           Text='{Brand} assumes required service account credentials or gMSA configuration details will be provided before migration; discovery of undocumented credentials is out of scope.' }
        @{ Cats=@('Database');           Type='Cutover';              Text='{Brand} assumes database backups can be taken and restored during an approved migration window, and that application connection strings/DSNs can be updated to the target server.' }
        @{ Cats=@('Licensing');          Type='Licensing';            Text='{Brand} assumes any license reactivation, host rebinding, or dongle transfer will be supported by the client and/or vendor; licensing legality determinations are out of scope.' }
        @{ Cats=@('Backup / DR');        Type='BackupRollback';       Text='{Brand} assumes a validated, recent backup exists and can be used for rollback; verifying backup integrity is a client/vendor responsibility unless separately scoped.' }
        @{ Cats=@('Vendor');             Type='VendorResponsibility'; Text='Vendor coordination, agent reinstallation, and console re-enrollment for third-party products are assumed to be supported by the respective vendors and may require separate coordination time.' }
        @{ Cats=@('Certificates');       Type='Cutover';              Text='{Brand} assumes required certificates can be reissued or migrated by the certificate owner; private keys are not exported by discovery.' }
        @{ Cats=@('Identity / AD / DC'); Type='Cutover';              Text='{Brand} assumes directory role changes (domain controller promotion/demotion, FSMO transfer, DNS and DHCP cutover) will be scheduled in an approved maintenance window with a documented rollback plan.' }
        @{ Cats=@('Applications');       Type='Assumption';           Text='{Brand} assumes application installation media, license keys, configuration documentation, and vendor support contacts will be provided before migration; application reinstallation performed by a vendor is out of scope unless separately quoted.' }
        @{ Cats=@('Web');                Type='Cutover';              Text='{Brand} assumes site bindings, host headers, application pool identities, and any DNS or hosts-file entries that point at this server will be identified and updated by the application owner during cutover.' }
        @{ Cats=@('File / Print');       Type='Cutover';              Text='{Brand} assumes share paths and NTFS permissions can be reproduced on the target, that users and applications referencing this server by name or UNC path will be identified by the client, and that print drivers compatible with the target operating system are available.' }
        @{ Cats=@('Network');            Type='Assumption';           Text='{Brand} assumes IP addressing, DNS records, and firewall rules can be changed during the migration window, and that the client will identify any system, device, or integration that reaches this server by IP address or host name.' }
        @{ Cats=@('Storage');            Type='ChangeOrderTrigger';   Text='Target storage sizing is based on capacity observed at the time of discovery. Growth, additional volumes, or data discovered outside the scanned paths may require a change order.' }
        @{ Cats=@('Security');           Type='Exclusion';            Text='Remediation of pre-existing security findings (insecure protocols, missing endpoint protection, excessive privilege, encryption gaps) is not included unless separately scoped and quoted.' }
        @{ Cats=@('Hyper-V / Cluster');  Type='Cutover';              Text='{Brand} assumes the guest inventory is complete, that checkpoints can be consolidated before migration, and that host or cluster changes will be scheduled in an approved window with capacity to fail workloads over.' }
        @{ Cats=@('Operating System');   Type='ChangeOrderTrigger';   Text='An operating system at or near end of support may require an in-place upgrade or a rebuild on a supported platform. Where that is required and not already scoped, it is a change order.' }
        @{ Cats=@('Performance');        Type='Assumption';           Text='Target sizing is derived from a point-in-time performance snapshot. Sustained load profiling, capacity modelling, and application performance tuning are out of scope unless separately quoted.' }
        @{ Cats=@('Services / Tasks');   Type='ChangeOrderTrigger';   Text='{Brand} assumes required services and scheduled tasks will be recreated on the target from what discovery detected. Undocumented automation found during or after migration may require a change order.' }
        @{ Cats=@('Discovery Quality');  Type='ChangeOrderTrigger';   Text='Where discovery could not determine a dependency, additional scope uncovered during migration may require a change order. Resolving the recorded unknowns before work begins reduces this risk.' }
    )
    foreach ($entry in $byCategory) {
        if (Test-AnyFindingCategory -Context $Context -Categories $entry.Cats) {
            Add-ScopeLanguage -Context $Context -Type $entry.Type -Module 'ScopeLanguage' -Text (& $brandText $entry.Text) | Out-Null
        }
    }
    # Limitation-driven assumptions.
    $configScanRan = ($Context.DataSets.Contains('ConfigDependencyHints'))
    if (-not $configScanRan) {
        Add-ScopeLanguage -Context $Context -Type 'ChangeOrderTrigger' -Module 'ScopeLanguage' -Text 'Because a config dependency scan was not performed, discovery of additional hardcoded dependencies during migration may constitute a change order trigger.' | Out-Null
    }
    if (-not $Context.IsAdmin) {
        Add-ScopeLanguage -Context $Context -Type 'Assumption' -Module 'ScopeLanguage' -Text 'Discovery was not run elevated; some data may be incomplete and additional findings may emerge when full administrative discovery is performed.' | Out-Null
    }

    # Build assumption / exclusion datasets from the accumulated scope language.
    $assumptions = @($Context.ScopeLanguage | Where-Object { $_.Type -in @('Assumption','Cutover','Validation','Licensing','Credential','BackupRollback','ClientResponsibility','VendorResponsibility') } | ForEach-Object { [pscustomobject]@{ Type=$_.Type; DraftLanguage=$_.Text; Source=$_.Module } })
    $exclusions  = @($Context.ScopeLanguage | Where-Object { $_.Type -in @('Exclusion','ChangeOrderTrigger') } | ForEach-Object { [pscustomobject]@{ Type=$_.Type; DraftLanguage=$_.Text; Source=$_.Module } })

    Add-DataSet -Context $Context -Name 'ScopeAssumptions' -Description 'Draft scope assumptions derived from findings and limitations.' -Rows $assumptions -Visibility 'Both' -SourceModule 'ScopeLanguage' | Out-Null
    Add-DataSet -Context $Context -Name 'ScopeExclusions'  -Description 'Draft scope exclusions derived from findings and limitations.'  -Rows $exclusions  -Visibility 'Both' -SourceModule 'ScopeLanguage' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis'
