<#
    ClientInterviewPack.psm1
    Synthesis module. Generates tailored, specific client validation questions
    based on findings. Ends with the mandatory "what did we miss?" question.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName                = 'ClientInterviewPack'
        DisplayName               = 'Client Interview / Validation Pack'
        Category                  = 'Synthesis'
        Version                   = '1.0.0'
        DefaultInFast             = $true
        DefaultInDeep             = $true
        RequiresAdmin             = $false
        RequiresDomainContext     = $false
        RequiresRole              = $null
        EstimatedImpact           = 'Minimal'
        CanRunAsSystem            = $true
        ProducesDatasets          = @('ClientInterviewQuestions')
        ProducesRisks             = $false
        ProducesFollowUpQuestions = $true
        SupportsDeepMode          = $true
        SupportsComplianceLens    = $false
        IsSynthesis               = $true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='ClientInterviewPack'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoverySynthesis {
    param([object]$Context)
    Write-SectionStatus -Title 'Client Interview Pack' -Status 'Building' -Context $Context

    # Promote finding-specific validation questions (deduplicated) into the client pack.
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($f in @($Context.Findings)) {
        $q = $f.SuggestedValidationQuestion
        if ([string]::IsNullOrWhiteSpace($q)) { continue }
        if ($seen.Contains($q)) { continue }
        [void]$seen.Add($q)
        $cat = switch -Regex ($f.Category) {
            'Database'            { 'Databases'; break }
            'Service Account'     { 'Service accounts'; break }
            'Web'                 { 'Applications'; break }
            'Applications'        { 'Applications'; break }
            'File / Print'        { 'File shares / printing'; break }
            'Certificates'        { 'Certificates'; break }
            'Licensing'           { 'Licensing'; break }
            'Backup / DR'         { 'Backup / restore'; break }
            'Identity / AD / DC'  { 'Critical systems'; break }
            'Security'            { 'Security / compliance'; break }
            'Vendor'             { 'Vendor support'; break }
            'Hyper-V / Cluster'   { 'Critical systems'; break }
            default               { 'General' }
        }
        Add-FollowUpQuestion -Context $Context -Category $cat -Question $q -Module 'ClientInterviewPack' -RelatedFinding $f.FindingId -Audience 'ClientSafe' | Out-Null
    }

    # Ensure baseline category coverage even when a category produced no findings.
    $baseline = @(
        @{ Cat='Critical systems'; Q='Which systems or applications on this server are considered business-critical, and who is impacted if they are unavailable even briefly?' }
        @{ Cat='Daily/periodic usage'; Q='Which applications on this server are used daily, and which are used only monthly, quarterly, or at year-end (e.g., billing, payroll, reporting)?' }
        @{ Cat='Data sources / storage'; Q='Where does this server store its data, and are there data locations off the primary drive we should account for?' }
        @{ Cat='Mapped drives / UNC'; Q='Do users or applications connect to this server by name or UNC path (mapped drives, shortcuts, hardcoded paths)?' }
        @{ Cat='Equipment dependencies'; Q='Does any equipment (scales, scanners, label printers, time clocks, machines) depend on this server?' }
        @{ Cat='Licensing'; Q='Are there any license keys, dongles, or license servers tied to this specific server that could require reactivation?' }
        @{ Cat='Printing / labels'; Q='Does this server handle any printing or label printing that must keep working after a change?' }
        @{ Cat='Data retention'; Q='Are there data retention or compliance requirements for data on this server that affect how long it must be kept?' }
        @{ Cat='Tribal knowledge'; Q='Is there anything about this server that only one or two people know, or that is not documented anywhere?' }
        @{ Cat='Vendors / third parties'; Q='Which vendors or third parties have access to, or support responsibilities for, anything on this server?' }
        @{ Cat='Change sensitivity'; Q='Have there been past incidents where changes to this server caused problems we should be aware of?' }
        @{ Cat='Performance / latency'; Q='Are there any applications on this server that are sensitive to performance or latency (e.g., would be affected by a move to the cloud)?' }
        @{ Cat='Validation contacts'; Q='Who should validate each key application/function after a migration or change, and how do we reach them?' }
    )
    $existingCats = @($Context.FollowUpQuestions | Select-Object -ExpandProperty Category -Unique)
    foreach ($b in $baseline) {
        if ($existingCats -notcontains $b.Cat) {
            Add-FollowUpQuestion -Context $Context -Category $b.Cat -Question $b.Q -Module 'ClientInterviewPack' -Audience 'ClientSafe' | Out-Null
        }
    }

    # Mandatory final question.
    Add-FollowUpQuestion -Context $Context -Category 'What did we miss' -Module 'ClientInterviewPack' -Audience 'ClientSafe' `
        -Question 'Is there anything we did not ask about that, if changed, migrated, powered off, renamed, or removed, would cause problems for your team?' | Out-Null

    # Dataset mirror for workbook/CSV.
    $rows = @($Context.FollowUpQuestions | ForEach-Object { [pscustomobject]@{ Category=$_.Category; Question=$_.Question; Audience=$_.Audience; RelatedFinding=$_.RelatedFinding; Module=$_.Module } })
    Add-DataSet -Context $Context -Name 'ClientInterviewQuestions' -Description 'Tailored client validation questions.' -Rows $rows -Visibility 'Both' -SourceModule 'ClientInterviewPack' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoverySynthesis'
