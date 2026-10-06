#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Compare-DiscoveryRuns.Tests.ps1 - fixture-based tests for run-to-run drift detection.

    Builds small fake "completed run" folders under $TestDrive, same convention as
    Merge-FleetDiscoveryResults.Tests.ps1's New-FakeRunFolder (duplicated here rather than shared
    across test files, matching how each Pester file in this repo owns its own fixture helpers).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $Root 'tools\Compare-DiscoveryRuns.ps1')

    function New-FakeRunFolder {
        param(
            [Parameter(Mandatory)][string]$RunRoot,
            [Parameter(Mandatory)][string]$ComputerName,
            [string]$RunId = "run-$ComputerName",
            [string]$StartTime = '2026-01-01T00:00:00',
            [hashtable]$Datasets = @{},
            [hashtable]$DatasetVisibility = @{}
        )
        $runDir = Join-Path $RunRoot ("Discover-WindowsServer_{0}_20260101_010101" -f $ComputerName)
        New-Item -ItemType Directory -Path (Join-Path $runDir 'evidence\data\json') -Force | Out-Null
        $datasetMeta = @(foreach ($name in $Datasets.Keys) {
            $vis = if ($DatasetVisibility.ContainsKey($name)) { $DatasetVisibility[$name] } else { 'Internal' }
            @{ Name = $name; Rows = @($Datasets[$name]).Count; Visibility = $vis }
        })
        $meta = @{ RunId = $RunId; ComputerName = $ComputerName; Mode = 'Fast'; StartTime = $StartTime; Datasets = $datasetMeta }
        (ConvertTo-Json $meta -Depth 5) | Out-File (Join-Path $runDir 'evidence\collection-metadata.json') -Encoding utf8
        foreach ($name in $Datasets.Keys) {
            (ConvertTo-Json @($Datasets[$name]) -Depth 5) | Out-File (Join-Path $runDir ("evidence\data\json\{0}.json" -f $name)) -Encoding utf8
        }
        return $runDir
    }
}

Describe 'Compare-DiscoveryDataset' {
    It 'reports added, removed and changed rows by natural key' {
        $baseline = @(@{ Name = 'Data'; Description = 'old' }, @{ Name = 'ToRemove'; Description = 'x' }) | ForEach-Object { [pscustomobject]$_ }
        $current  = @(@{ Name = 'Data'; Description = 'new' }, @{ Name = 'ToAdd'; Description = 'y' }) | ForEach-Object { [pscustomobject]$_ }
        $r = Compare-DiscoveryDataset -DatasetName 'SmbShares' -BaselineRows $baseline -CurrentRows $current
        $r.Supported | Should -BeTrue
        @($r.Added).Count | Should -Be 1
        $r.Added[0].Name | Should -Be 'ToAdd'
        @($r.Removed).Count | Should -Be 1
        $r.Removed[0].Name | Should -Be 'ToRemove'
        @($r.Changed).Count | Should -Be 1
        $r.Changed[0].Key | Should -Be 'Data'
        $r.Changed[0].Fields[0].Field | Should -Be 'Description'
    }

    It 'does not report a row as changed when only an ignored field differs' {
        $baseline = @([pscustomobject]@{ TaskName = 'T1'; TaskPath = '\'; ActionsText = 'old'; State = 'Ready' })
        $current  = @([pscustomobject]@{ TaskName = 'T1'; TaskPath = '\'; ActionsText = 'new (irrelevant)'; State = 'Ready' })
        $r = Compare-DiscoveryDataset -DatasetName 'ScheduledTasks' -BaselineRows $baseline -CurrentRows $current
        @($r.Changed).Count | Should -Be 0
        $r.UnchangedCount | Should -Be 1
    }

    It 'filters out the toolkit''s own transient remote-run scheduled task by name pattern' {
        $baseline = @([pscustomobject]@{ TaskName = 'DiscoverWindowsServer_a1b2c3d4'; TaskPath = '\'; State = 'Running' })
        $current  = @([pscustomobject]@{ TaskName = 'DiscoverWindowsServer_e5f6a7b8'; TaskPath = '\'; State = 'Running' })
        $r = Compare-DiscoveryDataset -DatasetName 'ScheduledTasks' -BaselineRows $baseline -CurrentRows $current
        @($r.Added).Count | Should -Be 0
        @($r.Removed).Count | Should -Be 0
    }

    It 'reports Supported=$false for an excluded dataset (no stable identity across runs)' {
        $r = Compare-DiscoveryDataset -DatasetName 'RunningProcesses' -BaselineRows @() -CurrentRows @()
        $r.Supported | Should -BeFalse
        $r.SkipReason | Should -Match 'stable'
    }

    It 'reports Supported=$false for an unrecognized dataset name instead of throwing' {
        { Compare-DiscoveryDataset -DatasetName 'SomeBrandNewDataset' -BaselineRows @() -CurrentRows @() } | Should -Not -Throw
        $r = Compare-DiscoveryDataset -DatasetName 'SomeBrandNewDataset' -BaselineRows @() -CurrentRows @()
        $r.Supported | Should -BeFalse
    }

    It 'handles a composite key (Group + Member) correctly' {
        $baseline = @([pscustomobject]@{ Group = 'Administrators'; Member = 'Administrator' })
        $current  = @(
            [pscustomobject]@{ Group = 'Administrators'; Member = 'Administrator' }
            [pscustomobject]@{ Group = 'Administrators'; Member = 'svc-new' }
        )
        $r = Compare-DiscoveryDataset -DatasetName 'LocalGroupMembers' -BaselineRows $baseline -CurrentRows $current
        @($r.Added).Count | Should -Be 1
        $r.Added[0].Member | Should -Be 'svc-new'
    }

    It 'treats $null baseline/current rows as empty rather than throwing' {
        { Compare-DiscoveryDataset -DatasetName 'SmbShares' -BaselineRows $null -CurrentRows $null } | Should -Not -Throw
        $r = Compare-DiscoveryDataset -DatasetName 'SmbShares' -BaselineRows $null -CurrentRows $null
        @($r.Added).Count | Should -Be 0
        @($r.Removed).Count | Should -Be 0
    }
}

Describe 'Compare-DiscoveryRunPair' {
    It 'diffs the union of both runs'' recorded datasets, including one that disappeared entirely' {
        $eng = Join-Path $TestDrive 'pair1'
        $baselineRun = New-FakeRunFolder -RunRoot (Join-Path $eng 'old') -ComputerName 'SRV1' -RunId 'r-old' -Datasets @{
            SmbShares = @(@{ Name = 'Data' }, @{ Name = 'GoingAway' })
            Services  = @(@{ Name = 'Spooler'; Status = 'Running' })
        }
        $currentRun = New-FakeRunFolder -RunRoot (Join-Path $eng 'new') -ComputerName 'SRV1' -RunId 'r-new' -Datasets @{
            SmbShares = @(@{ Name = 'Data' }, @{ Name = 'NewOne' })
        }
        $result = Compare-DiscoveryRunPair -BaselineRunFolder $baselineRun -CurrentRunFolder $currentRun
        $result.ComputerName | Should -Be 'SRV1'
        $shares = $result.DatasetResults | Where-Object { $_.DatasetName -eq 'SmbShares' }
        @($shares.Added).Count | Should -Be 1
        @($shares.Added)[0].Name | Should -Be 'NewOne'
        @($shares.Removed).Count | Should -Be 1
        @($shares.Removed)[0].Name | Should -Be 'GoingAway'
        # Services existed in the baseline but not the current run at all - must show up as fully
        # removed, not be silently skipped because the current run's own metadata never mentioned it.
        $services = $result.DatasetResults | Where-Object { $_.DatasetName -eq 'Services' }
        @($services.Removed).Count | Should -Be 1
    }
}

Describe 'Compare-DiscoveryFleetRuns' {
    It 'matches servers by ComputerName and reports servers present on only one side' {
        $baselineEng = Join-Path $TestDrive 'fleet-old'
        $currentEng = Join-Path $TestDrive 'fleet-new'
        New-FakeRunFolder -RunRoot $baselineEng -ComputerName 'SRV1' -Datasets @{ SmbShares = @(@{ Name = 'Data' }) } | Out-Null
        New-FakeRunFolder -RunRoot $baselineEng -ComputerName 'SRV-DECOMM' -Datasets @{ SmbShares = @(@{ Name = 'Old' }) } | Out-Null
        New-FakeRunFolder -RunRoot $currentEng -ComputerName 'SRV1' -Datasets @{ SmbShares = @(@{ Name = 'Data' }, @{ Name = 'New' }) } | Out-Null
        New-FakeRunFolder -RunRoot $currentEng -ComputerName 'SRV-NEW' -Datasets @{ SmbShares = @(@{ Name = 'Fresh' }) } | Out-Null

        $result = Compare-DiscoveryFleetRuns -BaselineEngagementFolder $baselineEng -CurrentEngagementFolder $currentEng
        @($result.ServerResults).Count | Should -Be 1
        $result.ServerResults[0].ComputerName | Should -Be 'SRV1'
        @($result.OnlyInBaseline) | Should -Be @('SRV-DECOMM')
        @($result.OnlyInCurrent) | Should -Be @('SRV-NEW')
    }
}

Describe 'Get-ClientSafeDriftSummary' {
    It 'only includes datasets the CURRENT run recorded as ClientSafe or Both, with a generic count-only label' {
        $datasetResults = @(
            [pscustomobject]@{ DatasetName = 'SmbShares'; Supported = $true; Added = @(1); Removed = @(); Changed = @() }
            [pscustomobject]@{ DatasetName = 'LocalGroupMembers'; Supported = $true; Added = @(1, 2); Removed = @(); Changed = @() }
        )
        $visibility = @{ SmbShares = 'ClientSafe'; LocalGroupMembers = 'Internal' }
        $summary = Get-ClientSafeDriftSummary -DatasetResults $datasetResults -DatasetVisibility $visibility
        @($summary).Count | Should -Be 1
        $summary[0].DatasetName | Should -Be 'SmbShares'
        $summary[0].Label | Should -Be '1 new'
    }

    It 'omits a dataset with zero net drift even if it is ClientSafe' {
        $datasetResults = @([pscustomobject]@{ DatasetName = 'SmbShares'; Supported = $true; Added = @(); Removed = @(); Changed = @() })
        $summary = Get-ClientSafeDriftSummary -DatasetResults $datasetResults -DatasetVisibility @{ SmbShares = 'ClientSafe' }
        @($summary).Count | Should -Be 0
    }

    It 'never includes an Unsupported dataset result' {
        $datasetResults = @([pscustomobject]@{ DatasetName = 'RunningProcesses'; Supported = $false; Added = @(1); Removed = @(); Changed = @() })
        $summary = Get-ClientSafeDriftSummary -DatasetResults $datasetResults -DatasetVisibility @{ RunningProcesses = 'ClientSafe' }
        @($summary).Count | Should -Be 0
    }
}

Describe 'New-DriftReport (single-server and fleet)' {
    It 'writes all five drift report files for a single-server comparison' {
        $eng = Join-Path $TestDrive 'single1'
        $baselineRun = New-FakeRunFolder -RunRoot (Join-Path $eng 'old') -ComputerName 'SRV1' -Datasets @{
            SmbShares = @(@{ Name = 'Data' })
        } -DatasetVisibility @{ SmbShares = 'ClientSafe' }
        $currentRun = New-FakeRunFolder -RunRoot (Join-Path $eng 'new') -ComputerName 'SRV1' -Datasets @{
            SmbShares = @(@{ Name = 'Data' }, @{ Name = 'New' })
        } -DatasetVisibility @{ SmbShares = 'ClientSafe' }
        $outPath = Join-Path $TestDrive 'single1-out'
        $report = New-DriftReport -BaselineRunFolder $baselineRun -CurrentRunFolder $currentRun -OutputPath $outPath
        $report.ServerCount | Should -Be 1
        $report.TotalAdded | Should -Be 1
        foreach ($p in @($report.JsonPath, $report.HtmlPath, $report.MarkdownPath, $report.ClientHtmlPath, $report.ClientMarkdownPath)) {
            Test-Path -LiteralPath $p | Should -BeTrue
        }
        (Get-Content -LiteralPath $report.ClientHtmlPath -Raw) | Should -Match '1 new'
    }

    It 'a fleet-wide comparison rolls up every server into one model' {
        $baselineEng = Join-Path $TestDrive 'fleetreport-old'
        $currentEng = Join-Path $TestDrive 'fleetreport-new'
        New-FakeRunFolder -RunRoot $baselineEng -ComputerName 'SRV1' -Datasets @{ SmbShares = @(@{ Name = 'Data' }) } | Out-Null
        New-FakeRunFolder -RunRoot $baselineEng -ComputerName 'SRV2' -Datasets @{ SmbShares = @(@{ Name = 'Data' }) } | Out-Null
        New-FakeRunFolder -RunRoot $currentEng -ComputerName 'SRV1' -Datasets @{ SmbShares = @(@{ Name = 'Data' }, @{ Name = 'New' }) } | Out-Null
        New-FakeRunFolder -RunRoot $currentEng -ComputerName 'SRV2' -Datasets @{ SmbShares = @(@{ Name = 'Data' }) } | Out-Null
        $outPath = Join-Path $TestDrive 'fleetreport-out'
        $report = New-DriftReport -BaselineEngagementFolder $baselineEng -CurrentEngagementFolder $currentEng -OutputPath $outPath
        $report.ServerCount | Should -Be 2
        $report.TotalAdded | Should -Be 1
    }

    It 'internal report never appears in the client-safe summary for an Internal-only dataset' {
        $eng = Join-Path $TestDrive 'safety1'
        $baselineRun = New-FakeRunFolder -RunRoot (Join-Path $eng 'old') -ComputerName 'SRV1' -Datasets @{
            LocalGroupMembers = @(@{ Group = 'Administrators'; Member = 'Administrator' })
        } -DatasetVisibility @{ LocalGroupMembers = 'Internal' }
        $currentRun = New-FakeRunFolder -RunRoot (Join-Path $eng 'new') -ComputerName 'SRV1' -Datasets @{
            LocalGroupMembers = @(@{ Group = 'Administrators'; Member = 'Administrator' }, @{ Group = 'Administrators'; Member = 'svc-suspicious' })
        } -DatasetVisibility @{ LocalGroupMembers = 'Internal' }
        $outPath = Join-Path $TestDrive 'safety1-out'
        $report = New-DriftReport -BaselineRunFolder $baselineRun -CurrentRunFolder $currentRun -OutputPath $outPath
        # The real drift happened (1 added) - confirm it shows in the INTERNAL report...
        (Get-Content -LiteralPath $report.HtmlPath -Raw) | Should -Match 'svc-suspicious'
        # ...but never in the client-safe one, since LocalGroupMembers is Internal-only.
        (Get-Content -LiteralPath $report.ClientHtmlPath -Raw) | Should -Not -Match 'svc-suspicious'
        (Get-Content -LiteralPath $report.ClientMarkdownPath -Raw) | Should -Not -Match 'svc-suspicious'
    }
}
