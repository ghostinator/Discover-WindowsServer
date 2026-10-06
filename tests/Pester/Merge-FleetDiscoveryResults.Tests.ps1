#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Merge-FleetDiscoveryResults.Tests.ps1 - fixture-based tests for the fleet rollup script.

    Builds small fake "completed run" folders under $TestDrive (a collection-metadata.json plus
    an evidence\data\json\<Dataset>.json) rather than depending on a real discovery run's output -
    same $TestDrive-fixture approach used elsewhere in this repo (see
    tests\Pester\ConfigDependencyScan.Tests.ps1) so these tests never touch a real output folder.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $Root 'tools\Merge-FleetDiscoveryResults.ps1')

    function New-FakeRunFolder {
        <#
            Test helper: builds one fake completed-run folder under $TestDrive.
            -DatasetVisibility is optional and additive: when omitted, collection-metadata.json's
            Datasets array stays empty exactly as before (existing tests that don't care about
            per-dataset Visibility are unaffected byte-for-byte). Pass it to test anything that
            reads $meta.Datasets' own recorded Visibility - Get-FleetClientSafeDataset (the
            client-summary safety gate) and Get-FleetFolderSummary's FindingCount both do.
        #>
        param(
            [Parameter(Mandatory)][string]$EngagementFolder,
            [Parameter(Mandatory)][string]$ComputerName,
            [string]$RunId = "run-$ComputerName",
            [string]$Mode = 'Fast',
            [hashtable]$Datasets = @{},
            [hashtable]$DatasetVisibility = @{}
        )
        $runDir = Join-Path $EngagementFolder ("Discover-WindowsServer_{0}_20260925_010101" -f $ComputerName)
        New-Item -ItemType Directory -Path (Join-Path $runDir 'evidence\data\json') -Force | Out-Null
        $datasetMeta = @()
        if ($DatasetVisibility.Count -gt 0) {
            $datasetMeta = @(foreach ($name in $Datasets.Keys) {
                $vis = if ($DatasetVisibility.ContainsKey($name)) { $DatasetVisibility[$name] } else { 'Internal' }
                @{ Name = $name; Rows = @($Datasets[$name]).Count; Visibility = $vis }
            })
        }
        $meta = @{ RunId = $RunId; ComputerName = $ComputerName; Mode = $Mode; Datasets = $datasetMeta }
        (ConvertTo-Json $meta -Depth 5) | Out-File (Join-Path $runDir 'evidence\collection-metadata.json') -Encoding utf8
        foreach ($name in $Datasets.Keys) {
            (ConvertTo-Json @($Datasets[$name]) -Depth 5) | Out-File (Join-Path $runDir ("evidence\data\json\{0}.json" -f $name)) -Encoding utf8
        }
        return $runDir
    }
}

Describe 'Get-FleetRunFolder' {
    # None of these wrap the call in an extra @() - Get-FleetRunFolder already returns ,@(...),
    # and re-wrapping an already-array result at the call site nests it inside a spurious
    # 1-element array instead of counting its real contents (the "@(Get-Foo) instead of Get-Foo"
    # gotcha - caught by hand while first writing these tests; see Invoke-FleetDiscovery.Tests.ps1
    # for the full story of how it was found).

    It 'finds only Discover-WindowsServer_* subfolders, ignoring others like fleet-status or rollup' {
        $eng = Join-Path $TestDrive 'eng1'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $eng 'fleet-status') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $eng 'rollup') -Force | Out-Null

        $found = Get-FleetRunFolder -EngagementFolder $eng
        $found.Count      | Should -Be 1
        $found[0].Name    | Should -Match '^Discover-WindowsServer_SRV1_'
    }

    It 'returns an empty array for a folder that does not exist' {
        (Get-FleetRunFolder -EngagementFolder (Join-Path $TestDrive 'does-not-exist')).Count | Should -Be 0
    }
}

Describe 'Get-FleetRunMetadata' {

    It 'parses a valid collection-metadata.json' {
        $eng = Join-Path $TestDrive 'eng2'
        $runDir = New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' -RunId 'abc-123'
        $meta = Get-FleetRunMetadata -RunFolder $runDir
        $meta.ComputerName | Should -Be 'SRV1'
        $meta.RunId        | Should -Be 'abc-123'
    }

    It 'returns $null when collection-metadata.json is missing, rather than throwing' {
        $emptyDir = Join-Path $TestDrive 'eng3-empty-run'
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
        Get-FleetRunMetadata -RunFolder $emptyDir | Should -BeNullOrEmpty
    }

    It 'returns $null for corrupt JSON rather than throwing' {
        $badDir = Join-Path $TestDrive 'eng4-bad-run'
        New-Item -ItemType Directory -Path (Join-Path $badDir 'evidence') -Force | Out-Null
        'not valid json {{{' | Out-File (Join-Path $badDir 'evidence\collection-metadata.json') -Encoding utf8
        Get-FleetRunMetadata -RunFolder $badDir | Should -BeNullOrEmpty
    }
}

Describe 'Add-FleetRowStamp' {

    It 'adds ComputerName/RunId/Mode to every row without losing existing fields' {
        $rows = @([pscustomobject]@{ Title = 'Finding A' }, [pscustomobject]@{ Title = 'Finding B' })
        $stamped = Add-FleetRowStamp -Rows $rows -ComputerName 'SRV1' -RunId 'r1' -Mode 'Deep'
        $stamped.Count           | Should -Be 2
        $stamped[0].ComputerName | Should -Be 'SRV1'
        $stamped[0].RunId        | Should -Be 'r1'
        $stamped[0].Mode         | Should -Be 'Deep'
        $stamped[0].Title        | Should -Be 'Finding A'
    }

    It 'returns an empty array for an empty input' {
        (Add-FleetRowStamp -Rows @() -ComputerName 'SRV1').Count | Should -Be 0
    }
}

Describe 'Merge-FleetDataset' {

    It 'merges the same dataset across two runs and stamps each row with its own server' {
        $eng = Join-Path $TestDrive 'eng5'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F1'; Severity = 'High' }) } | Out-Null
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV2' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F2'; Severity = 'Low' }) } | Out-Null

        # @() wraps the call, matching how every real caller in Merge-FleetDiscoveryResults.ps1
        # consumes this function (never a bare assignment relied on for .Count/indexing) - a
        # bare $merged = Merge-FleetDataset ... unwraps to a scalar for a 1-result merge, and
        # Windows PowerShell 5.1 (unlike pwsh 7+) has no automatic .Count on a scalar object.
        $merged = @(Merge-FleetDataset -EngagementFolder $eng -DatasetName 'ScopingRisks')
        $merged.Count | Should -Be 2
        @($merged.ComputerName | Sort-Object) | Should -Be @('SRV1', 'SRV2')
    }

    It 'skips a run that is missing the requested dataset instead of failing the whole merge' {
        $eng = Join-Path $TestDrive 'eng6'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F1'; Severity = 'High' }) } | Out-Null
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV2' -Datasets @{} | Out-Null   # no ScopingRisks.json at all

        $merged = @(Merge-FleetDataset -EngagementFolder $eng -DatasetName 'ScopingRisks')
        $merged.Count            | Should -Be 1
        $merged[0].ComputerName  | Should -Be 'SRV1'
    }
}

Describe 'Get-SeverityRank' {
    It 'ranks Critical above High above Medium above Low above Info' {
        (Get-SeverityRank 'Critical') | Should -BeGreaterThan (Get-SeverityRank 'High')
        (Get-SeverityRank 'High')     | Should -BeGreaterThan (Get-SeverityRank 'Medium')
        (Get-SeverityRank 'Medium')   | Should -BeGreaterThan (Get-SeverityRank 'Low')
        (Get-SeverityRank 'Low')      | Should -BeGreaterThan (Get-SeverityRank 'Info')
    }

    It 'ranks an unrecognized value lowest rather than throwing' {
        (Get-SeverityRank 'Bogus') | Should -BeLessThan (Get-SeverityRank 'Info')
    }
}

Describe 'Get-FleetRiskRegister' {

    It 'sorts the combined register worst-severity-first across servers' {
        $eng = Join-Path $TestDrive 'eng7'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F1'; Severity = 'Info' }) } | Out-Null
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV2' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F2'; Severity = 'Critical' }) } | Out-Null

        $register = Get-FleetRiskRegister -EngagementFolder $eng
        $register[0].Severity | Should -Be 'Critical'
        $register[-1].Severity | Should -Be 'Info'
    }
}

Describe 'Get-FleetDependencyHint' {

    It 'groups a same-Category/same-Subject finding shared by 2+ servers' {
        $rows = @(
            [pscustomobject]@{ FindingId = 'F1'; Category = 'Cluster'; Subject = 'LABCLUS01'; ComputerName = 'SRV1' }
            [pscustomobject]@{ FindingId = 'F2'; Category = 'Cluster'; Subject = 'LABCLUS01'; ComputerName = 'SRV2' }
        )
        $hints = Get-FleetDependencyHint -FindingRows $rows
        $hints.Count | Should -Be 1
        @($hints[0].ComputerNames | Sort-Object) | Should -Be @('SRV1', 'SRV2')
    }

    It 'does not suggest a group for a Subject that only appears on one server' {
        $rows = @([pscustomobject]@{ FindingId = 'F1'; Category = 'Cluster'; Subject = 'LABCLUS01'; ComputerName = 'SRV1' })
        (Get-FleetDependencyHint -FindingRows $rows).Count | Should -Be 0
    }

    It 'ignores rows with no Subject rather than grouping everything together' {
        $rows = @(
            [pscustomobject]@{ FindingId = 'F1'; Category = 'OS'; Subject = ''; ComputerName = 'SRV1' }
            [pscustomobject]@{ FindingId = 'F2'; Category = 'OS'; Subject = ''; ComputerName = 'SRV2' }
        )
        (Get-FleetDependencyHint -FindingRows $rows).Count | Should -Be 0
    }
}

Describe 'Get-FleetRunOutcome' {

    It 'reads fleet-run-results.json when present' {
        $eng = Join-Path $TestDrive 'eng9'
        New-Item -ItemType Directory -Path $eng -Force | Out-Null
        @([pscustomobject]@{ ComputerName = 'SRV1'; Status = 'Succeeded' }) | ConvertTo-Json | Out-File (Join-Path $eng 'fleet-run-results.json')
        $outcomes = Get-FleetRunOutcome -EngagementFolder $eng
        $outcomes.Count | Should -Be 1
        $outcomes[0].ComputerName | Should -Be 'SRV1'
    }

    It 'returns an empty array (not $null or a throw) when the file is missing' {
        (Get-FleetRunOutcome -EngagementFolder (Join-Path $TestDrive 'eng9-missing')).Count | Should -Be 0
    }
}

Describe 'New-FleetRollupReport' {

    It 'writes fleet-rollup.json and fleet-rollup.html summarizing every server' {
        $eng = Join-Path $TestDrive 'eng8'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F1'; Severity = 'High'; Category = 'OS'; Title = 'X'; Evidence = 'Y' }) } | Out-Null

        $report = New-FleetRollupReport -EngagementFolder $eng
        Test-Path -LiteralPath $report.JsonPath | Should -BeTrue
        Test-Path -LiteralPath $report.HtmlPath | Should -BeTrue
        $report.ServerCount  | Should -Be 1
        $report.FindingCount | Should -Be 1
    }

    It 'shows a failed target with its real error message, not silence - the actual bug reported live' {
        # A rollup built purely from successful Discover-WindowsServer_* folders used to drop
        # every failed target with no trace anywhere - a 4-of-7-failed real run looked identical
        # to "only 3 servers were ever requested." fleet-run-results.json is what makes a failed
        # target visible at all, since it never gets a folder of its own.
        $eng = Join-Path $TestDrive 'eng10'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV-OK' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F1'; Severity = 'Low' }) } | Out-Null
        @(
            [pscustomobject]@{ ComputerName = 'SRV-OK'; Status = 'Succeeded'; LocalResultPath = (Join-Path $eng 'Discover-WindowsServer_SRV-OK_20260925_010101'); ErrorMessage = '' }
            [pscustomobject]@{ ComputerName = 'SRV-DEAD'; Status = 'Unreachable'; LocalResultPath = $null; ErrorMessage = 'WinRM port 5985 did not respond.' }
        ) | ConvertTo-Json | Out-File (Join-Path $eng 'fleet-run-results.json')

        $report = New-FleetRollupReport -EngagementFolder $eng
        $report.ServerCount          | Should -Be 2
        $report.SucceededServerCount | Should -Be 1
        (Get-Content -LiteralPath $report.HtmlPath -Raw) | Should -Match 'SRV-DEAD'
        (Get-Content -LiteralPath $report.HtmlPath -Raw) | Should -Match 'WinRM port 5985 did not respond'
    }

    It 'also writes an interactive dashboard report alongside the printable one' {
        $eng = Join-Path $TestDrive 'eng11'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F1'; Severity = 'Critical'; Category = 'OS'; Title = 'Critical thing'; Evidence = 'Y' }) } | Out-Null

        $report = New-FleetRollupReport -EngagementFolder $eng
        Test-Path -LiteralPath $report.DashboardPath | Should -BeTrue
        $dashHtml = Get-Content -LiteralPath $report.DashboardPath -Raw
        $dashHtml.TrimEnd().EndsWith('</html>') | Should -BeTrue
        $dashHtml | Should -Match 'class="navlink sel"'
        $dashHtml | Should -Match 'Critical thing'
        $dashHtml | Should -Match 'addEventListener'
    }

    It 'renders the same finding in both the printable and dashboard reports (single model, no drift)' {
        $eng = Join-Path $TestDrive 'eng12'
        New-FakeRunFolder -EngagementFolder $eng -ComputerName 'SRV1' -Datasets @{ ScopingRisks = @(@{ FindingId = 'F1'; Severity = 'High'; Category = 'Backup'; Title = 'No backup agent'; Evidence = 'Y' }) } | Out-Null

        $report = New-FleetRollupReport -EngagementFolder $eng
        (Get-Content -LiteralPath $report.HtmlPath -Raw) -match 'No backup agent' | Should -BeTrue
        (Get-Content -LiteralPath $report.DashboardPath -Raw) -match 'No backup agent' | Should -BeTrue
    }
}

Describe 'Get-FleetRollupModel' {
    # Single source of truth for both fleet report formats - the one place their shared
    # aggregation logic can actually be tested.

    BeforeAll {
        $script:Eng = Join-Path $TestDrive 'eng-model'
        New-FakeRunFolder -EngagementFolder $Eng -ComputerName 'SRV-A' -Datasets @{
            ScopingRisks = @(
                @{ FindingId = 'F1'; Severity = 'Critical'; Category = 'Security'; Title = 'SMBv1 enabled'; Evidence = 'X' }
                @{ FindingId = 'F2'; Severity = 'Low'; Category = 'OS'; Title = 'Minor thing'; Evidence = 'X' }
            )
            DecommissionReadiness = @(@{ Factor = 'DNS'; Status = 'Present' })
        } | Out-Null
        @(
            [pscustomobject]@{ ComputerName = 'SRV-A'; Status = 'Succeeded'; LocalResultPath = (Join-Path $Eng 'Discover-WindowsServer_SRV-A_20260925_010101'); ErrorMessage = '' }
            [pscustomobject]@{ ComputerName = 'SRV-DEAD'; Status = 'Failed'; LocalResultPath = $null; ErrorMessage = 'No output folder was found.' }
        ) | ConvertTo-Json | Out-File (Join-Path $Eng 'fleet-run-results.json')
        $script:Model = Get-FleetRollupModel -EngagementFolder $Eng
    }

    It 'includes every attempted server, not just successful ones' {
        $Model.ServerCount | Should -Be 2
        $Model.SucceededServerCount | Should -Be 1
        (@($Model.ServerSummaries | Where-Object { $_.ComputerName -eq 'SRV-DEAD' })).Status | Should -Be 'Failed'
    }

    It 'counts findings per severity across the whole fleet' {
        $Model.Counts['Critical'] | Should -Be 1
        $Model.Counts['Low'] | Should -Be 1
        $Model.Counts['High'] | Should -Be 0
    }

    It 'carries the decommission readiness rollup through' {
        @($Model.DecommissionReadiness).Count | Should -Be 1
    }
}

Describe 'Get-FleetClientSafeDataset and Get-FleetClientModel' {
    # The client summary's whole safety contract: it may only ever surface a dataset a server's
    # OWN collection-metadata.json actually recorded as ClientSafe/Both, and for findings
    # specifically (ScopingRisks is Internal) it may only ever surface Title +
    # WhyItMattersForScoping - never Evidence, Subject, or anything else collected from the box.

    BeforeAll {
        $script:CsEng = Join-Path $TestDrive 'eng-clientsafe'
        New-FakeRunFolder -EngagementFolder $CsEng -ComputerName 'SRV-A' -Datasets @{
            ApplicationFingerprints = @(@{ ApplicationName = 'Sage 300'; Vendor = 'Sage'; Confidence = 'Confirmed'; ComputerName = 'SRV-A' })
            SecurityPosture         = @(@{ Check = 'SMB signing'; Result = 'No' })
            SmbShares               = @(
                @{ Name = 'Data'; ComputerName = 'SRV-A'; Description = 'Data share'; IsUserShare = $true }
                @{ Name = 'Finance'; ComputerName = 'SRV-A'; Description = 'Finance share'; IsUserShare = $true }
            )
            ScopingRisks            = @(
                @{ FindingId = 'F1'; Severity = 'Critical'; Category = 'Security'; Title = 'SMBv1 enabled'; WhyItMattersForScoping = 'Legacy protocol.'; Evidence = 'EnableSMB1=True on \\SRV-A\admin$ registry path' }
                @{ FindingId = 'F2'; Severity = 'Low'; Category = 'OS'; Title = 'Minor thing'; WhyItMattersForScoping = 'Not urgent.'; Evidence = 'some internal path' }
            )
        } -DatasetVisibility @{ ApplicationFingerprints = 'ClientSafe'; SecurityPosture = 'Internal'; SmbShares = 'ClientSafe'; ScopingRisks = 'Internal' }
        New-FakeRunFolder -EngagementFolder $CsEng -ComputerName 'SRV-B' -Datasets @{
            SmbShares    = @(@{ Name = 'Backups'; ComputerName = 'SRV-B'; Description = 'Backups share'; IsUserShare = $true })
            ScopingRisks = @(@{ FindingId = 'F3'; Severity = 'Critical'; Category = 'Security'; Title = 'SMBv1 enabled'; WhyItMattersForScoping = 'Legacy protocol.'; Evidence = 'EnableSMB1=True on SRV-B' })
        } -DatasetVisibility @{ SmbShares = 'ClientSafe'; ScopingRisks = 'Internal' }
    }

    It 'only surfaces a dataset the server itself recorded as ClientSafe or Both' {
        $apps = Get-FleetClientSafeDataset -EngagementFolder $CsEng -DatasetName 'ApplicationFingerprints'
        @($apps).Count | Should -Be 1
        $secPosture = Get-FleetClientSafeDataset -EngagementFolder $CsEng -DatasetName 'SecurityPosture'
        @($secPosture).Count | Should -Be 0
    }

    It 'Get-FleetClientModel keeps one row per share across servers instead of collapsing them into one blob' {
        # Regression test for a real bug found reviewing an actual 7-server fleet run: with 3
        # rows spread across two servers, $Model.Shares silently collapsed to ONE row whose every
        # property was every real row's values space-joined together (e.g. Server showing
        # "SRV-A SRV-A SRV-B"). A 1-2 row fixture can't catch this - the whole point of it is that
        # it only manifests once a dataset actually has more than one row. Caused by
        # Get-FleetClientSafeDataset previously returning ,@($allRows) (correct only for a bare
        # `$x = Get-FleetClientSafeDataset ...` assignment), while every real caller here instead
        # wraps the call in @(...) or pipes it straight into Where-Object/ForEach-Object.
        $model = Get-FleetClientModel -EngagementFolder $CsEng
        @($model.Shares).Count | Should -Be 3
        @($model.Shares | Where-Object { $_.Server -eq 'SRV-A' }).Count | Should -Be 2
        @($model.Shares | Where-Object { $_.Server -eq 'SRV-B' }).Count | Should -Be 1
        ($model.Shares | Where-Object { $_.'Shared folder' -eq 'Finance' }).Server | Should -Be 'SRV-A'
    }

    It 'headlines carry only Title/Category/WhyItMatters/AffectedServers - never Evidence' {
        $headlines = Get-FleetClientHeadlines -EngagementFolder $CsEng
        $headlines.Count | Should -BeGreaterThan 0
        foreach ($h in $headlines) {
            $h.PSObject.Properties.Name | Should -Not -Contain 'Evidence'
        }
        ($headlines | ConvertTo-Json) | Should -Not -Match 'admin\$|registry path'
    }

    It 'groups the same finding title across servers into one headline listing both' {
        $headlines = Get-FleetClientHeadlines -EngagementFolder $CsEng
        $smb1 = $headlines | Where-Object { $_.WhatWeFound -eq 'SMBv1 enabled' }
        $smb1.AffectedServers | Should -Match 'SRV-A'
        $smb1.AffectedServers | Should -Match 'SRV-B'
    }

    It 'Get-FleetClientModel never exposes an internal error message for a failed server' {
        $eng2 = Join-Path $TestDrive 'eng-clientsafe2'
        New-FakeRunFolder -EngagementFolder $eng2 -ComputerName 'SRV-OK' -Datasets @{} | Out-Null
        @(
            [pscustomobject]@{ ComputerName = 'SRV-OK'; Status = 'Succeeded'; LocalResultPath = (Join-Path $eng2 'Discover-WindowsServer_SRV-OK_20260925_010101'); ErrorMessage = '' }
            [pscustomobject]@{ ComputerName = 'SRV-DEAD'; Status = 'Failed'; LocalResultPath = $null; ErrorMessage = 'DCOM bootstrap failed against internal IP 10.0.5.4 using service account svc-fleet' }
        ) | ConvertTo-Json | Out-File (Join-Path $eng2 'fleet-run-results.json')

        $model = Get-FleetClientModel -EngagementFolder $eng2
        ($model | ConvertTo-Json -Depth 5) | Should -Not -Match 'DCOM|10\.0\.5\.4|svc-fleet'
        $model.ServerCount | Should -Be 2
        @($model.ReviewedServers).Count | Should -Be 1
    }

    It 'Write-FleetClientHtmlReport and the Markdown twin never leak Evidence text' {
        $model = Get-FleetClientModel -EngagementFolder $CsEng
        $htmlPath = Join-Path $TestDrive 'client-summary.html'
        $mdPath = Join-Path $TestDrive 'client-summary.md'
        Write-FleetClientHtmlReport -Model $model -Path $htmlPath
        Write-FleetClientMarkdownReport -Model $model -Path $mdPath
        $html = Get-Content -LiteralPath $htmlPath -Raw
        $md = Get-Content -LiteralPath $mdPath -Raw
        $html | Should -Match 'SMBv1 enabled'
        $html | Should -Not -Match 'admin\$|registry path'
        $md | Should -Not -Match 'admin\$|registry path'
        $html.TrimEnd().EndsWith('</html>') | Should -BeTrue
    }
}

Describe 'Get-FleetBranding and Get-FleetLogoHtml' {
    # Regression coverage for a real bug found reviewing a live fleet run: fleet reports called
    # their own CSS functions with no accent color at all, so they showed zero branding no matter
    # what config/output-settings.json said. Get-FleetBranding has no $Context (this script
    # deliberately has no hard dependency on Core.psm1 - see ConvertTo-FleetHtmlTable's own
    # comment) and reads config/output-settings.json off disk directly, so unlike
    # Get-DiscoveryBranding this can only be exercised against the real repo config, not a
    # $TestDrive fixture - it never fails soft into throwing either way, which is what matters.
    It 'reads the real repo config without throwing and returns the expected shape' {
        $b = Get-FleetBranding
        $b.Brand | Should -Not -BeNullOrEmpty
        $b.Accent | Should -Match '^#[0-9A-Fa-f]{6}$'
    }

    It 'prefers %ProgramData% branding (and its logo) over the config dir, like Core does' {
        $cfg = Join-Path $TestDrive 'fb-config'; $pd = Join-Path $TestDrive 'fb-programdata'
        New-Item -ItemType Directory -Path $cfg, $pd -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $cfg 'output-settings.json') -Value '{"html":{"brandName":"Your Company","accentColorHex":"#1F4E79","logoPath":""}}'
        Set-Content -LiteralPath (Join-Path $cfg 'branding.local.json') -Value '{"html":{"brandName":"Old Location"}}'
        Set-Content -LiteralPath (Join-Path $pd 'branding.local.json') -Value '{"html":{"brandName":"Acme","logoPath":"branding-logo.png"}}'
        [System.IO.File]::WriteAllBytes((Join-Path $pd 'branding-logo.png'), [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='))
        $b = Get-FleetBranding -ConfigDirectory $cfg -ProgramDataBrandingDirectory $pd
        $b.Brand | Should -Be 'Acme'
        $b.LogoDataUri | Should -Match '^data:image/png;base64,'
        (Get-FleetBranding -ConfigDirectory $cfg -ProgramDataBrandingDirectory (Join-Path $TestDrive 'none')).Brand | Should -Be 'Old Location'
    }

    It 'Get-FleetLogoHtml renders an image tag only when a logo is set' {
        Get-FleetLogoHtml -Branding @{ Brand = 'Acme'; LogoDataUri = 'data:image/png;base64,ABC' } |
            Should -Be '<img src="data:image/png;base64,ABC" alt="Acme" class="brand-logo">'
        Get-FleetLogoHtml -Branding @{ Brand = 'Acme'; LogoDataUri = $null } | Should -Be ''
    }

    It 'Get-FleetLogoHtml HTML-encodes the brand name in the alt attribute' {
        Get-FleetLogoHtml -Branding @{ Brand = 'A & B <Co>'; LogoDataUri = 'data:image/png;base64,ABC' } |
            Should -Match 'alt="A &amp; B &lt;Co&gt;"'
    }
}
