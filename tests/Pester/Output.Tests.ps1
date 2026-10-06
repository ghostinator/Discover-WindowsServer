#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Output.Tests.ps1 - framework Output module tests (Pester 5.x).
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')     -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')
    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dws-tests-" + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
}

AfterAll {
    if ($Tmp -and (Test-Path $Tmp)) { Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Sanitize-WorksheetName' {
    It 'truncates to 31 characters' {
        (Sanitize-WorksheetName -Name ('X' * 50)).Length | Should -Be 31
    }
    It 'removes forbidden worksheet characters' {
        Sanitize-WorksheetName -Name 'a:b/c\d?e*f[g]' | Should -Not -Match '[:\\/\?\*\[\]]'
    }
}

Describe 'Escape-CsvValue' {
    It 'quotes values containing the delimiter' {
        Escape-CsvValue -Value 'a,b' | Should -Be '"a,b"'
    }
    It 'doubles embedded quotes' {
        Escape-CsvValue -Value 'he said "hi"' | Should -Be '"he said ""hi"""'
    }
    It 'guards against formula injection' {
        (Escape-CsvValue -Value '=SUM(A1)').StartsWith("'") | Should -BeTrue
    }
}

Describe 'Escape-XmlText' {
    It 'escapes XML special characters' {
        Escape-XmlText -Value '<a> & "b" ''c''' | Should -Be '&lt;a&gt; &amp; &quot;b&quot; &apos;c&apos;'
    }
    It 'strips illegal control characters' {
        Escape-XmlText -Value ("ok" + [char]0x07 + "text") | Should -Be 'oktext'
    }
}

Describe 'CSV writing' {
    It 'writes a header and rows' {
        $p = Join-Path $Tmp 'out.csv'
        Write-ObjectListToCsv -Rows @([pscustomobject]@{A=1;B='x'}, [pscustomobject]@{A=2;B='y'}) -Path $p | Out-Null
        $lines = Get-Content $p
        $lines[0] | Should -Be 'A,B'
        @($lines | Where-Object { $_ -match '^\d' }).Count | Should -Be 2
    }
    It 'writes a header-only file for empty rows without throwing' {
        $p = Join-Path $Tmp 'empty.csv'
        { Write-ObjectListToCsv -Rows @() -Path $p -Columns @('A','B') | Out-Null } | Should -Not -Throw
        (Get-Content $p)[0] | Should -Be 'A,B'
    }
}

Describe 'JSON writing' {
    # A per-dataset export must be a JSON ARRAY at every row count. Two real defects
    # found on the first Windows run made that false:
    #   0 rows -> "@() | ConvertTo-Json" emits nothing, so the file was 0 bytes and no
    #             parser accepted it. 31 of 89 exports on a real Deep run.
    #   1 row  -> piping unrolled the single-element array, so the file held a bare
    #             object {...} instead of [{...}], i.e. the shape depended on row count.
    # Row counts are parameterised deliberately - a 2-row fixture catches neither.
    BeforeAll {
        $script:JsonDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dwsjson-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $script:JsonDir -Force | Out-Null
    }
    AfterAll {
        if ($script:JsonDir -and (Test-Path $script:JsonDir)) {
            Remove-Item $script:JsonDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes a parseable JSON array for <Label>' -ForEach @(
        @{ Label = '0 rows';  Rows = @();                                                          Expect = 0 }
        @{ Label = '1 row';   Rows = @([pscustomobject]@{ A = 1 });                                 Expect = 1 }
        @{ Label = '2 rows';  Rows = @([pscustomobject]@{ A = 1 }, [pscustomobject]@{ A = 2 });      Expect = 2 }
    ) {
        $p = Join-Path $script:JsonDir ("ds-" + $Expect + ".json")
        Write-ObjectListToJson -InputObject $Rows -Path $p | Should -BeTrue

        (Get-Item $p).Length | Should -BeGreaterThan 0 -Because 'a 0-byte file is not valid JSON'
        $raw = (Get-Content -LiteralPath $p -Raw).Trim()
        $raw.StartsWith('[') | Should -BeTrue -Because 'a dataset export is always an array, whatever the row count'

        # Assign BEFORE counting. Windows PowerShell 5.1's ConvertFrom-Json emits the
        # whole array as ONE pipeline object (PowerShell 6+ made it enumerate), so
        # "@($raw | ConvertFrom-Json).Count" is 1 on 5.1 no matter how many rows there
        # are. Assigning first, then wrapping, is correct on both runtimes.
        $parsed = $raw | ConvertFrom-Json
        @($parsed).Count | Should -Be $Expect
    }

    It 'writes [] for $null rather than [null]' {
        # @($null) is a ONE-element array containing $null, so normalising before the
        # null check would serialise as [null].
        $p = Join-Path $script:JsonDir 'null.json'
        Write-ObjectListToJson -InputObject $null -Path $p | Should -BeTrue
        (Get-Content -LiteralPath $p -Raw).Trim() | Should -Be '[]'
    }
}

Describe 'Excel XML workbook' {
    It 'produces well-formed XML with one worksheet per included dataset' {
        $c = New-DiscoveryContext -Mode Fast -Config $Config
        Add-DataSet -Context $c -Name 'Alpha' -Rows @([pscustomobject]@{A=1}) -IncludeInWorkbook $true | Out-Null
        Add-DataSet -Context $c -Name 'Beta'  -Rows @([pscustomobject]@{B=2}) -IncludeInWorkbook $true | Out-Null
        $p = Join-Path $Tmp 'workbook.xml'
        Write-ExcelXmlWorkbook -Context $c -Path $p | Out-Null
        { [xml](Get-Content $p -Raw) } | Should -Not -Throw
        ([xml](Get-Content $p -Raw)).Workbook.Worksheet.Count | Should -Be 2
    }
    It 'de-duplicates worksheet names that collide after truncation' {
        $c = New-DiscoveryContext -Mode Fast -Config $Config
        Add-DataSet -Context $c -Name ('LongName' * 5 + 'One') -Rows @([pscustomobject]@{A=1}) | Out-Null
        Add-DataSet -Context $c -Name ('LongName' * 5 + 'Two') -Rows @([pscustomobject]@{A=1}) | Out-Null
        $p = Join-Path $Tmp 'wb2.xml'
        Write-ExcelXmlWorkbook -Context $c -Path $p | Out-Null
        $names = ([xml](Get-Content $p -Raw)).Workbook.Worksheet | ForEach-Object { $_.Name }
        @($names | Select-Object -Unique).Count | Should -Be $names.Count
    }
}

Describe 'Markdown table' {
    It 'renders a header, separator, and rows' {
        $md = ConvertTo-MarkdownTable -Rows @([pscustomobject]@{Name='x';Val=1})
        $md | Should -Match '\| Name \| Val \|'
        $md | Should -Match '\| --- \| --- \|'
    }
    It 'returns a placeholder for empty input' {
        ConvertTo-MarkdownTable -Rows @() | Should -Be '_No data._'
    }
}

Describe 'Dependency edge row creation' {
    It 'New-DependencyEdge produces the documented columns' {
        $e = New-DependencyEdge -SourceType 'Service' -SourceName 'AcmeSvc' -DependencyType 'RunsAs' -Target 'DOMAIN\svc' -Confidence 'Confirmed'
        $e.PSObject.Properties.Name | Should -Contain 'SourceType'
        $e.PSObject.Properties.Name | Should -Contain 'ValidationQuestion'
        $e.Target | Should -Be 'DOMAIN\svc'
    }
}

Describe 'Get-InternalReportModel' {
    # Single source of truth for both internal report formats (the printable engineering
    # report and the Command Center dashboard) - this is the one place their shared sort/
    # filter logic can actually be tested, since neither renderer recomputes it itself.

    BeforeAll {
        $script:Ctx = New-DiscoveryContext -Mode Deep -ProjectType Decommission -Config $Config
        $Ctx.Findings.Add((New-DiscoveryFinding -Category 'OS' -Severity 'Low' -Title 'Low finding' -PotentialProjectImpact @('Labor')))
        $Ctx.Findings.Add((New-DiscoveryFinding -Category 'OS' -Severity 'Critical' -Title 'Critical finding'))
        $emph = New-DiscoveryFinding -Category 'Backup' -Severity 'High' -Title 'Emphasized high finding' -PotentialProjectImpact @('Downtime')
        $emph.IsEmphasized = $true
        $Ctx.Findings.Add($emph)
        Add-DataSet -Context $Ctx -Name 'DecommissionReadiness' -Rows @([pscustomobject]@{Factor='DNS'}) -SourceModule 'Test' | Out-Null
        # ScreamTestPlan is in the section map but deliberately left with zero rows, to prove
        # an empty dataset does not produce an empty section either report has to render.
        Add-DataSet -Context $Ctx -Name 'ScreamTestPlan' -Rows @() -SourceModule 'Test' | Out-Null
        $script:Model = Get-InternalReportModel -Context $Ctx
    }

    It 'sorts emphasized findings before severity order, regardless of severity' {
        $Model.Findings[0].Title | Should -Be 'Emphasized high finding'
        $Model.Findings[1].Title | Should -Be 'Critical finding'
        $Model.Findings[2].Title | Should -Be 'Low finding'
    }

    It 'counts findings per severity band' {
        $Model.Counts['Critical'] | Should -Be 1
        $Model.Counts['High']     | Should -Be 1
        $Model.Counts['Low']      | Should -Be 1
        $Model.Counts['Medium']   | Should -Be 0
    }

    It 'isolates emphasized findings without needing to re-filter' {
        $Model.Emphasized.Count | Should -Be 1
        $Model.Emphasized[0].Title | Should -Be 'Emphasized high finding'
    }

    It 'includes a named-dataset section only when it actually has rows' {
        $titles = @($Model.Sections | ForEach-Object { $_.Title })
        $titles | Should -Contain 'Decommission Readiness'
        $titles | Should -Not -Contain 'Scream Test Plan'
    }

    It 'groups findings by project impact' {
        $labor = $Model.ImpactRows | Where-Object { $_.ProjectImpact -eq 'Labor' }
        $labor.FindingCount | Should -Be 1
        $downtime = $Model.ImpactRows | Where-Object { $_.ProjectImpact -eq 'Downtime' }
        $downtime.FindingCount | Should -Be 1
    }

    It 'indexes every dataset, not just the ones with a named section' {
        ($Model.DatasetIndex | Where-Object { $_.Dataset -eq 'ScreamTestPlan' }).Rows | Should -Be 0
    }
}

Describe 'Write-HtmlReport and Write-DashboardHtmlReport' {
    # Both renderers consume the same Get-InternalReportModel - real coverage of the HTML
    # itself lives in tests\Invoke-OutputSmokeTest.ps1 (a real engine run, not a fixture); these
    # just confirm each file is well-formed and the two audiences (print-through vs on-screen
    # nav) actually render differently for the same input.

    BeforeAll {
        $script:Ctx2 = New-DiscoveryContext -Mode Fast -ProjectType GeneralDiscovery -Config $Config
        $Ctx2.Findings.Add((New-DiscoveryFinding -Category 'Security' -Severity 'High' -Title 'Open SMBv1' -Evidence 'EnableSMB1=True'))
        Add-DataSet -Context $Ctx2 -Name 'SecurityPosture' -Rows @([pscustomobject]@{Check='SMB signing'; Result='No'}) -SourceModule 'Test' | Out-Null
    }

    It 'Write-HtmlReport writes a closed, card-rendering HTML file' {
        $p = Join-Path $Tmp 'internal-engineering-report.html'
        Write-HtmlReport -Context $Ctx2 -Path $p | Should -BeTrue
        $html = Get-Content -LiteralPath $p -Raw
        $html.TrimEnd().EndsWith('</html>') | Should -BeTrue
        $html | Should -Match 'class="card sev-High'
        $html | Should -Match 'Open SMBv1'
    }

    It 'Write-DashboardHtmlReport writes a closed HTML file with a sidebar nav and no bare <script> before its library' {
        $p = Join-Path $Tmp 'internal-dashboard-report.html'
        Write-DashboardHtmlReport -Context $Ctx2 -Path $p | Should -BeTrue
        $html = Get-Content -LiteralPath $p -Raw
        $html.TrimEnd().EndsWith('</html>') | Should -BeTrue
        $html | Should -Match 'class="navlink sel"'
        $html | Should -Match 'Open SMBv1'
        $html | Should -Match 'addEventListener'
    }

    It 'renders the same finding in both reports (single Get-InternalReportModel, no drift)' {
        $p1 = Join-Path $Tmp 'both-1.html'; $p2 = Join-Path $Tmp 'both-2.html'
        Write-HtmlReport -Context $Ctx2 -Path $p1 | Out-Null
        Write-DashboardHtmlReport -Context $Ctx2 -Path $p2 | Out-Null
        (Get-Content -LiteralPath $p1 -Raw) -match 'Open SMBv1' | Should -BeTrue
        (Get-Content -LiteralPath $p2 -Raw) -match 'Open SMBv1' | Should -BeTrue
    }
}

Describe 'Get-DependencyDiagramSvg' {
    # Hand-rolled inline SVG, not a JS library - see the function's own doc-comment for why
    # (every report in this repo is a single offline-capable file with no external <script src>).

    It 'returns $null for null/empty edges rather than throwing' {
        { Get-DependencyDiagramSvg -Edges $null } | Should -Not -Throw
        Get-DependencyDiagramSvg -Edges $null | Should -BeNullOrEmpty
        Get-DependencyDiagramSvg -Edges @() | Should -BeNullOrEmpty
    }

    It 'excludes ListeningPort edges by default' {
        $edges = @([pscustomobject]@{ SourceType='Process'; SourceName='svchost'; DependencyType='ListeningPort'; Target='445'; Confidence='Confirmed' })
        Get-DependencyDiagramSvg -Edges $edges | Should -BeNullOrEmpty
    }

    It 'renders a well-formed SVG with a line per surviving edge' {
        $edges = @(
            [pscustomobject]@{ SourceType='SmbShare'; SourceName='Data'; DependencyType='ServesPath'; Target='C:\Shares\Data'; Confidence='Confirmed' }
            [pscustomobject]@{ SourceType='Process'; SourceName='svchost'; DependencyType='ListeningPort'; Target='445'; Confidence='Confirmed' }
        )
        $svg = Get-DependencyDiagramSvg -Edges $edges
        $svg | Should -Not -BeNullOrEmpty
        { [xml]$svg } | Should -Not -Throw
        (@([regex]::Matches($svg, '<line class="dep-edge"'))).Count | Should -Be 1
    }

    It 'HTML-encodes a hostile Target value rather than emitting it raw' {
        $edges = @([pscustomobject]@{ SourceType='Server'; SourceName='SRV1'; DependencyType='HostedOn'; Target='<script>alert(1)</script>'; Confidence='Confirmed' })
        $svg = Get-DependencyDiagramSvg -Edges $edges
        $svg | Should -Not -Match '<script>alert'
        $svg | Should -Match '&lt;script&gt;'
    }

    It 'dedupes an identical edge repeated multiple times and annotates the count' {
        $edges = @(1..3 | ForEach-Object { [pscustomobject]@{ SourceType='ScheduledTask'; SourceName='Nightly'; DependencyType='UsesPath'; Target='\\fs01\share'; Confidence='Confirmed' } })
        $svg = Get-DependencyDiagramSvg -Edges $edges
        (@([regex]::Matches($svg, '<line class="dep-edge"'))).Count | Should -Be 1
        $svg | Should -Match '\(x3\)'
    }

    It 'caps rendered edges at MaxEdges and notes the overflow' {
        $edges = @(1..10 | ForEach-Object { [pscustomobject]@{ SourceType='Server'; SourceName="SRV$_"; DependencyType='DNS'; Target='192.168.0.1'; Confidence='Confirmed' } })
        $svg = Get-DependencyDiagramSvg -Edges $edges -MaxEdges 3
        (@([regex]::Matches($svg, '<line class="dep-edge"'))).Count | Should -Be 3
        $svg | Should -Match '\+7 more edge'
    }
}
