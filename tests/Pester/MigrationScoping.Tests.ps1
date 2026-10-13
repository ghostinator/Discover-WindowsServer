#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    MigrationScoping.Tests.ps1 - cross-cutting checks for the migration-scoping round:
    CLI backward compatibility, the finding/risk-register schema, per-collector failure
    isolation, the new report sections, decommission states, hypervisor inventory import,
    workload profiles and printer assessment.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')             -Force -DisableNameChecking -Global
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1')         -Force -DisableNameChecking -Global
    Import-Module (Join-Path $Root 'modules\RiskEngine\RiskEngine.psm1') -Force -DisableNameChecking -Global
    Import-Module (Join-Path $Root 'Discover-WindowsServer.psm1')        -Force -DisableNameChecking -Global
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')
}

Describe 'CLI backward compatibility' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'Discover-WindowsServer.ps1'), [ref]$null, [ref]$null)
        $script:Params = @{}
        foreach ($p in $ast.ParamBlock.Parameters) { $script:Params[$p.Name.VariablePath.UserPath] = $p }
    }
    It 'still declares every 1.0 parameter with its original type' {
        $v1 = [ordered]@{ Mode='string'; ProjectType='string'; IncludeModules='string[]'; ExcludeModules='string[]'; OutputRoot='string'; DeepFileShareScan='switch'
            MaxDepth='int'; LargeFileThresholdGB='int'; OldFileYears='int'; EventLogDays='int'; MaxEventSamplesPerLog='int'; FullEventLogExport='switch'
            IncludeConfigDependencyScan='switch'; ConfigScanMaxFileSizeMB='int'; IncludeUserProfiles='switch'; IncludeRecycleBin='switch'; IncludeWindowsFolder='switch'
            AttemptSqlIntegratedAuth='switch'; SkipZip='switch'; GenerateEvidenceManifest='switch'; ComplianceLens='string'; Quiet='switch'; VerboseLogging='switch'; WhatIf='switch' }
        foreach ($k in $v1.Keys) {
            $script:Params.ContainsKey($k) | Should -BeTrue -Because "$k must survive"
            $script:Params[$k].StaticType.Name.ToLowerInvariant() | Should -Be $(switch ($v1[$k]) { 'switch' {'switchparameter'} 'string[]' {'string[]'} 'int' {'int32'} default { $v1[$k] } })
        }
    }
    It 'adds the new parameters as optional, with the privacy-sensitive ones as switches that default off' {
        foreach ($k in 'ExchangeLogDays','CopyExchangeRawLogs','IncludeSensitiveEvidence','HypervisorInventoryPath') { $script:Params.ContainsKey($k) | Should -BeTrue }
        $script:Params['CopyExchangeRawLogs'].StaticType.Name | Should -Be 'SwitchParameter'
        $script:Params['IncludeSensitiveEvidence'].StaticType.Name | Should -Be 'SwitchParameter'
        foreach ($p in $script:Params.Values) {
            @($p.Attributes | Where-Object { $_.TypeName.Name -eq 'Parameter' -and $_.NamedArguments.ArgumentName -contains 'Mandatory' }).Count | Should -Be 0
        }
    }
    It 'registers every new collector in collectorModuleOrder and every collector has a manifest' {
        $order = @($script:Config.Default.collectorModuleOrder)
        foreach ($m in 'ExchangeSmtp','ApplicationStacks','WorkloadProfile','HypervisorInventory') {
            $order | Should -Contain $m
            Test-Path (Join-Path $script:Root "modules\$m\$m.psd1") | Should -BeTrue
        }
        $order.IndexOf('WorkloadProfile') | Should -Be ($order.Count - 1)
        $order.IndexOf('ApplicationStacks') | Should -BeGreaterThan $order.IndexOf('EventLogs')
    }
}

Describe 'Finding and risk-register schema compatibility' {
    It 'keeps every original ScopingRisks column, in order, and appends the new ones' {
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-Finding -Context $ctx -Category 'Database' -Severity 'High' -Confidence 'Likely' -Title 'T' -RiskCategory 'Database migration' | Out-Null
        Build-ContextListDatasets -Context $ctx
        $cols = @($ctx.DataSets['ScopingRisks'].Rows[0].PSObject.Properties.Name)
        $original = @('FindingId','Severity','Confidence','Category','Title','Subject','IsEmphasized','EmphasisReason','Evidence','WhyItMattersForScoping','PotentialProjectImpact','SuggestedValidationQuestion','ComplianceRelevance','SourceModule','SourceDataset')
        ($cols[0..($original.Count - 1)] -join ',') | Should -Be ($original -join ',')
        $cols | Should -Contain 'RiskCategory'; $cols | Should -Contain 'ClientSafe'; $cols | Should -Contain 'SourceServer'
        $ctx.DataSets['ScopingRisks'].Rows[0].SourceServer | Should -Be $env:COMPUTERNAME
    }
    It 'defaults a finding to client-safe and lets a rule opt out' {
        (New-DiscoveryFinding -Category 'X' -Title 'T').ClientSafe | Should -BeTrue
        (New-DiscoveryFinding -Category 'X' -Title 'T' -ClientSafe $false).ClientSafe | Should -BeFalse
    }
    It 'maps rules to the normalized risk categories' {
        Get-RiskCategoryForRule -Rule ([pscustomobject]@{ id='RULE-DNS-001'; category='Identity / AD / DC' }) | Should -Be 'DNS cutover'
        Get-RiskCategoryForRule -Rule ([pscustomobject]@{ id='RULE-X-1'; category='Database' }) | Should -Be 'Database migration'
        Get-RiskCategoryForRule -Rule ([pscustomobject]@{ id='RULE-X-1'; category='Database'; riskCategory='ODBC dependency' }) | Should -Be 'ODBC dependency'
    }
    It 'gives every shipped rule a risk category from the normalized list or its own category' {
        $norm = @('Application compatibility','Database migration','ODBC dependency','IIS dependency','SMTP relay','Exchange decommissioning','Entra Connect relocation','AD role migration','DNS cutover','DHCP cutover','File migration','Printer migration','Target capacity','Backup readiness','Unsupported software','Hypervisor decommissioning','Incomplete discovery')
        foreach ($r in @($script:Config.RiskRules.rules | Where-Object { $_.riskCategory })) { $norm | Should -Contain $r.riskCategory -Because $r.id }
    }
    It 'keeps client-safe headlines free of findings marked clientSafe false (fleet register rows without the column still pass)' {
        . (Join-Path $script:Root 'tools\Merge-FleetDiscoveryResults.ps1')
        $eng = Join-Path $TestDrive 'eng'
        $run = Join-Path $eng 'Discover-WindowsServer_S1_20260101_000000\evidence\data\json'; New-Item -ItemType Directory $run -Force | Out-Null
        @{ RunId='r'; ComputerName='S1'; Mode='Fast'; Datasets=@() } | ConvertTo-Json | Out-File (Join-Path $eng 'Discover-WindowsServer_S1_20260101_000000\evidence\collection-metadata.json') -Encoding utf8
        ConvertTo-Json @(
            [pscustomobject]@{ Severity='High'; Title='Old-style finding'; Category='C'; WhyItMattersForScoping='w' }
            [pscustomobject]@{ Severity='High'; Title='Hidden finding'; Category='C'; WhyItMattersForScoping='w'; ClientSafe=$false }
        ) | Out-File (Join-Path $run 'ScopingRisks.json') -Encoding utf8
        $h = Get-FleetClientHeadlines -EngagementFolder $eng
        @($h.WhatWeFound) | Should -Contain 'Old-style finding'
        @($h.WhatWeFound) | Should -Not -Contain 'Hidden finding'
    }
}

Describe 'Per-collector failure isolation' {
    It 'a collector that throws is recorded and does not stop the next collector' {
        $root = Join-Path $TestDrive 'mods'
        foreach ($m in 'Core','Output') { New-Item -ItemType Directory (Join-Path $root $m) -Force | Out-Null; Copy-Item (Join-Path $script:Root "modules\$m\$m.psm1") (Join-Path $root "$m\$m.psm1") }
        New-Item -ItemType Directory (Join-Path $root 'Boom') -Force | Out-Null
        Set-Content (Join-Path $root 'Boom\Boom.psm1') "function Invoke-DiscoveryCollection { param(`$Context) throw 'collector exploded' }`nfunction ConvertTo-DiscoveryDatasets { param(`$Context, `$RawData) }`nExport-ModuleMember -Function Invoke-DiscoveryCollection,ConvertTo-DiscoveryDatasets"
        New-Item -ItemType Directory (Join-Path $root 'Fine') -Force | Out-Null
        Set-Content (Join-Path $root 'Fine\Fine.psm1') "function Invoke-DiscoveryCollection { param(`$Context) return ,@{ A = 1 } }`nfunction ConvertTo-DiscoveryDatasets { param(`$Context, `$RawData) Add-DataSet -Context `$Context -Name 'FineData' -Rows @([pscustomobject]@{ A = `$RawData.A }) | Out-Null }`nExport-ModuleMember -Function Invoke-DiscoveryCollection,ConvertTo-DiscoveryDatasets"
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config -Quiet $true
        Invoke-CollectorModule -Context $ctx -Name 'Boom' -ModulesRoot $root
        Invoke-CollectorModule -Context $ctx -Name 'Fine' -ModulesRoot $root
        $ctx.DataSets.Contains('FineData') | Should -BeTrue
        $ctx.DataSets['FineData'].Rows[0].A | Should -Be 1
        @($ctx.ModuleStatuses | Where-Object ModuleName -eq 'Boom').Count | Should -Be 1
        ($ctx.Logs | Where-Object { $_.Module -eq 'Boom' -and $_.Level -eq 'ERROR' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Report rendering - new sections' {
    It 'renders the migration-scoping sections in the HTML and Markdown internal reports' {
        $out = Join-Path $TestDrive 'rpt'; New-Item -ItemType Directory $out -Force | Out-Null
        $ctx = New-DiscoveryContext -Mode Deep -Config $script:Config -OutputPath $out -IsAdmin $true -Quiet $true
        Add-DataSet -Context $ctx -Name 'WorkloadProfile' -Rows @([pscustomobject]@{ ComputerName='S1'; TotalMemoryGB=32 }) | Out-Null
        Add-DataSet -Context $ctx -Name 'SmtpRelayAssessment' -Rows @([pscustomobject]@{ Status='Logs unavailable'; UsageProvenUnused=$false }) | Out-Null
        Add-DataSet -Context $ctx -Name 'AppStackSummary' -Rows @([pscustomobject]@{ Stack='Sage 300 Construction and Real Estate'; HostRole='Server' }) -Visibility 'Both' | Out-Null
        Add-DataSet -Context $ctx -Name 'Services' -Rows @([pscustomobject]@{ Name='VendorSvc'; IsNonMicrosoftAutoStart=$true }, [pscustomobject]@{ Name='Spooler'; IsNonMicrosoftAutoStart=$false }) | Out-Null
        $html = Join-Path $out 'r.html'
        Write-HtmlReport -Context $ctx -Path $html | Out-Null
        $t = Get-Content $html -Raw
        $t | Should -Match 'Server Workload &amp; Capacity'
        $t | Should -Match 'SMTP Relay Assessment'
        $t | Should -Match 'Application Stacks'
        $t | Should -Match 'Non-Microsoft Services'
        $t | Should -Match 'VendorSvc'
        $t | Should -Not -Match '<td>Spooler</td>'
        Import-Module (Join-Path $script:Root 'modules\ReportBuilder\ReportBuilder.psm1') -Force -DisableNameChecking
        $md = Join-Path $out 'r.md'
        Write-InternalMarkdownReport -Context $ctx -Path $md
        $m = Get-Content $md -Raw
        $m | Should -Match '## \d+\. SMTP relay assessment'
        $m | Should -Match '## \d+\. Application stacks'
        $m | Should -Match '## \d+\. Follow-up questions'
        ([regex]::Matches($m, '(?m)^## (\d+)\.') | ForEach-Object { [int]$_.Groups[1].Value } | Group-Object | Where-Object Count -gt 1) | Should -BeNullOrEmpty
    }
}

Describe 'Decommission states' {
    BeforeAll { Import-Module (Join-Path $script:Root 'modules\DecommissionReadiness\DecommissionReadiness.psm1') -Force -DisableNameChecking }
    It 'reports running and powered-off VMs, never claims safe, and always requires separate approval for physical removal' {
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config
        Add-DataSet -Context $ctx -Name 'HyperVVMs' -Rows @([pscustomobject]@{ Name='VM1'; State='Running' }, [pscustomobject]@{ Name='VM2'; State='Off' }) | Out-Null
        Build-DecommissionStates -Context $ctx
        $s = @($ctx.DataSets['DecommissionStates'].Rows)
        ($s | Where-Object State -eq 'Active VMs remain').Applies | Should -BeTrue
        ($s | Where-Object State -eq 'Powered-off VMs require disposition').Applies | Should -BeTrue
        ($s | Where-Object State -eq 'Ready for final dependency review').Applies | Should -BeFalse
        ($s | Where-Object State -eq 'Physical removal or data destruction requires separate approval').Applies | Should -BeTrue
        ($s.State -join ' ') | Should -Not -Match '(?i)safe to (shut|power)'
    }
    It 'reaches Ready for final dependency review only when nothing blocks' {
        $ctx = New-DiscoveryContext -Mode Fast -Config $script:Config
        Build-DecommissionStates -Context $ctx
        (@($ctx.DataSets['DecommissionStates'].Rows) | Where-Object State -eq 'Ready for final dependency review').Applies | Should -BeTrue
    }
}

Describe 'Hypervisor inventory import' {
    BeforeAll { Import-Module (Join-Path $script:Root 'modules\HypervisorInventory\HypervisorInventory.psm1') -Force -DisableNameChecking }
    It 'keeps only schema columns (free-text notes are dropped) and classifies power state' {
        $inv = ConvertTo-HypervisorInventory -Rows @(
            [pscustomobject]@{ VMName='APP01'; PowerState='poweredOn'; HostName='esx1'; Notes='admin password Sup3rS3cret!'; SnapshotCount='2'; Source='vCenter' }
            [pscustomobject]@{ VMName='OLD01'; PowerState='poweredOff'; HostName='esx1'; Source='vCenter' }
            [pscustomobject]@{ RecordType='File'; Path='[ds1] iso/win.iso'; Datastore='ds1' }
            [pscustomobject]@{ RecordType='Bogus'; Name='x' }
        )
        @($inv.VM).Count | Should -Be 2
        ($inv.VM[0].PSObject.Properties.Name -contains 'Notes') | Should -BeFalse
        (($inv.VM | ConvertTo-Json)) | Should -Not -Match 'Sup3rS3cret'
        $inv.VM[0].IsRunning | Should -BeTrue
        $inv.VM[0].HasSnapshots | Should -BeTrue
        $inv.VM[1].IsPoweredOff | Should -BeTrue
        $inv.File[0].IsIso | Should -BeTrue
        $inv.Rejected | Should -Be 1
    }
    It 'reports a VM-count conflict between sources for the same host' {
        $vms = @(
            [pscustomobject]@{ VMName='A'; HostName='esx1'; Source='vCenter' }, [pscustomobject]@{ VMName='B'; HostName='esx1'; Source='vCenter' }
            [pscustomobject]@{ VMName='A'; HostName='esx1'; Source='RMM' }
        )
        $c = Get-HypervisorCountConflicts -VMs $vms
        @($c).Count | Should -Be 1
        $c[0].CountsBySource | Should -Match 'vCenter=2'
        # Assign first: the function returns ,@() and wrapping the call in @() would count the empty array as one item.
        $none = Get-HypervisorCountConflicts -VMs @($vms[0], $vms[2])
        @($none).Count | Should -Be 0
    }
    It 'is a clean skip when no inventory file is supplied' {
        (Test-DiscoveryPrerequisites -Context (New-DiscoveryContext -Mode Fast -Config $script:Config)).Status | Should -Be 'NotApplicable'
    }
}

Describe 'Workload profile' {
    BeforeAll { Import-Module (Join-Path $script:Root 'modules\WorkloadProfile\WorkloadProfile.psm1') -Force -DisableNameChecking }
    It 'sums capacity, reports unknown share size as unknown (not zero), and never recommends a size' {
        $data = @{
            Volumes = @([pscustomobject]@{ DriveLetter='C'; SizeGB=100; FreeGB=40 }, [pscustomobject]@{ DriveLetter='D'; SizeGB=500; FreeGB=100 })
            SmbShares = @([pscustomobject]@{ Name='Data'; IsUserShare=$true })
            SqlServerSummary = @([pscustomobject]@{ TotalDatabaseSizeGB=55.5; ProductVersions='SQL Server 2019' })
            Hardware = @([pscustomobject]@{ TotalPhysicalMemoryGB=32; LogicalProcessors=8 })
        }
        $get = { param($n) if ($data.ContainsKey($n)) { @($data[$n]) } else { @() } }.GetNewClosure()
        $p = Get-WorkloadProfileRow -GetRows $get -ComputerName 'S1' -FreeMemoryGB 12
        $p.TotalCapacityGB | Should -Be 600
        $p.FreeCapacityGB | Should -Be 140
        $p.UsedCapacityGB | Should -Be 460
        $p.SqlDataGB | Should -Be 55.5
        $p.ShareDataGB | Should -BeNullOrEmpty
        $p.ShareSizeUnknown | Should -BeTrue
        $p.SizingNote | Should -Match 'Not a sizing recommendation'
    }
}

Describe 'Printer assessment' {
    BeforeAll { Import-Module (Join-Path $script:Root 'modules\PrintServer\PrintServer.psm1') -Force -DisableNameChecking }
    It 'flags multifunction devices, direct-IP ports and legacy drivers' {
        $a = Get-PrinterAssessment -Name 'Copier 2F' -DriverName 'KONICA MINOLTA bizhub C458' -PortName '10.0.0.40' -PortHostAddress '10.0.0.40' -DriverMajorVersion 2
        $a.IsMultifunctionLikely | Should -BeTrue
        $a.IsDirectIp | Should -BeTrue
        $a.IsLegacyDriver | Should -BeTrue
        (Get-PrinterAssessment -Name 'Zebra GK420' -DriverName 'ZDesigner GK420d' -PortName 'USB001').IsLabelPrinter | Should -BeTrue
        (Get-PrinterAssessment -Name 'Office' -DriverName 'HP Universal Printing PCL 6' -PortName 'IP_10.0.0.9' -DriverMajorVersion 3).IsLegacyDriver | Should -BeFalse
    }
}

Describe 'Event provider areas' {
    BeforeAll { Import-Module (Join-Path $script:Root 'modules\EventLogs\EventLogs.psm1') -Force -DisableNameChecking }
    It 'maps providers to migration areas (SQL engine providers stay SQL, then vendors before platform areas)' {
        Get-EventProviderArea -ProviderName 'MSSQL$SAGE' | Should -Be 'SQL Server'
        Get-EventProviderArea -ProviderName 'Sage Timberline Office' | Should -Be 'Sage / Timberline'
        Get-EventProviderArea -ProviderName 'MSExchangeTransport' | Should -Be 'Exchange'
        Get-EventProviderArea -ProviderName 'ADSync' | Should -Be 'Entra Connect'
        Get-EventProviderArea -ProviderName 'Service Control Manager' | Should -Be ''
    }
}
