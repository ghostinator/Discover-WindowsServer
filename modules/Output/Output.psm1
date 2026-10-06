<#
    Output.psm1
    Ultimate Modular Windows Server Discovery Toolkit - Output module.

    Responsible for turning the runtime context into files:
      - CSV / JSON per dataset
      - Excel 2003 XML workbook (no Excel required)
      - Static internal HTML report (embedded CSS, no external dependencies)
      - Markdown pack (summaries, questions, scope language, complexity, etc.)
      - Discovery plan
      - Live status handled by Core; this module handles final artifacts
      - Optional ZIP archive

    All writers are read-only with respect to the target system: they only write
    into the toolkit output folder.
#>

$script:XmlNamespaces = @'
 xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:html="http://www.w3.org/TR/REC-html40"
'@

#region Value formatting ------------------------------------------------------

function ConvertTo-DisplayString {
    <# Flattens any value into a single stable display string for CSV/HTML/workbook. #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool])   { return ([string]$Value) }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    # Order matters: a hashtable/dictionary is also IEnumerable, so it must be handled first or
    # it gets enumerated into DictionaryEntry objects and every cell renders as
    # "System.Collections.DictionaryEntry".
    if ($Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
        try { return ($Value | ConvertTo-Json -Depth 4 -Compress) } catch { return [string]$Value }
    }
    if ($Value -is [pscustomobject]) {
        try { return ($Value | ConvertTo-Json -Depth 4 -Compress) } catch { return [string]$Value }
    }
    if (($Value -is [System.Array]) -or (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string]))) {
        try {
            $parts = @()
            foreach ($v in $Value) { $parts += (ConvertTo-DisplayString -Value $v) }
            return ($parts -join '; ')
        } catch { return [string]$Value }
    }
    return [string]$Value
}

function Get-DatasetColumns {
    <# Returns the ordered union of property names across dataset rows. #>
    [CmdletBinding()] param($Rows)
    $cols = [System.Collections.Specialized.OrderedDictionary]::new()
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        # Test dictionaries first: a hashtable also satisfies -is [psobject], and reading
        # PSObject.Properties on one returns Keys/Values/Count rather than its entries.
        if ($r -is [hashtable] -or $r -is [System.Collections.IDictionary]) {
            foreach ($k in $r.Keys) { if (-not $cols.Contains($k)) { $cols[$k] = $true } }
        } elseif ($r -is [pscustomobject] -or $r -is [psobject]) {
            foreach ($p in $r.PSObject.Properties) { if (-not $cols.Contains($p.Name)) { $cols[$p.Name] = $true } }
        }
    }
    return @($cols.Keys)
}

function Get-CsvDelimiter {
    <# Resolves the configured CSV delimiter (config\output-settings.json -> csv.delimiter). #>
    [CmdletBinding()] param([object]$Context)
    $d = ','
    try { if ($Context -and $Context.Config -and $Context.Config.Output -and $Context.Config.Output.csv -and $Context.Config.Output.csv.delimiter) { $d = [string]$Context.Config.Output.csv.delimiter } } catch { }
    if ([string]::IsNullOrEmpty($d)) { $d = ',' }
    return $d
}

function Get-RowValue {
    [CmdletBinding()] param($Row, [string]$Column)
    if ($null -eq $Row) { return $null }
    try {
        if ($Row -is [hashtable]) { if ($Row.ContainsKey($Column)) { return $Row[$Column] } else { return $null } }
        $prop = $Row.PSObject.Properties[$Column]
        if ($prop) { return $prop.Value }
        return $null
    } catch { return $null }
}

#endregion

#region CSV -------------------------------------------------------------------

function Escape-CsvValue {
    <# RFC 4180-style CSV escaping with basic formula-injection guarding. #>
    [CmdletBinding()]
    param([AllowNull()]$Value, [string]$Delimiter = ',')
    $s = ConvertTo-DisplayString -Value $Value
    if ([string]::IsNullOrEmpty($s)) { return '' }
    # Guard against spreadsheet formula injection.
    if ($s.Length -gt 0 -and ('=','+','-','@') -contains $s[0]) { $s = "'" + $s }
    $needsQuote = ($s.Contains($Delimiter) -or $s.Contains('"') -or $s.Contains("`n") -or $s.Contains("`r"))
    if ($needsQuote) { $s = '"' + ($s -replace '"','""') + '"' }
    return $s
}

function Write-ObjectListToCsv {
    <# Writes a list of objects to a CSV file with consistent, controlled escaping. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Columns,
        [string]$Delimiter = ','
    )
    try {
        $rowArray = @(if ($null -eq $Rows) { @() } else { @($Rows) })
        if (-not $Columns -or $Columns.Count -eq 0) { $Columns = Get-DatasetColumns -Rows $rowArray }
        if (-not $Columns -or $Columns.Count -eq 0) { $Columns = @('Value') }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine((($Columns | ForEach-Object { Escape-CsvValue -Value $_ -Delimiter $Delimiter }) -join $Delimiter))
        foreach ($r in $rowArray) {
            $cells = foreach ($c in $Columns) { Escape-CsvValue -Value (Get-RowValue -Row $r -Column $c) -Delimiter $Delimiter }
            [void]$sb.AppendLine(($cells -join $Delimiter))
        }
        $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Warning ("Write-ObjectListToCsv failed for '{0}': {1}" -f $Path, $_.Exception.Message)
        return $false
    }
}

#endregion

#region JSON ------------------------------------------------------------------

function Write-ObjectListToJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 12
    )
    try {
        # A per-dataset export must ALWAYS be a JSON array, for every row count.
        # Two bugs lived in the old one-liner:
        #   0 rows -> an empty array is not $null, so it fell through to ConvertTo-Json,
        #             and "@() | ConvertTo-Json" emits NOTHING. The result was a 0-byte
        #             file that no JSON parser accepts. 31 of 89 exports on a real run.
        #   1 row  -> piping unrolls the single-element array, so ConvertTo-Json received
        #             a bare object and wrote {...} instead of [{...}]. Consumers got a
        #             different shape depending on how many rows happened to exist.
        # Passing -InputObject instead of piping is what preserves the array. Note that
        # ConvertTo-Json -AsArray would be the obvious fix but does not exist in Windows
        # PowerShell 5.1, which is the target runtime.
        # $null must be handled BEFORE the @() normalisation: @($null) is a ONE-element
        # array containing $null, which would serialise as [null] rather than [].
        if ($null -eq $InputObject) {
            $json = '[]'
        } else {
            $rowsToWrite = @($InputObject)
            if ($rowsToWrite.Count -eq 0) {
                $json = '[]'
            } else {
                $json = ConvertTo-Json -InputObject $rowsToWrite -Depth $Depth
            }
        }
        $json | Out-File -LiteralPath $Path -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Warning ("Write-ObjectListToJson failed for '{0}': {1}" -f $Path, $_.Exception.Message)
        return $false
    }
}

#endregion

#region Excel 2003 XML workbook ----------------------------------------------

function Escape-XmlText {
    <# Escapes XML special chars and strips characters illegal in XML 1.0. #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    $s = ConvertTo-DisplayString -Value $Value
    if ([string]::IsNullOrEmpty($s)) { return '' }
    # Remove control chars except tab (09), LF (0A), CR (0D).
    $s = [regex]::Replace($s, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
    $s = $s -replace '&','&amp;'
    $s = $s -replace '<','&lt;'
    $s = $s -replace '>','&gt;'
    $s = $s -replace '"','&quot;'
    $s = $s -replace "'",'&apos;'
    return $s
}

function Sanitize-WorksheetName {
    <# Makes an Excel-safe worksheet name (<=31 chars, no : \ / ? * [ ]). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name, [int]$MaxLength = 31)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'Sheet' }
    $clean = $Name -replace '[:\\/\?\*\[\]]', '_'
    $clean = $clean.Trim("'").Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Sheet' }
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength) }
    return $clean
}

function Get-ExcelXmlType {
    <# Returns the Excel SpreadsheetML data type for a value. #>
    [CmdletBinding()] param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'String' }
    if ($Value -is [bool]) { return 'String' }
    if ($Value -is [datetime]) { return 'DateTime' }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [float] -or $Value -is [int16] -or $Value -is [uint32] -or $Value -is [uint64]) { return 'Number' }
    return 'String'
}

function Get-ExcelXmlValue {
    <# Formats a value for an Excel SpreadsheetML <Data> element (already XML-escaped). #>
    [CmdletBinding()] param([AllowNull()]$Value, [string]$Type = 'String')
    switch ($Type) {
        'Number'   { try { return ([string]([double]$Value)) } catch { return (Escape-XmlText $Value) } }
        'DateTime' { try { return ([datetime]$Value).ToString('yyyy-MM-ddTHH:mm:ss.000') } catch { return (Escape-XmlText $Value) } }
        default    { return (Escape-XmlText $Value) }
    }
}

function ConvertTo-ExcelXmlWorksheet {
    <# Builds one <Worksheet> element for a dataset. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorksheetName,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Rows,
        [string[]]$Columns
    )
    $rowArray = @(if ($null -eq $Rows) { @() } else { @($Rows) })
    if (-not $Columns -or $Columns.Count -eq 0) { $Columns = Get-DatasetColumns -Rows $rowArray }
    if (-not $Columns -or $Columns.Count -eq 0) { $Columns = @('Value') }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine((' <Worksheet ss:Name="{0}">' -f (Escape-XmlText $WorksheetName)))
    [void]$sb.AppendLine('  <Table>')
    # Header row.
    [void]$sb.AppendLine('   <Row>')
    foreach ($c in $Columns) {
        [void]$sb.AppendLine(('    <Cell ss:StyleID="Header"><Data ss:Type="String">{0}</Data></Cell>' -f (Escape-XmlText $c)))
    }
    [void]$sb.AppendLine('   </Row>')
    # Data rows.
    foreach ($r in $rowArray) {
        [void]$sb.AppendLine('   <Row>')
        foreach ($c in $Columns) {
            $val = Get-RowValue -Row $r -Column $c
            $type = Get-ExcelXmlType -Value $val
            $fmt  = Get-ExcelXmlValue -Value $val -Type $type
            [void]$sb.AppendLine(('    <Cell><Data ss:Type="{0}">{1}</Data></Cell>' -f $type, $fmt))
        }
        [void]$sb.AppendLine('   </Row>')
    }
    [void]$sb.AppendLine('  </Table>')
    [void]$sb.AppendLine(' </Worksheet>')
    return $sb.ToString()
}

function Write-ExcelXmlWorkbook {
    <#
        Writes an Excel 2003 XML workbook with one worksheet per dataset that is
        marked IncludeInWorkbook. Worksheet names are sanitized and de-duplicated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Path,
        [string]$HeaderColor = '#D9EAF7',
        [string]$FontName = 'Calibri',
        [int]$FontSize = 11
    )
    try {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('<?xml version="1.0"?>')
        [void]$sb.AppendLine('<?mso-application progid="Excel.Sheet"?>')
        [void]$sb.AppendLine(('<Workbook{0}>' -f $script:XmlNamespaces))
        [void]$sb.AppendLine(' <Styles>')
        [void]$sb.AppendLine(('  <Style ss:ID="Default" ss:Name="Normal"><Font ss:FontName="{0}" ss:Size="{1}"/><Alignment ss:Vertical="Top"/></Style>' -f $FontName, $FontSize))
        [void]$sb.AppendLine(('  <Style ss:ID="Header"><Font ss:FontName="{0}" ss:Size="{1}" ss:Bold="1"/><Interior ss:Color="{2}" ss:Pattern="Solid"/><Alignment ss:Vertical="Top"/></Style>' -f $FontName, $FontSize, $HeaderColor))
        [void]$sb.AppendLine(' </Styles>')

        $usedNames = [System.Collections.Generic.HashSet[string]]::new()
        $maxLen = 31
        if ($Context.Config -and $Context.Config.Output -and $Context.Config.Output.workbook -and $Context.Config.Output.workbook.maxWorksheetNameLength) {
            $maxLen = [int]$Context.Config.Output.workbook.maxWorksheetNameLength
        }

        $wsCount = 0
        foreach ($key in $Context.DataSets.Keys) {
            $ds = $Context.DataSets[$key]
            if (-not $ds.IncludeInWorkbook) { continue }
            $baseName = Sanitize-WorksheetName -Name $ds.Name -MaxLength $maxLen
            $name = $baseName; $i = 2
            while ($usedNames.Contains($name.ToLowerInvariant())) {
                $suffix = "_{0}" -f $i
                $trim = [math]::Max(0, $maxLen - $suffix.Length)
                $name = (Sanitize-WorksheetName -Name $baseName -MaxLength $trim) + $suffix
                $i++
            }
            [void]$usedNames.Add($name.ToLowerInvariant())
            $wsRows = if ($ds.PSObject.Properties['WorkbookRows']) { $ds.WorkbookRows } else { $ds.Rows }
            [void]$sb.Append((ConvertTo-ExcelXmlWorksheet -WorksheetName $name -Rows $wsRows))
            $wsCount++
        }

        if ($wsCount -eq 0) {
            # Always produce at least one worksheet so the file is valid.
            [void]$sb.Append((ConvertTo-ExcelXmlWorksheet -WorksheetName 'NoData' -Rows @([pscustomobject]@{ Note = 'No datasets were marked for the workbook.' })))
        }

        [void]$sb.AppendLine('</Workbook>')
        $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Warning ("Write-ExcelXmlWorkbook failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

#endregion

#region Markdown --------------------------------------------------------------

function Write-MarkdownFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    try { $Content | Out-File -LiteralPath $Path -Encoding UTF8 -Force; return $true }
    catch { Write-Warning ("Write-MarkdownFile failed for '{0}': {1}" -f $Path, $_.Exception.Message); return $false }
}

function ConvertTo-MarkdownTable {
    <# Builds a GitHub-flavored markdown table from a list of objects. #>
    [CmdletBinding()]
    param([AllowNull()]$Rows, [string[]]$Columns)
    $rowArray = @(if ($null -eq $Rows) { @() } else { @($Rows) })
    if ($rowArray.Count -eq 0) { return '_No data._' }
    if (-not $Columns -or $Columns.Count -eq 0) { $Columns = Get-DatasetColumns -Rows $rowArray }
    $esc = { param($v) (ConvertTo-DisplayString -Value $v) -replace '\|','\|' -replace '(\r\n|\n|\r)',' ' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('| ' + (($Columns | ForEach-Object { & $esc $_ }) -join ' | ') + ' |')
    [void]$sb.AppendLine('| ' + (($Columns | ForEach-Object { '---' }) -join ' | ') + ' |')
    foreach ($r in $rowArray) {
        $cells = foreach ($c in $Columns) { & $esc (Get-RowValue -Row $r -Column $c) }
        [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
    }
    return $sb.ToString()
}

#endregion

#region Compression -----------------------------------------------------------

function Compress-Folder {
    <#
        Zips the contents of a folder (excluding named subfolders such as the
        archive folder itself) into a destination .zip. Read-only w.r.t. the OS.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceFolder,
        [Parameter(Mandatory)][string]$DestinationZip,
        [string[]]$ExcludeChildFolders = @('archive')
    )
    if (-not (Test-Path -LiteralPath $SourceFolder)) { return $false }
    $items = Get-ChildItem -LiteralPath $SourceFolder -Force | Where-Object {
        -not ($_.PSIsContainer -and ($ExcludeChildFolders -contains $_.Name))
    }
    if (-not $items) { return $false }
    if (Test-Path -LiteralPath $DestinationZip) { Remove-Item -LiteralPath $DestinationZip -Force -ErrorAction SilentlyContinue }
    # One retry: a file this zips (e.g. the live status JSON) can still be mid-write by the
    # engine when archiving starts, producing a transient sharing-violation on the first attempt.
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            Compress-Archive -Path ($items.FullName) -DestinationPath $DestinationZip -Force -ErrorAction Stop
            return (Test-Path -LiteralPath $DestinationZip)
        } catch {
            $script:LastCompressFolderError = $_.Exception.Message
            if ($attempt -eq 2) { return $false }
            Start-Sleep -Seconds 2
        }
    }
}

function Get-CompressFolderLastError {
    <# The exception message from the most recent failed Compress-Folder call, if any. #>
    [CmdletBinding()]
    param()
    return $script:LastCompressFolderError
}

#endregion

#region Dataset export --------------------------------------------------------

function Export-DiscoveryDatasets {
    <# Writes every dataset to csv\ and json\, and returns the count written. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    $csvDir  = $Context.Paths['Csv']
    $jsonDir = $Context.Paths['Json']
    $delim = Get-CsvDelimiter -Context $Context
    $depth = 12
    if ($Context.Config -and $Context.Config.Output -and $Context.Config.Output.json -and $Context.Config.Output.json.depth) { $depth = [int]$Context.Config.Output.json.depth }
    $count = 0
    foreach ($key in $Context.DataSets.Keys) {
        $ds = $Context.DataSets[$key]
        $safe = ConvertTo-SafeFileName -Name $ds.Name
        try { Write-ObjectListToCsv  -Rows $ds.Rows -Path (Join-Path $csvDir  ("{0}.csv"  -f $safe)) -Delimiter $delim | Out-Null } catch { }
        try { Write-ObjectListToJson -InputObject @($ds.Rows) -Path (Join-Path $jsonDir ("{0}.json" -f $safe)) -Depth $depth | Out-Null } catch { }
        $count++
    }
    return $count
}

#endregion

#region Discovery plan --------------------------------------------------------

function Write-DiscoveryPlan {
    <# Writes discovery-plan.md before collectors run. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$Path)
    $p = $Context.Parameters
    $get = { param($k, $d) if ($p -and $p.ContainsKey($k)) { $p[$k] } else { $d } }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Discovery Plan')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> Generated before collection began. This documents exactly what the toolkit intends to do.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Run Metadata')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('- **Run ID:** {0}' -f $Context.RunId))
    [void]$sb.AppendLine(('- **Computer name:** {0}' -f $Context.ComputerName))
    [void]$sb.AppendLine(('- **Started:** {0}' -f $Context.StartTime.ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$sb.AppendLine(('- **Mode:** {0}' -f $Context.Mode))
    [void]$sb.AppendLine(('- **Project type:** {0}' -f $Context.ProjectType))
    [void]$sb.AppendLine(('- **Compliance lens:** {0}' -f $Context.ComplianceLens))
    [void]$sb.AppendLine(('- **Running elevated (admin):** {0}' -f $Context.IsAdmin))
    [void]$sb.AppendLine(('- **Running as SYSTEM:** {0}' -f $Context.IsSystem))
    [void]$sb.AppendLine(('- **PowerShell version:** {0}' -f $Context.PowerShellVersion))
    [void]$sb.AppendLine(('- **Output path:** {0}' -f $Context.OutputPath))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Module Plan')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('- **Included modules:** {0}' -f (($Context.IncludedModules) -join ', ')))
    [void]$sb.AppendLine(('- **Excluded modules:** {0}' -f (($Context.ExcludedModules) -join ', ')))
    [void]$sb.AppendLine('')
    if (@($Context.ModuleStatuses).Count -gt 0) {
        [void]$sb.AppendLine('### Module status / impact')
        [void]$sb.AppendLine('')
        $planRows = foreach ($m in $Context.ModuleMetadata) {
            $st = $Context.ModuleStatuses | Where-Object { $_.ModuleName -eq $m.ModuleName } | Select-Object -First 1
            [pscustomobject]@{
                Module = $m.ModuleName
                Impact = $m.EstimatedImpact
                Planned = ($Context.IncludedModules -contains $m.ModuleName)
                CanRun = if ($st) { $st.CanRun } else { '' }
                Status = if ($st) { $st.Status } else { 'NotEvaluated' }
                Reason = if ($st) { $st.Reason } else { '' }
            }
        }
        [void]$sb.AppendLine((ConvertTo-MarkdownTable -Rows $planRows))
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('## High-Impact Activity Switches')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('- **Deep file share scan:** {0}' -f (& $get 'DeepFileShareScan' $false)))
    [void]$sb.AppendLine(('- **Config dependency scan:** {0}' -f (& $get 'IncludeConfigDependencyScan' $false)))
    [void]$sb.AppendLine(('- **SQL integrated auth attempt:** {0}' -f (& $get 'AttemptSqlIntegratedAuth' $false)))
    [void]$sb.AppendLine(('- **Full event log export:** {0}' -f (& $get 'FullEventLogExport' $false)))
    [void]$sb.AppendLine(('- **Include user profiles:** {0}' -f (& $get 'IncludeUserProfiles' $false)))
    [void]$sb.AppendLine(('- **Include recycle bin:** {0}' -f (& $get 'IncludeRecycleBin' $false)))
    [void]$sb.AppendLine(('- **Include Windows folder:** {0}' -f (& $get 'IncludeWindowsFolder' $false)))
    [void]$sb.AppendLine(('- **Generate evidence manifest:** {0}' -f (& $get 'GenerateEvidenceManifest' $false)))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Expected Limitations')
    [void]$sb.AppendLine('')
    if (-not $Context.IsAdmin) { [void]$sb.AppendLine('- Not running elevated: some security posture, event log, and WMI/registry data may be incomplete.') }
    if ($Context.IsSystem) { [void]$sb.AppendLine('- Running as SYSTEM: user-context data (mapped drives, user DSNs, HKCU) may be invisible.') }
    if ($Context.Mode -eq 'Fast') { [void]$sb.AppendLine('- Fast mode: deep file share crawl, config dependency scan, and deep SQL enumeration are skipped unless explicitly enabled.') }
    [void]$sb.AppendLine('- Warranty, licensing legality, and vendor support status cannot be determined locally and require client/vendor validation.')
    [void]$sb.AppendLine('')
    Write-MarkdownFile -Path $Path -Content ($sb.ToString()) | Out-Null
}

#endregion

#region HTML report -----------------------------------------------------------

function Get-HtmlReportCss {
    <#
        Option-B visual language (see the report-redesign conversation): KPI strip, a colored
        left stripe per severity instead of a badge dot, everything rendered inline/expanded so
        the file reads start to finish like a printed report - no collapse, no JS, prints
        cleanly to PDF. System font stack only (no CDN/Google Fonts) - this file is opened
        offline on client sites, sometimes air-gapped.
    #>
    [CmdletBinding()] param([string]$AccentColorHex = '#1F4E79')
    if ([string]::IsNullOrWhiteSpace($AccentColorHex)) { $AccentColorHex = '#1F4E79' }
    $css = @'
:root{--accent:__ACCENT__;--accent-bg:#EAF1F8;--accent-text:#123350;--bg:#ffffff;--surface:#F7F8FA;--fg:#1A1F27;--muted:#5B6472;--line:#E1E5EA;
--critical:#B42318;--critical-bg:#FBEAE9;--high:#B54708;--high-bg:#FDF1E7;--medium:#4A5B79;--medium-bg:#EBEEF4;--low:#5B6472;--low-bg:#EEF0F3;--info:#5B6472;--info-bg:#EEF0F3;--emph:#6A3E9E;--emph-bg:#F5F0FA}
*{box-sizing:border-box}body{font-family:Segoe UI,Calibri,Arial,sans-serif;color:var(--fg);background:var(--bg);margin:0;line-height:1.55;font-size:14px}
header{background:var(--accent);color:#fff;padding:28px 36px}header h1{margin:0 0 5px;font-size:22px;font-weight:600}header .sub{opacity:.9;font-size:13px}
header .brand-logo{max-height:40px;vertical-align:middle;margin-right:12px}
main{max-width:1200px;margin:0 auto;padding:8px 36px 36px}
h2{color:var(--accent);border-bottom:2px solid var(--line);padding-bottom:7px;margin-top:38px;font-size:19px}
h3{color:#333;margin-top:22px;font-size:15px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
th,td{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{background:var(--surface);font-weight:600}
.meta{display:flex;flex-wrap:wrap;gap:8px 24px;font-size:13px;margin:12px 0}
.meta div{min-width:180px}.meta b{color:var(--accent)}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.kpi{flex:1;min-width:130px;border-radius:8px;padding:14px;text-align:center;background:var(--surface)}
.kpi .n{font-size:26px;font-weight:700;color:var(--accent);word-break:break-word}.kpi .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-top:2px}
.dep-diagram{overflow-x:auto;border:1px solid var(--line);border-radius:8px;padding:8px;background:#fff}
.muted{color:var(--muted);font-size:12px}
.card{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:0 8px 8px 0;padding:12px 16px;margin:10px 0;background:#fff}
.card.sev-Critical{border-left-color:var(--critical);background:var(--critical-bg)}
.card.sev-High{border-left-color:var(--high);background:var(--high-bg)}
.card.sev-Medium{border-left-color:var(--medium);background:var(--medium-bg)}
.card.sev-Low{border-left-color:var(--low);background:var(--low-bg)}
.card.sev-Info{border-left-color:var(--info);background:var(--info-bg)}
.card.emph-card{border-left-color:var(--emph);box-shadow:inset 0 0 0 1px var(--emph)}
.badge{display:inline-block;padding:2px 9px;border-radius:100px;font-size:11px;font-weight:600}
.sev-Critical .badge.sevbadge{background:var(--critical);color:#fff}
.sev-High .badge.sevbadge{background:var(--high);color:#fff}
.sev-Medium .badge.sevbadge{background:var(--medium);color:#fff}
.sev-Low .badge.sevbadge{background:var(--low);color:#fff}
.sev-Info .badge.sevbadge{background:var(--info);color:#fff}
.badge.emph{background:var(--emph);color:#fff}
code{background:var(--surface);padding:1px 4px;border-radius:3px;font-size:12px;font-family:Consolas,"Cascadia Code",monospace}
footer{max-width:1200px;margin:24px auto;padding:16px 36px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
ul.q li{margin:6px 0}
@media print{header{background:#fff;color:var(--accent);border-bottom:3px solid var(--accent)}main{padding:0 8px}.card{break-inside:avoid}}
'@
    return ($css -replace '__ACCENT__', $AccentColorHex)
}

function Get-InternalReportSectionMap {
    <#
        Display name -> dataset name, for every named-dataset section the internal report
        renders. One list shared by both internal report formats (the printable engineering
        report and the Command Center dashboard) so adding a dataset section to one can't
        silently leave it missing from the other - same reasoning as Get-RbClientModel's own
        "build the model once" comment in ReportBuilder.psm1.
    #>
    return [ordered]@{
        'Decommission Readiness'   = 'DecommissionReadiness'
        'Scream Test Plan'         = 'ScreamTestPlan'
        'Migration Complexity'     = 'MigrationComplexity'
        'Application Validation Matrix' = 'ApplicationValidationMatrix'
        'Database Findings'        = 'SqlInstances'
        'IIS / Web Findings'       = 'IisSites'
        'Identity / AD / DNS / DHCP' = 'DomainContext'
        'Certificates / PKI'       = 'Certificates'
        'Backup / DR'              = 'BackupDiscovery'
        'Security Posture'         = 'SecurityPosture'
        'Licensing'               = 'Licensing'
        'Vendor Dependencies'      = 'VendorAgents'
        'Patch / Update Posture'   = 'UpdatePosture'
        'Hybrid Identity / Cloud Attachment' = 'HybridIdentity'
        'Time Synchronization'     = 'TimeSync'
        'Mapped Drives (user context)' = 'MappedDrives'
        'User Profiles'            = 'UserProfiles'
        'Readiness Score - Subsections' = 'ReadinessScoreSubsections'
        'Dependency Graph (table)' = 'DependencyGraph'
    }
}

# Edge types with no real diagnostic value for a dependency PICTURE (as opposed to the full
# DependencyGraph table, where they still belong) - confirmed live against a real fleet run:
# 12 of 28 real edges on one host were plain Process/Service -> ListeningPort bindings, which
# clutter a diagram without showing a real cross-component dependency. Named and overridable
# rather than hardcoded inline, matching Compare-DiscoveryRuns.ps1's own
# $script:DriftExcludedDatasets precedent.
$script:DependencyDiagramExcludedTypes = @('ListeningPort')

# Loopback/link-local addresses that show up as dependency Targets (DNS, Gateway, etc.) on
# effectively every Windows host regardless of its real network config - localhost, the IPv4
# loopback, and the three hardcoded IPv6 "site-local" DNS addresses Windows has shipped by
# default since Server 2003. Confirmed live: these add rows to the diagram with zero diagnostic
# value ("what does this server actually depend on" never means its own loopback). Filtered from
# the PICTURE only - the full DependencyGraph dataset/table still lists them for anyone who wants
# the raw evidence.
$script:DependencyDiagramExcludedTargets = @('127.0.0.1', '::1', 'localhost', 'fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3')

function Get-DependencyDiagramSvg {
    <#
        Hand-rolled inline SVG, not a JS charting library - every report in this toolkit is a
        single, fully self-contained file with no external <script src>/CDN reference (see
        Get-HtmlReportCss's own comment on why: these open offline on client sites, sometimes
        air-gapped), so pulling in Mermaid.js or similar was ruled out rather than vendored.

        Lives in Output.psm1, not RiskEngine.psm1 (where the DependencyGraph dataset itself is
        built) - deliberately: Invoke-SynthesisModule unloads each synthesis module
        (Remove-Module) immediately after it runs (see Discover-WindowsServer.psm1's
        Invoke-SynthesisModule), so by the time reports are written, RiskEngine.psm1's own
        functions are already gone. Output.psm1 is imported once at the very start and never
        unloaded, so anything report-writing needs to CALL (as opposed to just read from a
        dataset RiskEngine already wrote) has to live here. Confirmed live: this exact mistake
        (defining it in RiskEngine.psm1) broke both HTML reports with a
        "Get-DependencyDiagramSvg is not recognized" error during the output smoke test.

        Layout: a plain two-column ("bipartite") diagram - distinct source entities in a left
        column, distinct target values in a right column, connecting lines. This fits the
        data's actual shape (confirmed live: many edges point at a small number of repeated
        targets) far better than a force-directed graph would, and needs no real layout
        algorithm since positions are just fixed vertical stacks - safe specifically because
        edge count is capped (below) so the two columns can never grow large enough for that
        simplicity to become illegible.

        A DependencyGraph row's Target is free text (an IP, a UNC path, literally the string
        "UNC path", a hostname) - not a resolvable node reference - so this deliberately never
        tries to chain edges into a connected multi-hop graph, only a flat source->target
        picture. That is a real, known limitation, not an oversight.

        DependencyType used to be drawn as text at each line's midpoint. On a real host with a
        few dozen edges, most lines' vertical midpoints land close enough together that the
        labels stack on top of each other into unreadable text soup (confirmed live against a
        real fleet run's LABFS01/CLAUDEWIN2025DE output - reported by the user as illegible).
        Fixed by moving DependencyType off the line entirely: each type gets a fixed color
        (shown in a legend below the diagram) and each line carries its full detail
        (type, count, confidence) as a hover <title> instead of inline text. Confidence is
        shown via line style (solid/dashed/dotted) so it doesn't need its own color axis.
        Right-column node order is chosen by a barycenter heuristic (average row of everything
        pointing at it) rather than alphabetically, which untangles most real-world crossings
        without a real graph-layout algorithm.

        Left-column labels are right-aligned so their text ends right where their line starts,
        rather than sitting at a fixed left margin with a variable, ambiguous gap before the
        line (the previous layout - confirmed live to make it unclear which label owned which
        line once labels varied much in length). The column's own width is sized to the longest
        surviving label (character-count heuristic, since SVG has no layout-time text
        measurement) instead of a fixed width, so short labels don't leave a large gap and long
        ones aren't clipped any sooner than necessary; LabelMaxChars still caps the pathological
        case, with the untruncated value always in the hover <title>.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Edges,
        [string[]]$ExcludeDependencyTypes = $script:DependencyDiagramExcludedTypes,
        [string[]]$ExcludeTargets = $script:DependencyDiagramExcludedTargets,
        [int]$MaxEdges = 40,
        [int]$RowHeight = 26,
        [int]$LabelMaxChars = 42
    )
    $esc = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }
    $truncate = {
        param($s)
        if ([string]::IsNullOrEmpty($s)) { return '' }
        if ($s.Length -gt $LabelMaxChars) { return $s.Substring(0, $LabelMaxChars - 1) + [char]0x2026 }
        return $s
    }
    $confidenceRank = @{ Confirmed = 0; Likely = 1; Possible = 2 }
    $confidenceDash = @{ Confirmed = ''; Likely = '5,3'; Possible = '2,2' }
    # Fixed, deterministic qualitative palette assigned to DependencyType in first-seen order
    # (cycled if there are more distinct types than colors) - same type always gets the same
    # color within one diagram render.
    $palette = @('#2E6E8E', '#B0562F', '#4A7C4E', '#8B4B8B', '#B08A2E', '#4A5B79', '#A8433A', '#3E8E82')

    $all = @(if ($null -eq $Edges) { @() } else { @($Edges) })
    $filtered = @($all | Where-Object {
        ($ExcludeDependencyTypes -notcontains [string]$_.DependencyType) -and
        ($ExcludeTargets -notcontains ([string]$_.Target).Trim())
    })
    if ($filtered.Count -eq 0) { return $null }

    # Dedup identical SourceType|SourceName|DependencyType|Target quadruples (a collector often
    # emits the same edge shape once per item - e.g. one UsesPath edge per scheduled task that
    # happens to reference the same share), tracking how many raw edges collapsed into each one
    # so the rendered label can say "(x3)" instead of drawing three overlapping lines.
    $groups = [ordered]@{}
    foreach ($e in $filtered) {
        $key = '{0}|{1}|{2}|{3}' -f [string]$e.SourceType, [string]$e.SourceName, [string]$e.DependencyType, [string]$e.Target
        if ($groups.Contains($key)) { $groups[$key].Count++ }
        else {
            $groups[$key] = [pscustomobject]@{
                SourceType = [string]$e.SourceType; SourceName = [string]$e.SourceName
                DependencyType = [string]$e.DependencyType; Target = [string]$e.Target
                Confidence = [string]$e.Confidence; Count = 1
            }
        }
    }
    $deduped = @($groups.Values)

    # Most-confirmed-first, so a hard cap on edge count keeps the most trustworthy ones.
    $sorted = @($deduped | Sort-Object -Property @{ Expression = { if ($confidenceRank.ContainsKey($_.Confidence)) { $confidenceRank[$_.Confidence] } else { 3 } } }, SourceName)
    $overflowCount = [Math]::Max(0, $sorted.Count - $MaxEdges)
    $rendered = @($sorted | Select-Object -First $MaxEdges)
    if ($rendered.Count -eq 0) { return $null }

    $typeColor = @{}
    foreach ($r in $rendered) {
        if (-not $typeColor.ContainsKey($r.DependencyType)) {
            $typeColor[$r.DependencyType] = $palette[$typeColor.Count % $palette.Count]
        }
    }

    $leftNodes = @($rendered | ForEach-Object { "$($_.SourceType): $($_.SourceName)" } | Sort-Object -Unique)
    $leftIndex = @{}; for ($i = 0; $i -lt $leftNodes.Count; $i++) { $leftIndex[$leftNodes[$i]] = $i }

    # Order right nodes by the average row of everything that points at them (a barycenter
    # heuristic), not alphabetically - alphabetical order ignores which rows actually connect,
    # so unrelated nodes land next to each other and nearly every line ends up crossing every
    # other one. This one pass untangles the common case without a real graph-layout library.
    $rightBarycenter = @{}; $rightCounts = @{}
    foreach ($r in $rendered) {
        $li = $leftIndex["$($r.SourceType): $($r.SourceName)"]
        if (-not $rightBarycenter.ContainsKey($r.Target)) { $rightBarycenter[$r.Target] = 0.0; $rightCounts[$r.Target] = 0 }
        $rightBarycenter[$r.Target] += $li
        $rightCounts[$r.Target]++
    }
    $rightNodes = @($rightBarycenter.Keys | Sort-Object -Property @{ Expression = { $rightBarycenter[$_] / $rightCounts[$_] } }, @{ Expression = { $_ } })
    $rightIndex = @{}; for ($i = 0; $i -lt $rightNodes.Count; $i++) { $rightIndex[$rightNodes[$i]] = $i }

    # Column widths are sized to their longest surviving (truncated) label instead of a fixed
    # width - SVG has no layout-time text measurement, so this is a character-count heuristic
    # (~6.3px/char at 12px Segoe UI), not exact, but close enough that the line always starts/ends
    # right next to its own label instead of floating in a fixed-width column with an ambiguous
    # gap for short labels.
    $charWidth = 6.3
    $leftLabel = @{}; foreach ($n in $leftNodes) { $leftLabel[$n] = & $truncate $n }
    $rightLabel = @{}; foreach ($n in $rightNodes) { $rightLabel[$n] = & $truncate $n }
    $maxLeftChars = ($leftLabel.Values | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $maxRightChars = ($rightLabel.Values | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum

    $topMargin = 40
    $maxRows = [Math]::Max($leftNodes.Count, $rightNodes.Count)
    $leftMargin = 12
    $lineSpan = 220
    $lineStartX = $leftMargin + [Math]::Ceiling($maxLeftChars * $charWidth) + 14
    $lineEndX = $lineStartX + $lineSpan
    $rightTextX = $lineEndX + 10
    $width = $rightTextX + [Math]::Ceiling($maxRightChars * $charWidth) + 20
    $legendTypes = @($typeColor.Keys | Sort-Object)
    $legendCols = [Math]::Max(1, [Math]::Min(4, [Math]::Floor($width / 180)))
    $legendRows = [Math]::Ceiling($legendTypes.Count / $legendCols)
    $legendHeight = 22 + ($legendRows * 18)
    $height = $topMargin + ($RowHeight * $maxRows) + 30 + $legendHeight
    $leftTextX = $lineStartX - 8

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<svg viewBox=`"0 0 $width $height`" xmlns=`"http://www.w3.org/2000/svg`" font-family=`"Segoe UI,Calibri,Arial,sans-serif`" font-size=`"12`">")
    foreach ($r in $rendered) {
        $leftKey = "$($r.SourceType): $($r.SourceName)"
        $y1 = $topMargin + ($leftIndex[$leftKey] * $RowHeight) + [Math]::Round($RowHeight / 2)
        $y2 = $topMargin + ($rightIndex[$r.Target] * $RowHeight) + [Math]::Round($RowHeight / 2)
        $color = $typeColor[$r.DependencyType]
        $dash = if ($confidenceDash.ContainsKey($r.Confidence)) { $confidenceDash[$r.Confidence] } else { '' }
        $dashAttr = if ($dash) { " stroke-dasharray=`"$dash`"" } else { '' }
        $titleText = $r.DependencyType
        if ($r.Count -gt 1) { $titleText = "$titleText (x$($r.Count))" }
        if ($r.Confidence) { $titleText = "$titleText - $($r.Confidence)" }
        [void]$sb.Append("<line class=`"dep-edge`" x1=`"$lineStartX`" y1=`"$y1`" x2=`"$lineEndX`" y2=`"$y2`" stroke=`"$color`" stroke-width=`"1.5`" opacity=`"0.8`"$dashAttr><title>$(& $esc $titleText)</title></line>")
    }
    foreach ($n in $leftNodes) {
        $y = $topMargin + ($leftIndex[$n] * $RowHeight) + [Math]::Round($RowHeight / 2) + 4
        [void]$sb.Append("<text x=`"$leftTextX`" y=`"$y`" text-anchor=`"end`" fill=`"#1A1F27`">$(& $esc $leftLabel[$n])<title>$(& $esc $n)</title></text>")
    }
    foreach ($n in $rightNodes) {
        $y = $topMargin + ($rightIndex[$n] * $RowHeight) + [Math]::Round($RowHeight / 2) + 4
        [void]$sb.Append("<text x=`"$rightTextX`" y=`"$y`" fill=`"#1A1F27`">$(& $esc $rightLabel[$n])<title>$(& $esc $n)</title></text>")
    }
    if ($overflowCount -gt 0) {
        $noteY = $topMargin + ($RowHeight * $maxRows) + 16
        [void]$sb.Append("<text x=`"$leftMargin`" y=`"$noteY`" fill=`"#5B6472`" font-style=`"italic`" font-size=`"11`">+$overflowCount more edge(s) not shown - see the DependencyGraph dataset for the full list.</text>")
    }

    # Legend: color -> DependencyType. Confidence is called out once here via line style
    # (solid/dashed/dotted) instead of needing its own row of colors, and hovering any line
    # still shows its full type/count/confidence via <title>.
    $legendY = $height - $legendHeight + 8
    [void]$sb.Append("<text x=`"$leftMargin`" y=`"$legendY`" fill=`"#5B6472`" font-size=`"11`" font-weight=`"600`">Dependency type (line style: solid = Confirmed, dashed = Likely, dotted = Possible)</text>")
    $legendColWidth = [Math]::Floor($width / $legendCols)
    for ($i = 0; $i -lt $legendTypes.Count; $i++) {
        $type = $legendTypes[$i]
        $col = $i % $legendCols
        $row = [Math]::Floor($i / $legendCols)
        $swX = $leftMargin + ($col * $legendColWidth)
        $swY = $legendY + 14 + ($row * 18)
        [void]$sb.Append("<line x1=`"$swX`" y1=`"$($swY - 4)`" x2=`"$($swX + 24)`" y2=`"$($swY - 4)`" stroke=`"$($typeColor[$type])`" stroke-width=`"3`" />")
        [void]$sb.Append("<text x=`"$($swX + 30)`" y=`"$swY`" fill=`"#1A1F27`" font-size=`"11`">$(& $esc (& $truncate $type))</text>")
    }
    [void]$sb.Append('</svg>')
    return $sb.ToString()
}

function Get-InternalReportModel {
    <#
        Single source of truth for what the internal report contains, computed once so the
        printable engineering report and the Command Center dashboard can never show different
        data for the same run.
    #>
    param([Parameter(Mandatory)][object]$Context)

    $sevOrder = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3; 'Info'=4 }
    # Emphasised findings (those a rule flags for the active -ProjectType) lead their severity
    # band. Emphasis changes ORDER and VISIBILITY only - never Severity itself.
    $findings = @($Context.Findings) | Sort-Object `
        @{ Expression = { if ($_.IsEmphasized) { 0 } else { 1 } } }, `
        @{ Expression = { $sevOrder[$_.Severity] } }, Category
    $counts = @{}
    foreach ($s in @('Critical','High','Medium','Low','Info')) { $counts[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }

    $impacts = @('Labor','Licensing','Downtime','Vendor Dependency','Security/Compliance','Data Migration','Cutover Complexity','Client Coordination','Architecture Decision','Rollback Planning')
    $impactRows = foreach ($imp in $impacts) {
        $matched = @($findings | Where-Object { @($_.PotentialProjectImpact) -contains $imp })
        if ($matched.Count -eq 0) { continue }
        $examples = (($matched | Select-Object -First 4 | ForEach-Object { $_.Title }) -join '; ')
        [pscustomobject]@{ ProjectImpact = $imp; FindingCount = $matched.Count; ExampleFindings = $examples }
    }

    $sectionMap = Get-InternalReportSectionMap
    $sections = foreach ($h in $sectionMap.Keys) {
        $dsName = $sectionMap[$h]
        if ($Context.DataSets.Contains($dsName) -and @($Context.DataSets[$dsName].Rows).Count -gt 0) {
            [pscustomobject]@{ Title = $h; Dataset = $dsName; Rows = $Context.DataSets[$dsName].Rows }
        }
    }

    $dsRows = foreach ($k in $Context.DataSets.Keys) {
        $d = $Context.DataSets[$k]
        [pscustomobject]@{ Dataset = $d.Name; Rows = $d.RowCount; Visibility = $d.Visibility; Source = $d.SourceModule; Description = $d.Description }
    }

    $readiness = $null
    if ($Context.DataSets.Contains('ReadinessScore') -and @($Context.DataSets['ReadinessScore'].Rows).Count -gt 0) {
        $readiness = @($Context.DataSets['ReadinessScore'].Rows)[0]
    }
    $dependencyDiagramSvg = $null
    if ($Context.DataSets.Contains('DependencyGraph')) {
        $dependencyDiagramSvg = Get-DependencyDiagramSvg -Edges @($Context.DataSets['DependencyGraph'].Rows)
    }

    [pscustomobject]@{
        Findings            = @($findings)
        Counts              = $counts
        Emphasized          = @($findings | Where-Object { $_.IsEmphasized })
        Functions           = @(Get-LikelyServerFunctions -Context $Context)
        ImpactRows          = @($impactRows)
        Sections            = @($sections)
        DatasetIndex        = @($dsRows)
        Readiness           = $readiness
        DependencyDiagramSvg = $dependencyDiagramSvg
    }
}

function Write-HtmlReport {
    <# Writes the static, fully-expanded internal engineering HTML report - reads start to
       finish like a printed document. See Write-DashboardHtmlReport for the interactive,
       sidebar-navigated companion covering the same model. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$Path)
    $enc = { param($v) [System.Net.WebUtility]::HtmlEncode((ConvertTo-DisplayString -Value $v)) }
    $model = Get-InternalReportModel -Context $Context
    $findings = $model.Findings
    $counts = $model.Counts

    $b = Get-DiscoveryBranding -Context $Context
    $title = $b.Title
    $brand = $b.Brand
    $accent = $b.Accent
    $logoHtml = if ($b.LogoDataUri) { '<img src="{0}" alt="{1}" class="brand-logo">' -f $b.LogoDataUri, (& $enc $b.Brand) } else { '' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>{0}</title>' -f (& $enc $title)))
    [void]$sb.AppendLine(('<style>{0}</style></head><body>' -f (Get-HtmlReportCss -AccentColorHex $accent)))
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine($logoHtml)
    [void]$sb.AppendLine(('<h1>{0}</h1>' -f (& $enc $title)))
    [void]$sb.AppendLine(('<div class="sub">{0} &middot; {1} &middot; Generated {2}</div>' -f (& $enc $brand), (& $enc $Context.ComputerName), (& $enc (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))))
    [void]$sb.AppendLine('</header><main>')

    # Executive summary + KPIs
    [void]$sb.AppendLine('<h2>Executive Technical Summary</h2>')
    [void]$sb.AppendLine('<div class="kpis">')
    [void]$sb.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Findings</div></div>' -f $findings.Count))
    [void]$sb.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Critical/High</div></div>' -f ($counts['Critical'] + $counts['High'])))
    [void]$sb.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Datasets</div></div>' -f $Context.DataSets.Count))
    [void]$sb.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Unknowns</div></div>' -f $Context.Unknowns.Count))
    [void]$sb.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Limitations</div></div>' -f $Context.Limitations.Count))
    if ($model.Readiness) {
        [void]$sb.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Readiness ({1})</div></div>' -f (& $enc $model.Readiness.Grade), (& $enc $model.Readiness.Label)))
    }
    [void]$sb.AppendLine('</div>')
    if ($model.Readiness) {
        [void]$sb.AppendLine(('<p class="muted">Readiness score {0}/100 - {1} <em>{2}</em></p>' -f $model.Readiness.Score, (& $enc $model.Readiness.Description), (& $enc $model.Readiness.Caveat)))
    }

    # Project-type priority section - the visible payoff of -ProjectType.
    $emphasized = $model.Emphasized
    [void]$sb.AppendLine(('<h2>Priority For This Project Type ({0})</h2>' -f (& $enc $Context.ProjectType)))
    if ($emphasized.Count -gt 0) {
        [void]$sb.AppendLine(('<p class="muted">{0} finding(s) are flagged as especially relevant to a <b>{1}</b> project. Severity is unchanged - this is prioritisation, not escalation.</p>' -f $emphasized.Count, (& $enc $Context.ProjectType)))
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $emphasized -Columns @('FindingId','Severity','Category','Title','Subject','Evidence')))
    } elseif ($Context.ProjectType -eq 'GeneralDiscovery') {
        [void]$sb.AppendLine('<p class="muted">General discovery uses no project-type lens, so no findings are prioritised. Re-run with a specific <code>-ProjectType</code> to surface the findings that matter most for that kind of project.</p>')
    } else {
        [void]$sb.AppendLine(('<p class="muted">No findings carried a project-type emphasis for <b>{0}</b>.</p>' -f (& $enc $Context.ProjectType)))
    }

    # Run metadata
    [void]$sb.AppendLine('<h2>Discovery Run Metadata</h2><div class="meta">')
    [void]$sb.AppendLine(('<div><b>Run ID:</b> {0}</div>' -f (& $enc $Context.RunId)))
    [void]$sb.AppendLine(('<div><b>Mode:</b> {0}</div>' -f (& $enc $Context.Mode)))
    [void]$sb.AppendLine(('<div><b>Project type:</b> {0}</div>' -f (& $enc $Context.ProjectType)))
    [void]$sb.AppendLine(('<div><b>Compliance lens:</b> {0}</div>' -f (& $enc $Context.ComplianceLens)))
    [void]$sb.AppendLine(('<div><b>Elevated:</b> {0}</div>' -f (& $enc $Context.IsAdmin)))
    [void]$sb.AppendLine(('<div><b>As SYSTEM:</b> {0}</div>' -f (& $enc $Context.IsSystem)))
    [void]$sb.AppendLine(('<div><b>PowerShell:</b> {0}</div>' -f (& $enc $Context.PowerShellVersion)))
    [void]$sb.AppendLine('</div>')

    # Likely server functions
    [void]$sb.AppendLine('<h2>Likely Server Functions</h2>')
    $functions = $model.Functions
    if ($functions.Count -gt 0) {
        [void]$sb.AppendLine('<ul>')
        foreach ($f in $functions) { [void]$sb.AppendLine(('<li>{0}</li>' -f (& $enc $f))) }
        [void]$sb.AppendLine('</ul>')
    } else { [void]$sb.AppendLine('<p class="muted">No definitive server functions were detected from the collected data.</p>') }

    # Findings by severity
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $group = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($group.Count -eq 0) { continue }
        [void]$sb.AppendLine(('<h2>{0}-Severity Findings ({1})</h2>' -f $sev, $group.Count))
        foreach ($f in $group) {
            $cardClass = if ($f.IsEmphasized) { 'card sev-{0} emph-card' -f $f.Severity } else { 'card sev-{0}' -f $f.Severity }
            [void]$sb.AppendLine(('<div class="{0}">' -f $cardClass))
            $emphBadge = ''
            if ($f.IsEmphasized) { $emphBadge = ' <span class="badge emph">PRIORITY</span>' }
            [void]$sb.AppendLine(('<div><span class="badge sevbadge">{0}</span>{5} <b>{1}</b> <span class="muted">[{2}] {3} &middot; {4}</span></div>' -f $f.Severity, (& $enc $f.Title), (& $enc $f.FindingId), (& $enc $f.Category), (& $enc $f.Confidence), $emphBadge))
            if ($f.Subject) { [void]$sb.AppendLine(('<div><b>Subject:</b> {0}</div>' -f (& $enc $f.Subject))) }
            if ($f.EmphasisReason) { [void]$sb.AppendLine(('<div class="muted">{0}</div>' -f (& $enc $f.EmphasisReason))) }
            if ($f.Evidence) { [void]$sb.AppendLine(('<div><b>Evidence:</b> {0} <span class="muted">({1})</span></div>' -f (& $enc $f.Evidence), (& $enc $f.EvidenceSource))) }
            if ($f.WhyItMattersForScoping) { [void]$sb.AppendLine(('<div><b>Why it matters:</b> {0}</div>' -f (& $enc $f.WhyItMattersForScoping))) }
            if (@($f.PotentialProjectImpact).Count -gt 0) { [void]$sb.AppendLine(('<div><b>Project impact:</b> {0}</div>' -f (& $enc $f.PotentialProjectImpact))) }
            if ($f.SuggestedValidationQuestion) { [void]$sb.AppendLine(('<div><b>Validation question:</b> {0}</div>' -f (& $enc $f.SuggestedValidationQuestion))) }
            if (@($f.ComplianceRelevance).Count -gt 0) { [void]$sb.AppendLine(('<div><b>Compliance relevance:</b> {0}</div>' -f (& $enc $f.ComplianceRelevance))) }
            [void]$sb.AppendLine('</div>')
        }
    }

    # Findings by project impact
    [void]$sb.AppendLine('<h2>Findings by Project Impact</h2>')
    $impactRows = $model.ImpactRows
    if (@($impactRows).Count -gt 0) { [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $impactRows -Columns @('ProjectImpact','FindingCount','ExampleFindings'))) }
    else { [void]$sb.AppendLine('<p class="muted">No project-impact-tagged findings.</p>') }

    # Dependency diagram - a rendering of the DependencyGraph dataset (see the "Dependency Graph
    # (table)" section further down for the full row-level data), not a validated architecture
    # diagram: Target is free text, so this cannot reliably chain edges across servers or resolve
    # a target to another node - it only shows what each source directly references.
    [void]$sb.AppendLine('<h2>Dependency Diagram</h2>')
    if ($model.DependencyDiagramSvg) {
        [void]$sb.AppendLine('<p class="muted">Source components on the left, the things they reference on the right. Line color is dependency type (see legend); line style is confidence (solid/dashed/dotted). Hover a line for its full detail. This is a picture of the DependencyGraph dataset below, not a validated architecture diagram.</p>')
        [void]$sb.AppendLine(('<div class="dep-diagram">{0}</div>' -f $model.DependencyDiagramSvg))
    } else {
        [void]$sb.AppendLine('<p class="muted">No dependency edges were recorded for this run.</p>')
    }

    # Unknowns that matter
    [void]$sb.AppendLine('<h2>Unknowns That Matter</h2>')
    if (@($Context.Unknowns).Count -gt 0) {
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Context.Unknowns -Columns @('Unknown','WhyItMatters','Evidence','RecommendedValidationQuestion')))
    } else { [void]$sb.AppendLine('<p class="muted">No unknowns recorded.</p>') }

    # Named-dataset sections (Decommission Readiness, Security Posture, ...)
    foreach ($section in $model.Sections) {
        [void]$sb.AppendLine(('<h2>{0}</h2>' -f (& $enc $section.Title)))
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $section.Rows))
    }

    # Client validation questions
    [void]$sb.AppendLine('<h2>Client Validation Questions</h2>')
    if (@($Context.FollowUpQuestions).Count -gt 0) {
        [void]$sb.AppendLine('<ul class="q">')
        foreach ($q in $Context.FollowUpQuestions) { [void]$sb.AppendLine(('<li>[{0}] {1}</li>' -f (& $enc $q.Category), (& $enc $q.Question))) }
        [void]$sb.AppendLine('</ul>')
    } else { [void]$sb.AppendLine('<p class="muted">No follow-up questions were generated.</p>') }

    # Draft scope language
    [void]$sb.AppendLine('<h2>Draft Scope Language</h2><p class="muted">DRAFT - requires review before use in any statement of work.</p>')
    if (@($Context.ScopeLanguage).Count -gt 0) {
        [void]$sb.AppendLine('<ul>')
        foreach ($s in $Context.ScopeLanguage) { [void]$sb.AppendLine(('<li><b>{0}:</b> {1}</li>' -f (& $enc $s.Type), (& $enc $s.Text))) }
        [void]$sb.AppendLine('</ul>')
    } else { [void]$sb.AppendLine('<p class="muted">No draft scope language was generated.</p>') }

    # Dataset index
    [void]$sb.AppendLine('<h2>Dataset Index</h2>')
    $dsRows = $model.DatasetIndex
    if (@($dsRows).Count -gt 0) { [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $dsRows)) } else { [void]$sb.AppendLine('<p class="muted">No datasets.</p>') }

    # Limitations
    [void]$sb.AppendLine('<h2>Limitations</h2>')
    if (@($Context.Limitations).Count -gt 0) {
        [void]$sb.AppendLine((ConvertTo-HtmlTable -Rows $Context.Limitations -Columns @('Module','Message','Impact','Reason')))
    } else { [void]$sb.AppendLine('<p class="muted">No limitations recorded.</p>') }

    [void]$sb.AppendLine('</main><footer>')
    [void]$sb.AppendLine(('Generated by the Ultimate Modular Windows Server Discovery Toolkit on {0}. Read-only discovery. Findings are indicators for scoping and require human validation. No compliance certification is asserted.' -f (& $enc (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))))
    [void]$sb.AppendLine('</footer></body></html>')

    try { $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force; return $true }
    catch { Write-Warning ("Write-HtmlReport failed: {0}" -f $_.Exception.Message); return $false }
}

function Get-DashboardReportCss {
    <#
        Command Center layout: a fixed sidebar nav plus per-section panes swapped by a few
        lines of vanilla JS (no framework - this file has to open standalone, sometimes
        offline). Every table sits inside a fixed-height scroll box with a sticky header row
        and a text filter, instead of the page itself growing to hundreds of rows tall.
    #>
    [CmdletBinding()] param([string]$AccentColorHex = '#1F4E79')
    if ([string]::IsNullOrWhiteSpace($AccentColorHex)) { $AccentColorHex = '#1F4E79' }
    $css = @'
:root{--accent:__ACCENT__;--accent-bg:#EAF1F8;--accent-text:#123350;--bg:#ffffff;--surface:#F5F6F8;--surface-2:#ECEEF1;--fg:#1A1F27;--muted:#5B6472;--line:#DFE3E8;--line-strong:#C6CCD4;
--critical:#B42318;--critical-bg:#FBEAE9;--critical-text:#7A160E;--high:#B54708;--high-bg:#FDF1E7;--high-text:#7A2F05;--medium:#4A5B79;--medium-bg:#EBEEF4;--medium-text:#333F54;--low:#5B6472;--low-bg:#EEF0F3}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;font-family:Segoe UI,Calibri,Arial,sans-serif;color:var(--fg);background:var(--bg);font-size:14px}
.shell{display:grid;grid-template-columns:230px 1fr;height:100vh}
.side{background:var(--surface);border-right:1px solid var(--line);padding:16px 10px;overflow-y:auto}
.side h1{font-size:14px;font-weight:600;margin:2px 8px 2px;color:var(--accent)}
.side .brand-logo{max-height:28px;display:block;margin:2px 8px 8px}
.side .sub{font-size:11px;color:var(--muted);margin:0 8px 14px}
.side .grp{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:14px 8px 6px}
.side a{display:flex;justify-content:space-between;gap:6px;padding:7px 8px;border-radius:6px;color:#333;text-decoration:none;font-size:13px;cursor:pointer}
.side a:hover{background:var(--surface-2)}
.side a.sel{background:var(--accent-bg);color:var(--accent-text);font-weight:600}
.side a .n{font-size:11px;color:var(--muted)}
.side a.sel .n{color:var(--accent-text)}
.main{padding:20px 26px;overflow-y:auto}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.kpi{background:var(--surface);border-radius:8px;padding:12px 14px;text-align:center}
.kpi .n{font-size:22px;font-weight:700;color:var(--accent);word-break:break-word}
.kpi .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-top:2px}
.dep-diagram{overflow-x:auto;border:1px solid var(--line);border-radius:8px;padding:8px;background:#fff}
.pane{display:none}
.pane.active{display:block}
.pane h2{font-size:17px;margin:0 0 4px;color:var(--accent)}
.pane .pd{font-size:12.5px;color:var(--muted);margin:0 0 12px}
.filterrow{margin-bottom:8px}
.filterrow input{width:100%;max-width:360px;font-family:inherit;font-size:13px;padding:7px 10px;border:1px solid var(--line-strong);border-radius:6px;background:#fff;color:var(--fg)}
.tablebox{border:1px solid var(--line);border-radius:8px;max-height:60vh;overflow:auto}
table{border-collapse:collapse;width:100%;font-size:12.5px}
thead th{position:sticky;top:0;background:var(--surface);text-align:left;padding:8px 10px;font-weight:600;border-bottom:1px solid var(--line)}
tbody td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr.hide{display:none}
.card{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:0 8px 8px 0;padding:10px 14px;margin:8px 0;background:#fff}
.card.sev-Critical{border-left-color:var(--critical);background:var(--critical-bg)}
.card.sev-High{border-left-color:var(--high);background:var(--high-bg)}
.card.sev-Medium{border-left-color:var(--medium);background:var(--medium-bg)}
.card.sev-Low,.card.sev-Info{border-left-color:var(--low);background:var(--low-bg)}
.badge{display:inline-block;padding:2px 9px;border-radius:100px;font-size:11px;font-weight:600}
.sev-Critical .badge.sevbadge{background:var(--critical);color:#fff}
.sev-High .badge.sevbadge{background:var(--high);color:#fff}
.sev-Medium .badge.sevbadge{background:var(--medium);color:#fff}
.sev-Low .badge.sevbadge,.sev-Info .badge.sevbadge{background:var(--low);color:#fff}
.badge.emph{background:#6A3E9E;color:#fff}
.muted{color:var(--muted);font-size:12px}
code{background:var(--surface);padding:1px 4px;border-radius:3px;font-size:12px;font-family:Consolas,"Cascadia Code",monospace}
ul.q li{margin:6px 0}
@media (max-width:820px){.shell{grid-template-columns:1fr}.side{display:none}}
'@
    return ($css -replace '__ACCENT__', $AccentColorHex)
}

function Write-DashboardHtmlReport {
    <#
        Writes the interactive Command Center companion to Write-HtmlReport: same content
        model (Get-InternalReportModel), a sidebar nav in place of one long scroll, and each
        table in its own scrollable/filterable box. Meant for reference use on screen; use the
        plain internal-engineering-report.html for printing or reading straight through.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$Path)
    $enc = { param($v) [System.Net.WebUtility]::HtmlEncode((ConvertTo-DisplayString -Value $v)) }
    $model = Get-InternalReportModel -Context $Context
    $findings = $model.Findings
    $counts = $model.Counts

    $b = Get-DiscoveryBranding -Context $Context
    $title = $b.Title
    $brand = $b.Brand
    $accent = $b.Accent
    $logoHtml = if ($b.LogoDataUri) { '<img src="{0}" alt="{1}" class="brand-logo">' -f $b.LogoDataUri, (& $enc $b.Brand) } else { '' }

    # Every nav-able section gets a stable, unique pane id: kebab-cased title plus an index so
    # two sections that happen to share a display name (shouldn't, but datasets are config-
    # driven) never collide.
    $slug = { param($s, $i) (($s.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')) + '-' + $i }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>{0} - Dashboard</title>' -f (& $enc $title)))
    [void]$sb.AppendLine(('<style>{0}</style></head><body>' -f (Get-DashboardReportCss -AccentColorHex $accent)))
    [void]$sb.AppendLine('<div class="shell"><nav class="side">')
    [void]$sb.AppendLine(('{0}<h1>{1}</h1><div class="sub">{2} &middot; {3}</div>' -f $logoHtml, (& $enc $brand), (& $enc $Context.ComputerName), (& $enc (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))))

    # Build nav + panes together so a section can never appear in one but not the other.
    # navIndex is a [ref] (a reference type), not a plain int, because $addNavAndPane runs via
    # `&` - that gives it its own child scope, so a plain int assignment inside it would rebind
    # a NEW local rather than mutate this one. $script:-scoping it instead would leak across
    # calls (module-level state surviving into the next report this same process renders).
    $panes = New-Object System.Text.StringBuilder
    $navIndex = [ref]0
    $addNavAndPane = {
        param([string]$Group, [string]$Label, [string]$CountText, [string]$BodyHtml, [bool]$First = $false)
        $navIndex.Value++
        $id = & $slug $Label $navIndex.Value
        $selClass = if ($First) { ' sel' } else { '' }
        $activeClass = if ($First) { ' active' } else { '' }
        [void]$sb.AppendLine(('<a class="navlink{0}" data-pane="p-{1}">{2} <span class="n">{3}</span></a>' -f $selClass, $id, (& $enc $Label), (& $enc $CountText)))
        [void]$panes.AppendLine(('<div class="pane{0}" id="p-{1}">{2}</div>' -f $activeClass, $id, $BodyHtml))
    }

    [void]$sb.AppendLine('<div class="grp">Overview</div>')
    $overviewBody = New-Object System.Text.StringBuilder
    [void]$overviewBody.AppendLine('<div class="kpis">')
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Findings</div></div>' -f $findings.Count))
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Critical/High</div></div>' -f ($counts['Critical'] + $counts['High'])))
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Datasets</div></div>' -f $Context.DataSets.Count))
    [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Unknowns</div></div>' -f $Context.Unknowns.Count))
    if ($model.Readiness) {
        [void]$overviewBody.AppendLine(('<div class="kpi"><div class="n">{0}</div><div class="l">Readiness ({1})</div></div>' -f (& $enc $model.Readiness.Grade), (& $enc $model.Readiness.Label)))
    }
    [void]$overviewBody.AppendLine('</div>')
    if ($model.Readiness) {
        [void]$overviewBody.AppendLine(('<p class="pd">Readiness score {0}/100 - {1}</p>' -f $model.Readiness.Score, (& $enc $model.Readiness.Description)))
    }
    [void]$overviewBody.AppendLine('<h2>Discovery run metadata</h2>')
    [void]$overviewBody.AppendLine(('<p class="pd">Mode {0} &middot; project type {1} &middot; compliance lens {2} &middot; elevated {3} &middot; SYSTEM {4} &middot; PowerShell {5}</p>' -f (& $enc $Context.Mode), (& $enc $Context.ProjectType), (& $enc $Context.ComplianceLens), (& $enc $Context.IsAdmin), (& $enc $Context.IsSystem), (& $enc $Context.PowerShellVersion)))
    [void]$overviewBody.AppendLine('<h2>Likely server functions</h2>')
    if ($model.Functions.Count -gt 0) {
        [void]$overviewBody.AppendLine('<ul>')
        foreach ($f in $model.Functions) { [void]$overviewBody.AppendLine(('<li>{0}</li>' -f (& $enc $f))) }
        [void]$overviewBody.AppendLine('</ul>')
    } else { [void]$overviewBody.AppendLine('<p class="muted">No definitive server functions were detected from the collected data.</p>') }
    if ($model.Emphasized.Count -gt 0) {
        [void]$overviewBody.AppendLine(('<h2>Priority for {0}</h2>' -f (& $enc $Context.ProjectType)))
        [void]$overviewBody.AppendLine('<div class="tablebox">')
        [void]$overviewBody.AppendLine((ConvertTo-HtmlTable -Rows $model.Emphasized -Columns @('FindingId','Severity','Category','Title','Subject','Evidence')))
        [void]$overviewBody.AppendLine('</div>')
    }
    & $addNavAndPane 'Overview' 'Summary' '' $overviewBody.ToString() $true

    if ($model.DependencyDiagramSvg) {
        $diagramBody = "<h2>Dependency Diagram</h2><p class=`"pd`">Source components on the left, the things they reference on the right. Line color is dependency type (see legend); line style is confidence (solid/dashed/dotted). Hover a line for its full detail. This is a picture of the DependencyGraph dataset (see Datasets below), not a validated architecture diagram.</p><div class=`"dep-diagram`">$($model.DependencyDiagramSvg)</div>"
        & $addNavAndPane 'Overview' 'Dependency Diagram' '' $diagramBody
    }

    [void]$sb.AppendLine('<div class="grp">Findings</div>')
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $group = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($group.Count -eq 0) { continue }
        $body = New-Object System.Text.StringBuilder
        [void]$body.AppendLine(('<h2>{0}-severity findings</h2>' -f $sev))
        [void]$body.AppendLine(('<p class="pd">{0} finding(s).</p>' -f $group.Count))
        foreach ($f in $group) {
            $cardClass = if ($f.IsEmphasized) { 'card sev-{0}' -f $f.Severity } else { 'card sev-{0}' -f $f.Severity }
            [void]$body.AppendLine(('<div class="{0}">' -f $cardClass))
            $emphBadge = ''
            if ($f.IsEmphasized) { $emphBadge = ' <span class="badge emph">PRIORITY</span>' }
            [void]$body.AppendLine(('<div><span class="badge sevbadge">{0}</span>{5} <b>{1}</b> <span class="muted">[{2}] {3} &middot; {4}</span></div>' -f $f.Severity, (& $enc $f.Title), (& $enc $f.FindingId), (& $enc $f.Category), (& $enc $f.Confidence), $emphBadge))
            if ($f.Subject) { [void]$body.AppendLine(('<div><b>Subject:</b> {0}</div>' -f (& $enc $f.Subject))) }
            if ($f.EmphasisReason) { [void]$body.AppendLine(('<div class="muted">{0}</div>' -f (& $enc $f.EmphasisReason))) }
            if ($f.Evidence) { [void]$body.AppendLine(('<div><b>Evidence:</b> {0} <span class="muted">({1})</span></div>' -f (& $enc $f.Evidence), (& $enc $f.EvidenceSource))) }
            if ($f.WhyItMattersForScoping) { [void]$body.AppendLine(('<div><b>Why it matters:</b> {0}</div>' -f (& $enc $f.WhyItMattersForScoping))) }
            if ($f.SuggestedValidationQuestion) { [void]$body.AppendLine(('<div><b>Validation question:</b> {0}</div>' -f (& $enc $f.SuggestedValidationQuestion))) }
            [void]$body.AppendLine('</div>')
        }
        & $addNavAndPane 'Findings' "$sev severity" ([string]$group.Count) $body.ToString()
    }
    if (@($model.ImpactRows).Count -gt 0) {
        $body = '<h2>Findings by project impact</h2>' + (ConvertTo-HtmlTable -Rows $model.ImpactRows -Columns @('ProjectImpact','FindingCount','ExampleFindings'))
        & $addNavAndPane 'Findings' 'By project impact' ([string]@($model.ImpactRows).Count) ('<div class="tablebox">{0}</div>' -f $body)
    }

    if (@($Context.Unknowns).Count -gt 0) {
        [void]$sb.AppendLine('<div class="grp">Other</div>')
        $body = '<h2>Unknowns that matter</h2>' + (ConvertTo-HtmlTable -Rows $Context.Unknowns -Columns @('Unknown','WhyItMatters','Evidence','RecommendedValidationQuestion'))
        & $addNavAndPane 'Other' 'Unknowns' ([string]@($Context.Unknowns).Count) ('<div class="tablebox">{0}</div>' -f $body)
    }

    if ($model.Sections.Count -gt 0) {
        [void]$sb.AppendLine('<div class="grp">Datasets</div>')
        foreach ($section in $model.Sections) {
            $rowCount = @($section.Rows).Count
            $body = "<h2>$(& $enc $section.Title)</h2>" + '<div class="filterrow"><input type="text" placeholder="Filter rows..." data-filtertarget="1"></div><div class="tablebox">' + (ConvertTo-HtmlTable -Rows $section.Rows) + '</div>'
            & $addNavAndPane 'Datasets' $section.Title ([string]$rowCount) $body
        }
    }

    [void]$sb.AppendLine('<div class="grp">Reference</div>')
    if (@($Context.FollowUpQuestions).Count -gt 0) {
        $qbody = New-Object System.Text.StringBuilder
        [void]$qbody.AppendLine('<h2>Client validation questions</h2><ul class="q">')
        foreach ($q in $Context.FollowUpQuestions) { [void]$qbody.AppendLine(('<li>[{0}] {1}</li>' -f (& $enc $q.Category), (& $enc $q.Question))) }
        [void]$qbody.AppendLine('</ul>')
        & $addNavAndPane 'Reference' 'Questions' ([string]@($Context.FollowUpQuestions).Count) $qbody.ToString()
    }
    if (@($Context.ScopeLanguage).Count -gt 0) {
        $scbody = New-Object System.Text.StringBuilder
        [void]$scbody.AppendLine('<h2>Draft scope language</h2><p class="pd">DRAFT - requires review before use in any statement of work.</p><ul>')
        foreach ($s in $Context.ScopeLanguage) { [void]$scbody.AppendLine(('<li><b>{0}:</b> {1}</li>' -f (& $enc $s.Type), (& $enc $s.Text))) }
        [void]$scbody.AppendLine('</ul>')
        & $addNavAndPane 'Reference' 'Scope language' ([string]@($Context.ScopeLanguage).Count) $scbody.ToString()
    }
    $indexBody = '<h2>Dataset index</h2><div class="tablebox">' + (ConvertTo-HtmlTable -Rows $model.DatasetIndex) + '</div>'
    & $addNavAndPane 'Reference' 'Dataset index' ([string]@($model.DatasetIndex).Count) $indexBody
    if (@($Context.Limitations).Count -gt 0) {
        $limBody = '<h2>Limitations</h2><div class="tablebox">' + (ConvertTo-HtmlTable -Rows $Context.Limitations -Columns @('Module','Message','Impact','Reason')) + '</div>'
        & $addNavAndPane 'Reference' 'Limitations' ([string]@($Context.Limitations).Count) $limBody
    }

    [void]$sb.AppendLine('</nav><main class="main">')
    [void]$sb.Append($panes.ToString())
    [void]$sb.AppendLine('</main></div>')

    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine(@'
document.querySelectorAll(".navlink").forEach(function(link){
  link.addEventListener("click", function(){
    document.querySelectorAll(".navlink").forEach(function(l){ l.classList.remove("sel"); });
    document.querySelectorAll(".pane").forEach(function(p){ p.classList.remove("active"); });
    link.classList.add("sel");
    document.getElementById(link.dataset.pane).classList.add("active");
  });
});
document.querySelectorAll("[data-filtertarget]").forEach(function(input){
  input.addEventListener("input", function(){
    var q = input.value.toLowerCase();
    var box = input.closest(".pane").querySelector(".tablebox tbody");
    if (!box) { return; }
    box.querySelectorAll("tr").forEach(function(row){
      row.classList.toggle("hide", q.length > 0 && row.textContent.toLowerCase().indexOf(q) === -1);
    });
  });
});
'@)
    [void]$sb.AppendLine('</script></body></html>')

    try { $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8 -Force; return $true }
    catch { Write-Warning ("Write-DashboardHtmlReport failed: {0}" -f $_.Exception.Message); return $false }
}

function ConvertTo-HtmlTable {
    [CmdletBinding()] param([AllowNull()]$Rows, [string[]]$Columns)
    $rowArray = @(if ($null -eq $Rows) { @() } else { @($Rows) })
    if ($rowArray.Count -eq 0) { return '<p class="muted">No data.</p>' }
    if (-not $Columns -or $Columns.Count -eq 0) { $Columns = Get-DatasetColumns -Rows $rowArray }
    $enc = { param($v) [System.Net.WebUtility]::HtmlEncode((ConvertTo-DisplayString -Value $v)) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append(('<th>{0}</th>' -f (& $enc $c))) }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rowArray) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) { [void]$sb.Append(('<td>{0}</td>' -f (& $enc (Get-RowValue -Row $r -Column $c)))) }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Test-DatasetHasRows {
    [CmdletBinding()] param([object]$Context, [string]$Dataset)
    return ($Context.DataSets.Contains($Dataset) -and @($Context.DataSets[$Dataset].Rows).Count -gt 0)
}

function Test-RoleFeaturePresent {
    [CmdletBinding()] param([object]$Context, [string]$Pattern)
    if (-not $Context.DataSets.Contains('RolesFeatures')) { return $false }
    return (@($Context.DataSets['RolesFeatures'].Rows | Where-Object { ($_.Name -match $Pattern) -or ($_.DisplayName -match $Pattern) }).Count -gt 0)
}

function Test-DatasetFieldTrue {
    [CmdletBinding()] param([object]$Context, [string]$Dataset, [string]$Field)
    if (-not $Context.DataSets.Contains($Dataset)) { return $false }
    return (@($Context.DataSets[$Dataset].Rows | Where-Object { (Get-RowValue -Row $_ -Column $Field) -eq $true }).Count -gt 0)
}

function Get-LikelyServerFunctions {
    <# Infers human-readable server functions from collected datasets/roles. #>
    [CmdletBinding()] param([Parameter(Mandatory)][object]$Context)
    $funcs = [System.Collections.Generic.List[string]]::new()

    $isDc = (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)AD-Domain|ADDS') -or (Test-DatasetFieldTrue -Context $Context -Dataset 'DomainContext' -Field 'IsDomainController')
    if ($isDc) { $funcs.Add('Active Directory Domain Controller') }
    if (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)^DNS$|DNS-Server')  { $funcs.Add('DNS Server') }
    if (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)^DHCP$|DHCP-Server') { $funcs.Add('DHCP Server') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'SqlInstances')        { $funcs.Add('Database Server (SQL Server)') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'OtherDatabaseEngines'){ $funcs.Add('Database Server (non-Microsoft engine)') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'IisSites')            { $funcs.Add('Web / Application Server (IIS)') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'HyperVVMs')           { $funcs.Add('Hyper-V Virtualization Host') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'ClusterDiscovery')    { $funcs.Add('Failover Cluster Node') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'RdsDiscovery')        { $funcs.Add('Remote Desktop Services') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'NpsRadiusDiscovery')  { $funcs.Add('Network Policy / RADIUS Server') }
    if (Test-DatasetFieldTrue -Context $Context -Dataset 'SmbShares' -Field 'IsUserShare') { $funcs.Add('File Server') }
    if (Test-DatasetFieldTrue -Context $Context -Dataset 'Printers' -Field 'Shared')       { $funcs.Add('Print Server') }
    if (Test-RoleFeaturePresent -Context $Context -Pattern '(?i)AD-Certificate|ADCS')      { $funcs.Add('Certificate Authority (AD CS)') }

    # Roles that do not appear as a Windows feature and so were previously invisible to
    # this function. Each is a genuine "you cannot just turn this off" dependency.
    if (Test-DatasetFieldTrue -Context $Context -Dataset 'UpdatePosture' -Field 'IsWsusServer') { $funcs.Add('Update Server (WSUS)') }
    if (Test-DatasetHasRows -Context $Context -Dataset 'HybridIdentity') {
        foreach ($h in @($Context.DataSets['HybridIdentity'].Rows)) {
            $label = [string](Get-RowValue -Row $h -Column 'Component')
            if ($label) { $funcs.Add(('Hybrid identity / cloud connector: {0}' -f $label)) }
        }
    }
    if (Test-DatasetFieldTrue -Context $Context -Dataset 'TimeSync' -Field 'IsAuthoritativeTimeSource') { $funcs.Add('Authoritative Time Source') }

    return @($funcs | Select-Object -Unique)
}

#endregion

Export-ModuleMember -Function `
    'ConvertTo-DisplayString','Get-DatasetColumns','Get-RowValue', `
    'Escape-CsvValue','Write-ObjectListToCsv','Write-ObjectListToJson','Get-CsvDelimiter', `
    'Escape-XmlText','Sanitize-WorksheetName','Get-ExcelXmlType','Get-ExcelXmlValue', `
    'ConvertTo-ExcelXmlWorksheet','Write-ExcelXmlWorkbook', `
    'Write-MarkdownFile','ConvertTo-MarkdownTable','Compress-Folder','Get-CompressFolderLastError','Export-DiscoveryDatasets', `
    'Write-DiscoveryPlan','Write-HtmlReport','Write-DashboardHtmlReport','Get-InternalReportModel', `
    'ConvertTo-HtmlTable','Get-LikelyServerFunctions','Get-DependencyDiagramSvg', `
    'Test-DatasetHasRows','Test-RoleFeaturePresent','Test-DatasetFieldTrue'
