<#
    PrintServer.psm1 - printers, drivers, and ports (read-only).
    Produces: Printers, PrinterDrivers, PrintPorts.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='PrintServer'; DisplayName='Print Server'; Category='File'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('Printers','PrinterDrivers','PrintPorts')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='PrintServer'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $printers=[System.Collections.Generic.List[object]]::new(); $drivers=[System.Collections.Generic.List[object]]::new(); $ports=[System.Collections.Generic.List[object]]::new()
    $labelRx = '(?i)zebra|dymo|brother\s*ql|bartender|godex|intermec|sato|toshiba tec|label'
    try {
        if (Get-CommandAvailable -Name 'Get-Printer') {
            foreach ($p in (Get-Printer -ErrorAction SilentlyContinue)) {
                $isLabel = ($p.Name -match $labelRx) -or ($p.DriverName -match $labelRx)
                $printers.Add([pscustomobject]@{ Name=$p.Name; DriverName=$p.DriverName; PortName=$p.PortName; Shared=([bool]$p.Shared); ShareName=$p.ShareName; Location=$p.Location; Comment=$p.Comment; Published=([bool]$p.Published); PrinterStatus=[string]$p.PrinterStatus; IsLabelPrinter=$isLabel })
                if ($p.Shared) { Add-DependencyEdge -Context $Context -SourceType 'Printer' -SourceName $p.Name -DependencyType 'UsesPort' -Target $p.PortName -Evidence 'Shared printer' -Confidence 'Confirmed' -SourceDataset 'Printers' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Do users map to this printer by server name?' | Out-Null }
            }
            foreach ($d in (Get-PrinterDriver -ErrorAction SilentlyContinue)) { $drivers.Add([pscustomobject]@{ Name=$d.Name; Manufacturer=$d.Manufacturer; DriverVersion=[string]$d.DriverVersion; Environment=$d.PrinterEnvironment }) }
            foreach ($pt in (Get-PrinterPort -ErrorAction SilentlyContinue)) { $ports.Add([pscustomobject]@{ Name=$pt.Name; PrinterHostAddress=$pt.PrinterHostAddress; PortMonitor=$pt.PortMonitor; Description=$pt.Description }) }
        } else {
            foreach ($p in (Invoke-CimSafe -ClassName 'Win32_Printer')) {
                $isLabel = ($p.Name -match $labelRx) -or ($p.DriverName -match $labelRx)
                $printers.Add([pscustomobject]@{ Name=$p.Name; DriverName=$p.DriverName; PortName=$p.PortName; Shared=([bool]$p.Shared); ShareName=$p.ShareName; Location=$p.Location; Comment=$p.Comment; Published=([bool]$p.Published); PrinterStatus=[string]$p.PrinterStatus; IsLabelPrinter=$isLabel })
            }
        }
    } catch { Add-Limitation -Context $Context -Module 'PrintServer' -Message 'Printer enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    if ($printers.Count -eq 0) { Add-Limitation -Context $Context -Module 'PrintServer' -Message 'No printers detected (print server role may be absent).' | Out-Null }
    return ,@{ Printers=@($printers); PrinterDrivers=@($drivers); PrintPorts=@($ports) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'Printers'       -Description 'Printers (shared status, label-printer flag).' -Rows (& $get 'Printers')       -Visibility 'Both'     -SourceModule 'PrintServer' | Out-Null
    Add-DataSet -Context $Context -Name 'PrinterDrivers' -Description 'Installed printer drivers.'                    -Rows (& $get 'PrinterDrivers') -Visibility 'Internal' -SourceModule 'PrintServer' | Out-Null
    Add-DataSet -Context $Context -Name 'PrintPorts'     -Description 'Printer ports (host IPs).'                     -Rows (& $get 'PrintPorts')     -Visibility 'Internal' -SourceModule 'PrintServer' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets'
