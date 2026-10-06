<#
    DHCP.psm1 - DHCP Server role discovery (read-only). Role-gated.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='DHCP'; DisplayName='DHCP Server'; Category='Identity'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole='DHCP'; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('DhcpScopes','DhcpReservations')
        # ProducesRisks is $false, not a placeholder: this module's own datasets (scope/
        # reservation lists) are informational, not risk-scored, and no risk-rules.json rule
        # references them. The real "server hosts the DHCP role" risk finding already exists
        # (RULE-DHCP-001) and is deliberately sourced from RolesFeatures instead, since that
        # module runs on every server (this one is role-gated and simply never runs on the
        # other 90%+ of a fleet).
        ProducesRisks=$false; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$false
    }
}

function Test-DhcpPresent {
    if (Get-CommandAvailable -Name 'Get-DhcpServerv4Scope') { return $true }
    if (Get-Service -Name 'DHCPServer' -ErrorAction SilentlyContinue) { return $true }
    return $false
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    if (Test-DhcpPresent) { return [pscustomobject]@{ ModuleName='DHCP'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() } }
    [pscustomobject]@{ ModuleName='DHCP'; CanRun=$false; Status='NotApplicable'; Reason='DHCP Server role not present.'; Limitations=@() }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    # Default cmdlets resolve $env:COMPUTERNAME through DNS on every call (~1 s each; 20-30x slower than 'localhost'), and a resolution failure is swallowed by -ErrorAction SilentlyContinue as an empty result.
    $PSDefaultParameterValues = @{ 'Get-Dhcp*:ComputerName' = 'localhost' }
    $scopes=[System.Collections.Generic.List[object]]::new(); $res=[System.Collections.Generic.List[object]]::new()
    if (-not (Get-CommandAvailable -Name 'Get-DhcpServerv4Scope')) { Add-Limitation -Context $Context -Module 'DHCP' -Message 'DhcpServer module not available; DHCP present but not enumerable.' | Out-Null; return ,@{ DhcpScopes=@(); DhcpReservations=@() } }
    try {
        foreach ($s in (Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) {
            $scopes.Add([pscustomobject]@{ ScopeId=[string]$s.ScopeId; Name=$s.Name; StartRange=[string]$s.StartRange; EndRange=[string]$s.EndRange; SubnetMask=[string]$s.SubnetMask; State=[string]$s.State; LeaseDuration=[string]$s.LeaseDuration })
            try { foreach ($r in (Get-DhcpServerv4Reservation -ScopeId $s.ScopeId -ErrorAction SilentlyContinue)) { $res.Add([pscustomobject]@{ ScopeId=[string]$s.ScopeId; IPAddress=[string]$r.IPAddress; ClientId=[string]$r.ClientId; Name=$r.Name; Description=$r.Description }) } } catch { }
        }
    } catch { Add-Limitation -Context $Context -Module 'DHCP' -Message 'DHCP scope enumeration failed.' -Reason $_.Exception.Message | Out-Null }
    return ,@{ DhcpScopes=@($scopes); DhcpReservations=@($res) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $get = { param($k) if ($RawData[$k]) { @($RawData[$k]) } else { @() } }
    Add-DataSet -Context $Context -Name 'DhcpScopes'       -Description 'DHCP scopes.'       -Rows (& $get 'DhcpScopes')       -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
    Add-DataSet -Context $Context -Name 'DhcpReservations' -Description 'DHCP reservations.' -Rows (& $get 'DhcpReservations') -Visibility 'Internal' -SourceModule 'DHCP' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','Test-DhcpPresent'
