<#
    Certificates.psm1 - local machine certificate stores (read-only).
    Produces: Certificates, CertificateBindings.
    NEVER exports certificates or private keys - metadata/booleans only.
#>

function Get-DiscoveryModuleMetadata {
    [pscustomobject]@{
        ModuleName='Certificates'; DisplayName='Certificates & PKI'; Category='Certificates'; Version='1.0.0'
        DefaultInFast=$true; DefaultInDeep=$true; RequiresAdmin=$false; RequiresDomainContext=$false
        RequiresRole=$null; EstimatedImpact='Low'; CanRunAsSystem=$true
        ProducesDatasets=@('Certificates','CertificateBindings','CertificateAuthority','CertificateAuthorityUsage')
        ProducesRisks=$true; ProducesFollowUpQuestions=$false; SupportsDeepMode=$true; SupportsComplianceLens=$true
    }
}

function Test-DiscoveryPrerequisites {
    param([object]$Context)
    [pscustomobject]@{ ModuleName='Certificates'; CanRun=$true; Status='Ready'; Reason=''; Limitations=@() }
}

# Pure: summarises `certutil -view -out "Request.SubmittedWhen,CertificateTemplate" csv` output
# (issued requests only). Counts and template names only - never subjects or requesters.
function ConvertTo-CaIssuanceSummary {
    param([string[]]$Lines, [datetime]$Now = (Get-Date))
    $dates = [System.Collections.Generic.List[datetime]]::new(); $tpl = @{}
    foreach ($l in $Lines) {
        if ($l -notmatch '^"([^"]*)","([^"]*)"') { continue }
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParse($Matches[1], [ref]$d)) { continue }   # header row / unparsable
        $dates.Add($d); $t = $Matches[2]; if (-not $t) { $t = '(none)' }; $tpl[$t] = 1 + [int]$tpl[$t]
    }
    [pscustomobject]@{
        IssuedInLookback = $dates.Count
        Issued30d  = @($dates | Where-Object { $_ -ge $Now.AddDays(-30) }).Count
        Issued90d  = @($dates | Where-Object { $_ -ge $Now.AddDays(-90) }).Count
        LastIssued = $(if ($dates.Count) { ($dates | Sort-Object -Descending | Select-Object -First 1).ToString('yyyy-MM-dd HH:mm') } else { '' })
        TopTemplates = ((@($tpl.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })) -join '; ')
    }
}

function Invoke-DiscoveryCollection {
    param([object]$Context)
    $certs = [System.Collections.Generic.List[object]]::new()
    $bindings = [System.Collections.Generic.List[object]]::new()
    $now = Get-Date
    $stores = @('My','WebHosting','Remote Desktop','CA')
    foreach ($store in $stores) {
        try {
            $path = "Cert:\LocalMachine\$store"
            if (-not (Test-Path -LiteralPath $path)) { continue }
            foreach ($c in (Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue)) {
                try {
                    $eku = ''
                    try { $eku = (($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join '; ') } catch { }
                    $certs.Add([pscustomobject]@{
                        StoreLocation='LocalMachine'; StoreName=$store
                        Subject=$c.Subject; Issuer=$c.Issuer; Thumbprint=$c.Thumbprint; FriendlyName=$c.FriendlyName
                        NotBefore=(Normalize-DateTime $c.NotBefore); NotAfter=(Normalize-DateTime $c.NotAfter)
                        EnhancedKeyUsage=$eku; HasPrivateKey=([bool]$c.HasPrivateKey)
                        SelfSigned=([bool]($c.Subject -eq $c.Issuer))
                        ExpiringSoon=([bool]($c.NotAfter -le $now.AddDays(90)))
                        DaysUntilExpiry=([int]([math]::Round(($c.NotAfter - $now).TotalDays,0)))
                    })
                } catch { }
            }
        } catch { Add-Limitation -Context $Context -Module 'Certificates' -Message ("Certificate store '{0}' read failed." -f $store) -Reason $_.Exception.Message | Out-Null }
    }

    # Correlate to IIS SSL bindings if the IIS module already produced them.
    try {
        if ($Context.DataSets.Contains('IisBindings')) {
            foreach ($b in @($Context.DataSets['IisBindings'].Rows)) {
                $hash = Get-RowValue -Row $b -Column 'CertificateHash'
                if ($hash) {
                    $bindings.Add([pscustomobject]@{ Usage='IIS'; BoundTo=(Get-RowValue -Row $b -Column 'Site'); Thumbprint=$hash; Detail=(Get-RowValue -Row $b -Column 'BindingInformation') })
                    Add-DependencyEdge -Context $Context -SourceType 'IIS Site' -SourceName (Get-RowValue -Row $b -Column 'Site') -DependencyType 'UsesCertificate' -Target $hash -Evidence 'SSL binding' -Confidence 'Confirmed' -SourceDataset 'IisBindings' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Can this certificate be exported or reissued on the target server?' | Out-Null
                }
            }
        }
    } catch { }

    # A CONFIGURED certificate authority (not merely the role): its CRL/AIA publication URLs
    # usually hard-code this server's name, and every issued certificate chains to it.
    $ca = [System.Collections.Generic.List[object]]::new()
    try {
        $cfgRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
        $active = Get-RegistryValueSafe -Path $cfgRoot -Name 'Active'
        if ($active) {
            $p = Join-Path $cfgRoot $active
            $type = switch ([int](Get-RegistryValueSafe -Path $p -Name 'CAType')) { 0 {'Enterprise Root'} 1 {'Enterprise Subordinate'} 3 {'Standalone Root'} 4 {'Standalone Subordinate'} default {'Unknown'} }
            $urls = @(@(Get-RegistryValueSafe -Path $p -Name 'CRLPublicationURLs') + @(Get-RegistryValueSafe -Path $p -Name 'CACertPublicationURLs') | Where-Object { $_ } | ForEach-Object { ([string]$_ -replace '^\d+:','') })
            $names = @($env:COMPUTERNAME, (Get-RegistryValueSafe -Path $p -Name 'CAServerName')) | Where-Object { $_ }
            $ca.Add([pscustomobject]@{
                CAName=$active; CAType=$type; CAServerName=[string](Get-RegistryValueSafe -Path $p -Name 'CAServerName')
                ServiceStatus=[string](Get-Service CertSvc -ErrorAction SilentlyContinue).Status
                ValidityPeriod=("{0} {1}" -f (Get-RegistryValueSafe -Path $p -Name 'ValidityPeriodUnits'), (Get-RegistryValueSafe -Path $p -Name 'ValidityPeriod'))
                CrlPeriod=("{0} {1}" -f (Get-RegistryValueSafe -Path $p -Name 'CRLPeriodUnits'), (Get-RegistryValueSafe -Path $p -Name 'CRLPeriod'))
                PublicationUrls=($urls -join ' | ')
                # %1 is the CA server's DNS name, so http://%1/... hard-codes this server for every relying party.
                UrlsReferenceThisServer=[bool](@($urls | Where-Object { $_ -match '^(https?|file)://%1' }).Count -or @($names | Where-Object { $n = $_; $urls | Where-Object { $_ -match [regex]::Escape($n) } }).Count)
            })
            Add-DependencyEdge -Context $Context -SourceType 'Certificate Authority' -SourceName $active -DependencyType 'IssuesCertificates' -Target 'All certificate consumers' -Evidence 'AD CS configuration' -Confidence 'Confirmed' -SourceDataset 'CertificateAuthority' -ProjectImpact 'Cutover Complexity' -ValidationQuestion 'Which systems hold certificates issued by this CA, and can the CA and its CRL/AIA locations be migrated or replaced?' | Out-Null
        }
    } catch { }

    # CA usage: issued-certificate recency/volume from the CA database (read-only certutil -view).
    $usage = [System.Collections.Generic.List[object]]::new()
    if ($ca.Count -gt 0) {
        $lookback = 365
        $row = [ordered]@{ CAName=$ca[0].CAName; LookbackDays=$lookback; Status='Unavailable'; IssuedInLookback=$null; Issued30d=$null; Issued90d=$null; LastIssued=''; TopTemplates=''; Reason='' }
        try {
            if ($ca[0].ServiceStatus -ne 'Running') { $row.Reason = "CertSvc is $($ca[0].ServiceStatus); CA database not queried." }
            else {
                $since = (Get-Date).AddDays(-$lookback).ToString('d')   # certutil parses dates in the current culture
                $r = Invoke-CommandLineSafe -FilePath 'certutil.exe' -Arguments @('-view','-restrict',('"Request.Disposition=20,Request.SubmittedWhen>={0}"' -f $since),'-out','"Request.SubmittedWhen,CertificateTemplate"','csv') -TimeoutSeconds 120
                if ($r.TimedOut) { $row.Reason = 'certutil -view timed out (CA database too large for the module budget).' }
                elseif (-not $r.Succeeded -and $r.StdOut -notmatch '^"') { $row.Reason = 'certutil -view failed (needs CA Auditor/Manager rights): ' + (($r.StdErr + ' ' + $r.StdOut).Trim() -replace '\s+',' ') }
                else {
                    $sum = ConvertTo-CaIssuanceSummary -Lines @($r.StdOut -split "`r?`n")
                    $row.Status='Queried'; $row.IssuedInLookback=$sum.IssuedInLookback; $row.Issued30d=$sum.Issued30d; $row.Issued90d=$sum.Issued90d; $row.LastIssued=$sum.LastIssued; $row.TopTemplates=$sum.TopTemplates
                }
            }
        } catch { $row.Reason = $_.Exception.Message }
        if ($row.Status -ne 'Queried') { Add-Limitation -Context $Context -Module 'Certificates' -Message 'CA issuance history could not be read; whether this CA is actively issuing is unknown.' -Reason $row.Reason | Out-Null }
        $usage.Add([pscustomobject]$row)
    }

    return ,@{ Certificates=@($certs); CertificateBindings=@($bindings); CertificateAuthority=@($ca); CertificateAuthorityUsage=@($usage) }
}

function ConvertTo-DiscoveryDatasets {
    param([object]$Context, $RawData)
    if (-not $RawData) { $RawData = @{} }
    $certs = @(if ($RawData.Certificates) { @($RawData.Certificates) } else { @() })
    $bindings = @(if ($RawData.CertificateBindings) { @($RawData.CertificateBindings) } else { @() })
    Add-DataSet -Context $Context -Name 'Certificates' -Description 'Local machine certificates (no keys exported).' -Rows $certs -Visibility 'Internal' -SourceModule 'Certificates' | Out-Null
    Add-DataSet -Context $Context -Name 'CertificateBindings' -Description 'Certificate-to-service/site correlations.' -Rows $bindings -Visibility 'Internal' -SourceModule 'Certificates' | Out-Null
    Add-DataSet -Context $Context -Name 'CertificateAuthority' -Description 'Configured AD CS certification authority (registry config only).' -Rows @(if ($RawData.CertificateAuthority) { @($RawData.CertificateAuthority) } else { @() }) -Visibility 'Internal' -SourceModule 'Certificates' | Out-Null
    Add-DataSet -Context $Context -Name 'CertificateAuthorityUsage' -Description 'CA issuance volume/recency from the CA database (counts and template names only).' -Rows @(if ($RawData.CertificateAuthorityUsage) { @($RawData.CertificateAuthorityUsage) } else { @() }) -Visibility 'Internal' -SourceModule 'Certificates' | Out-Null
}

Export-ModuleMember -Function 'Get-DiscoveryModuleMetadata','Test-DiscoveryPrerequisites','Invoke-DiscoveryCollection','ConvertTo-DiscoveryDatasets','ConvertTo-CaIssuanceSummary'
