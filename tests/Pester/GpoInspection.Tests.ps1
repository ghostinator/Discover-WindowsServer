#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    GpoInspection.Tests.ps1 - Group Policy content inspection: server references from each SYSVOL
    file type, and the hard rule that GPP passwords and script parameters never reach a row.
    Fixture files are written to $TestDrive in the real GPP/INI/Registry.pol formats.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                       -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\Output\Output.psm1')                   -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\ActiveDirectory\ActiveDirectory.psm1') -Force -DisableNameChecking
    . (Join-Path $Root 'tools\Merge-FleetDiscoveryResults.ps1')
}

Describe 'Get-GpoFileReferences' {
    It 'extracts drive-map and printer paths with the item name, and the referenced host' {
        $p = Join-Path $TestDrive 'Drives.xml'
        Set-Content $p '<Drives><Drive name="S:" uid="{1}"><Properties action="U" path="\\fs01\Data" label="Shared" letter="S"/></Drive></Drives>'
        $r = Get-GpoFileReferences -Path $p -Scope 'User'
        $r.References.Count | Should -Be 1
        $r.References[0].SettingType | Should -Be 'Drive map'
        $r.References[0].Item | Should -Be 'S:'
        $r.References[0].ReferencedHost | Should -Be 'fs01'
        $r.HasStoredPassword | Should -BeFalse
    }

    It 'detects a stored GPP password without ever reading its value into a row' {
        $p = Join-Path $TestDrive 'Groups.xml'
        Set-Content $p '<Groups><User name="LocalAdmin"><Properties cpassword="U3VwM3JTM2NyZXQh" userName="LocalAdmin" description="\\fs01\docs"/></User></Groups>'
        $r = Get-GpoFileReferences -Path $p -Scope 'Computer'
        $r.HasStoredPassword | Should -BeTrue
        ($r.References | ConvertTo-Json) | Should -Not -Match 'U3VwM3JTM2NyZXQh'
    }

    It 'reads script command lines but never the Parameters line' {
        $p = Join-Path $TestDrive 'scripts.ini'
        Set-Content $p "[Logon]`r`n0CmdLine=\\dc01\NETLOGON\map.bat`r`n0Parameters=/user:svc /pass:hunter2public" -Encoding Unicode
        $r = Get-GpoFileReferences -Path $p -Scope 'User'
        $r.References.Count | Should -Be 1
        $r.References[0].SettingType | Should -Be 'Logon/startup script'
        ($r.References | ConvertTo-Json) | Should -Not -Match 'hunter2public'
    }

    It 'reads folder redirection targets and UNC paths inside a binary Registry.pol' {
        $f = Join-Path $TestDrive 'fdeploy1.ini'
        Set-Content $f "[Documents]`r`nS-1-1-0=\\fs02\home\%USERNAME%\Documents" -Encoding Unicode
        (Get-GpoFileReferences -Path $f -Scope 'User').References[0].ReferencedHost | Should -Be 'fs02'
        $pol = Join-Path $TestDrive 'Registry.pol'
        $bytes = [byte[]](0x50,0x52,0x65,0x67,1,0,0,0) + [System.Text.Encoding]::Unicode.GetBytes("[Software\Policies\X;Path`0;1;40;\\app01\deploy\setup.msi`0]")
        [System.IO.File]::WriteAllBytes($pol, $bytes)
        $r = Get-GpoFileReferences -Path $pol -Scope 'Computer'
        $r.References[0].ReferencedHost | Should -Be 'app01'
        $r.References[0].SettingType | Should -Be 'Administrative template'
    }

    It 'reads the server of an ODBC data source preference' {
        $p = Join-Path $TestDrive 'DataSources.xml'
        Set-Content $p '<DataSources><DataSource name="ERP"><Properties dsn="ERP" driver="SQL Server" username="sa" cpassword=""><Attributes><Attribute name="SERVER" value="sql02"/></Attributes></Properties></DataSource></DataSources>'
        $r = Get-GpoFileReferences -Path $p -Scope 'Computer'
        $r.References[0].ReferencedHost | Should -Be 'sql02'
        $r.References[0].SettingType | Should -Be 'ODBC data source'
        $r.HasStoredPassword | Should -BeFalse   # empty cpassword is not a stored password
    }

    It 'ignores local paths and returns nothing for an empty file' {
        $p = Join-Path $TestDrive 'Files.xml'
        Set-Content $p '<Files><File name="cfg"><Properties fromPath="C:\Temp\a.cfg" targetPath="C:\App\a.cfg"/></File></Files>'
        (Get-GpoFileReferences -Path $p).References.Count | Should -Be 0
    }
}

Describe 'Get-GpoHostFromText' {
    It 'finds every UNC host and only falls back to a bare host when asked' {
        # Assign first: the function returns ,@() and wrapping the call in @() would nest it.
        $two = Get-GpoHostFromText -Text 'copy \\a1\x \\b2.corp.local\y'; $two | Should -Be @('a1','b2.corp.local')
        $none = Get-GpoHostFromText -Text 'sql02'; @($none).Count | Should -Be 0
        $bare = Get-GpoHostFromText -Text 'sql02,1433' -BareHost; $bare | Should -Be @('sql02')
    }
}

Describe 'Fleet rollup - Group Policy references' {
    It 'deduplicates the same GPO reference seen from several servers and flags retiring targets' {
        $eng = Join-Path $TestDrive 'eng'
        $ref = [pscustomobject]@{ GpoName='Drives'; GpoGuid='{G1}'; GpoLinked=$true; Scope='User'; SettingType='Drive map'; Item='S:'; Reference='\\OLD01\Data'; ReferencedHost='OLD01'; ReferencesThisServer=$false }
        foreach ($n in 'OLD01','APP01','APP02') {
            $dir = Join-Path $eng "Discover-WindowsServer_${n}_20261001_000000\evidence\data\json"; New-Item -ItemType Directory $dir -Force | Out-Null
            @{ RunId="r$n"; ComputerName=$n; Mode='Deep'; ProjectType=$(if ($n -eq 'OLD01') { 'Decommission' } else { 'GeneralDiscovery' }); Datasets=@() } | ConvertTo-Json | Out-File (Join-Path (Split-Path (Split-Path $dir)) 'collection-metadata.json') -Encoding utf8
            if ($n -ne 'OLD01') { ConvertTo-Json @($ref) | Out-File (Join-Path $dir 'GpoServerReferences.json') -Encoding utf8 }
        }
        $c = Get-FleetCorrelations -EngagementFolder $eng
        $g = @($c.GpoReferences)
        $g.Count | Should -Be 1
        $g[0].ReferencesServer | Should -Be 'OLD01'
        $g[0].TargetIsRetiring | Should -BeTrue
        $g[0].SeenFrom | Should -Be 'APP01, APP02'
    }
}
