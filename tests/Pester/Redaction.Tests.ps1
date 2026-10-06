#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Redaction.Tests.ps1 - the secret-shape corpus that config\redaction-patterns.json must defeat.

    WHY THIS FILE EXISTS
    An audit found that Redact-SensitiveValue only handled the shape
    'key=unquoted-value'. Every value pattern terminated on ["'], so a quoted secret
    (--password="x") could not be matched at all, ':'-delimited secrets were missed
    entirely, and command-line flags (sqlcmd -P x) had no pattern. Five of seven
    realistic service/scheduled-task command lines kept the plaintext secret.

    That matters because these exact strings populate Services.PathName,
    ScheduledTasks.ActionsText and RunningProcesses command lines - all collected in
    FAST mode by default and exported to csv\, json\, workbook.xml and
    internal-report.html. A miss here writes a live credential into a client
    deliverable, breaking the "never collects passwords" contract in docs\README.md.

    So: when adding a redaction pattern, add its shape to the -ForEach table in
    'Secrets never survive redaction'. When a pattern starts eating useful scoping
    evidence, add that case to 'Scoping evidence survives redaction'. Both directions
    are load-bearing - over-redaction that destroys 'Server=sql01' makes the evidence
    useless, and under-redaction leaks a credential.

    NOTE: do not name a -ForEach key 'Input' - it collides with PowerShell's automatic
    $input variable. This table uses 'Text'.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')
    $script:Ctx = New-DiscoveryContext -Mode Fast -Config $Config
}

Describe 'redaction-patterns.json loads' {
    It 'parses and exposes value patterns' {
        $Config.Redaction | Should -Not -BeNullOrEmpty
        @($Config.Redaction.valuePatterns).Count | Should -BeGreaterThan 0
    }
    It 'every pattern is a valid .NET regex' {
        foreach ($p in @($Config.Redaction.valuePatterns)) {
            { [regex]::new($p.pattern) } | Should -Not -Throw -Because "pattern '$($p.name)' must compile"
        }
    }
    It 'every keepStructure pattern supplies a structureReplacement' {
        foreach ($p in @($Config.Redaction.valuePatterns | Where-Object { $_.keepStructure })) {
            $p.structureReplacement | Should -Not -BeNullOrEmpty -Because "pattern '$($p.name)' keeps structure"
        }
    }
}

Describe 'Secrets never survive redaction' {
    # Secret = the literal that must be gone from the output.
    It '<Shape>' -ForEach @(
        @{ Shape = 'connection string, bare value';        Text = 'Server=sql01;Password=Sup3rS3cret!;Database=erp';                          Secret = 'Sup3rS3cret!' }
        @{ Shape = 'connection string inside XML attr';    Text = '<add name="db" connectionString="Server=s;User ID=sa;Password=Sup3rS3cret!" />'; Secret = 'Sup3rS3cret!' }
        @{ Shape = 'JSON, double-quoted value';            Text = '  "password": "Sup3rS3cret!",';                                            Secret = 'Sup3rS3cret!' }
        @{ Shape = 'YAML, colon delimited';                Text = 'password: Sup3rS3cret!';                                                    Secret = 'Sup3rS3cret!' }
        @{ Shape = 'XML key/value attribute pair';         Text = '<add key="Password" value="Sup3rS3cret!" />';                               Secret = 'Sup3rS3cret!' }
        @{ Shape = 'env-style key with prefix';            Text = 'SMTP_PASSWORD=Sup3rS3cret!';                                                Secret = 'Sup3rS3cret!' }
        @{ Shape = 'camelCase key, single-quoted value';   Text = "dbPassword='Sup3rS3cret!'";                                                 Secret = 'Sup3rS3cret!' }
        @{ Shape = 'ClientSecret key';                     Text = 'ClientSecret=Sup3rS3cret!';                                                 Secret = 'Sup3rS3cret!' }
        @{ Shape = 'sharedSecret, colon delimited';        Text = 'sharedSecret: Sup3rS3cret!';                                                Secret = 'Sup3rS3cret!' }
        @{ Shape = 'CLI flag, quoted value';               Text = '"C:\App\svc.exe" --password="Sup3rS3cret!" --port 8080';                    Secret = 'Sup3rS3cret!' }
        @{ Shape = 'CLI flag, colon + single quotes';      Text = '"C:\App\svc.exe" -pwd:''Sup3rS3cret!'' -db erp';                            Secret = 'Sup3rS3cret!' }
        @{ Shape = 'sqlcmd -P, space delimited';           Text = 'sqlcmd.exe -S sql01 -U sa -P Sup3rS3cret! -Q "backup database erp"';        Secret = 'Sup3rS3cret!' }
        @{ Shape = 'sqlcmd -P, no .exe suffix';            Text = 'sqlcmd -S sql01 -U sa -P Sup3rS3cret!';                                    Secret = 'Sup3rS3cret!' }
        @{ Shape = 'bcp -P, space delimited';              Text = 'bcp erp.dbo.orders out D:\\o.dat -S sql01 -U sa -P Sup3rS3cret!';            Secret = 'Sup3rS3cret!' }
        @{ Shape = 'osql -P, space delimited';             Text = 'osql -S sql01 -U sa -P Sup3rS3cret!';                                      Secret = 'Sup3rS3cret!' }
        @{ Shape = 'CLI flag, space delimited';            Text = 'app.exe --password Sup3rS3cret! --verbose';                                 Secret = 'Sup3rS3cret!' }
        @{ Shape = 'net use positional password';          Text = 'powershell -Command "net use Z: \\fs01\data /user:DOMAIN\svc Sup3rS3cret!"'; Secret = 'Sup3rS3cret!' }
        @{ Shape = 'PowerShell variable assignment';       Text = '$pwd = "Sup3rS3cret!"';                                                     Secret = 'Sup3rS3cret!' }
        @{ Shape = 'JWT behind --token flag';              Text = 'C:\App\sync.exe --token eyJhbGciOiJIUzI1NiJ9.payloadpayload.sigsig';        Secret = 'eyJhbGciOiJIUzI1NiJ9.payloadpayload' }
        @{ Shape = 'JWT behind token: key';                Text = 'token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghijklmnop';             Secret = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' }
        @{ Shape = 'Bearer authorization header';          Text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdefghijk';                     Secret = 'eyJhbGciOiJIUzI1NiJ9abcdefghijk' }
        @{ Shape = 'AWS access key id';                    Text = '  "apiKey": "AKIAIOSFODNN7EXAMPLE12",';                                    Secret = 'AKIAIOSFODNN7EXAMPLE12' }
        @{ Shape = 'SNMP community string';                Text = 'snmp community = public';                                                     Secret = 'public' }
        @{ Shape = 'PEM private key header';               Text = '-----BEGIN RSA PRIVATE KEY-----';                                          Secret = 'BEGIN RSA PRIVATE KEY' }
    ) {
        $out = Redact-SensitiveValue -InputString $Text -Context $Ctx
        $out | Should -Not -BeLike ('*' + $Secret + '*') -Because "the shape '$Shape' must not leak its secret"
    }

    It 'does not merely prepend a marker while leaving the secret in place' {
        # Regression guard: keepStructure once produced '$pwd=[REDACTED]"Sup3rS3cret!"',
        # which reads as redacted but is not - the value must be consumed, not decorated.
        $out = Redact-SensitiveValue -InputString '$pwd = "Sup3rS3cret!"' -Context $Ctx
        $out | Should -Match '\[REDACTED'
        $out | Should -Not -BeLike '*Sup3rS3cret!*'
    }
}

Describe 'Scoping evidence survives redaction' {
    It 'keeps <Keep>' -ForEach @(
        @{ Text = 'Server=sql01;Password=x;Database=erp';         Keep = 'Server=sql01' }
        @{ Text = 'Server=sql01;Password=x;Database=erp';         Keep = 'Database=erp' }
        @{ Text = 'Data Source=sql01;Initial Catalog=erp';        Keep = 'Data Source=sql01' }
        @{ Text = 'robocopy \\fs01\share D:\bak /XO';             Keep = '\\fs01\share' }
        @{ Text = 'C:\App\svc.exe -p 8080 -path C:\data';         Keep = '-p 8080' }
        @{ Text = 'jdbc:sqlserver://sql01:1433;databaseName=erp'; Keep = 'sql01:1433' }
        @{ Text = 'ldap://dc01.corp.local/DC=corp,DC=local';      Keep = 'dc01.corp.local' }
        @{ Text = '"C:\Program Files\Acme\svc.exe" --port 9000';  Keep = 'Acme\svc.exe' }
        # -P is a password ONLY for the SQL command-line tools. A bare (?-i:-P) pattern
        # matched any space-delimited -P and ate the following token, which was found on
        # the first real Windows run: every redaction in that output was a false positive
        # of this shape and not one was a real secret. Keep both directions covered.
        @{ Text = '/usr/bin/pwd -P /c/Users/brandon/scratch';     Keep = '/c/Users/brandon/scratch' }
        @{ Text = 'tar -P -xf archive.tar';                       Keep = '-xf archive.tar' }
        @{ Text = 'curl -P 21 ftp://host/file';                   Keep = 'ftp://host/file' }
        @{ Text = 'C:\App\tool.exe -P ProductionProfile';        Keep = 'ProductionProfile' }
        @{ Text = 'robocopy D:\src E:\dst /MIR -P 4';             Keep = '-P 4' }
    ) {
        $out = Redact-SensitiveValue -InputString $Text -Context $Ctx
        $out | Should -BeLike ('*' + $Keep + '*') -Because 'redaction must not destroy dependency evidence'
    }
}

Describe 'Redaction edge cases' {
    It 'returns null for null input' { Redact-SensitiveValue -InputString $null -Context $Ctx | Should -BeNullOrEmpty }
    It 'returns empty string unchanged' { Redact-SensitiveValue -InputString '' -Context $Ctx | Should -Be '' }
    It 'leaves a string with no secrets untouched' {
        $s = 'C:\Windows\system32\svchost.exe -k netsvcs'
        Redact-SensitiveValue -InputString $s -Context $Ctx | Should -Be $s
    }
    It 'is idempotent - redacting twice changes nothing further' {
        $once  = Redact-SensitiveValue -InputString 'Server=s;Password=Sup3rS3cret!;' -Context $Ctx
        $twice = Redact-SensitiveValue -InputString $once -Context $Ctx
        $twice | Should -Be $once
    }
    It 'works with no config supplied (built-in fallback patterns)' {
        $bare = New-DiscoveryContext -Mode Fast
        $out = Redact-SensitiveValue -InputString 'Server=s;Password=Sup3rS3cret!;' -Context $bare
        $out | Should -Not -BeLike '*Sup3rS3cret!*'
    }
}
