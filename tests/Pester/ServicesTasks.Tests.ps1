#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    ServicesTasks.Tests.ps1 - fixture-based tests for the Services/ScheduledTasks collector.

    Picked as the next collector (after DNS/Network) because it carries the toolkit's most
    security-relevant heuristics - unquoted-service-path detection (the classic local
    privilege-escalation pattern) and domain-account/service-account classification for
    migration cutover planning - and per HANDOFF.md/TODO.md it's one of the two modules
    named as having the least real-world exercise so far. Deliberately vulnerable-looking
    service configs are exactly the kind of thing this repo's standing rules say not to go
    plant on the lab (see feedback-standing-rules memory) - fixtures are the only safe way
    to exercise these paths at all.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')                 -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\ServicesTasks\ServicesTasks.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-STTestContext {
        New-DiscoveryContext -Mode Fast -Config $script:Config
    }
}

Describe 'Get-ServiceExePath' {
    It 'extracts a quoted path with spaces, dropping the quotes and any arguments' {
        Get-ServiceExePath -PathName '"C:\Program Files\Foo\svc.exe" -k netsvcs' | Should -Be 'C:\Program Files\Foo\svc.exe'
    }
    It 'extracts an unquoted path ending in .exe before any arguments' {
        Get-ServiceExePath -PathName 'C:\Windows\System32\svchost.exe -k netsvcs' | Should -Be 'C:\Windows\System32\svchost.exe'
    }
    It 'falls back to the first whitespace-delimited token when there is no .exe match' {
        Get-ServiceExePath -PathName 'C:\Tools\somebinary arg1 arg2' | Should -Be 'C:\Tools\somebinary'
    }
    It 'returns the whole string when there is no whitespace at all' {
        Get-ServiceExePath -PathName 'C:\Tools\onepiece.exe' | Should -Be 'C:\Tools\onepiece.exe'
    }
    It 'returns empty for null/blank input' {
        Get-ServiceExePath -PathName ''    | Should -Be ''
        Get-ServiceExePath -PathName $null | Should -Be ''
    }
    It 'does not throw on a leading quote with no matching closing quote (malformed quoting)' {
        # Known current behaviour: falls through to the unquoted branch with the leading
        # quote still attached, since IndexOf finds no closing '"'. Locking this in so a
        # future change to the parsing logic is a deliberate decision, not a silent drift.
        Get-ServiceExePath -PathName '"C:\Program Files\Foo\svc.exe -k netsvcs' | Should -Be '"C:\Program Files\Foo\svc.exe'
    }
}

Describe 'Test-DomainAccount' {
    It 'treats NT AUTHORITY\SYSTEM as well-known, not a domain account' {
        Test-DomainAccount -Account 'NT AUTHORITY\SYSTEM' | Should -BeFalse
    }
    It 'treats BUILTIN\Users as well-known, not a domain account' {
        Test-DomainAccount -Account 'BUILTIN\Users' | Should -BeFalse
    }
    It 'treats LocalSystem (no backslash) as not a domain account' {
        Test-DomainAccount -Account 'LOCALSYSTEM' | Should -BeFalse
    }
    It 'treats COMPUTERNAME\LocalAdmin as a local, not domain, account' {
        Test-DomainAccount -Account ('{0}\LocalAdmin' -f $env:COMPUTERNAME) | Should -BeFalse
    }
    It 'treats DOMAIN\svc-account as a domain account' {
        Test-DomainAccount -Account 'CORP\svc-sql' | Should -BeTrue
    }
    It 'treats a UPN (user@domain) as a domain account' {
        Test-DomainAccount -Account 'svc-sql@corp.local' | Should -BeTrue
    }
    It 'returns false for blank/null input' {
        Test-DomainAccount -Account ''    | Should -BeFalse
        Test-DomainAccount -Account $null | Should -BeFalse
    }
    It 'returns false for a string with neither a backslash nor an @' {
        Test-DomainAccount -Account 'justausername' | Should -BeFalse
    }
}

Describe 'Invoke-DiscoveryCollection - Services heuristics' {

    BeforeEach {
        # Keep the ScheduledTasks half of collection out of the way for these tests.
        Mock -CommandName Get-CommandAvailable -ModuleName ServicesTasks -MockWith { $false }
        Mock -CommandName Invoke-CommandLineSafe -ModuleName ServicesTasks -MockWith {
            [pscustomobject]@{ Succeeded = $false; StdOut = ''; StdErr = ''; ExitCode = 1; TimedOut = $false }
        }
    }

    It 'flags an unquoted auto-start path with spaces outside C:\Windows as a vulnerable non-MS autostart' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith {
            @([pscustomobject]@{
                Name = 'VulnSvc'; DisplayName = 'Vulnerable Service'; State = 'Running'; StartMode = 'Auto'
                StartName = 'LocalSystem'; PathName = 'C:\Program Files\Custom App\my service.exe -x'
                Description = ''; ServiceType = 'Own Process'; ProcessId = 1001
            })
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.Services | Where-Object Name -eq 'VulnSvc'
        $row.ExecutablePath           | Should -Be 'C:\Program Files\Custom App\my service.exe'
        $row.UnquotedPathWithSpaces   | Should -BeTrue
        $row.IsNonMicrosoftAutoStart  | Should -BeTrue
        $row.PathExists               | Should -BeFalse
    }

    It 'does not flag a properly quoted Windows service under C:\Windows, even if auto-start' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith {
            @([pscustomobject]@{
                Name = 'SvcHostLike'; DisplayName = 'Host Process'; State = 'Running'; StartMode = 'Auto'
                StartName = 'LocalSystem'; PathName = '"C:\Windows\System32\svchost.exe" -k netsvcs'
                Description = ''; ServiceType = 'Share Process'; ProcessId = 1002
            })
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.Services | Where-Object Name -eq 'SvcHostLike'
        $row.ExecutablePath          | Should -Be 'C:\Windows\System32\svchost.exe'
        $row.UnquotedPathWithSpaces  | Should -BeFalse
        $row.IsNonMicrosoftAutoStart | Should -BeFalse
        $row.PathExists              | Should -BeTrue
    }

    It 'does not flag a non-MS service as autostart-risk when its start mode is Manual' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith {
            @([pscustomobject]@{
                Name = 'ManualSvc'; DisplayName = 'Manual Tool'; State = 'Stopped'; StartMode = 'Manual'
                StartName = 'LocalSystem'; PathName = '"C:\Program Files\Other\svc.exe"'
                Description = ''; ServiceType = 'Own Process'; ProcessId = 1003
            })
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.Services | Where-Object Name -eq 'ManualSvc'
        $row.IsNonMicrosoftAutoStart | Should -BeFalse
    }

    It 'flags an executable under C:\Users as running from a user profile' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith {
            @([pscustomobject]@{
                Name = 'ProfileSvc'; DisplayName = 'Profile Tool'; State = 'Running'; StartMode = 'Manual'
                StartName = 'LocalSystem'; PathName = '"C:\Users\svcaccount\AppData\Local\Tool\tool.exe"'
                Description = ''; ServiceType = 'Own Process'; ProcessId = 1004
            })
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.Services | Where-Object Name -eq 'ProfileSvc'
        $row.RunsFromUserProfile | Should -BeTrue
        $row.RunsFromNetworkPath | Should -BeFalse
    }

    It 'flags a UNC executable path as running from a network path' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith {
            @([pscustomobject]@{
                Name = 'NetworkSvc'; DisplayName = 'Network Tool'; State = 'Running'; StartMode = 'Manual'
                StartName = 'LocalSystem'; PathName = '\\fileserver\share\app\app.exe'
                Description = ''; ServiceType = 'Own Process'; ProcessId = 1005
            })
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.Services | Where-Object Name -eq 'NetworkSvc'
        $row.RunsFromNetworkPath    | Should -BeTrue
        $row.UnquotedPathWithSpaces | Should -BeFalse -Because 'the path has no spaces'
    }

    It 'reports a limitation rather than throwing when service enumeration fails outright' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith { throw 'WMI unavailable' }
        { Invoke-DiscoveryCollection -Context $ctx } | Should -Not -Throw
        ($ctx.Limitations | Where-Object { $_.Message -match 'Service enumeration failed' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-DiscoveryCollection - ScheduledTasks via Get-ScheduledTask' {

    BeforeEach {
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith { @() }
        Mock -CommandName Get-CommandAvailable -ModuleName ServicesTasks -MockWith { $true }
    }

    It 'does not count "task is currently running" (267011) or "never run" (267009) as a failure, but does count a real error code' {
        $ctx = New-STTestContext
        Mock -CommandName Get-ScheduledTask -ModuleName ServicesTasks -MockWith {
            @(
                [pscustomobject]@{ TaskName = 'RunningTask'; TaskPath = '\'; State = 'Running'; Actions = @(); Principal = [pscustomobject]@{ UserId = 'SYSTEM'; GroupId = $null; RunLevel = 'Highest' } }
                [pscustomobject]@{ TaskName = 'NeverRunTask'; TaskPath = '\'; State = 'Ready';   Actions = @(); Principal = [pscustomobject]@{ UserId = 'SYSTEM'; GroupId = $null; RunLevel = 'Highest' } }
                [pscustomobject]@{ TaskName = 'FailedTask';  TaskPath = '\'; State = 'Ready';   Actions = @(); Principal = [pscustomobject]@{ UserId = 'SYSTEM'; GroupId = $null; RunLevel = 'Highest' } }
                [pscustomobject]@{ TaskName = 'OkTask';      TaskPath = '\'; State = 'Ready';   Actions = @(); Principal = [pscustomobject]@{ UserId = 'SYSTEM'; GroupId = $null; RunLevel = 'Highest' } }
            )
        }
        Mock -CommandName Get-ScheduledTaskInfo -ModuleName ServicesTasks -MockWith {
            switch ($TaskName) {
                'RunningTask'  { [pscustomobject]@{ LastTaskResult = 267011; LastRunTime = $null; NextRunTime = $null } }
                'NeverRunTask' { [pscustomobject]@{ LastTaskResult = 267009; LastRunTime = $null; NextRunTime = $null } }
                'FailedTask'   { [pscustomobject]@{ LastTaskResult = 1;      LastRunTime = $null; NextRunTime = $null } }
                'OkTask'       { [pscustomobject]@{ LastTaskResult = 0;      LastRunTime = $null; NextRunTime = $null } }
            }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($raw.ScheduledTasks | Where-Object TaskName -eq 'RunningTask').LastRunFailed  | Should -BeFalse
        ($raw.ScheduledTasks | Where-Object TaskName -eq 'NeverRunTask').LastRunFailed | Should -BeFalse
        ($raw.ScheduledTasks | Where-Object TaskName -eq 'FailedTask').LastRunFailed   | Should -BeTrue
        ($raw.ScheduledTasks | Where-Object TaskName -eq 'OkTask').LastRunFailed       | Should -BeFalse
    }

    It 'detects a UNC path, a script action, a backup/export tool, and a domain-account principal from the actions text' {
        $ctx = New-STTestContext
        Mock -CommandName Get-ScheduledTask -ModuleName ServicesTasks -MockWith {
            @([pscustomobject]@{
                TaskName = 'NightlyBackup'; TaskPath = '\Custom\'; State = 'Ready'
                Actions   = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = '-File \\fileserver\scripts\backup.ps1 -Robocopy' })
                Principal = [pscustomobject]@{ UserId = 'CORP\svc-backup'; GroupId = $null; RunLevel = 'Highest' }
            })
        }
        Mock -CommandName Get-ScheduledTaskInfo -ModuleName ServicesTasks -MockWith {
            [pscustomobject]@{ LastTaskResult = 0; LastRunTime = (Get-Date '2026-01-01'); NextRunTime = (Get-Date '2026-01-02') }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.ScheduledTasks | Where-Object TaskName -eq 'NightlyBackup'
        $row.UsesUncPath              | Should -BeTrue
        $row.RunsScript                | Should -BeTrue
        $row.PerformsBackupExportImport | Should -BeTrue
        $row.RunsAsDomainAccount        | Should -BeTrue
    }

    It 'does not flag a plain local-account task with no script/UNC/backup content' {
        $ctx = New-STTestContext
        Mock -CommandName Get-ScheduledTask -ModuleName ServicesTasks -MockWith {
            @([pscustomobject]@{
                TaskName = 'CleanupTemp'; TaskPath = '\'; State = 'Ready'
                Actions   = @([pscustomobject]@{ Execute = 'C:\Windows\System32\cleanmgr.exe'; Arguments = '' })
                Principal = [pscustomobject]@{ UserId = 'SYSTEM'; GroupId = $null; RunLevel = 'Highest' }
            })
        }
        Mock -CommandName Get-ScheduledTaskInfo -ModuleName ServicesTasks -MockWith {
            [pscustomobject]@{ LastTaskResult = 0; LastRunTime = $null; NextRunTime = $null }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $row = $raw.ScheduledTasks | Where-Object TaskName -eq 'CleanupTemp'
        $row.UsesUncPath               | Should -BeFalse
        $row.RunsScript                 | Should -BeFalse
        $row.PerformsBackupExportImport | Should -BeFalse
        $row.RunsAsDomainAccount        | Should -BeFalse
    }
}

Describe 'Invoke-DiscoveryCollection - ScheduledTasks via schtasks.exe fallback' {

    It 'parses schtasks CSV output and skips the duplicate header-as-data-row schtasks /v sometimes emits' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith { @() }
        Mock -CommandName Get-CommandAvailable -ModuleName ServicesTasks -MockWith { $false }
        $stdout = @'
"TaskName","Status","Task To Run","Run As User","Last Result","Last Run Time","Next Run Time"
"TaskName","Status","Task To Run","Run As User","Last Result","Last Run Time","Next Run Time"
"\MyBackupJob","Ready","C:\Scripts\backup.ps1 -Full","CORP\svc-backup","0","1/1/2026 2:00:00 AM","1/2/2026 2:00:00 AM"
'@
        Mock -CommandName Invoke-CommandLineSafe -ModuleName ServicesTasks -MockWith {
            [pscustomobject]@{ Succeeded = $true; StdOut = $stdout; StdErr = ''; ExitCode = 0; TimedOut = $false }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.ScheduledTasks.Count | Should -Be 1 -Because 'the duplicate header row must be skipped, not counted as a task'
        $row = $raw.ScheduledTasks[0]
        $row.TaskName             | Should -Be '\MyBackupJob'
        $row.RunsScript           | Should -BeTrue
        $row.RunsAsDomainAccount  | Should -BeTrue
    }

    It 'logs a limitation when schtasks itself returns nothing usable' {
        $ctx = New-STTestContext
        Mock -CommandName Invoke-CimSafe -ModuleName ServicesTasks -MockWith { @() }
        Mock -CommandName Get-CommandAvailable -ModuleName ServicesTasks -MockWith { $false }
        Mock -CommandName Invoke-CommandLineSafe -ModuleName ServicesTasks -MockWith {
            [pscustomobject]@{ Succeeded = $false; StdOut = ''; StdErr = 'access denied'; ExitCode = 1; TimedOut = $false }
        }
        $raw = Invoke-DiscoveryCollection -Context $ctx
        $raw.ScheduledTasks.Count | Should -Be 0
        ($ctx.Limitations | Where-Object { $_.Message -match 'schtasks fallback did not return data' }) | Should -Not -BeNullOrEmpty
    }
}
