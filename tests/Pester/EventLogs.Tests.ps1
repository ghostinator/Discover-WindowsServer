#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    EventLogs.Tests.ps1 - fixture-based tests for the event log / audit policy collector.

    First-time coverage for this module. Picked because a 2026-09-29 module audit found two
    real, connected gaps: the Security event log was declared reachable (a limitation message
    existed specifically for it failing) but was never actually added to the log list being
    queried, and there was no audit policy (auditpol) collection at all despite the module
    claiming ProducesRisks=$true. Both are fixed here: 'Security' is now attempted only when
    Context.IsAdmin, and Get-AuditPolicySettings/the AuditPolicyGaps derivation are new.

    Get-AuditPolicySettings's fixture text is a real excerpt (not guessed) from
    `auditpol /get /category:*` captured live on a Server 2025 box - category headers at column
    0, subcategory lines indented two spaces, blank lines between entries.
#>

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $Root 'modules\Core\Core.psm1')           -Force -DisableNameChecking
    Import-Module (Join-Path $Root 'modules\EventLogs\EventLogs.psm1') -Force -DisableNameChecking
    $script:Config = Get-DiscoveryConfigBundle -ConfigDirectory (Join-Path $Root 'config')

    function New-EvtTestContext {
        param([bool]$IsAdmin = $false)
        New-DiscoveryContext -Mode Fast -Config $script:Config -IsAdmin $IsAdmin
    }

    # Real captured shape, trimmed to a representative excerpt rather than the full ~60
    # subcategories: covers a category transition, and all three Setting values that matter to
    # the parser (No Auditing / Success / Success and Failure).
    $script:RealAuditPolOutput = @"
System audit policy

Category/Subcategory                      Setting
System
  Security System Extension               No Auditing

  System Integrity                        Success and Failure

  Security State Change                   Success

Logon/Logoff
  Logon                                   Success and Failure

  Account Lockout                         No Auditing

Account Management
  User Account Management                 Success
"@
}

Describe 'Get-AuditPolicySettings' {
    # NOTE: always assign the function's result to a variable BEFORE wrapping in @() for
    # .Count - never @(Get-AuditPolicySettings).Count directly. The function returns ,@($list);
    # wrapping the CALL ITSELF in @() nests the result one level deeper instead of flattening it
    # (confirmed live while writing this file - the exact footgun documented in TODO.md item 8
    # for Get-FingerprintMatches, and re-hit independently while writing
    # Get-SensitiveUserRightsGrants's own tests earlier this session).

    It 'returns an empty array when auditpol.exe is not available' {
        Mock -CommandName Get-CommandAvailable -ModuleName EventLogs -MockWith { $false }
        $rows = Get-AuditPolicySettings
        @($rows).Count | Should -Be 0
    }

    It 'returns an empty array, not a throw, when the auditpol call fails' {
        Mock -CommandName Get-CommandAvailable -ModuleName EventLogs -MockWith { $true }
        Mock -CommandName Invoke-CommandLineSafe -ModuleName EventLogs -MockWith { [pscustomobject]@{ Succeeded = $false; StdOut = ''; StdErr = 'denied'; ExitCode = 1; TimedOut = $false } }
        { Get-AuditPolicySettings } | Should -Not -Throw
        $rows = Get-AuditPolicySettings
        @($rows).Count | Should -Be 0
    }

    It 'parses category, subcategory, and setting from real auditpol output' {
        Mock -CommandName Get-CommandAvailable -ModuleName EventLogs -MockWith { $true }
        Mock -CommandName Invoke-CommandLineSafe -ModuleName EventLogs -MockWith {
            [pscustomobject]@{ Succeeded = $true; StdOut = $script:RealAuditPolOutput; StdErr = ''; ExitCode = 0; TimedOut = $false }
        }
        $rows = Get-AuditPolicySettings
        @($rows).Count | Should -Be 6

        $logon = $rows | Where-Object { $_.Subcategory -eq 'Logon' }
        $logon.Category | Should -Be 'Logon/Logoff'
        $logon.Setting  | Should -Be 'Success and Failure'

        $lockout = $rows | Where-Object { $_.Subcategory -eq 'Account Lockout' }
        $lockout.Category | Should -Be 'Logon/Logoff'
        $lockout.Setting  | Should -Be 'No Auditing'

        $uam = $rows | Where-Object { $_.Subcategory -eq 'User Account Management' }
        $uam.Category | Should -Be 'Account Management'
        $uam.Setting  | Should -Be 'Success'
    }

    It 'does not mistake the header lines for a category name' {
        Mock -CommandName Get-CommandAvailable -ModuleName EventLogs -MockWith { $true }
        Mock -CommandName Invoke-CommandLineSafe -ModuleName EventLogs -MockWith {
            [pscustomobject]@{ Succeeded = $true; StdOut = $script:RealAuditPolOutput; StdErr = ''; ExitCode = 0; TimedOut = $false }
        }
        $rows = Get-AuditPolicySettings
        ($rows.Category -contains 'System audit policy')       | Should -BeFalse
        ($rows.Category -contains 'Category/Subcategory')      | Should -BeFalse
        ($rows | Where-Object { $_.Subcategory -eq 'Security System Extension' }).Category | Should -Be 'System'
    }
}

Describe 'Invoke-DiscoveryCollection - audit policy gap detection' {
    BeforeEach {
        Mock -CommandName Get-WinEvent -ModuleName EventLogs -MockWith { @() }
    }

    It 'flags a curated critical subcategory set to No Auditing' {
        Mock -CommandName Get-AuditPolicySettings -ModuleName EventLogs -MockWith {
            ,@(
                [pscustomobject]@{ Category = 'Logon/Logoff'; Subcategory = 'Logon'; Setting = 'No Auditing' }
                [pscustomobject]@{ Category = 'System';       Subcategory = 'IPsec Driver'; Setting = 'No Auditing' }
            )
        }
        $raw = Invoke-DiscoveryCollection -Context (New-EvtTestContext)
        $gaps = @($raw.AuditPolicyGaps)
        $gaps.Count | Should -Be 1
        $gaps[0].Subcategory | Should -Be 'Logon'
    }

    It 'does not flag a subcategory outside the curated critical list, even if set to No Auditing' {
        Mock -CommandName Get-AuditPolicySettings -ModuleName EventLogs -MockWith {
            ,@([pscustomobject]@{ Category = 'System'; Subcategory = 'IPsec Driver'; Setting = 'No Auditing' })
        }
        $raw = Invoke-DiscoveryCollection -Context (New-EvtTestContext)
        @($raw.AuditPolicyGaps).Count | Should -Be 0
    }

    It 'does not flag a critical subcategory that is actually being audited' {
        Mock -CommandName Get-AuditPolicySettings -ModuleName EventLogs -MockWith {
            ,@([pscustomobject]@{ Category = 'Logon/Logoff'; Subcategory = 'Logon'; Setting = 'Success and Failure' })
        }
        $raw = Invoke-DiscoveryCollection -Context (New-EvtTestContext)
        @($raw.AuditPolicyGaps).Count | Should -Be 0
    }

    It 'logs a limitation when audit policy could not be read at all' {
        Mock -CommandName Get-AuditPolicySettings -ModuleName EventLogs -MockWith { ,@() }
        $ctx = New-EvtTestContext
        Invoke-DiscoveryCollection -Context $ctx | Out-Null
        ($ctx.Limitations | Where-Object { $_.Message -match 'Audit policy .* could not be read' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-DiscoveryCollection - Security log elevation gating' {
    BeforeEach {
        Mock -CommandName Get-AuditPolicySettings -ModuleName EventLogs -MockWith { ,@() }
    }

    It 'never queries the Security log when not elevated, and logs why' {
        Mock -CommandName Get-WinEvent -ModuleName EventLogs -MockWith { @() }
        $ctx = New-EvtTestContext -IsAdmin $false
        Invoke-DiscoveryCollection -Context $ctx | Out-Null
        Should -Invoke -CommandName Get-WinEvent -ModuleName EventLogs -ParameterFilter { $FilterHashtable.LogName -eq 'Security' } -Times 0
        ($ctx.Limitations | Where-Object { $_.Message -match 'Security log not sampled' }) | Should -Not -BeNullOrEmpty
    }

    It 'queries the Security log when elevated' {
        Mock -CommandName Get-WinEvent -ModuleName EventLogs -MockWith { @() }
        $ctx = New-EvtTestContext -IsAdmin $true
        Invoke-DiscoveryCollection -Context $ctx | Out-Null
        Should -Invoke -CommandName Get-WinEvent -ModuleName EventLogs -ParameterFilter { $FilterHashtable.LogName -eq 'Security' } -Times 1
    }

    It 'records a reachable limitation (not the old unreachable one) if the Security log query fails even while elevated' {
        Mock -CommandName Get-WinEvent -ModuleName EventLogs -MockWith {
            if ($FilterHashtable.LogName -eq 'Security') { throw 'Access is denied.' }
            @()
        }
        $ctx = New-EvtTestContext -IsAdmin $true
        Invoke-DiscoveryCollection -Context $ctx | Out-Null
        ($ctx.Limitations | Where-Object { $_.Message -match 'Security log query failed even though this run was elevated' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-DiscoveryCollection - filtered, capped event queries' {
    # Regression: the module used to load EVERY event in the window and timed out the 600s
    # deadline on a lab DC with 180k Security records, losing all of its data.
    BeforeEach {
        Mock -CommandName Get-AuditPolicySettings -ModuleName EventLogs -MockWith { ,@() }
    }

    It 'asks only for levels 1-3 (or audit failures for Security), with a MaxEvents cap' {
        Mock -CommandName Get-WinEvent -ModuleName EventLogs -MockWith { @() }
        Invoke-DiscoveryCollection -Context (New-EvtTestContext -IsAdmin $true) | Out-Null
        Should -Invoke -CommandName Get-WinEvent -ModuleName EventLogs -Times 1 -ParameterFilter {
            $FilterHashtable.LogName -eq 'System' -and (@($FilterHashtable.Level) -join ',') -eq '1,2,3' -and $MaxEvents -gt 0
        }
        Should -Invoke -CommandName Get-WinEvent -ModuleName EventLogs -Times 1 -ParameterFilter {
            $FilterHashtable.LogName -eq 'Security' -and $FilterHashtable.Keywords -eq 4503599627370496 -and $MaxEvents -gt 0
        }
    }

    It 'treats NoMatchingEventsFound as a clean zero, not a failed Security query' {
        Mock -CommandName Get-WinEvent -ModuleName EventLogs -MockWith {
            if ($FilterHashtable) {
                throw [System.Management.Automation.ErrorRecord]::new([Exception]::new('No events were found that match the specified selection criteria.'), 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', 'ObjectNotFound', $null)
            }
        }
        $ctx = New-EvtTestContext -IsAdmin $true
        $raw = Invoke-DiscoveryCollection -Context $ctx
        ($ctx.Limitations | Where-Object { $_.Message -match 'Security log query failed' }) | Should -BeNullOrEmpty
        $sec = @($raw.EventLogSummary | Where-Object { $_.LogName -eq 'Security' })
        $sec.Count | Should -Be 1
        $sec[0].AuditFailureCount | Should -Be 0
    }

    It 'counts levels per log and samples only critical/error events' {
        Mock -CommandName Get-WinEvent -ModuleName EventLogs -MockWith {
            if ($FilterHashtable.LogName -eq 'System') {
                [pscustomobject]@{ Level = 2; Id = 7001; TimeCreated = (Get-Date); LevelDisplayName = 'Error';   ProviderName = 'P'; Message = 'err' }
                [pscustomobject]@{ Level = 3; Id = 1014; TimeCreated = (Get-Date); LevelDisplayName = 'Warning'; ProviderName = 'P'; Message = 'warn' }
            }
        }
        $raw = Invoke-DiscoveryCollection -Context (New-EvtTestContext -IsAdmin $false)
        $sys = @($raw.EventLogSummary | Where-Object { $_.LogName -eq 'System' })[0]
        $sys.ErrorCount   | Should -Be 1
        $sys.WarningCount | Should -Be 1
        $sys.QueryCapped  | Should -BeFalse
        @($raw.EventLogSamples | Where-Object { $_.LogName -eq 'System' }).Id | Should -Be @(7001)
    }
}
