BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\..\modules\RoleUsage\RoleUsage.psd1') -Force }
Describe 'Get-RoleUsageVerdict' {
    It 'is Unknown without an evidence source' { Get-RoleUsageVerdict $null 14 | Should -Be 'Unknown' }
    It 'is Active when events exist'           { Get-RoleUsageVerdict 3 14 | Should -Be 'Active' }
    It 'is Light/Occasional when recent volume is under the threshold' { Get-RoleUsageVerdict 12 365 1 5 | Should -Be 'Light/Occasional' }
    It 'is Active at or above the threshold'   { Get-RoleUsageVerdict 40 365 5 5 | Should -Be 'Active' }
    It 'keeps the band for old-only activity'  { Get-RoleUsageVerdict 3 365 0 5 | Should -Be 'Light/Occasional' }
    It 'reports no activity only with a window' { Get-RoleUsageVerdict 0 14 | Should -Be 'No activity in window' }
    It 'never claims absence without a window'  { Get-RoleUsageVerdict 0 0 | Should -Be 'Unknown' }
}
Describe 'IIS / DNS usage helpers' {
    BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\..\modules\IIS\IIS.psd1') -Force; Import-Module (Join-Path $PSScriptRoot '..\..\modules\DNS\DNS.psd1') -Force }
    It 'summarises W3C log files' {
        $now = [datetime]'2026-11-20'
        $r = ConvertTo-IisLogSummary -Now $now -WindowDays 14 -Files @(
            [pscustomobject]@{ LastWriteTime=$now.AddDays(-2); Requests=40 }, [pscustomobject]@{ LastWriteTime=$now.AddDays(-5); Requests=0 }, [pscustomobject]@{ LastWriteTime=$now.AddDays(-30); Requests=0 })
        $r.LogFiles | Should -Be 2; $r.Requests | Should -Be 40; $r.LastRequest | Should -Be '2026-11-18 00:00'; $r.CoverageDays | Should -Be 30
    }
    It 'computes DNS query rate' { (Get-DnsQueryRate -TotalQueries 200 -StartTime ([datetime]'2026-11-18') -Now ([datetime]'2026-11-20')).QueriesPerDay | Should -Be 100 }
}
Describe 'Get-EventUsageSummary' {
    BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\..\modules\RoleUsageEvidence\RoleUsageEvidence.psd1') -Force }
    It 'counts, finds the last event and caps coverage at the window' {
        $now = [datetime]'2026-11-20'
        $r = Get-EventUsageSummary -Times @($now.AddDays(-1), $now.AddDays(-3)) -OldestAvailable $now.AddDays(-90) -WindowDays 14 -Now $now
        $r.Count | Should -Be 2; $r.Last | Should -Be '2026-11-19 00:00'; $r.CoverageDays | Should -Be 14
    }
    It 'reports short log retention as short coverage' { (Get-EventUsageSummary -Times @() -OldestAvailable ([datetime]'2026-11-18') -WindowDays 14 -Now ([datetime]'2026-11-20')).CoverageDays | Should -Be 2 }
}
