BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\..\modules\RoleUsage\RoleUsage.psd1') -Force }
Describe 'Get-RoleUsageVerdict' {
    It 'is Unknown without an evidence source' { Get-RoleUsageVerdict $null 14 | Should -Be 'Unknown' }
    It 'is Active when events exist'           { Get-RoleUsageVerdict 3 14 | Should -Be 'Active' }
    It 'reports no activity only with a window' { Get-RoleUsageVerdict 0 14 | Should -Be 'No activity in window' }
    It 'never claims absence without a window'  { Get-RoleUsageVerdict 0 0 | Should -Be 'Unknown' }
}
