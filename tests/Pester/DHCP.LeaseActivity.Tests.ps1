BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\..\modules\DHCP\DHCP.psd1') -Force }
Describe 'ConvertTo-DhcpLeaseSummary' {
    BeforeAll {
        $r = ConvertTo-DhcpLeaseSummary -Lines @('ID,Date,Time,Description', '24,11/16/26,00:00:30,Database Cleanup Begin,,,,,0,6',
            '10,11/17/26,08:15:00,Assign,10.0.0.5,pc1,AABBCC,,1,6', '11,11/18/26,09:00:00,Renew,10.0.0.5,pc1,AABBCC,,2,6',
            '12,11/19/26,10:30:00,Release,10.0.0.5,pc1,AABBCC,,3,6', 'garbage', '25,11/20/26,00:00:30,Cleanup,,,,,0,6')
    }
    It 'counts lease events'          { $r.NewLeases | Should -Be 1; $r.Renewals | Should -Be 1; $r.Releases | Should -Be 1 }
    It 'finds the last lease event'   { $r.LastLeaseEvent | Should -Be '2026-11-19 10:30' }
    It 'measures coverage from all dated rows' { $r.CoverageDays | Should -Be 4 }
    It 'reports zero events on housekeeping-only logs' { (ConvertTo-DhcpLeaseSummary -Lines @('24,11/19/26,00:00:30,Cleanup,,,,,0,6')).NewLeases | Should -Be 0 }
}
