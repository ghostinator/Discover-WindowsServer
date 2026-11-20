BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\..\modules\Certificates\Certificates.psd1') -Force }
Describe 'ConvertTo-CaIssuanceSummary' {
    BeforeAll {
        $now = [datetime]'2026-11-20'
        $lines = @('"Issued Request ID","Request Submission Date","Certificate Template"',
            ('"{0}","WebServer"' -f $now.AddDays(-5).ToString('s')), ('"{0}","WebServer"' -f $now.AddDays(-60).ToString('s')),
            ('"{0}",""' -f $now.AddDays(-200).ToString('s')), '', 'CertUtil: -view command completed successfully.')
        $r = ConvertTo-CaIssuanceSummary -Lines $lines -Now $now
    }
    It 'counts by window'      { $r.IssuedInLookback | Should -Be 3; $r.Issued30d | Should -Be 1; $r.Issued90d | Should -Be 2 }
    It 'reports last issued'   { $r.LastIssued | Should -Be '2026-11-15 00:00' }
    It 'ranks templates'       { $r.TopTemplates | Should -Match '^WebServer \(2\); \(none\) \(1\)$' }
    It 'handles empty output'  { (ConvertTo-CaIssuanceSummary -Lines @()).IssuedInLookback | Should -Be 0 }
}
