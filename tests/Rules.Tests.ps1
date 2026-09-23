BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Rule pack integrity' {
    BeforeAll { $script:Pack = Get-VsatRulePack }
    It 'has unique rule ids and required fields' {
        $ids = @($script:Pack.rules | ForEach-Object { $_.id })
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        foreach ($r in $script:Pack.rules) {
            foreach ($k in 'id', 'title', 'domain', 'assetType', 'severity', 'check', 'rationale', 'mitigation') { $r.Contains($k) | Should -BeTrue -Because "$($r.id) needs $k" }
            $r.severity | Should -BeIn @('critical', 'high', 'medium', 'low', 'info')
            $r.check.type | Should -BeIn @('setting', 'service', 'script', 'manual')
        }
    }
    It 'references existing evaluators and work packages' {
        $wps = @((Get-VsatRulePackMeta).workPackages | ForEach-Object { $_.id })
        foreach ($r in $script:Pack.rules) {
            if ($r.check.type -eq 'script') { Get-Command "Invoke-VsatCheck$($r.check.name)" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because $r.id }
            $wps | Should -Contain $r.mitigation.workPackage -Because $r.id
        }
    }
    It 'labels every framework mapping with a mapping status and never claims unverified CIS as verified' {
        foreach ($r in $script:Pack.rules) {
            @($r.frameworks).Count | Should -BeGreaterThan 0
            foreach ($f in $r.frameworks) {
                $f.mappingStatus | Should -BeIn @('verified', 'unverified')
                if ($f.framework -like 'CIS*') { $f.mappingStatus | Should -Be 'unverified' }
            }
        }
    }
    It 'maps no CIS control to vCenter or NSX (no CIS benchmark exists for them)' {
        foreach ($r in @($script:Pack.rules | Where-Object { $_.domain -in @('vcenter', 'nsx') })) {
            @($r.frameworks | Where-Object { $_.framework -like 'CIS*' }) | Should -BeNullOrEmpty -Because $r.id
        }
    }
}

Describe 'Evaluation semantics' {
    BeforeAll {
        $script:Rule = @{ id = 'T-1'; title = 't'; domain = 'esxi'; severity = 'low'; rationale = 'r'; check = @{ type = 'setting'; fact = 'advanced'; key = 'X.Y'; op = 'le'; value = 5; absent = 'fail' } }
        function New-A($facts) { [ordered]@{ id = 'a1'; name = 'a1'; type = 'host'; endpoint = 'e'; observedUtc = 'x'; props = [ordered]@{}; facts = $facts } }
    }
    It 'passes when compliant' { (Invoke-VsatSettingCheck -Rule $script:Rule -Asset (New-A @{ advanced = @{ status = 'ok'; value = @{ 'X.Y' = 3 } } }) -Check $script:Rule.check).result | Should -Be 'PASS' }
    It 'fails when non-compliant' { (Invoke-VsatSettingCheck -Rule $script:Rule -Asset (New-A @{ advanced = @{ status = 'ok'; value = @{ 'X.Y' = 9 } } }) -Check $script:Rule.check).result | Should -Be 'FAIL' }
    It 'returns UNKNOWN (never PASS) when access is denied' { (Invoke-VsatSettingCheck -Rule $script:Rule -Asset (New-A @{ advanced = @{ status = 'denied'; value = $null } }) -Check $script:Rule.check).result | Should -Be 'UNKNOWN' }
    It 'returns UNKNOWN when the API is unsupported' { (Invoke-VsatSettingCheck -Rule $script:Rule -Asset (New-A @{ advanced = @{ status = 'unsupported'; value = $null } }) -Check $script:Rule.check).result | Should -Be 'UNKNOWN' }
    It 'returns ERROR when collection failed' { (Invoke-VsatSettingCheck -Rule $script:Rule -Asset (New-A @{ advanced = @{ status = 'error'; value = $null } }) -Check $script:Rule.check).result | Should -Be 'ERROR' }
    It 'returns UNKNOWN when the fact was never collected' { (Invoke-VsatSettingCheck -Rule $script:Rule -Asset (New-A @{}) -Check $script:Rule.check).result | Should -Be 'UNKNOWN' }
    It 'labels product-default assumptions as inferred' {
        $c = @{ type = 'setting'; fact = 'advanced'; key = 'X.Y'; op = 'le'; value = 5; absent = 'default'; default = 1 }
        $f = Invoke-VsatSettingCheck -Rule $script:Rule -Asset (New-A @{ advanced = @{ status = 'ok'; value = @{} } }) -Check $c
        $f.result | Should -Be 'PASS'; $f.confidence | Should -Be 'inferred'
    }
    It 'compares booleans and numeric strings robustly' {
        Test-VsatOperator 'TRUE' 'eq' $true | Should -BeTrue
        Test-VsatOperator '600' 'range' @(1, 600) | Should -BeTrue
        Test-VsatOperator 'abc' 'le' 5 | Should -BeFalse
    }
    It 'applies profile overrides (strict lockdown)' {
        $ev = Get-TestEvidence
        $std = Get-TestResults -Evidence $ev -ProfileName standard
        (Get-TestFinding $std 'ESXI-LOCKDOWN' 'esx01.example.local').result | Should -Be 'PASS'
        $ev2 = Get-TestEvidence
        $strict = Get-TestResults -Evidence $ev2 -ProfileName strict
        (Get-TestFinding $strict 'ESXI-LOCKDOWN' 'esx01.example.local').result | Should -Be 'FAIL'
        (Get-TestFinding $strict 'ESXI-LOCKDOWN' 'esx04.example.local').result | Should -Be 'PASS'
    }
    It 'keeps exceptions visible and never turns FAIL into PASS; expired exceptions return to the worklist' {
        $r = Get-TestResults
        $ssh = Get-TestFinding $r 'ESXI-SVC-SSH' 'esx02.example.local'
        $ssh.result | Should -Be 'FAIL'; $ssh.exception.active | Should -BeTrue
        $gpu = Get-TestFinding $r 'VM-PASSTHROUGH' 'ai-train01'
        $gpu.result | Should -Be 'FAIL'; $gpu.exception.active | Should -BeFalse
        $wpIds = @($r.analysis.workPackages | ForEach-Object { $_.findingIds })
        $wpIds | Should -Not -Contain $ssh.id
        $wpIds | Should -Contain $gpu.id
    }
    It 'honours scope exclusions' {
        $r = Get-TestResults
        @($r.findings | Where-Object { $_.assetName -eq 'lab-test01' }) | Should -BeNullOrEmpty
    }
}
