# OT / ICS segmentation lens (virtualization layer only).
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:X = Get-OtEvidence
    $script:R = Get-TestResults $script:X.evidence
}
Describe 'OT segmentation lens' {
    It 'is NOT_APPLICABLE when no zone declares a Purdue level' {
        $r = Get-TestResults (Get-TestEvidence)
        $d = $r.coverage.domains | Where-Object id -eq 'ot-segmentation'
        $d.state | Should -Be 'NOT_APPLICABLE'
        $d.mandatory | Should -BeFalse
        @($d.evidence) | Should -Contain 'No zone declares a Purdue level'
        @($r.findings | Where-Object { $_.domain -eq 'ot-segmentation' -and $_.result -ne 'NOT_APPLICABLE' }) | Should -BeNullOrEmpty
        @($r.findings | Where-Object { $_.domain -eq 'ot-segmentation' }).Count | Should -BeGreaterThan 0
        @($r.analysis.blastRadius.nodes | Where-Object { $_.crownReason -match 'OT workload' }) | Should -BeNullOrEmpty
    }
    It 'keeps the lens off (no purdueLevel on assets) without Purdue levels' {
        $ev = Get-TestEvidence
        Set-VsatScopeAnnotations -Evidence $ev
        @($ev.assets | Where-Object { $_.Contains('purdueLevel') }) | Should -BeNullOrEmpty
        Get-VsatOtClass (@($ev.assets | Where-Object type -eq 'vm')[0]) | Should -BeNullOrEmpty
    }
    It 'classifies OT, IT and DMZ assets when the lens is on' {
        $ev = (Get-OtEvidence).evidence
        Set-VsatScopeAnnotations -Evidence $ev
        $vm = @($ev.assets | Where-Object type -eq 'vm' | Sort-Object { $_.id })
        $vm[0].purdueLevel | Should -Be 2
        Get-VsatOtClass $vm[0] | Should -Be 'ot'
        Get-VsatOtClass $vm[5] | Should -Be 'it'
        Get-VsatOtClass ([ordered]@{ id = 'x'; type = 'vm'; purdueLevel = 'dmz' }) | Should -Be 'dmz'
        Get-VsatOtClass ([ordered]@{ id = 'x'; type = 'vm'; purdueLevel = 5 }) | Should -Be 'it'
        Get-VsatOtClass (@($ev.assets | Where-Object type -eq 'host')[0]) | Should -BeNullOrEmpty
    }
    It 'annotates Purdue levels and makes OT workloads crown jewels' {
        foreach ($n in $script:X.otNames) {
            @($script:R.analysis.blastRadius.nodes | Where-Object { $_.name -eq $n -and $_.crown -and $_.crownReason -match 'OT workload \(Purdue L2\)' }).Count | Should -Be 1
        }
    }
    It 'reports the domain as assessed and optional when Purdue levels are declared' {
        $d = $script:R.coverage.domains | Where-Object id -eq 'ot-segmentation'
        $d.state | Should -BeIn @('ASSESSED', 'PARTIAL')
        $d.mandatory | Should -BeFalse
    }
    It 'flags a host that runs OT and IT workloads together' {
        @($script:R.findings | Where-Object { $_.ruleId -eq 'OT-SHARED-HOST' -and $_.result -eq 'FAIL' }).Count | Should -BeGreaterThan 0
        @($script:R.findings | Where-Object { $_.ruleId -eq 'OT-SHARED-HOST' -and $_.result -eq 'PASS' }) | Should -BeNullOrEmpty
    }
    It 'passes a host that runs only OT workloads' {
        $x = Get-OtEvidence
        $h = @($x.evidence.assets | Where-Object { $_.type -eq 'host' -and $_.id -like '*:host-40' })[0]
        $guests = @($x.evidence.relationships | Where-Object { $_.type -eq 'runs-on' -and $_.target -eq $h.id } | ForEach-Object { $_.source })
        foreach ($v in @($x.evidence.assets | Where-Object { $_.id -in $guests })) { $v.tags = @(@($v.tags) + 'zone=plant-l2') }
        $r = Get-TestResults $x.evidence
        @(Get-TestFinding $r 'OT-SHARED-HOST' $h.name)[0].result | Should -Be 'PASS'
    }
    It 'flags a virtual switch shared by OT and IT workloads' {
        @($script:R.findings | Where-Object { $_.ruleId -eq 'OT-SHARED-VSWITCH' -and $_.result -eq 'FAIL' }).Count | Should -BeGreaterThan 0
    }
    It 'flags the shared management plane' {
        @(Get-TestFinding $script:R 'OT-SHARED-MGMT')[0].result | Should -Be 'FAIL'
    }
    It 'flags an identity that administers OT and IT hosts' {
        $f = @($script:R.findings | Where-Object { $_.ruleId -eq 'OT-IT-ADMIN' -and $_.result -eq 'FAIL' })
        $f.Count | Should -BeGreaterThan 0
        $f[0].observed | Should -Match 'IT'
    }
    It 'reports IT-to-OT reachability with the path narrative' {
        $f = @($script:R.findings | Where-Object { $_.ruleId -eq 'OT-IT-PATH' -and $_.result -eq 'FAIL' })
        $f.Count | Should -BeGreaterThan 0
        $f[0].observed | Should -Match '→'
        $f[0].severity | Should -Be 'critical'
    }
    It 'is NOT_APPLICABLE for OT-IT-PATH and OT-DMZ-BYPASS on IT workloads' {
        $it = @($script:R.findings | Where-Object { $_.ruleId -in @('OT-IT-PATH', 'OT-DMZ-BYPASS') -and $_.assetName -notin $script:X.otNames })
        $it.Count | Should -BeGreaterThan 0
        @($it | Where-Object result -ne 'NOT_APPLICABLE') | Should -BeNullOrEmpty
    }
    It 'OT-IT-PATH is UNKNOWN, not PASS, when NSX policy was not assessed and no other path exists' {
        $x = Get-OtEvidence; Remove-TestNsx $x.evidence
        $r = Get-TestResults $x.evidence
        @($r.findings | Where-Object { $_.ruleId -eq 'OT-IT-PATH' -and $_.result -eq 'PASS' -and $_.assetType -eq 'vm' }) | Should -BeNullOrEmpty
        @($r.findings | Where-Object { $_.ruleId -eq 'OT-DMZ-BYPASS' -and $_.result -eq 'PASS' -and $_.assetType -eq 'vm' }) | Should -BeNullOrEmpty
    }
    It 'flags a direct IT-to-OT network edge that skips the DMZ' {
        $f = @($script:R.findings | Where-Object { $_.ruleId -eq 'OT-DMZ-BYPASS' -and $_.assetName -in $script:X.otNames })
        $f.Count | Should -Be 2
        @($f | Where-Object result -eq 'PASS') | Should -BeNullOrEmpty
    }
    It 'lists IT workloads before principals as blast-radius entries when the lens is on' {
        $first = $script:R.analysis.blastRadius.entries | Select-Object -First 1
        $id = if ($first -is [string]) { $first } else { $first.id }
        $script:VsatAssetIndex[$id].type | Should -Be 'vm'
    }
    It 'never contacts anything new: OT rules only read existing facts and relationships' {
        (Get-Content (Join-Path $script:RepoRoot 'src/66-EvaluatorsOt.ps1') -Raw) | Should -Not -Match '(?i)Invoke-(Rest|Web)|Connect-|Get-View|ssh|virsh'
    }
    It 'defines the six OT rules and the OT work package' {
        $ids = @((Get-VsatRulePack).rules | Where-Object domain -eq 'ot-segmentation' | ForEach-Object id)
        ($ids | Sort-Object) -join ',' | Should -Be 'OT-DMZ-BYPASS,OT-IT-ADMIN,OT-IT-PATH,OT-SHARED-HOST,OT-SHARED-MGMT,OT-SHARED-VSWITCH'
        @((Get-VsatRulePackMeta).workPackages | ForEach-Object id) | Should -Contain 'WP-OT-SEGMENTATION'
    }
}
