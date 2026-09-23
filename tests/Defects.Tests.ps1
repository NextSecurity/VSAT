# Regression tests for the defects identified in VSAT 1.x (plan section 2).
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe '1.x defect: static ESXi 7.0.3 VIB equality used as patch assessment' {
    It 'evaluates build ranges per fix line (8.0 U2 vs U3) instead of VIB equality' {
        $a = [ordered]@{ id = 'h'; name = 'h'; type = 'host'; endpoint = 'e'; observedUtc = 'x'; version = '8.0.2'; build = '24585300'; props = [ordered]@{}; facts = [ordered]@{} }
        $ctx = @{ now = [datetime]'2026-09-23' }
        $rule = (Get-VsatRulePack).rules | Where-Object { $_.id -eq 'ESXI-PATCH-ADV' }
        $f = Invoke-VsatCheckAdvisory -Rule $rule -Asset $a -Check $rule.check -Context $ctx
        # 8.0 U2d (24585300) fixes VMSA-2025-0004 on the U2 line but is below U2e for VMSA-2025-0013.
        $f.result | Should -Be 'FAIL'
        $f.observed | Should -Match 'VMSA-2025-0013'
        $f.observed | Should -Not -Match 'VMSA-2025-0004'
    }
    It 'passes a fully patched host within the snapshot' {
        $a = [ordered]@{ id = 'h'; name = 'h'; type = 'host'; endpoint = 'e'; observedUtc = 'x'; version = '8.0.3'; build = '25595708'; props = [ordered]@{}; facts = [ordered]@{} }
        $rule = (Get-VsatRulePack).rules | Where-Object { $_.id -eq 'ESXI-PATCH-ADV' }
        (Invoke-VsatCheckAdvisory -Rule $rule -Asset $a -Check $rule.check -Context @{ now = [datetime]::UtcNow }).result | Should -Be 'PASS'
    }
    It 'returns UNKNOWN (not PASS) for a branch without advisory data (e.g. ESX 9.0)' {
        $a = [ordered]@{ id = 'h'; name = 'h'; type = 'host'; endpoint = 'e'; observedUtc = 'x'; version = '9.0.0'; build = '24755229'; props = [ordered]@{}; facts = [ordered]@{} }
        $rule = (Get-VsatRulePack).rules | Where-Object { $_.id -eq 'ESXI-PATCH-ADV' }
        (Invoke-VsatCheckAdvisory -Rule $rule -Asset $a -Check $rule.check -Context @{ now = [datetime]::UtcNow }).result | Should -Be 'UNKNOWN'
    }
    It 'treats a line with no public fix as exposed' {
        $a = [ordered]@{ id = 'h'; name = 'h'; type = 'host'; endpoint = 'e'; observedUtc = 'x'; version = '7.0.3'; build = '99999999'; props = [ordered]@{}; facts = [ordered]@{} }
        $rule = (Get-VsatRulePack).rules | Where-Object { $_.id -eq 'ESXI-PATCH-ADV' }
        (Invoke-VsatCheckAdvisory -Rule $rule -Asset $a -Check $rule.check -Context @{ now = [datetime]::UtcNow }).observed | Should -Match 'no public fix'
    }
}

Describe '1.x defect: boolean adminDisabled compared with normal/strict strings' {
    It 'uses the lockdownMode enum: <Mode> => <Expected>' -ForEach @(
        @{ Mode = 'lockdownDisabled'; Expected = 'FAIL' }, @{ Mode = 'lockdownNormal'; Expected = 'PASS' }, @{ Mode = 'lockdownStrict'; Expected = 'PASS' }
    ) {
        $ev = Get-TestEvidence
        (Get-TestAsset $ev 'esx01.example.local' 'host').facts.lockdown.value.mode = $Mode
        (Get-TestFinding (Get-TestResults $ev) 'ESXI-LOCKDOWN' 'esx01.example.local').result | Should -Be $Expected
    }
    It 'reports UNKNOWN when lockdownMode is not exposed' {
        $ev = Get-TestEvidence
        (Get-TestAsset $ev 'esx01.example.local' 'host').facts.lockdown = [ordered]@{ status = 'unsupported'; value = $null }
        (Get-TestFinding (Get-TestResults $ev) 'ESXI-LOCKDOWN' 'esx01.example.local').result | Should -Be 'UNKNOWN'
    }
}

Describe '1.x defect: distributed-switch checks relied on object existence' {
    It 'detects an effective per-port promiscuous override' {
        $r = Get-TestResults
        (Get-TestFinding $r 'NET-VDS-PORT-OVERRIDES' 'dvpg-app').result | Should -Be 'FAIL'
        (Get-TestFinding $r 'NET-VDS-PORT-OVERRIDES' 'dvpg-web').result | Should -Be 'PASS'
    }
    It 'evaluates effective standard port group policy (override merged over vSwitch)' {
        (Get-TestFinding (Get-TestResults) 'NET-VSS-PROMISC' 'esx04.example.local DMZ-Trunk').result | Should -Be 'FAIL'
    }
    It 'ignores uplink port groups' {
        (Get-TestFinding (Get-TestResults) 'NET-VDS-PROMISC' 'dvs-prod-uplinks').result | Should -Be 'NOT_APPLICABLE'
    }
}

Describe '1.x defect: hardcoded native VLAN 1' {
    It 'returns UNKNOWN without operator scope or neighbor evidence' {
        $ev = Get-TestEvidence
        $ev.scope.nativeVlans = @()
        $ev.relationships = New-VsatList @($ev.relationships | Where-Object { $_.type -ne 'neighbor' })
        @(Get-TestFinding (Get-TestResults $ev) 'NET-VLAN-NATIVE' | Where-Object { $_.result -ne 'UNKNOWN' }) | Should -BeNullOrEmpty
    }
    It 'uses operator-scoped native VLAN when supplied' {
        $ev = Get-TestEvidence
        $ev.scope.nativeVlans = @(@{ switch = '*'; vlan = 10 })
        (Get-TestFinding (Get-TestResults $ev) 'NET-VLAN-NATIVE' 'esx01.example.local Management Network').result | Should -Be 'FAIL'
    }
    It 'uses CDP/LLDP neighbor evidence as inferred when no scope is supplied' {
        $ev = Get-TestEvidence
        $ev.scope.nativeVlans = @()
        $f = Get-TestFinding (Get-TestResults $ev) 'NET-VLAN-NATIVE' 'esx01.example.local Management Network'
        $f.result | Should -Be 'PASS'; $f.confidence | Should -Be 'inferred'
    }
}

Describe '1.x defect: zero-object loops returned success' {
    It 'marks an empty but successfully collected scope as assessed with an explicit empty-scope note, not a pass' {
        $ev = Get-TestEvidence
        $ev.assets = New-VsatList @($ev.assets | Where-Object { $_.type -ne 'datastore' })
        $r = Get-TestResults $ev
        $d = $r.coverage.domains | Where-Object { $_.id -eq 'storage' }
        $d.detail | Should -Match 'not a pass|object\(s\)'
    }
    It 'marks a denied collector as incomplete coverage (exit code 2)' {
        $ev = Get-TestEvidence
        ($ev.collection.collectors | Where-Object { $_.name -eq 'vsphere.vms' }).status = 'denied'
        $r = Get-TestResults $ev
        ($r.coverage.domains | Where-Object { $_.id -eq 'vm' }).state | Should -Be 'INCOMPLETE'
        $r.status.exitCode | Should -Be 2
    }
    It 'returns NOT_APPLICABLE for hosts without iSCSI adapters instead of PASS' {
        (Get-TestFinding (Get-TestResults) 'ESXI-ISCSI-CHAP' 'esx02.example.local').result | Should -Be 'NOT_APPLICABLE'
    }
}

Describe '1.x defect: persistent PowerCLI certificate-policy change' {
    It 'contains no user/all-users scope PowerCLI configuration change' {
        $src = [IO.File]::ReadAllText($script:VsatScript)
        $src | Should -Not -Match 'Set-PowerCLIConfiguration[^\r\n]*-Scope\s+(User|AllUsers)'
    }
}
