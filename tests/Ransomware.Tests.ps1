# Ransomware readiness: tagged rules, backupSystems scope key, RW-* rules, one-account reach.
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:SpecTags = @('ESXI-PATCH-ADV', 'VC-PATCH-ADV', 'ESXI-EXEC-INSTALLED-ONLY', 'ESXI-ACCEPTANCE', 'ESXI-AD-ADMINS-GROUP', 'ESXI-AD-ADMINS-AUTOADD', 'ESXI-LOCKDOWN', 'ESXI-SVC-SSH', 'ESXI-SVC-SHELL', 'ESXI-SVC-SLP', 'ESXI-SYSLOG-REMOTE', 'VC-ADMIN-USERS', 'NSX-MGR-BACKUP', 'ST-RECOVERY-EVIDENCE', 'HV-OS-PATCH-AGE', 'HV-ADMINS', 'KVM-OS-PATCH-AGE', 'KVM-SSH-ROOT', 'KVM-SSH-PASSWORD', 'KVM-LIBVIRT-GROUP')
    $script:RwIds = @('RW-BACKUP-COLOCATED', 'RW-BACKUP-REACHABLE', 'RW-BACKUP-SHARED-ADMIN')

    function Get-RwEvidence {
        # Demo lab with backup01 (esx02, cluster cl-prod) declared as backup infrastructure.
        $ev = Get-TestEvidence
        $ev.scope.backupSystems = @(@{ match = 'name:backup01' })
        return $ev
    }
    function Move-RwBackupToOwnHost {
        # Moves backup01 to a new standalone host esx09 (in no cluster, not under the vCenter root)
        # administered only by EXAMPLE\backup-admins: no colocation and no shared admin.
        param($Evidence)
        $h = Add-VsatAsset -Evidence $Evidence -Id 'ep-vc01:host-90' -Type host -Name 'esx09.example.local' -Endpoint 'ep-vc01' -Version '8.0.3' -Build '24585383' -Props ([ordered]@{ connectionState = 'connected' })
        $bk = Get-TestAsset $Evidence 'backup01' 'vm'
        foreach ($r in @($Evidence.relationships | Where-Object { $_.source -eq $bk.id -and $_.type -eq 'runs-on' })) { $r.target = $h.id }
        $vc = @($Evidence.assets | Where-Object type -eq 'vcenter')[0]
        $vc.facts.permissions.value = @(@($vc.facts.permissions.value) + [ordered]@{ principal = 'EXAMPLE\backup-admins'; role = 'Admin'; entity = 'esx09.example.local'; entityId = 'HostSystem-host-90'; propagate = $true; isGroup = $true })
        $script:VsatAssetIndex = @{}; foreach ($a in $Evidence.assets) { $script:VsatAssetIndex[$a.id] = $a }
        return $h
    }
    $script:R = Get-TestResults (Get-RwEvidence)
}

Describe 'Ransomware tag on existing rules' {
    It 'tags exactly the rules listed in the 2.5 plan, and every tagged ID exists' {
        $rules = @((Get-VsatRulePack).rules)
        $ids = @($rules | ForEach-Object id)
        foreach ($t in $script:SpecTags) { $ids | Should -Contain $t -Because "$t is tagged in the plan" }
        $tagged = @($rules | Where-Object { [bool](Get-VsatProp $_ 'ransomware' $false) } | ForEach-Object id)
        (@($tagged | Sort-Object) -join ',') | Should -Be (@($script:SpecTags | Sort-Object) -join ',')
    }
}

Describe 'backupSystems scope key' {
    It 'is an array-shaped 2.3-style scope key with a safe default' {
        $script:VsatNewScopeArrayKeys | Should -Contain 'backupSystems'
        @((New-VsatScope $null).backupSystems).Count | Should -Be 0
        $s = New-VsatScope @{ backupSystems = @(@{ match = 'name:bk*' }) }
        @($s.backupSystems).Count | Should -Be 1
        @($s.backupSystems)[0].match | Should -Be 'name:bk*'
    }
    It 'ignores a bad shape (not an array) and keeps the default' {
        @((New-VsatScope @{ backupSystems = 'name:bk*' }).backupSystems).Count | Should -Be 0
    }
    It 'is re-applied by the replay scope merge, including an explicit empty array' {
        $es = New-VsatScope @{ backupSystems = @(@{ match = 'name:a' }) }
        Merge-VsatScopeOverrides -Scope @{ backupSystems = @() } -EvidenceScope $es
        @($es.backupSystems).Count | Should -Be 0
    }
    It 'is declared for backup01 in the demo lab' {
        @((Get-TestEvidence).scope.backupSystems | ForEach-Object { $_.match }) | Should -Contain 'name:backup01'
    }
    It 'makes matched assets crown jewels with reason "backup infrastructure"' {
        $n = @($script:R.analysis.blastRadius.nodes | Where-Object { $_.name -eq 'backup01' })[0]
        $n.crown | Should -BeTrue
        $n.crownReason | Should -Be 'backup infrastructure'
    }
    It 'registers the backup crown rule right after the management plane' {
        @($script:VsatCrownRules | ForEach-Object id) | Should -Be @('management-plane', 'backup-system', 'operator-high', 'ot-workload', 'ai-control-plane', 'inferred-high')
    }
}

Describe 'Ransomware readiness domain' {
    It 'is NOT_APPLICABLE, non-mandatory, with "No backup systems declared" when backupSystems is empty' {
        $ev = Get-TestEvidence; $ev.scope.backupSystems = @()
        $r = Get-TestResults $ev
        $d = $r.coverage.domains | Where-Object id -eq 'ransomware-readiness'
        $d.state | Should -Be 'NOT_APPLICABLE'
        $d.mandatory | Should -BeFalse
        @($d.evidence) | Should -Contain 'No backup systems declared'
        $rw = @($r.findings | Where-Object { $_.domain -eq 'ransomware-readiness' })
        $rw.Count | Should -BeGreaterThan 0
        @($rw | Where-Object result -ne 'NOT_APPLICABLE') | Should -BeNullOrEmpty
        @($r.analysis.blastRadius.nodes | Where-Object { $_.crownReason -eq 'backup infrastructure' }) | Should -BeNullOrEmpty
    }
    It 'replays evidence whose scope predates backupSystems' {
        $ev = Get-TestEvidence; $ev.scope.Remove('backupSystems')
        $r = Get-TestResults (ConvertTo-VsatLiveEvidence $ev)
        ($r.coverage.domains | Where-Object id -eq 'ransomware-readiness').state | Should -Be 'NOT_APPLICABLE'
        $r.analysis.ransomware | Should -Not -BeNullOrEmpty
    }
    It 'is assessed and optional when backup systems are declared' {
        $d = $script:R.coverage.domains | Where-Object id -eq 'ransomware-readiness'
        $d.state | Should -BeIn @('ASSESSED', 'PARTIAL')
        $d.mandatory | Should -BeFalse
        (@($d.evidence) -join ' ') | Should -Match 'backup01'
    }
    It 'defines the three RW rules, their severities, ATT&CK T1486/T1490 and the WP-RANSOMWARE work package' {
        $rw = @((Get-VsatRulePack).rules | Where-Object domain -eq 'ransomware-readiness')
        (@($rw | ForEach-Object id | Sort-Object) -join ',') | Should -Be ($script:RwIds -join ',')
        ($rw | Where-Object id -eq 'RW-BACKUP-REACHABLE').severity | Should -Be 'critical'
        ($rw | Where-Object id -eq 'RW-BACKUP-COLOCATED').severity | Should -Be 'high'
        ($rw | Where-Object id -eq 'RW-BACKUP-SHARED-ADMIN').severity | Should -Be 'high'
        foreach ($r in $rw) {
            @($r.attack.mitigates | Where-Object { $_ -in @('T1486', 'T1490') }).Count | Should -BeGreaterThan 0 -Because $r.id
            $r.mitigation.workPackage | Should -Be 'WP-RANSOMWARE'
        }
        @((Get-VsatRulePackMeta).workPackages | ForEach-Object id) | Should -Contain 'WP-RANSOMWARE'
    }
    It 'shows all three RW findings on the demo backup VM' {
        foreach ($id in $script:RwIds) { @(Get-TestFinding $script:R $id 'backup01')[0].result | Should -Be 'FAIL' -Because $id }
    }
    It 'is NOT_APPLICABLE on workloads that are not declared backup systems' {
        $f = @($script:R.findings | Where-Object { $_.ruleId -in $script:RwIds -and $_.assetName -ne 'backup01' })
        $f.Count | Should -BeGreaterThan 0
        @($f | Where-Object result -ne 'NOT_APPLICABLE') | Should -BeNullOrEmpty
    }
    It 'never contacts anything new: RW rules only read facts, relationships, scope and the graph' {
        (Get-Content (Join-Path $script:RepoRoot 'src/77-EvaluatorsRansomware.ps1') -Raw) | Should -Not -Match '(?i)Invoke-(Rest|Web)|Connect-|Get-View|ssh |virsh'
    }
}

Describe 'RW-BACKUP-REACHABLE' {
    It 'fails with the attack path narrative when an entry point reaches the backup VM' {
        $f = @(Get-TestFinding $script:R 'RW-BACKUP-REACHABLE' 'backup01')[0]
        $f.result | Should -Be 'FAIL'
        $f.severity | Should -Be 'critical'
        $f.observed | Should -Match '→'
    }
    It 'passes when the declared entry points reach no backup system' {
        $ev = Get-RwEvidence
        $ev.scope.entryPoints = @(@{ principal = 'EXAMPLE\helpdesk' })
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'RW-BACKUP-REACHABLE' 'backup01')[0].result | Should -Be 'PASS'
    }
    It 'is UNKNOWN, never PASS, when vCenter permissions were denied and NSX is not assessed' {
        $ev = Get-RwEvidence; Remove-TestNsx $ev
        $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
        Set-VsatFact $vc 'permissions' -Status denied -Value $null
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'RW-BACKUP-REACHABLE' 'backup01')[0].result | Should -Be 'UNKNOWN'
    }
}

Describe 'RW-BACKUP-COLOCATED' {
    It 'fails when the backup VM shares its vSphere cluster with production workloads' {
        $f = @(Get-TestFinding $script:R 'RW-BACKUP-COLOCATED' 'backup01')[0]
        $f.result | Should -Be 'FAIL'
        $f.observed | Should -Match 'cl-prod'
        $f.observed | Should -Match 'db02|web02|app02'
    }
    It 'passes when the backup VM runs alone on a dedicated host' {
        $ev = Get-RwEvidence; [void](Move-RwBackupToOwnHost $ev)
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'RW-BACKUP-COLOCATED' 'backup01')[0].result | Should -Be 'PASS'
    }
    It 'is UNKNOWN when the VM inventory was only partly collected' {
        $ev = Get-RwEvidence; [void](Move-RwBackupToOwnHost $ev)
        @($ev.collection.collectors | Where-Object name -eq 'vsphere.vms')[0].status = 'partial'
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'RW-BACKUP-COLOCATED' 'backup01')[0].result | Should -Be 'UNKNOWN'
    }
    It 'is UNKNOWN when the backup VM placement was not collected' {
        $ev = Get-RwEvidence
        $bk = Get-TestAsset $ev 'backup01' 'vm'
        $ev.relationships = New-VsatList @($ev.relationships | Where-Object { -not ($_.source -eq $bk.id -and $_.type -eq 'runs-on') })
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'RW-BACKUP-COLOCATED' 'backup01')[0].result | Should -Be 'UNKNOWN'
        @(Get-TestFinding $r 'RW-BACKUP-SHARED-ADMIN' 'backup01')[0].result | Should -Be 'UNKNOWN'
    }
    It 'fails for a KVM backup VM that shares its host with other guests' {
        $ev = Get-XplatEvidence
        $kvm = @($ev.assets | Where-Object type -eq 'kvm-vm' | Sort-Object { $_.id })
        $kvm.Count | Should -BeGreaterThan 1
        $ev.scope.backupSystems = @(@{ match = "id:$($kvm[0].id)" })
        $r = Get-TestResults $ev
        @($r.findings | Where-Object { $_.ruleId -eq 'RW-BACKUP-COLOCATED' -and $_.assetId -eq $kvm[0].id })[0].result | Should -Be 'FAIL'
    }
}

Describe 'RW-BACKUP-SHARED-ADMIN' {
    It 'fails when an administrator of the backup host also administers production hosts' {
        $f = @(Get-TestFinding $script:R 'RW-BACKUP-SHARED-ADMIN' 'backup01')[0]
        $f.result | Should -Be 'FAIL'
        $f.observed | Should -Match 'vi-admins'
    }
    It 'passes when the backup host has a dedicated administrator group' {
        $ev = Get-RwEvidence; [void](Move-RwBackupToOwnHost $ev)
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'RW-BACKUP-SHARED-ADMIN' 'backup01')[0].result | Should -Be 'PASS'
    }
    It 'is UNKNOWN when vCenter permissions were denied' {
        $ev = Get-RwEvidence
        $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
        Set-VsatFact $vc 'permissions' -Status denied -Value $null
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'RW-BACKUP-SHARED-ADMIN' 'backup01')[0].result | Should -Be 'UNKNOWN'
    }
}

Describe 'Ransomware analysis (one account reach)' {
    It 'lists principals by hypervisor hosts administered, worst first, domain admin group first' {
        $o = @($script:R.analysis.ransomware.oneAccountReach)
        $o.Count | Should -BeGreaterThan 1
        $o[0].principal | Should -Be 'EXAMPLE\vi-admins'
        $o[0].hypervisors | Should -Be 5
        $o[0].total | Should -Be 5
        @($o[0].platforms) | Should -Contain 'vmware'
        for ($i = 1; $i -lt $o.Count; $i++) { $o[$i].hypervisors | Should -BeLessOrEqual $o[$i - 1].hypervisors }
        (@($o | Where-Object principal -eq 'EXAMPLE\j.doe'))[0].hypervisors | Should -Be 3
    }
    It 'counts hosts across platforms' {
        $r = Get-TestResults (Get-XplatEvidence)
        $o = @($r.analysis.ransomware.oneAccountReach)
        $o[0].total | Should -BeGreaterThan 5
        @($o | ForEach-Object { @($_.platforms) }) | Should -Contain 'kvm'
    }
    It 'summarizes the tagged rules by status' {
        $t = $script:R.analysis.ransomware.taggedRules
        @($t.ruleIds).Count | Should -Be 20
        $n = @($script:R.findings | Where-Object { $_.ruleId -in $script:SpecTags }).Count
        ($t.counts.PASS + $t.counts.FAIL + $t.counts.UNKNOWN + $t.counts.ERROR + $t.counts.MANUAL + $t.counts.NOT_APPLICABLE) | Should -Be $n
        $t.counts.FAIL | Should -BeGreaterThan 0
    }
    It 'lists blast-radius paths that end at a backup system' {
        $p = @($script:R.analysis.ransomware.backupPaths)
        $p.Count | Should -BeGreaterThan 0
        $p[0].backup | Should -Be 'backup01'
        $p[0].narrative | Should -Match '→'
    }
    It 'is redacted with the rest of the results' {
        $ev = Get-XplatEvidence
        $ev.scope.backupSystems = @(@{ match = 'name:backup01' })
        $r = Get-TestResults $ev
        $red = Get-VsatRedactedCopy -Evidence $ev -Results $r
        $txt = ConvertTo-VsatJson $red.results.analysis.ransomware
        foreach ($s in 'vi-admins', 'j.doe', 'backup01', 'esx01') { $txt | Should -Not -Match ([regex]::Escape($s)) -Because $s }
        foreach ($x in @($red.results.analysis.ransomware.oneAccountReach)) { $x.principal | Should -Not -BeIn @('jdoe', 'ops', 'root') }
    }
}
