BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Mandatory NSX coverage states' {
    It 'NSX discovered and accessible => ASSESSED' {
        $r = Get-TestResults
        ($r.coverage.domains | Where-Object { $_.id -eq 'nsx' }).state | Should -Be 'ASSESSED'
    }
    It 'NSX detected but no access => INCOMPLETE: NSX NOT ASSESSED, other results preserved, exit 2' {
        $ev = Get-TestEvidence; Remove-TestNsx $ev
        $r = Get-TestResults $ev
        $d = $r.coverage.domains | Where-Object { $_.id -eq 'nsx' }
        $d.state | Should -Be 'INCOMPLETE'
        $r.status.label | Should -Be 'INCOMPLETE: NSX NOT ASSESSED'
        $r.status.exitCode | Should -Be 2
        @($d.missing -join ' ') | Should -Match 'nsx01.example.local'
        @($r.findings | Where-Object { $_.domain -eq 'esxi' -and $_.result -eq 'FAIL' }).Count | Should -BeGreaterThan 0
    }
    It 'NSX state cannot be determined => UNKNOWN and no clean completion' {
        $ev = Get-TestEvidence; Remove-TestNsx $ev
        (Get-TestAsset $ev 'vc01.example.local' 'vcenter').facts.extensions = [ordered]@{ status = 'denied'; value = $null }
        foreach ($p in @($ev.assets | Where-Object { $_.type -eq 'dvportgroup' })) { $p.props.segmentId = $null; $p.props.backingType = 'standard'; $p.props.logicalSwitchUuid = $null }
        $r = Get-TestResults $ev
        ($r.coverage.domains | Where-Object { $_.id -eq 'nsx' }).state | Should -Be 'UNKNOWN'
        $r.status.overall | Should -Be 'incomplete'
    }
    It 'operator declares absent without sufficient evidence => REVIEW' {
        $ev = Get-TestEvidence; Remove-TestNsx $ev
        $ev.scope.nsxDeclaredAbsent = $true
        (Get-TestAsset $ev 'vc01.example.local' 'vcenter').facts.extensions = [ordered]@{ status = 'denied'; value = $null }
        foreach ($p in @($ev.assets | Where-Object { $_.type -eq 'dvportgroup' })) { $p.props.segmentId = $null; $p.props.backingType = 'standard'; $p.props.logicalSwitchUuid = $null }
        $r = Get-TestResults $ev
        ($r.coverage.domains | Where-Object { $_.id -eq 'nsx' }).state | Should -Be 'REVIEW'
        $r.status.exitCode | Should -Be 2
    }
    It 'operator declares absent but discovery finds NSX => INCOMPLETE (declaration conflicts)' {
        $ev = Get-TestEvidence; Remove-TestNsx $ev
        $ev.scope.nsxDeclaredAbsent = $true
        ($r = Get-TestResults $ev) | Out-Null
        ($r.coverage.domains | Where-Object { $_.id -eq 'nsx' }).state | Should -Be 'INCOMPLETE'
    }
    It 'NSX confirmed absent => NOT APPLICABLE: NSX NOT DEPLOYED with evidence (not a pass)' {
        $ev = Get-TestEvidence; Remove-TestNsx $ev
        $vc = Get-TestAsset $ev 'vc01.example.local' 'vcenter'
        $vc.facts.extensions.value = @($vc.facts.extensions.value | Where-Object { $_.key -notlike 'com.vmware.nsx*' })
        foreach ($p in @($ev.assets | Where-Object { $_.type -eq 'dvportgroup' })) { $p.props.segmentId = $null; $p.props.backingType = 'standard'; $p.props.logicalSwitchUuid = $null }
        $r = Get-TestResults $ev
        $d = $r.coverage.domains | Where-Object { $_.id -eq 'nsx' }
        $d.state | Should -Be 'NOT_APPLICABLE'
        $d.label | Should -Be 'NOT APPLICABLE: NSX NOT DEPLOYED'
        @($d.evidence).Count | Should -BeGreaterThan 0
        @($r.findings | Where-Object { $_.domain -eq 'nsx' -and $_.result -eq 'PASS' }) | Should -BeNullOrEmpty
    }
    It 'partially authorized NSX => PARTIAL with affected scope listed' {
        $ev = Get-TestEvidence
        ($ev.collection.collectors | Where-Object { $_.name -eq 'nsx.groups' }).status = 'denied'
        foreach ($g in @($ev.assets | Where-Object { $_.type -eq 'nsx-group' })) { $g.facts.members = [ordered]@{ status = 'denied'; value = $null } }
        $r = Get-TestResults $ev
        $d = $r.coverage.domains | Where-Object { $_.id -eq 'nsx' }
        $d.state | Should -Be 'PARTIAL'
        ($d.missing -join ' ') | Should -Match 'nsx.groups'
        (Get-TestFinding $r 'NSX-DFW-EMPTY-GROUP' 'decom-app-access').result | Should -Be 'UNKNOWN'
    }
    It 'NSX endpoint failed to connect => INCOMPLETE' {
        $ev = Get-TestEvidence
        ($ev.scope.endpoints | Where-Object { $_.type -eq 'nsx' }).status = 'failed'
        ($r = Get-TestResults $ev) | Out-Null
        ($r.coverage.domains | Where-Object { $_.id -eq 'nsx' }).state | Should -Be 'INCOMPLETE'
    }
    It 'undisclosed NSX manager registered in vCenter => PARTIAL' {
        $ev = Get-TestEvidence
        $vc = Get-TestAsset $ev 'vc01.example.local' 'vcenter'
        $vc.facts.extensions.value[0].urls = @('https://nsx01.example.local/', 'https://nsx-dr.example.local/')
        ($r = Get-TestResults $ev) | Out-Null
        $d = $r.coverage.domains | Where-Object { $_.id -eq 'nsx' }
        $d.state | Should -Be 'PARTIAL'; ($d.missing -join ' ') | Should -Match 'nsx-dr.example.local'
    }
}

Describe 'NSX policy analysis' {
    BeforeAll { $script:R = Get-TestResults }
    It 'flags the default layer-3 ALLOW rule' { (Get-TestFinding $script:R 'NSX-DFW-DEFAULT').result | Should -Be 'FAIL' }
    It 'flags any-any-any allows only' {
        (Get-TestFinding $script:R 'NSX-DFW-ANYANY' 'temp-any-any').result | Should -Be 'FAIL'
        (Get-TestFinding $script:R 'NSX-DFW-ANYANY' 'web-https').result | Should -Be 'PASS'
    }
    It 'detects rules shadowed by earlier rules in category order (conflicting action)' {
        $f = Get-TestFinding $script:R 'NSX-DFW-SHADOW' 'jump-ssh-to-db'
        $f.result | Should -Be 'FAIL'; $f.confidence | Should -Be 'inferred'; $f.observed | Should -Match 'deny-dmz-to-data'
    }
    It 'flags rules referencing groups without effective members' { (Get-TestFinding $script:R 'NSX-DFW-EMPTY-GROUP' 'decom-app-access').result | Should -Be 'FAIL' }
    It 'flags exclusion list members' { (Get-TestFinding $script:R 'NSX-DFW-EXCLUDE').result | Should -Be 'FAIL' }
    It 'flags NAT firewall bypass' { (Get-TestFinding $script:R 'NSX-NAT-BYPASS' 't1-dmz').result | Should -Be 'FAIL' }
    It 'respects applied-to scope when modeling paths and honours earlier DROP rules' {
        $p = @($script:R.analysis.attackPaths | Where-Object { ($script:R.assets | Where-Object id -eq $_.source).name -eq 'jump01' -and ($script:R.assets | Where-Object id -eq $_.target).name -eq 'db01' })
        $p.Count | Should -Be 1
        $p[0].decision | Should -Be 'deny'
        $p[0].confidence | Should -Be 'configuration-inferred'
    }
    It 'ranks chokepoint rules that enable the most paths' {
        $script:R.analysis.chokepoints[0].name | Should -Be 'temp-any-any'
    }
    It 'never merges separate NSX managers (stable namespaced ids)' {
        $ids = @($script:R.assets | Where-Object { $_.type -like 'nsx-*' } | ForEach-Object { $_.id })
        @($ids | Where-Object { $_ -notlike 'ep-nsx01:*' }) | Should -BeNullOrEmpty
    }
    It 'marks group membership unknown => path decision unknown, not allow/deny' {
        $ev = Get-TestEvidence
        foreach ($g in @($ev.assets | Where-Object { $_.type -eq 'nsx-group' })) { $g.facts.members = [ordered]@{ status = 'error'; value = $null } }
        $r = Get-TestResults $ev
        @($r.analysis.attackPaths | Where-Object { $_.decision -eq 'deny' }) | Should -BeNullOrEmpty
    }
}

Describe 'NSX compute-manager collection' {
    It 'computeManagers collected with username but no credential material' {
        Mock Invoke-VsatRest {
            if ($Path -like '/api/v1/fabric/compute-managers*') {
                return [ordered]@{ result_count = 1; results = @([ordered]@{
                            id = 'cm-1'; display_name = 'vc01'; server = 'vc01.example.local'; origin_type = 'vCenter'; origin_id = '7153b5e7-edfb-e742-95ae-c6f5f3fdfa71'
                            credential = [ordered]@{ credential_type = 'UsernamePasswordLoginCredential'; username = 'svc-nsx@vsphere.local'; password = 'S3cret!'; thumbprint = 'AA:BB:CC' }
                        }) }
            }
            if ($Path -like '*page_size*') { return [ordered]@{ result_count = 0; results = @() } }
            return $null
        }
        $ev = New-VsatEvidence -Mode fixture
        $ep = Add-VsatEndpoint -Evidence $ev -Type nsx -Address 'nsx01.example.local'
        Invoke-VsatNsxCollection -Evidence $ev -Endpoint $ep -Session @{ headers = @{} }
        $asset = @($ev.assets | Where-Object type -eq 'nsx-manager')[0]
        $asset.facts.computeManagers.status | Should -Be 'ok'
        $cm = @($asset.facts.computeManagers.value)[0]
        $cm.server | Should -Be 'vc01.example.local'
        $cm.username | Should -Be 'svc-nsx@vsphere.local'
        $cm.origin_id | Should -Be '7153b5e7-edfb-e742-95ae-c6f5f3fdfa71'
        ConvertTo-VsatJson $asset.facts.computeManagers | Should -Not -Match 'password|thumbprint|S3cret|AA:BB'
        @($ev.relationships | Where-Object { $_.type -eq 'manages' -and $_.target -eq 'vcenter:vc01.example.local' }).Count | Should -Be 1
    }
}
