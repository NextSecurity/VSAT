# Cross-platform security graph tests (VSAT 2.3 "Blast Radius").
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Principal identity keys' {
    BeforeAll { $script:Sc = @{ identityDomains = @(@{ netbios = 'EXAMPLE'; dns = 'example.local' }) } }
    It '<In> => <Key>' -ForEach @(
        @{ In = 'EXAMPLE\vi-admins';        Ep = 'ep-vc01';  Key = 'ad:example\vi-admins' }
        @{ In = 'example\VI-Admins';        Ep = 'ep-hv01';  Key = 'ad:example\vi-admins' }
        @{ In = 'vi-admins@example.local';  Ep = 'ep-vc01';  Key = 'ad:example\vi-admins' }
        @{ In = 'ops@other.corp';           Ep = 'ep-vc01';  Key = 'upn:ops@other.corp' }
        @{ In = 'VSPHERE.LOCAL\Administrator'; Ep = 'ep-vc01'; Key = 'local:ep-vc01:vsphere.local\administrator' }
        @{ In = 'HV01\Administrator';       Ep = 'ep-hv01';  Key = 'local:ep-hv01:hv01\administrator' }
        @{ In = 'BUILTIN\Administrators';   Ep = 'ep-hv01';  Key = 'local:ep-hv01:builtin\administrators' }
        @{ In = 'alice';                    Ep = 'ep-kvm01'; Key = 'local:ep-kvm01:alice' }
        @{ In = 'EXAMPLE\İSTANBUL';         Ep = 'ep-vc01';  Key = 'ad:example\istanbul' }
        @{ In = 'ＥＸＡＭＰＬＥ\ops';        Ep = 'ep-vc01';  Key = 'ad:example\ops' }
        @{ In = 'u@example.local.';         Ep = 'ep-vc01';  Key = 'ad:example\u' }
    ) {
        (ConvertTo-VsatPrincipalKey -Name $In -Endpoint $Ep -Scope $script:Sc).key | Should -Be $Key
    }
    It 'never joins local principals across endpoints' {
        (ConvertTo-VsatPrincipalKey 'root' 'ep-kvm01' $script:Sc).key | Should -Not -Be (ConvertTo-VsatPrincipalKey 'root' 'ep-kvm02' $script:Sc).key
    }
    It 'treats host-named NetBIOS prefixes as local (hostname == prefix)' {
        (ConvertTo-VsatPrincipalKey -Name 'HV01\ops' -Endpoint 'ep-hv01' -Scope $script:Sc -HostName 'hv01.example.local').local | Should -BeTrue
    }
    It 'treats an empty account after "domain\" as local, never ad: (fix round 1)' {
        $k = ConvertTo-VsatPrincipalKey -Name 'EXAMPLE\' -Endpoint 'ep-vc01' -Scope $script:Sc
        $k.local | Should -BeTrue
        $k.key | Should -Not -Match '^ad:'
    }
    It 'folds the Turkish dotted I (U+0130) the same way regardless of endpoint (join, not endpoint-namespaced)' {
        (ConvertTo-VsatPrincipalKey -Name 'EXAMPLE\İSTANBUL' -Endpoint 'ep-vc01' -Scope $script:Sc).key |
            Should -Be (ConvertTo-VsatPrincipalKey -Name 'example\istanbul' -Endpoint 'ep-hv01' -Scope $script:Sc).key
    }
    It 'never folds the Turkish dotless ı (U+0131) into ASCII i - a false join fabricates an attack path (fix round 2)' {
        (ConvertTo-VsatPrincipalKey -Name 'EXAMPLE\ısik' -Endpoint 'ep-vc01' -Scope $script:Sc).key |
            Should -Not -Be (ConvertTo-VsatPrincipalKey -Name 'EXAMPLE\isik' -Endpoint 'ep-vc01' -Scope $script:Sc).key
    }
}

Describe 'New-VsatScope: new 2.3 scope keys (controller ruling P51)' {
    It 'preserves identityDomains and entryPoints through New-VsatScope' {
        $raw = [ordered]@{
            identityDomains = @(@{ netbios = 'EXAMPLE'; dns = 'example.local' })
            entryPoints     = @(@{ assetId = 'ep-vc01:vm/1' })
        }
        $s = New-VsatScope $raw
        $s.identityDomains.Count | Should -Be 1
        $s.identityDomains[0].netbios | Should -Be 'EXAMPLE'
        $s.entryPoints.Count | Should -Be 1
        $s.entryPoints[0].assetId | Should -Be 'ep-vc01:vm/1'
    }
    It 'defaults all new keys to empty arrays when scope is absent' {
        $s = New-VsatScope $null
        foreach ($k in 'entryPoints', 'credentialStores', 'identityGroups', 'identityDomains', 'aiWorkloads', 'signoffs') {
            , $s[$k] | Should -BeOfType [array]
            $s[$k].Count | Should -Be 0
        }
    }
    It 'falls back to the default (with a warning) when a new key is not array-shaped' {
        $s = New-VsatScope ([ordered]@{ identityGroups = 'not-an-array' })
        , $s.identityGroups | Should -BeOfType [array]
        $s.identityGroups.Count | Should -Be 0
    }
    It 'passes through optional exceptions fields (approver, compensatingControl, ticket)' {
        $raw = [ordered]@{ exceptions = @(
                @{ ruleId = 'X'; approver = 'bob'; compensatingControl = 'WAF'; ticket = 'JIRA-1' }
                @{ ruleId = 'Y'; approver = 'alice'; compensatingControl = 'IDS'; ticket = 'JIRA-2' }
            ) }
        $s = New-VsatScope $raw
        $s.exceptions[0].approver | Should -Be 'bob'
        $s.exceptions[0].compensatingControl | Should -Be 'WAF'
        $s.exceptions[0].ticket | Should -Be 'JIRA-1'
        $s.exceptions[1].approver | Should -Be 'alice'
    }
}

Describe 'Read-VsatScopeArrayKey (fix round 1)' {
    It 'reports present=true with an empty array for an explicit empty array (not absent)' {
        $r = Read-VsatScopeArrayKey -Scope ([ordered]@{ identityDomains = @() }) -Key 'identityDomains'
        $r.present | Should -BeTrue
        , $r.value | Should -BeOfType [array]
        $r.value.Count | Should -Be 0
    }
    It 'reports present=false when the key is absent' {
        $r = Read-VsatScopeArrayKey -Scope ([ordered]@{}) -Key 'identityDomains'
        $r.present | Should -BeFalse
    }
    It 'warns and reports present=false for a bad shape (a bare object instead of an array)' {
        $before = $script:VsatLog.Count
        $r = Read-VsatScopeArrayKey -Scope ([ordered]@{ identityGroups = @{ group = 'x' } }) -Key 'identityGroups'
        $r.present | Should -BeFalse
        @($script:VsatLog | Select-Object -Skip $before | Where-Object { $_.level -eq 'warn' -and $_.message -match "identityGroups" }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Merge-VsatScopeOverrides: -Replay scope re-application (fix round 1)' {
    It 'honours an explicit empty-array override instead of ignoring it as absent' {
        $ev = New-VsatEvidence -Mode replay -Scope ([ordered]@{ identityDomains = @(@{ netbios = 'EXAMPLE'; dns = 'example.local' }) })
        $ev.scope.identityDomains.Count | Should -Be 1
        Merge-VsatScopeOverrides -Scope ([ordered]@{ identityDomains = @() }) -EvidenceScope $ev.scope
        $ev.scope.identityDomains.Count | Should -Be 0
    }
    It 'warns and keeps the current value on a bad-shaped override' {
        $ev = New-VsatEvidence -Mode replay -Scope ([ordered]@{ entryPoints = @(@{ assetId = 'a' }) })
        $ev.scope.entryPoints.Count | Should -Be 1
        $before = $script:VsatLog.Count
        Merge-VsatScopeOverrides -Scope ([ordered]@{ entryPoints = 'not-an-array' }) -EvidenceScope $ev.scope
        $ev.scope.entryPoints.Count | Should -Be 1
        @($script:VsatLog | Select-Object -Skip $before | Where-Object { $_.level -eq 'warn' -and $_.message -match 'entryPoints' }).Count | Should -BeGreaterThan 0
    }
    It 'still applies a single-element array override (no unwrap to a bare element)' {
        $ev = New-VsatEvidence -Mode replay -Scope $null
        Merge-VsatScopeOverrides -Scope ([ordered]@{ identityDomains = @(@{ netbios = 'EXAMPLE'; dns = 'example.local' }) }) -EvidenceScope $ev.scope
        $ev.scope.identityDomains.Count | Should -Be 1
        $ev.scope.identityDomains[0].netbios | Should -Be 'EXAMPLE'
    }
    It 'leaves pre-existing keys (e.g. exceptions) unaffected when no override is given' {
        $ev = New-VsatEvidence -Mode replay -Scope ([ordered]@{ exceptions = @(@{ ruleId = 'X' }, @{ ruleId = 'Y' }) })
        Merge-VsatScopeOverrides -Scope ([ordered]@{}) -EvidenceScope $ev.scope
        $ev.scope.exceptions.Count | Should -Be 2
    }
}

Describe 'Security graph builder' {
    BeforeAll {
        $script:Ev = Get-XplatEvidence
        $r = Invoke-VsatRules -Evidence $script:Ev -ProfileName standard
        $script:G = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
        $script:E = @($script:G.edges.Values)
    }
    It 'creates principal nodes joined across vCenter and Hyper-V by normalized AD key' {
        $script:G.nodes.ContainsKey('ad:example\domain admins') | Should -BeTrue
        @($script:E | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\vi-admins' }).Count | Should -BeGreaterThan 0
        $script:G.nodes['ad:example\vi-admins'].kind | Should -Be 'principal'
        $script:G.nodes['ad:example\vi-admins'].platform | Should -Be 'identity'
    }
    It 'keeps local principals namespaced per endpoint (never joined)' {
        $script:G.nodes.ContainsKey('local:ep-hv01:hv01\administrator') | Should -BeTrue
        $script:G.nodes.ContainsKey('local:ep-vc01:vsphere.local\administrator') | Should -BeTrue
    }
    It 'correlates the vCenter appliance VM on Hyper-V with an embodies edge (correlated confidence)' {
        $e = @($script:E | Where-Object { $_.kind -eq 'embodies' -and $script:G.nodes[$_.target].type -eq 'vcenter' })
        $e.Count | Should -Be 1
        $e[0].confidence | Should -Be 'correlated'
        $script:G.nodes[$e[0].source].type | Should -Be 'hyperv-vm'
        $script:G.nodes[$e[0].source].name | Should -Be 'vcsa-hv01'
        $e[0].fixId | Should -Match '^relocate:'
        $e[0].cost | Should -Be 0
        @($e[0].evidence | ForEach-Object fact) | Should -Contain 'endpoint.resolvedAddresses'
    }
    It 'every edge cites evidence with status ok or absent, or is operator-declared' {
        foreach ($e in $script:E) {
            if ($e.confidence -eq 'operator-declared') { continue }
            @($e.evidence).Count | Should -BeGreaterThan 0
            foreach ($x in $e.evidence) { $x.status | Should -BeIn @('ok', 'absent') }
        }
    }
    It 'uses only the allowed edge kinds and confidences' {
        foreach ($e in $script:E) {
            $e.kind | Should -BeIn @('admin-of', 'controls', 'embodies', 'network-allow', 'mgmt-reach', 'credential-exposure', 'member-of')
            $e.confidence | Should -BeIn @('observed', 'configuration-inferred', 'correlated', 'operator-declared')
        }
    }
    It 'IP matches only ever produce correlated edges' {
        @($script:E | Where-Object { $_.kind -eq 'embodies' -and $_.confidence -ne 'correlated' }) | Should -BeNullOrEmpty
    }
    It 'edge ids are E- plus 16 hex characters' {
        foreach ($k in $script:G.edges.Keys) { $k | Should -Match '^E-[0-9a-f]{16}$' }
    }
    It 'does not create admin-of edges from denied permission facts' {
        $ev = Get-XplatEvidence
        $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
        $vc.facts.permissions = @{ status = 'denied'; value = $null; error = 'NoPermission' }
        $r = Invoke-VsatRules -Evidence $ev -ProfileName standard
        $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
        @($g.edges.Values | Where-Object { $_.kind -eq 'admin-of' -and $g.nodes[$_.target].type -eq 'vcenter' }) | Should -BeNullOrEmpty
        $g.notes | Should -Contain 'vCenter permissions not collected on ep-vc01 (denied): identity paths into vCenter are unknown'
    }
    It 'marks management planes as crown jewels automatically' {
        foreach ($t in 'vcenter', 'nsx-manager', 'hyperv-cluster') { @($script:G.crowns | Where-Object { $script:G.nodes[$_].type -eq $t }).Count | Should -BeGreaterThan 0 }
        $vc = @($script:G.crowns | Where-Object { $script:G.nodes[$_].type -eq 'vcenter' })[0]
        $script:G.nodes[$vc].crownReason | Should -Be 'management plane (vcenter)'
    }
    It 'edge ids are stable across rebuilds' {
        $r2 = Invoke-VsatRules -Evidence (Get-XplatEvidence) -ProfileName standard
        $g2 = New-VsatSecurityGraph -Context $r2.context -Findings $r2.findings
        (@($g2.edges.Keys) | Sort-Object) -join ',' | Should -Be ((@($script:G.edges.Keys) | Sort-Object) -join ',')
    }
    It 'indexes every edge in out[source]' {
        $n = 0; foreach ($k in $script:G.out.Keys) { $n += $script:G.out[$k].Count }
        $n | Should -Be $script:G.edges.Count
    }
    It 'hypervisor hosts control their guests (Hyper-V and KVM)' {
        foreach ($t in 'hyperv-vm', 'kvm-vm') {
            @($script:E | Where-Object { $_.kind -eq 'controls' -and $script:G.nodes[$_.target].type -eq $t }).Count | Should -BeGreaterThan 0
        }
    }
    It 'KVM libvirt group members are admins of the KVM host' {
        $kh = @($script:Ev.assets | Where-Object type -eq 'kvm-host')[0].id
        $src = @($script:E | Where-Object { $_.kind -eq 'admin-of' -and $_.target -eq $kh } | ForEach-Object source)
        $src | Should -Contain 'local:ep-kvm01:ops'
        $src | Should -Contain 'local:ep-kvm01:jdoe'
    }
    It 'attaches FAIL finding keys of the target asset to admin-of edges' {
        $e = @($script:E | Where-Object { $_.kind -eq 'admin-of' -and $script:G.nodes[$_.target].type -eq 'hyperv-host' })
        $e.Count | Should -BeGreaterThan 0
        foreach ($x in $e) { , $x.findingKeys | Should -BeOfType [array] }
    }
}

Describe 'Security graph: evidence discipline' {
    It 'never creates embodies edges from names (same name, different IP)' {
        $ev = Get-XplatEvidence
        $hv = @($ev.assets | Where-Object type -eq 'hyperv-vm')[0]
        $hv.facts.adapters.value[0].ips = @('10.20.9.9'); $hv.props.ipAddresses = @('10.20.9.9')
        $hv.name = 'vc01.example.local'
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'embodies' -and $g.nodes[$_.target].type -eq 'vcenter' }) | Should -BeNullOrEmpty
    }
    It 'embodies needs a recorded resolved address; without one the hop is needsEvidence, never an edge' {
        $ev = Get-XplatEvidence
        $vcEp = @($ev.scope.endpoints | Where-Object type -eq 'vcenter')[0]
        $vcEp.Remove('resolvedAddresses')
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'embodies' -and $g.nodes[$_.target].type -eq 'vcenter' }) | Should -BeNullOrEmpty
        $ne = @($g.needsEvidence | Where-Object { $_.kind -eq 'embodies' -and $_.target -eq 'ep-vc01:root' })
        $ne.Count | Should -Be 1
        $ne[0].missingFact | Should -Be 'endpoint.resolvedAddresses'
        $ne[0].status | Should -Be 'missing'
    }
    It 'records denied permissions as a needsEvidence admin-of candidate (not an edge)' {
        $ev = Get-XplatEvidence
        $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
        $vc.facts.permissions = @{ status = 'denied'; value = $null; error = 'NoPermission' }
        $g = Get-XplatGraph $ev
        $ne = @($g.needsEvidence | Where-Object { $_.kind -eq 'admin-of' -and $_.target -eq $vc.id })
        $ne.Count | Should -Be 1
        $ne[0].status | Should -Be 'denied'
        $ne[0].missingFact | Should -Be 'permissions'
        $ne[0].assetId | Should -Be $vc.id
        $ne[0].source | Should -Be 'principal:*'
        foreach ($k in 'kind', 'source', 'target', 'missingFact', 'assetId', 'status') { $ne[0].Contains($k) | Should -BeTrue }
    }
    It 'records a missing Hyper-V admins fact as needsEvidence with status missing' {
        $ev = Get-XplatEvidence
        $h = @($ev.assets | Where-Object type -eq 'hyperv-host')[0]
        $h.facts.Remove('hvAdmins')
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\hv-operators' }) | Should -BeNullOrEmpty
        $ne = @($g.needsEvidence | Where-Object { $_.kind -eq 'admin-of' -and $_.target -eq $h.id -and $_.missingFact -eq 'hvAdmins' })
        $ne.Count | Should -Be 1
        $ne[0].status | Should -Be 'missing'
    }
    It 'records an errored VM adapters fact as an embodies needsEvidence candidate' {
        $ev = Get-XplatEvidence
        $hv = @($ev.assets | Where-Object type -eq 'hyperv-vm')[0]
        $hv.facts.adapters = @{ status = 'error'; value = $null; error = 'WMI failure' }
        $hv.props.ipAddresses = @()
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'embodies' -and $_.source -eq $hv.id }) | Should -BeNullOrEmpty
        @($g.needsEvidence | Where-Object { $_.source -eq $hv.id }).Count | Should -Be 1
        @($g.needsEvidence | Where-Object { $_.kind -eq 'embodies' -and $_.source -eq $hv.id -and $_.target -eq 'mgmt:*' -and $_.status -eq 'error' -and $_.missingFact -eq 'adapters' }).Count | Should -Be 1
    }
    It 'does not record absent facts as needsEvidence (absent is evidence)' {
        $ev = Get-XplatEvidence
        $h = @($ev.assets | Where-Object type -eq 'hyperv-host')[0]
        $h.facts.hvAdmins = @{ status = 'absent'; value = $null }
        $g = Get-XplatGraph $ev
        @($g.needsEvidence | Where-Object { $_.target -eq $h.id -and $_.missingFact -eq 'hvAdmins' }) | Should -BeNullOrEmpty
    }
    It 'exposes needsEvidence as an array on the graph' {
        $g = Get-XplatGraph
        , $g.needsEvidence | Should -Not -BeNullOrEmpty
        $g.Contains('needsEvidence') | Should -BeTrue
    }
}

Describe 'Security graph: NSX credential exposure (correlated manages relationship)' {
    It 'links nsx-manager to vCenter through the correlated compute-manager relationship' {
        $g = Get-XplatGraph
        $e = @($g.edges.Values | Where-Object { $_.kind -eq 'credential-exposure' -and $_.source -eq 'ep-nsx01:manager' })
        $e.Count | Should -Be 1
        $e[0].target | Should -Be 'ep-vc01:root'
        $e[0].confidence | Should -Be 'observed'
        $e[0].fixId | Should -Be 'scope-svc:ep-nsx01:manager>ep-vc01:root'
        @($e[0].evidence | ForEach-Object fact) | Should -Contain 'computeManagers'
    }
    It 'does not match vCenter by name when the relationship is missing' {
        $ev = Get-XplatEvidence
        $ev.relationships = New-VsatList @($ev.relationships | Where-Object { -not ($_.type -eq 'manages' -and $_.target -eq 'ep-vc01:root') })
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'credential-exposure' -and $_.source -eq 'ep-nsx01:manager' }) | Should -BeNullOrEmpty
    }
    It 'still links when the vCenter asset is renamed (identity is the relationship, not the name)' {
        $ev = Get-XplatEvidence
        (@($ev.assets | Where-Object type -eq 'vcenter')[0]).name = 'renamed-vc'
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'credential-exposure' -and $_.source -eq 'ep-nsx01:manager' }).Count | Should -Be 1
    }
    It 'denied computeManagers become needsEvidence candidates, not edges' {
        $ev = Get-XplatEvidence
        $m = @($ev.assets | Where-Object type -eq 'nsx-manager')[0]
        $m.facts.computeManagers = @{ status = 'denied'; value = $null; error = '403' }
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'credential-exposure' -and $_.source -eq $m.id }) | Should -BeNullOrEmpty
        @($g.needsEvidence | Where-Object { $_.kind -eq 'credential-exposure' -and $_.source -eq $m.id -and $_.status -eq 'denied' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Security graph: operator-declared edges' {
    It 'creates credential-exposure and member-of edges from the scope file' {
        $ev = Get-XplatEvidence
        $ev.scope.credentialStores = @(@{ match = 'name:jump01'; grants = 'type:nsx-manager'; note = 'saved admin credentials' })
        $ev.scope.identityGroups = @(@{ group = 'EXAMPLE\vi-admins'; members = @('EXAMPLE\alice') })
        $g = Get-XplatGraph $ev
        $cs = @($g.edges.Values | Where-Object { $_.kind -eq 'credential-exposure' -and $_.confidence -eq 'operator-declared' })
        $cs.Count | Should -Be 1
        $cs[0].target | Should -Be 'ep-nsx01:manager'
        $cs[0].fixId | Should -Match '^rotate:'
        $mo = @($g.edges.Values | Where-Object { $_.kind -eq 'member-of' })
        $mo.Count | Should -Be 1
        $mo[0].source | Should -Be 'ad:example\alice'
        $mo[0].target | Should -Be 'ad:example\vi-admins'
        $mo[0].cost | Should -Be 0
        $g.notes | Should -Not -Contain 'AD group nesting not collected; principals are joined by exact normalized name only (declare identityGroups in the scope file)'
    }
}

Describe 'Security graph: crown detection order (data-driven)' {
    It 'management plane wins over operator criticality' {
        $ev = Get-XplatEvidence
        $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
        $vc.criticality = 'high'; $vc.criticalitySource = 'operator'
        $g = Get-XplatGraph $ev
        $g.nodes[$vc.id].crownReason | Should -Be 'management plane (vcenter)'
    }
    It 'operator high wins over inferred high; inferred high still counts' {
        $g = Get-XplatGraph
        $dc = @($g.nodes.Values | Where-Object { $_.name -eq 'dc01' })[0]
        $dc.crown | Should -BeTrue
        $dc.crownReason | Should -Be 'critical asset (operator)'
        $ev = Get-XplatEvidence
        $a = @($ev.assets | Where-Object { $_.name -eq 'backup01' })[0]
        $a.criticality = 'high'; $a.criticalitySource = 'inferred'
        $g2 = Get-XplatGraph $ev
        $g2.nodes[$a.id].crownReason | Should -Be 'critical asset (inferred)'
    }
    It 'is an ordered list later tasks insert into before inferred high' {
        @($script:VsatCrownRules | ForEach-Object id) | Should -Be @('management-plane', 'operator-high', 'ot-workload', 'inferred-high')
        $saved = @($script:VsatCrownRules)
        try {
            Add-VsatCrownRule -Id 'test-ot' -Before 'inferred-high' -Test { param($a) if ($a.name -eq 'backup01') { 'OT asset (test)' } }
            @($script:VsatCrownRules | ForEach-Object id) | Should -Be @('management-plane', 'operator-high', 'ot-workload', 'test-ot', 'inferred-high')
            $g = Get-XplatGraph
            $n = @($g.nodes.Values | Where-Object { $_.name -eq 'backup01' })[0]
            $n.crown | Should -BeTrue
            $n.crownReason | Should -Be 'OT asset (test)'
        }
        finally { $script:VsatCrownRules = [System.Collections.Generic.List[object]]::new(); foreach ($x in $saved) { $script:VsatCrownRules.Add($x) } }
    }
    It 'crowns are sorted and unique' {
        $g = Get-XplatGraph
        (@($g.crowns) -join ',') | Should -Be ((@($g.crowns) | Sort-Object -Unique) -join ',')
    }
}

Describe 'Get-VsatVmIps' {
    It 'unifies vSphere props, Hyper-V adapters and KVM domain ips' {
        $a = [ordered]@{ props = [ordered]@{ ipAddresses = @('10.0.0.1') }; facts = [ordered]@{ adapters = @{ status = 'ok'; value = @(@{ ips = @('10.0.0.2', '10.0.0.1') }) }; domain = @{ status = 'ok'; value = @{ ips = @('10.0.0.3') } } } }
        @(Get-VsatVmIps -Asset $a | Sort-Object) | Should -Be @('10.0.0.1', '10.0.0.2', '10.0.0.3')
    }
    It 'ignores adapters with a non-ok status' {
        $a = [ordered]@{ props = [ordered]@{}; facts = [ordered]@{ adapters = @{ status = 'denied'; value = @(@{ ips = @('10.0.0.2') }) } } }
        @(Get-VsatVmIps -Asset $a).Count | Should -Be 0
    }
}

Describe 'Endpoint resolved addresses (recorded at connect time)' {
    It 'uses an IP literal directly (<In>)' -ForEach @(
        @{ In = '10.0.0.5'; Out = '10.0.0.5' }
        @{ In = 'https://10.0.0.6'; Out = '10.0.0.6' }
        @{ In = '10.0.0.7:5986'; Out = '10.0.0.7' }
        @{ In = '[fe80::1]:22'; Out = 'fe80::1' }
    ) {
        $ep = [ordered]@{ id = 'ep-x'; address = $In }
        Resolve-VsatEndpointAddress -Endpoint $ep
        @($ep.resolvedAddresses) | Should -Be @($Out)
    }
    It 'records an empty list and a note when resolution fails' {
        $ep = [ordered]@{ id = 'ep-x'; address = 'vsat-no-such-host.invalid' }
        Resolve-VsatEndpointAddress -Endpoint $ep
        , $ep.resolvedAddresses | Should -BeOfType [array]
        $ep.resolvedAddresses.Count | Should -Be 0
        $ep.resolvedAddressesNote | Should -Match 'not resolved'
    }
    It 'the demo endpoints carry resolvedAddresses' {
        $ev = Get-TestEvidence
        foreach ($e in $ev.scope.endpoints) { @($e.resolvedAddresses).Count | Should -BeGreaterThan 0 }
    }
    It 'the demo vCenter appliance VM embodies vCenter in the demo lab' {
        $ev = Get-TestEvidence
        [void](Update-VsatNsxDiscovery -Evidence $ev); Invoke-VsatCorrelation -Evidence $ev; $ev.nsx.correlated = $true; Set-VsatScopeAnnotations -Evidence $ev
        $g = Get-XplatGraph $ev
        $e = @($g.edges.Values | Where-Object { $_.kind -eq 'embodies' -and $_.target -eq 'ep-vc01:root' })
        $e.Count | Should -Be 1
        $g.nodes[$e[0].source].name | Should -Be 'vcsa01'
    }
}

Describe 'KVM collector privilege groups (P35)' {
    It 'collects wheel and sudo group membership with getent (read-only)' {
        $script:VsatKvmCollector | Should -Match 'getent group libvirt kvm libvirt-qemu wheel sudo'
    }
}

Describe 'Security graph: vCenter permission scope (fix round 1)' {
    BeforeAll {
        function script:Get-Reach {
            param($G, [string]$From, [string[]]$Confidence)
            $seen = @{ $From = $true }; $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($From)
            while ($q.Count) { $u = $q.Dequeue(); foreach ($e in @($G.out[$u])) { if ($e -and (-not $Confidence -or $e.confidence -in $Confidence) -and -not $seen.ContainsKey($e.target)) { $seen[$e.target] = $true; $q.Enqueue($e.target) } } }
            return $seen
        }
        function script:New-PermEvidence {
            param([object[]]$Perms, [object[]]$Roles)
            $ev = Get-XplatEvidence
            $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
            $vc.facts.permissions = [ordered]@{ status = 'ok'; value = @($Perms) }
            if ($Roles) { $vc.facts.roles = [ordered]@{ status = 'ok'; value = @($Roles) } }
            return $ev
        }
    }
    It 'propagate=false Admin on a cluster reaches hosts only through the configuration-inferred self-grant' {
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\j.doe'; role = 'Admin'; entity = 'cl-prod'; entityId = 'ClusterComputeResource-domain-c8'; propagate = $false; isGroup = $false })
        $g = Get-XplatGraph $ev
        $e = @($g.edges.Values | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\j.doe' })
        $e.Count | Should -Be 1
        $e[0].target | Should -Be 'ep-vc01:domain-c8#object-only@ad:example\j.doe'
        $e[0].confidence | Should -Be 'observed'
        $e[0].propagate | Should -BeFalse
        $e[0].explanation | Should -Match 'not propagating'
        $sink = $g.nodes[$e[0].target]
        $sink.kind | Should -Be 'scope'
        $sink.crown | Should -BeFalse
        $sg = @($g.out[$e[0].target])
        $sg.Count | Should -Be 1
        $sg[0].target | Should -Be 'ep-vc01:domain-c8'
        $sg[0].kind | Should -Be 'admin-of'
        $sg[0].confidence | Should -Be 'configuration-inferred'
        $sg[0].cost | Should -Be 2
        $sg[0].propagate | Should -BeTrue
        $sg[0].fixId | Should -Be 'revoke:ad:example\j.doe@ep-vc01:domain-c8'
        $sg[0].explanation | Should -Match 'holds Authorization\.ModifyPermissions here, so it can grant itself a propagating permission'
        @($sg[0].evidence | ForEach-Object fact) | Should -Contain 'permissions'
        @($sg[0].evidence | ForEach-Object fact) | Should -Contain 'roles'
        # a path to host-* exists, and every such path uses the inferred self-grant: observed edges alone reach no host
        $all = Get-Reach $g 'ad:example\j.doe'
        @($all.Keys | Where-Object { $g.nodes[$_] -and $g.nodes[$_].type -eq 'host' }).Count | Should -BeGreaterThan 0
        $obs = Get-Reach $g 'ad:example\j.doe' -Confidence 'observed'
        @($obs.Keys | Where-Object { $g.nodes[$_] -and $g.nodes[$_].type -eq 'host' }) | Should -BeNullOrEmpty
    }
    It 'propagate=false Admin on the root folder reaches the vCenter crown only through the inferred self-grant' {
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\j.doe'; role = 'Admin'; entity = 'Datacenters'; entityId = 'Folder-group-d1'; propagate = $false; isGroup = $false })
        $g = Get-XplatGraph $ev
        (Get-Reach $g 'ad:example\j.doe').ContainsKey('ep-vc01:root') | Should -BeTrue
        $obs = Get-Reach $g 'ad:example\j.doe' -Confidence 'observed'
        $obs.ContainsKey('ep-vc01:root') | Should -BeFalse
        @($g.crowns | Where-Object { $obs.ContainsKey($_) }) | Should -BeNullOrEmpty
    }
    It 'object-only custom role without ModifyPermissions has no self-grant and reaches no host' {
        $ev = New-PermEvidence -Perms @([ordered]@{ principal = 'EXAMPLE\host-ops'; role = 'HostOps'; entity = 'cl-prod'; entityId = 'ClusterComputeResource-domain-c8'; propagate = $false; isGroup = $true }) -Roles @([ordered]@{ name = 'HostOps'; system = $false; privilegeCount = 12; adminPrivileges = @('Host.Config.Settings') })
        $g = Get-XplatGraph $ev
        $e = @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\host-ops' })
        $e.Count | Should -Be 1
        $e[0].target | Should -Be 'ep-vc01:domain-c8#object-only'
        @($g.out[$e[0].target]).Where({ $_ }).Count | Should -Be 0
        $reach = Get-Reach $g 'ad:example\host-ops'
        @($reach.Keys | Where-Object { $g.nodes[$_] -and $g.nodes[$_].type -eq 'host' }) | Should -BeNullOrEmpty
    }
    It 'object-only custom role with ModifyPermissions gets the self-grant' {
        $ev = New-PermEvidence -Perms @([ordered]@{ principal = 'EXAMPLE\perm-ops'; role = 'PermOps'; entity = 'cl-prod'; entityId = 'ClusterComputeResource-domain-c8'; propagate = $false; isGroup = $true }) -Roles @([ordered]@{ name = 'PermOps'; system = $false; privilegeCount = 3; adminPrivileges = @('Authorization.ModifyPermissions') })
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.confidence -eq 'configuration-inferred' -and $_.target -eq 'ep-vc01:domain-c8' -and $_.fixId -eq 'revoke:ad:example\perm-ops@ep-vc01:domain-c8' }).Count | Should -Be 1
    }
    It 'non-propagating VirtualMachinePowerUser on a cluster reaches no host' {
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\helpdesk'; role = 'VirtualMachinePowerUser'; entity = 'cl-dmz'; entityId = 'ClusterComputeResource-domain-c9'; propagate = $false; isGroup = $true })
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.confidence -eq 'configuration-inferred' }) | Should -BeNullOrEmpty
        $reach = Get-Reach $g 'ad:example\helpdesk'
        @($reach.Keys | Where-Object { $g.nodes[$_] -and $g.nodes[$_].type -in @('host', 'cluster', 'vcenter') }) | Should -BeNullOrEmpty
    }
    It 'propagating Admin on a cluster reaches its hosts and records propagate=true' {
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\j.doe'; role = 'Admin'; entity = 'cl-prod'; entityId = 'ClusterComputeResource-domain-c8'; propagate = $true; isGroup = $false })
        $g = Get-XplatGraph $ev
        $e = @($g.edges.Values | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\j.doe' })
        $e[0].target | Should -Be 'ep-vc01:domain-c8'
        $e[0].propagate | Should -BeTrue
        $reach = Get-Reach $g 'ad:example\j.doe'
        @($reach.Keys | Where-Object { $g.nodes[$_] -and $g.nodes[$_].type -eq 'host' }).Count | Should -BeGreaterThan 0
    }
    It 'propagating Admin on the root folder is vCenter admin' {
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\vi-admins'; role = 'Admin'; entity = 'Datacenters'; entityId = 'Folder-group-d1'; propagate = $true; isGroup = $true })
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\vi-admins' })[0].target | Should -Be 'ep-vc01:root'
    }
    It 'an unknown inventory object is never widened to vCenter: no edge, needsEvidence inventory:<moref>' {
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\vm-ops'; role = 'Admin'; entity = 'Linux VMs'; entityId = 'Folder-group-v3'; propagate = $true; isGroup = $true })
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\vm-ops' }) | Should -BeNullOrEmpty
        $ne = @($g.needsEvidence | Where-Object { $_.missingFact -eq 'inventory:group-v3' })
        $ne.Count | Should -Be 1
        $ne[0].kind | Should -Be 'admin-of'
        $ne[0].source | Should -Be 'ad:example\vm-ops'
        $ne[0].assetId | Should -Be 'ep-vc01:root'
        $ne[0].status | Should -Be 'missing'
    }
    It 'a non-admin role on a cluster reaches only the VMs beneath it, never the hosts' {
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\helpdesk'; role = 'VirtualMachinePowerUser'; entity = 'cl-dmz'; entityId = 'ClusterComputeResource-domain-c9'; propagate = $true; isGroup = $true })
        $g = Get-XplatGraph $ev
        $e = @($g.edges.Values | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\helpdesk' })
        $e.Count | Should -BeGreaterThan 0
        foreach ($x in $e) { $g.nodes[$x.target].type | Should -Be 'vm'; $x.fixId | Should -Be 'revoke:ad:example\helpdesk@ep-vc01:domain-c9' }
        $reach = Get-Reach $g 'ad:example\helpdesk'
        @($reach.Keys | Where-Object { $g.nodes[$_] -and $g.nodes[$_].type -in @('host', 'cluster', 'vcenter') }) | Should -BeNullOrEmpty
        # the VMs are exactly those running on cl-dmz hosts
        $ctx = New-VsatRuleContext -Evidence $ev -ProfileName standard
        $hosts = @($ctx.out['ep-vc01:domain-c9'] | Where-Object type -eq 'contains' | ForEach-Object target)
        $vms = @($hosts | ForEach-Object { @($ctx.in[$_] | Where-Object type -eq 'runs-on' | ForEach-Object source) } | Sort-Object -Unique)
        (@($e | ForEach-Object target | Sort-Object) -join ',') | Should -Be ($vms -join ',')
    }
    It 'a custom role with Host.Config privileges counts as admin-equivalent' {
        $ev = New-PermEvidence -Perms @([ordered]@{ principal = 'EXAMPLE\host-ops'; role = 'HostOps'; entity = 'cl-dmz'; entityId = 'ClusterComputeResource-domain-c9'; propagate = $true; isGroup = $true }) -Roles @([ordered]@{ name = 'HostOps'; system = $false; privilegeCount = 12; adminPrivileges = @('Host.Config.Settings') })
        $g = Get-XplatGraph $ev
        @($g.edges.Values | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\host-ops' })[0].target | Should -Be 'ep-vc01:domain-c9'
    }
    It 'NoCryptoAdmin and NoTrustedAdmin are admin-equivalent' {
        $ev = New-PermEvidence @(
            [ordered]@{ principal = 'EXAMPLE\a1'; role = 'NoCryptoAdmin'; entity = 'cl-dmz'; entityId = 'ClusterComputeResource-domain-c9'; propagate = $true; isGroup = $false }
            [ordered]@{ principal = 'EXAMPLE\a2'; role = 'NoTrustedAdmin'; entity = 'cl-dmz'; entityId = 'ClusterComputeResource-domain-c9'; propagate = $true; isGroup = $false })
        $g = Get-XplatGraph $ev
        foreach ($p in 'ad:example\a1', 'ad:example\a2') { @($g.edges.Values | Where-Object { $_.source -eq $p })[0].target | Should -Be 'ep-vc01:domain-c9' }
    }
    It 'propagate=false on a leaf (VM) keeps a direct edge' {
        $vm = 'ep-vc01:vm-207'
        $ev = New-PermEvidence @([ordered]@{ principal = 'EXAMPLE\j.doe'; role = 'Admin'; entity = 'x'; entityId = 'VirtualMachine-vm-207'; propagate = $false; isGroup = $false })
        $g = Get-XplatGraph $ev
        $e = @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\j.doe' })
        $e.Count | Should -Be 1
        $e[0].target | Should -Be $vm
        $e[0].propagate | Should -BeFalse
    }
}

Describe 'Security graph: unknown role privileges (fix round 3)' {
    BeforeAll {
        function script:New-RolePermGraph {
            param([bool]$Propagate, $RolesFact, [string]$Role = 'CustomOps', [string]$EntityId = 'ClusterComputeResource-domain-c9')
            $ev = Get-XplatEvidence
            $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
            $vc.facts.permissions = [ordered]@{ status = 'ok'; value = @([ordered]@{ principal = 'EXAMPLE\ops'; role = $Role; entity = 'x'; entityId = $EntityId; propagate = $Propagate; isGroup = $true }) }
            if ($RolesFact) { $vc.facts.roles = $RolesFact }
            return (Get-XplatGraph $ev)
        }
    }
    It 'roles denied + custom role on a propagating cluster: only VM edges plus a roles gap' {
        $g = New-RolePermGraph -Propagate $true -RolesFact ([ordered]@{ status = 'denied'; value = $null; error = 'NoPermission' })
        $e = @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\ops' })
        $e.Count | Should -BeGreaterThan 0
        foreach ($x in $e) { $g.nodes[$x.target].type | Should -Be 'vm' }
        $gap = @($g.needsEvidence | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\ops' -and $_.target -eq 'ep-vc01:domain-c9' -and $_.missingFact -eq 'roles' })
        $gap.Count | Should -Be 1
        $gap[0].status | Should -Be 'denied'
    }
    It 'roles denied + custom role, propagate=false: object-only sink, no self-grant, plus a roles gap' {
        $g = New-RolePermGraph -Propagate $false -RolesFact ([ordered]@{ status = 'denied'; value = $null; error = 'NoPermission' })
        @($g.edges.Values | Where-Object { $_.confidence -eq 'configuration-inferred' }) | Should -BeNullOrEmpty
        @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\ops' })[0].target | Should -Be 'ep-vc01:domain-c9#object-only'
        $gap = @($g.needsEvidence | Where-Object { $_.kind -eq 'admin-of' -and $_.source -eq 'ad:example\ops' -and $_.target -eq 'ep-vc01:domain-c9' -and $_.missingFact -eq 'roles' })
        $gap.Count | Should -Be 1
        $gap[0].status | Should -Be 'denied'
    }
    It 'role row without adminPrivileges (2.0/2.2 evidence) is unknown: roles gap with status missing' {
        $g = New-RolePermGraph -Propagate $true -RolesFact ([ordered]@{ status = 'ok'; value = @([ordered]@{ name = 'CustomOps'; system = $false; privilegeCount = 30 }) })
        @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\ops' -and $g.nodes[$_.target].type -ne 'vm' }) | Should -BeNullOrEmpty
        $gap = @($g.needsEvidence | Where-Object { $_.source -eq 'ad:example\ops' -and $_.missingFact -eq 'roles' })
        $gap.Count | Should -Be 1
        $gap[0].status | Should -Be 'missing'
    }
    It 'role absent from the roles list is unknown (roles gap, status missing)' {
        $g = New-RolePermGraph -Propagate $true -Role 'NotListed'
        @($g.needsEvidence | Where-Object { $_.source -eq 'ad:example\ops' -and $_.missingFact -eq 'roles' -and $_.status -eq 'missing' }).Count | Should -Be 1
    }
    It 'built-in admin roles need no roles evidence (no gap even when roles is denied)' {
        $g = New-RolePermGraph -Propagate $true -Role 'Admin' -RolesFact ([ordered]@{ status = 'denied'; value = $null })
        @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\ops' })[0].target | Should -Be 'ep-vc01:domain-c9'
        @($g.needsEvidence | Where-Object { $_.missingFact -eq 'roles' }) | Should -BeNullOrEmpty
    }
    It 'a known non-admin custom role creates no roles gap' {
        $g = New-RolePermGraph -Propagate $true -Role 'VirtualMachinePowerUser'
        @($g.needsEvidence | Where-Object { $_.missingFact -eq 'roles' }) | Should -BeNullOrEmpty
    }
    It 'a non-admin role on a host reaches only the VMs on that host' {
        $g = New-RolePermGraph -Propagate $true -Role 'VirtualMachinePowerUser' -EntityId 'HostSystem-host-10'
        $e = @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\ops' })
        $e.Count | Should -BeGreaterThan 0
        $onHost = @($g.edges.Values | Where-Object { $_.kind -eq 'controls' -and $_.source -eq 'ep-vc01:host-10' } | ForEach-Object target | Sort-Object)
        (@($e | ForEach-Object target | Sort-Object) -join ',') | Should -Be ($onHost -join ',')
        @($e | Where-Object { $_.target -eq 'ep-vc01:host-10' }) | Should -BeNullOrEmpty
    }
    It 'cites the roles fact when admin status comes from a collected role row' {
        $g = New-RolePermGraph -Propagate $true -Role 'HostOps' -RolesFact ([ordered]@{ status = 'ok'; value = @([ordered]@{ name = 'HostOps'; system = $false; privilegeCount = 5; adminPrivileges = @('Host.Config.Settings') }) })
        $e = @($g.edges.Values | Where-Object { $_.source -eq 'ad:example\ops' })[0]
        $e.target | Should -Be 'ep-vc01:domain-c9'
        @($e.evidence | ForEach-Object fact) | Should -Contain 'roles'
        $g2 = New-RolePermGraph -Propagate $true -Role 'VirtualMachinePowerUser'
        foreach ($x in @($g2.edges.Values | Where-Object { $_.source -eq 'ad:example\ops' })) { @($x.evidence | ForEach-Object fact) | Should -Contain 'roles' }
    }
    It 'creates the principal node for a grant on an unknown object' {
        $g = New-RolePermGraph -Propagate $true -Role 'Admin' -EntityId 'Folder-group-v3'
        $g.nodes.ContainsKey('ad:example\ops') | Should -BeTrue
    }
}

Describe 'Security graph: fix round 1 minors' {
    It 'adds an aggregate note for vSphere VMs without IPs' {
        $ev = Get-XplatEvidence
        (@($ev.assets | Where-Object { $_.type -eq 'vm' -and -not $_.props.template -and @($_.props.ipAddresses).Count })[0]).props.ipAddresses = @()
        $n = @($ev.assets | Where-Object { $_.type -eq 'vm' -and -not $_.props.template -and -not @($_.props.ipAddresses | Where-Object { $_ }).Count }).Count
        $n | Should -BeGreaterThan 0
        $g = Get-XplatGraph $ev
        $g.notes | Should -Contain "$n vSphere VMs report no IP (VMware Tools); embodies correlation unknown for them"
    }
    It 'merges evidence when the same edge is added twice' {
        $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new(); needsEvidence = [System.Collections.Generic.List[object]]::new() }
        $a = Add-VsatGraphEdge $G 's' 't' 'controls' 'observed' 1 $null @([ordered]@{ assetId = 's'; fact = 'relationships'; status = 'ok' })
        $b = Add-VsatGraphEdge $G 's' 't' 'controls' 'observed' 1 $null @([ordered]@{ assetId = 't'; fact = 'relationships'; status = 'ok' }, [ordered]@{ assetId = 's'; fact = 'relationships'; status = 'ok' })
        $b.id | Should -Be $a.id
        @($G.edges[$a.id].evidence).Count | Should -Be 2
        $G.out['s'].Count | Should -Be 1
    }
    It 'admin-of findingKeys come only from identity/privilege rules' {
        $g = Get-XplatGraph
        $keys = @($g.edges.Values | Where-Object kind -eq 'admin-of' | ForEach-Object { $_.findingKeys })
        foreach ($k in $keys) { ($k -split '\|')[0] | Should -BeIn $script:VsatIdentityRuleIds }
    }
    It 'operator-declared edges cite the scope file' {
        $ev = Get-XplatEvidence
        $ev.scope.credentialStores = @(@{ match = 'name:jump01'; grants = 'type:nsx-manager' })
        $ev.scope.identityGroups = @(@{ group = 'EXAMPLE\vi-admins'; members = @('EXAMPLE\alice') })
        $g = Get-XplatGraph $ev
        $cs = @($g.edges.Values | Where-Object { $_.confidence -eq 'operator-declared' -and $_.kind -eq 'credential-exposure' })[0]
        $cs.evidence[0].assetId | Should -Be 'scope'; $cs.evidence[0].fact | Should -Be 'credentialStores'; $cs.evidence[0].status | Should -Be 'ok'
        $mo = @($g.edges.Values | Where-Object kind -eq 'member-of')[0]
        $mo.evidence[0].assetId | Should -Be 'scope'; $mo.evidence[0].fact | Should -Be 'identityGroups'
    }
    It 'records the vCenter root folder moref' {
        (@((Get-TestEvidence).assets | Where-Object type -eq 'vcenter')[0]).props.rootFolder | Should -Be 'group-d1'
    }
}

Describe 'Blast radius search' {
    BeforeAll {
        $script:Ev = Get-XplatEvidence
        $r = Invoke-VsatRules -Evidence $script:Ev -ProfileName standard
        $script:Ctx = $r.context
        $script:G = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
        $script:BR = Get-VsatBlastRadius -Graph $script:G -Context $r.context
    }
    It 'finds the cross-platform path Hyper-V admin -> vcsa VM -> vCenter -> ESXi' {
        # P58: the xplat vCenter VM is vcsa-hv01 (hyperv-vm); pick paths whose entry is a principal.
        $p = @($script:BR.paths | Where-Object { $script:G.nodes[$_.entry].kind -eq 'principal' -and @($_.platforms) -contains 'hyperv' -and @($_.platforms) -contains 'vmware' -and $script:G.nodes[$_.crown].type -eq 'vcenter' })
        $p.Count | Should -BeGreaterThan 0
        $kinds = @($p[0].edgeIds | ForEach-Object { $script:G.edges[$_].kind })
        $kinds | Should -Contain 'admin-of'; $kinds | Should -Contain 'controls'; $kinds | Should -Contain 'embodies'
        $p[0].narrative | Should -Match 'hv01'
    }
    It 'is deterministic (same evidence => identical path ids and edge sequences)' {
        $b2 = Get-VsatBlastRadius -Graph (New-VsatSecurityGraph -Context $script:Ctx -Findings @()) -Context $script:Ctx
        ($b2.paths | ForEach-Object { "$($_.id)=" + ($_.edgeIds -join '>') }) -join '|' | Should -Be (($script:BR.paths | ForEach-Object { "$($_.id)=" + ($_.edgeIds -join '>') }) -join '|')
    }
    It 'ranks relocating the vCenter appliance as a top fix' {
        $fp = Get-VsatFixPlan -Paths $script:BR.paths -Graph $script:G
        @($fp | Select-Object -First 3).fixId | Should -Contain ("relocate:" + @($script:Ev.assets | Where-Object { $_.type -eq 'hyperv-vm' -and $_.name -eq 'vcsa-hv01' })[0].id)
        $fp[0].cumulativeBroken | Should -BeLessOrEqual $fp[0].pathsTotal
        for ($i = 1; $i -lt $fp.Count; $i++) { $fp[$i].cumulativeBroken | Should -BeGreaterOrEqual $fp[$i - 1].cumulativeBroken }
    }
    It 'never uses inherent (fixId null) edges as fixes' {
        @(Get-VsatFixPlan -Paths $script:BR.paths -Graph $script:G | Where-Object { -not $_.fixId }) | Should -BeNullOrEmpty
    }
    It 'respects MaxPaths and reports truncation' {
        $b = Get-VsatBlastRadius -Graph $script:G -Context $script:Ctx -MaxPaths 2
        @($b.paths).Count | Should -BeLessOrEqual 2
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match 'bounds hit' }).Count | Should -BeGreaterThan 0
    }
    It 'handles a synthetic 10k-VM / 2k-principal graph within budget' -Tag 'perf' {
        $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new() }
        [void](Add-VsatGraphNode $G 'vc' 'asset' 'vcenter' 'vc' 'vmware'); $G.nodes['vc'].crown = $true; $G.crowns = @('vc')
        for ($h = 0; $h -lt 200; $h++) { [void](Add-VsatGraphNode $G "h$h" 'asset' 'host' "h$h" 'vmware'); [void](Add-VsatGraphEdge $G 'vc' "h$h" 'controls' 'observed' 1 $null @(@{assetId='vc';fact='x';status='ok'})) }
        for ($v = 0; $v -lt 10000; $v++) { [void](Add-VsatGraphNode $G "v$v" 'asset' 'vm' "v$v" 'vmware'); [void](Add-VsatGraphEdge $G "h$($v % 200)" "v$v" 'controls' 'observed' 1 $null @(@{assetId='x';fact='x';status='ok'})) }
        for ($p = 0; $p -lt 2000; $p++) { [void](Add-VsatGraphNode $G "p$p" 'principal' 'user' "p$p" 'identity'); [void](Add-VsatGraphEdge $G "p$p" "h$($p % 200)" 'admin-of' 'observed' 1 "revoke:p$p" @(@{assetId='x';fact='x';status='ok'})) }
        $G.nodes['v42'].crown = $true; $G.crowns = @('vc', 'v42')
        # Fix round 1 (MINOR-1): make it real. Every principal is also vCenter admin, ~1,000 crown VMs.
        $cr = [System.Collections.Generic.List[string]]::new(); $cr.Add('vc')
        for ($v = 0; $v -lt 10000; $v += 10) { $G.nodes["v$v"].crown = $true; $cr.Add("v$v") }
        $cr.Add('v42')
        for ($p = 0; $p -lt 2000; $p++) { [void](Add-VsatGraphEdge $G "p$p" 'vc' 'admin-of' 'observed' 1 "revoke:p$p@vc" @(@{assetId='x';fact='x';status='ok'})) }
        $G.crowns = Get-VsatOrdinalSorted $cr
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $b = Get-VsatBlastRadius -Graph $G -Context @{ evidence = @{ assets = @() }; assets = @{} } -BudgetMs 20000
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
        @($b.paths).Count | Should -BeGreaterThan 0
        @($b.paths).Count | Should -BeLessOrEqual 500
        # 2k principals exceed maxSources and the paths exceed maxPaths: bounded, and it says so.
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match 'bounds hit' -and $_ -match 'principals' }).Count | Should -Be 1
        @($b.notes | Where-Object { $_ -match 'bounds hit' -and $_ -match 'maxPaths' }).Count | Should -Be 1
        $b.bounds.pathsFound | Should -BeGreaterThan @($b.paths).Count
        $b.bounds.crownsReachable | Should -BeGreaterThan 900
        # maxPaths is shared across entries, not spent on the first one.
        # maxNodes stops the search after ~24 of the 60 capped principals (each reaches ~10k nodes); every
        # principal that was searched is represented in paths (maxPaths is shared, not spent on the first).
        @($b.notes | Where-Object { $_ -match 'bounds hit' -and $_ -match 'maxNodes' }).Count | Should -Be 1
        @($b.paths | ForEach-Object { $_.entry } | Sort-Object -Unique).Count | Should -BeGreaterThan 20
    }
}

Describe 'Blast radius: bounds and scale' {
    BeforeAll {
        function script:New-FlatGraph {
            # Admin p0 of hub h0 that controls N VMs; crowns: vc and every 10th VM.
            param([int]$Vms = 3000, [int]$Principals = 5)
            $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new(); needsEvidence = [System.Collections.Generic.List[object]]::new() }
            [void](Add-VsatGraphNode $G 'h0' 'asset' 'host' 'h0' 'vmware')
            $crowns = [System.Collections.Generic.List[string]]::new()
            for ($v = 0; $v -lt $Vms; $v++) { [void](Add-VsatGraphNode $G "v$v" 'asset' 'vm' "v$v" 'vmware'); [void](Add-VsatGraphEdge $G 'h0' "v$v" 'controls' 'observed' 1 $null @(@{ assetId = 'x'; fact = 'x'; status = 'ok' })); if ($v % 10 -eq 0) { $G.nodes["v$v"].crown = $true; $crowns.Add("v$v") } }
            for ($p = 0; $p -lt $Principals; $p++) { [void](Add-VsatGraphNode $G "p$p" 'principal' 'user' "p$p" 'identity'); [void](Add-VsatGraphEdge $G "p$p" 'h0' 'admin-of' 'observed' 1 "revoke:p$p@h0" @(@{ assetId = 'x'; fact = 'x'; status = 'ok' })) }
            $G.crowns = Get-VsatOrdinalSorted $crowns
            return $G
        }
    }
    It 'caps principal entries at maxSources, most admin-of edges first, ordinal tie-break, with a note' {
        $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @('c'); entries = @(); notes = [System.Collections.Generic.List[string]]::new(); needsEvidence = [System.Collections.Generic.List[object]]::new() }
        [void](Add-VsatGraphNode $G 'c' 'asset' 'vcenter' 'c' 'vmware'); $G.nodes['c'].crown = $true
        foreach ($n in 'pb', 'pa', 'pc', 'pz') { [void](Add-VsatGraphNode $G $n 'principal' 'user' $n 'identity'); [void](Add-VsatGraphEdge $G $n 'c' 'admin-of' 'observed' 1 "revoke:$n@c" @(@{ assetId = 'x'; fact = 'x'; status = 'ok' })) }
        [void](Add-VsatGraphNode $G 'h' 'asset' 'host' 'h' 'vmware')
        [void](Add-VsatGraphEdge $G 'pz' 'h' 'admin-of' 'observed' 1 'revoke:pz@h' @(@{ assetId = 'x'; fact = 'x'; status = 'ok' }))
        $b = Get-VsatBlastRadius -Graph $G -Context @{ evidence = @{ assets = @() }; assets = @{} } -MaxSources 2
        @($b.entries) | Should -Be @('pz', 'pa')
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match '2 of 4 principals' -and $_ -match 'bounds hit' }).Count | Should -Be 1
    }
    It 'never treats scope (object-only) nodes as principal entries' {
        $ev = Get-XplatEvidence
        $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
        $vc.facts.permissions = [ordered]@{ status = 'ok'; value = @([ordered]@{ principal = 'EXAMPLE\j.doe'; role = 'Admin'; entity = 'cl-prod'; entityId = 'ClusterComputeResource-domain-c8'; propagate = $false; isGroup = $false }) }
        $r = Invoke-VsatRules -Evidence $ev -ProfileName standard
        $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
        $b = Get-VsatBlastRadius -Graph $g -Context $r.context
        @($b.entries | Where-Object { $_ -like '*#object-only*' }) | Should -BeNullOrEmpty
        $b.entries | Should -Contain 'ad:example\j.doe'
    }
    It 'degrades to truncated with a note when the time budget is spent (never hangs)' {
        $G = New-FlatGraph -Vms 3000
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $b = Get-VsatBlastRadius -Graph $G -Context @{ evidence = @{ assets = @() }; assets = @{} } -BudgetMs 1
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 10
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match 'bounds hit' -and $_ -match 'time budget' }).Count | Should -Be 1
    }
    It 'degrades to truncated when the node budget is spent (deterministic bound)' {
        $G = New-FlatGraph -Vms 3000
        $b = Get-VsatBlastRadius -Graph $G -Context @{ evidence = @{ assets = @() }; assets = @{} } -MaxNodes 500
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match 'bounds hit' -and $_ -match 'node budget' }).Count | Should -Be 1
        $b2 = Get-VsatBlastRadius -Graph (New-FlatGraph -Vms 3000) -Context @{ evidence = @{ assets = @() }; assets = @{} } -MaxNodes 500
        (@($b2.paths | ForEach-Object { $_.edgeIds -join '>' }) -join '|') | Should -Be (@($b.paths | ForEach-Object { $_.edgeIds -join '>' }) -join '|')
    }
    It 'never materializes pairwise network-allow edges on a flat L2 switch (lazy, entries only)' {
        # 2000 Hyper-V VMs on one switch and VLAN; 200 are crowns. Only entry VMs get network edges.
        $n = 2000
        $assets = [System.Collections.Generic.List[object]]::new(); $rels = [System.Collections.Generic.List[object]]::new()
        $assets.Add([ordered]@{ id = 'ep-hv:host'; type = 'hyperv-host'; name = 'hv'; endpoint = 'ep-hv'; props = @{}; facts = [ordered]@{} })
        $assets.Add([ordered]@{ id = 'ep-hv:vswitch/s'; type = 'hyperv-vswitch'; name = 'sw'; endpoint = 'ep-hv'; props = @{ allowManagementOS = $false }; facts = [ordered]@{} })
        for ($i = 0; $i -lt $n; $i++) {
            $id = 'ep-hv:vm/{0:d5}' -f $i
            $assets.Add([ordered]@{ id = $id; type = 'hyperv-vm'; name = "vm$i"; endpoint = 'ep-hv'; props = @{}; facts = [ordered]@{ adapters = @{ status = 'ok'; value = @() } }; criticality = $(if ($i % 10 -eq 0) { 'high' } else { $null }); criticalitySource = 'operator' })
            $rels.Add([ordered]@{ source = $id; target = 'ep-hv:host'; type = 'runs-on'; props = @{} })
            $rels.Add([ordered]@{ source = $id; target = 'ep-hv:vswitch/s'; type = 'connects'; props = @{ vlan = 20 } })
        }
        $ev = [ordered]@{ assets = $assets; relationships = $rels; scope = (New-VsatScope $null); nsx = @{} }
        $ctx = New-VsatRuleContext -Evidence $ev -ProfileName standard
        $g = New-VsatSecurityGraph -Context $ctx -Findings @()
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $b = Get-VsatBlastRadius -Graph $g -Context $ctx
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
        $net = @($g.edges.Values | Where-Object kind -eq 'network-allow')
        $net.Count | Should -BeGreaterThan 0
        $net.Count | Should -BeLessOrEqual (@($b.entries).Count * @($g.crowns).Count)
        foreach ($e in $net) { $b.entries | Should -Contain $e.source }
    }
}

Describe 'Blast radius: lazy network and management edges (P34)' {
    BeforeAll {
        function script:Get-XplatBlast {
            param($Evidence)
            if (-not $Evidence) { $Evidence = Get-XplatEvidence }
            $r = Invoke-VsatRules -Evidence $Evidence -ProfileName standard
            $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
            $b = Get-VsatBlastRadius -Graph $g -Context $r.context
            return @{ G = $g; B = $b; Ctx = $r.context; Ev = $Evidence }
        }
        $script:X = Get-XplatBlast
    }
    It 'every network-allow and mgmt-reach edge starts at an entry VM' {
        $lazy = @($script:X.G.edges.Values | Where-Object { $_.kind -in 'network-allow', 'mgmt-reach' })
        $lazy.Count | Should -BeGreaterThan 0
        foreach ($e in $lazy) { $script:X.B.entries | Should -Contain $e.source }
    }
    It 'vSphere: a VM on a trunk portgroup of the management vSwitch reaches the host management vmknic' {
        $jump = @($script:X.Ev.assets | Where-Object name -eq 'jump01')[0]
        $script:X.B.entries | Should -Contain $jump.id
        $e = @($script:X.G.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.source -eq $jump.id })
        $e.Count | Should -Be 1
        $e[0].target | Should -Be 'ep-vc01:host-40'
        $e[0].fixId | Should -Be 'isolate:ep-vc01:host-40'
        $e[0].confidence | Should -Be 'configuration-inferred'
        $e[0].cost | Should -Be 2
        @($e[0].evidence | Where-Object { $_.assetId -eq 'ep-vc01:host-40' -and $_.fact -eq 'vmkernel' -and $_.status -eq 'ok' }).Count | Should -Be 1
    }
    It 'vSphere: services given as a string (not an array) still count as management' {
        # esx04 vmk0 carries services = "management" (a bare string) in the demo lab.
        @($script:X.G.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq 'ep-vc01:host-40' }).Count | Should -BeGreaterThan 0
    }
    It 'Hyper-V: a VM on a switch shared with the management OS reaches the host' {
        $e = @($script:X.G.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq 'ep-hv01:host' })
        $e.Count | Should -BeGreaterThan 0
        $e[0].fixId | Should -Be 'isolate:ep-hv01:host'
    }
    It 'Hyper-V: no mgmt-reach when allowManagementOS is false' {
        $ev = Get-XplatEvidence
        foreach ($s in @($ev.assets | Where-Object type -eq 'hyperv-vswitch')) { $s.props.allowManagementOS = $false }
        $x = Get-XplatBlast $ev
        @($x.G.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq 'ep-hv01:host' }) | Should -BeNullOrEmpty
    }
    It 'KVM: a NAT network plus non-loopback libvirt/ssh listeners reaches the host (props.forwardMode)' {
        $e = @($script:X.G.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq 'ep-kvm01:host' })
        $e.Count | Should -Be 1
        $e[0].explanation | Should -Match '22'
        @($e[0].evidence | Where-Object { $_.fact -eq 'listening' }).Count | Should -Be 1
    }
    It 'KVM: an isolated network (no forward mode) does not reach the host' {
        $ev = Get-XplatEvidence
        foreach ($n in @($ev.assets | Where-Object type -eq 'kvm-network')) { $n.props.forwardMode = '' }
        $x = Get-XplatBlast $ev
        @($x.G.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq 'ep-kvm01:host' }) | Should -BeNullOrEmpty
    }
    It 'KVM: listening not collected is a needsEvidence hop, never an edge' {
        $ev = Get-XplatEvidence
        $h = @($ev.assets | Where-Object type -eq 'kvm-host')[0]
        $h.facts.listening = @{ status = 'denied'; value = $null }
        $x = Get-XplatBlast $ev
        @($x.G.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq $h.id }) | Should -BeNullOrEmpty
        @($x.G.needsEvidence | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq $h.id -and $_.missingFact -eq 'listening' -and $_.status -eq 'denied' }).Count | Should -Be 1
    }
    It 'Hyper-V flat L2: an entry VM reaches a crown VM on the same switch and VLAN (segment fix)' {
        $e = @($script:X.G.edges.Values | Where-Object { $_.kind -eq 'network-allow' -and $_.fixId -eq 'segment:ep-hv01:vswitch/sw-ext-1' })
        $e.Count | Should -BeGreaterThan 0
        $e[0].cost | Should -Be 3
        $e[0].confidence | Should -Be 'configuration-inferred'
    }
}

Describe 'Blast radius: needsEvidence paths and confidence (P8)' {
    BeforeAll {
        function script:Get-XplatBlast2 {
            param($Evidence)
            $r = Invoke-VsatRules -Evidence $Evidence -ProfileName standard
            $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
            return @{ G = $g; B = (Get-VsatBlastRadius -Graph $g -Context $r.context) }
        }
    }
    It 'paths use only present edges; a hop that needs evidence goes to needsEvidence, never to paths or fixPlan' {
        $ev = Get-XplatEvidence
        $h = @($ev.assets | Where-Object type -eq 'hyperv-host')[0]
        $h.facts.admins = @{ status = 'denied'; value = $null }
        $h.facts.hvAdmins = @{ status = 'denied'; value = $null }
        $x = Get-XplatBlast2 $ev
        foreach ($p in $x.B.paths) { foreach ($id in $p.edgeIds) { $x.G.edges.ContainsKey($id) | Should -BeTrue } }
        $ne = @($x.B.needsEvidence | Where-Object { $_.gap.kind -eq 'admin-of' -and $_.gap.target -eq $h.id })
        $ne.Count | Should -Be 2
        $ne[0].entry | Should -Be 'principal:*'
        $ne[0].crown | Should -Not -BeNullOrEmpty
        $ne[0].gap.status | Should -Be 'denied'
        $ne[0].id | Should -Match '^NE-\d{3}$'
        $ne[0].explanation | Should -Match 'Collect'
        $fp = Get-VsatFixPlan -Paths $x.B.paths -Graph $x.G
        $fp[0].pathsTotal | Should -Be @($x.B.paths).Count
    }
    It 'a VM whose IPs were not collected yields a "collect this to confirm" item with its known prefix' {
        $ev = Get-XplatEvidence
        $hv = @($ev.assets | Where-Object { $_.type -eq 'hyperv-vm' -and $_.name -eq 'vcsa-hv01' })[0]
        $hv.facts.adapters = @{ status = 'error'; value = $null }
        $hv.props.ipAddresses = @()
        $x = Get-XplatBlast2 $ev
        $ne = @($x.B.needsEvidence | Where-Object { $_.gap.kind -eq 'embodies' -and $_.gap.source -eq $hv.id })
        $ne.Count | Should -Be 1
        $ne[0].crown | Should -Be 'mgmt:*'
        @($ne[0].edgeIds).Count | Should -BeGreaterThan 0
        $x.G.edges[@($ne[0].edgeIds)[-1]].target | Should -Be $hv.id
    }
    It 'labels each path with the weakest confidence across its edges' {
        $x = Get-XplatBlast2 (Get-XplatEvidence)
        foreach ($p in $x.B.paths) {
            $confs = @($p.edgeIds | ForEach-Object { $x.G.edges[$_].confidence })
            if ($confs -contains 'correlated') { $p.confidence | Should -Be 'correlated' }
            elseif ($confs -contains 'configuration-inferred') { $p.confidence | Should -Be 'configuration-inferred' }
            elseif ($confs -contains 'operator-declared') { $p.confidence | Should -Be 'operator-declared' }
            else { $p.confidence | Should -Be 'observed' }
        }
        @($x.B.paths | Where-Object confidence -eq 'correlated').Count | Should -BeGreaterThan 0
    }
    It 'keeps the configuration-inferred self-grant as a normal (evidence-backed) path edge' {
        $ev = Get-XplatEvidence
        $vc = @($ev.assets | Where-Object type -eq 'vcenter')[0]
        $vc.facts.permissions = [ordered]@{ status = 'ok'; value = @([ordered]@{ principal = 'EXAMPLE\j.doe'; role = 'Admin'; entity = 'Datacenters'; entityId = 'Folder-group-d1'; propagate = $false; isGroup = $false }) }
        $x = Get-XplatBlast2 $ev
        $p = @($x.B.paths | Where-Object { $_.entry -eq 'ad:example\j.doe' -and $_.crown -eq $vc.id })
        $p.Count | Should -Be 1
        $p[0].confidence | Should -Be 'configuration-inferred'
        @($p[0].edgeIds | ForEach-Object { $x.G.edges[$_].confidence }) | Should -Contain 'configuration-inferred'
    }
}

Describe 'Blast radius: result shape and fix titles' {
    BeforeAll {
        $ev = Get-XplatEvidence
        $r = Invoke-VsatRules -Evidence $ev -ProfileName standard
        $script:G3 = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
        $script:B3 = Get-VsatBlastRadius -Graph $script:G3 -Context $r.context
        $script:F3 = Get-VsatFixPlan -Paths $script:B3.paths -Graph $script:G3
    }
    It 'has the §1.2 fields (without fixPlan)' {
        foreach ($k in 'bounds', 'nodes', 'edges', 'paths', 'needsEvidence', 'notes') { $script:B3.Contains($k) | Should -BeTrue }
        $script:B3.Contains('fixPlan') | Should -BeFalse
        foreach ($k in 'maxDepth', 'maxPaths', 'maxSources', 'truncated', 'elapsedMs') { $script:B3.bounds.Contains($k) | Should -BeTrue }
        $p = $script:B3.paths[0]
        foreach ($k in 'id', 'entry', 'crown', 'cost', 'edgeIds', 'platforms', 'narrative', 'confidence') { $p.Contains($k) | Should -BeTrue }
        $p.id | Should -Be 'BR-001'
    }
    It 'exports every edge on a path and every crown node' {
        $ids = @{}; foreach ($e in $script:B3.edges) { $ids[$e.id] = $true }
        foreach ($p in $script:B3.paths) { foreach ($id in $p.edgeIds) { $ids.ContainsKey($id) | Should -BeTrue } }
        $nids = @($script:B3.nodes | ForEach-Object { $_.id })
        foreach ($c in $script:G3.crowns) { $nids | Should -Contain $c }
    }
    It 'paths are sorted by cost with sequential ids' {
        for ($i = 1; $i -lt @($script:B3.paths).Count; $i++) { $script:B3.paths[$i].cost | Should -BeGreaterOrEqual $script:B3.paths[$i - 1].cost }
    }
    It 'every edge carries an attack field (P9: set in Add-VsatGraphEdge; mapping is a hook)' {
        foreach ($e in $script:B3.edges) { $e.Contains('attack') | Should -BeTrue }
    }
    It 'calls the ATT&CK hook for lazily added edges too' {
        $saved = $script:VsatEdgeAttackHook
        try {
            $script:VsatEdgeAttackHook = { param($Edge, $Graph) if ($Edge.kind -eq 'mgmt-reach') { @{ technique = 'TEST'; name = 'test' } } }
            $ev = Get-XplatEvidence
            $r = Invoke-VsatRules -Evidence $ev -ProfileName standard
            $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
            [void](Get-VsatBlastRadius -Graph $g -Context $r.context)
            @($g.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.attack.technique -eq 'TEST' }).Count | Should -BeGreaterThan 0
        }
        finally { $script:VsatEdgeAttackHook = $saved }
    }
    It 'splits revoke fixIds on the LAST @ (P6: upn principal keys contain @)' {
        $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new() }
        [void](Add-VsatGraphNode $G 'upn:ops@other.corp' 'principal' 'user' 'ops@other.corp' 'identity')
        [void](Add-VsatGraphNode $G 'ep-vc01:root' 'asset' 'vcenter' 'vc01' 'vmware')
        Get-VsatFixTitle 'revoke:upn:ops@other.corp@ep-vc01:root' $G | Should -Be 'Remove ops@other.corp admin rights on vc01'
    }
    It 'fix plan entries carry title, work package and kind; relocate is management isolation' {
        foreach ($f in $script:F3) { foreach ($k in 'rank', 'fixId', 'title', 'kind', 'pathsBroken', 'cumulativeBroken', 'pathsTotal', 'findingKeys', 'workPackage') { $f.Contains($k) | Should -BeTrue } }
        $rel = @($script:F3 | Where-Object { $_.fixId -like 'relocate:*' })[0]
        $rel.workPackage | Should -Be 'WP-MGMT-ISOLATION'
        $rel.title | Should -Match 'vcsa-hv01'
        $rel.title | Should -Match 'hv01'
        $wps = @((Get-VsatRulePackMeta).workPackages | ForEach-Object { $_.id })
        foreach ($f in $script:F3) { $wps | Should -Contain $f.workPackage }
    }
    It 'fix plan is greedy on weighted remaining paths with an ordinal tie-break' {
        $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new() }
        foreach ($n in 'a', 'b', 'c1', 'c2') { [void](Add-VsatGraphNode $G $n 'asset' 'vm' $n 'vmware') }
        $e1 = Add-VsatGraphEdge $G 'a' 'c1' 'mgmt-reach' 'configuration-inferred' 2 'isolate:y' @(@{ assetId = 'a'; fact = 'x'; status = 'ok' })
        $e2 = Add-VsatGraphEdge $G 'b' 'c2' 'mgmt-reach' 'configuration-inferred' 2 'isolate:x' @(@{ assetId = 'b'; fact = 'x'; status = 'ok' })
        $paths = @(
            [ordered]@{ id = 'BR-001'; entry = 'a'; crown = 'c1'; cost = 2; edgeIds = @($e1.id); criticality = 'high' }
            [ordered]@{ id = 'BR-002'; entry = 'b'; crown = 'c2'; cost = 2; edgeIds = @($e2.id); criticality = 'high' }
        )
        $fp = Get-VsatFixPlan -Paths $paths -Graph $G
        $fp[0].fixId | Should -Be 'isolate:x'
        $fp[1].fixId | Should -Be 'isolate:y'
        $fp[1].cumulativeBroken | Should -Be 2
        $paths[0].criticality = 'low'
        (Get-VsatFixPlan -Paths $paths -Graph $G)[0].fixId | Should -Be 'isolate:x'
        $paths[0].criticality = 'high'; $paths[1].criticality = 'low'
        (Get-VsatFixPlan -Paths $paths -Graph $G)[0].fixId | Should -Be 'isolate:y'
    }
}

Describe 'Blast radius: declared entry points' {
    It 'uses scope entryPoints (asset match and principal) instead of the default set' {
        $ev = Get-XplatEvidence
        $ev.scope.entryPoints = @(@{ match = 'name:jump01' }, @{ principal = 'EXAMPLE\j.doe' })
        $r = Invoke-VsatRules -Evidence $ev -ProfileName standard
        $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
        $b = Get-VsatBlastRadius -Graph $g -Context $r.context
        $jump = @($ev.assets | Where-Object name -eq 'jump01')[0].id
        @($b.entries) | Should -Be @('ad:example\j.doe', $jump)
        @($b.paths | Where-Object { $_.entry -notin @('ad:example\j.doe', $jump) }) | Should -BeNullOrEmpty
        @($b.paths | Where-Object entry -eq 'ad:example\j.doe').Count | Should -BeGreaterThan 0
        @($g.edges.Values | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.source -eq $jump }).Count | Should -Be 1
    }
}

Describe 'Blast radius: fix round 1 (depth, fairness, undecidable DFW)' {
    BeforeAll {
        $script:Ok = @{ assetId = 'x'; fact = 'x'; status = 'ok' }
        $script:NoCtx = @{ evidence = @{ assets = @() }; assets = @{} }
        function script:New-EmptyGraph { [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new(); needsEvidence = [System.Collections.Generic.List[object]]::new() } }
    }
    It 'reports the depth limit when a crown lies beyond maxDepth (never silent)' {
        $G = New-EmptyGraph
        [void](Add-VsatGraphNode $G 'p' 'principal' 'user' 'p' 'identity')
        [void](Add-VsatGraphNode $G 'n0' 'asset' 'host' 'n0' 'vmware'); [void](Add-VsatGraphEdge $G 'p' 'n0' 'admin-of' 'observed' 1 'revoke:p@n0' @($script:Ok))
        for ($i = 1; $i -le 9; $i++) { [void](Add-VsatGraphNode $G "n$i" 'asset' 'host' "n$i" 'vmware'); [void](Add-VsatGraphEdge $G "n$($i - 1)" "n$i" 'controls' 'observed' 1 $null @($script:Ok)) }
        $G.nodes['n9'].crown = $true; $G.crowns = @('n9')
        $b = Get-VsatBlastRadius -Graph $G -Context $script:NoCtx
        @($b.paths).Count | Should -Be 0
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match 'depth limit of 8 hops reached \(maxDepth\)' }).Count | Should -Be 1
    }
    It 'a cheap long route to a node never masks a short route through it to a crown' {
        $G = New-EmptyGraph
        [void](Add-VsatGraphNode $G 'p' 'principal' 'user' 'p' 'identity')
        $prev = 'p'
        for ($i = 1; $i -le 8; $i++) { [void](Add-VsatGraphNode $G "n$i" 'asset' 'host' "n$i" 'vmware'); [void](Add-VsatGraphEdge $G $prev "n$i" 'embodies' 'correlated' 0 "relocate:n$i" @($script:Ok)); $prev = "n$i" }
        [void](Add-VsatGraphEdge $G 'p' 'n8' 'admin-of' 'observed' 1 'revoke:p@n8' @($script:Ok))
        [void](Add-VsatGraphNode $G 'c' 'asset' 'vcenter' 'c' 'vmware'); $G.nodes['c'].crown = $true; $G.crowns = @('c')
        [void](Add-VsatGraphEdge $G 'n8' 'c' 'controls' 'observed' 1 $null @($script:Ok))
        $b = Get-VsatBlastRadius -Graph $G -Context $script:NoCtx
        @($b.paths).Count | Should -Be 1
        $b.paths[0].hops | Should -Be 2
        $b.paths[0].cost | Should -Be 2
    }
    It 'maxPaths is shared: two principals with disjoint crowns both appear' {
        $G = New-EmptyGraph
        foreach ($h in 'h', 'h2') { [void](Add-VsatGraphNode $G $h 'asset' 'host' $h 'vmware') }
        foreach ($p in 'pa', 'pb') { [void](Add-VsatGraphNode $G $p 'principal' 'user' $p 'identity') }
        [void](Add-VsatGraphEdge $G 'pa' 'h' 'admin-of' 'observed' 1 'revoke:pa@h' @($script:Ok))
        [void](Add-VsatGraphEdge $G 'pb' 'h2' 'admin-of' 'observed' 1 'revoke:pb@h2' @($script:Ok))
        $cr = @()
        for ($i = 0; $i -lt 5; $i++) { [void](Add-VsatGraphNode $G "c$i" 'asset' 'vcenter' "c$i" 'vmware'); $G.nodes["c$i"].crown = $true; $cr += "c$i"; [void](Add-VsatGraphEdge $G 'h' "c$i" 'controls' 'observed' 1 $null @($script:Ok)) }
        [void](Add-VsatGraphNode $G 'cz' 'asset' 'vcenter' 'cz' 'vmware'); $G.nodes['cz'].crown = $true; $cr += 'cz'; [void](Add-VsatGraphEdge $G 'h2' 'cz' 'controls' 'observed' 1 $null @($script:Ok))
        $G.crowns = $cr
        $b = Get-VsatBlastRadius -Graph $G -Context $script:NoCtx -MaxPaths 2
        @($b.paths | ForEach-Object { "$($_.entry)->$($_.crown)" }) | Should -Be @('pa->c0', 'pb->cz')
        $b.bounds.pathsFound | Should -Be 6
        $b.bounds.crownsReachable | Should -Be 6
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match 'Fix plan' -and $_ -match '2 of 6' }).Count | Should -Be 1
        $fp = Get-VsatFixPlan -Paths $b.paths -Graph $G -Bounds $b.bounds
        $fp[0].note | Should -Match '2 of 6'
        # Shared crown too: pb also reaches cz, which pa wins on the tie; pb must still appear.
        [void](Add-VsatGraphEdge $G 'pa' 'h2' 'admin-of' 'observed' 1 'revoke:pa@h2' @($script:Ok))
        $b = Get-VsatBlastRadius -Graph $G -Context $script:NoCtx -MaxPaths 5
        @($b.paths | ForEach-Object { $_.entry } | Sort-Object -Unique) | Should -Be @('pa', 'pb')
        $b.bounds.pathsFound | Should -Be 7
    }
    It 'an undecidable DFW decision becomes a needsEvidence item (status unknown, missingFact dfw), never a path or fix' {
        $ev = Get-XplatEvidence
        $ev.assets = New-VsatList @($ev.assets | Where-Object { $_.type -ne 'nsx-rule' })
        $script:VsatAssetIndex = @{}; foreach ($a in $ev.assets) { $script:VsatAssetIndex[$a.id] = $a }
        $r = Invoke-VsatRules -Evidence $ev -ProfileName standard
        $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
        $b = Get-VsatBlastRadius -Graph $g -Context $r.context
        $ne = @($b.needsEvidence | Where-Object { $_.gap.kind -eq 'network-allow' })
        $ne.Count | Should -BeGreaterThan 0
        foreach ($x in $ne) { $x.gap.status | Should -Be 'unknown'; $x.gap.missingFact | Should -Be 'dfw' }
        @($g.edges.Values | Where-Object { $_.kind -eq 'network-allow' -and $_.fixId -like 'rule:*' }) | Should -BeNullOrEmpty
        @(Get-VsatFixPlan -Paths $b.paths -Graph $g | Where-Object { $_.fixId -like 'rule:*' }) | Should -BeNullOrEmpty
    }
    It 'a budget stop inside a needsEvidence suffix search is reported, not silent' {
        $G = New-EmptyGraph
        [void](Add-VsatGraphNode $G 'h' 'asset' 'host' 'h' 'vmware')
        for ($v = 0; $v -lt 3000; $v++) { [void](Add-VsatGraphNode $G "v$v" 'asset' 'vm' "v$v" 'vmware'); [void](Add-VsatGraphEdge $G 'h' "v$v" 'controls' 'observed' 1 $null @($script:Ok)) }
        [void](Add-VsatGraphNode $G 'c' 'asset' 'vcenter' 'c' 'vmware'); $G.nodes['c'].crown = $true; $G.crowns = @('c')
        Add-VsatGraphGap $G 'admin-of' 'principal:*' 'h' 'admins' 'h' 'denied' 'unknown admins'
        $b = Get-VsatBlastRadius -Graph $G -Context $script:NoCtx -MaxNodes 100
        $b.bounds.truncated | Should -BeTrue
        @($b.notes | Where-Object { $_ -match 'bounds hit' -and $_ -match 'evidence gap' }).Count | Should -Be 1
    }
}

Describe 'Blast radius: adjacency order (fix round 1)' {
    It 'breaks equal-cost ties by edge id ordinal, not insertion order' {
        $ok = @{ assetId = 'x'; fact = 'x'; status = 'ok' }
        $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @('c'); entries = @(); notes = [System.Collections.Generic.List[string]]::new(); needsEvidence = [System.Collections.Generic.List[object]]::new() }
        [void](Add-VsatGraphNode $G 'p' 'principal' 'user' 'p' 'identity')
        [void](Add-VsatGraphNode $G 'c' 'asset' 'vcenter' 'c' 'vmware'); $G.nodes['c'].crown = $true
        $kinds = @('admin-of', 'credential-exposure', 'mgmt-reach', 'network-allow')
        $ids = @($kinds | ForEach-Object { Get-VsatGraphEdgeId 'p' $_ 'c' })
        $lowest = (Get-VsatOrdinalSorted $ids)[0]
        # Insert in descending id order so insertion order disagrees with id order.
        $byId = @{}; for ($i = 0; $i -lt $kinds.Count; $i++) { $byId[$ids[$i]] = $kinds[$i] }
        $desc = Get-VsatOrdinalSorted $ids; [Array]::Reverse($desc)
        foreach ($id in $desc) { [void](Add-VsatGraphEdge $G 'p' 'c' $byId[$id] 'observed' 1 "fix:$id" @($ok)) }
        $b = Get-VsatBlastRadius -Graph $G -Context @{ evidence = @{ assets = @() }; assets = @{} }
        @($b.paths[0].edgeIds) | Should -Be @($lowest)
    }
}

Describe 'Pipeline integration' {
    BeforeAll {
        $script:PR = Get-TestResults (Get-XplatEvidence)
    }
    It 'results carry analysis.blastRadius with fixPlan; attackPaths unchanged' {
        $r = $script:PR
        $r.analysis.blastRadius.paths.Count | Should -BeGreaterThan 0
        $r.analysis.blastRadius.fixPlan.Count | Should -BeGreaterThan 0
        $r.analysis.Contains('attackPaths') | Should -BeTrue
        foreach ($k in 'privilegePaths', 'chokepoints', 'pathNotes', 'impact', 'workPackages', 'drift') { $r.analysis.Contains($k) | Should -BeTrue }
    }
    It 'rebuilds the graph after rule evaluation so fix plan findingKeys are filled (P17)' {
        @($script:PR.analysis.blastRadius.fixPlan | Where-Object { @($_.findingKeys).Count -gt 0 }).Count | Should -BeGreaterThan 0
        @($script:PR.analysis.blastRadius.edges | Where-Object { @($_.findingKeys).Count -gt 0 }).Count | Should -BeGreaterThan 0
    }
    It 'fix plan items carry the bounds note field' {
        foreach ($f in $script:PR.analysis.blastRadius.fixPlan) { $f.Contains('note') | Should -BeTrue }
    }
    It 'adds a work package catalog from the rule pack (titles for fixes with no finding)' {
        $cat = @($script:PR.analysis.workPackageCatalog)
        $cat.Count | Should -Be @((Get-VsatRulePackMeta).workPackages).Count
        $m = @($cat | Where-Object { $_.id -eq 'WP-MGMT-ISOLATION' })[0]
        $m.title | Should -Not -BeNullOrEmpty
        foreach ($f in $script:PR.analysis.blastRadius.fixPlan) { @($cat | ForEach-Object { $_.id }) | Should -Contain $f.workPackage }
    }
    It 'Set-VsatPriority treats crowns reached by a blast-radius path as path targets' {
        $crowns = @{}; foreach ($p in $script:PR.analysis.blastRadius.paths) { $crowns[$p.crown] = $true }
        $hit = @($script:PR.findings | Where-Object { $_.result -in @('FAIL', 'UNKNOWN', 'ERROR') -and $crowns.ContainsKey($_.assetId) })
        $hit.Count | Should -BeGreaterThan 0
        foreach ($f in $hit) { @($f.priority.reasons) | Should -Contain 'reachable in a modeled attack path' }
    }
    It 'serializes to JSON and back with the blast radius intact' {
        $j = ConvertTo-VsatJson $script:PR.analysis.blastRadius | ConvertFrom-Json
        @($j.paths).Count | Should -Be @($script:PR.analysis.blastRadius.paths).Count
        @($j.fixPlan).Count | Should -Be @($script:PR.analysis.blastRadius.fixPlan).Count
    }
    It 'replaying a 2.0 package still works and yields a blastRadius section' {
        $p = Read-VsatPackage -Path (Join-Path $PSScriptRoot 'fixtures/evidence-2.0.json')
        [string]$p.evidence.schemaVersion | Should -Be '2.0'
        $r = Get-TestResults (ConvertTo-VsatLiveEvidence $p.evidence)
        $r.analysis.blastRadius | Should -Not -BeNullOrEmpty
        $r.analysis.blastRadius.Contains('fixPlan') | Should -BeTrue
        @($r.findings).Count | Should -BeGreaterThan 0
    }
    It 'redaction pseudonymizes principal keys and names inside the blast radius' {
        $ev = Get-XplatEvidence
        $red = Get-VsatRedactedCopy -Evidence $ev -Results $script:PR
        $txt = ConvertTo-VsatJson $red.results.analysis.blastRadius
        foreach ($s in 'j.doe', 'vi-admins', 'vc01.example.local', 'vcsa-hv01', 'db01') { $txt | Should -Not -Match ([regex]::Escape($s)) -Because $s }
        # Consistent pseudonyms keep the graph joinable: every path edge id still resolves.
        $b = $red.results.analysis.blastRadius
        $nodes = @{}; foreach ($n in $b.nodes) { $nodes[$n.id] = $true }
        foreach ($e in $b.edges) { $nodes.ContainsKey($e.source) | Should -BeTrue; $nodes.ContainsKey($e.target) | Should -BeTrue }
        # Bare local principal names (jdoe, ops on kvm01) are pseudonymized in principal-bearing fields.
        foreach ($n in @($b.nodes | Where-Object { $_.kind -eq 'principal' })) { $n.name | Should -Not -BeIn @('jdoe', 'ops') }
        foreach ($p in $b.paths) { $p.narrative | Should -Not -Match '(^|[^A-Za-z0-9_.-])(jdoe|ops)([^A-Za-z0-9_-]|$)' }
    }
    It 'redaction never rewrites a bare principal name outside principal-bearing fields (minor 7)' {
        $blast = [ordered]@{
            nodes = @([ordered]@{ id = 'local:ep-kvm01:root'; kind = 'principal'; name = 'root' }, [ordered]@{ id = 'ep-kvm01:host'; kind = 'asset'; name = 'kvm01' })
            edges = @([ordered]@{ source = 'local:ep-kvm01:root'; explanation = 'root is in group wheel'; evidence = @(@{ fact = 'root' }) },
                [ordered]@{ source = 'ep-kvm01:host'; explanation = 'root filesystem is shared'; evidence = @(@{ fact = 'root' }) })
            paths = @([ordered]@{ narrative = 'root → admin of kvm01' }); needsEvidence = @()
            fixPlan = @([ordered]@{ fixId = 'revoke:local:ep-kvm01:root@ep-kvm01:host'; title = 'Remove root admin rights on kvm01' }, [ordered]@{ fixId = 'isolate:ep-kvm01:host'; title = 'Isolate the root network' })
        }
        Protect-VsatRedactBlastPrincipals -Blast $blast -Bare ([ordered]@{ root = 'principal-0009' })
        $blast.nodes[0].name | Should -Be 'principal-0009'
        $blast.edges[0].explanation | Should -Be 'principal-0009 is in group wheel'
        $blast.edges[1].explanation | Should -Be 'root filesystem is shared'
        $blast.edges[1].evidence[0].fact | Should -Be 'root'
        $blast.paths[0].narrative | Should -Be 'principal-0009 → admin of kvm01'
        $blast.fixPlan[0].title | Should -Be 'Remove principal-0009 admin rights on kvm01'
        $blast.fixPlan[1].title | Should -Be 'Isolate the root network'
    }
    It 'crown nodes carry criticality (minor 6)' {
        foreach ($n in @($script:PR.analysis.blastRadius.nodes | Where-Object { $_.crown })) { $n.criticality | Should -BeIn @('high', 'medium', 'low') }
    }
}

Describe 'Browser parity (blast-core.js mirrors the engine)' {
    BeforeAll {
        # Fixtures for tests/js/blast-parity.test.mjs (CI runs `node --test tests/js/` after Pester).
        # Each holds the engine result, the engine's per-entry search work (pops) and the engine's
        # result with the first fix's edges removed, so the browser recompute is checked edge for edge.
        $script:JsDir = Join-Path $PSScriptRoot 'js'
        function script:Export-ParityFixture {
            param($G, $Context, [string]$Name, [int]$MaxDepth = 8)
            $b = Get-VsatBlastRadius -Graph $G -Context $Context -MaxDepth $MaxDepth
            $b.fixPlan = @(Get-VsatFixPlan -Paths $b.paths -Graph $G -Bounds $b.bounds)
            $rank = @{}; $i = 0; foreach ($id in (Get-VsatOrdinalSorted $G.nodes.Keys)) { $rank[$id] = $i; $i++ }
            $pops = [ordered]@{}
            foreach ($en in $b.entries) {
                $st = @{ rank = $rank; adj = @{}; pops = 0; maxNodes = 250000; maxDepth = $MaxDepth; sw = [Diagnostics.Stopwatch]::StartNew(); budgetMs = 20000; stop = $null }
                [void](Invoke-VsatGraphSearch -G $G -Start $en -State $st)
                $pops[$en] = $st.pops
            }
            $json = ConvertTo-VsatJson ([ordered]@{ analysis = [ordered]@{ blastRadius = $b } })   # before the graph is cut
            $cut = $null
            if (@($b.fixPlan).Count) {
                $fid = [string]$b.fixPlan[0].fixId
                foreach ($e in @($G.edges.Values | Where-Object { $_.fixId -eq $fid })) { [void]$G.edges.Remove($e.id); [void]$G.out[$e.source].Remove($e) }
                $b2 = Get-VsatBlastRadius -Graph $G -Context $Context -MaxDepth $MaxDepth
                @($b2.edges | Where-Object { $_.fixId -eq $fid }).Count | Should -Be 0 -Because 'the cut fix must not be re-derived'
                $cut = [ordered]@{ fixId = $fid; entries = @($b2.entries); paths = @($b2.paths) }
            }
            $doc = ConvertFrom-VsatJson $json
            $doc.probe = [ordered]@{ maxDepth = $MaxDepth; pops = $pops }
            $doc.cut = $cut
            [IO.File]::WriteAllText((Join-Path $script:JsDir $Name), (ConvertTo-VsatJson $doc))
            return $b
        }
        foreach ($f in @(Get-ChildItem -Path $script:JsDir -Filter 'fixture-*.json' -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $f.FullName }
        foreach ($lab in @(@{ n = 'fixture-results.json'; ev = (Get-XplatEvidence) }, @{ n = 'fixture-demo-results.json'; ev = (Get-TestEvidence) })) {
            $r = Invoke-VsatRules -Evidence $lab.ev -ProfileName standard
            $g = New-VsatSecurityGraph -Context $r.context -Findings $r.findings
            [void](Export-ParityFixture -G $g -Context $r.context -Name $lab.n)
        }
        # Synthetic graph that pins every tie-break of the search (maxDepth 5):
        #  (a) pA -> cA over two equal-cost edges inserted in reverse id order (adjacency: edge id ordinal;
        #      strict relaxation keeps the first);
        #  (b) pB -> t over equal-cost routes with 3 and 4 hops (pop order: hops before node id);
        #  (c) pC -> w over two equal routes through c-u and c-v (pop order: node id ordinal; strict relax);
        #  (d) pD -> y: a cheap 6-hop route over maxDepth next to a costlier 3-hop one;
        #  (e) equal-weight fixes, so the fix plan's fixId tie-break decides the order.
        $ok = @(@{ assetId = 'syn'; fact = 'x'; status = 'ok' })
        $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new(); needsEvidence = [System.Collections.Generic.List[object]]::new() }
        foreach ($p in 'pA', 'pB', 'pC', 'pD', 'pE') { [void](Add-VsatGraphNode $G $p 'principal' 'user' $p 'identity') }
        foreach ($n in 'cA', 'b-s', 'b-m', 'b-a', 'b-b', 't', 'c-s', 'c-u', 'c-v', 'w', 'd0', 'd1', 'd2', 'd3', 'x', 'y', 'e1', 'e2', 'cE1', 'cE2') { [void](Add-VsatGraphNode $G $n 'asset' 'vm' $n 'vmware') }
        $crit = @{ cA = 'medium'; t = 'low'; w = 'high'; y = 'high'; cE1 = 'medium'; cE2 = 'medium' }
        $assets = @{}
        foreach ($c in $crit.Keys) { $G.nodes[$c].crown = $true; $G.nodes[$c].crownReason = 'critical asset (operator)'; $G.nodes[$c].criticality = $crit[$c]; $assets[$c] = @{ id = $c; criticality = $crit[$c] } }
        $G.crowns = Get-VsatOrdinalSorted $crit.Keys
        $E = { param($s, $t, $k, $c, $f) [void](Add-VsatGraphEdge $G $s $t $k 'observed' $c $f $ok) }
        # (a) reverse id order
        $ids = @{ 'admin-of' = (Get-VsatGraphEdgeId 'pA' 'admin-of' 'cA'); 'credential-exposure' = (Get-VsatGraphEdgeId 'pA' 'credential-exposure' 'cA') }
        foreach ($k in @($ids.Keys | Sort-Object { $ids[$_] } -Descending)) { & $E 'pA' 'cA' $k 1 "fix:a-$k" }
        # (b)
        & $E 'pB' 'b-s' 'admin-of' 1 'revoke:pB@b-s'
        & $E 'b-s' 'b-b' 'controls' 2 $null; & $E 'b-s' 'b-m' 'controls' 1 $null; & $E 'b-m' 'b-a' 'controls' 1 $null
        & $E 'b-a' 't' 'mgmt-reach' 1 'isolate:b-a'; & $E 'b-b' 't' 'mgmt-reach' 1 'isolate:b-b'
        # (c)
        & $E 'pC' 'c-s' 'admin-of' 1 'revoke:pC@c-s'
        & $E 'c-s' 'c-v' 'controls' 1 $null; & $E 'c-s' 'c-u' 'controls' 1 $null
        & $E 'c-v' 'w' 'network-allow' 1 'segment:c-v'; & $E 'c-u' 'w' 'network-allow' 1 'segment:c-u'
        # (d)
        & $E 'pD' 'd0' 'admin-of' 1 'revoke:pD@d0'
        & $E 'd0' 'd1' 'controls' 1 $null; & $E 'd1' 'd2' 'controls' 1 $null; & $E 'd2' 'd3' 'controls' 1 $null; & $E 'd3' 'x' 'controls' 1 $null
        & $E 'd0' 'x' 'credential-exposure' 10 'rotate:d0>x'; & $E 'x' 'y' 'controls' 1 $null
        # (e)
        & $E 'pE' 'e1' 'admin-of' 1 'revoke:pE@e1'; & $E 'e1' 'cE1' 'mgmt-reach' 1 'isolate:zz'; & $E 'e1' 'cE2' 'mgmt-reach' 1 'isolate:aa'
        $script:SynCtx = @{ evidence = @{ assets = @(); scope = @{} }; assets = $assets }
        $script:Syn = Export-ParityFixture -G $G -Context $script:SynCtx -Name 'fixture-synthetic-results.json' -MaxDepth 5
        $script:Node = Get-Command node -ErrorAction SilentlyContinue
    }
    It 'the synthetic engine result pins each tie-break' {
        $by = @{}; foreach ($p in $script:Syn.paths) { $by["$($p.entry)>$($p.crown)"] = $p }
        $by['pA>cA'].edgeIds | Should -Be @((Get-VsatOrdinalSorted @((Get-VsatGraphEdgeId 'pA' 'admin-of' 'cA'), (Get-VsatGraphEdgeId 'pA' 'credential-exposure' 'cA')))[0])
        $by['pB>t'].hops | Should -Be 3
        $by['pC>w'].edgeIds[-1] | Should -Be (Get-VsatGraphEdgeId 'c-u' 'network-allow' 'w')
        $by['pD>y'].hops | Should -Be 3
        $by['pD>y'].cost | Should -Be 12
    }
    It 'the embedded report script starts with blast-core.js (P60: one inline script)' {
        $core = [IO.File]::ReadAllText((Join-Path $script:RepoRoot 'assets/report/blast-core.js')).Replace("`r`n", "`n")
        (Get-VsatEmbeddedText 'assets/report/report.js').StartsWith($core) | Should -BeTrue
        (Get-VsatEmbeddedText 'assets/ui/app.js').StartsWith($core) | Should -BeTrue
    }
    It 'browser paths and fix order equal the engine output (node --test tests/js/)' {
        if (-not $script:Node) { Set-ItResult -Skipped -Because 'node is not installed'; return }
        $out = & $script:Node.Source --test $script:JsDir 2>&1
        $code = $LASTEXITCODE
        $text = $out -join "`n"
        $code | Should -Be 0 -Because $text
        $text | Should -Match '(?m)^\S+ fail 0\s*$'
        $text | Should -Match '(?m)^\S+ pass [1-9]'
    }
}
