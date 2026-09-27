#region Security graph
# Typed, evidence-backed graph across VMware, NSX, Hyper-V, KVM and identity. Every edge
# cites the facts it was derived from. A hop whose deriving fact is denied, errored,
# unsupported or missing is never an edge: it is recorded in $G.needsEvidence so the
# blast-radius search can show it as "collect this to confirm" (never ranked).
# Names and IPs are never identity: IP matches create only 'correlated' edges.

$script:VsatNonAdminRoles = @('ReadOnly', 'NoAccess', 'Anonymous', 'View')
$script:VsatKvmAdminGroups = @('libvirt', 'wheel', 'sudo', 'kvm', 'root')
$script:VsatManagementPlaneTypes = @('vcenter', 'nsx-manager', 'hyperv-cluster')
$script:VsatGraphVmTypes = @('vm', 'hyperv-vm', 'kvm-vm')
$script:VsatGraphHostTypes = @('host', 'hyperv-host', 'kvm-host')
$script:VsatGraphSkipTypes = @('nsx-rule', 'nsx-policy', 'nsx-group')
$script:VsatEvidenceGapStatuses = @('denied', 'error', 'unsupported', 'missing')
# vCenter roles that administer everything beneath a container (hosts included). Other
# non-read roles on a container reach only the VMs beneath it. A custom role counts as
# admin-equivalent when its collected privileges include Host.Config.* or Authorization.ModifyPermissions.
$script:VsatAdminEquivalentRoles = @('Admin', 'NoCryptoAdmin', 'NoTrustedAdmin')
# vCenter inventory containers: a non-propagating grant on these never reaches their children.
$script:VsatContainerTypes = @('vcenter', 'esxi-endpoint', 'datacenter', 'cluster', 'hyperv-cluster', 'folder', 'resource-pool', 'vapp')
# Finding keys attached to admin-of edges come only from identity / privilege rules.
$script:VsatIdentityRuleIds = @('VC-ADMIN-USERS', 'VC-PERMISSIONS-REVIEW', 'HV-ADMINS', 'KVM-LIBVIRT-GROUP', 'ESXI-AD-ADMINS-GROUP', 'ESXI-AD-ADMINS-AUTOADD')
# ATT&CK labeling hook for graph edges: { param($Edge, $Graph) -> @{ technique; name } | $null }.
# Null until the ATT&CK mapping is loaded; Add-VsatGraphEdge calls it for every new edge.
$script:VsatEdgeAttackHook = $null

# Crown-jewel detection: an ordered, data-driven list. The first rule that returns a reason
# wins and sets crownReason. Order: management plane > operator criticality high > (OT) >
# (AI control plane) > inferred high. Later tasks insert with Add-VsatCrownRule -Before 'inferred-high'.
$script:VsatCrownRules = [System.Collections.Generic.List[object]]::new()

function Add-VsatCrownRule {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][scriptblock]$Test, [string]$Before)
    for ($i = $script:VsatCrownRules.Count - 1; $i -ge 0; $i--) { if ($script:VsatCrownRules[$i].id -eq $Id) { $script:VsatCrownRules.RemoveAt($i) } }
    $rule = [ordered]@{ id = $Id; test = $Test }
    $at = -1
    if ($Before) { for ($i = 0; $i -lt $script:VsatCrownRules.Count; $i++) { if ($script:VsatCrownRules[$i].id -eq $Before) { $at = $i; break } } }
    if ($at -ge 0) { $script:VsatCrownRules.Insert($at, $rule) } else { $script:VsatCrownRules.Add($rule) }
}

function Get-VsatCrownReason {
    # Returns the crownReason of the first matching rule, or $null.
    param([Parameter(Mandatory)]$Asset, $Context)
    foreach ($r in $script:VsatCrownRules) {
        $reason = & $r.test $Asset $Context
        if ($reason) { return [string]$reason }
    }
    return $null
}

Add-VsatCrownRule -Id 'management-plane' -Test { param($a) if ($a.type -in $script:VsatManagementPlaneTypes) { "management plane ($($a.type))" } }
Add-VsatCrownRule -Id 'operator-high' -Test { param($a) if ($a.criticality -eq 'high' -and $a.criticalitySource -eq 'operator') { 'critical asset (operator)' } }
Add-VsatCrownRule -Id 'ot-workload' -Test { param($a) if ($a.type -in $script:VsatGraphVmTypes -and (Get-VsatOtClass $a) -eq 'ot') { "OT workload (Purdue L$($a.purdueLevel))" } }
Add-VsatCrownRule -Id 'ai-control-plane' -Test { param($a) if ($a.aiRole -in $script:VsatAiCrownRoles) { "AI control plane / data ($($a.aiRole))" } }
Add-VsatCrownRule -Id 'inferred-high' -Test { param($a) if ($a.criticality -eq 'high') { "critical asset ($(if ($a.criticalitySource) { $a.criticalitySource } else { 'inferred' }))" } }

function ConvertTo-VsatIpString {
    # Normalized IP text, or $null for non-IPs, loopback and unspecified addresses.
    param($Value)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse(([string]$Value).Trim(), [ref]$ip)) { return $null }
    if ([System.Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([System.Net.IPAddress]::Any) -or $ip.Equals([System.Net.IPAddress]::IPv6Any)) { return $null }
    return $ip.ToString()
}

function Get-VsatVmIpSources {
    # VM IPs with the fact each came from: vSphere props.ipAddresses (VMware Tools), Hyper-V
    # facts.adapters.value[].ips, KVM facts.domain.value.ips. Only ok facts contribute.
    param($Asset)
    $out = [System.Collections.Generic.List[object]]::new()
    $facts = $Asset.facts
    $hasAdapters = $facts -and $facts.Contains('adapters')
    if (-not $hasAdapters) {
        foreach ($ip in @(Get-VsatProp $Asset 'props.ipAddresses' @())) { $n = ConvertTo-VsatIpString $ip; if ($n) { $out.Add(@{ ip = $n; fact = 'props.ipAddresses' }) } }
    }
    else {
        # Hyper-V props.ipAddresses is derived from adapters; cite the fact itself.
        foreach ($ip in @(Get-VsatProp $Asset 'props.ipAddresses' @())) { $n = ConvertTo-VsatIpString $ip; if ($n -and $facts.adapters.status -ne 'ok') { $out.Add(@{ ip = $n; fact = 'props.ipAddresses' }) } }
        if ($facts.adapters.status -eq 'ok') {
            foreach ($ad in @($facts.adapters.value)) { foreach ($ip in @(Get-VsatProp $ad 'ips' @())) { $n = ConvertTo-VsatIpString $ip; if ($n) { $out.Add(@{ ip = $n; fact = 'adapters' }) } } }
        }
    }
    if ($facts -and $facts.Contains('domain') -and $facts.domain.status -eq 'ok') {
        foreach ($ip in @(Get-VsatProp $facts.domain.value 'ips' @())) { $n = ConvertTo-VsatIpString $ip; if ($n) { $out.Add(@{ ip = $n; fact = 'domain' }) } }
    }
    return , $out
}

function Get-VsatVmIps {
    param($Asset)
    $seen = [System.Collections.Generic.List[string]]::new()
    foreach ($s in (Get-VsatVmIpSources $Asset)) { if (-not $seen.Contains($s.ip)) { $seen.Add($s.ip) } }
    return [string[]]$seen.ToArray()
}

function Get-VsatVmIpGap {
    # The IP-bearing fact of a Hyper-V/KVM VM when it is not ok/absent: @{ fact; status } or $null.
    param($Asset)
    $fact = switch ($Asset.type) { 'hyperv-vm' { 'adapters' } 'kvm-vm' { 'domain' } default { $null } }
    if (-not $fact) { return $null }
    $st = if ($Asset.facts.Contains($fact)) { [string]$Asset.facts[$fact].status } else { 'missing' }
    if ($st -in $script:VsatEvidenceGapStatuses) { return @{ fact = $fact; status = $st } }
    return $null
}

function Get-VsatEndpointAddresses {
    # Management-plane asset id -> addresses recorded in evidence. Never resolves names at
    # analysis time: endpoint.resolvedAddresses is recorded at connect time (Resolve-VsatEndpointAddress),
    # ESXi host management addresses come from the vmkernel fact.
    param($Evidence)
    $map = [ordered]@{}
    $gaps = [System.Collections.Generic.List[object]]::new()
    $byEp = @{}
    foreach ($a in $Evidence.assets) {
        if ($a.type -notin @('vcenter', 'esxi-endpoint', 'host', 'nsx-manager', 'hyperv-host', 'kvm-host')) { continue }
        if (-not $byEp.ContainsKey($a.endpoint)) { $byEp[$a.endpoint] = @{} }
        if (-not $byEp[$a.endpoint].ContainsKey($a.type)) { $byEp[$a.endpoint][$a.type] = $a }
    }
    foreach ($e in @($Evidence.scope.endpoints)) {
        $types = switch ([string]$e.type) { 'vcenter' { @('vcenter') } 'esxi' { @('host', 'esxi-endpoint') } 'nsx' { @('nsx-manager') } 'hyperv' { @('hyperv-host') } 'kvm' { @('kvm-host') } default { @() } }
        $asset = $null
        foreach ($t in $types) { if ($byEp.ContainsKey($e.id) -and $byEp[$e.id].ContainsKey($t)) { $asset = $byEp[$e.id][$t]; break } }
        if (-not $asset) { continue }
        $ips = @(@(Get-VsatProp $e 'resolvedAddresses' @()) | ForEach-Object { ConvertTo-VsatIpString $_ } | Where-Object { $_ } | Select-Object -Unique)
        if ($ips.Count) { $map[$asset.id] = @{ ips = $ips; evidence = @([ordered]@{ assetId = $asset.id; fact = 'endpoint.resolvedAddresses'; status = 'ok' }) } }
        else { $gaps.Add(@{ assetId = $asset.id; fact = 'endpoint.resolvedAddresses'; status = 'missing'; note = "Endpoint $($e.id) ($($e.address)) has no recorded resolved address: VMs that may run $($asset.name) cannot be correlated" }) }
    }
    foreach ($h in @($Evidence.assets | Where-Object { $_.type -eq 'host' })) {
        if ($map.Contains($h.id)) { continue }
        $st = if ($h.facts.Contains('vmkernel')) { [string]$h.facts.vmkernel.status } else { 'missing' }
        if ($st -ne 'ok') {
            if ($st -in $script:VsatEvidenceGapStatuses) { $gaps.Add(@{ assetId = $h.id; fact = 'vmkernel'; status = $st; note = "ESXi host $($h.name) management addresses not collected ($st): VMs that may run this host cannot be correlated" }) }
            continue
        }
        $ips = @(@($h.facts.vmkernel.value) | Where-Object { @($_.services) -contains 'management' } | ForEach-Object { ConvertTo-VsatIpString $_.ip } | Where-Object { $_ } | Select-Object -Unique)
        if ($ips.Count) { $map[$h.id] = @{ ips = $ips; evidence = @([ordered]@{ assetId = $h.id; fact = 'vmkernel'; status = 'ok' }) } }
    }
    return @{ map = $map; gaps = $gaps }
}

# Keyed sorts use the non-generic Array.Sort(Array, Array, IComparer): the generic overload copies an
# object[] items array when PowerShell binds it, leaving the caller's items unsorted.
function Get-VsatOrdinalSorted {
    # Culture-independent ordinal sort of string keys (determinism across locales).
    param($Keys)
    $arr = [string[]]@($Keys | ForEach-Object { [string]$_ })
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    return , $arr
}

function Add-VsatGraphNode {
    param($G, [string]$Id, [string]$Kind, [string]$Type, [string]$Name, [string]$Platform)
    if (-not $G.nodes.ContainsKey($Id)) { $G.nodes[$Id] = [ordered]@{ id = $Id; kind = $Kind; type = $Type; name = $Name; platform = $Platform; crown = $false; crownReason = $null } }
    return $G.nodes[$Id]
}

function Get-VsatAssetPlatform {
    param([string]$Type)
    if ($Type -like 'nsx-*') { return 'nsx' }
    if ($Type -like 'hyperv-*') { return 'hyperv' }
    if ($Type -like 'kvm-*') { return 'kvm' }
    return 'vmware'
}

function Get-VsatGraphEdgeId {
    param([string]$Source, [string]$Kind, [string]$Target)
    return 'E-' + (Get-VsatCanonicalHash "$Source|$Kind|$Target").Substring(0, 16)
}

function Add-VsatGraphEdge {
    param($G, [string]$Source, [string]$Target, [string]$Kind, [string]$Confidence, [int]$Cost, [AllowNull()][string]$FixId, $Evidence, [string[]]$FindingKeys = @(), [string]$Explanation, [System.Collections.IDictionary]$Extra)
    $id = Get-VsatGraphEdgeId $Source $Kind $Target
    if ($G.edges.ContainsKey($id)) {
        # Same hop derived again: keep the first edge, merge the evidence it cites (unique by asset+fact).
        $old = $G.edges[$id]
        $have = @{}; foreach ($x in @($old.evidence)) { $have["$($x.assetId)|$($x.fact)"] = $true }
        $add = @($Evidence | Where-Object { $_ -and -not $have.ContainsKey("$($_.assetId)|$($_.fact)") })
        if ($add.Count) { $old.evidence = @(@($old.evidence) + $add) }
        $fks = @(@($old.findingKeys) + @($FindingKeys | Where-Object { $_ }) | Select-Object -Unique)
        $old.findingKeys = $fks
        # mgmt-reach derived again through another network: union the listening ports it cites and
        # relabel, since the ATT&CK technique can depend on them (port 22 -> SSH).
        if ($Extra -and $Extra.Contains('ports') -and $old.Contains('ports')) {
            $pu = @(@($old.ports) + @($Extra.ports) | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ } | Sort-Object -Unique)
            if ($pu.Count -ne @($old.ports).Count) { $old.ports = [int[]]$pu; if ($script:VsatEdgeAttackHook) { $old.attack = & $script:VsatEdgeAttackHook $old $G } }
        }
        return $old
    }
    $e = [ordered]@{ id = $id; source = $Source; target = $Target; kind = $Kind; confidence = $Confidence; cost = $Cost; fixId = $(if ($FixId) { $FixId } else { $null }); evidence = @(); findingKeys = @($FindingKeys | Where-Object { $_ }); explanation = $Explanation; attack = $null }
    $seenEv = @{}; $evList = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($Evidence | Where-Object { $_ })) { $k = "$($x.assetId)|$($x.fact)"; if (-not $seenEv.ContainsKey($k)) { $seenEv[$k] = $true; $evList.Add($x) } }
    $e.evidence = $evList.ToArray()
    if ($Extra) { foreach ($k in $Extra.Keys) { $e[$k] = $Extra[$k] } }
    # ATT&CK label is set here so lazily added edges (network-allow, mgmt-reach) get it too.
    if ($script:VsatEdgeAttackHook) { $e.attack = & $script:VsatEdgeAttackHook $e $G }
    $G.edges[$id] = $e
    if (-not $G.out.ContainsKey($Source)) { $G.out[$Source] = [System.Collections.Generic.List[object]]::new() }
    $G.out[$Source].Add($e)
    return $e
}

function Add-VsatGraphGap {
    # A candidate hop VSAT could not verify. Never an edge; Task 4 routes paths through these
    # into blastRadius.needsEvidence. Source/target may be a placeholder ('principal:*', 'vm:*').
    param($G, [string]$Kind, [string]$Source, [string]$Target, [string]$MissingFact, [string]$AssetId, [string]$Status, [string]$Explanation)
    $k = "$Kind|$Source|$Target|$MissingFact|$AssetId"
    if (-not $G.Contains('gapIndex')) { $G.gapIndex = @{}; foreach ($x in $G.needsEvidence) { $G.gapIndex["$($x.kind)|$($x.source)|$($x.target)|$($x.missingFact)|$($x.assetId)"] = $x } }
    if ($G.gapIndex.ContainsKey($k)) { return }
    $gap = [ordered]@{ kind = $Kind; source = $Source; target = $Target; missingFact = $MissingFact; assetId = $AssetId; status = $Status; explanation = $Explanation }
    $G.gapIndex[$k] = $gap
    $G.needsEvidence.Add($gap)
}

function Get-VsatFactGapStatus {
    # 'ok' | 'absent' | 'denied' | 'error' | 'unsupported' | 'missing'
    param($Asset, [string]$Fact)
    if (-not $Asset.facts -or -not $Asset.facts.Contains($Fact)) { return 'missing' }
    $st = [string]$Asset.facts[$Fact].status
    if (-not $st) { return 'missing' }
    return $st
}

function Get-VsatVmsBeneath {
    # VMs under an inventory container: follow 'contains' down to hosts, then the VMs that run on them.
    param($Context, [string]$Id)
    $seen = @{ $Id = $true }; $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($Id)
    $vms = [System.Collections.Generic.List[string]]::new()
    while ($q.Count) {
        $u = $q.Dequeue()
        $a = $Context.assets[$u]
        if ($a -and $a.type -in $script:VsatGraphHostTypes) {
            foreach ($r in @($Context.in[$u] | Where-Object { $_ -and $_.type -eq 'runs-on' })) { if (-not $vms.Contains($r.source)) { $vms.Add($r.source) } }
            continue
        }
        foreach ($r in @($Context.out[$u] | Where-Object { $_ -and $_.type -eq 'contains' })) {
            $t = $Context.assets[$r.target]
            if (-not $t -or $seen.ContainsKey($t.id)) { continue }
            if ($t.type -in $script:VsatGraphVmTypes) { if (-not $vms.Contains($t.id)) { $vms.Add($t.id) }; continue }
            if ($t.type -in $script:VsatContainerTypes -or $t.type -in $script:VsatGraphHostTypes) { $seen[$t.id] = $true; $q.Enqueue($t.id) }
        }
    }
    return (Get-VsatOrdinalSorted $vms)
}

function New-VsatSecurityGraph {
    param([Parameter(Mandatory)]$Context, $Findings = @())
    $ev = $Context.evidence
    $G = [ordered]@{ nodes = @{}; out = @{}; edges = @{}; crowns = @(); entries = @(); notes = [System.Collections.Generic.List[string]]::new(); needsEvidence = [System.Collections.Generic.List[object]]::new(); gapIndex = @{} }
    $failByAsset = @{}; $idFailByAsset = @{}
    foreach ($f in @($Findings | Where-Object { $_ -and $_.result -eq 'FAIL' })) {
        if (-not $failByAsset.ContainsKey($f.assetId)) { $failByAsset[$f.assetId] = [System.Collections.Generic.List[string]]::new() }
        $failByAsset[$f.assetId].Add([string]$f.key)
        if ([string]$f.ruleId -in $script:VsatIdentityRuleIds) {
            if (-not $idFailByAsset.ContainsKey($f.assetId)) { $idFailByAsset[$f.assetId] = [System.Collections.Generic.List[string]]::new() }
            $idFailByAsset[$f.assetId].Add([string]$f.key)
        }
    }
    $fk = { param($id) if ($failByAsset.ContainsKey($id)) { , [string[]]$failByAsset[$id].ToArray() } else { , [string[]]@() } }
    $idfk = { param($id) if ($idFailByAsset.ContainsKey($id)) { , [string[]]$idFailByAsset[$id].ToArray() } else { , [string[]]@() } }
    $byType = @{}
    foreach ($a in $ev.assets) {
        if (-not $byType.ContainsKey($a.type)) { $byType[$a.type] = [System.Collections.Generic.List[object]]::new() }
        $byType[$a.type].Add($a)
        if ($a.type -notin $script:VsatGraphSkipTypes) { [void](Add-VsatGraphNode $G $a.id 'asset' $a.type $a.name (Get-VsatAssetPlatform $a.type)) }
    }
    $ofType = { param([string[]]$t) foreach ($x in $t) { if ($byType.ContainsKey($x)) { $byType[$x] } } }
    $ref = { param($asset, [string]$fact) [ordered]@{ assetId = $asset.id; fact = $fact; status = $(if ($fact -eq 'relationships' -or $fact -like 'props.*') { 'ok' } else { [string]$asset.facts[$fact].status }) } }

    # 1. controls: management hierarchy and hypervisor -> guest (observed relationships).
    $ctlSources = @('vcenter', 'esxi-endpoint', 'datacenter', 'cluster', 'hyperv-cluster')
    $ctlTargets = @('datacenter', 'cluster', 'host', 'hyperv-host')
    foreach ($r in $ev.relationships) {
        if (-not ($G.nodes.ContainsKey($r.source) -and $G.nodes.ContainsKey($r.target))) { continue }
        $s = $Context.assets[$r.source]; $t = $Context.assets[$r.target]
        if ($r.type -eq 'contains' -and $s.type -in $ctlSources -and $t.type -in $ctlTargets) {
            [void](Add-VsatGraphEdge $G $s.id $t.id 'controls' 'observed' 1 $null @(& $ref $s 'relationships') -Explanation "$($s.name) manages $($t.name)")
        }
        elseif ($r.type -eq 'runs-on' -and $s.type -in $script:VsatGraphVmTypes -and $t.type -in $script:VsatGraphHostTypes) {
            [void](Add-VsatGraphEdge $G $t.id $s.id 'controls' 'observed' 1 $null @(& $ref $s 'relationships') -Explanation "Administrator of $($t.name) controls guest $($s.name) (console, disks, memory)")
        }
    }
    # NSX manager defines the distributed firewall policy of every VM attached to its segments.
    $mgrByEp = @{}; foreach ($m in @(& $ofType 'nsx-manager')) { if (-not $mgrByEp.ContainsKey($m.endpoint)) { $mgrByEp[$m.endpoint] = $m } }
    if ($mgrByEp.Count) {
        $vmSeg = Get-VsatVmSegments $Context
        foreach ($vmId in (Get-VsatOrdinalSorted $vmSeg.Keys)) {
            foreach ($seg in @($vmSeg[$vmId])) {
                $mgr = $mgrByEp[($seg -split ':')[0]]
                if ($mgr -and $G.nodes.ContainsKey($vmId)) { [void](Add-VsatGraphEdge $G $mgr.id $vmId 'controls' 'observed' 1 $null @(& $ref $Context.assets[$vmId] 'relationships') -Explanation "$($mgr.name) defines the distributed firewall policy for $($Context.assets[$vmId].name)") }
            }
        }
    }

    # 2. admin-of from each platform's privilege facts.
    foreach ($vc in @(& $ofType 'vcenter')) {
        $st = Get-VsatFactGapStatus $vc 'permissions'
        if ($st -ne 'ok') {
            if ($st -in $script:VsatEvidenceGapStatuses) {
                $G.notes.Add("vCenter permissions not collected on $($vc.endpoint) ($st): identity paths into vCenter are unknown")
                Add-VsatGraphGap $G 'admin-of' 'principal:*' $vc.id 'permissions' $vc.id $st "Principals holding vCenter roles on $($vc.name) are unknown (permissions $st)"
            }
            continue
        }
        $root = [string](Get-VsatProp $vc 'props.rootFolder' '')
        if (-not $root) { $root = 'group-d1' }   # the vCenter root folder moref is fixed by the vSphere API
        $adminRoles = [System.Collections.Generic.List[string]]::new(); foreach ($r in $script:VsatAdminEquivalentRoles) { $adminRoles.Add($r) }
        # Roles known to hold Authorization.ModifyPermissions: the admin built-ins, plus custom roles whose collected privileges include it.
        $modPermRoles = [System.Collections.Generic.List[string]]::new(); foreach ($r in $script:VsatAdminEquivalentRoles) { $modPermRoles.Add($r) }
        # Custom roles whose privileges were collected (a row with an adminPrivileges field).
        # Any other non-built-in role has unknown privileges: never assumed admin or non-admin.
        $rolesStatus = Get-VsatFactGapStatus $vc 'roles'
        $knownRoles = @{}
        if ($rolesStatus -eq 'ok') {
            foreach ($r in @($vc.facts.roles.value | Where-Object { $_ })) {
                $hasPriv = if ($r -is [System.Collections.IDictionary]) { $r.Contains('adminPrivileges') } else { $null -ne $r.PSObject.Properties['adminPrivileges'] }
                if ($hasPriv) { $knownRoles[[string]$r.name] = $true }
                $privs = @(Get-VsatProp $r 'adminPrivileges' @())
                if (@($privs | Where-Object { $_ -like 'Host.Config.*' -or $_ -eq 'Authorization.ModifyPermissions' }).Count) { $adminRoles.Add([string]$r.name) }
                if ($privs -contains 'Authorization.ModifyPermissions') { $modPermRoles.Add([string]$r.name) }
            }
        }
        $rolesRef = if ((Get-VsatFactGapStatus $vc 'roles') -eq 'ok') { @(& $ref $vc 'roles') } else { @() }
        foreach ($p in @($vc.facts.permissions.value | Where-Object { $_ })) {
            if ([string]$p.role -in $script:VsatNonAdminRoles -or -not $p.principal) { continue }
            $pk = ConvertTo-VsatPrincipalKey -Name ([string]$p.principal) -Endpoint $vc.endpoint -Scope $ev.scope
            $mo = ([string]$p.entityId -replace '^[A-Za-z]+-', '')
            $obj = "$($vc.endpoint):$mo"
            if ($mo -eq $root) { $obj = $vc.id }
            elseif (-not $G.nodes.ContainsKey($obj)) {
                # Never widen an unknown object (VM folder, resource pool...) to the vCenter root.
                [void](Add-VsatGraphNode $G $pk.key 'principal' $(if ($p.isGroup) { 'group' } else { 'user' }) $pk.display 'identity')
                Add-VsatGraphGap $G 'admin-of' $pk.key $obj "inventory:$mo" $vc.id 'missing' "$($p.principal) holds $($p.role) on $($p.entity) ($($p.entityId)), which is not in the collected inventory: what it grants is unknown"
                continue
            }
            [void](Add-VsatGraphNode $G $pk.key 'principal' $(if ($p.isGroup) { 'group' } else { 'user' }) $pk.display 'identity')
            $tn = $G.nodes[$obj]
            $role = [string]$p.role
            $isContainer = $tn.type -in $script:VsatContainerTypes
            $isHost = $tn.type -in $script:VsatGraphHostTypes
            $propagate = [bool]$p.propagate
            $builtin = $role -in $script:VsatAdminEquivalentRoles
            $privKnown = $builtin -or $knownRoles.ContainsKey($role)
            $gapStatus = if ($rolesStatus -ne 'ok') { $rolesStatus } else { 'missing' }
            $isAdmin = $privKnown -and $role -in $adminRoles
            $canGrant = $privKnown -and $role -in $modPermRoles
            $fix = "revoke:$($pk.key)@$obj"
            # Cite the roles fact whenever the admin decision came from a collected role row.
            $evid = @(@(& $ref $vc 'permissions') + $(if (-not $builtin -and $privKnown) { $rolesRef } else { @() }))
            $extra = [ordered]@{ propagate = $propagate; role = $role }
            $roleGap = {
                param([string]$what)
                Add-VsatGraphGap $G 'admin-of' $pk.key $obj 'roles' $vc.id $gapStatus "Privileges of role '$role' held by $($p.principal) on $($p.entity) are unknown (roles $gapStatus): $what"
            }
            if ($isContainer -and -not $propagate) {
                # Object-only grant on a container: a scope node, never a crown. Observed edges stop here.
                if ($canGrant) {
                    # Authorization.ModifyPermissions lets the holder grant itself a propagating permission
                    # on this container. The sink is per principal so the inferred self-grant hop (and its
                    # fixId) belongs to this principal only.
                    $sink = "$obj#object-only@$($pk.key)"
                    if (-not $G.nodes.ContainsKey($sink)) { [void](Add-VsatGraphNode $G $sink 'scope' 'object-only' "$($tn.name) (object only, $($pk.display))" $tn.platform) }
                    [void](Add-VsatGraphEdge $G $pk.key $sink 'admin-of' 'observed' 1 $fix @($evid + $rolesRef) (& $idfk $vc.id) "$($p.principal) holds $role on $($p.entity) only (not propagating): it does not directly reach the objects beneath" -Extra $extra)
                    [void](Add-VsatGraphEdge $G $sink $obj 'admin-of' 'configuration-inferred' 2 $fix @($evid + $rolesRef) (& $idfk $vc.id) "$($p.principal) holds Authorization.ModifyPermissions here, so it can grant itself a propagating permission on $($p.entity)" -Extra ([ordered]@{ propagate = $true; role = $role }))
                }
                else {
                    $sink = "$obj#object-only"
                    if (-not $G.nodes.ContainsKey($sink)) { [void](Add-VsatGraphNode $G $sink 'scope' 'object-only' "$($tn.name) (object only)" $tn.platform) }
                    [void](Add-VsatGraphEdge $G $pk.key $sink 'admin-of' 'observed' 1 $fix $evid (& $idfk $vc.id) "$($p.principal) holds $role on $($p.entity) only (not propagating): it does not reach the objects beneath" -Extra $extra)
                    if (-not $privKnown) { & $roleGap 'whether it can grant itself a propagating permission (Authorization.ModifyPermissions) is unknown' }
                }
            }
            elseif (($isContainer -or $isHost) -and -not $isAdmin) {
                # Non-admin (or unknown-privilege) role on a container or host: only the VMs beneath it, never the hosts.
                if ($propagate) {
                    foreach ($vmId in (Get-VsatVmsBeneath -Context $Context -Id $obj)) {
                        if (-not $G.nodes.ContainsKey($vmId)) { continue }
                        [void](Add-VsatGraphEdge $G $pk.key $vmId 'admin-of' 'observed' 1 $fix @($evid + @(& $ref $Context.assets[$vmId] 'relationships')) (& $idfk $vc.id) "$($p.principal) holds $role (propagating) on $($p.entity), which contains VM $($G.nodes[$vmId].name)" -Extra $extra)
                    }
                }
                else {
                    # Host, object only: the host object itself, which controls nothing beneath.
                    $sink = "$obj#object-only"
                    if (-not $G.nodes.ContainsKey($sink)) { [void](Add-VsatGraphNode $G $sink 'scope' 'object-only' "$($tn.name) (object only)" $tn.platform) }
                    [void](Add-VsatGraphEdge $G $pk.key $sink 'admin-of' 'observed' 1 $fix $evid (& $idfk $vc.id) "$($p.principal) holds $role on $($p.entity) only (not propagating)" -Extra $extra)
                }
                if (-not $privKnown) { & $roleGap "whether it administers $($p.entity) itself (hosts included) is unknown" }
            }
            else {
                $prop = if ($propagate) { ' (propagating)' } else { ' (this object only, not propagating)' }
                [void](Add-VsatGraphEdge $G $pk.key $obj 'admin-of' 'observed' 1 $fix $evid (& $idfk $vc.id) "$($p.principal) holds $role$prop on $($p.entity)" -Extra $extra)
            }
        }
    }
    foreach ($h in @(& $ofType 'hyperv-host')) {
        foreach ($fact in 'admins', 'hvAdmins') {
            $grp = if ($fact -eq 'admins') { 'Administrators' } else { 'Hyper-V Administrators' }
            $st = Get-VsatFactGapStatus $h $fact
            if ($st -ne 'ok') {
                if ($st -in $script:VsatEvidenceGapStatuses) {
                    $G.notes.Add("Hyper-V $fact not collected on $($h.name) ($st): identity paths into this host are unknown")
                    Add-VsatGraphGap $G 'admin-of' 'principal:*' $h.id $fact $h.id $st "Members of $grp on $($h.name) are unknown ($fact $st)"
                }
                continue
            }
            foreach ($m in @($h.facts[$fact].value | Where-Object { $_ -and $_.name })) {
                $pk = ConvertTo-VsatPrincipalKey -Name ([string]$m.name) -Endpoint $h.endpoint -Scope $ev.scope -HostName $h.name
                [void](Add-VsatGraphNode $G $pk.key 'principal' $(if ($m.class -eq 'Group') { 'group' } else { 'user' }) $pk.display 'identity')
                [void](Add-VsatGraphEdge $G $pk.key $h.id 'admin-of' 'observed' 1 "revoke:$($pk.key)@$($h.id)" @(& $ref $h $fact) (& $idfk $h.id) "$($m.name) is a member of $grp on $($h.name)" -Extra ([ordered]@{ propagate = $true; role = $grp }))
            }
        }
    }
    foreach ($h in @(& $ofType 'kvm-host')) {
        $st = Get-VsatFactGapStatus $h 'groups'
        if ($st -ne 'ok') {
            if ($st -in $script:VsatEvidenceGapStatuses) {
                $G.notes.Add("KVM groups not collected on $($h.name) ($st): identity paths into this host are unknown")
                Add-VsatGraphGap $G 'admin-of' 'principal:*' $h.id 'groups' $h.id $st "Members of libvirt/wheel/sudo/kvm on $($h.name) are unknown (groups $st)"
            }
            continue
        }
        foreach ($kg in @($h.facts.groups.value | Where-Object { $_ -and [string]$_.group -in $script:VsatKvmAdminGroups })) {
            foreach ($m in @($kg.members | Where-Object { $_ })) {
                $pk = ConvertTo-VsatPrincipalKey -Name ([string]$m) -Endpoint $h.endpoint -Scope $ev.scope -HostName $h.name
                [void](Add-VsatGraphNode $G $pk.key 'principal' 'user' $pk.display 'identity')
                [void](Add-VsatGraphEdge $G $pk.key $h.id 'admin-of' 'observed' 1 "revoke:$($pk.key)@$($h.id)" @(& $ref $h 'groups') (& $idfk $h.id) "$m is in group '$($kg.group)' on $($h.name)" -Extra ([ordered]@{ propagate = $true; role = [string]$kg.group }))
            }
        }
    }

    # 3. embodies: a VM whose recorded IP equals a management endpoint's recorded address IS
    # that endpoint (correlated, never observed). Indexed by IP, so this is linear in VMs.
    $addr = Get-VsatEndpointAddresses $ev
    foreach ($gap in $addr.gaps) {
        $G.notes.Add($gap.note)
        Add-VsatGraphGap $G 'embodies' 'vm:*' $gap.assetId $gap.fact $gap.assetId $gap.status $gap.note
    }
    $byIp = @{}
    foreach ($mid in $addr.map.Keys) { foreach ($ip in $addr.map[$mid].ips) { if (-not $byIp.ContainsKey($ip)) { $byIp[$ip] = [System.Collections.Generic.List[string]]::new() }; if (-not $byIp[$ip].Contains($mid)) { $byIp[$ip].Add($mid) } } }
    $mgmtIds = Get-VsatOrdinalSorted $addr.map.Keys
    $noIpVms = 0
    foreach ($vm in @(& $ofType $script:VsatGraphVmTypes)) {
        $gap = Get-VsatVmIpGap $vm
        if ($gap -and $mgmtIds.Count) {
            Add-VsatGraphGap $G 'embodies' $vm.id 'mgmt:*' $gap.fact $vm.id $gap.status "IP addresses of VM $($vm.name) not collected ($($gap.fact) $($gap.status)): it may be a management endpoint"
        }
        $src = Get-VsatVmIpSources $vm
        if (-not $src.Count) { if ($vm.type -eq 'vm' -and -not (Get-VsatProp $vm 'props.template' $false)) { $noIpVms++ }; continue }
        $hits = [ordered]@{}
        foreach ($s in $src) {
            if (-not $byIp.ContainsKey($s.ip)) { continue }
            foreach ($mid in $byIp[$s.ip]) {
                if ($mid -eq $vm.id) { continue }
                if (-not $hits.Contains($mid)) { $hits[$mid] = @{ ip = $s.ip; facts = [System.Collections.Generic.List[string]]::new() } }
                if (-not $hits[$mid].facts.Contains($s.fact)) { $hits[$mid].facts.Add($s.fact) }
            }
        }
        foreach ($mid in (Get-VsatOrdinalSorted $hits.Keys)) {
            $m = $Context.assets[$mid]
            $evid = @(@($hits[$mid].facts | ForEach-Object { & $ref $vm $_ }) + @($addr.map[$mid].evidence))
            [void](Add-VsatGraphEdge $G $vm.id $mid 'embodies' 'correlated' 0 "relocate:$($vm.id)" $evid (& $fk $vm.id) "VM $($vm.name) ($(Get-VsatAssetPlatform $vm.type)) reports IP $($hits[$mid].ip), the recorded address of $($m.type) $($m.name) (correlated, not observed): controlling the VM controls $($m.name)")
        }
    }

    if ($noIpVms) { $G.notes.Add("$noIpVms vSphere VMs report no IP (VMware Tools); embodies correlation unknown for them") }

    # 4. credential-exposure: NSX compute-manager registrations hold vCenter credentials. The
    # vCenter is the target of the correlated 'manages' relationship (Invoke-VsatCorrelation
    # resolves the registration's server against in-scope vCenter endpoints), never a name match.
    $vcs = @(foreach ($id in (Get-VsatOrdinalSorted @(& $ofType 'vcenter' | ForEach-Object { $_.id }))) { $Context.assets[$id] })
    foreach ($mgr in @(& $ofType 'nsx-manager')) {
        $st = Get-VsatFactGapStatus $mgr 'computeManagers'
        if ($st -ne 'ok') {
            if ($st -in $script:VsatEvidenceGapStatuses) {
                $G.notes.Add("NSX compute managers not collected on $($mgr.name) ($st): credential exposure to vCenter is unknown")
                foreach ($vc in $vcs) { Add-VsatGraphGap $G 'credential-exposure' $mgr.id $vc.id 'computeManagers' $mgr.id $st "Whether $($mgr.name) holds credentials for $($vc.name) is unknown (computeManagers $st)" }
            }
            continue
        }
        $cms = @($mgr.facts.computeManagers.value | Where-Object { $_ })
        foreach ($r in @($Context.out[$mgr.id] | Where-Object { $_ -and $_.type -eq 'manages' })) {
            $vc = $Context.assets[$r.target]
            if (-not $vc -or $vc.type -ne 'vcenter') { continue }
            $server = [string](Get-VsatProp $r 'props.server' '')
            $user = @($cms | Where-Object { $server -and [string]$_.server -eq $server } | ForEach-Object { [string](Get-VsatProp $_ 'username' '') } | Where-Object { $_ })[0]
            [void](Add-VsatGraphEdge $G $mgr.id $vc.id 'credential-exposure' 'observed' 1 "scope-svc:$($mgr.id)>$($vc.id)" @((& $ref $mgr 'computeManagers'), (& $ref $mgr 'relationships')) (& $fk $vc.id) "$($mgr.name) is registered with compute manager $($vc.name) and stores its service credentials$(if ($user) { " (user $user)" })")
        }
    }
    foreach ($cm in @(Get-VsatProp $ev.nsx 'unmatchedComputeManagers' @())) { $G.notes.Add("NSX compute manager $cm is outside the vCenter scope: its credential exposure is not modeled") }
    foreach ($cs in @(Get-VsatProp $ev.scope 'credentialStores' @())) {
        $mt = [string](Get-VsatProp $cs 'match' ''); $gt = [string](Get-VsatProp $cs 'grants' '')
        if (-not $mt -or -not $gt) { continue }
        $note = [string](Get-VsatProp $cs 'note' '')
        foreach ($s in @($ev.assets | Where-Object { $G.nodes.ContainsKey($_.id) -and (Test-VsatAssetMatch $_ $mt) })) {
            foreach ($t in @($ev.assets | Where-Object { $G.nodes.ContainsKey($_.id) -and $_.id -ne $s.id -and (Test-VsatAssetMatch $_ $gt) })) {
                [void](Add-VsatGraphEdge $G $s.id $t.id 'credential-exposure' 'operator-declared' 1 "rotate:$($s.id)>$($t.id)" @([ordered]@{ assetId = 'scope'; fact = 'credentialStores'; status = 'ok' }) -Explanation "Operator declared: $($s.name) holds credentials for $($t.name)$(if ($note) { " ($note)" })")
            }
        }
    }
    $igs = @(Get-VsatProp $ev.scope 'identityGroups' @())
    foreach ($ig in $igs) {
        $gn = [string](Get-VsatProp $ig 'group' '')
        if (-not $gn) { continue }
        $grp = ConvertTo-VsatPrincipalKey -Name $gn -Endpoint 'scope' -Scope $ev.scope
        [void](Add-VsatGraphNode $G $grp.key 'principal' 'group' $grp.display 'identity')
        foreach ($m in @(Get-VsatProp $ig 'members' @() | Where-Object { $_ })) {
            $mk = ConvertTo-VsatPrincipalKey -Name ([string]$m) -Endpoint 'scope' -Scope $ev.scope
            [void](Add-VsatGraphNode $G $mk.key 'principal' 'user' $mk.display 'identity')
            [void](Add-VsatGraphEdge $G $mk.key $grp.key 'member-of' 'operator-declared' 0 "revoke-member:$($mk.key)@$($grp.key)" @([ordered]@{ assetId = 'scope'; fact = 'identityGroups'; status = 'ok' }) -Explanation "Operator declared: $m is a member of $gn")
        }
    }
    if (-not $igs.Count) { $G.notes.Add('AD group nesting not collected; principals are joined by exact normalized name only (declare identityGroups in the scope file)') }

    # 5. crown jewels (ordered rule list, first match wins).
    $crowns = [System.Collections.Generic.List[string]]::new()
    foreach ($id in (Get-VsatOrdinalSorted $G.nodes.Keys)) {
        $n = $G.nodes[$id]
        if ($n.kind -ne 'asset') { continue }
        $a = $Context.assets[$id]
        if (-not $a) { continue }
        $reason = Get-VsatCrownReason -Asset $a -Context $Context
        if ($reason) {
            $n.crown = $true; $n.crownReason = $reason; $crowns.Add($id)
            # Fix-plan weight of this crown (same value Get-VsatBlastRadius puts on its paths).
            $cv = [string]$a.criticality; $n.criticality = $(if ($cv -in @('high', 'medium', 'low')) { $cv } else { 'high' })
        }
    }
    $G.crowns = [string[]]$crowns.ToArray()
    # Deterministic order (ordinal, culture-independent); stays a list so later stages can append.
    $sortedGaps = [System.Collections.Generic.List[object]]::new()
    foreach ($k in (Get-VsatOrdinalSorted $G.gapIndex.Keys)) { $sortedGaps.Add($G.gapIndex[$k]) }
    $G.needsEvidence = $sortedGaps
    $G.Remove('gapIndex')
    return $G
}
#endregion Security graph

#region Blast radius
# Deterministic, bounded search from entry points to crown jewels over the security graph,
# plus a greedy fix ranking. Paths use only present (evidence-backed) edges. A route that
# needs a hop VSAT could not verify goes to needsEvidence ("collect this to confirm"),
# never to paths, and is never ranked.

# Weakest-link order used to label a path's confidence (the minimum across its edges).
$script:VsatConfidenceRank = @{ 'observed' = 4; 'operator-declared' = 3; 'configuration-inferred' = 2; 'correlated' = 1 }
$script:VsatBlastVerbs = @{ 'admin-of' = 'admin of'; 'controls' = 'controls'; 'embodies' = 'is (matched by IP)'; 'network-allow' = 'can reach (network)'; 'mgmt-reach' = 'reaches management of'; 'credential-exposure' = 'holds credentials for'; 'member-of' = 'member of' }
$script:VsatMgmtListenPorts = @(22, 16509, 16514)

function Test-VsatLoopbackAddress {
    param([string]$Address)
    $a = $Address.Trim().Trim('[', ']')
    if ($a -eq 'localhost' -or $a -eq '::1' -or $a -like '127.*') { return $true }
    return $false
}

function Get-VsatMgmtIndex {
    # ESXi management vmknics, indexed once per search: standard portgroups per host, dvPortgroups -> hosts.
    param($Context)
    $idx = @{ std = @{}; dv = @{}; gap = @{} }
    foreach ($h in @($Context.evidence.assets | Where-Object { $_ -and $_.type -eq 'host' })) {
        $st = Get-VsatFactGapStatus $h 'vmkernel'
        if ($st -ne 'ok') { if ($st -in $script:VsatEvidenceGapStatuses) { $idx.gap[$h.id] = $st }; continue }
        foreach ($k in @($h.facts.vmkernel.value | Where-Object { $_ -and @($_.services) -contains 'management' })) {
            $pg = [string](Get-VsatProp $k 'portgroup' '')
            $dv = [string](Get-VsatProp $k 'dvPortgroup' '')
            if ($pg) {
                if (-not $idx.std.ContainsKey($h.id)) { $idx.std[$h.id] = [System.Collections.Generic.List[object]]::new() }
                $idx.std[$h.id].Add(@{ pgId = "$($h.id)/pg/$pg"; portgroup = $pg; device = [string]$k.device })
            }
            if ($dv) {
                $dvId = "$($h.endpoint):$dv"
                if (-not $idx.dv.ContainsKey($dvId)) { $idx.dv[$dvId] = [System.Collections.Generic.List[object]]::new() }
                $idx.dv[$dvId].Add(@{ hostId = $h.id; device = [string]$k.device })
            }
        }
    }
    return $idx
}

function Get-VsatMgmtReach {
    # A VM that shares L2 with a hypervisor management interface. Returns
    # @{ reach = [@{ hostId; ports?; evidence; explanation }]; gaps = [@{ hostId; fact; assetId; status; explanation }] }.
    param($Context, $Vm, $MgmtIndex)
    $reach = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    if (-not $Context.out) { return @{ reach = $reach; gaps = $gaps } }
    $rels = @($Context.out[$Vm.id] | Where-Object { $_ })
    $vmRef = [ordered]@{ assetId = $Vm.id; fact = 'relationships'; status = 'ok' }
    $host_ = @($rels | Where-Object type -eq 'runs-on' | ForEach-Object { $Context.assets[$_.target] } | Where-Object { $_ })[0]
    foreach ($c in @($rels | Where-Object type -eq 'connects')) {
        $net = $Context.assets[$c.target]
        if (-not $net) { continue }
        switch ($net.type) {
            'hyperv-vswitch' {
                $owner = @($Context.in[$net.id] | Where-Object { $_ -and $_.type -eq 'contains' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ -and $_.type -eq 'hyperv-host' })[0]
                if (-not $owner) { $owner = $host_ }
                if (-not $owner) { continue }
                $props = $net.props
                $has = if ($props -is [System.Collections.IDictionary]) { $props.Contains('allowManagementOS') } else { $null -ne $props.PSObject.Properties['allowManagementOS'] }
                if (-not $has) { $gaps.Add(@{ hostId = $owner.id; fact = 'props.allowManagementOS'; assetId = $net.id; status = 'missing'; explanation = "Whether switch $($net.name) is shared with the management OS of $($owner.name) was not collected" }); continue }
                if ([bool](Get-VsatProp $net 'props.allowManagementOS' $false)) {
                    $reach.Add(@{ hostId = $owner.id; evidence = @($vmRef, [ordered]@{ assetId = $net.id; fact = 'props.allowManagementOS'; status = 'ok' }); explanation = "Switch $($net.name) is shared with the management OS of $($owner.name) (AllowManagementOS): guests share L2 with the host management interface" })
                }
            }
            'kvm-network' {
                $owner = if ($host_ -and $host_.type -eq 'kvm-host') { $host_ } else { @($Context.in[$net.id] | Where-Object { $_ -and $_.type -eq 'contains' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ -and $_.type -eq 'kvm-host' })[0] }
                if (-not $owner) { continue }
                $props = $net.props
                $has = if ($props -is [System.Collections.IDictionary]) { $props.Contains('forwardMode') } else { $null -ne $props.PSObject.Properties['forwardMode'] }
                if (-not $has) { $gaps.Add(@{ hostId = $owner.id; fact = 'props.forwardMode'; assetId = $net.id; status = 'missing'; explanation = "Forward mode of libvirt network $($net.name) was not collected" }); continue }
                $fm = ([string](Get-VsatProp $net 'props.forwardMode' '')).ToLowerInvariant()
                if ($fm -eq 'bridge') {
                    $gaps.Add(@{ hostId = $owner.id; fact = 'hostBridgeAddress'; assetId = $owner.id; status = 'missing'; explanation = "Libvirt network $($net.name) bridges guests onto host bridge $(Get-VsatProp $net 'props.bridge' '?'); whether $($owner.name) has its management address on that bridge was not collected" })
                    continue
                }
                if ($fm -notin @('nat', 'route', 'open')) { continue }   # isolated (no forward mode): no host routing
                $lst = Get-VsatFactGapStatus $owner 'listening'
                if ($lst -ne 'ok') {
                    if ($lst -in $script:VsatEvidenceGapStatuses) { $gaps.Add(@{ hostId = $owner.id; fact = 'listening'; assetId = $owner.id; status = $lst; explanation = "Libvirt network $($net.name) ($fm) is routed by $($owner.name), but its listening services were not collected ($lst)" }) }
                    continue
                }
                $svc = @($owner.facts.listening.value | Where-Object { $_ -and [int](Get-VsatProp $_ 'port' 0) -in $script:VsatMgmtListenPorts -and -not (Test-VsatLoopbackAddress ([string](Get-VsatProp $_ 'address' ''))) })
                if ($svc.Count) {
                    $ports = @($svc | ForEach-Object { [int]$_.port } | Sort-Object -Unique)
                    $reach.Add(@{ hostId = $owner.id; ports = $ports; evidence = @($vmRef, [ordered]@{ assetId = $net.id; fact = 'props.forwardMode'; status = 'ok' }, [ordered]@{ assetId = $owner.id; fact = 'listening'; status = 'ok' }); explanation = "Guest network $($net.name) ($fm) is routed by $($owner.name), which listens on port $($ports -join ', ') on non-loopback addresses" })
                }
            }
            'portgroup' {
                $at = $net.id.IndexOf('/pg/')
                if ($at -lt 0) { continue }
                $hid = $net.id.Substring(0, $at)
                $h = $Context.assets[$hid]
                if (-not $h -or $h.type -ne 'host') { continue }
                if ($MgmtIndex.gap.ContainsKey($hid)) { $gaps.Add(@{ hostId = $hid; fact = 'vmkernel'; assetId = $hid; status = $MgmtIndex.gap[$hid]; explanation = "VM $($Vm.name) is on portgroup $($net.name) of $($h.name), whose management vmknics were not collected ($($MgmtIndex.gap[$hid]))" }); continue }
                if (-not $MgmtIndex.std.ContainsKey($hid)) { continue }
                foreach ($m in $MgmtIndex.std[$hid]) {
                    $mpg = $Context.assets[$m.pgId]
                    $why = $null
                    if ($m.pgId -eq $net.id) { $why = "VM $($Vm.name) is attached to management portgroup $($net.name) ($($m.device)) of $($h.name)" }
                    elseif ($mpg -and [string](Get-VsatProp $net 'props.vswitch' '') -and [string](Get-VsatProp $net 'props.vswitch' '') -eq [string](Get-VsatProp $mpg 'props.vswitch' '')) {
                        $vl = [string](Get-VsatProp $net 'props.vlan' ''); $mvl = [string](Get-VsatProp $mpg 'props.vlan' '')
                        if ($vl -eq '4095') { $why = "Portgroup $($net.name) on $($h.name) trunks all VLANs (4095) on $(Get-VsatProp $net 'props.vswitch'), which carries management VLAN $mvl ($($m.device))" }
                        elseif ($vl -and $vl -eq $mvl) { $why = "Portgroup $($net.name) on $($h.name) uses management VLAN $mvl on $(Get-VsatProp $net 'props.vswitch') ($($m.device))" }
                    }
                    if ($why) { $reach.Add(@{ hostId = $hid; evidence = @($vmRef, [ordered]@{ assetId = $hid; fact = 'vmkernel'; status = 'ok' }, [ordered]@{ assetId = $net.id; fact = 'props.vlan'; status = 'ok' }); explanation = $why }) }
                }
            }
            'dvportgroup' {
                if (-not $MgmtIndex.dv.ContainsKey($net.id)) { continue }
                foreach ($m in $MgmtIndex.dv[$net.id]) {
                    $h = $Context.assets[$m.hostId]
                    $reach.Add(@{ hostId = $m.hostId; evidence = @($vmRef, [ordered]@{ assetId = $m.hostId; fact = 'vmkernel'; status = 'ok' }); explanation = "VM $($Vm.name) is attached to distributed portgroup $($net.name), which carries the management vmknic $($m.device) of $($h.name)" })
                }
            }
        }
    }
    return @{ reach = $reach; gaps = $gaps }
}

function Get-VsatNetworkEdges {
    # Lazy: only entry VMs -> crown VMs (network-allow) and entry VMs -> host management
    # (mgmt-reach). Never pairwise. Returns $false when the time budget ran out.
    param($G, $Context, [string[]]$EntryVmIds, [System.Diagnostics.Stopwatch]$Stopwatch, [int]$BudgetMs = [int]::MaxValue)
    if (-not @($EntryVmIds).Count -or -not $Context.assets -or -not $Context.out) { return $true }
    if (-not $Stopwatch) { $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew() }
    $crownVms = @($G.crowns | Where-Object { $Context.assets[$_] -and $Context.assets[$_].type -in $script:VsatGraphVmTypes })
    $entryVms = @($EntryVmIds | Where-Object { $Context.assets[$_] -and $Context.assets[$_].type -in $script:VsatGraphVmTypes })
    $relRef = { param($id) [ordered]@{ assetId = $id; fact = 'relationships'; status = 'ok' } }
    # 1. NSX DFW (vSphere VMs on NSX segments of the same manager).
    $vsCrowns = @($crownVms | Where-Object { $Context.assets[$_].type -eq 'vm' })
    $vsEntries = @($entryVms | Where-Object { $Context.assets[$_].type -eq 'vm' })
    if ($vsCrowns.Count -and $vsEntries.Count -and @($Context.evidence.assets | Where-Object { $_.type -eq 'nsx-manager' }).Count) {
        $vmSeg = Get-VsatVmSegments $Context
        $groups = Get-VsatGroupIndex $Context
        $mgrByEp = @{}; foreach ($m in @($Context.evidence.assets | Where-Object { $_.type -eq 'nsx-manager' })) { if (-not $mgrByEp.ContainsKey($m.endpoint)) { $mgrByEp[$m.endpoint] = $m.id } }
        $epsCache = @{}
        $epsOf = { param($id) if (-not $epsCache.ContainsKey($id)) { $epsCache[$id] = Get-VsatOrdinalSorted @(@($vmSeg[$id]) | Where-Object { $_ } | ForEach-Object { ([string]$_ -split ':')[0] } | Select-Object -Unique) }; , $epsCache[$id] }
        foreach ($sid in $vsEntries) {
            # Every NSX segment of the VM counts (multi-NIC VMs), grouped by NSX manager endpoint.
            $sEps = & $epsOf $sid
            if (-not $sEps.Count) { continue }
            $s = $Context.assets[$sid]
            foreach ($tid in $vsCrowns) {
                if ($Stopwatch.ElapsedMilliseconds -gt $BudgetMs) { return $false }
                if ($tid -eq $sid) { continue }
                $tEps = & $epsOf $tid
                foreach ($ep in $sEps) {
                    if ($tEps -notcontains $ep) { continue }   # different NSX domains are never merged
                    if (-not $Context.Contains("dfw:$ep")) { $Context["dfw:$ep"] = @(Get-VsatNsxRules $Context $ep 'dfw') }
                    $t = $Context.assets[$tid]
                    $d = Get-VsatDfwDecision -Src $s -Dst $t -Rules $Context["dfw:$ep"] -Groups $groups -Endpoint $ep
                    if ($d.decision -eq 'allow') {
                        $rule = @($d.rules | Where-Object { $_.action -eq 'ALLOW' })[0]
                        [void](Add-VsatGraphEdge $G $sid $tid 'network-allow' 'configuration-inferred' 2 "rule:$($rule.ruleAssetId)" @([ordered]@{ assetId = $rule.ruleAssetId; fact = 'props'; status = 'ok' }, (& $relRef $sid), (& $relRef $tid)) -Explanation "NSX DFW rule '$($rule.name)' allows $($s.name) -> $($t.name) ($($rule.reason)); configuration-inferred" -Extra ([ordered]@{ ruleName = [string]$rule.name; services = @($rule.services) }))
                    }
                    elseif ($d.decision -eq 'unknown') {
                        # Gap-only status 'unknown': the policy is undecidable from collected rules/groups (never a fact status).
                        $mgrId = if ($mgrByEp.ContainsKey($ep)) { $mgrByEp[$ep] } else { $ep }
                        Add-VsatGraphGap $G 'network-allow' $sid $tid 'dfw' $mgrId 'unknown' "Whether NSX DFW allows $($s.name) -> $($t.name) cannot be decided from collected policy: $(@($d.uncertainty) -join '; ')"
                    }
                }
            }
        }
    }
    # 2. Flat L2 on Hyper-V / KVM: same switch + VLAN or same libvirt network, no port ACL evidence.
    $l2 = @{}
    foreach ($tid in @($crownVms | Where-Object { $Context.assets[$_].type -in @('hyperv-vm', 'kvm-vm') })) {
        foreach ($c in @($Context.out[$tid] | Where-Object { $_ -and $_.type -eq 'connects' })) {
            $k = "$($c.target)|$([string](Get-VsatProp $c 'props.vlan' ''))"
            if (-not $l2.ContainsKey($k)) { $l2[$k] = [System.Collections.Generic.List[string]]::new() }
            if (-not $l2[$k].Contains($tid)) { $l2[$k].Add($tid) }
        }
    }
    $mgmtIdx = $null
    foreach ($sid in $entryVms) {
        if ($Stopwatch.ElapsedMilliseconds -gt $BudgetMs) { return $false }
        $s = $Context.assets[$sid]
        if ($l2.Count -and $s.type -in @('hyperv-vm', 'kvm-vm')) {
            foreach ($c in @($Context.out[$sid] | Where-Object { $_ -and $_.type -eq 'connects' })) {
                $vl = [string](Get-VsatProp $c 'props.vlan' '')
                $k = "$($c.target)|$vl"
                if (-not $l2.ContainsKey($k)) { continue }
                $sw = $Context.assets[$c.target]
                foreach ($tid in (Get-VsatOrdinalSorted $l2[$k])) {
                    if ($tid -eq $sid) { continue }
                    [void](Add-VsatGraphEdge $G $sid $tid 'network-allow' 'configuration-inferred' 3 "segment:$($c.target)" @((& $relRef $sid), (& $relRef $tid)) -Explanation "$($s.name) and $($Context.assets[$tid].name) share $(if ($sw) { $sw.name } else { $c.target })$(if ($vl) { " VLAN $vl" }); no port ACL evidence collected (configuration-inferred)")
                }
            }
        }
        # 3. Management reach.
        if ($null -eq $mgmtIdx) { $mgmtIdx = Get-VsatMgmtIndex $Context }
        $mr = Get-VsatMgmtReach -Context $Context -Vm $s -MgmtIndex $mgmtIdx
        foreach ($x in $mr.reach) {
            if (-not $G.nodes.ContainsKey($x.hostId)) { continue }
            # ports: management listeners the hop relies on, when collected (KVM 'listening'); empty for
            # L2 adjacency (vSphere management VLAN, Hyper-V AllowManagementOS), where no port was observed.
            [void](Add-VsatGraphEdge $G $sid $x.hostId 'mgmt-reach' 'configuration-inferred' 2 "isolate:$($x.hostId)" @($x.evidence) -Explanation $x.explanation -Extra ([ordered]@{ ports = [int[]]@($x.ports | Where-Object { $null -ne $_ }) }))
        }
        foreach ($x in $mr.gaps) { Add-VsatGraphGap $G 'mgmt-reach' $sid $x.hostId $x.fact $x.assetId $x.status $x.explanation }
    }
    return $true
}

function Get-VsatBlastEntries {
    # Entry points: scope entryPoints, else one representative VM per (platform, network) and
    # every principal with an admin-of edge. Each class is capped at MaxSources.
    param($G, $Context, [int]$MaxSources, $Notes)
    $vmIds = [System.Collections.Generic.List[string]]::new()
    $pIds = [System.Collections.Generic.List[string]]::new()
    $capped = $false
    $scope = Get-VsatProp $Context.evidence 'scope' $null
    $declared = @(Get-VsatProp $scope 'entryPoints' @() | Where-Object { $_ })
    if ($declared.Count) {
        foreach ($d in $declared) {
            if ($d -is [string]) { $d = @{ match = $d } }
            $aid = [string](Get-VsatProp $d 'assetId' '')
            if ($aid -and $G.nodes.ContainsKey($aid) -and -not $vmIds.Contains($aid)) { $vmIds.Add($aid) }
            $m = [string](Get-VsatProp $d 'match' '')
            $z = [string](Get-VsatProp $d 'zone' '')
            if (-not $m -and $z) { $m = "zone:$z" }
            if ($m) { foreach ($a in @($Context.evidence.assets | Where-Object { $G.nodes.ContainsKey($_.id) -and (Test-VsatAssetMatch $_ $m) } | ForEach-Object { $_.id })) { if (-not $vmIds.Contains($a)) { $vmIds.Add($a) } } }
            $pn = [string](Get-VsatProp $d 'principal' '')
            if ($pn) {
                $pk = (ConvertTo-VsatPrincipalKey -Name $pn -Endpoint 'scope' -Scope $scope).key
                if ($G.nodes.ContainsKey($pk)) { if (-not $pIds.Contains($pk)) { $pIds.Add($pk) } }
                else { $Notes.Add("Declared entry principal '$pn' holds no modeled rights (not in the graph)") }
            }
        }
        $Notes.Add("Entry points: $($pIds.Count + $vmIds.Count) declared in the scope file")
    }
    else {
        # Principals ("credential compromised"): most admin-of edges first, ordinal tie-break.
        $cnt = @{}
        foreach ($src in $G.out.Keys) {
            $n = $G.nodes[$src]
            if (-not $n -or $n.kind -ne 'principal') { continue }
            $c = 0; foreach ($e in $G.out[$src]) { if ($e.kind -eq 'admin-of') { $c++ } }
            if ($c) { $cnt[$src] = $c }
        }
        foreach ($c in @($cnt.Values | Sort-Object -Unique -Descending)) {
            foreach ($id in (Get-VsatOrdinalSorted @($cnt.Keys | Where-Object { $cnt[$_] -eq $c }))) { $pIds.Add($id) }
        }
        # One representative VM per (platform, network): a VM is added when it covers a network not yet covered.
        $seen = @{}
        $vms = @($G.nodes.Keys | Where-Object { $n = $G.nodes[$_]; $n.kind -eq 'asset' -and $n.type -in $script:VsatGraphVmTypes -and -not $n.crown })
        foreach ($id in (Get-VsatOrdinalSorted $vms)) {
            $a = if ($Context.assets) { $Context.assets[$id] } else { $null }
            if ($a -and (Get-VsatProp $a 'props.template' $false)) { continue }
            $plat = $G.nodes[$id].platform
            $nets = if ($Context.out) { @($Context.out[$id] | Where-Object { $_ -and $_.type -eq 'connects' } | ForEach-Object { [string]$_.target }) } else { @() }
            $keys = if ($nets.Count) { @($nets | ForEach-Object { "$plat|$_" }) } else { @("$plat|") }
            $new = $false; foreach ($k in $keys) { if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $new = $true } }
            if ($new) { $vmIds.Add($id) }
        }
    }
    $pOut = @($pIds); $vOut = @($vmIds)
    # OT lens: IT-zone workloads are the entries that matter most (listed first, never capped out by the rest).
    $otLens = [bool]$script:VsatOtLens -and $Context.assets
    if ($otLens) { $vOut = @(@($vOut | Where-Object { (Get-VsatOtClass $Context.assets[$_]) -eq 'it' }) + @($vOut | Where-Object { (Get-VsatOtClass $Context.assets[$_]) -ne 'it' })) }
    if ($pOut.Count -gt $MaxSources) { $Notes.Add("Blast radius bounds hit: entry points capped at $MaxSources of $($pOut.Count) principals (most admin-of edges first; maxSources)"); $pOut = @($pOut | Select-Object -First $MaxSources); $capped = $true }
    if ($vOut.Count -gt $MaxSources) { $Notes.Add("Blast radius bounds hit: entry points capped at $MaxSources of $($vOut.Count) $(if ($declared.Count) { 'declared assets' } else { 'representative VMs' }) (maxSources)"); $vOut = @($vOut | Select-Object -First $MaxSources); $capped = $true }
    $ordered = if ($otLens) { @($vOut) + @($pOut) } else { @($pOut) + @($vOut) }
    return @{ ids = [string[]]@($ordered | Select-Object -Unique); capped = $capped }
}

function Invoke-VsatGraphSearch {
    # Dijkstra from one node over (node, hops) states, hops <= MaxDepth, so a cheap long route to a
    # node can never mask a shorter route through it. Weight is lexicographic (cost, hops); pop order
    # is (cost, hops, node ordinal rank); adjacency is ordered by (cost, edge id ordinal); relaxation
    # only on strict cost improvement per state (ties keep the first route found). A state is
    # dominated, and skipped, when its node was already settled with no more hops. A node's label is
    # its first settled state (cheapest, then fewest hops). depthHit is set when a state at MaxDepth
    # had an out-edge to a node that was never reached.
    param($G, [string]$Start, $State)
    $sd = @{}; $sprev = @{}; $minHops = @{}; $dist = @{}; $hops = @{}
    $done = [System.Collections.Generic.List[string]]::new()
    $blocked = [System.Collections.Generic.List[string]]::new()
    $pq = [System.Collections.Generic.PriorityQueue[string, long]]::new()
    $rank = $State.rank
    $sd["0|$Start"] = 0
    $pq.Enqueue("0|$Start", [long]$rank[$Start])
    while ($pq.Count) {
        $key = $pq.Dequeue()
        $bar = $key.IndexOf('|'); $h = [int]$key.Substring(0, $bar); $u = $key.Substring($bar + 1)
        if ($minHops.ContainsKey($u) -and $h -ge $minHops[$u]) { continue }
        $du = $sd[$key]
        $minHops[$u] = $h
        if (-not $dist.ContainsKey($u)) { $dist[$u] = $du; $hops[$u] = $h; $done.Add($u) }
        $State.pops++
        if ($State.pops -gt $State.maxNodes) { $State.stop = 'node'; break }
        if (($State.pops -band 255) -eq 0 -and $State.sw.ElapsedMilliseconds -gt $State.budgetMs) { $State.stop = 'time'; break }
        if (-not $State.adj.ContainsKey($u)) {
            $arr = [object[]]@($G.out[$u] | Where-Object { $_ })
            if ($arr.Count -gt 1) {
                $keys = [string[]]::new($arr.Count)
                for ($i = 0; $i -lt $arr.Count; $i++) { $keys[$i] = ('{0:d6}|{1}' -f [int]$arr[$i].cost, $arr[$i].id) }
                [Array]::Sort([Array]$keys, [Array]$arr, [System.Collections.IComparer][StringComparer]::Ordinal)
            }
            $State.adj[$u] = $arr
        }
        if ($h -ge $State.maxDepth) { foreach ($e in $State.adj[$u]) { $blocked.Add($e.target) }; continue }
        $nh = $h + 1
        foreach ($e in $State.adj[$u]) {
            $t = $e.target
            if (-not $rank.ContainsKey($t)) { continue }
            if ($minHops.ContainsKey($t) -and $nh -ge $minHops[$t]) { continue }
            $nk = "$nh|$t"; $nd = $du + [int]$e.cost
            if ($sd.ContainsKey($nk) -and $nd -ge $sd[$nk]) { continue }
            $sd[$nk] = $nd; $sprev[$nk] = $e
            $pq.Enqueue($nk, ([long]$nd -shl 40) + ([long]$nh -shl 32) + [long]$rank[$t])
        }
    }
    $depthHit = $false
    foreach ($t in $blocked) { if ($rank.ContainsKey($t) -and -not $dist.ContainsKey($t)) { $depthHit = $true; break } }
    return @{ dist = $dist; hops = $hops; prev = $sprev; done = $done; doneSet = $dist; depthHit = $depthHit }
}

function Get-VsatSearchChain {
    # Edges of the settled route Start -> To (its first settled state).
    param($Search, [string]$Start, [string]$To)
    $chain = [System.Collections.Generic.List[object]]::new(); $x = $To; $h = [int]$Search.hops[$To]
    while ($h -gt 0) { $e = $Search.prev["$h|$x"]; $chain.Insert(0, $e); $x = $e.source; $h-- }
    return , $chain
}

function Get-VsatGraphNodeName {
    # Display name of a node id, including the needsEvidence placeholders.
    param($G, [string]$Id)
    if ($G.nodes.ContainsKey($Id)) { return [string]$G.nodes[$Id].name }
    switch ($Id) { 'principal:*' { return 'an unknown principal' } 'vm:*' { return 'an unidentified VM' } 'mgmt:*' { return 'a management endpoint' } }
    return $Id
}

function Get-VsatPathDescription {
    # platforms (in order of appearance), weakest confidence and a plain narrative for a chain of edges.
    param($G, [string]$Entry, $Chain)
    $plats = [System.Collections.Generic.List[string]]::new()
    $nm = { param($id) Get-VsatGraphNodeName $G $id }
    if ($G.nodes.ContainsKey($Entry)) { $plats.Add([string]$G.nodes[$Entry].platform) }
    $conf = 'observed'; $parts = [System.Collections.Generic.List[string]]::new(); $parts.Add((& $nm $Entry))
    foreach ($e in $Chain) {
        $pl = if ($G.nodes.ContainsKey($e.target)) { [string]$G.nodes[$e.target].platform } else { $null }
        if ($pl -and -not $plats.Contains($pl)) { $plats.Add($pl) }
        if ($script:VsatConfidenceRank[[string]$e.confidence] -lt $script:VsatConfidenceRank[$conf]) { $conf = [string]$e.confidence }
        $verb = if ($script:VsatBlastVerbs.ContainsKey($e.kind)) { $script:VsatBlastVerbs[$e.kind] } else { $e.kind }
        $parts.Add("$verb $(& $nm $e.target)")
    }
    return @{ platforms = [string[]]$plats.ToArray(); confidence = $conf; narrative = ($parts -join ' → '); steps = [string[]]@($parts | Select-Object -Skip 1) }
}

function Get-VsatBlastRadius {
    param([Parameter(Mandatory)]$Graph, [Parameter(Mandatory)]$Context, [int]$MaxDepth = 8, [int]$MaxPaths = 500, [int]$MaxSources = 60, [int]$BudgetMs = 20000, [int]$MaxNodes = 250000)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $G = $Graph
    if (-not $G.Contains('needsEvidence') -or $null -eq $G.needsEvidence) { $G.needsEvidence = [System.Collections.Generic.List[object]]::new() }
    $notes = [System.Collections.Generic.List[string]]::new(); foreach ($n in @($G.notes)) { if ($n) { $notes.Add([string]$n) } }
    $res = [ordered]@{
        bounds = [ordered]@{ maxDepth = $MaxDepth; maxPaths = $MaxPaths; maxSources = $MaxSources; maxNodes = $MaxNodes; budgetMs = $BudgetMs; truncated = $false; elapsedMs = 0; pathsFound = 0; crownsReachable = 0 }
        entries = @(); nodes = @(); edges = @(); paths = @(); needsEvidence = @(); notes = @()
    }
    $hit = @{}
    $bound = { param([string]$why) $res.bounds.truncated = $true; if (-not $hit.ContainsKey($why)) { $hit[$why] = $true; $notes.Add("Blast radius bounds hit: $why; results are partial") } }
    if (-not @($G.crowns).Count) {
        $notes.Add('No crown jewels: mark critical assets in the scope file')
        $res.notes = [string[]]$notes.ToArray(); $res.bounds.elapsedMs = [int]$sw.ElapsedMilliseconds
        return $res
    }
    $ent = Get-VsatBlastEntries -G $G -Context $Context -MaxSources $MaxSources -Notes $notes
    if ($ent.capped) { $res.bounds.truncated = $true }
    $G.entries = $ent.ids
    $res.entries = $ent.ids
    $vmEntries = @($G.entries | Where-Object { $G.nodes[$_] -and $G.nodes[$_].kind -eq 'asset' })
    if (-not (Get-VsatNetworkEdges -G $G -Context $Context -EntryVmIds $vmEntries -Stopwatch $sw -BudgetMs $BudgetMs)) { & $bound "time budget of $BudgetMs ms spent while deriving network edges" }

    # Ordinal node ranks make the pop order total and locale-independent.
    $rank = @{}; $i = 0; foreach ($id in (Get-VsatOrdinalSorted $G.nodes.Keys)) { $rank[$id] = $i; $i++ }
    $state = @{ rank = $rank; adj = @{}; pops = 0; maxNodes = $MaxNodes; maxDepth = $MaxDepth; sw = $sw; budgetMs = $BudgetMs; stop = $null }
    $crownSet = @{}; foreach ($c in $G.crowns) { $crownSet[$c] = $true }
    # Concrete gap sources: the cheapest known prefix from any entry is kept for "collect this" items.
    $gapSrc = @{}; foreach ($x in $G.needsEvidence) { if ($x.source -and -not ([string]$x.source).EndsWith(':*') -and $G.nodes.ContainsKey($x.source)) { $gapSrc[[string]$x.source] = $true } }
    $bestPrefix = @{}
    $reachAll = @{}
    $perEntry = [System.Collections.Generic.List[object]]::new()   # per entry, its first MaxPaths hits by (cost, crown)
    $bestCrown = @{}                                                 # crown -> cheapest hit across entries (ties: entry ordinal)
    $pathsFound = 0; $crownHit = @{}; $depthHit = $false
    foreach ($entry in $G.entries) {
        if ($state.stop) { break }
        if ($sw.ElapsedMilliseconds -gt $BudgetMs) { $state.stop = 'time'; break }
        if (-not $rank.ContainsKey($entry)) { continue }
        $s = Invoke-VsatGraphSearch -G $G -Start $entry -State $state
        if ($s.depthHit) { $depthHit = $true }
        foreach ($k in $s.done) { $reachAll[$k] = $true }
        if ($gapSrc.Count) {
            $cands = if ($s.done.Count -lt $gapSrc.Count) { @($s.done | Where-Object { $gapSrc.ContainsKey($_) }) } else { @($gapSrc.Keys | Where-Object { $s.doneSet.ContainsKey($_) }) }
            foreach ($gs in $cands) {
                $d = [int]$s.dist[$gs]
                if (-not $bestPrefix.ContainsKey($gs) -or $d -lt $bestPrefix[$gs].cost) { $bestPrefix[$gs] = @{ entry = $entry; cost = $d; chain = (Get-VsatSearchChain $s $entry $gs) } }
            }
        }
        $hits = @($s.done | Where-Object { $crownSet.ContainsKey($_) -and $_ -ne $entry })
        if (-not $hits.Count) { continue }
        $keys = [string[]]@($hits | ForEach-Object { '{0:d6}|{1}' -f [int]$s.dist[$_], $_ }); $arr = [string[]]$hits
        [Array]::Sort([Array]$keys, [Array]$arr, [System.Collections.IComparer][StringComparer]::Ordinal)
        $pathsFound += $arr.Count
        $mine = [System.Collections.Generic.List[object]]::new()
        for ($j = 0; $j -lt $arr.Count; $j++) {
            $c = $arr[$j]; $d = [int]$s.dist[$c]
            $crownHit[$c] = $true
            $bc = $bestCrown[$c]
            $better = (-not $bc) -or $d -lt $bc.cost -or ($d -eq $bc.cost -and [string]::CompareOrdinal($entry, $bc.entry) -lt 0)
            $keep = $j -lt $MaxPaths
            if (-not ($better -or $keep)) { continue }
            $rec = @{ entry = $entry; crown = $c; cost = $d; key = $keys[$j]; chain = (Get-VsatSearchChain $s $entry $c) }
            if ($keep) { $mine.Add($rec) }
            if ($better) { $bestCrown[$c] = $rec }
        }
        $perEntry.Add(@{ entry = $entry; hits = $mine })
    }
    if ($state.stop -eq 'node') { & $bound "node budget of $MaxNodes settled nodes spent (maxNodes)" }
    elseif ($state.stop -eq 'time') { & $bound "time budget of $BudgetMs ms spent during the search" }
    if ($depthHit) { & $bound "depth limit of $MaxDepth hops reached (maxDepth)" }
    $res.bounds.pathsFound = $pathsFound
    $res.bounds.crownsReachable = $crownHit.Count

    # Select up to MaxPaths (entry, crown) pairs, fairly: (0) the cheapest pair of every entry, so no
    # entry that reaches a crown is starved; (1) the cheapest pair per crown across entries (ties by
    # entry ordinal); (2) every other pair. Phases 1-2 round-robin across entries (entry order), each
    # entry by (cost, crown ordinal).
    $sel = [System.Collections.Generic.List[object]]::new(); $selSet = @{}
    $roundRobin = {
        param($lists)
        $idx = @{}; for ($q = 0; $q -lt $lists.Count; $q++) { $idx[$q] = 0 }
        $progress = $true
        while ($progress -and $sel.Count -lt $MaxPaths) {
            $progress = $false
            for ($q = 0; $q -lt $lists.Count -and $sel.Count -lt $MaxPaths; $q++) {
                $l = $lists[$q]
                while ($idx[$q] -lt $l.Count) {
                    $r = $l[$idx[$q]]; $idx[$q]++
                    $k = "$($r.entry)`n$($r.crown)"
                    if ($selSet.ContainsKey($k)) { continue }
                    $selSet[$k] = $true; $sel.Add($r); $progress = $true; break
                }
            }
        }
    }
    $winners = [System.Collections.Generic.List[object]]::new()
    foreach ($pe in $perEntry) {
        $w = @($bestCrown.Values | Where-Object { $_.entry -eq $pe.entry })
        if (-not $w.Count) { continue }
        $wk = [string[]]@($w | ForEach-Object { $_.key }); $wa = [object[]]$w
        [Array]::Sort([Array]$wk, [Array]$wa, [System.Collections.IComparer][StringComparer]::Ordinal)
        $winners.Add($wa)
    }
    & $roundRobin @($perEntry | Where-Object { $_.hits.Count } | ForEach-Object { , @($_.hits[0]) })
    & $roundRobin $winners
    & $roundRobin @($perEntry | ForEach-Object { , $_.hits.ToArray() })
    if ($pathsFound -gt $sel.Count) {
        & $bound "path limit of $MaxPaths reached (maxPaths): $($sel.Count) of $pathsFound paths listed"
        $notes.Add("Fix plan ranks only the $($sel.Count) of $pathsFound paths listed (maxPaths); pathsBroken and pathsTotal count listed paths only")
    }
    $paths = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $sel) {
        $desc = Get-VsatPathDescription $G $r.entry $r.chain
        $crit = 'high'
        if ($Context.assets -and $Context.assets[$r.crown]) { $cv = [string]$Context.assets[$r.crown].criticality; if ($cv -in @('high', 'medium', 'low')) { $crit = $cv } }
        $paths.Add([ordered]@{ id = $null; entry = $r.entry; crown = $r.crown; cost = $r.cost; hops = $r.chain.Count; edgeIds = [string[]]@($r.chain | ForEach-Object { $_.id }); platforms = $desc.platforms; confidence = $desc.confidence; criticality = $crit; narrative = $desc.narrative })
    }
    $ordered = [System.Collections.Generic.List[object]]::new(); foreach ($p in $paths) { $ordered.Add($p) }
    $ordered.Sort([Comparison[object]] {
            param($a, $b)
            if ($a.cost -ne $b.cost) { return $a.cost.CompareTo($b.cost) }
            $x = [string]::CompareOrdinal([string]$a.crown, [string]$b.crown); if ($x) { return $x }
            return [string]::CompareOrdinal([string]$a.entry, [string]$b.entry)
        })
    $i = 0; foreach ($p in $ordered) { $i++; $p.id = 'BR-{0:d3}' -f $i }
    $res.paths = $ordered.ToArray()

    # needsEvidence: routes that need at least one hop VSAT could not verify. Never ranked.
    $neItems = [System.Collections.Generic.List[object]]::new()
    $suffixCache = @{}
    $neEdges = @{}
    $order = 0
    foreach ($gap in @($G.needsEvidence)) {
        if ($neItems.Count -ge $MaxPaths) { & $bound "needsEvidence limit of $MaxPaths reached (maxPaths)"; break }
        if ($sw.ElapsedMilliseconds -gt $BudgetMs) { & $bound "time budget of $BudgetMs ms spent while listing evidence gaps"; break }
        $src = [string]$gap.source; $tgt = [string]$gap.target
        $prefix = @(); $pcost = 0; $entry = $src
        if (-not $src.EndsWith(':*') -and $bestPrefix.ContainsKey($src)) { $bp = $bestPrefix[$src]; $entry = $bp.entry; $prefix = @($bp.chain); $pcost = $bp.cost }
        $crown = $null; $suffix = @(); $scost = 0; $reach = @()
        if ($tgt.EndsWith(':*')) { $crown = $tgt }
        elseif ($crownSet.ContainsKey($tgt)) { $crown = $tgt; $reach = @($tgt) }
        elseif ($G.nodes.ContainsKey($tgt)) {
            if (-not $suffixCache.ContainsKey($tgt)) {
                $st2 = @{ rank = $rank; adj = $state.adj; pops = 0; maxNodes = $MaxNodes; maxDepth = $MaxDepth; sw = $sw; budgetMs = $BudgetMs; stop = $null }
                $fs = Invoke-VsatGraphSearch -G $G -Start $tgt -State $st2
                if ($st2.stop -eq 'node') { & $bound "node budget of $MaxNodes settled nodes spent while tracing an evidence gap (maxNodes)" }
                elseif ($st2.stop -eq 'time') { & $bound "time budget of $BudgetMs ms spent while tracing an evidence gap" }
                if ($fs.depthHit) { & $bound "depth limit of $MaxDepth hops reached (maxDepth)" }
                $hs = @($fs.done | Where-Object { $crownSet.ContainsKey($_) })
                $best = $null
                if ($hs.Count) {
                    $keys = [string[]]@($hs | ForEach-Object { '{0:d6}|{1}' -f [int]$fs.dist[$_], $_ }); $arr = [string[]]$hs
                    [Array]::Sort([Array]$keys, [Array]$arr, [System.Collections.IComparer][StringComparer]::Ordinal)
                    $best = @{ crown = $arr[0]; cost = [int]$fs.dist[$arr[0]]; chain = (Get-VsatSearchChain $fs $tgt $arr[0]); reach = (Get-VsatOrdinalSorted $arr) }
                }
                $suffixCache[$tgt] = $best
            }
            $sb = $suffixCache[$tgt]
            if (-not $sb) { continue }   # the unverified hop leads to no crown jewel
            $crown = $sb.crown; $suffix = @($sb.chain); $scost = $sb.cost; $reach = @($sb.reach)
        }
        # else: the target itself is outside the collected inventory; what it reaches is unknown (crown stays $null).
        $gapCost = switch ([string]$gap.kind) { 'embodies' { 0 } 'member-of' { 0 } 'network-allow' { 2 } 'mgmt-reach' { 2 } default { 1 } }
        $nm = { param($id) Get-VsatGraphNodeName $G $id }
        $pd = Get-VsatPathDescription $G $entry $prefix
        $sd = Get-VsatPathDescription $G $tgt $suffix
        $mid = "[not verified: $([string]$gap.kind) $(& $nm $tgt)]"
        $narr = if ($prefix.Count) { "$($pd.narrative) → $mid" } else { "$(& $nm $entry) → $mid" }
        if ($suffix.Count) { $narr += ' → ' + ($sd.steps -join ' → ') }
        $plats = [System.Collections.Generic.List[string]]::new(); foreach ($pl in @($pd.platforms) + @($sd.platforms)) { if ($pl -and -not $plats.Contains($pl)) { $plats.Add($pl) } }
        $assetName = & $nm ([string]$gap.assetId)
        foreach ($e in @($prefix) + @($suffix)) { $neEdges[$e.id] = $e }
        $order++
        $neItems.Add([ordered]@{
                id = $null; entry = $entry; crown = $crown; crowns = [string[]]@($reach); cost = $pcost + $gapCost + $scost
                edgeIds = [string[]]@(@($prefix) + @($suffix) | ForEach-Object { $_.id }); gapAt = @($prefix).Count; platforms = [string[]]$plats.ToArray()
                gap = $gap; narrative = $narr; order = $order
                explanation = "Collect $($gap.missingFact) on $assetName (currently $($gap.status)) to confirm or rule out this route"
            })
    }
    $neSorted = [System.Collections.Generic.List[object]]::new(); foreach ($x in $neItems) { $neSorted.Add($x) }
    $neSorted.Sort([Comparison[object]] { param($a, $b) if ($a.cost -ne $b.cost) { return $a.cost.CompareTo($b.cost) }; return $a.order.CompareTo($b.order) })
    $i = 0; foreach ($x in $neSorted) { $i++; $x.id = 'NE-{0:d3}' -f $i; $x.Remove('order') }
    $res.needsEvidence = $neSorted.ToArray()

    # Export every edge reachable from any entry (bounded), not only edges on cheapest paths: the
    # report recomputes paths in the browser when the viewer ticks fixes, including reroutes.
    $exp = [System.Collections.Generic.List[object]]::new()
    foreach ($id in (Get-VsatOrdinalSorted $G.edges.Keys)) { $e = $G.edges[$id]; if ($reachAll.ContainsKey($e.source) -or $neEdges.ContainsKey($id)) { $exp.Add($e) } }
    $res.edges = $exp.ToArray()
    $nids = @{}
    foreach ($e in $exp) { $nids[$e.source] = $true; $nids[$e.target] = $true }
    foreach ($x in @($G.entries) + @($G.crowns)) { $nids[$x] = $true }
    foreach ($x in $res.needsEvidence) { foreach ($y in @($x.gap.source, $x.gap.target)) { if ($y -and $G.nodes.ContainsKey($y)) { $nids[$y] = $true } } }
    $res.nodes = @(foreach ($id in (Get-VsatOrdinalSorted $nids.Keys)) { if ($G.nodes.ContainsKey($id)) { $G.nodes[$id] } })
    $res.bounds.elapsedMs = [int]$sw.ElapsedMilliseconds
    $res.notes = [string[]]$notes.ToArray()
    return $res
}

function Get-VsatContextGraph {
    # Security graph + blast radius for evaluators that need reachability, built once per rule
    # context (no findings yet, so edges carry no findingKeys; the pipeline rebuilds for output).
    param([Parameter(Mandatory)]$Context)
    if (-not $Context.Contains('graph')) {
        $Context.graph = New-VsatSecurityGraph -Context $Context -Findings @()
        $Context.blast = Get-VsatBlastRadius -Graph $Context.graph -Context $Context
    }
    return @{ graph = $Context.graph; blast = $Context.blast }
}

function Get-VsatFixPlan {
    # Greedy weighted set cover over fixIds (weight = crown criticality: high 3, medium 2, low 1).
    # Each round picks the fix breaking the most remaining weight; ties by fixId ordinal.
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Paths, [Parameter(Mandatory)]$Graph, [int]$Rounds = 10, $Bounds)
    $w = @{ high = 3; medium = 2; low = 1 }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($Paths | Where-Object { $_ })) {
        $crit = if ($p.Contains('criticality')) { [string]$p.criticality } else { [string](Get-VsatProp $script:VsatAssetIndex[[string]$p.crown] 'criticality' 'high') }
        if (-not $w.ContainsKey($crit)) { $crit = 'high' }
        $fx = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in @($p.edgeIds)) { $e = $Graph.edges[$id]; if ($e -and $e.fixId) { [void]$fx.Add([string]$e.fixId) } }
        $items.Add(@{ path = $p; weight = $w[$crit]; fixes = $fx })
    }
    # Representative edge (lowest id) and all finding keys per fixId.
    $rep = @{}; $fks = @{}
    foreach ($id in (Get-VsatOrdinalSorted $Graph.edges.Keys)) {
        $e = $Graph.edges[$id]
        if (-not $e.fixId) { continue }
        if (-not $rep.ContainsKey($e.fixId)) { $rep[$e.fixId] = $e; $fks[$e.fixId] = [System.Collections.Generic.List[string]]::new() }
        foreach ($k in @($e.findingKeys)) { if ($k -and -not $fks[$e.fixId].Contains($k)) { $fks[$e.fixId].Add($k) } }
    }
    $total = $items.Count; $cum = 0; $rank = 0
    # Under maxPaths truncation the plan ranks the listed paths only; say so on every item.
    $found = if ($Bounds) { [int](Get-VsatProp $Bounds 'pathsFound' 0) } else { 0 }
    $scopeNote = if ($found -gt $total) { "Ranked over the $total of $found paths found that are listed (maxPaths); this fix may break more paths than shown" } else { $null }
    $plan = [System.Collections.Generic.List[object]]::new()
    while ($items.Count -and $rank -lt $Rounds) {
        $score = @{}
        foreach ($it in $items) { foreach ($f in $it.fixes) { $score[$f] = [int]$score[$f] + $it.weight } }
        if (-not $score.Count) { break }
        $best = $null
        foreach ($f in $score.Keys) { if ($null -eq $best -or $score[$f] -gt $score[$best] -or ($score[$f] -eq $score[$best] -and [string]::CompareOrdinal($f, $best) -lt 0)) { $best = $f } }
        $broken = @($items | Where-Object { $_.fixes.Contains($best) })
        foreach ($b in $broken) { [void]$items.Remove($b) }
        $rank++; $cum += $broken.Count
        $edge = $rep[$best]
        $plan.Add([ordered]@{
                rank = $rank; fixId = $best; title = (Get-VsatFixTitle -FixId $best -Graph $Graph -Edge $edge); kind = $(if ($edge) { $edge.kind } else { $null })
                pathsBroken = $broken.Count; cumulativeBroken = $cum; pathsTotal = $total; weightBroken = [int]$score[$best]
                pathIds = [string[]]@($broken | ForEach-Object { $_.path.id } | Where-Object { $_ })
                findingKeys = $(if ($fks.ContainsKey($best)) { [string[]]$fks[$best].ToArray() } else { [string[]]@() })
                workPackage = (Get-VsatFixWorkPackage -FixId $best -Graph $Graph)
                note = $scopeNote
            })
    }
    return @($plan)
}

function Get-VsatFixTitle {
    param([string]$FixId, $Graph, $Edge)
    $nm = { param($id) if ($Graph -and $Graph.nodes.ContainsKey($id)) { [string]$Graph.nodes[$id].name } elseif ($script:VsatAssetIndex -and $script:VsatAssetIndex.ContainsKey($id)) { [string]$script:VsatAssetIndex[$id].name } else { $id } }
    $label = @{ 'vcenter' = 'vCenter'; 'nsx-manager' = 'NSX Manager'; 'hyperv-cluster' = 'Hyper-V cluster'; 'host' = 'ESXi host'; 'esxi-endpoint' = 'ESXi host'; 'hyperv-host' = 'Hyper-V host'; 'kvm-host' = 'KVM host' }
    $at = $FixId.IndexOf(':')
    if ($at -lt 0) { return $FixId }
    $verb = $FixId.Substring(0, $at); $rest = $FixId.Substring($at + 1)
    switch ($verb) {
        { $_ -in 'revoke', 'revoke-member' } {
            # Principal keys may contain '@' (upn:user@domain): split on the LAST '@'.
            $j = $rest.LastIndexOf('@')
            if ($j -lt 0) { return $FixId }
            $p = $rest.Substring(0, $j); $o = $rest.Substring($j + 1)
            if ($verb -eq 'revoke-member') { return "Remove $(& $nm $p) from group $(& $nm $o)" }
            return "Remove $(& $nm $p) admin rights on $(& $nm $o)"
        }
        'relocate' {
            $what = $null; $hostName = $null
            if ($Graph) {
                foreach ($e in $Graph.edges.Values) {
                    if ($e.source -eq $rest -and $e.kind -eq 'embodies' -and (-not $what -or [string]::CompareOrdinal($e.target, $what) -lt 0)) { $what = $e.target }
                    if ($e.target -eq $rest -and $e.kind -eq 'controls' -and $Graph.nodes.ContainsKey($e.source) -and $Graph.nodes[$e.source].type -in $script:VsatGraphHostTypes -and (-not $hostName -or [string]::CompareOrdinal($e.source, $hostName) -lt 0)) { $hostName = $e.source }
                }
            }
            $kind = if ($what -and $Graph.nodes.ContainsKey($what) -and $label.ContainsKey($Graph.nodes[$what].type)) { "$($label[$Graph.nodes[$what].type]) appliance " } else { 'management appliance ' }
            if ($hostName) { return "Move $kind$(& $nm $rest) off $($label[$Graph.nodes[$hostName].type]) $(& $nm $hostName) to a dedicated management cluster" }
            return "Move $kind$(& $nm $rest) to a dedicated management cluster and restrict its hypervisor admins"
        }
        'rule' { $rn = if ($Edge -and $Edge.Contains('ruleName') -and $Edge.ruleName) { $Edge.ruleName } else { & $nm $rest }; return "Tighten NSX distributed firewall rule '$rn'" }
        'segment' { return "Segment or apply port ACLs on $(& $nm $rest)" }
        'isolate' { return "Isolate the management network of $(& $nm $rest) from guest networks" }
        'scope-svc' { $a, $b = $rest -split '>', 2; return "Scope the NSX compute-manager service account of $(& $nm $a) on $(& $nm $b) (least privilege)" }
        'rotate' { $a, $b = $rest -split '>', 2; return "Rotate the credentials $(& $nm $a) holds for $(& $nm $b)" }
        default { return $FixId }
    }
}

function Get-VsatFixWorkPackage {
    param([string]$FixId, $Graph)
    if ($FixId -like 'revoke:*') {
        $j = $FixId.LastIndexOf('@')
        $o = if ($j -ge 0) { $FixId.Substring($j + 1) } else { '' }
        if ($Graph -and $Graph.nodes.ContainsKey($o) -and $Graph.nodes[$o].type -in @('hyperv-host', 'kvm-host', 'hyperv-cluster')) { return 'WP-HOST-ACCESS' }
        return 'WP-VC-ACCESS'
    }
    switch -Wildcard ($FixId) { 'relocate:*' { return 'WP-MGMT-ISOLATION' } 'isolate:*' { return 'WP-MGMT-ISOLATION' } 'rule:*' { return 'WP-NSX-DFW' } 'segment:*' { return 'WP-NET-L2' } 'scope-svc:*' { return 'WP-NSX-MGMT' } default { return 'WP-MANUAL' } }
}
#endregion Blast radius
