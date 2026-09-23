#region Correlation
function Invoke-VsatCorrelation {
    # Resolves cross-endpoint references by stable identifiers only (never by display name).
    param([Parameter(Mandatory)]$Evidence)
    $idx = @{}; foreach ($a in $Evidence.assets) { $idx[$a.id] = $a }
    $segByUnique = @{}; $segByPath = @{}
    foreach ($s in @($Evidence.assets | Where-Object { $_.type -eq 'nsx-segment' })) {
        if ($s.props.uniqueId) { $segByUnique[[string]$s.props.uniqueId] = $s.id }
        if (-not $segByPath.ContainsKey([string]$s.props.path)) { $segByPath[[string]$s.props.path] = [System.Collections.Generic.List[string]]::new() }
        $segByPath[[string]$s.props.path].Add($s.id)
    }
    $dvpgByKey = @{}
    foreach ($p in @($Evidence.assets | Where-Object { $_.type -eq 'dvportgroup' })) { $dvpgByKey["$($p.endpoint):dvpg-key:$($p.props.key)"] = $p.id }
    $vcByAddr = @{}
    foreach ($e in @($Evidence.scope.endpoints | Where-Object { $_.type -eq 'vcenter' })) { $vcByAddr[$e.address.ToLowerInvariant()] = "$($e.id):root" }
    $unmatchedCm = [System.Collections.Generic.List[string]]::new()
    $keep = [System.Collections.Generic.List[object]]::new()
    $dropped = 0
    foreach ($r in $Evidence.relationships) {
        $t = [string]$r.target
        if ($t -like 'opaque:*') {
            $id = $t.Substring(7)
            if ($segByUnique.ContainsKey($id)) { $r.target = $segByUnique[$id] } else { $dropped++; continue }
        }
        elseif ($t -like '*:dvpg-key:*') {
            if ($dvpgByKey.ContainsKey($t)) { $r.target = $dvpgByKey[$t]; $r.confidence = 'observed' } else { $dropped++; continue }
        }
        elseif ($t -like 'vcenter:*') {
            $addr = $t.Substring(8).ToLowerInvariant()
            if ($vcByAddr.ContainsKey($addr)) { $r.target = $vcByAddr[$addr] } else { $unmatchedCm.Add($t.Substring(8)); continue }
        }
        if (-not $idx.ContainsKey($r.source) -or -not $idx.ContainsKey($r.target)) { $dropped++; continue }
        $keep.Add($r)
    }
    # VDS-backed NSX segments: dvPortgroup.segmentId carries the NSX policy path.
    foreach ($p in @($Evidence.assets | Where-Object { $_.type -eq 'dvportgroup' -and $_.props.segmentId })) {
        $sid = [string]$p.props.segmentId
        if ($segByPath.ContainsKey($sid)) {
            foreach ($s in $segByPath[$sid]) { $keep.Add([ordered]@{ source = $p.id; target = $s; type = 'connects'; provenance = 'correlation.segmentId'; confidence = 'observed'; props = [ordered]@{} }) }
        }
    }
    $Evidence.relationships = $keep
    $Evidence.nsx.unmatchedComputeManagers = @($unmatchedCm | Select-Object -Unique)
    if ($dropped) { Write-VsatLog -Level debug -Source 'correlation' -Message "$dropped relationship(s) referenced objects outside the collected scope" }
}

function Set-VsatScopeAnnotations {
    # Applies operator-supplied criticality and zones; labels inferred values.
    param([Parameter(Mandatory)]$Evidence)
    foreach ($a in $Evidence.assets) {
        foreach ($c in @($Evidence.scope.criticalAssets)) {
            if (Test-VsatAssetMatch -Asset $a -Match ([string]$c.match)) { $a.criticality = [string]$c.criticality; $a.criticalitySource = 'operator' }
        }
        foreach ($z in @($Evidence.scope.zones)) {
            if (Test-VsatAssetMatch -Asset $a -Match ([string]$z.match)) { $a.zone = [string]$z.name }
        }
        if (-not $a.criticality) {
            if ($a.type -in @('vcenter', 'nsx-manager')) { $a.criticality = 'high'; $a.criticalitySource = 'inferred' }
            elseif ($a.type -eq 'vm' -and $a.name -match '(?i)(vcenter|vcsa|nsx-?(mgr|manager)|psc|kms|backup|veeam|domain.?controller|\bdc\d)') { $a.criticality = 'high'; $a.criticalitySource = 'inferred' }
        }
    }
}

function Test-VsatAssetMatch {
    param($Asset, [string]$Match)
    if (-not $Match) { return $false }
    if ($Match -match '^(name|type|tag|id|zone):(.*)$') {
        $k = $Matches[1]; $v = $Matches[2]
        switch ($k) {
            'name' { return ($Asset.name -like $v) }
            'type' { return ($Asset.type -like $v) }
            'id' { return ($Asset.id -like $v) }
            'zone' { return ([string]$Asset.zone -like $v) }
            'tag' { return [bool](@($Asset.tags) | Where-Object { $_ -like $v }) }
        }
    }
    return ($Asset.name -like $Match)
}
#endregion Correlation

#region Exceptions and priority
function Set-VsatExceptions {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)][object[]]$Findings)
    $now = [DateTime]::UtcNow
    foreach ($ex in @($Evidence.scope.exceptions)) {
        $exp = $null
        if ($ex.expires) { try { $exp = [DateTime]::Parse([string]$ex.expires, [Globalization.CultureInfo]::InvariantCulture) } catch { } }
        $active = ($null -eq $exp -or $exp.Date -ge $now.Date)
        foreach ($f in $Findings) {
            if ($f.ruleId -notlike [string]$ex.ruleId) { continue }
            $pat = if ($ex.asset) { [string]$ex.asset } else { '*' }
            if ($f.assetName -notlike $pat -and $f.assetId -notlike $pat) { continue }
            # Exceptions stay visible and never turn a FAIL into a PASS.
            $f.exception = [ordered]@{ owner = $ex.owner; rationale = $ex.rationale; expires = $ex.expires; active = $active }
        }
    }
}

function Set-VsatPriority {
    param([Parameter(Mandatory)][object[]]$Findings, [Parameter(Mandatory)]$Context, $PathTargets)
    $base = @{ critical = 90; high = 70; medium = 45; low = 20; info = 5 }
    foreach ($f in $Findings) {
        if ($f.result -notin @('FAIL', 'UNKNOWN', 'ERROR')) { continue }
        $reasons = [System.Collections.Generic.List[string]]::new()
        $s = [int]$base[[string]$f.severity]
        $reasons.Add("$($f.severity) severity")
        if ($f.result -ne 'FAIL') { $s = [int]($s * 0.4); $reasons.Add('evidence missing (risk not confirmed)') }
        $a = $Context.assets[$f.assetId]
        if ($a -and $a.criticality -eq 'high') { $s += 15; $reasons.Add("asset criticality high ($($a.criticalitySource))") }
        elseif ($a -and $a.criticality -eq 'medium') { $s += 8; $reasons.Add("asset criticality medium ($($a.criticalitySource))") }
        if ($f.Contains('advisories') -and @($f.advisories | Where-Object { $_.kev }).Count) { $s += 15; $reasons.Add('known exploited vulnerability (CISA KEV)') }
        if ($a -and $a.type -in @('vcenter', 'nsx-manager')) { $s += 10; $reasons.Add('control-plane scope (affects all managed assets)') }
        if ($PathTargets -and $PathTargets.ContainsKey($f.assetId)) { $s += 10; $reasons.Add('reachable in a modeled attack path') }
        if ($f.exception -and $f.exception.active) { $s = [int]($s * 0.5); $reasons.Add('active exception recorded') }
        $f.priority = [ordered]@{ score = [Math]::Min(100, $s); reasons = @($reasons) }
    }
}
#endregion Exceptions and priority

#region Attack paths
function Get-VsatVmSegments {
    param($Context)
    $map = @{}
    foreach ($vm in @($Context.evidence.assets | Where-Object { $_.type -eq 'vm' })) {
        $segs = [System.Collections.Generic.List[string]]::new()
        foreach ($r in @($Context.out[$vm.id])) {
            if ($r.type -ne 'connects') { continue }
            $t = $Context.assets[$r.target]
            if (-not $t) { continue }
            if ($t.type -eq 'nsx-segment') { $segs.Add($t.id) }
            elseif ($t.type -eq 'dvportgroup') { foreach ($r2 in @($Context.out[$t.id])) { if ($r2.type -eq 'connects' -and $Context.assets[$r2.target] -and $Context.assets[$r2.target].type -eq 'nsx-segment') { $segs.Add($r2.target) } } }
        }
        $map[$vm.id] = @($segs | Select-Object -Unique)
    }
    return $map
}

function Get-VsatGroupIndex {
    param($Context)
    $g = @{}
    foreach ($ga in @($Context.evidence.assets | Where-Object { $_.type -eq 'nsx-group' })) {
        $path = [string]$ga.props.path
        $entry = @{ id = $ga.id; name = $ga.name; known = $false; vms = @{}; ips = @{} }
        if ($ga.facts.Contains('members') -and $ga.facts.members.status -eq 'ok') {
            $entry.known = $true
            foreach ($v in @($ga.facts.members.value.vms)) { $entry.vms[[string]$v.externalId] = $true }
            foreach ($ip in @($ga.facts.members.value.ips)) { $entry.ips[[string]$ip] = $true }
        }
        $g["$($ga.endpoint):$path"] = $entry
    }
    return $g
}

function Test-VsatGroupRef {
    # Returns 'yes' | 'no' | 'unknown' for a VM against a rule's group list.
    param($Refs, $Vm, $Groups, [string]$Endpoint)
    if (@($Refs) -contains 'ANY') { return 'yes' }
    $unknown = $false
    foreach ($ref in @($Refs)) {
        $g = $Groups["${Endpoint}:$ref"]
        if (-not $g) {
            if ($ref -match '^\d{1,3}(\.\d{1,3}){3}(/\d+)?$') { if (@($Vm.props.ipAddresses) -contains ($ref -replace '/32$', '')) { return 'yes' }; continue }
            $unknown = $true; continue
        }
        if (-not $g.known) { $unknown = $true; continue }
        if ($g.vms.ContainsKey([string]$Vm.props.instanceUuid)) { return 'yes' }
        foreach ($ip in @($Vm.props.ipAddresses)) { if ($g.ips.ContainsKey([string]$ip)) { return 'yes' } }
    }
    if ($unknown) { return 'unknown' }
    return 'no'
}

function Get-VsatDfwDecision {
    # First-match evaluation of DFW policy for any traffic from Src to Dst (configuration-inferred).
    param($Src, $Dst, $Rules, $Groups, [string]$Endpoint)
    $allowed = [System.Collections.Generic.List[object]]::new()
    $uncertain = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $Rules) {
        $p = $r.props
        if ($p.disabled) { continue }
        $act = ([string]$p.action).ToUpperInvariant()
        if ($act -eq 'JUMP_TO_APPLICATION') { continue }
        if ($p.sourcesExcluded -or $p.destinationsExcluded) { $uncertain.Add("rule '$($r.name)' uses negated groups (not evaluated)"); continue }
        $scope = if (@($p.appliedTo) -contains 'ANY') { $p.policyAppliedTo } else { $p.appliedTo }
        $sc = if (@($scope) -contains 'ANY') { 'yes' } else {
            $a1 = Test-VsatGroupRef $scope $Dst $Groups $Endpoint
            $a2 = Test-VsatGroupRef $scope $Src $Groups $Endpoint
            if ($a1 -eq 'yes' -or $a2 -eq 'yes') { 'yes' } elseif ($a1 -eq 'unknown' -or $a2 -eq 'unknown') { 'unknown' } else { 'no' }
        }
        $sm = Test-VsatGroupRef $p.sources $Src $Groups $Endpoint
        $dm = Test-VsatGroupRef $p.destinations $Dst $Groups $Endpoint
        if ($sc -eq 'no' -or $sm -eq 'no' -or $dm -eq 'no') { continue }
        $partial = ($sc -eq 'unknown' -or $sm -eq 'unknown' -or $dm -eq 'unknown')
        $anySvc = (@($p.services) -contains 'ANY') -and (@($p.profiles) -contains 'ANY')
        $ruleRef = [ordered]@{ ruleAssetId = $r.id; name = $r.name; action = $act; category = $p.category; services = @($p.services); reason = '' }
        if ($partial) { $uncertain.Add("rule '$($r.name)' references groups with unknown effective membership"); continue }
        if ($act -eq 'ALLOW') {
            $ruleRef.reason = "matches (sources $(Format-VsatValue $p.sources) -> destinations $(Format-VsatValue $p.destinations)); services $(Format-VsatValue $p.services)"
            $allowed.Add($ruleRef)
            if ($anySvc) { return @{ decision = 'allow'; rules = @($allowed); uncertainty = @($uncertain); final = $ruleRef } }
            continue
        }
        if ($anySvc) {
            $ruleRef.reason = "first full match denies all services"
            if ($allowed.Count) { return @{ decision = 'allow'; rules = @($allowed) + $ruleRef; uncertainty = @($uncertain) + 'Only the services listed on earlier ALLOW rules are reachable'; final = $ruleRef } }
            return @{ decision = $(if ($uncertain.Count) { 'unknown' } else { 'deny' }); rules = @($ruleRef); uncertainty = @($uncertain); final = $ruleRef }
        }
    }
    if ($allowed.Count) { return @{ decision = 'allow'; rules = @($allowed); uncertainty = @($uncertain) + 'Service-specific allows only' } }
    return @{ decision = 'unknown'; rules = @(); uncertainty = @($uncertain) + 'No matching rule or default rule found in collected policy' }
}

function Get-VsatAttackPaths {
    param([Parameter(Mandatory)]$Context, [int]$MaxSources = 40, [int]$MaxTargets = 40)
    $result = [ordered]@{ attackPaths = @(); chokepoints = @(); privilegePaths = @(); notes = @() }
    $ev = $Context.evidence
    $result.privilegePaths = @(Get-VsatPrivilegePaths -Context $Context)
    $mgrs = @($ev.assets | Where-Object { $_.type -eq 'nsx-manager' })
    if ($mgrs.Count -eq 0) { $result.notes = @('Network attack paths require assessed NSX policy; none available.'); return $result }
    $vmSeg = Get-VsatVmSegments $Context
    $groups = Get-VsatGroupIndex $Context
    $vms = @($ev.assets | Where-Object { $_.type -eq 'vm' -and -not $_.props.template -and @($vmSeg[$_.id]).Count })
    $targets = @($vms | Where-Object { $_.criticality -eq 'high' } | Select-Object -First $MaxTargets)
    if ($targets.Count -eq 0) { $result.notes = @('No critical workloads identified; mark critical assets in the scope file to model attack paths.'); return $result }
    # One representative source per zone/segment keeps the model bounded and explainable.
    $sources = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($vm in $vms) {
        if ($vm.criticality -eq 'high') { continue }
        $key = if ($vm.zone) { "zone:$($vm.zone)" } else { "seg:" + (@($vmSeg[$vm.id]) -join ',') }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true; $sources.Add($vm)
        if ($sources.Count -ge $MaxSources) { break }
    }
    $paths = [System.Collections.Generic.List[object]]::new()
    $choke = @{}
    $n = 0
    foreach ($t in $targets) {
        foreach ($s in $sources) {
            $sSeg = @($vmSeg[$s.id])[0]; $tSeg = @($vmSeg[$t.id])[0]
            $ep = ($sSeg -split ':')[0]
            if (($tSeg -split ':')[0] -ne $ep) { continue }   # different NSX domains are never merged
            if (-not $Context.Contains("dfw:$ep")) { $Context["dfw:$ep"] = @(Get-VsatNsxRules $Context $ep 'dfw') }
            $d = Get-VsatDfwDecision -Src $s -Dst $t -Rules $Context["dfw:$ep"] -Groups $groups -Endpoint $ep
            $hops = [System.Collections.Generic.List[object]]::new()
            $hops.Add([ordered]@{ asset = $s.id; via = 'source' })
            $hops.Add([ordered]@{ asset = $sSeg; via = 'connects' })
            if ($sSeg -ne $tSeg) {
                $gw = @($Context.out[$sSeg] | Where-Object { $_.type -eq 'routes' }) | Select-Object -First 1
                if ($gw) { $hops.Add([ordered]@{ asset = $gw.target; via = 'routes' }) }
                $hops.Add([ordered]@{ asset = $tSeg; via = 'routes' })
            }
            $hops.Add([ordered]@{ asset = $t.id; via = 'connects' })
            $n++
            $unc = @($d.uncertainty) + @('Guest OS firewalls and upstream physical ACLs are not assessed', 'Configuration-inferred: not proof of reachability or exploitability')
            if ($sSeg -ne $tSeg) { $unc += 'Gateway firewall between segments not modeled in this path' }
            $p = [ordered]@{
                id = ('AP-{0:d3}' -f $n); source = $s.id; sourceZone = $(if ($s.zone) { $s.zone } else { $Context.assets[$sSeg].name }); target = $t.id
                decision = $d.decision; confidence = 'configuration-inferred'; hops = @($hops); rules = @($d.rules)
                explanation = $(switch ($d.decision) { 'allow' { "Traffic from $($s.name) to $($t.name) is permitted by $(@($d.rules | Where-Object { $_.action -eq 'ALLOW' })[0].name)." } 'deny' { "Traffic from $($s.name) to $($t.name) is blocked by $($d.final.name)." } default { "Decision for $($s.name) to $($t.name) cannot be determined from collected evidence." } })
                prerequisites = @("Attacker controls $($s.name) (or a workload in the same segment/zone)")
                uncertainty = @($unc | Select-Object -Unique)
            }
            $paths.Add($p)
            if ($d.decision -eq 'allow') { foreach ($r in @($d.rules | Where-Object { $_.action -eq 'ALLOW' })) { $choke[$r.ruleAssetId] = @{ name = $r.name; n = [int](Get-VsatProp $choke[$r.ruleAssetId] 'n' 0) + 1 } } }
        }
    }
    $result.attackPaths = @($paths)
    $result.chokepoints = @($choke.Keys | ForEach-Object { [ordered]@{ ruleAssetId = $_; name = $choke[$_].name; pathsInterrupted = $choke[$_].n } } | Sort-Object { - $_.pathsInterrupted })
    return $result
}

function Get-VsatPrivilegePaths {
    param($Context)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($vc in @($Context.evidence.assets | Where-Object { $_.type -eq 'vcenter' })) {
        if (-not $vc.facts.Contains('permissions') -or $vc.facts.permissions.status -ne 'ok') { continue }
        foreach ($p in @($vc.facts.permissions.value)) {
            if ($p.role -in @('ReadOnly', 'NoAccess', 'Anonymous', 'View')) { continue }
            $mo = ([string]$p.entityId -replace '^[A-Za-z]+-', '')
            $obj = "$($vc.endpoint):$mo"
            if (-not $Context.assets.ContainsKey($obj)) { $obj = $vc.id }
            $out.Add([ordered]@{ principal = $p.principal; role = $p.role; object = $obj; objectName = $p.entity; propagate = [bool]$p.propagate; isGroup = [bool]$p.isGroup })
        }
    }
    return @($out)
}
#endregion Attack paths

#region Failure impact
function Get-VsatImpact {
    param([Parameter(Mandatory)]$Context, [int]$MaxAffected = 500)
    $ev = $Context.evidence
    $list = [System.Collections.Generic.List[object]]::new()
    $vmsOnHost = @{}; $vmsOnDs = @{}; $vmsOnNet = @{}
    foreach ($r in $ev.relationships) {
        switch ($r.type) {
            'runs-on' { if (-not $vmsOnHost[$r.target]) { $vmsOnHost[$r.target] = [System.Collections.Generic.List[string]]::new() }; $vmsOnHost[$r.target].Add($r.source) }
            'stores' { if (-not $vmsOnDs[$r.target]) { $vmsOnDs[$r.target] = [System.Collections.Generic.List[string]]::new() }; $vmsOnDs[$r.target].Add($r.source) }
            'connects' { if ($Context.assets[$r.source] -and $Context.assets[$r.source].type -eq 'vm') { if (-not $vmsOnNet[$r.target]) { $vmsOnNet[$r.target] = [System.Collections.Generic.List[string]]::new() }; $vmsOnNet[$r.target].Add($r.source) } }
        }
    }
    foreach ($h in @($ev.assets | Where-Object { $_.type -eq 'host' })) {
        $cl = @($Context.in[$h.id] | Where-Object { $_.type -eq 'contains' -and $Context.assets[$_.source] -and $Context.assets[$_.source].type -eq 'cluster' }) | Select-Object -First 1
        $ha = $false; $peers = 0
        if ($cl) {
            $c = $Context.assets[$cl.source]
            $ha = [bool](Get-VsatProp $c.facts 'ha.value.enabled' $false)
            $peers = @($Context.out[$c.id] | Where-Object { $_.type -eq 'contains' }).Count - 1
        }
        $effect = if ($ha -and $peers -gt 0) { 'restart-expected' } else { 'outage' }
        $reason = if ($effect -eq 'restart-expected') { "HA enabled with $peers other host(s); restart depends on capacity and admission control" } else { 'No HA restart target in cluster' }
        $aff = @($vmsOnHost[$h.id] | Select-Object -First $MaxAffected | ForEach-Object { [ordered]@{ asset = $_; effect = $effect; reason = $reason } })
        if ($aff.Count) { $list.Add([ordered]@{ component = $h.id; componentType = 'host'; affected = $aff; redundancy = $(if ($effect -eq 'restart-expected') { 'redundant' } else { 'none' }); notes = @('HA capacity is not verified; this is not proof of successful failover') }) }
    }
    foreach ($d in @($ev.assets | Where-Object { $_.type -eq 'datastore' })) {
        $isVsan = ($d.props.type -eq 'vsan')
        $effect = if ($isVsan) { 'degraded' } else { 'outage' }
        $aff = @($vmsOnDs[$d.id] | Select-Object -Unique -First $MaxAffected | ForEach-Object { [ordered]@{ asset = $_; effect = $effect; reason = $(if ($isVsan) { 'vSAN storage policy determines tolerance (not evaluated)' } else { 'VM files stored on this datastore' }) } })
        if ($aff.Count) { $list.Add([ordered]@{ component = $d.id; componentType = 'datastore'; affected = $aff; redundancy = $(if ($isVsan) { 'unknown' } else { 'none' }); notes = @('Array-level redundancy and replication are not assessed') }) }
    }
    foreach ($sw in @($ev.assets | Where-Object { $_.type -eq 'vss' })) {
        $ups = @($Context.out[$sw.id] | Where-Object { $_.type -eq 'uplink' } | ForEach-Object { $_.target })
        $pgs = @($Context.out[$sw.id] | Where-Object { $_.type -eq 'contains' } | ForEach-Object { $_.target })
        $vms = @($pgs | ForEach-Object { $vmsOnNet[$_] } | Where-Object { $_ } | Select-Object -Unique)
        foreach ($u in $ups) {
            $effect = if ($ups.Count -ge 2) { 'degraded' } else { 'outage' }
            $aff = @($vms | Select-Object -First $MaxAffected | ForEach-Object { [ordered]@{ asset = $_; effect = $effect; reason = $(if ($effect -eq 'degraded') { "$($ups.Count) uplinks on $($sw.name)" } else { "single uplink on $($sw.name)" }) } })
            if ($aff.Count) { $list.Add([ordered]@{ component = $u; componentType = 'pnic'; affected = $aff; redundancy = $(if ($ups.Count -ge 2) { 'redundant' } else { 'none' }); notes = @('Upstream physical redundancy is unknown unless LLDP/CDP shows distinct neighbors') }) }
        }
    }
    foreach ($ec in @($ev.assets | Where-Object { $_.type -eq 'nsx-edge-cluster' })) {
        $gws = @($Context.in[$ec.id] | Where-Object { $_.type -eq 'depends' } | ForEach-Object { $_.source })
        $segs = [System.Collections.Generic.List[string]]::new()
        foreach ($g in $gws) {
            foreach ($r in @($Context.in[$g])) { if ($r.type -eq 'routes') { $segs.Add($r.source); foreach ($r2 in @($Context.in[$r.source])) { if ($r2.type -eq 'routes') { $segs.Add($r2.source) } } } }
        }
        $segIds = @($segs | Where-Object { $Context.assets[$_] -and $Context.assets[$_].type -eq 'nsx-segment' } | Select-Object -Unique)
        $vms = [System.Collections.Generic.List[string]]::new()
        foreach ($s in $segIds) {
            foreach ($x in @($vmsOnNet[$s])) { $vms.Add($x) }
            foreach ($r in @($Context.in[$s] | Where-Object { $_.type -eq 'connects' })) { foreach ($x in @($vmsOnNet[$r.source])) { $vms.Add($x) } }
        }
        $members = [int]$ec.props.memberCount
        $effect = if ($members -ge 2) { 'degraded' } else { 'outage' }
        $aff = @($vms | Select-Object -Unique -First $MaxAffected | ForEach-Object { [ordered]@{ asset = $_; effect = $effect; reason = "North-south and gateway services via $($ec.name) ($members edge node(s))" } })
        $list.Add([ordered]@{ component = $ec.id; componentType = 'nsx-edge-cluster'; affected = $aff; redundancy = $(if ($members -ge 2) { 'redundant' } else { 'none' }); notes = @('East-west distributed routing continues without edges', 'Physical uplink redundancy of edge nodes is unknown') })
    }
    foreach ($nb in @($ev.assets | Where-Object { $_.type -eq 'physical-neighbor' })) {
        $pn = @($Context.in[$nb.id] | Where-Object { $_.type -eq 'neighbor' } | ForEach-Object { $_.source })
        $hosts = @($pn | ForEach-Object { ($_ -split '/pnic/')[0] } | Select-Object -Unique)
        $aff = [System.Collections.Generic.List[object]]::new()
        foreach ($h in $hosts) {
            $allNb = @($Context.out[$h] | Where-Object { $_.type -eq 'contains' -and $Context.assets[$_.target] -and $Context.assets[$_.target].type -eq 'pnic' } | ForEach-Object { @($Context.out[$_.target] | Where-Object { $_.type -eq 'neighbor' } | ForEach-Object { $_.target }) } | Select-Object -Unique)
            $eff = if ($allNb.Count -le 1) { 'outage' } else { 'degraded' }
            foreach ($v in @($vmsOnHost[$h])) { $aff.Add([ordered]@{ asset = $v; effect = $eff; reason = $(if ($eff -eq 'outage') { "all observed uplinks of $($Context.assets[$h].name) connect to this switch" } else { "$($Context.assets[$h].name) has uplinks to other switches" }) }) }
        }
        if ($aff.Count) { $list.Add([ordered]@{ component = $nb.id; componentType = 'physical-neighbor'; affected = @($aff | Select-Object -First $MaxAffected); redundancy = 'unknown'; notes = @('Based on LLDP/CDP immediate-neighbor evidence only; the physical fabric is not fully visible') }) }
    }
    return @($list)
}
#endregion Failure impact

#region Work packages
function Get-VsatWorkPackages {
    param([Parameter(Mandatory)][object[]]$Findings)
    $pack = Get-VsatRulePackMeta
    $defs = @{}; foreach ($w in @($pack.workPackages)) { $defs[$w.id] = $w }
    $groups = [ordered]@{}
    $sevRank = @{ critical = 5; high = 4; medium = 3; low = 2; info = 1 }
    foreach ($f in $Findings) {
        if ($f.result -notin @('FAIL', 'MANUAL')) { continue }
        if ($f.exception -and $f.exception.active) { continue }   # expired exceptions return to the worklist
        $wp = if ($f.result -eq 'MANUAL') { 'WP-MANUAL' } else { [string](Get-VsatProp $f.mitigation 'workPackage' 'WP-MANUAL') }
        if (-not $groups.Contains($wp)) { $groups[$wp] = [System.Collections.Generic.List[object]]::new() }
        $groups[$wp].Add($f)
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $groups.Keys) {
        $fs = $groups[$k]
        $d = if ($defs.ContainsKey($k)) { $defs[$k] } else { [ordered]@{ id = $k; title = $k; team = 'Unassigned' } }
        $steps = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $fs) { $s = [string](Get-VsatProp $f.mitigation 'summary'); if ($s -and -not $steps.Contains($s)) { $steps.Add($s) } }
        $max = ($fs | Sort-Object { - [int]$sevRank[[string]$_.severity] } | Select-Object -First 1).severity
        $out.Add([ordered]@{
                id = $k; title = $d.title; team = $d.team; findingIds = @($fs | ForEach-Object { $_.id }); assetIds = @($fs | ForEach-Object { $_.assetId } | Select-Object -Unique)
                outcome = Get-VsatProp $d 'outcome' ''; prerequisites = @(Get-VsatProp $d 'prerequisites' @()); impact = Get-VsatProp $d 'impact' ''
                maintenanceWindow = [bool](Get-VsatProp $d 'maintenanceWindow' $false); rollback = Get-VsatProp $d 'rollback' ''; validation = Get-VsatProp $d 'validation' ''
                steps = @($steps); maxSeverity = $max; findingCount = $fs.Count
            })
    }
    return @($out | Sort-Object { - [int]$sevRank[[string]$_.maxSeverity] }, { - $_.findingCount })
}
#endregion Work packages

#region Drift
function Get-VsatDrift {
    param([Parameter(Mandatory)]$Current, [Parameter(Mandatory)]$Baseline)
    # Baseline findings were re-evaluated with the current rule pack so rule-version
    # changes do not masquerade as drift. Disappeared evidence is never "resolved".
    $cur = @{}; foreach ($f in $Current.findings) { $cur[$f.key] = $f }
    $old = @{}; foreach ($f in $Baseline.findings) { $old[$f.key] = $f }
    $items = [System.Collections.Generic.List[object]]::new()
    $counts = [ordered]@{ new = 0; resolved = 0; changed = 0; unassessed = 0; unchanged = 0 }
    $known = @('PASS', 'FAIL', 'NOT_APPLICABLE')
    foreach ($k in $cur.Keys) {
        $c = $cur[$k]; $o = $old[$k]
        $change = $null
        if (-not $o) { if ($c.result -eq 'FAIL') { $change = 'new' } }
        elseif ($o.result -eq $c.result) { $counts.unchanged++; continue }
        elseif ($c.result -eq 'FAIL') { $change = 'new' }
        elseif ($o.result -eq 'FAIL' -and $c.result -in @('PASS', 'NOT_APPLICABLE')) { $change = 'resolved' }
        elseif ($o.result -in $known -and $c.result -in @('UNKNOWN', 'ERROR')) { $change = 'unassessed' }
        else { $change = 'changed' }
        if (-not $change) { continue }
        $counts[$change]++
        $items.Add([ordered]@{ key = $k; ruleId = $c.ruleId; assetId = $c.assetId; assetName = $c.assetName; change = $change; before = $(if ($o) { $o.result } else { $null }); after = $c.result; title = $c.title })
    }
    foreach ($k in $old.Keys) {
        if ($cur.ContainsKey($k)) { continue }
        $o = $old[$k]
        if ($o.result -notin $known) { continue }
        $counts.unassessed++
        $items.Add([ordered]@{ key = $k; ruleId = $o.ruleId; assetId = $o.assetId; assetName = $o.assetName; change = 'unassessed'; before = $o.result; after = $null; title = $o.title })
    }
    $ca = @{}; foreach ($a in $Current.assets) { $ca[$a.id] = $a }
    $oa = @{}; foreach ($a in $Baseline.assets) { $oa[$a.id] = $a }
    $added = @($ca.Keys | Where-Object { -not $oa.ContainsKey($_) })
    $removed = @($oa.Keys | Where-Object { -not $ca.ContainsKey($_) })
    $nsxMod = 0
    foreach ($id in @($ca.Keys | Where-Object { $ca[$_].type -eq 'nsx-rule' -and $oa.ContainsKey($_) })) {
        if ((ConvertTo-VsatJson $ca[$id].props -Compress) -ne (ConvertTo-VsatJson $oa[$id].props -Compress)) { $nsxMod++ }
    }
    return [ordered]@{
        baselineRunId = $Baseline.run.id; baselineUtc = $Baseline.run.startedUtc; counts = $counts; items = @($items)
        assets = [ordered]@{ added = $added; removed = $removed }
        nsxRules = [ordered]@{ added = @($added | Where-Object { $ca[$_].type -eq 'nsx-rule' }).Count; removed = @($removed | Where-Object { $oa[$_].type -eq 'nsx-rule' }).Count; modified = $nsxMod }
    }
}
#endregion Drift
