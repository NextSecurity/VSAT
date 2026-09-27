#region OT segmentation evaluators
# Virtualization-layer only: reads collected facts, relationships, scope annotations and the
# security graph. It assesses where OT workloads run (hosts, virtual switches, management
# planes, admin rights); it never talks to OT networks or field devices. The lens is off
# unless a scope zone declares a Purdue level.

$script:VsatOtLens = $false
$script:VsatOtVmTypes = @('vm', 'hyperv-vm', 'kvm-vm')
$script:VsatOtOffText = 'No zone declares a Purdue level'

function ConvertTo-VsatPurdueLevel {
    # 0..5 (int) or 'dmz'; anything else is $null (not a level).
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -ieq 'dmz') { return 'dmz' }
    $n = 0
    if ([int]::TryParse($s, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -ge 0 -and $n -le 5) { return $n }
    return $null
}

function Test-VsatOtLensDeclared {
    param($Scope)
    foreach ($z in @(Get-VsatProp $Scope 'zones' @())) {
        if ($z -and $null -ne (ConvertTo-VsatPurdueLevel (Get-VsatProp $z 'purdueLevel' $null))) { return $true }
    }
    return $false
}

function Get-VsatOtClass {
    # 'ot' (Purdue 0-3) | 'it' (4-5, or a workload VM with no level) | 'dmz' | $null (lens off / not a workload).
    param($Asset)
    if (-not $script:VsatOtLens -or -not $Asset) { return $null }
    $l = Get-VsatProp $Asset 'purdueLevel' $null
    if ($null -eq $l) { return $(if ($Asset.type -in $script:VsatOtVmTypes) { 'it' } else { $null }) }
    if ([string]$l -eq 'dmz') { return 'dmz' }
    if ([int]$l -le 3) { return 'ot' }
    return 'it'
}

function Get-VsatOtScopeVms {
    # Workload VMs "under" an asset: host -> guests, switch -> attached VMs (portgroups of one
    # switch count as that switch), management plane -> guests of the hosts it manages.
    param($Context, $Asset, [string]$Scope)
    $vmTypes = $script:VsatOtVmTypes
    switch ($Scope) {
        'host' { return @($Context.in[$Asset.id] | Where-Object { $_ -and $_.type -eq 'runs-on' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ -and $_.type -in $vmTypes } | Sort-Object { $_.id } -Unique) }
        'switch' {
            $pgs = @($Asset.id) + @($Context.out[$Asset.id] | Where-Object { $_ -and $_.type -eq 'contains' } | ForEach-Object { $_.target })
            return @($pgs | ForEach-Object { $Context.in[$_] } | Where-Object { $_ -and $_.type -eq 'connects' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ -and $_.type -in $vmTypes } | Sort-Object { $_.id } -Unique)
        }
        'management' {
            $seen = @{}; $queue = [System.Collections.Generic.Queue[string]]::new(); $queue.Enqueue($Asset.id); $vms = [System.Collections.Generic.List[object]]::new()
            while ($queue.Count) {
                $id = $queue.Dequeue(); if ($seen.ContainsKey($id)) { continue }; $seen[$id] = $true
                foreach ($r in @($Context.out[$id] | Where-Object { $_ -and $_.type -eq 'contains' })) { $queue.Enqueue($r.target) }
                foreach ($r in @($Context.in[$id] | Where-Object { $_ -and $_.type -eq 'runs-on' })) { $v = $Context.assets[$r.source]; if ($v -and $v.type -in $vmTypes) { $vms.Add($v) } }
            }
            return @($vms | Sort-Object { $_.id } -Unique)
        }
    }
    return @()
}

function Format-VsatOtNames {
    param($Names, [int]$Max = 5)
    $n = @($Names)
    return "$(@($n | Select-Object -First $Max) -join ', ')$(if ($n.Count -gt $Max) { " (+$($n.Count - $Max))" })"
}

function Invoke-VsatCheckOtMix {
    param($Rule, $Asset, $Check, $Context)
    if (-not $script:VsatOtLens) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed $script:VsatOtOffText -Expected '') }
    $vms = @(Get-VsatOtScopeVms -Context $Context -Asset $Asset -Scope $Check.scope)
    $ot = @($vms | Where-Object { (Get-VsatOtClass $_) -eq 'ot' }); $it = @($vms | Where-Object { (Get-VsatOtClass $_) -eq 'it' })
    $exp = "OT workloads isolated from IT at the $($Check.scope) level"
    if (-not $ot.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No OT workload here' -Expected $exp) }
    if ($it.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "OT: $(Format-VsatOtNames @($ot.name)); IT: $(Format-VsatOtNames @($it.name))" -Expected $exp -Facts @('props')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "OT only ($($ot.Count))" -Expected $exp -Facts @('props'))
}

function Get-VsatOtAdminIndex {
    # Per principal: the hosts it administers (admin-of on the host, or on a container that
    # controls it), including rights inherited through member-of. Cached on the rule context.
    param($Context)
    if ($Context.Contains('otAdmin')) { return $Context.otAdmin }
    $G = (Get-VsatContextGraph -Context $Context).graph
    $hostTypes = $script:VsatGraphHostTypes
    $under = @{}
    $hostsUnder = {
        param([string]$Id)
        if ($under.ContainsKey($Id)) { return $under[$Id] }
        $set = @{}; $seen = @{ $Id = $true }; $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($Id)
        while ($q.Count) {
            $u = $q.Dequeue()
            if ($G.nodes.ContainsKey($u) -and $G.nodes[$u].type -in $hostTypes) { $set[$u] = $true; continue }
            foreach ($e in @($G.out[$u] | Where-Object { $_ -and $_.kind -eq 'controls' })) { if (-not $seen.ContainsKey($e.target)) { $seen[$e.target] = $true; $q.Enqueue($e.target) } }
        }
        $under[$Id] = $set
        return $set
    }
    $direct = @{}
    foreach ($p in (Get-VsatOrdinalSorted @($G.nodes.Keys | Where-Object { $G.nodes[$_].kind -eq 'principal' }))) {
        $set = @{}
        foreach ($e in @($G.out[$p] | Where-Object { $_ -and $_.kind -eq 'admin-of' })) {
            if (-not $G.nodes.ContainsKey($e.target) -or $G.nodes[$e.target].kind -ne 'asset') { continue }
            foreach ($h in (& $hostsUnder $e.target).Keys) { $set[$h] = $true }
        }
        $direct[$p] = $set
    }
    $reach = @{}
    foreach ($p in $direct.Keys) {
        $set = @{}; $seen = @{ $p = $true }; $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($p)
        while ($q.Count) {
            $u = $q.Dequeue()
            if ($direct.ContainsKey($u)) { foreach ($h in $direct[$u].Keys) { $set[$h] = $true } }
            foreach ($e in @($G.out[$u] | Where-Object { $_ -and $_.kind -eq 'member-of' })) { if (-not $seen.ContainsKey($e.target)) { $seen[$e.target] = $true; $q.Enqueue($e.target) } }
        }
        if ($set.Count) { $reach[$p] = $set }
    }
    # Ancestors of each host over 'controls', to match "principals unknown" gaps on containers above it.
    $parents = @{}
    foreach ($e in $G.edges.Values) { if ($e.kind -eq 'controls') { if (-not $parents.ContainsKey($e.target)) { $parents[$e.target] = [System.Collections.Generic.List[string]]::new() }; $parents[$e.target].Add($e.source) } }
    $gapTargets = @{}; foreach ($x in @($G.needsEvidence | Where-Object { $_ -and $_.kind -eq 'admin-of' })) { $gapTargets[[string]$x.target] = $x }
    $Context.otAdmin = @{ graph = $G; reach = $reach; parents = $parents; gapTargets = $gapTargets }
    return $Context.otAdmin
}

function Invoke-VsatCheckOtAdmin {
    param($Rule, $Asset, $Check, $Context)
    if (-not $script:VsatOtLens) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed $script:VsatOtOffText -Expected '') }
    $exp = 'Administrators of OT hosts hold no administrative rights over IT hosts or their management plane'
    $ot = @(Get-VsatOtScopeVms -Context $Context -Asset $Asset -Scope 'host' | Where-Object { (Get-VsatOtClass $_) -eq 'ot' })
    if (-not $ot.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Host runs no OT workload' -Expected $exp) }
    $idx = Get-VsatOtAdminIndex -Context $Context
    $G = $idx.graph
    $itHost = @{}
    $bridges = [System.Collections.Generic.List[string]]::new()
    foreach ($p in (Get-VsatOrdinalSorted $idx.reach.Keys)) {
        $set = $idx.reach[$p]
        if (-not $set.ContainsKey($Asset.id)) { continue }
        $its = [System.Collections.Generic.List[string]]::new()
        foreach ($h in (Get-VsatOrdinalSorted $set.Keys)) {
            if ($h -eq $Asset.id) { continue }
            if (-not $itHost.ContainsKey($h)) { $itHost[$h] = [bool]@(Get-VsatOtScopeVms -Context $Context -Asset @{ id = $h } -Scope 'host' | Where-Object { (Get-VsatOtClass $_) -eq 'it' }).Count }
            if ($itHost[$h]) { $its.Add([string]$G.nodes[$h].name) }
        }
        if ($its.Count) { $bridges.Add("$($G.nodes[$p].name) (also IT host(s): $(Format-VsatOtNames $its 3))") }
    }
    if ($bridges.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Identity bridge between OT and IT: $(Format-VsatOtNames $bridges 3)" -Expected $exp -Facts @('props') -Confidence inferred) }
    # Unknown principals on this host or on any container above it: never a pass.
    $seen = @{}; $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($Asset.id)
    while ($q.Count) {
        $u = $q.Dequeue(); if ($seen.ContainsKey($u)) { continue }; $seen[$u] = $true
        if ($idx.gapTargets.ContainsKey($u)) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Administrators cannot be fully determined: $($idx.gapTargets[$u].explanation)" -Expected $exp) }
        if ($idx.parents.ContainsKey($u)) { foreach ($x in $idx.parents[$u]) { $q.Enqueue($x) } }
    }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No administrator of this host also administers an IT host' -Expected $exp -Facts @('props') -Confidence inferred)
}

function Invoke-VsatCheckOtPath {
    param($Rule, $Asset, $Check, $Context)
    if (-not $script:VsatOtLens) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed $script:VsatOtOffText -Expected '') }
    $dmz = [bool](Get-VsatProp $Check 'requireDmz' $false)
    $lvl = Get-VsatProp $Asset 'purdueLevel' $null
    if ($dmz) {
        $exp = 'IT workloads reach Purdue level 0-2 workloads only through the OT DMZ'
        if ((Get-VsatOtClass $Asset) -ne 'ot' -or [int]$lvl -gt 2) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Not a Purdue level 0-2 workload' -Expected $exp) }
    }
    else {
        $exp = 'No IT entry point reaches this OT workload in the blast-radius graph'
        if ((Get-VsatOtClass $Asset) -ne 'ot') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Not an OT workload' -Expected $exp) }
    }
    $cg = Get-VsatContextGraph -Context $Context
    if ($dmz) {
        if (-not $Context.Contains('otNetIn')) {
            $Context.otNetIn = @{}
            foreach ($e in $cg.graph.edges.Values) { if ($e.kind -eq 'network-allow') { if (-not $Context.otNetIn.ContainsKey($e.target)) { $Context.otNetIn[$e.target] = [System.Collections.Generic.List[object]]::new() }; $Context.otNetIn[$e.target].Add($e) } }
        }
        $src = @($Context.otNetIn[$Asset.id] | Where-Object { $_ -and (Get-VsatOtClass $Context.assets[$_.source]) -eq 'it' } | ForEach-Object { [string]$cg.graph.nodes[$_.source].name })
        if ($src.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Direct network path from IT, no OT DMZ hop: $(Format-VsatOtNames (Get-VsatOrdinalSorted $src)) → $($Asset.name)" -Expected $exp -Confidence inferred) }
    }
    else {
        $hits = @($cg.blast.paths | Where-Object { $_.crown -eq $Asset.id -and (Get-VsatOtClass $Context.assets[[string]$_.entry]) -eq 'it' })
        if ($hits.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "$($hits[0].narrative)$(if ($hits.Count -gt 1) { " (+$($hits.Count - 1) more IT path(s))" })" -Expected $exp -Confidence inferred) }
    }
    # No path found: only a pass when the evidence behind it is complete.
    if ($Asset.type -eq 'vm' -and $Context.nsxState -ne 'ASSESSED') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "No IT path found, but NSX policy was not assessed (NSX coverage: $($Context.nsxState)); network reachability is unknown" -Expected $exp) }
    if ($cg.blast.bounds.truncated) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'No IT path found, but blast-radius search bounds were hit (results partial)' -Expected $exp) }
    if (@($cg.blast.needsEvidence | Where-Object { $_ -and @($_.crowns) -contains $Asset.id }).Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'No confirmed IT path, but a route to this workload needs evidence VSAT could not collect' -Expected $exp) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed $(if ($dmz) { 'No direct IT network path to this workload' } else { 'No IT entry point reaches this workload' }) -Expected $exp -Confidence inferred)
}
#endregion OT segmentation evaluators
