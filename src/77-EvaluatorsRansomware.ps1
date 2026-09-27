#region Ransomware readiness
# "Could one stolen account encrypt every hypervisor, and the backups too?" Reads collected
# facts, relationships, the backupSystems scope key and the security graph only. Loaded after
# the graph (76) so the backup crown rule can register itself; the evaluators build the graph
# lazily through Get-VsatContextGraph, like the OT lens. Off unless backupSystems is declared.

$script:VsatRwVmTypes = @('vm', 'hyperv-vm', 'kvm-vm')
$script:VsatRwOffText = 'No backup systems declared'
$script:VsatRwVmCollectors = @{ vm = 'vsphere.vms'; 'hyperv-vm' = 'hyperv.vms'; 'kvm-vm' = 'kvm.vms' }

function Get-VsatBackupMatches {
    # The match patterns of scope backupSystems ([{ match }] or bare strings); empty when undeclared.
    param($Scope)
    return @(foreach ($b in @(Get-VsatProp $Scope 'backupSystems' @() | Where-Object { $_ })) {
            $m = if ($b -is [string]) { $b } else { [string](Get-VsatProp $b 'match' '') }
            if ($m) { $m }
        })
}

function Get-VsatBackupIndex {
    # @{ declared; ids } for the evidence under evaluation, cached on the rule context.
    param($Context)
    if ($Context.Contains('backupIndex')) { return $Context.backupIndex }
    $ids = @{}
    $pats = @(Get-VsatBackupMatches -Scope $Context.scope)
    if ($pats.Count -and $Context.evidence) {
        foreach ($a in $Context.evidence.assets) { foreach ($m in $pats) { if (Test-VsatAssetMatch -Asset $a -Match $m) { $ids[$a.id] = $true; break } } }
    }
    $Context.backupIndex = @{ declared = [bool]$pats.Count; ids = $ids }
    return $Context.backupIndex
}

# Declared backup systems are crown jewels ahead of operator criticality, so the reason always reads as backup.
Add-VsatCrownRule -Id 'backup-system' -Before 'operator-high' -Test { param($a, $c) if ($c -and $c.Contains('scope') -and (Get-VsatBackupIndex -Context $c).ids.ContainsKey($a.id)) { 'backup infrastructure' } }

function Get-VsatRwSkip {
    # NOT_APPLICABLE finding when the lens is off or the asset is not a declared backup system, else $null.
    param($Rule, $Asset, $Context)
    $idx = Get-VsatBackupIndex -Context $Context
    if (-not $idx.declared) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed $script:VsatRwOffText -Expected '') }
    if (-not $idx.ids.ContainsKey($Asset.id)) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Not a declared backup system' -Expected '') }
    return $null
}

function Test-VsatRwProduction {
    # A production workload: a VM that is neither a declared backup system nor a template.
    param($Context, $Vm)
    return ($Vm -and $Vm.type -in $script:VsatRwVmTypes -and -not (Get-VsatBackupIndex -Context $Context).ids.ContainsKey($Vm.id) -and -not (Get-VsatProp $Vm 'props.template' $false))
}

function Get-VsatRwPlacement {
    # Where a VM runs: its host, and the unit it shares with other workloads (the vSphere or
    # Hyper-V cluster of that host, else the host itself), with every VM in that unit.
    # $null when the VM's host was not collected.
    param($Context, $Asset)
    $hid = @($Context.out[$Asset.id] | Where-Object { $_ -and $_.type -eq 'runs-on' } | ForEach-Object { [string]$_.target })[0]
    if (-not $hid -or -not $Context.assets[$hid]) { return $null }
    $h = $Context.assets[$hid]
    $cl = @($Context.in[$hid] | Where-Object { $_ -and $_.type -eq 'contains' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ -and $_.type -in @('cluster', 'hyperv-cluster') })[0]
    $hosts = if ($cl) { @($Context.out[$cl.id] | Where-Object { $_ -and $_.type -eq 'contains' } | ForEach-Object { $Context.assets[$_.target] } | Where-Object { $_ -and $_.type -in $script:VsatGraphHostTypes }) } else { @($h) }
    $vms = @($hosts | ForEach-Object { $Context.in[$_.id] } | Where-Object { $_ -and $_.type -eq 'runs-on' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ -and $_.type -in $script:VsatRwVmTypes } | Sort-Object { $_.id } -Unique)
    return @{ host = $h; unit = $(if ($cl) { $cl } else { $h }); vms = $vms }
}

function Invoke-VsatCheckRwReachable {
    param($Rule, $Asset, $Check, $Context)
    $skip = Get-VsatRwSkip -Rule $Rule -Asset $Asset -Context $Context
    if ($skip) { return $skip }
    $exp = 'No blast-radius entry point reaches this backup system'
    $cg = Get-VsatContextGraph -Context $Context
    $hits = @($cg.blast.paths | Where-Object { $_.crown -eq $Asset.id })
    if ($hits.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "$($hits[0].narrative)$(if ($hits.Count -gt 1) { " (+$($hits.Count - 1) more path(s))" })" -Expected $exp -Confidence inferred) }
    # No path found: only a pass when the evidence behind it is complete (same gates as OT-IT-PATH).
    if ($Asset.type -eq 'vm' -and $Context.nsxState -ne 'ASSESSED') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "No path found, but NSX policy was not assessed (NSX coverage: $($Context.nsxState)); network reachability is unknown" -Expected $exp) }
    if ($cg.blast.bounds.truncated) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'No path found, but blast-radius search bounds were hit (results partial)' -Expected $exp) }
    if (@($cg.blast.needsEvidence | Where-Object { $_ -and @($_.crowns) -contains $Asset.id }).Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'No confirmed path, but a route to this backup system needs evidence VSAT could not collect' -Expected $exp) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No entry point reaches this backup system' -Expected $exp -Confidence inferred)
}

function Invoke-VsatCheckRwColocated {
    param($Rule, $Asset, $Check, $Context)
    $skip = Get-VsatRwSkip -Rule $Rule -Asset $Asset -Context $Context
    if ($skip) { return $skip }
    $exp = 'Backup system runs in its own cluster or host, apart from the production workloads it protects'
    $pl = Get-VsatRwPlacement -Context $Context -Asset $Asset
    if (-not $pl) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'The host this VM runs on was not collected; placement is unknown' -Expected $exp) }
    $where = "$(if ($pl.unit.type -like '*cluster') { 'cluster' } else { 'host' }) $($pl.unit.name)"
    $prod = @($pl.vms | Where-Object { $_.id -ne $Asset.id -and (Test-VsatRwProduction -Context $Context -Vm $_) })
    if ($prod.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Runs in $where with $($prod.Count) production workload(s): $(Format-VsatOtNames (Get-VsatOrdinalSorted @($prod.name)))" -Expected $exp -Facts @('props')) }
    # Alone in its unit: only a pass when the VM inventory of this endpoint was fully collected.
    $cn = $script:VsatRwVmCollectors[[string]$Asset.type]
    $coll = @($Context.evidence.collection.collectors | Where-Object { $_ -and $_.name -eq $cn -and $_.endpoint -eq $Asset.endpoint })
    if (-not @($coll | Where-Object status -eq 'ok').Count -or @($coll | Where-Object status -ne 'ok').Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "No production workload found in $where, but the VM inventory ($cn) was not fully collected" -Expected $exp) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "No production workload in $where" -Expected $exp -Facts @('props'))
}

function Invoke-VsatCheckRwSharedAdmin {
    param($Rule, $Asset, $Check, $Context)
    $skip = Get-VsatRwSkip -Rule $Rule -Asset $Asset -Context $Context
    if ($skip) { return $skip }
    $exp = 'No administrator of the backup system''s hypervisor also administers production hypervisors'
    $pl = Get-VsatRwPlacement -Context $Context -Asset $Asset
    if (-not $pl) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'The host this VM runs on was not collected; its administrators are unknown' -Expected $exp) }
    $hid = $pl.host.id
    $idx = Get-VsatOtAdminIndex -Context $Context
    $G = $idx.graph
    $prodHost = @{}
    $admins = 0
    $shared = [System.Collections.Generic.List[string]]::new()
    foreach ($p in (Get-VsatOrdinalSorted $idx.reach.Keys)) {
        $set = $idx.reach[$p]
        if (-not $set.ContainsKey($hid)) { continue }
        $admins++
        $others = [System.Collections.Generic.List[string]]::new()
        foreach ($h in (Get-VsatOrdinalSorted $set.Keys)) {
            if ($h -eq $hid) { continue }
            if (-not $prodHost.ContainsKey($h)) { $prodHost[$h] = [bool]@($Context.in[$h] | Where-Object { $_ -and $_.type -eq 'runs-on' -and (Test-VsatRwProduction -Context $Context -Vm $Context.assets[$_.source]) }).Count }
            if ($prodHost[$h]) { $others.Add([string]$G.nodes[$h].name) }
        }
        if ($others.Count) { $shared.Add("$($G.nodes[$p].name) (also $($others.Count) production host(s): $(Format-VsatOtNames $others 3))") }
    }
    if ($shared.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Administrators of $($pl.host.name) also administer production hypervisors: $(Format-VsatOtNames $shared 3)" -Expected $exp -Facts @('props') -Confidence inferred) }
    # Unknown principals on the backup host or on any container above it: never a pass.
    $seen = @{}; $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($hid)
    while ($q.Count) {
        $u = $q.Dequeue(); if ($seen.ContainsKey($u)) { continue }; $seen[$u] = $true
        if ($idx.gapTargets.ContainsKey($u)) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Administrators of $($pl.host.name) cannot be fully determined: $($idx.gapTargets[$u].explanation)" -Expected $exp) }
        if ($idx.parents.ContainsKey($u)) { foreach ($x in $idx.parents[$u]) { $q.Enqueue($x) } }
    }
    if (-not $admins) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "No administrator of $($pl.host.name) was identified in the collected evidence" -Expected $exp) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "$admins administrator(s) of $($pl.host.name), none of them administers a production hypervisor" -Expected $exp -Facts @('props') -Confidence inferred)
}

function Get-VsatRansomwareAnalysis {
    # results.analysis.ransomware: one-account reach over hypervisor hosts (admin-of, directly,
    # through a group or through a management plane that controls the host), status counts of
    # the ransomware-tagged rules, and the blast-radius paths that end at a backup system.
    param([Parameter(Mandatory)]$Graph, $Blast, [Parameter(Mandatory)]$Context, [AllowEmptyCollection()][object[]]$Findings = @(), $Rules = @())
    $idx = Get-VsatHostAdminIndex -Graph $Graph
    $hostIds = Get-VsatOrdinalSorted @($Graph.nodes.Keys | Where-Object { $Graph.nodes[$_].kind -eq 'asset' -and $Graph.nodes[$_].type -in $script:VsatGraphHostTypes })
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $idx.reach.Keys) {
        $hs = Get-VsatOrdinalSorted $idx.reach[$p].Keys
        $n = $Graph.nodes[$p]
        $rows.Add([ordered]@{
                principal = [string]$n.name; id = [string]$p; type = [string]$n.type
                hypervisors = $hs.Count; total = $hostIds.Count
                platforms = [string[]]@(Get-VsatOrdinalSorted @($hs | ForEach-Object { [string]$Graph.nodes[$_].platform } | Select-Object -Unique))
                hosts = [string[]]@($hs | Select-Object -First 20 | ForEach-Object { [string]$Graph.nodes[$_].name })
            })
    }
    # Worst first: most hosts, then principal name and key (ordinal, culture-independent).
    $reach = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @($rows | ForEach-Object { $_.hypervisors } | Sort-Object -Unique -Descending)) {
        $byKey = @{}; foreach ($r in @($rows | Where-Object { $_.hypervisors -eq $c })) { $byKey["$($r.principal)`n$($r.id)"] = $r }
        foreach ($k in (Get-VsatOrdinalSorted $byKey.Keys)) { if ($reach.Count -lt 50) { $reach.Add($byKey[$k]) } }
    }
    $tagged = @(@($Rules) | Where-Object { $_ -and [bool](Get-VsatProp $_ 'ransomware' $false) } | ForEach-Object { [string]$_.id })
    $tagSet = @{}; foreach ($t in $tagged) { $tagSet[$t] = $true }
    $counts = [ordered]@{ PASS = 0; FAIL = 0; MANUAL = 0; UNKNOWN = 0; ERROR = 0; NOT_APPLICABLE = 0 }
    foreach ($f in @($Findings | Where-Object { $_ -and $tagSet.ContainsKey([string]$_.ruleId) })) { $counts[[string]$f.result] = [int]$counts[[string]$f.result] + 1 }
    $bidx = Get-VsatBackupIndex -Context $Context
    $backups = @(foreach ($id in (Get-VsatOrdinalSorted $bidx.ids.Keys)) { $a = $Context.assets[$id]; if ($a) { [ordered]@{ id = [string]$id; name = [string]$a.name; type = [string]$a.type } } })
    $paths = @(foreach ($p in @($Blast.paths | Where-Object { $_ -and $bidx.ids.ContainsKey([string]$_.crown) })) {
            [ordered]@{ pathId = $p.id; backupId = [string]$p.crown; backup = (Get-VsatGraphNodeName $Graph ([string]$p.crown)); entryId = [string]$p.entry; entry = (Get-VsatGraphNodeName $Graph ([string]$p.entry)); cost = $p.cost; hops = $p.hops; platforms = @($p.platforms); narrative = [string]$p.narrative }
        })
    $gapHosts = @($hostIds | Where-Object {
            $seen = @{}; $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($_); $hit = $false
            while ($q.Count -and -not $hit) { $u = $q.Dequeue(); if ($seen.ContainsKey($u)) { continue }; $seen[$u] = $true; if ($idx.gapTargets.ContainsKey($u)) { $hit = $true }; if ($idx.parents.ContainsKey($u)) { foreach ($x in $idx.parents[$u]) { $q.Enqueue($x) } } }
            $hit
        })
    $notes = [System.Collections.Generic.List[string]]::new()
    if ($gapHosts.Count) { $notes.Add("Administrators of $($gapHosts.Count) hypervisor host(s) could not be fully determined; their reach counts may be low") }
    if (-not $bidx.declared) { $notes.Add('No backup systems declared: declare backupSystems in the scope file to assess backup exposure') }
    elseif (-not $backups.Count) { $notes.Add('backupSystems matched no collected asset') }
    return [ordered]@{
        declared = $bidx.declared; backups = @($backups)
        oneAccountReach = @($reach); hostTotal = $hostIds.Count; unknownAdminHosts = $gapHosts.Count
        taggedRules = [ordered]@{ ruleIds = [string[]]$tagged; counts = $counts }
        backupPaths = @($paths); notes = [string[]]$notes.ToArray()
    }
}

function Get-VsatRansomwareSummary {
    # Compact copy of analysis.ransomware for the local UI results step (top principals, counts).
    param($Analysis)
    if (-not $Analysis) { return $null }
    return [ordered]@{
        declared = [bool]$Analysis.declared; backups = @($Analysis.backups).Count; backupPaths = @($Analysis.backupPaths).Count; hostTotal = $Analysis.hostTotal
        oneAccountReach = @(@($Analysis.oneAccountReach) | Select-Object -First 5 | ForEach-Object { [ordered]@{ principal = $_.principal; hypervisors = $_.hypervisors; total = $_.total; platforms = @($_.platforms) } })
        taggedRules = [ordered]@{ counts = $Analysis.taggedRules.counts }
    }
}
#endregion Ransomware readiness
