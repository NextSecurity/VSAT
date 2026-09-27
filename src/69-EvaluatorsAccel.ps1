#region AI / accelerator evaluators
# Isolation of GPUs and other passthrough devices (IOMMU, interrupt remapping, ACS, IOMMU
# groups, MIG, SR-IOV), protection of model and dataset storage, and network exposure of
# declared Kubernetes control planes. PASS and NOT_APPLICABLE need positive evidence: an
# uncollected guest inventory or host fact makes a check UNKNOWN, never a pass.

$script:VsatAiRoles = @('k8s-control-plane', 'k8s-worker', 'training', 'inference', 'dataset-store', 'model-registry')
# Roles that become blast-radius crown jewels (see the 'ai-control-plane' crown rule in 76-Graph.ps1).
$script:VsatAiCrownRoles = @('k8s-control-plane', 'model-registry', 'dataset-store')
# Share, export, mount and datastore names that hold models or training data (check.namePattern overrides it).
$script:VsatAiNamePattern = '(?i)model|dataset|ckpt|checkpoint|weights|train'
$script:VsatAiVmTypes = @('vm', 'hyperv-vm', 'kvm-vm')

function Get-VsatAccelInfo {
    # Passthrough / accelerator devices of a VM: @{ state = ok|denied|error|unsupported|no-fact; count; devices }.
    # Evidence collected before the accel fact existed is read from the device list where that list
    # is complete (vSphere devices, libvirt domain XML); Hyper-V DDA entries count only when present,
    # because GPU partitions were not collected then.
    param($Asset)
    if (-not $Asset -or -not $Asset.facts) { return @{ state = 'no-fact'; count = 0; devices = @() } }
    if ($Asset.facts.Contains('accel')) {
        $f = $Asset.facts.accel
        if ($f.status -eq 'absent') { return @{ state = 'ok'; count = 0; devices = @() } }
        if ($f.status -ne 'ok') { return @{ state = [string]$f.status; count = 0; devices = @(); error = (Get-VsatProp $f 'error') } }
        return @{ state = 'ok'; count = [int](Get-VsatProp $f.value 'count' 0); devices = @(Get-VsatProp $f.value 'devices' @()) }
    }
    switch ($Asset.type) {
        'vm' {
            $r = Resolve-VsatFactValue -Asset $Asset -Fact 'devices'
            if ($r.state -eq 'ok') {
                $d = @(@($r.value) | Where-Object { $_ -and $_.type -in @('VirtualPCIPassthrough', 'VirtualSriovEthernetCard') } | ForEach-Object { @{ kind = $(if ($_.type -eq 'VirtualSriovEthernetCard') { 'sriov-nic' } else { 'passthrough' }) } })
                return @{ state = 'ok'; count = $d.Count; devices = $d; derived = $true }
            }
        }
        'kvm-vm' {
            $r = Resolve-VsatFactValue -Asset $Asset -Fact 'domain'
            if ($r.state -eq 'ok') {
                $d = @(@(Get-VsatProp $r.value 'hostdevs' @()) | Where-Object { $_ -and $_.type -in @('pci', 'mdev') } | ForEach-Object { @{ kind = $(if ($_.type -eq 'mdev') { 'mdev' } else { 'hostdev-pci' }) } })
                $d += @(@(Get-VsatProp $r.value 'interfaces' @()) | Where-Object { $_ -and $_.type -eq 'hostdev' } | ForEach-Object { @{ kind = 'sriov-vf' } })
                return @{ state = 'ok'; count = $d.Count; devices = $d; derived = $true }
            }
        }
        'hyperv-vm' {
            $r = Resolve-VsatFactValue -Asset $Asset -Fact 'devices'
            $d = @(@($r.value) | Where-Object { $_ -and $_.type -eq 'dda' } | ForEach-Object { @{ kind = 'dda' } })
            if ($r.state -eq 'ok' -and $d.Count) { return @{ state = 'ok'; count = $d.Count; devices = $d; derived = $true } }
        }
    }
    return @{ state = 'no-fact'; count = 0; devices = @() }
}

function Test-VsatAiWorkload {
    # A declared/tagged AI workload, or a VM with at least one accelerator or passthrough device.
    param($Asset)
    if (-not $Asset) { return $false }
    if ($Asset.aiRole) { return $true }
    return ($Asset.type -in $script:VsatAiVmTypes -and (Get-VsatAccelInfo $Asset).count -gt 0)
}

function Get-VsatHostGuests {
    param($Context, $HostAsset)
    return @($Context.in[$HostAsset.id] | Where-Object { $_ -and $_.type -eq 'runs-on' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ -and $_.type -in $script:VsatAiVmTypes } | Sort-Object { $_.id } -Unique)
}

function Get-VsatAiHostState {
    # 'ai' when the host or a guest is an AI workload, 'none' with positive evidence that no guest
    # is, otherwise 'unknown' (guest accelerator inventory incomplete).
    param($Context, $HostAsset)
    $vms = @(Get-VsatHostGuests $Context $HostAsset)
    $ai = @($vms | Where-Object { Test-VsatAiWorkload $_ })
    if ($HostAsset.aiRole -or $ai.Count) { return @{ state = 'ai'; workloads = $ai } }
    $gaps = @($vms | Where-Object { (Get-VsatAccelInfo $_).state -ne 'ok' })
    if ($gaps.Count) { return @{ state = 'unknown'; workloads = @(); reason = "accelerator inventory incomplete for $($gaps.Count) guest(s)" } }
    return @{ state = 'none'; workloads = @() }
}

function Get-VsatAiPattern {
    param($Check)
    $p = [string](Get-VsatProp $Check 'namePattern' '')
    if ($p) { return $p }
    return $script:VsatAiNamePattern
}

function New-VsatGapFinding {
    # UNKNOWN/ERROR finding for a fact that is not ok/absent.
    param($Rule, $Asset, $Resolved, [string]$Fact, [string]$Expected)
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $Resolved.state) -Observed (Get-VsatGapText $Resolved $Fact) -Expected $Expected -Facts @($Fact))
}

function Invoke-VsatCheckAccelIommu {
    # AI-IOMMU-OFF (IOMMU on) and AI-IOMMU-IR (check.requireIR: interrupt remapping) on KVM hosts.
    param($Rule, $Asset, $Check, $Context)
    $ir = [bool](Get-VsatProp $Check 'requireIR' $false)
    $exp = if ($ir) { 'Interrupt remapping enabled on hosts that pass devices through' } else { 'IOMMU (VT-d / AMD-Vi) enabled on hosts that pass devices through' }
    $vms = @(Get-VsatHostGuests $Context $Asset)
    $info = @($vms | ForEach-Object { Get-VsatAccelInfo $_ })
    $used = @($info | Where-Object { $_.count -gt 0 }).Count
    if (-not $used) {
        $gap = @($info | Where-Object { $_.state -ne 'ok' }).Count
        if ($gap) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Passthrough inventory incomplete for $gap of $($vms.Count) guest(s)" -Expected $exp -Facts @('accel')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "No guest uses PCI passthrough, mediated devices or SR-IOV VFs ($($vms.Count) guest(s) checked)" -Expected $exp)
    }
    $c = Resolve-VsatFactValue -Asset $Asset -Fact 'cmdline'
    $g = Resolve-VsatFactValue -Asset $Asset -Fact 'iommu'
    if ($ir) {
        if ($g.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $g 'iommu' $exp) }
        $v = Get-VsatProp $g.value 'interruptRemapping'
        if ($null -eq $v) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Interrupt remapping capability not readable (no Intel VT-d capability register exposed)' -Expected $exp -Facts @('iommu')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ([bool]$v) { 'PASS' } else { 'FAIL' }) -Observed "interrupt remapping $(if ([bool]$v) { 'supported and not disabled' } else { 'unavailable or disabled (intremap=off)' }); $used guest(s) with passthrough devices" -Expected $exp -Facts @('iommu', 'cmdline'))
    }
    if ($g.state -eq 'ok') {
        $n = @(Get-VsatProp $g.value 'groups' @()).Count
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($n) { 'PASS' } else { 'FAIL' }) -Observed "$n IOMMU group(s)$(if ($c.state -eq 'ok') { "; kernel iommu=$(if ($c.value.iommu) { $c.value.iommu } else { 'default' })" }); $used guest(s) with passthrough devices" -Expected $exp -Facts @('iommu', 'cmdline'))
    }
    if ($c.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $g 'iommu' $exp) }
    switch ([string]$c.value.iommu) {
        'off' { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Kernel command line disables the IOMMU; $used guest(s) with passthrough devices" -Expected $exp -Facts @('cmdline')) }
        { $_ -in @('on', 'pt') } { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "Kernel command line enables the IOMMU (iommu=$($c.value.iommu)); IOMMU groups not readable" -Expected $exp -Facts @('cmdline') -Confidence inferred) }
    }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "IOMMU groups not readable and the kernel command line uses the distribution default ($(Get-VsatGapText $g 'iommu'))" -Expected $exp -Facts @('cmdline', 'iommu'))
}

function Invoke-VsatCheckAccelAcsOverride {
    param($Rule, $Asset, $Check, $Context)
    $exp = 'No pcie_acs_override on the kernel command line'
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'cmdline'
    if ($r.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $r 'cmdline' $exp) }
    $bad = [bool]$r.value.acsOverride
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad) { (@([string]$r.value.raw -split '\s+' | Where-Object { $_ -like 'pcie_acs_override*' }) -join ' ') } else { 'pcie_acs_override not set' }) -Expected $exp -Facts @('cmdline'))
}

function Invoke-VsatCheckAccelIommuGroup {
    # A guest's PCI device must not share its IOMMU group with a device the guest does not own
    # (other functions of the same slot count as its own).
    param($Rule, $Asset, $Check, $Context)
    $exp = 'Each passed-through device alone in its IOMMU group (apart from other functions of the same slot)'
    $a = Get-VsatAccelInfo $Asset
    if ($a.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $a.state) -Observed "Guest passthrough devices not collected ($($a.state))" -Expected $exp -Facts @('accel')) }
    $pci = @($a.devices | Where-Object { $_.kind -in @('hostdev-pci', 'sriov-vf') })
    if (-not $pci.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No PCI device passed through to this guest' -Expected $exp -Facts @('accel')) }
    $mine = @($pci | Where-Object { $_.bdf } | ForEach-Object { ([string]$_.bdf).ToLowerInvariant() })
    if ($mine.Count -lt $pci.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'A passed-through PCI device has no source address in the domain XML' -Expected $exp -Facts @('accel')) }
    $h = @($Context.out[$Asset.id] | Where-Object { $_ -and $_.type -eq 'runs-on' } | ForEach-Object { $Context.assets[$_.target] } | Where-Object { $_ })[0]
    $g = if ($h) { Resolve-VsatFactValue -Asset $h -Fact 'iommu' } else { @{ state = 'no-fact'; value = $null } }
    if ($g.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $g.state) -Observed "Host IOMMU groups: $(Get-VsatGapText $g 'iommu')" -Expected $exp -Facts @('accel')) }
    $slots = @($mine | ForEach-Object { $_ -replace '\.[0-7]$', '' })
    $viol = [System.Collections.Generic.List[string]]::new()
    $found = 0
    foreach ($grp in @(Get-VsatProp $g.value 'groups' @())) {
        $devs = @($grp.devices | ForEach-Object { ([string]$_).ToLowerInvariant() })
        if (-not @($devs | Where-Object { $mine -contains $_ }).Count) { continue }
        $found++
        $others = @($devs | Where-Object { $mine -notcontains $_ -and ($_ -replace '\.[0-7]$', '') -notin $slots })
        if ($others.Count) { $viol.Add("IOMMU group $($grp.id) also contains $($others -join ', ')") }
    }
    if ($viol.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "$($mine -join ', '): $($viol -join '; ')" -Expected $exp -Facts @('accel')) }
    if (-not $found) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "$($mine -join ', ') not found in any host IOMMU group" -Expected $exp -Facts @('accel')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "Isolated IOMMU group(s) for $($mine -join ', ')" -Expected $exp -Facts @('accel'))
}

function Invoke-VsatCheckAccelMigIsolation {
    # A GPU shared by several guests through mediated devices needs MIG (hardware partitioning);
    # time-sliced vGPU gives no memory or fault isolation between tenants.
    param($Rule, $Asset, $Check, $Context)
    $exp = 'A GPU shared by several guests runs in MIG mode (or each GPU serves one guest)'
    $vms = @(Get-VsatHostGuests $Context $Asset)
    $byUuid = @{}
    $gap = 0
    foreach ($v in $vms) {
        $i = Get-VsatAccelInfo $v
        if ($i.state -ne 'ok') { $gap++; continue }
        foreach ($d in @($i.devices | Where-Object { $_.kind -eq 'mdev' })) {
            $u = [string](Get-VsatProp $d 'mdevUuid' '')
            if (-not $byUuid.ContainsKey($u)) { $byUuid[$u] = [System.Collections.Generic.List[string]]::new() }
            if (-not $byUuid[$u].Contains($v.name)) { $byUuid[$u].Add([string]$v.name) }
        }
    }
    if (-not $byUuid.Count) {
        if ($gap) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Guest device inventory incomplete for $gap guest(s)" -Expected $exp -Facts @('accel')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "No guest uses a mediated (shared) GPU device ($($vms.Count) guest(s) checked)" -Expected $exp)
    }
    $md = Resolve-VsatFactValue -Asset $Asset -Fact 'mdev'
    if ($md.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $md 'mdev' $exp) }
    $parentOf = @{}; $typeOf = @{}
    foreach ($m in @($md.value)) { $parentOf[[string]$m.uuid] = [string]$m.parent; $typeOf[[string]$m.parent] = [string]$m.type }
    $tenants = @{}
    foreach ($u in $byUuid.Keys) {
        $p = if ($parentOf.ContainsKey($u)) { $parentOf[$u] } else { '(unknown parent)' }
        if (-not $tenants.ContainsKey($p)) { $tenants[$p] = [System.Collections.Generic.List[string]]::new() }
        foreach ($n in $byUuid[$u]) { if (-not $tenants[$p].Contains($n)) { $tenants[$p].Add($n) } }
    }
    $mig = Resolve-VsatFactValue -Asset $Asset -Fact 'gpuMig'
    $gpus = @{}; if ($mig.state -eq 'ok') { foreach ($x in @($mig.value)) { $gpus[[string]$x.index] = $x } }
    $fail = [System.Collections.Generic.List[string]]::new(); $unk = [System.Collections.Generic.List[string]]::new(); $ok = [System.Collections.Generic.List[string]]::new()
    foreach ($p in (Get-VsatOrdinalSorted $tenants.Keys)) {
        $names = @($tenants[$p])
        if ($names.Count -lt 2) { $ok.Add("$p serves one guest"); continue }
        $who = "$p shared by $($names -join ', ')"
        if ($gpus.ContainsKey($p)) {
            if ([string]$gpus[$p].migMode -eq 'Enabled') { $ok.Add("$p in MIG mode") } else { $fail.Add("$who; MIG $($gpus[$p].migMode)") }
        }
        elseif ($p -ne '(unknown parent)' -and $mig.state -in @('ok', 'absent') -and $typeOf[$p] -notlike 'nvidia-*') { $fail.Add("$who; $($typeOf[$p]) is time-sliced (no MIG)") }
        else { $unk.Add("$who; MIG mode not readable ($(if ($mig.state -eq 'ok') { 'GPU not listed by nvidia-smi' } else { "nvidia-smi: $($mig.state)" }))") }
    }
    if ($fail.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed ($fail -join '; ') -Expected $exp -Facts @('mdev', 'gpuMig')) }
    if ($unk.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed ($unk -join '; ') -Expected $exp -Facts @('mdev', 'gpuMig')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed ($ok -join '; ') -Expected $exp -Facts @('mdev', 'gpuMig'))
}

function Invoke-VsatCheckAccelSriov {
    # SR-IOV virtual functions bypass the virtual switch; they must not share a physical port with
    # host management (ESXi management vmknic uplink; Hyper-V switch shared with the management OS).
    param($Rule, $Asset, $Check, $Context)
    $exp = 'SR-IOV virtual functions not enabled on a NIC or switch that carries host management'
    if ($Asset.type -eq 'hyperv-host') {
        $r = Resolve-VsatFactValue -Asset $Asset -Fact 'sriov'
        $fact = 'sriov'
        if ($r.state -eq 'no-fact') {
            # Earlier collectors recorded IovEnabled / AllowManagementOS on the switch assets.
            $sw = @($Context.out[$Asset.id] | Where-Object { $_ -and $_.type -eq 'contains' } | ForEach-Object { $Context.assets[$_.target] } | Where-Object { $_ -and $_.type -eq 'hyperv-vswitch' })
            if (-not $sw.Count) { return (New-VsatGapFinding $Rule $Asset $r 'sriov' $exp) }
            $list = @($sw | ForEach-Object { @{ switch = [string]$_.name; iovEnabled = [bool](Get-VsatProp $_ 'props.iov' $false); allowManagementOS = [bool](Get-VsatProp $_ 'props.allowManagementOS' $false) } })
            $fact = 'props'
        }
        elseif ($r.state -eq 'absent') { $list = @() }
        elseif ($r.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $r 'sriov' $exp) }
        else { $list = @($r.value | Where-Object { $_ }) }
        $iov = @($list | Where-Object { [bool]$_.iovEnabled })
        if (-not $iov.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "No virtual switch has SR-IOV enabled ($($list.Count) switch(es))" -Expected $exp -Facts @($fact)) }
        $bad = @($iov | Where-Object { [bool]$_.allowManagementOS } | ForEach-Object { [string]$_.switch })
        if ($bad.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "SR-IOV switch shared with the management OS: $($bad -join ', ')" -Expected $exp -Facts @($fact)) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "SR-IOV switch(es) not shared with the management OS: $(@($iov | ForEach-Object { [string]$_.switch }) -join ', ')" -Expected $exp -Facts @($fact))
    }
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'pciPassthru'
    if ($r.state -notin @('ok', 'absent')) { return (New-VsatGapFinding $Rule $Asset $r 'pciPassthru' $exp) }
    $sr = @(@($r.value) | Where-Object { $_ -and [bool]$_.sriovEnabled -and [int](Get-VsatProp $_ 'numVirtualFunction' 0) -gt 0 })
    if (-not $sr.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No SR-IOV virtual functions enabled on this host' -Expected $exp -Facts @('pciPassthru')) }
    $pnics = @($Context.out[$Asset.id] | Where-Object { $_ -and $_.type -eq 'contains' } | ForEach-Object { $Context.assets[$_.target] } | Where-Object { $_ -and $_.type -eq 'pnic' })
    $byPci = @{}; foreach ($p in $pnics) { $pci = [string](Get-VsatProp $p 'props.pci' ''); if ($pci) { $byPci[$pci.ToLowerInvariant()] = $p } }
    if ($pnics.Count -and -not $byPci.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Physical NIC PCI addresses not collected (evidence from an earlier VSAT version)' -Expected $exp -Facts @('pciPassthru')) }
    $srNics = @($sr | ForEach-Object { $n = $byPci[([string]$_.id).ToLowerInvariant()]; if ($n) { @{ nic = [string]$n.props.device; id = $n.id; vfs = [int]$_.numVirtualFunction } } })
    $desc = @($sr | ForEach-Object { "$($_.id) ($([int]$_.numVirtualFunction) VFs)" }) -join ', '
    if (-not $srNics.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "SR-IOV enabled on $desc, which is not a host uplink NIC" -Expected $exp -Facts @('pciPassthru')) }
    $vmk = Resolve-VsatFactValue -Asset $Asset -Fact 'vmkernel'
    if ($vmk.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $vmk 'vmkernel' $exp) }
    $mgmtNics = @{}; $onVds = @()
    foreach ($m in @(@($vmk.value) | Where-Object { $_ -and @($_.services) -contains 'management' })) {
        if ($m.dvPortgroup) { $onVds += [string]$m.device; continue }
        $pg = $Context.assets["$($Asset.id)/pg/$($m.portgroup)"]
        $vs = if ($pg) { $Context.assets["$($Asset.id)/vss/$(Get-VsatProp $pg 'props.vswitch' '')"] } else { $null }
        foreach ($u in @(Get-VsatProp $vs 'props.uplinks' @())) { $mgmtNics[[string]$u] = [string]$m.device }
    }
    $hit = @($srNics | Where-Object { $mgmtNics.ContainsKey($_.id) } | ForEach-Object { "$($_.nic) ($($_.vfs) VFs) carries management $($mgmtNics[$_.id])" })
    if ($hit.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "SR-IOV on a management uplink: $($hit -join '; ')" -Expected $exp -Facts @('pciPassthru', 'vmkernel')) }
    if ($onVds.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "SR-IOV on $(@($srNics | ForEach-Object { $_.nic }) -join ', '); management $($onVds -join ', ') runs on a distributed switch whose per-host uplinks are not collected" -Expected $exp -Facts @('pciPassthru', 'vmkernel')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "SR-IOV on $(@($srNics | ForEach-Object { $_.nic }) -join ', '); management uses $(@($mgmtNics.Keys | ForEach-Object { $Context.assets[$_].props.device } | Sort-Object -Unique) -join ', ')" -Expected $exp -Facts @('pciPassthru', 'vmkernel'))
}

function Invoke-VsatCheckAccelShare {
    # Model / dataset shares on AI hosts: NFS exports (check.kind = exports, KVM) or SMB shares
    # (check.kind = smb, Hyper-V). Relevant shares: all of them on a host that runs an AI workload,
    # otherwise those whose name or path matches the model/dataset pattern.
    param($Rule, $Asset, $Check, $Context)
    $pat = Get-VsatAiPattern $Check
    $smb = ([string]$Check.kind -eq 'smb')
    $fact = if ($smb) { 'smbShares' } else { 'exports' }
    $exp = if ($smb) { 'Model/dataset SMB shares grant no Full/Change to Everyone or Authenticated Users and encrypt data in transit' } else { 'Model/dataset NFS exports are not read-write to everyone and never no_root_squash for wildcard, subnet or netgroup clients' }
    $r = Resolve-VsatFactValue -Asset $Asset -Fact $fact
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed $(if ($smb) { 'No non-administrative SMB shares' } else { 'No NFS exports' }) -Expected $exp -Facts @($fact)) }
    if ($r.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $r $fact $exp) }
    $items = @(@($r.value) | Where-Object { $_ })
    $hs = Get-VsatAiHostState $Context $Asset
    $rel = if ($hs.state -eq 'ai') { $items } else { @($items | Where-Object { "$($_.path) $(Get-VsatProp $_ 'name' '')" -match $pat }) }
    if (-not $rel.Count) {
        if ($hs.state -eq 'unknown') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "No share is named like model/dataset storage, but the $($hs.reason)" -Expected $exp -Facts @($fact, 'accel')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "No AI workload on this host and no share named like model/dataset storage ($($items.Count) share(s))" -Expected $exp -Facts @($fact))
    }
    $issues = [System.Collections.Generic.List[string]]::new()
    $unk = [System.Collections.Generic.List[string]]::new()
    if ($smb) {
        $srv = Resolve-VsatFactValue -Asset $Asset -Fact 'smb'
        $srvEnc = if ($srv.state -eq 'ok') { [bool](Get-VsatProp $srv.value 'encryptData' $false) } else { $null }
        foreach ($s in $rel) {
            foreach ($ac in @(Get-VsatProp $s 'access' @())) {
                if ([string](Get-VsatProp $ac 'type' 'Allow') -ne 'Allow') { continue }
                if ([string]$ac.account -match '^(Everyone|(NT AUTHORITY\\)?Authenticated Users|(BUILTIN\\)?Users)$' -and [string]$ac.right -in @('Full', 'Change')) { $issues.Add("share '$($s.name)': $($ac.account) has $($ac.right)") }
            }
            if ("$($s.name) $($s.path)" -match $pat -and -not [bool]$s.encryptData) {
                if ($srvEnc -eq $true) { continue }
                if ($null -eq $srvEnc) { $unk.Add("share '$($s.name)' is not encrypted and the server-wide SMB encryption setting was not collected") }
                else { $issues.Add("share '$($s.name)' is not encrypted in transit (EncryptData off)") }
            }
        }
    }
    else {
        foreach ($e in $rel) {
            foreach ($c in @(Get-VsatProp $e 'clients' @())) {
                $opts = @(([string]$c.options) -split ',' | ForEach-Object { $_.Trim() })
                $world = [string]$c.host -in @('*', '0.0.0.0/0', '0.0.0.0/0.0.0.0', '::/0')
                $single = -not $world -and [string]$c.host -notmatch '[*?/@\[]'
                if ($world -and $opts -contains 'rw') { $issues.Add("$($e.path) is exported read-write to $($c.host)") }
                if ($opts -contains 'no_root_squash' -and -not $single) { $issues.Add("$($e.path) exports no_root_squash to $($c.host)") }
            }
        }
    }
    if ($issues.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed ($issues -join '; ') -Expected $exp -Facts @($fact)) }
    if ($unk.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed ($unk -join '; ') -Expected $exp -Facts @($fact, 'smb')) }
    if ($hs.state -eq 'unknown') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Model/dataset-named shares are restricted, but the $($hs.reason), so other shares may serve AI workloads" -Expected $exp -Facts @($fact, 'accel')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "$($rel.Count) relevant share(s) restricted: $(@($rel | ForEach-Object { if ($smb) { $_.name } else { $_.path } }) -join ', ')" -Expected $exp -Facts @($fact))
}

function Invoke-VsatCheckAccelNfsSec {
    # Model/dataset storage traffic protected in transit: NFS datastores behind AI VMs (Kerberos
    # integrity or privacy), and network mounts on KVM hosts that run AI guests (NFS sec=krb5p,
    # SMB seal, no plain-HTTP object storage endpoint).
    param($Rule, $Asset, $Check, $Context)
    $pat = Get-VsatAiPattern $Check
    if ($Asset.type -eq 'datastore') {
        $exp = 'NFS datastores that hold AI workloads use Kerberos with integrity or privacy (SEC_KRB5I / SEC_KRB5P)'
        if ([string](Get-VsatProp $Asset 'props.type' '') -notmatch '^NFS') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "Not an NFS datastore ($(Get-VsatProp $Asset 'props.type' 'unknown type'))" -Expected $exp) }
        $vms = @($Context.in[$Asset.id] | Where-Object { $_ -and $_.type -eq 'stores' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { $_ } | Sort-Object { $_.id } -Unique)
        $ai = @($vms | Where-Object { Test-VsatAiWorkload $_ })
        if (-not $ai.Count -and $Asset.name -notmatch $pat) {
            $gaps = @($vms | Where-Object { (Get-VsatAccelInfo $_).state -ne 'ok' })
            if ($gaps.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Accelerator inventory incomplete for $($gaps.Count) VM(s) stored here" -Expected $exp -Facts @('nas')) }
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "No AI workload stored on this datastore ($($vms.Count) VM(s))" -Expected $exp)
        }
        $n = Resolve-VsatFactValue -Asset $Asset -Fact 'nas'
        if ($n.state -ne 'ok') { return (New-VsatGapFinding $Rule $Asset $n 'nas' $exp) }
        $sec = [string](Get-VsatProp $n.value 'securityType' '')
        $who = if ($ai.Count) { "stores $(Format-VsatOtNames @($ai.name) 3)" } else { 'named like model/dataset storage' }
        if ($sec -in @('SEC_KRB5I', 'SEC_KRB5P')) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "securityType=$sec; $who" -Expected $exp -Facts @('nas')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "securityType=$(if ($sec) { $sec } else { 'AUTH_SYS (NFS 3 default)' }): no integrity or encryption in transit; $who" -Expected $exp -Facts @('nas'))
    }
    $exp = 'Network mounts of model/dataset storage are encrypted in transit (NFS sec=krb5p, SMB seal, HTTPS object storage)'
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'mounts'
    if ($r.state -notin @('ok', 'absent')) { return (New-VsatGapFinding $Rule $Asset $r 'mounts' $exp) }
    $mounts = @(@($r.value) | Where-Object { $_ })
    $hs = Get-VsatAiHostState $Context $Asset
    $rel = if ($hs.state -eq 'ai') { $mounts } else { @($mounts | Where-Object { "$($_.source) $($_.target)" -match $pat }) }
    if (-not $rel.Count) {
        if ($hs.state -eq 'unknown' -and $mounts.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Network mounts present, but the $($hs.reason)" -Expected $exp -Facts @('mounts', 'accel')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed $(if ($mounts.Count) { "No AI workload on this host and no mount named like model/dataset storage ($($mounts.Count) network mount(s))" } else { 'No network file system or object storage mounts' }) -Expected $exp -Facts @('mounts'))
    }
    $issues = [System.Collections.Generic.List[string]]::new()
    foreach ($m in $rel) {
        $o = @(([string]$m.options) -split ',')
        $what = "$($m.source) on $($m.target)"
        switch -Regex ([string]$m.fstype) {
            '^nfs' { $sec = @($o | Where-Object { $_ -like 'sec=*' } | ForEach-Object { $_.Substring(4) })[0]; if ($sec -ne 'krb5p') { $issues.Add("${what}: NFS sec=$(if ($sec) { $sec } else { 'sys' }) (not encrypted)") } }
            '^(cifs|smb3)$' { if ($o -notcontains 'seal') { $issues.Add("${what}: SMB without seal (not encrypted)") } }
            '^fuse\.' { if ([string]$m.options -match '(^|,)(url|endpoint|endpoint-url)=http://') { $issues.Add("${what}: object storage endpoint over plain HTTP") } }
        }
    }
    if ($issues.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed ($issues -join '; ') -Expected $exp -Facts @('mounts')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "$($rel.Count) relevant mount(s) encrypted in transit or not assessable as plaintext: $(@($rel | ForEach-Object { $_.target }) -join ', ')" -Expected $exp -Facts @('mounts'))
}

function Invoke-VsatCheckAccelK8sExposure {
    # A declared or tagged Kubernetes control plane is a crown jewel; FAIL when a blast-radius path
    # from a modeled entry point reaches it over a network-allow hop (API 6443, etcd 2379, kubelet 10250).
    param($Rule, $Asset, $Check, $Context)
    $exp = 'Control plane reachable only from admin and worker networks (no network path from modeled entry points)'
    if ($Asset.aiRole -ne 'k8s-control-plane') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Not a declared or tagged Kubernetes control plane' -Expected '') }
    $cg = Get-VsatContextGraph -Context $Context
    $hits = @($cg.blast.paths | Where-Object { [string]$_.crown -eq $Asset.id -and @(@($_.edgeIds) | ForEach-Object { $cg.graph.edges[$_].kind }) -contains 'network-allow' })
    if ($hits.Count) {
        $from = @($hits | ForEach-Object { Get-VsatGraphNodeName $cg.graph ([string]$_.entry) } | Select-Object -Unique)
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Reachable over the network from $(Format-VsatOtNames $from 3): $($hits[0].narrative)" -Expected $exp -Facts @('props') -Confidence inferred)
    }
    if ($Asset.type -eq 'vm' -and $Context.nsxState -ne 'ASSESSED') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "No network path found, but NSX policy was not assessed (NSX coverage: $($Context.nsxState))" -Expected $exp) }
    if ($cg.blast.bounds.truncated) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'No network path found, but blast-radius search bounds were hit (results partial)' -Expected $exp) }
    if (@($cg.blast.needsEvidence | Where-Object { $_ -and [string](Get-VsatProp $_ 'gap.kind' '') -eq 'network-allow' -and @($_.crowns) -contains $Asset.id }).Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'No confirmed network path, but a network route to this control plane needs evidence VSAT could not collect' -Expected $exp) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No network path from modeled entry points' -Expected $exp -Facts @('props') -Confidence inferred)
}

function Set-VsatAiAffectedWorkloads {
    # finding.affectedWorkloads = AI workload VMs an ai-infra finding puts at risk: guests of a host,
    # AI VMs stored on a datastore, the VM itself for VM findings.
    param([AllowEmptyCollection()][object[]]$Findings, $Context)
    foreach ($f in @($Findings | Where-Object { $_ -and $_.domain -eq 'ai-infra' })) {
        $a = $Context.assets[$f.assetId]
        if (-not $a) { continue }
        $ids = if ($a.type -in $script:VsatGraphHostTypes) { @(Get-VsatHostGuests $Context $a | Where-Object { Test-VsatAiWorkload $_ } | ForEach-Object { $_.id }) }
        elseif ($a.type -eq 'datastore') { @($Context.in[$a.id] | Where-Object { $_ -and $_.type -eq 'stores' } | ForEach-Object { $Context.assets[$_.source] } | Where-Object { Test-VsatAiWorkload $_ } | ForEach-Object { $_.id } | Select-Object -Unique) }
        else { @($a.id) }
        $f.affectedWorkloads = [string[]](Get-VsatOrdinalSorted @($ids))
    }
}

function Get-VsatAiWorkloads {
    # analysis.aiWorkloads: every declared/tagged AI workload and every VM with accelerators, with
    # its open findings (on the VM, or on infrastructure that affects it) and blast-radius paths.
    param([AllowEmptyCollection()][object[]]$Findings, $Context, $Blast)
    $byWl = @{}
    foreach ($f in @($Findings | Where-Object { $_ -and $_.result -in @('FAIL', 'UNKNOWN', 'ERROR') })) {
        $ids = @($f.assetId) + @(Get-VsatProp $f 'affectedWorkloads' @())
        foreach ($id in ($ids | Select-Object -Unique)) { if (-not $byWl.ContainsKey($id)) { $byWl[$id] = [System.Collections.Generic.List[string]]::new() }; $byWl[$id].Add([string]$f.id) }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($Context.evidence.assets | Where-Object { $_.type -in $script:VsatAiVmTypes -or $_.aiRole } | Sort-Object { [string]$_.id })) {
        $i = Get-VsatAccelInfo $a
        if (-not $a.aiRole -and $i.count -le 0) { continue }
        $paths = @(@($Blast.paths) | Where-Object { $_ -and ([string]$_.crown -eq $a.id -or [string]$_.entry -eq $a.id) } | ForEach-Object { [string]$_.id })
        $out.Add([ordered]@{
                assetId = $a.id; name = $a.name; type = $a.type; role = $(if ($a.aiRole) { [string]$a.aiRole } else { $null }); roleSource = $(if ($a.aiRole) { [string]$a.aiRoleSource } else { $null })
                platform = (Get-VsatAssetPlatform $a.type); accelerators = $(if ($i.state -eq 'ok') { $i.count } else { $null }); acceleratorKinds = @($i.devices | ForEach-Object { [string]$_.kind } | Select-Object -Unique)
                findings = @($(if ($byWl.ContainsKey($a.id)) { $byWl[$a.id] })); blastPaths = $paths
            })
    }
    return @($out)
}

function Get-VsatAiInfraCoverage {
    # ai-infra domain state. NOT_APPLICABLE only with positive evidence: every VM accelerator fact and
    # every host passthrough / GPU-partition fact collected with zero devices, no AI workload declared,
    # and no failing ai-infra check. Gaps with no accelerator in sight are UNKNOWN; once accelerators
    # are found the domain applies and gaps make it PARTIAL.
    param([Parameter(Mandatory)]$Evidence, $Checks)
    $devices = 0; $gpuHosts = 0; $checked = 0
    $gaps = [System.Collections.Generic.List[string]]::new()
    $notCollected = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $Evidence.assets) {
        if ($a.type -in $script:VsatAiVmTypes) {
            if ([bool](Get-VsatProp $a 'props.template' $false)) { continue }
            $i = Get-VsatAccelInfo $a
            $checked++
            if ($i.state -eq 'ok') { $devices += $i.count }
            elseif ($i.state -eq 'no-fact') { $notCollected.Add($a.name) }
            else { $gaps.Add("$($a.name): accelerator inventory $($i.state)") }
            continue
        }
        $fact = switch ($a.type) { 'host' { 'pciPassthru' } 'hyperv-host' { 'gpuPartition' } default { $null } }
        if (-not $fact) { continue }
        $checked++
        $r = Resolve-VsatFactValue -Asset $a -Fact $fact
        switch ($r.state) {
            'ok' {
                $n = if ($fact -eq 'pciPassthru') { @(@($r.value) | Where-Object { $_ -and ($_.passthruEnabled -or $_.passthruActive -or $_.sriovEnabled) }).Count } else { @(@($r.value) | Where-Object { $_ }).Count }
                if ($n) { $gpuHosts++ }
            }
            'absent' { }
            'no-fact' { $notCollected.Add($a.name) }
            default { $gaps.Add("$($a.name): $fact $($r.state)") }
        }
    }
    $declared = @($Evidence.assets | Where-Object { $_.aiRole }).Count
    $scopeN = @(@(Get-VsatProp $Evidence.scope 'aiWorkloads' @()) | Where-Object { $_ }).Count
    $fails = [int](Get-VsatProp $Checks 'FAIL' 0)
    $gapN = [int](Get-VsatProp $Checks 'UNKNOWN' 0) + [int](Get-VsatProp $Checks 'ERROR' 0)
    $applies = ($devices -gt 0 -or $gpuHosts -gt 0 -or $declared -gt 0 -or $scopeN -gt 0 -or $fails -gt 0)
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($g in @($gaps | Select-Object -First 5)) { $missing.Add($g) }
    if ($gaps.Count -gt 5) { $missing.Add("... and $($gaps.Count - 5) more") }
    if ($notCollected.Count) { $missing.Add("Accelerator inventory not collected for $($notCollected.Count) asset(s) (evidence from an earlier VSAT version or collector); re-collect to assess: $(Format-VsatOtNames @($notCollected) 3)") }
    $summary = "$devices accelerator/passthrough device(s) on VMs, $gpuHosts host(s) with passthrough, SR-IOV or GPU partitioning, $declared declared or tagged AI workload(s); $checked asset(s) checked."
    if (-not $applies) {
        if ($gaps.Count -or $notCollected.Count) {
            return [ordered]@{ state = 'UNKNOWN'; label = 'UNKNOWN: ACCELERATOR INVENTORY INCOMPLETE'; detail = "Whether AI/GPU checks apply cannot be decided: $summary"; evidence = @(); missing = @($missing) }
        }
        return [ordered]@{ state = 'NOT_APPLICABLE'; label = 'NOT APPLICABLE: NO ACCELERATORS OR AI WORKLOADS'; detail = "$summary This is not an AI infrastructure pass."; evidence = @('No accelerators, passthrough devices or declared AI workloads observed'); missing = @() }
    }
    if ($gapN) { $missing.Add("$gapN check(s) lack evidence (UNKNOWN/ERROR)") }
    $state = if ($missing.Count) { 'PARTIAL' } else { 'ASSESSED' }
    return [ordered]@{ state = $state; label = $(if ($state -eq 'PARTIAL') { 'PARTIAL: AI / GPU INFRASTRUCTURE' } else { 'AI / GPU INFRASTRUCTURE ASSESSED' }); detail = $summary; evidence = @($summary); missing = @($missing) }
}
#endregion AI / accelerator evaluators
