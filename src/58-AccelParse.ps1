#region Accelerator parsers
# Pure functions (no I/O) that turn read-only collector output into the accelerator and
# AI-storage facts: kernel command line, IOMMU groups, nvidia-smi XML, NFS exports, network
# mounts, mediated devices, and the vSphere passthrough / Hyper-V / libvirt device lists.

function ConvertFrom-VsatKernelCmdline {
    # /proc/cmdline -> iommu 'on'|'pt'|'off'|$null, ACS override and interrupt remapping opt-out.
    param([string]$Text)
    $raw = ([string]$Text).Trim()
    $io = $null
    foreach ($t in ($raw -split '\s+')) {
        if ($t -match '^(intel|amd)_iommu=(on|off)\b') { if ($io -ne 'pt') { $io = $Matches[2] } }
        if ($t -eq 'iommu=pt') { $io = 'pt' }
        if ($t -eq 'iommu=off') { $io = 'off' }
    }
    return [ordered]@{ raw = $raw; iommu = $io; acsOverride = [bool]($raw -match '(^|\s)pcie_acs_override='); intremapOff = [bool]($raw -match '(^|\s)intremap=off\b') }
}

function ConvertFrom-VsatIommuGroups {
    # `ls -d /sys/kernel/iommu_groups/*/devices/*` -> [{ id, devices:[bdf] }], ordered by id.
    param([string]$Text)
    $g = @{}
    foreach ($l in ([string]$Text -split "`r?`n")) {
        if ($l -match '/iommu_groups/(\d+)/devices/([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\s*$') {
            $id = [int]$Matches[1]
            if (-not $g.ContainsKey($id)) { $g[$id] = [System.Collections.Generic.List[string]]::new() }
            $g[$id].Add($Matches[2].ToLowerInvariant())
        }
    }
    return @($g.Keys | Sort-Object | ForEach-Object { [ordered]@{ id = $_; devices = @($g[$_]) } })
}

function ConvertFrom-VsatIommuEcap {
    # Intel VT-d extended capability registers (one hex value per IOMMU unit). Bit 3 = interrupt
    # remapping support. True only when every unit supports it; $null when nothing was readable.
    param([string]$Text)
    $vals = @(([string]$Text -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(0x)?[0-9a-fA-F]+$' })
    if (-not $vals.Count) { return $null }
    foreach ($v in $vals) {
        $n = [Convert]::ToUInt64(($v -replace '^0x', ''), 16)
        if (-not ($n -band 8)) { return $false }
    }
    return $true
}

function ConvertFrom-VsatNvidiaSmi {
    # `nvidia-smi -q -x` -> [{ index (PCI address), name, migMode, migDevices }]. Untrusted XML
    # goes through the hardened reader; a DTD or malformed document throws.
    param([string]$Xml)
    $doc = Read-VsatXml $Xml
    if (-not $doc) { throw 'nvidia-smi output rejected: not well-formed XML, or it contains a DTD / external entity.' }
    return @(foreach ($gpu in @($doc.SelectNodes('/nvidia_smi_log/gpu'))) {
            $id = [string]$gpu.GetAttribute('id')
            if ($id -match '^([0-9a-fA-F]{4,8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$') { $id = ('{0}:{1}:{2}.{3}' -f $Matches[1].Substring($Matches[1].Length - 4), $Matches[2], $Matches[3], $Matches[4]).ToLowerInvariant() }
            $mig = $gpu.SelectSingleNode('mig_mode/current_mig')
            [ordered]@{ index = $id; name = [string]$gpu.SelectSingleNode('product_name').InnerText; migMode = $(if ($mig) { $mig.InnerText.Trim() } else { 'N/A' }); migDevices = @($gpu.SelectNodes('mig_devices/mig_device')).Count }
        })
}

function ConvertFrom-VsatExports {
    # /etc/exports -> [{ path, clients:[{ host, options }] }]. "path(opts)" with no host means everyone.
    param([string]$Text)
    $out = [System.Collections.Generic.List[object]]::new()
    $joined = ([string]$Text -replace '\\\r?\n', ' ')
    foreach ($l in ($joined -split "`r?`n")) {
        $l = ($l -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        $parts = @($l -split '\s+')
        $path = $parts[0]
        $clients = [System.Collections.Generic.List[object]]::new()
        if ($path -match '^(?<p>[^(]+)\((?<o>[^)]*)\)$') { $path = $Matches.p; $clients.Add([ordered]@{ host = '*'; options = $Matches.o }) }
        foreach ($c in @($parts | Select-Object -Skip 1)) {
            if ($c -match '^(?<h>[^(]*)\((?<o>[^)]*)\)$') { $clients.Add([ordered]@{ host = $(if ($Matches.h) { $Matches.h } else { '*' }); options = $Matches.o }) }
            else { $clients.Add([ordered]@{ host = $c; options = '' }) }
        }
        $out.Add([ordered]@{ path = $path; clients = @($clients) })
    }
    return @($out)
}

function ConvertFrom-VsatProcMounts {
    # /proc/mounts lines (already filtered to network filesystems) -> [{ source, target, fstype, options }].
    param([string]$Text)
    return @(foreach ($l in ([string]$Text -split "`r?`n")) {
            $p = @($l.Trim() -split '\s+')
            if ($p.Count -ge 4) { [ordered]@{ source = $p[0]; target = $p[1]; fstype = $p[2]; options = $p[3] } }
        })
}

function ConvertFrom-VsatMdevList {
    # "<uuid> <mdev_type> <parent bdf>" per mediated device -> [{ uuid, type, parent }].
    param([string]$Text)
    return @(foreach ($l in ([string]$Text -split "`r?`n")) {
            if ($l.Trim() -match '^([0-9a-fA-F-]{36})\s+(\S+)\s+(\S+)$') { [ordered]@{ uuid = $Matches[1].ToLowerInvariant(); type = $Matches[2]; parent = $Matches[3].ToLowerInvariant() } }
        })
}

function ConvertFrom-VsatLspciAcs {
    # `lspci -D -vvv` filtered to device and ACSCtl lines -> [{ bdf, acsCtl }]. Unprivileged lspci
    # hides capabilities, so an empty result means "not readable", not "no ACS".
    param([string]$Text)
    $cur = $null
    return @(foreach ($l in ([string]$Text -split "`r?`n")) {
            if ($l -match '^([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\s') { $cur = $Matches[1].ToLowerInvariant(); continue }
            if ($cur -and $l -match 'ACSCtl:\s*(.+)$') { [ordered]@{ bdf = $cur; acsCtl = $Matches[1].Trim() } }
        })
}

function ConvertTo-VsatPciAddress {
    # libvirt <address domain= bus= slot= function=/> -> 0000:3b:00.0, or $null when incomplete.
    param($Address)
    if (-not $Address) { return $null }
    $v = foreach ($k in 'domain', 'bus', 'slot', 'function') { [string]$Address.GetAttribute($k) }
    if (@($v | Where-Object { $_ -notmatch '^0x[0-9a-fA-F]+$' }).Count) { return $null }
    return ('{0:x4}:{1:x2}:{2:x2}.{3:x1}' -f [Convert]::ToInt32($v[0], 16), [Convert]::ToInt32($v[1], 16), [Convert]::ToInt32($v[2], 16), [Convert]::ToInt32($v[3], 16))
}

function Get-VsatKvmAccelFromXml {
    # Domain XML -> { count, devices:[{ kind 'hostdev-pci'|'mdev'|'sriov-vf', bdf, managed, mdevUuid, mdevType }] }.
    param([Parameter(Mandatory)][xml]$Xml)
    $dev = [System.Collections.Generic.List[object]]::new()
    foreach ($h in @($Xml.SelectNodes('/domain/devices/hostdev'))) {
        $t = $h.GetAttribute('type')
        if ($t -eq 'pci') { $dev.Add([ordered]@{ kind = 'hostdev-pci'; bdf = (ConvertTo-VsatPciAddress $h.SelectSingleNode('source/address')); managed = ($h.GetAttribute('managed') -eq 'yes'); mdevUuid = $null; mdevType = $null }) }
        elseif ($t -eq 'mdev') {
            $a = $h.SelectSingleNode('source/address')
            $dev.Add([ordered]@{ kind = 'mdev'; bdf = $null; managed = $false; mdevUuid = $(if ($a) { ([string]$a.GetAttribute('uuid')).ToLowerInvariant() } else { $null }); mdevType = $null })
        }
    }
    foreach ($i in @($Xml.SelectNodes("/domain/devices/interface[@type='hostdev']"))) { $dev.Add([ordered]@{ kind = 'sriov-vf'; bdf = (ConvertTo-VsatPciAddress $i.SelectSingleNode('source/address')); managed = ($i.GetAttribute('managed') -eq 'yes'); mdevUuid = $null; mdevType = $null }) }
    return [ordered]@{ count = $dev.Count; devices = @($dev) }
}

function Get-VsatVimTypeName {
    # Short vSphere API type name of a PowerCLI view object (VMware.Vim.X -> X).
    param($Object)
    if ($null -eq $Object) { return $null }
    return ([string]$Object.PSObject.TypeNames[0] -split '\.')[-1]
}

function ConvertTo-VsatVmAccel {
    # VM Config.Hardware.Device -> { count, devices:[{ kind, id, vgpuProfile, pfId }] }.
    param([AllowNull()][object[]]$Devices)
    $dev = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($Devices | Where-Object { $null -ne $_ })) {
        $t = Get-VsatVimTypeName $d
        if ($t -eq 'VirtualPCIPassthrough') {
            $b = $d.Backing
            $kind = switch (Get-VsatVimTypeName $b) { 'VirtualPCIPassthroughDynamicBackingInfo' { 'dynamic-passthrough' } 'VirtualPCIPassthroughVmiopBackingInfo' { 'vgpu' } default { 'passthrough' } }
            $dev.Add([ordered]@{ kind = $kind; id = $(if ($kind -eq 'passthrough' -and $b) { [string](Get-VsatProp $b 'Id' '') } else { $null }); vgpuProfile = $(if ($kind -eq 'vgpu') { [string](Get-VsatProp $b 'Vgpu' '') } else { $null }); pfId = $null })
        }
        elseif ($t -eq 'VirtualSriovEthernetCard') {
            $dev.Add([ordered]@{ kind = 'sriov-nic'; id = $null; vgpuProfile = $null; pfId = [string](Get-VsatProp $d 'SriovBacking.PhysicalFunctionBacking.Id' '') })
        }
    }
    return [ordered]@{ count = $dev.Count; devices = @($dev) }
}

function ConvertTo-VsatPciPassthru {
    # HostSystem Config.PciPassthruInfo + Hardware.PciDevice -> passthrough/SR-IOV state of every
    # device that is passthrough-capable, enabled, active or has SR-IOV enabled.
    param([AllowNull()][object[]]$PassthruInfo, [AllowNull()][object[]]$PciDevice)
    $pci = @{}; foreach ($p in @($PciDevice | Where-Object { $null -ne $_ })) { $pci[[string]$p.Id] = $p }
    $hex = { param($v) if ($null -eq $v) { $null } else { '{0:x4}' -f ([int]$v -band 0xffff) } }
    return @(foreach ($i in @($PassthruInfo | Where-Object { $null -ne $_ })) {
            $sriov = [bool](Get-VsatProp $i 'SriovEnabled' $false)
            if (-not ($i.PassthruCapable -or $i.PassthruEnabled -or $i.PassthruActive -or $sriov)) { continue }
            $p = $pci[[string]$i.Id]
            [ordered]@{
                id = [string]$i.Id; vendorId = (& $hex (Get-VsatProp $p 'VendorId')); deviceId = (& $hex (Get-VsatProp $p 'DeviceId'))
                vendorName = [string](Get-VsatProp $p 'VendorName' ''); deviceName = [string](Get-VsatProp $p 'DeviceName' ''); classId = (& $hex (Get-VsatProp $p 'ClassId'))
                passthruCapable = [bool]$i.PassthruCapable; passthruEnabled = [bool]$i.PassthruEnabled; passthruActive = [bool]$i.PassthruActive
                sriovEnabled = $sriov; numVirtualFunction = [int](Get-VsatProp $i 'NumVirtualFunction' 0)
            }
        })
}
#endregion Accelerator parsers
