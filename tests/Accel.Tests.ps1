# AI & GPU isolation: read-only accelerator/AI-storage evidence, the ai-infra rules and
# coverage domain, and AI workload mapping (GPU lab: Get-XplatEvidence -Gpu).
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:KvmGpuText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/xplat/kvm-gpu01.txt'))
    function Get-GpuAsset([Parameter(Mandatory)]$Evidence, [string]$Name, [string]$Type) { return @($Evidence.assets | Where-Object { $_.name -eq $Name -and (-not $Type -or $_.type -eq $Type) })[0] }
    function Set-TestFact($Asset, [string]$Name, $Value, [string]$Status = 'ok') { $Asset.facts[$Name] = [ordered]@{ status = $Status; value = $Value } }
    function Import-TestKvm([string]$Text) {
        $ev = New-VsatEvidence -Mode fixture
        $ep = Add-VsatEndpoint -Evidence $ev -Type kvm -Address 'kvm-gpu01.example.local'
        Invoke-VsatKvmCollection -Evidence $ev -Endpoint $ep -ImportedText $Text
        return $ev
    }
    function Get-TestSection([string]$Text, [string]$Name, [string]$Body) {
        # Replaces the body of one collector section.
        $pat = '(?s)(==VSAT:SECTION ' + [regex]::Escape($Name) + '==\n).*?(?=\n==VSAT:SECTION )'
        return [regex]::Replace($Text.Replace("`r`n", "`n"), $pat, { param($m) $m.Groups[1].Value + $Body + "`n" })
    }
}

Describe 'Accelerator parsers' {
    It 'parses kernel cmdline IOMMU and ACS override' {
        $c = ConvertFrom-VsatKernelCmdline 'BOOT_IMAGE=/vmlinuz root=/dev/sda1 intel_iommu=on iommu=pt pcie_acs_override=downstream,multifunction'
        $c.iommu | Should -Be 'pt'; $c.acsOverride | Should -BeTrue
        (ConvertFrom-VsatKernelCmdline 'root=/dev/sda1 amd_iommu=off').iommu | Should -Be 'off'
        (ConvertFrom-VsatKernelCmdline 'root=/dev/sda1 intel_iommu=on').iommu | Should -Be 'on'
        (ConvertFrom-VsatKernelCmdline 'root=/dev/sda1').iommu | Should -BeNullOrEmpty
        (ConvertFrom-VsatKernelCmdline 'root=/dev/sda1').acsOverride | Should -BeFalse
        (ConvertFrom-VsatKernelCmdline 'root=/dev/sda1 intremap=off').intremapOff | Should -BeTrue
    }
    It 'parses IOMMU group listing into groups' {
        $g = ConvertFrom-VsatIommuGroups "/sys/kernel/iommu_groups/12/devices/0000:3b:00.0`n/sys/kernel/iommu_groups/12/devices/0000:3b:00.1`n/sys/kernel/iommu_groups/13/devices/0000:5e:00.0"
        @($g).Count | Should -Be 2
        @(@($g | Where-Object { $_.id -eq 12 })[0].devices) | Should -Be @('0000:3b:00.0', '0000:3b:00.1')
        @(ConvertFrom-VsatIommuGroups '').Count | Should -Be 0
    }
    It 'reads interrupt remapping support from the Intel extended capability register (bit 3)' {
        ConvertFrom-VsatIommuEcap "f020df`nf020df" | Should -BeTrue
        ConvertFrom-VsatIommuEcap "f020df`nf020d7" | Should -BeFalse
        ConvertFrom-VsatIommuEcap '' | Should -BeNullOrEmpty
    }
    It 'parses nvidia-smi XML MIG mode and refuses a DTD (XXE)' {
        $xml = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nvidia_smi_log><gpu id="00000000:3B:00.0"><product_name>NVIDIA H100 80GB HBM3</product_name><mig_mode><current_mig>Enabled</current_mig></mig_mode><mig_devices><mig_device><index>0</index></mig_device></mig_devices></gpu></nvidia_smi_log>'
        { ConvertFrom-VsatNvidiaSmi $xml } | Should -Throw '*DTD*'
        $ok = @(ConvertFrom-VsatNvidiaSmi ($xml -replace '<!DOCTYPE[^\]]*\]>', ''))
        $ok[0].migMode | Should -Be 'Enabled'; $ok[0].migDevices | Should -Be 1
        $ok[0].index | Should -Be '0000:3b:00.0'
    }
    It 'parses /etc/exports including world-exported rw no_root_squash' {
        $e = @(ConvertFrom-VsatExports "/srv/models  10.8.0.0/16(rw,sync,no_root_squash) *(ro)`n# comment`n/srv/data gpu*.lab(rw)`n/srv/anon(rw)")
        $e.Count | Should -Be 3
        @($e[0].clients | Where-Object { $_.host -eq '*' })[0].options | Should -Be 'ro'
        @($e[0].clients | Where-Object { $_.host -eq '10.8.0.0/16' })[0].options | Should -Match 'no_root_squash'
        @($e[2].clients)[0].host | Should -Be '*'
    }
    It 'parses network mounts from /proc/mounts' {
        $m = @(ConvertFrom-VsatProcMounts "10.0.30.5:/datasets /mnt/datasets nfs4 rw,vers=4.2,sec=sys 0 0`nbucket /mnt/s3 fuse.s3fs rw,url=http://minio.lab:9000 0 0")
        $m.Count | Should -Be 2
        $m[0].fstype | Should -Be 'nfs4'; $m[0].options | Should -Match 'sec=sys'
        $m[1].target | Should -Be '/mnt/s3'
    }
    It 'parses mediated devices and ACS control lines' {
        $d = @(ConvertFrom-VsatMdevList "c3d1a0c2-1111-2222-3333-444455556666 nvidia-471 0000:5e:00.0")
        $d[0].uuid | Should -Be 'c3d1a0c2-1111-2222-3333-444455556666'; $d[0].type | Should -Be 'nvidia-471'; $d[0].parent | Should -Be '0000:5e:00.0'
        $a = ConvertFrom-VsatLspciAcs "0000:3a:00.0 PCI bridge: X`n`t`tACSCtl:`tSrcValid+ TransBlk-`n0000:3b:00.0 3D controller: Y"
        @($a).Count | Should -Be 1
        @($a)[0].bdf | Should -Be '0000:3a:00.0'
        ConvertFrom-VsatLspciAcs "0000:3b:00.0 3D controller: Y" | Should -BeNullOrEmpty
    }
    It 'extracts kvm-vm accel from domain XML hostdev, mdev and SR-IOV interfaces' {
        $x = [xml]'<domain><devices><hostdev mode="subsystem" type="pci" managed="yes"><source><address domain="0x0000" bus="0x3b" slot="0x00" function="0x0"/></source></hostdev><hostdev mode="subsystem" type="mdev" model="vfio-pci"><source><address uuid="c3d1a0c2-1111-2222-3333-444455556666"/></source></hostdev><interface type="hostdev" managed="yes"><source><address type="pci" domain="0x0000" bus="0x18" slot="0x02" function="0x1"/></source></interface><hostdev mode="subsystem" type="pci"/></devices></domain>'
        $a = Get-VsatKvmAccelFromXml $x
        $a.count | Should -Be 4
        @($a.devices | ForEach-Object { $_.kind }) | Should -Be @('hostdev-pci', 'mdev', 'hostdev-pci', 'sriov-vf')
        $a.devices[0].bdf | Should -Be '0000:3b:00.0'
        $a.devices[1].mdevUuid | Should -Be 'c3d1a0c2-1111-2222-3333-444455556666'
        $a.devices[2].bdf | Should -BeNullOrEmpty
        $a.devices[3].bdf | Should -Be '0000:18:02.1'
    }
    It 'maps vSphere passthrough backings to accelerator kinds' {
        function New-V([string]$Type, $Props) { $o = [pscustomobject]$Props; $o.PSObject.TypeNames.Insert(0, "VMware.Vim.$Type"); return $o }
        $devs = @(
            (New-V 'VirtualPCIPassthrough' @{ Backing = (New-V 'VirtualPCIPassthroughDeviceBackingInfo' @{ Id = '0000:3b:00.0' }) })
            (New-V 'VirtualPCIPassthrough' @{ Backing = (New-V 'VirtualPCIPassthroughDynamicBackingInfo' @{ AllowedDevice = @() }) })
            (New-V 'VirtualPCIPassthrough' @{ Backing = (New-V 'VirtualPCIPassthroughVmiopBackingInfo' @{ Vgpu = 'grid_a100-4c' }) })
            (New-V 'VirtualSriovEthernetCard' @{ Backing = $null; SriovBacking = [pscustomobject]@{ PhysicalFunctionBacking = [pscustomobject]@{ Id = '0000:18:00.0' } } })
            (New-V 'VirtualVmxnet3' @{ Backing = $null }))
        $a = ConvertTo-VsatVmAccel $devs
        $a.count | Should -Be 4
        @($a.devices | ForEach-Object { $_.kind }) | Should -Be @('passthrough', 'dynamic-passthrough', 'vgpu', 'sriov-nic')
        $a.devices[0].id | Should -Be '0000:3b:00.0'; $a.devices[2].vgpuProfile | Should -Be 'grid_a100-4c'; $a.devices[3].pfId | Should -Be '0000:18:00.0'
    }
    It 'maps ESXi PCI passthrough and SR-IOV state, listing only capable or enabled devices' {
        $pci = @([pscustomobject]@{ Id = '0000:3b:00.0'; VendorId = [int16]0x10de; DeviceId = [int16]0x2331; VendorName = 'NVIDIA Corporation'; DeviceName = 'GH100 [H100 PCIe]'; ClassId = [int16]0x0302 },
            [pscustomobject]@{ Id = '0000:18:00.0'; VendorId = [int16]0x15b3; DeviceId = [int16]0x1021; VendorName = 'Mellanox'; DeviceName = 'ConnectX-7'; ClassId = [int16]0x0200 },
            [pscustomobject]@{ Id = '0000:00:1f.0'; VendorId = [int16]-32634; DeviceId = [int16]0x1; VendorName = 'Intel'; DeviceName = 'LPC'; ClassId = [int16]0x0601 })
        $info = @([pscustomobject]@{ Id = '0000:3b:00.0'; PassthruCapable = $true; PassthruEnabled = $true; PassthruActive = $true },
            [pscustomobject]@{ Id = '0000:18:00.0'; PassthruCapable = $true; PassthruEnabled = $false; PassthruActive = $false; SriovEnabled = $true; NumVirtualFunction = 8 },
            [pscustomobject]@{ Id = '0000:00:1f.0'; PassthruCapable = $false; PassthruEnabled = $false; PassthruActive = $false })
        $p = @(ConvertTo-VsatPciPassthru -PassthruInfo $info -PciDevice $pci)
        $p.Count | Should -Be 2
        $p[0].vendorId | Should -Be '10de'; $p[0].passthruActive | Should -BeTrue; $p[0].classId | Should -Be '0302'
        $p[1].sriovEnabled | Should -BeTrue; $p[1].numVirtualFunction | Should -Be 8
    }
}

Describe 'Accelerator evidence from fixtures' {
    BeforeAll { $script:Ev = Get-XplatEvidence -Gpu }
    It 'KVM GPU host has IOMMU groups, cmdline, MIG, mdev, ACS, exports and mounts facts' {
        $h = Get-GpuAsset $script:Ev 'kvm-gpu01.example.local' 'kvm-host'
        $h.facts.iommu.status | Should -Be 'ok'
        $h.facts.iommu.value.enabled | Should -BeTrue
        @($h.facts.iommu.value.groups).Count | Should -Be 3
        $h.facts.iommu.value.interruptRemapping | Should -BeTrue
        $h.facts.cmdline.value.acsOverride | Should -BeTrue
        $h.facts.cmdline.value.iommu | Should -Be 'pt'
        @($h.facts.gpuMig.value)[0].migMode | Should -Be 'Disabled'
        @($h.facts.mdev.value).Count | Should -Be 2
        $h.facts.acs.status | Should -Be 'ok'
        @($h.facts.exports.value).Count | Should -Be 2
        @($h.facts.mounts.value)[0].fstype | Should -Be 'nfs4'
    }
    It 'KVM VM accel lists the PCI hostdev and the mdev; domifaddr fills domain.ips' {
        $t = Get-GpuAsset $script:Ev 'train01' 'kvm-vm'
        $t.facts.accel.value.count | Should -Be 1
        $t.facts.accel.value.devices[0].bdf | Should -Be '0000:3b:00.0'
        @($t.facts.domain.value.ips) | Should -Contain '10.20.40.11'
        (Get-GpuAsset $script:Ev 'vgpu-a' 'kvm-vm').facts.accel.value.devices[0].kind | Should -Be 'mdev'
    }
    It 'Hyper-V VM accel lists GPU-P; the host lists partitionable GPUs, SR-IOV switches and SMB shares' {
        (Get-GpuAsset $script:Ev 'infer01' 'hyperv-vm').facts.accel.value.devices[0].kind | Should -Be 'gpu-p'
        $h = Get-GpuAsset $script:Ev 'hvgpu01.example.local' 'hyperv-host'
        @($h.facts.gpuPartition.value).Count | Should -Be 1
        @($h.facts.sriov.value)[0].iovEnabled | Should -BeTrue
        @($h.facts.smbShares.value | Where-Object { $_.name -eq 'datasets' }).Count | Should -Be 1
    }
    It 'records nvidia-smi as absent when it is not installed, and as error when its output is not XML' {
        $ev = Import-TestKvm (Get-TestSection $script:KvmGpuText 'nvidia-smi' 'not-installed')
        (@($ev.assets | Where-Object type -eq 'kvm-host')[0]).facts.gpuMig.status | Should -Be 'absent'
        $ev = Import-TestKvm (Get-TestSection $script:KvmGpuText 'nvidia-smi' 'NVIDIA-SMI has failed because it could not communicate with the NVIDIA driver.')
        (@($ev.assets | Where-Object type -eq 'kvm-host')[0]).facts.gpuMig.status | Should -Be 'error'
    }
    It 'records ACS as unsupported when unprivileged lspci hides the capability' {
        $ev = Import-TestKvm (Get-TestSection $script:KvmGpuText 'pci-acs' '0000:3b:00.0 3D controller: NVIDIA Corporation GH100 [H100 PCIe] (rev a1)')
        (@($ev.assets | Where-Object type -eq 'kvm-host')[0]).facts.acs.status | Should -Be 'unsupported'
    }
    It 'output of an earlier collector (no accelerator sections) records no host accelerator facts, but VM accel from domain XML' {
        $h = Get-GpuAsset $script:Ev 'kvm01.example.local' 'kvm-host'
        $h.facts.Contains('cmdline') | Should -BeFalse
        $h.facts.Contains('iommu') | Should -BeFalse
        (Get-GpuAsset $script:Ev 'nva-kvm01' 'kvm-vm').facts.accel.value.count | Should -Be 1
    }
    It 'the demo lab carries accelerator facts for its GPU VMs and hosts' {
        $ev = Get-TestEvidence
        (Get-GpuAsset $ev 'ai-train01' 'vm').facts.accel.value.count | Should -Be 1
        (Get-GpuAsset $ev 'web01' 'vm').facts.accel.value.count | Should -Be 0
        @((Get-GpuAsset $ev 'esx01.example.local' 'host').facts.pciPassthru.value | Where-Object { $_.passthruActive }).Count | Should -Be 1
    }
}

Describe 'AI/GPU rules' {
    BeforeAll {
        $script:R = Get-TestResults (Get-XplatEvidence -Gpu)
        # PASS variants of the GPU lab.
        $ev = Get-XplatEvidence -Gpu
        $k = Get-GpuAsset $ev 'kvm-gpu01.example.local' 'kvm-host'
        $k.facts.cmdline.value.acsOverride = $false
        @($k.facts.gpuMig.value)[0].migMode = 'Enabled'
        $k.facts.exports.value = @(ConvertFrom-VsatExports '/srv/models 10.8.0.0/16(rw,sync,root_squash)')
        $k.facts.mounts.value = @(ConvertFrom-VsatProcMounts '10.0.30.5:/datasets /mnt/datasets nfs4 rw,vers=4.2,sec=krb5p 0 0')
        $hv = Get-GpuAsset $ev 'hvgpu01.example.local' 'hyperv-host'
        @($hv.facts.sriov.value)[0].allowManagementOS = $false
        foreach ($s in @($hv.facts.smbShares.value)) { $s.encryptData = $true; $s.access = @([ordered]@{ account = 'EXAMPLE\ml-team'; right = 'Change'; type = 'Allow' }) }
        (Get-GpuAsset $ev 'ds-nfs-01' 'datastore').facts.nas.value.securityType = 'SEC_KRB5I'
        $ev.scope.aiWorkloads = @(@($ev.scope.aiWorkloads) + @{ match = 'name:infer02'; role = 'k8s-control-plane' })
        $script:RPass = Get-TestResults $ev
        # FAIL variants: IOMMU off and no interrupt remapping.
        $ev = Get-XplatEvidence -Gpu
        $k = Get-GpuAsset $ev 'kvm-gpu01.example.local' 'kvm-host'
        $k.facts.cmdline.value.iommu = 'off'
        $k.facts.iommu.value.groups = @(); $k.facts.iommu.value.enabled = $false; $k.facts.iommu.value.interruptRemapping = $false
        $script:RFail = Get-TestResults $ev
    }
    It '<Rule> on <Asset> => <Expected> (<Set>)' -ForEach @(
        @{ Set = 'lab'; Rule = 'AI-IOMMU-OFF'; Asset = 'kvm-gpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'fail'; Rule = 'AI-IOMMU-OFF'; Asset = 'kvm-gpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'lab'; Rule = 'AI-IOMMU-IR'; Asset = 'kvm-gpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'fail'; Rule = 'AI-IOMMU-IR'; Asset = 'kvm-gpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'lab'; Rule = 'AI-ACS-OVERRIDE'; Asset = 'kvm-gpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-ACS-OVERRIDE'; Asset = 'kvm-gpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-IOMMU-GROUP-SHARED'; Asset = 'train01'; Expected = 'FAIL' }
        @{ Set = 'lab'; Rule = 'AI-IOMMU-GROUP-SHARED'; Asset = 'infer02'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-IOMMU-GROUP-SHARED'; Asset = 'vgpu-a'; Expected = 'NOT_APPLICABLE' }
        @{ Set = 'lab'; Rule = 'AI-GPU-SHARED-NO-MIG'; Asset = 'kvm-gpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-GPU-SHARED-NO-MIG'; Asset = 'kvm-gpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-SRIOV-HOST'; Asset = 'esx01.example.local'; Expected = 'FAIL' }
        @{ Set = 'lab'; Rule = 'AI-SRIOV-HOST'; Asset = 'esx03.example.local'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-SRIOV-HOST'; Asset = 'esx02.example.local'; Expected = 'NOT_APPLICABLE' }
        @{ Set = 'lab'; Rule = 'AI-SRIOV-HOST'; Asset = 'hvgpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-SRIOV-HOST'; Asset = 'hvgpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-SHARE-WORLD'; Asset = 'kvm-gpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-SHARE-WORLD'; Asset = 'kvm-gpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-SHARE-SMB'; Asset = 'hvgpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-SHARE-SMB'; Asset = 'hvgpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-SHARE-PLAINTEXT'; Asset = 'kvm-gpu01.example.local'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-SHARE-PLAINTEXT'; Asset = 'kvm-gpu01.example.local'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-SHARE-PLAINTEXT'; Asset = 'ds-nfs-01'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-SHARE-PLAINTEXT'; Asset = 'ds-nfs-01'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-SHARE-PLAINTEXT'; Asset = 'ds-prod-01'; Expected = 'NOT_APPLICABLE' }
        @{ Set = 'lab'; Rule = 'AI-K8S-CP-EXPOSED'; Asset = 'app02'; Expected = 'FAIL' }
        @{ Set = 'pass'; Rule = 'AI-K8S-CP-EXPOSED'; Asset = 'infer02'; Expected = 'PASS' }
        @{ Set = 'lab'; Rule = 'AI-K8S-CP-EXPOSED'; Asset = 'web01'; Expected = 'NOT_APPLICABLE' }
    ) {
        $res = switch ($Set) { 'pass' { $script:RPass } 'fail' { $script:RFail } default { $script:R } }
        $f = @(Get-TestFinding $res $Rule $Asset)
        $f.Count | Should -Be 1
        $f[0].result | Should -Be $Expected -Because $f[0].observed
        if ($Expected -in @('PASS', 'FAIL')) { @($f[0].evidence).Count | Should -BeGreaterThan 0 }
    }
    It 'every AI rule has a PASS and a FAIL case above' {
        $ids = @((Get-VsatRulePack).rules | Where-Object { $_.domain -eq 'ai-infra' } | ForEach-Object { $_.id })
        $ids.Count | Should -Be 10
        $all = @($script:R.findings) + @($script:RPass.findings) + @($script:RFail.findings)
        foreach ($id in $ids) {
            @($all | Where-Object { $_.ruleId -eq $id -and $_.result -eq 'PASS' }).Count | Should -BeGreaterThan 0 -Because "$id PASS"
            @($all | Where-Object { $_.ruleId -eq $id -and $_.result -eq 'FAIL' }).Count | Should -BeGreaterThan 0 -Because "$id FAIL"
        }
    }
    It 'IOMMU-OFF is UNKNOWN or ERROR (never PASS) when cmdline and IOMMU state were not collected' {
        $ev = Get-XplatEvidence -Gpu
        $h = Get-GpuAsset $ev 'kvm-gpu01.example.local' 'kvm-host'
        Set-TestFact $h 'cmdline' $null 'error'; Set-TestFact $h 'iommu' $null 'error'
        @(Get-TestFinding (Get-TestResults $ev) 'AI-IOMMU-OFF' 'kvm-gpu01.example.local')[0].result | Should -BeIn @('UNKNOWN', 'ERROR')
    }
    It 'host facts from an earlier collector leave host-level AI checks UNKNOWN, never PASS' {
        foreach ($id in 'AI-IOMMU-OFF', 'AI-IOMMU-IR', 'AI-ACS-OVERRIDE', 'AI-SHARE-WORLD') {
            @(Get-TestFinding $script:R $id 'kvm01.example.local')[0].result | Should -Be 'UNKNOWN' -Because $id
        }
    }
    It 'denied SMB share reads are UNKNOWN, not N/A' {
        $ev = Get-XplatEvidence -Gpu
        Set-TestFact (Get-GpuAsset $ev 'hvgpu01.example.local' 'hyperv-host') 'smbShares' $null 'denied'
        @(Get-TestFinding (Get-TestResults $ev) 'AI-SHARE-SMB' 'hvgpu01.example.local')[0].result | Should -Be 'UNKNOWN'
    }
    It 'names the no_root_squash world export and the shared IOMMU group device in the observation' {
        @(Get-TestFinding $script:R 'AI-SHARE-WORLD' 'kvm-gpu01.example.local')[0].observed | Should -Match '/srv/models'
        @(Get-TestFinding $script:R 'AI-IOMMU-GROUP-SHARED' 'train01')[0].observed | Should -Match '0000:3c:00.0'
    }
    It 'carries valid ATT&CK blocks and ATLAS labels on the model/dataset storage rules' {
        foreach ($r in @((Get-VsatRulePack).rules | Where-Object { $_.domain -eq 'ai-infra' })) {
            $r.attack.status | Should -Be 'proposed'
            @($r.attack.mitigates).Count | Should -BeGreaterThan 0
            $r.mitigation.workPackage | Should -BeIn @('WP-AI-ISOLATION', 'WP-AI-STORAGE')
        }
        foreach ($id in 'AI-SHARE-WORLD', 'AI-SHARE-SMB', 'AI-SHARE-PLAINTEXT') {
            @(@((Get-VsatRulePack).rules | Where-Object { $_.id -eq $id })[0].attack.mitigates | Where-Object { $_ -like 'AML.T*' }).Count | Should -BeGreaterThan 0 -Because $id
        }
    }
}

Describe 'ai-infra coverage domain' {
    It 'is optional and assessed on the GPU lab' {
        $d = (Get-TestResults (Get-XplatEvidence -Gpu)).coverage.domains | Where-Object id -eq 'ai-infra'
        $d.mandatory | Should -BeFalse
        $d.state | Should -BeIn @('ASSESSED', 'PARTIAL')
    }
    It 'is NOT_APPLICABLE with evidence when no accelerator exists and no AI workload is declared' {
        $ev = Get-TestEvidence
        foreach ($a in $ev.assets) {
            if ($a.facts.Contains('accel')) { $a.facts.accel = [ordered]@{ status = 'ok'; value = [ordered]@{ count = 0; devices = @() } } }
            if ($a.facts.Contains('pciPassthru')) { $a.facts.pciPassthru = [ordered]@{ status = 'ok'; value = @() } }
        }
        $ev.scope.aiWorkloads = @()
        $r = Get-TestResults $ev
        $d = $r.coverage.domains | Where-Object id -eq 'ai-infra'
        $d.state | Should -Be 'NOT_APPLICABLE'
        @($d.evidence) -join ' ' | Should -Match 'No accelerators, passthrough devices or declared AI workloads observed'
        $d.mandatory | Should -BeFalse
    }
    It 'is UNKNOWN when accelerator inventory was denied and no accelerator is known' {
        $ev = Get-TestEvidence
        foreach ($a in $ev.assets) { if ($a.facts.Contains('accel')) { $a.facts.accel = [ordered]@{ status = 'ok'; value = [ordered]@{ count = 0; devices = @() } } } }
        foreach ($a in @($ev.assets | Where-Object type -eq 'host')) { $a.facts.pciPassthru = [ordered]@{ status = 'denied'; value = $null; error = 'NoPermission' } }
        $ev.scope.aiWorkloads = @()
        $d = (Get-TestResults $ev).coverage.domains | Where-Object id -eq 'ai-infra'
        $d.state | Should -Be 'UNKNOWN'
        @($d.missing) -join ' ' | Should -Match 'denied'
    }
    It 'is PARTIAL (not NOT_APPLICABLE) when accelerators exist but part of the inventory was denied' {
        $ev = Get-TestEvidence
        foreach ($a in @($ev.assets | Where-Object type -eq 'host')) { $a.facts.pciPassthru = [ordered]@{ status = 'denied'; value = $null; error = 'NoPermission' } }
        $d = (Get-TestResults $ev).coverage.domains | Where-Object id -eq 'ai-infra'
        $d.state | Should -Be 'PARTIAL'
        @($d.missing) -join ' ' | Should -Match 'denied'
    }
    It 'is not NOT_APPLICABLE on the demo lab, which runs two GPU passthrough VMs' {
        $d = (Get-TestResults (Get-TestEvidence)).coverage.domains | Where-Object id -eq 'ai-infra'
        $d.state | Should -Not -Be 'NOT_APPLICABLE'
    }
    It 'replaying a 2.0 package (no accelerator facts) never errors and explains the gap' {
        $p = Read-VsatPackage -Path (Join-Path $PSScriptRoot 'fixtures/evidence-2.0.json')
        $r = Get-TestResults (ConvertTo-VsatLiveEvidence $p.evidence)
        $d = $r.coverage.domains | Where-Object id -eq 'ai-infra'
        $d.state | Should -BeIn @('UNKNOWN', 'NOT_APPLICABLE', 'PARTIAL')
        $d.mandatory | Should -BeFalse
        "$($d.detail) $(@($d.missing) -join ' ')" | Should -Match 'not collected|earlier VSAT'
        @($r.findings | Where-Object { $_.domain -eq 'ai-infra' -and $_.result -eq 'ERROR' }) | Should -BeNullOrEmpty
        # The GPU VMs of the old package are still recognized from their device list.
        @($r.analysis.aiWorkloads | Where-Object { $_.name -eq 'ai-train01' }).Count | Should -Be 1
    }
}

Describe 'AI workload mapping' {
    BeforeAll {
        $script:Ev = Get-XplatEvidence -Gpu
        $script:Ev.scope.aiWorkloads = @(@{ match = 'name:train01'; role = 'training' }, @{ match = 'tag:role=k8s-control-plane'; role = 'k8s-control-plane' })
        $script:R = Get-TestResults $script:Ev
    }
    It 'annotates workloads and lists them with their accelerators' {
        $w = @($script:R.analysis.aiWorkloads | Where-Object { $_.name -eq 'train01' })[0]
        $w.role | Should -Be 'training'; $w.accelerators | Should -Be 1; $w.platform | Should -Be 'kvm'
        @($w.findings).Count | Should -BeGreaterThan 0
        # GPU VMs without a declared role are listed too.
        @($script:R.analysis.aiWorkloads | Where-Object { $_.name -eq 'vgpu-a' })[0].role | Should -BeNullOrEmpty
    }
    It 'maps host-level AI findings to affected workloads' {
        $f = @(Get-TestFinding $script:R 'AI-ACS-OVERRIDE' 'kvm-gpu01.example.local')[0]
        @($f.affectedWorkloads | ForEach-Object { $script:VsatAssetIndex[$_].name }) | Should -Contain 'train01'
        $d = @(Get-TestFinding $script:R 'AI-SHARE-PLAINTEXT' 'ds-nfs-01')[0]
        @($d.affectedWorkloads | ForEach-Object { $script:VsatAssetIndex[$_].name }) | Should -Contain 'ai-train01'
        @($d.affectedWorkloads | ForEach-Object { $script:VsatAssetIndex[$_].name }) | Should -Not -Contain 'backup01'
    }
    It 'k8s control plane becomes a crown and exposure is evaluated from the graph' {
        @($script:R.analysis.blastRadius.nodes | Where-Object { $_.crown -and $_.crownReason -match 'k8s-control-plane' }).Count | Should -BeGreaterThan 0
        @(Get-TestFinding $script:R 'AI-K8S-CP-EXPOSED' 'app02')[0].result | Should -BeIn @('PASS', 'FAIL')
        @($script:R.analysis.aiWorkloads | Where-Object { $_.name -eq 'app02' })[0].blastPaths.Count | Should -BeGreaterThan 0
    }
    It 'AI-K8S-CP-EXPOSED is NOT_APPLICABLE without declared or tagged control planes' {
        $ev = Get-XplatEvidence -Gpu
        foreach ($a in $ev.assets) { $a.tags = @($a.tags | Where-Object { $_ -notlike 'role=*' }) }
        @((Get-TestResults $ev).findings | Where-Object { $_.ruleId -eq 'AI-K8S-CP-EXPOSED' -and $_.result -ne 'NOT_APPLICABLE' }) | Should -BeNullOrEmpty
    }
    It 'ignores role tags that are not AI roles and clears roles from an earlier scope' {
        $ev = Get-XplatEvidence -Gpu
        (Get-GpuAsset $ev 'web01' 'vm').tags = @('role=web')
        Set-VsatScopeAnnotations -Evidence $ev
        (Get-GpuAsset $ev 'web01' 'vm').Contains('aiRole') | Should -BeFalse
        (Get-GpuAsset $ev 'train01' 'kvm-vm').aiRole | Should -Be 'training'
        $ev.scope.aiWorkloads = @()
        Set-VsatScopeAnnotations -Evidence $ev
        (Get-GpuAsset $ev 'train01' 'kvm-vm').Contains('aiRole') | Should -BeFalse
    }
    It 'lists the AI control-plane crown rule before inferred high' {
        @($script:VsatCrownRules | ForEach-Object id) | Should -Be @('management-plane', 'backup-system', 'operator-high', 'ot-workload', 'ai-control-plane', 'inferred-high')
    }
}

Describe 'AI infra report view' {
    It 'has an AI infra tab and renderer' {
        $html = Get-VsatEmbeddedText 'assets/report/report.html'
        $html | Should -Match 'data-page="ai"'
        $html | Should -Match 'id="page-ai"'
        (Get-VsatEmbeddedText 'assets/report/report.js') | Should -Match 'renderers\.ai\s*='
    }
    It 'embeds analysis.aiWorkloads in the report data' {
        $r = Get-TestResults (Get-XplatEvidence -Gpu)
        $html = New-VsatReportHtml -Results $r
        $html | Should -Match '"aiWorkloads"'
    }
}

Describe 'AI evidence collection stays read-only' {
    It 'every virsh call in the KVM collector uses a read-only connection' {
        $code = @($script:VsatKvmCollector -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        # A virsh command word (not part of a name such as the virsh-version section) must be followed by --readonly or -r.
        ([regex]::Matches($code, '(?<![\w-])virsh(?![\w-])(?!\s+(--readonly|-r)\b)')).Count | Should -Be 0
        ([regex]::Matches($code, '(?<![\w-])virsh(?![\w-])')).Count | Should -BeGreaterThan 0
        $code | Should -Match 'domifaddr'
    }
    It 'runs nvidia-smi only as a query, and only when it is already on PATH' {
        $code = @($script:VsatKvmCollector -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        foreach ($m in [regex]::Matches($code, 'nvidia-smi[^;|\n]*')) { $m.Value | Should -Match '^nvidia-smi( -q -x|\s+2>|\)|$|")' -Because $m.Value }
        $code | Should -Match 'command -v nvidia-smi'
        foreach ($m in [regex]::Matches($code, '\blspci\b[^;|\n]*')) { $m.Value | Should -Match '^lspci( -D -vvv|\s+2>|\)|$|")' -Because $m.Value }
    }
    It 'the Hyper-V collector reads accelerators and shares only through Get-* cmdlets' {
        foreach ($c in 'Get-VMHostPartitionableGpu', 'Get-VMHostAssignableDevice', 'Get-VMGpuPartitionAdapter', 'Get-SmbShare', 'Get-SmbShareAccess', 'Get-VMAssignableDevice') { $script:VsatHyperVCollector | Should -Match ([regex]::Escape($c)) -Because $c }
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:VsatHyperVCollector, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Select-Object -Unique)
        @($cmds | Where-Object { $_ -notlike 'Get-*' -and $_ -notin @('ConvertTo-Json', 'Where-Object', 'ForEach-Object', 'Sort-Object', 'Select-Object', 'F', 'W', 'Confirm-SecureBootUEFI') }) | Should -BeNullOrEmpty
    }
}
