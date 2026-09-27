# Shared helpers: load the GENERATED single-file script in library mode so tests
# exercise exactly what ships.
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:VsatScript = Join-Path $script:RepoRoot 'vsat.ps1'
. $script:VsatScript -LibraryMode
Initialize-VsatProgress
$script:VsatQuiet = $true

function Get-TestEvidence {
    # Fresh, mutable copy of the synthetic lab.
    return (Get-VsatDemoEvidence)
}

function Get-TestResults {
    param($Evidence, [string]$ProfileName = 'standard', $Baseline)
    if (-not $Evidence) { $Evidence = Get-TestEvidence }
    return (Invoke-VsatAnalysisPipeline -Evidence $Evidence -ProfileName $ProfileName -BaselineEvidence $Baseline)
}

function Get-TestFinding {
    param($Results, [string]$RuleId, [string]$AssetName)
    return @($Results.findings | Where-Object { $_.ruleId -eq $RuleId -and (-not $AssetName -or $_.assetName -eq $AssetName) })
}

function Get-TestAsset {
    param($Evidence, [string]$Name, [string]$Type)
    return @($Evidence.assets | Where-Object { $_.name -eq $Name -and (-not $Type -or $_.type -eq $Type) })[0]
}

function Remove-TestNsx {
    # Removes every NSX asset, endpoint and collector from evidence.
    param($Evidence)
    $keep = @($Evidence.assets | Where-Object { $_.endpoint -ne 'ep-nsx01' })
    $Evidence.assets = New-VsatList $keep
    $Evidence.relationships = New-VsatList @($Evidence.relationships | Where-Object { $_.source -notlike 'ep-nsx01:*' -and $_.target -notlike 'ep-nsx01:*' })
    $Evidence.collection.collectors = New-VsatList @($Evidence.collection.collectors | Where-Object { $_.endpoint -ne 'ep-nsx01' })
    $Evidence.scope.endpoints = New-VsatList @($Evidence.scope.endpoints | Where-Object { $_.type -ne 'nsx' })
    $script:VsatAssetIndex = @{}; foreach ($a in $Evidence.assets) { $script:VsatAssetIndex[$a.id] = $a }
}

function Get-XplatEvidence {
    # Cross-platform lab (see tests/fixtures/xplat/README.md): the demo VMware + NSX lab, the
    # Hyper-V fixture and the KVM fixture in ONE evidence object, plus the cross-platform hop
    # under test: the vCenter appliance runs as a Hyper-V VM (correlated by recorded IP only).
    # -Gpu adds the AI/GPU part of the lab (tests/fixtures/xplat/README.md, "GPU lab").
    param([string]$VcenterIp = '10.0.0.99', [switch]$Gpu)
    $ev = Get-TestEvidence
    $hvEp = Add-VsatEndpoint -Evidence $ev -Type hyperv -Address 'hv01.example.local'
    Invoke-VsatHyperVCollection -Evidence $ev -Endpoint $hvEp -ImportedJson ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/hyperv-collector.json')))
    $kvmEp = Add-VsatEndpoint -Evidence $ev -Type kvm -Address 'kvm01.example.local'
    Invoke-VsatKvmCollection -Evidence $ev -Endpoint $kvmEp -ImportedText ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/kvm-collector.txt')))
    if ($Gpu) { Add-XplatGpuLab -Evidence $ev }
    # vCenter's address lives on the scope endpoint (a hostname); the resolved IP is recorded
    # at connect time. 10.0.0.99 is unused by the demo lab (dc01 is .10, vSphere vcsa01 is .20).
    $vcEp = @($ev.scope.endpoints | Where-Object type -eq 'vcenter')[0]
    $vcEp.resolvedAddresses = @($VcenterIp)
    $hvVm = @($ev.assets | Where-Object type -eq 'hyperv-vm')[0]
    $hvVm.name = 'vcsa-hv01'
    $hvVm.facts.adapters.value[0].ips = @($VcenterIp)
    $hvVm.props.ipAddresses = @($VcenterIp)
    $ev.scope.identityDomains = @(@{ netbios = 'EXAMPLE'; dns = 'example.local' })
    $ev.run.status = 'complete'
    $script:VsatAssetIndex = @{}; foreach ($a in $ev.assets) { $script:VsatAssetIndex[$a.id] = $a }
    # Same preparation the analysis pipeline does before rule evaluation.
    [void](Update-VsatNsxDiscovery -Evidence $ev)
    Invoke-VsatCorrelation -Evidence $ev
    $ev.nsx.correlated = $true
    Set-VsatScopeAnnotations -Evidence $ev
    return $ev
}

function Add-XplatGpuLab {
    # GPU hosts on Hyper-V and KVM (collector fixtures in tests/fixtures/xplat) plus a vSphere
    # overlay on the demo lab: SR-IOV on the esx01 management NIC and on a spare esx03 NIC,
    # ai-train01 on the AUTH_SYS NFS datastore and app02 tagged as a Kubernetes control plane.
    param([Parameter(Mandatory)]$Evidence)
    $ev = $Evidence
    $hvEp = Add-VsatEndpoint -Evidence $ev -Type hyperv -Address 'hvgpu01.example.local'
    Invoke-VsatHyperVCollection -Evidence $ev -Endpoint $hvEp -ImportedJson ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/xplat/hyperv-gpu01.json')))
    $kvmEp = Add-VsatEndpoint -Evidence $ev -Type kvm -Address 'kvm-gpu01.example.local'
    Invoke-VsatKvmCollection -Evidence $ev -Endpoint $kvmEp -ImportedText ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/xplat/kvm-gpu01.txt')))
    $sriov = { param($Id) [ordered]@{ id = $Id; vendorId = '15b3'; deviceId = '1021'; vendorName = 'Mellanox Technologies'; deviceName = 'MT2910 Family [ConnectX-7]'; classId = '0200'; passthruCapable = $true; passthruEnabled = $false; passthruActive = $false; sriovEnabled = $true; numVirtualFunction = 8 } }
    foreach ($x in @(@{ h = 'esx01.example.local'; pci = '0000:18:00.0' }, @{ h = 'esx03.example.local'; pci = '0000:af:00.0' })) {
        $h = @($ev.assets | Where-Object { $_.type -eq 'host' -and $_.name -eq $x.h })[0]
        $h.facts.pciPassthru.value = @(@($h.facts.pciPassthru.value) + (& $sriov $x.pci))
    }
    $nfs = @($ev.assets | Where-Object { $_.type -eq 'datastore' -and $_.name -eq 'ds-nfs-01' })[0]
    $train = @($ev.assets | Where-Object { $_.type -eq 'vm' -and $_.name -eq 'ai-train01' })[0]
    Add-VsatRelationship -Evidence $ev -Source $train.id -Target $nfs.id -Type stores -Provenance 'vsphere.vms'
    $cp = @($ev.assets | Where-Object { $_.type -eq 'vm' -and $_.name -eq 'app02' })[0]
    $cp.tags = @(@($cp.tags) + 'role=k8s-control-plane')
    $ev.scope.aiWorkloads = @(@{ match = 'name:train01'; role = 'training' }, @{ match = 'name:infer01'; role = 'inference' })
}

function Get-XplatGraph {
    param($Evidence)
    if (-not $Evidence) { $Evidence = Get-XplatEvidence }
    $r = Invoke-VsatRules -Evidence $Evidence -ProfileName standard
    return (New-VsatSecurityGraph -Context $r.context -Findings $r.findings)
}

function Get-OtEvidence {
    # Demo lab with two VMs declared as plant level 2 and a (tag-matched) corporate zone declared IT level 4.
    $ev = Get-TestEvidence
    $ot = @($ev.assets | Where-Object type -eq 'vm' | Sort-Object { $_.id } | Select-Object -First 2)
    foreach ($v in $ot) { $v.tags = @(@($v.tags) + 'zone=plant-l2') }
    $ev.scope.zones = @(@($ev.scope.zones) + @(
        @{ name = 'Plant-L2'; match = 'tag:zone=plant-l2'; purdueLevel = 2 },
        @{ name = 'Corp'; match = 'tag:zone=dmz'; purdueLevel = 4 }))
    $script:VsatAssetIndex = @{}; foreach ($a in $ev.assets) { $script:VsatAssetIndex[$a.id] = $a }
    return @{ evidence = $ev; otNames = @($ot.name) }
}
