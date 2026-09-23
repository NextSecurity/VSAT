<#
.SYNOPSIS
    Generates the deterministic synthetic lab evidence used by -Demo, tests and the
    GitHub Pages demo. Only example.local names and RFC 1918/5737 addresses are used.
    Several names are deliberately hostile to prove safe rendering in every output.
#>
[CmdletBinding()]
param([string]$OutFile)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutFile) { $OutFile = Join-Path $root 'tests/fixtures/demo-evidence.json' }
. (Join-Path $root 'src/10-Util.ps1')
. (Join-Path $root 'src/20-Model.ps1')
$script:VsatVersion = (Get-Content -Raw (Join-Path $root 'build/version.json') | ConvertFrom-Json).version

function U([string]$seed) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $b = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed))
    $b[6] = ($b[6] -band 0x0f) -bor 0x40; $b[8] = ($b[8] -band 0x3f) -bor 0x80
    return ([guid]::new($b)).ToString()
}

$scope = [ordered]@{
    nativeVlans = @(@{ switch = '*'; vlan = 1 })
    authorizedNetflowCollectors = @('10.0.0.50')
    authorizedSyslogTargets = @('udp://10.0.0.40:514', 'tcp://10.0.0.40:514')
    criticalAssets = @(@{ match = 'name:vcsa*'; criticality = 'high' }, @{ match = 'name:dc01*'; criticality = 'high' }, @{ match = 'name:db0*'; criticality = 'high' }, @{ match = 'name:web0*'; criticality = 'medium' })
    zones = @(@{ name = 'DMZ'; match = 'name:jump*' }, @{ name = 'Web'; match = 'name:web0*' }, @{ name = 'App'; match = 'name:app0*' }, @{ name = 'Data'; match = 'name:db0*' }, @{ name = 'Management'; match = 'name:vcsa*' })
    exclusions = @(@{ pattern = 'vm:lab-*'; reason = 'Disposable lab VMs out of scope' })
    exceptions = @(
        @{ ruleId = 'ESXI-SVC-SSH'; asset = 'esx02.example.local'; owner = 'infra-team'; rationale = 'Vendor support session (ticket CHG-1042)'; expires = '2026-12-31' }
        @{ ruleId = 'VM-PASSTHROUGH'; asset = 'ai-train01'; owner = 'ml-platform'; rationale = 'GPU passthrough for model training'; expires = '2026-06-30' }
    )
}
$ev = New-VsatEvidence -Mode demo -Scope $scope
$ev.run.id = '00000000-0000-4000-8000-000000000d30'
$ev.run.startedUtc = '2026-09-23T08:00:00Z'; $ev.run.endedUtc = '2026-09-23T08:03:41Z'; $ev.run.status = 'complete'

$vc = Add-VsatEndpoint -Evidence $ev -Type vcenter -Address 'vc01.example.local'
$vc.status = 'collected'; $vc.product = 'VMware vCenter Server 8.0.3 build-24322831'; $vc.version = '8.0.3'; $vc.build = '24322831'; $vc.instanceUuid = (U 'vc01'); $vc.apiVersion = '8.0.3.0'
$nsxEp = Add-VsatEndpoint -Evidence $ev -Type nsx -Address 'nsx01.example.local'
$nsxEp.status = 'collected'; $nsxEp.product = 'NSX'; $nsxEp.version = '4.2.1.3'; $nsxEp.build = '4.2.1.3.0.24533884'
$E = 'ep-vc01'; $NX = 'ep-nsx01'

$root = Add-VsatAsset -Evidence $ev -Id "${E}:root" -Type vcenter -Name 'vc01.example.local' -Endpoint $E -Version '8.0.3' -Build '24322831' -Props ([ordered]@{ product = 'VMware vCenter Server'; instanceUuid = (U 'vc01'); apiType = 'VirtualCenter' })
Set-VsatFact $root 'extensions' -Value @(
    [ordered]@{ key = 'com.vmware.nsx.management.nsxt'; company = 'VMware'; version = '4.2.1'; urls = @('https://nsx01.example.local:443/') }
    [ordered]@{ key = 'com.vmware.vim.sms'; company = 'VMware'; version = '8.0'; urls = @() })
Set-VsatFact $root 'permissions' -Value @(
    [ordered]@{ principal = 'VSPHERE.LOCAL\Administrator'; role = 'Admin'; entity = 'Datacenters'; entityId = 'Folder-group-d1'; propagate = $true; isGroup = $false }
    [ordered]@{ principal = 'EXAMPLE\vi-admins'; role = 'Admin'; entity = 'Datacenters'; entityId = 'Folder-group-d1'; propagate = $true; isGroup = $true }
    [ordered]@{ principal = 'EXAMPLE\j.doe'; role = 'Admin'; entity = 'cl-prod'; entityId = 'ClusterComputeResource-domain-c8'; propagate = $true; isGroup = $false }
    [ordered]@{ principal = 'EXAMPLE\helpdesk'; role = 'VirtualMachinePowerUser'; entity = 'cl-dmz'; entityId = 'ClusterComputeResource-domain-c9'; propagate = $true; isGroup = $true }
    [ordered]@{ principal = 'EXAMPLE\auditors'; role = 'ReadOnly'; entity = 'Datacenters'; entityId = 'Folder-group-d1'; propagate = $true; isGroup = $true })
Set-VsatFact $root 'roles' -Value @([ordered]@{ name = 'Admin'; system = $true; privilegeCount = 600 }, [ordered]@{ name = 'VirtualMachinePowerUser'; system = $false; privilegeCount = 40 })
Set-VsatFact $root 'settings' -Value ([ordered]@{ 'event.maxAge' = '30'; 'task.maxAge' = '30'; 'VirtualCenter.VimPasswordExpirationInDays' = '30' })
Set-VsatFact $root 'keyProviders' -Value @([ordered]@{ cluster = 'kms-cluster-01'; servers = @('kms01.example.local') })

$dc = Add-VsatAsset -Evidence $ev -Id "${E}:datacenter-2" -Type datacenter -Name 'DC1' -Endpoint $E
$dc.site = 'DC1'
Add-VsatRelationship -Evidence $ev -Source $root.id -Target $dc.id -Type contains
$clusters = @{}
foreach ($c in @(@{ id = 'domain-c8'; name = 'cl-prod'; ha = $true; ac = $true; hosts = 3 }, @{ id = 'domain-c9'; name = 'cl-dmz'; ha = $false; ac = $false; hosts = 2 })) {
    $a = Add-VsatAsset -Evidence $ev -Id "${E}:$($c.id)" -Type cluster -Name $c.name -Endpoint $E
    $a.site = 'DC1'
    Set-VsatFact $a 'ha' -Value ([ordered]@{ enabled = $c.ha; admissionControl = $c.ac; policy = 'ClusterFailoverResourcesAdmissionControlPolicy'; hostMonitoring = 'enabled'; vmMonitoring = 'vmMonitoringDisabled'; isolationResponse = 'powerOff'; heartbeatDatastorePolicy = 'allFeasibleDsWithUserPreference' })
    Set-VsatFact $a 'drs' -Value ([ordered]@{ enabled = $true; behavior = 'fullyAutomated'; rules = @() })
    Set-VsatFact $a 'summary' -Value ([ordered]@{ hosts = $c.hosts; effectiveHosts = $c.hosts })
    Add-VsatRelationship -Evidence $ev -Source $dc.id -Target $a.id -Type contains
    $clusters[$c.name] = $a
}

$goodAdv = [ordered]@{
    'UserVars.DcuiTimeOut' = 600; 'UserVars.ESXiShellTimeOut' = 600; 'UserVars.ESXiShellInteractiveTimeOut' = 300; 'UserVars.HostClientSessionTimeout' = 900
    'Security.AccountLockFailures' = 5; 'Security.AccountUnlockTime' = 900; 'Security.PasswordQualityControl' = 'retry=3 min=disabled,disabled,disabled,disabled,15'; 'Security.PasswordHistory' = 5
    'Config.HostAgent.plugins.hostsvc.esxAdminsGroup' = 'SG-ESX-Admins-Prod'; 'Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd' = $false
    'Config.HostAgent.plugins.solo.enableMob' = $false; 'Net.DVFilterBindIpAddress' = ''; 'Net.BlockGuestBPDU' = 1; 'Mem.ShareForceSalting' = 2; 'UserVars.SuppressShellWarning' = 0
    'Config.HostAgent.log.level' = 'info'; 'Syslog.global.logHost' = 'udp://10.0.0.40:514'; 'Syslog.global.logDir' = '[ds-prod-01] logs/'; 'DCUI.Access' = 'root'
}
$hostDefs = @(
    @{ n = 1; cl = 'cl-prod'; ver = '8.0.3'; build = '24585383'; ssh = $false; slp = $false; lock = 'lockdownNormal'; acc = 'PartnerSupported'; eio = $true; self = $false; tor = @('tor-a', 'tor-b'); iscsi = 'prohibited'; adv = @{} }
    @{ n = 2; cl = 'cl-prod'; ver = '8.0.3'; build = '24585383'; ssh = $true; slp = $false; lock = 'lockdownNormal'; acc = 'PartnerSupported'; eio = $true; self = $false; tor = @('tor-a', 'tor-b'); iscsi = $null; adv = @{ 'UserVars.DcuiTimeOut' = 3600 } }
    @{ n = 3; cl = 'cl-prod'; ver = '8.0.3'; build = '24585383'; ssh = $false; slp = $false; lock = 'lockdownNormal'; acc = 'CommunitySupported'; eio = $true; self = $false; tor = @('tor-a', 'tor-b'); iscsi = $null; adv = @{ 'Config.HostAgent.plugins.hostsvc.esxAdminsGroup' = 'ESX Admins'; 'Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd' = $true } }
    @{ n = 4; cl = 'cl-dmz'; ver = '8.0.3'; build = '25595708'; ssh = $false; slp = $false; lock = 'lockdownStrict'; acc = 'VMwareAccepted'; eio = $true; self = $false; tor = @('tor-a', 'tor-b'); iscsi = $null; adv = @{} }
    @{ n = 5; cl = 'cl-dmz'; ver = '7.0.3'; build = '24585291'; ssh = $false; slp = $true; lock = 'lockdownDisabled'; acc = 'PartnerSupported'; eio = $false; self = $true; tor = @('tor-a'); iscsi = $null; adv = @{ 'Security.PasswordQualityControl' = 'retry=3 min=disabled,disabled,disabled,7,7'; 'Syslog.global.logHost' = ''; 'Security.AccountLockFailures' = 10 } }
)
$hosts = @{}
foreach ($d in $hostDefs) {
    $name = "esx0$($d.n).example.local"
    $hid = "${E}:host-$($d.n)0"
    $h = Add-VsatAsset -Evidence $ev -Id $hid -Type host -Name $name -Endpoint $E -Version $d.ver -Build $d.build -Props ([ordered]@{ product = "VMware ESXi $($d.ver) build-$($d.build)"; connectionState = 'connected'; powerState = 'poweredOn'; maintenance = $false; vendor = 'ExampleVendor'; model = 'X-1000' })
    $h.site = 'DC1'
    $hosts[$d.n] = $h
    Add-VsatRelationship -Evidence $ev -Source $clusters[$d.cl].id -Target $hid -Type contains
    Set-VsatFact $h 'lockdown' -Value ([ordered]@{ mode = $d.lock })
    $adv = [ordered]@{}; foreach ($k in $goodAdv.Keys) { $adv[$k] = $goodAdv[$k] }; foreach ($k in $d.adv.Keys) { $adv[$k] = $d.adv[$k] }
    Set-VsatFact $h 'advanced' -Value $adv
    Set-VsatFact $h 'services' -Value @(
        [ordered]@{ key = 'TSM-SSH'; label = 'SSH'; running = $d.ssh; policy = $(if ($d.ssh) { 'on' } else { 'off' }) }
        [ordered]@{ key = 'TSM'; label = 'ESXi Shell'; running = $false; policy = 'off' }
        [ordered]@{ key = 'ntpd'; label = 'NTP Daemon'; running = $true; policy = 'on' }
        [ordered]@{ key = 'sfcbd-watchdog'; label = 'CIM Server'; running = $false; policy = 'off' }
        [ordered]@{ key = 'snmpd'; label = 'SNMP Server'; running = $false; policy = 'off' })
    if ($d.ver -like '7.*') { $h.facts.services.value += [ordered]@{ key = 'slpd'; label = 'SLP'; running = $d.slp; policy = $(if ($d.slp) { 'on' } else { 'off' }) } }
    Set-VsatFact $h 'ntp' -Value ([ordered]@{ servers = @('10.0.0.11', '10.0.0.12'); protocol = 'ntp' })
    Set-VsatFact $h 'firewall' -Value ([ordered]@{ defaultIncomingBlocked = $true; defaultOutgoingBlocked = $true; rulesets = @(
                [ordered]@{ key = 'sshServer'; enabled = $d.ssh; allIp = $d.ssh; allowedIps = @() }
                [ordered]@{ key = 'vSphereClient'; enabled = $true; allIp = ($d.n -eq 5); allowedIps = @('10.0.0.0/24') }
                [ordered]@{ key = 'syslog'; enabled = $true; allIp = $true; allowedIps = @() }) })
    Set-VsatFact $h 'certificate' -Value ([ordered]@{ subject = "CN=$name"; issuer = $(if ($d.self) { "CN=$name" } else { 'CN=CA, DC=vsphere, DC=local, O=VMware' }); notAfter = $(if ($d.self) { '2026-10-01T00:00:00Z' } else { '2028-03-01T00:00:00Z' }); selfSigned = $d.self; vmcaSigned = -not $d.self })
    Set-VsatFact $h 'secureBoot' -Value ([ordered]@{ uefiSecureBoot = $true; tpmSupported = $true; tpmVersion = '2.0' })
    Set-VsatFact $h 'attestation' -Value ([ordered]@{ status = $(if ($d.n -eq 5) { 'notAccepted' } else { 'accepted' }); message = $null })
    Set-VsatFact $h 'acceptance' -Value $d.acc
    Set-VsatFact $h 'kernel' -Value ([ordered]@{ execInstalledOnly = $d.eio })
    Set-VsatFact $h 'modules' -Value @([ordered]@{ name = 'vmkernel'; loaded = $true; enabled = $true })
    Set-VsatFact $h 'coredump' -Value ([ordered]@{ networkEnabled = ($d.n -ne 5); networkServer = $(if ($d.n -ne 5) { '10.0.0.41' } else { $null }); fileActive = 1 })
    Set-VsatFact $h 'syslog' -Value ([ordered]@{ remoteHost = $adv['Syslog.global.logHost']; logDir = '/scratch/log'; logDirUnique = $true })
    if ($d.iscsi) { Set-VsatFact $h 'iscsiAdapters' -Value @([ordered]@{ adapter = 'vmhba64'; chapLevel = $d.iscsi; mutualChapLevel = 'prohibited' }) } else { Set-VsatFact $h 'iscsiAdapters' -Value @() }
    Set-VsatFact $h 'vmkernel' -Value @(
        [ordered]@{ device = 'vmk0'; portgroup = 'Management Network'; ip = "10.0.10.$($d.n)"; netstack = 'defaultTcpipStack'; dvPortgroup = $null; services = $(if ($d.n -eq 5) { @('management', 'vmotion') } else { @('management') }) }
        [ordered]@{ device = 'vmk1'; portgroup = ''; ip = "10.0.20.$($d.n)"; netstack = 'vmotion'; dvPortgroup = 'dvportgroup-105'; services = @('vmotion') })
    # Physical uplinks, LLDP neighbors and standard switch
    $pn = @('vmnic0', 'vmnic1'); if ($d.n -eq 5) { $pn = @('vmnic0') }
    $pids = @()
    for ($i = 0; $i -lt $pn.Count; $i++) {
        $pid2 = "$hid/pnic/$($pn[$i])"
        $pa = Add-VsatAsset -Evidence $ev -Id $pid2 -Type pnic -Name "$name $($pn[$i])" -Endpoint $E -Props ([ordered]@{ device = $pn[$i]; mac = ('00:50:56:0{0}:00:0{1}' -f $d.n, $i); linkUp = $true; speedMb = 25000 })
        Add-VsatRelationship -Evidence $ev -Source $hid -Target $pid2 -Type contains
        $tor = $d.tor[[Math]::Min($i, $d.tor.Count - 1)]
        $nid = "physical:$tor.example.local"
        [void](Add-VsatAsset -Evidence $ev -Id $nid -Type 'physical-neighbor' -Name "$tor.example.local" -Endpoint $E -Props ([ordered]@{ protocol = 'LLDP'; mgmt = $(if ($tor -eq 'tor-a') { '192.0.2.10' } else { '192.0.2.11' }) }))
        Add-VsatRelationship -Evidence $ev -Source $pid2 -Target $nid -Type neighbor -Provenance 'vsphere.networkhint' -Props ([ordered]@{ port = "Eth1/$($d.n)"; nativeVlan = 1 })
        $pids += $pid2
    }
    Set-VsatFact $h 'neighbors' -Value @($pn | ForEach-Object { [ordered]@{ device = $_; cdp = $false; lldp = $true } })
    $sid = "$hid/vss/vSwitch0"
    $sa = Add-VsatAsset -Evidence $ev -Id $sid -Type vss -Name "$name vSwitch0" -Endpoint $E -Props ([ordered]@{ mtu = 1500; uplinks = $pids })
    Set-VsatFact $sa 'policy' -Value ([ordered]@{ security = [ordered]@{ allowPromiscuous = $false; macChanges = $false; forgedTransmits = $false }; teaming = [ordered]@{ active = $pn; standby = @() } })
    Add-VsatRelationship -Evidence $ev -Source $hid -Target $sid -Type contains
    foreach ($p in $pids) { Add-VsatRelationship -Evidence $ev -Source $sid -Target $p -Type uplink }
    $pgs = @(@{ n = 'Management Network'; vlan = 10; sec = @{ allowPromiscuous = $false; macChanges = $false; forgedTransmits = $false } })
    if ($d.cl -eq 'cl-dmz') { $pgs += @{ n = 'DMZ-Trunk'; vlan = 4095; sec = @{ allowPromiscuous = $true; macChanges = $false; forgedTransmits = $true } } }
    foreach ($pg in $pgs) {
        $gid = "$hid/pg/$($pg.n)"
        $ga = Add-VsatAsset -Evidence $ev -Id $gid -Type portgroup -Name "$name $($pg.n)" -Endpoint $E -Props ([ordered]@{ portgroup = $pg.n; vlan = $pg.vlan; vswitch = 'vSwitch0' })
        Set-VsatFact $ga 'policy' -Value ([ordered]@{ security = [ordered]@{ allowPromiscuous = $pg.sec.allowPromiscuous; macChanges = $pg.sec.macChanges; forgedTransmits = $pg.sec.forgedTransmits }; overridden = ($pg.n -eq 'DMZ-Trunk') })
        Add-VsatRelationship -Evidence $ev -Source $sid -Target $gid -Type contains
    }
}

# Distributed switch and NSX-backed port groups
$dvs = Add-VsatAsset -Evidence $ev -Id "${E}:dvs-100" -Type vds -Name 'dvs-prod' -Endpoint $E -Version '8.0.3'
Set-VsatFact $dvs 'policy' -Value ([ordered]@{ security = [ordered]@{ allowPromiscuous = $false; macChanges = $false; forgedTransmits = $false }; netflow = [ordered]@{ collectorIp = '10.0.0.99'; collectorPort = 2055 }; healthCheck = @([ordered]@{ type = 'VMwareDVSVlanMtuHealthCheckConfig'; enabled = $true }, [ordered]@{ type = 'VMwareDVSTeamingHealthCheckConfig'; enabled = $false }); mirroring = @([ordered]@{ name = 'ids-tap'; enabled = $true; destinations = @('10.0.0.60') }); lacp = 'multipleLag'; mtu = 9000; uplinks = @('uplink1', 'uplink2') })
foreach ($n in 1..5) { Add-VsatRelationship -Evidence $ev -Source $dvs.id -Target $hosts[$n].id -Type depends -Props ([ordered]@{ kind = 'member-host' }) }
$dvpgs = @{}
foreach ($pg in @(
        @{ id = 'dvportgroup-101'; n = 'dvpg-web'; vlan = 0; seg = '/infra/segments/web'; ovr = $false }
        @{ id = 'dvportgroup-102'; n = 'dvpg-app'; vlan = 0; seg = '/infra/segments/app'; ovr = $true }
        @{ id = 'dvportgroup-103'; n = 'dvpg-db'; vlan = 0; seg = '/infra/segments/db'; ovr = $false }
        @{ id = 'dvportgroup-104'; n = 'dvpg-mgmt'; vlan = 1; seg = $null; ovr = $false }
        @{ id = 'dvportgroup-105'; n = 'dvpg-vmotion'; vlan = 1010; seg = $null; ovr = $false }
        @{ id = 'dvportgroup-106'; n = 'dvpg-dmz'; vlan = 0; seg = '/infra/segments/dmz'; ovr = $false }
        @{ id = 'dvportgroup-99'; n = 'dvs-prod-uplinks'; vlan = '0-4094'; seg = $null; ovr = $false; up = $true })) {
    $a = Add-VsatAsset -Evidence $ev -Id "${E}:$($pg.id)" -Type dvportgroup -Name $pg.n -Endpoint $E -Props ([ordered]@{ key = $pg.id; uplink = [bool]$pg.up; vlan = $pg.vlan; vlanType = $(if ($pg.up) { 'VmwareDistributedVirtualSwitchTrunkVlanSpec' } else { 'VmwareDistributedVirtualSwitchVlanIdSpec' }); backingType = $(if ($pg.seg) { 'nsx' } else { 'standard' }); segmentId = $pg.seg; logicalSwitchUuid = $(if ($pg.seg) { U $pg.seg } else { $null }) })
    Set-VsatFact $a 'policy' -Value ([ordered]@{ security = [ordered]@{ allowPromiscuous = $false; macChanges = $false; forgedTransmits = $false }; overrides = [ordered]@{ security = $pg.ovr; vlan = $false; shaping = $false; blockOverride = $true; uplinkTeaming = $false; ipfix = $false; resetAtDisconnect = $true }; ipfixEnabled = $true; teaming = [ordered]@{ active = @('uplink1', 'uplink2'); standby = @() } })
    if ($pg.ovr) { Set-VsatFact $a 'portOverrides' -Value @([ordered]@{ port = '37'; connectee = 'vm-231'; security = [ordered]@{ allowPromiscuous = $true; macChanges = $false; forgedTransmits = $false } }) }
    Add-VsatRelationship -Evidence $ev -Source $dvs.id -Target $a.id -Type contains
    $dvpgs[$pg.n] = $a
}

# Datastores
$ds = @{}
foreach ($d in @(@{ id = 'datastore-11'; n = 'ds-prod-01'; t = 'VMFS' }, @{ id = 'datastore-12'; n = 'ds-nfs-01'; t = 'NFS' }, @{ id = 'datastore-13'; n = 'vsanDatastore'; t = 'vsan' })) {
    $a = Add-VsatAsset -Evidence $ev -Id "${E}:$($d.id)" -Type datastore -Name $d.n -Endpoint $E -Props ([ordered]@{ type = $d.t; capacityGB = 20480; freeGB = 6120; accessible = $true; multipleHostAccess = $true; hostCount = 5 })
    if ($d.t -eq 'NFS') { Set-VsatFact $a 'nas' -Value ([ordered]@{ remoteHost = '10.0.30.5'; remoteHosts = @('10.0.30.5'); type = 'NFS'; securityType = 'AUTH_SYS' }) }
    if ($d.t -eq 'vsan') { Set-VsatFact $a 'vsan' -Value ([ordered]@{ cluster = 'cl-prod'; encryption = $false; dataInTransitEncryption = $false; stretched = $false }) }
    foreach ($n in 1..5) { Add-VsatRelationship -Evidence $ev -Source $hosts[$n].id -Target $a.id -Type depends -Props ([ordered]@{ kind = 'mount' }) }
    $ds[$d.n] = $a
}

# Virtual machines (including deliberately hostile names)
$goodVmx = [ordered]@{ 'isolation.tools.diskShrink.disable' = 'TRUE'; 'isolation.tools.diskWiper.disable' = 'TRUE'; 'RemoteDisplay.maxConnections' = '1'; 'log.rotateSize' = '2048000'; 'isolation.device.connectable.disable' = 'TRUE' }
$vmDefs = @(
    @{ n = 'web01'; h = 1; pg = 'dvpg-web'; ip = '10.10.1.11' }, @{ n = 'web02'; h = 2; pg = 'dvpg-web'; ip = '10.10.1.12' }, @{ n = 'web03'; h = 3; pg = 'dvpg-web'; ip = '10.10.1.13'; vmx = @{ 'isolation.tools.copy.disable' = 'FALSE' } }
    @{ n = 'app01'; h = 1; pg = 'dvpg-app'; ip = '10.10.2.11' }, @{ n = 'app02'; h = 2; pg = 'dvpg-app'; ip = '10.10.2.12' }, @{ n = 'app03'; h = 3; pg = 'dvpg-app'; ip = '10.10.2.13'; usb = $true }
    @{ n = 'db01'; h = 1; pg = 'dvpg-db'; ip = '10.10.3.11'; snap = 34; ds = 'vsanDatastore' }, @{ n = 'db02'; h = 2; pg = 'dvpg-db'; ip = '10.10.3.12'; ds = 'vsanDatastore' }
    @{ n = 'vcsa01'; h = 3; pg = 'dvpg-mgmt'; ip = '10.0.0.20' }, @{ n = 'nsx-mgr01'; h = 3; pg = 'dvpg-mgmt'; ip = '10.0.0.21' }, @{ n = 'dc01'; h = 1; pg = 'dvpg-mgmt'; ip = '10.0.0.10'; floppy = $true }
    @{ n = 'backup01'; h = 2; pg = 'dvpg-mgmt'; ip = '10.0.0.30'; ds = 'ds-nfs-01' }, @{ n = 'mon01'; h = 2; pg = 'dvpg-app'; ip = '10.10.2.20'; tools = 'guestToolsNeedUpgrade' }
    @{ n = 'jump01'; h = 4; vss = 'DMZ-Trunk'; ip = '203.0.113.10'; seg2 = 'dvpg-dmz'; serial = $true }
    @{ n = 'ai-train01'; h = 1; pg = 'dvpg-app'; ip = '10.10.2.50'; gpu = $true }, @{ n = 'ai-infer01'; h = 2; pg = 'dvpg-web'; ip = '10.10.1.50'; gpu = $true }
    @{ n = 'legacy-erp'; h = 5; pg = 'dvpg-app'; ip = '10.10.2.70'; tools = 'guestToolsTooOld'; vmx = @{ 'RemoteDisplay.maxConnections' = '4' }; nonpersist = $true; nonsx = $true }
    @{ n = 'lab-test01'; h = 5; pg = 'dvpg-app'; ip = '10.10.9.9' }
    @{ n = '<img src=x onerror=alert(1)>'; h = 4; pg = 'dvpg-web'; ip = '10.10.1.66' }
    @{ n = '=cmd|'' /C calc''!A0'; h = 4; pg = 'dvpg-app'; ip = '10.10.2.66' }
    @{ n = '"><script>alert(2)</script>'; h = 4; pg = 'dvpg-db'; ip = '10.10.3.66' }
    @{ n = 'tmpl-rhel9'; h = 3; pg = 'dvpg-app'; ip = $null; template = $true }
)
$vmIndex = @{}; $k = 200
foreach ($d in $vmDefs) {
    $k++
    $vid = "${E}:vm-$k"
    $uuid = U "vm-$k"
    $v = Add-VsatAsset -Evidence $ev -Id $vid -Type vm -Name $d.n -Endpoint $E -Props ([ordered]@{ instanceUuid = $uuid; biosUuid = (U "bios-$k"); template = [bool]$d.template; powerState = $(if ($d.template) { 'poweredOff' } else { 'poweredOn' }); hardwareVersion = 'vmx-21'; guest = 'Example Linux (64-bit)'; ipAddresses = @($d.ip | Where-Object { $_ }) })
    $v.site = 'DC1'
    $vmIndex[$d.n] = $v
    Add-VsatRelationship -Evidence $ev -Source $vid -Target $hosts[$d.h].id -Type runs-on
    $dsn = if ($d.ds) { $d.ds } else { 'ds-prod-01' }
    Add-VsatRelationship -Evidence $ev -Source $vid -Target $ds[$dsn].id -Type stores
    $vmx = [ordered]@{}; foreach ($x in $goodVmx.Keys) { $vmx[$x] = $goodVmx[$x] }; if ($d.vmx) { foreach ($x in $d.vmx.Keys) { $vmx[$x] = $d.vmx[$x] } }
    Set-VsatFact $v 'extraConfig' -Value $vmx
    Set-VsatFact $v 'security' -Value ([ordered]@{ firmware = 'efi'; secureBoot = -not $d.nonpersist; vtpm = $false; encrypted = ($d.n -like 'db*'); keyProvider = $(if ($d.n -like 'db*') { 'kms-cluster-01' } else { $null }); maxMksConnections = 40; toolsStatus = $(if ($d.tools) { $d.tools } else { 'guestToolsCurrent' }); toolsRunning = 'guestToolsRunning' })
    $devs = @([ordered]@{ type = 'VirtualDisk'; label = 'Hard disk 1'; connected = $null; startConnected = $null; mode = $(if ($d.nonpersist) { 'independent_nonpersistent' } else { 'persistent' }); datastore = ($ds[$dsn].id -split ':')[1] })
    $devs += [ordered]@{ type = 'VirtualCdrom'; label = 'CD/DVD drive 1'; connected = ($d.n -eq 'legacy-erp'); startConnected = $false }
    if ($d.floppy) { $devs += [ordered]@{ type = 'VirtualFloppy'; label = 'Floppy drive 1'; connected = $false; startConnected = $false } }
    if ($d.usb) { $devs += [ordered]@{ type = 'VirtualUSBXHCIController'; label = 'USB xHCI controller'; connected = $null; startConnected = $null } }
    if ($d.serial) { $devs += [ordered]@{ type = 'VirtualSerialPort'; label = 'Serial port 1'; connected = $true; startConnected = $true; backing = 'VirtualSerialPortURIBackingInfo'; serviceUri = 'telnet://:7001' } }
    if ($d.gpu) { $devs += [ordered]@{ type = 'VirtualPCIPassthrough'; label = 'PCI device 0 (GPU)'; connected = $true; startConnected = $true } }
    if ($d.pg) {
        $devs += [ordered]@{ type = 'VirtualVmxnet3'; label = 'Network adapter 1'; connected = $true; startConnected = $true; mac = ('00:50:56:aa:{0:x2}:01' -f ($k % 256)); network = $dvpgs[$d.pg].id; portgroupKey = $dvpgs[$d.pg].props.key; port = "$k" }
        Add-VsatRelationship -Evidence $ev -Source $vid -Target $dvpgs[$d.pg].id -Type connects -Props ([ordered]@{ nic = 'Network adapter 1' })
    }
    if ($d.vss) {
        $gid = "$($hosts[$d.h].id)/pg/$($d.vss)"
        $devs += [ordered]@{ type = 'VirtualVmxnet3'; label = 'Network adapter 1'; connected = $true; startConnected = $true; mac = ('00:50:56:aa:{0:x2}:01' -f ($k % 256)); network = $gid; networkName = $d.vss }
        Add-VsatRelationship -Evidence $ev -Source $vid -Target $gid -Type connects -Props ([ordered]@{ nic = 'Network adapter 1' })
    }
    if ($d.seg2) {
        $devs += [ordered]@{ type = 'VirtualVmxnet3'; label = 'Network adapter 2'; connected = $true; startConnected = $true; mac = ('00:50:56:aa:{0:x2}:02' -f ($k % 256)); network = $dvpgs[$d.seg2].id; portgroupKey = $dvpgs[$d.seg2].props.key }
        Add-VsatRelationship -Evidence $ev -Source $vid -Target $dvpgs[$d.seg2].id -Type connects -Props ([ordered]@{ nic = 'Network adapter 2' })
    }
    Set-VsatFact $v 'devices' -Value @($devs)
    Set-VsatFact $v 'snapshots' -Value @($(if ($d.snap) { [ordered]@{ name = 'pre-upgrade'; createdUtc = '2026-08-20T09:00:00Z'; ageDays = $d.snap } }) | Where-Object { $_ })
}

# NSX Manager
$mgr = Add-VsatAsset -Evidence $ev -Id "${NX}:manager" -Type 'nsx-manager' -Name 'nsx01.example.local' -Endpoint $NX -Version '4.2.1.3'
Set-VsatFact $mgr 'version' -Value ([ordered]@{ product_version = '4.2.1.3'; node_version = '4.2.1.3.0.24533884' })
Set-VsatFact $mgr 'clusterStatus' -Value ([ordered]@{ mgmt_cluster_status = [ordered]@{ status = 'STABLE' }; control_cluster_status = [ordered]@{ status = 'STABLE' }; detailed_cluster_status = [ordered]@{ overall_status = 'STABLE' } })
Set-VsatFact $mgr 'backupConfig' -Value ([ordered]@{ backup_enabled = $false; backup_schedule = $null; remote_file_server = $null })
Set-VsatFact $mgr 'syslogExporters' -Value ([ordered]@{ results = @([ordered]@{ exporter_name = 'siem'; server = '10.0.0.40'; port = 514; protocol = 'UDP'; level = 'INFO' }) })
Set-VsatFact $mgr 'authPolicy' -Value ([ordered]@{ api_max_auth_failures = 5; api_failed_auth_lockout_period = 900; cli_max_auth_failures = 5; cli_failed_auth_lockout_period = 900; minimum_password_length = 12 })
Set-VsatFact $mgr 'ntp' -Value ([ordered]@{ service_name = 'ntp'; service_properties = [ordered]@{ servers = @('10.0.0.11', '10.0.0.12') } })
Set-VsatFact $mgr 'certificates' -Value @(
    [ordered]@{ id = 'c1'; name = 'mgmt-cluster-api'; usedBy = @('API'); notAfter = '2028-01-15T00:00:00Z'; selfSigned = $false; subject = 'CN=nsx01.example.local' }
    [ordered]@{ id = 'c2'; name = 'tier0-vpn-cert'; usedBy = @('IPSEC_VPN'); notAfter = '2026-10-10T00:00:00Z'; selfSigned = $true; subject = 'CN=vpn.example.local' })
Set-VsatFact $mgr 'computeManagers' -Value @([ordered]@{ id = 'cm-1'; display_name = 'vc01'; server = 'vc01.example.local'; origin_type = 'vCenter' })
Set-VsatFact $mgr 'transportNodeStates' -Value @(1..5 | ForEach-Object { [ordered]@{ transport_node_id = "tn-esx0$_"; state = $(if ($_ -eq 5) { 'failed' } else { 'success' }) } })
Set-VsatFact $mgr 'dfwSettings' -Value ([ordered]@{ enable_firewall = $true })
Set-VsatFact $mgr 'excludeList' -Value ([ordered]@{ members = @('/infra/domains/default/groups/grp-legacy-excluded') })
Set-VsatFact $mgr 'idsClusters' -Value @()
Set-VsatFact $mgr 'federation' -Status absent -Value $null
Add-VsatRelationship -Evidence $ev -Source $mgr.id -Target 'vcenter:vc01.example.local' -Type manages -Provenance 'nsx.compute-managers'
foreach ($n in 1..5) {
    $tn = Add-VsatAsset -Evidence $ev -Id "${NX}:tn/tn-esx0$n" -Type 'nsx-transport-node' -Name "esx0$n.example.local" -Endpoint $NX -Props ([ordered]@{ resourceType = 'HostNode'; externalId = "host-$($n)0"; fqdn = "esx0$n.example.local" })
    Add-VsatRelationship -Evidence $ev -Source $mgr.id -Target $tn.id -Type manages
}
foreach ($n in 1..2) {
    $tn = Add-VsatAsset -Evidence $ev -Id "${NX}:tn/edge-0$n" -Type 'nsx-transport-node' -Name "edge0$n.example.local" -Endpoint $NX -Props ([ordered]@{ resourceType = 'EdgeNode'; externalId = $null; fqdn = "edge0$n.example.local" })
    Add-VsatRelationship -Evidence $ev -Source $mgr.id -Target $tn.id -Type manages
}
$ec = Add-VsatAsset -Evidence $ev -Id "${NX}:edge-cluster/ec-01" -Type 'nsx-edge-cluster' -Name 'edge-cluster-01' -Endpoint $NX -Props ([ordered]@{ memberCount = 2 })
foreach ($n in 1..2) { Add-VsatRelationship -Evidence $ev -Source $ec.id -Target "${NX}:tn/edge-0$n" -Type contains }
$t0 = Add-VsatAsset -Evidence $ev -Id "${NX}:/infra/tier-0s/t0-core" -Type 'nsx-t0' -Name 't0-core' -Endpoint $NX -Props ([ordered]@{ path = '/infra/tier-0s/t0-core'; haMode = 'ACTIVE_STANDBY'; failoverMode = 'NON_PREEMPTIVE' })
Set-VsatFact $t0 'localeServices' -Value @([ordered]@{ id = 'default'; edgeClusterPath = '/infra/sites/default/enforcement-points/default/edge-clusters/ec-01' })
Set-VsatFact $t0 'bgp' -Value @([ordered]@{ enabled = $true; localAs = '65001'; gracefulRestart = 'HELPER_ONLY' })
Add-VsatRelationship -Evidence $ev -Source $t0.id -Target $ec.id -Type depends
$t1s = @{}
foreach ($t in @(@{ n = 't1-prod'; nat = @() }, @{ n = 't1-dmz'; nat = @([ordered]@{ id = 'dnat-jump'; action = 'DNAT'; source = $null; destination = '198.51.100.10'; translated = '203.0.113.10'; enabled = $true; firewallMatch = 'BYPASS' }) })) {
    $p = "/infra/tier-1s/$($t.n)"
    $a = Add-VsatAsset -Evidence $ev -Id "${NX}:$p" -Type 'nsx-t1' -Name $t.n -Endpoint $NX -Props ([ordered]@{ path = $p; tier0Path = '/infra/tier-0s/t0-core'; routeAdvertisement = @('TIER1_CONNECTED', 'TIER1_NAT') })
    Set-VsatFact $a 'natRules' -Value @($t.nat)
    Set-VsatFact $a 'localeServices' -Value @([ordered]@{ id = 'default'; edgeClusterPath = '/infra/sites/default/enforcement-points/default/edge-clusters/ec-01' })
    Add-VsatRelationship -Evidence $ev -Source $a.id -Target $t0.id -Type routes
    Add-VsatRelationship -Evidence $ev -Source $a.id -Target $ec.id -Type depends
    $t1s[$t.n] = $a
}
foreach ($s in @(@{ n = 'web'; t1 = 't1-prod'; gw = '10.10.1.1/24' }, @{ n = 'app'; t1 = 't1-prod'; gw = '10.10.2.1/24' }, @{ n = 'db'; t1 = 't1-prod'; gw = '10.10.3.1/24' }, @{ n = 'dmz'; t1 = 't1-dmz'; gw = '203.0.113.1/24' })) {
    $p = "/infra/segments/$($s.n)"
    $a = Add-VsatAsset -Evidence $ev -Id "${NX}:$p" -Type 'nsx-segment' -Name "seg-$($s.n)" -Endpoint $NX -Props ([ordered]@{ path = $p; uniqueId = (U $p); vlanIds = @(); transportZone = '/infra/sites/default/enforcement-points/default/transport-zones/overlay-tz'; connectivityPath = "/infra/tier-1s/$($s.t1)"; subnets = @($s.gw); adminState = 'UP'; type = 'overlay' })
    Add-VsatRelationship -Evidence $ev -Source $a.id -Target $t1s[$s.t1].id -Type routes
}
$groupMembers = @{
    'grp-web' = @('web01', 'web02', 'web03', 'ai-infer01', '<img src=x onerror=alert(1)>'); 'grp-app' = @('app01', 'app02', 'app03', 'mon01', 'ai-train01', '=cmd|'' /C calc''!A0')
    'grp-db' = @('db01', 'db02', '"><script>alert(2)</script>'); 'grp-mgmt' = @('vcsa01', 'nsx-mgr01', 'dc01', 'backup01'); 'grp-dmz' = @('jump01'); 'grp-legacy-excluded' = @('legacy-erp'); 'grp-empty-decom' = @()
}
foreach ($g in $groupMembers.Keys | Sort-Object) {
    $p = "/infra/domains/default/groups/$g"
    $a = Add-VsatAsset -Evidence $ev -Id "${NX}:$p" -Type 'nsx-group' -Name $g -Endpoint $NX -Props ([ordered]@{ path = $p; expressionCount = 1; tags = @("zone=$($g -replace 'grp-', '')") })
    Set-VsatFact $a 'members' -Value ([ordered]@{ vms = @($groupMembers[$g] | ForEach-Object { [ordered]@{ externalId = $vmIndex[$_].props.instanceUuid; name = $_ } }); ips = @($groupMembers[$g] | ForEach-Object { @($vmIndex[$_].props.ipAddresses) }) })
}
Set-VsatFact $mgr 'fabricVms' -Value @($vmIndex.Keys | Sort-Object | Where-Object { $_ -notin @('legacy-erp', 'tmpl-rhel9') } | ForEach-Object { [ordered]@{ externalId = $vmIndex[$_].props.instanceUuid; name = $_; sourceId = 'cm-1'; powerState = 'VM_RUNNING' } })

$GP = '/infra/domains/default/groups/'
$policies = @(
    @{ id = 'infra-services'; cat = 'Infrastructure'; seq = 10; rules = @(
            @{ id = 'allow-dns-ntp'; seq = 10; src = @('ANY'); dst = @("${GP}grp-mgmt"); svc = @('/infra/services/DNS', '/infra/services/NTP'); act = 'ALLOW'; log = $false }
            @{ id = 'allow-mgmt-admin'; seq = 20; src = @("${GP}grp-mgmt"); dst = @('ANY'); svc = @('ANY'); act = 'ALLOW'; log = $true }) }
    @{ id = 'env-isolation'; cat = 'Environment'; seq = 20; rules = @(
            @{ id = 'deny-dmz-to-data'; seq = 10; src = @("${GP}grp-dmz"); dst = @("${GP}grp-db"); svc = @('ANY'); act = 'DROP'; log = $false }) }
    @{ id = 'app-3tier'; cat = 'Application'; seq = 30; rules = @(
            @{ id = 'web-https'; seq = 10; src = @('ANY'); dst = @("${GP}grp-web"); svc = @('/infra/services/HTTPS'); act = 'ALLOW'; log = $true; scope = @("${GP}grp-web") }
            @{ id = 'web-to-app'; seq = 20; src = @("${GP}grp-web"); dst = @("${GP}grp-app"); svc = @('/infra/services/app-8443'); act = 'ALLOW'; log = $true; scope = @("${GP}grp-web", "${GP}grp-app") }
            @{ id = 'app-to-db'; seq = 30; src = @("${GP}grp-app"); dst = @("${GP}grp-db"); svc = @('/infra/services/MS-SQL-S'); act = 'ALLOW'; log = $true; scope = @("${GP}grp-app", "${GP}grp-db") }
            @{ id = 'decom-app-access'; seq = 40; src = @("${GP}grp-empty-decom"); dst = @("${GP}grp-app"); svc = @('ANY'); act = 'ALLOW'; log = $false }
            @{ id = 'old-ftp'; seq = 50; src = @("${GP}grp-app"); dst = @('ANY'); svc = @('/infra/services/FTP'); act = 'ALLOW'; log = $false; disabled = $true }) }
    @{ id = 'legacy-migration'; cat = 'Application'; seq = 40; rules = @(
            @{ id = 'temp-any-any'; seq = 10; src = @('ANY'); dst = @('ANY'); svc = @('ANY'); act = 'ALLOW'; log = $false }
            @{ id = 'jump-ssh-to-db'; seq = 20; src = @("${GP}grp-dmz"); dst = @("${GP}grp-db"); svc = @('/infra/services/SSH'); act = 'ALLOW'; log = $true }
            @{ id = 'block-db-egress'; seq = 30; src = @("${GP}grp-db"); dst = @('ANY'); svc = @('ANY'); act = 'DROP'; log = $false }) }
    @{ id = 'default-layer3-section'; cat = 'Application'; seq = 2147483647; default = $true; rules = @(
            @{ id = 'default-layer3-rule'; seq = 2147483647; src = @('ANY'); dst = @('ANY'); svc = @('ANY'); act = 'ALLOW'; log = $false }) }
)
foreach ($p in $policies) {
    $pp = "/infra/domains/default/security-policies/$($p.id)"
    $pa = Add-VsatAsset -Evidence $ev -Id "${NX}:$pp" -Type 'nsx-policy' -Name $p.id -Endpoint $NX -Props ([ordered]@{ path = $pp; firewall = 'dfw'; category = $p.cat; sequence = [long]$p.seq; scope = @('ANY'); stateful = $true; isDefault = [bool]$p.default })
    foreach ($r in $p.rules) {
        $rp = "$pp/rules/$($r.id)"
        $scopeRef = if ($r.scope) { $r.scope } else { @('ANY') }
        $ra = Add-VsatAsset -Evidence $ev -Id "${NX}:$rp" -Type 'nsx-rule' -Name $r.id -Endpoint $NX -Props ([ordered]@{
                path = $rp; firewall = 'dfw'; policy = $pa.id; policyName = $p.id; category = $p.cat; policySequence = [long]$p.seq; sequence = [long]$r.seq; ruleId = 1000 + $r.seq
                action = $r.act; direction = 'IN_OUT'; ipProtocol = 'IPV4_IPV6'; sources = $r.src; sourcesExcluded = $false; destinations = $r.dst; destinationsExcluded = $false
                services = $r.svc; profiles = @('ANY'); appliedTo = $scopeRef; policyAppliedTo = @('ANY'); disabled = [bool]$r.disabled; logged = [bool]$r.log; isDefault = [bool]$p.default })
        Add-VsatRelationship -Evidence $ev -Source $pa.id -Target $ra.id -Type contains
        foreach ($g in @($scopeRef | Where-Object { $_ -ne 'ANY' })) { Add-VsatRelationship -Evidence $ev -Source $ra.id -Target "${NX}:$g" -Type applies-to }
    }
}
$gp = '/infra/domains/default/gateway-policies/Policy_Default_Infra'
$gpa = Add-VsatAsset -Evidence $ev -Id "${NX}:$gp" -Type 'nsx-policy' -Name 'Policy_Default_Infra' -Endpoint $NX -Props ([ordered]@{ path = $gp; firewall = 'gfw'; category = 'Default'; sequence = 0L; scope = @('/infra/tier-0s/t0-core'); stateful = $true; isDefault = $true })
$gr = "$gp/rules/default_rule"
$gra = Add-VsatAsset -Evidence $ev -Id "${NX}:$gr" -Type 'nsx-rule' -Name 'default_rule (t0-core)' -Endpoint $NX -Props ([ordered]@{ path = $gr; firewall = 'gfw'; policy = $gpa.id; policyName = 'Policy_Default_Infra'; category = 'Default'; policySequence = 0L; sequence = 1L; ruleId = 2; action = 'ALLOW'; direction = 'IN_OUT'; ipProtocol = 'IPV4_IPV6'; sources = @('ANY'); sourcesExcluded = $false; destinations = @('ANY'); destinationsExcluded = $false; services = @('ANY'); profiles = @('ANY'); appliedTo = @('/infra/tier-0s/t0-core'); policyAppliedTo = @('/infra/tier-0s/t0-core'); disabled = $false; logged = $false; isDefault = $true })
Add-VsatRelationship -Evidence $ev -Source $gpa.id -Target $gra.id -Type contains

# Collector records (all successful in the synthetic lab)
$collectors = @(
    @('vsphere.vcenter', $E, 1), @('vsphere.inventory', $E, 1), @('vsphere.hosts', $E, 5), @('vsphere.vds', $E, 8), @('vsphere.datastores', $E, 3), @('vsphere.vms', $E, $vmDefs.Count),
    @('nsx.manager', $NX, 1), @('nsx.fabric', $NX, 8), @('nsx.networking', $NX, 7), @('nsx.groups', $NX, 7), @('nsx.dfw', $NX, 13), @('nsx.gfw', $NX, 1), @('nsx.inventory', $NX, $vmDefs.Count))
foreach ($c in $collectors) { $ev.collection.collectors.Add([ordered]@{ name = $c[0]; endpoint = $c[1]; status = 'ok'; startedUtc = '2026-09-23T08:00:05Z'; endedUtc = '2026-09-23T08:03:30Z'; objectCount = $c[2]; error = $null; affects = @() }) }
foreach ($a in $ev.assets) { $a.observedUtc = '2026-09-23T08:02:00Z' }
$ev.collection.log = @([ordered]@{ t = '2026-09-23T08:00:00Z'; level = 'info'; source = 'demo'; message = 'Synthetic lab evidence generated by build/New-DemoEvidence.ps1' })
$json = ConvertTo-VsatJson $ev
[System.IO.File]::WriteAllText($OutFile, $json.Replace("`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Wrote $OutFile ($($ev.assets.Count) assets, $($ev.relationships.Count) relationships)"
