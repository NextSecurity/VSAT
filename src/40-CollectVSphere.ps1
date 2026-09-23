#region vSphere collector
# Read-only vSphere collection through PowerCLI. Only Get-* cmdlets, Get-View property
# reads and read-only esxcli namespaces (*.get / *.list) are used; see the mutation
# guard test (tests/ReadOnly.Tests.ps1) which rejects any other VMware cmdlet.

$script:VsatEsxcliAllowed = @(
    'software.acceptance.get', 'system.settings.kernel.list', 'system.module.list',
    'system.coredump.network.get', 'system.coredump.file.list', 'system.syslog.config.get',
    'network.firewall.get', 'network.firewall.ruleset.list', 'network.firewall.ruleset.allowedip.list',
    'system.security.fips140.ssh.get', 'system.settings.encryption.get', 'system.account.list',
    'iscsi.adapter.list', 'iscsi.adapter.auth.chap.get', 'software.vib.list'
)

function Import-VsatPowerCli {
    # Loads the core PowerCLI module process-locally (offline package ./modules first).
    if (Get-Command -Name Connect-VIServer -ErrorAction SilentlyContinue) { return $true }
    try {
        Import-Module VMware.VimAutomation.Core -ErrorAction Stop -WarningAction SilentlyContinue 3>$null 6>$null | Out-Null
        # No telemetry: opt out of PowerCLI CEIP for this process only (user settings untouched).
        try { Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP $false -Confirm:$false -ErrorAction Stop | Out-Null } catch { }
        return $true
    }
    catch {
        Write-VsatLog -Level error -Source 'doctor' -Message "PowerCLI (VMware.VimAutomation.Core) is not available: $($_.Exception.Message)"
        return $false
    }
}

function Connect-VsatVSphere {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][pscredential]$Credential)
    if (-not (Import-VsatPowerCli)) { throw 'PowerCLI is required for vCenter/ESXi collection. Run .\vsat.ps1 -Doctor.' }
    Register-VsatSecret $Credential.GetNetworkCredential().Password
    $pin = $script:VsatPins[$Address.ToLowerInvariant()]
    $restore = $null
    try {
        if ($pin) {
            # Explicit per-endpoint approval: verify the presented certificate matches the pin,
            # then relax PowerCLI validation for this session scope only and restore it after.
            $cert = Get-VsatCertificateInfo -HostName $Address
            if (-not $cert -or $cert.sha256 -ne $pin) { throw "Certificate presented by $Address does not match the approved fingerprint; refusing to connect." }
            $restore = (Get-PowerCLIConfiguration -Scope Session).InvalidCertificateAction
            Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction Stop | Out-Null
            Write-VsatLog -Source 'tls' -Message "Using operator-approved certificate pin for $Address (session scope only)."
        }
        $hp = Split-VsatAddress $Address
        $conn = Connect-VIServer -Server $hp.host -Port $hp.port -Credential $Credential -Protocol https -NotDefault -ErrorAction Stop -WarningAction SilentlyContinue
    }
    finally {
        if ($pin) { Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction $(if ($restore) { $restore } else { 'Unset' }) -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    }
    return $conn
}

function Invoke-VsatEsxcli {
    param([Parameter(Mandatory)]$EsxCli, [Parameter(Mandatory)][string]$Namespace, [hashtable]$Arguments)
    if ($script:VsatEsxcliAllowed -notcontains $Namespace) { throw "VSAT read-only guard: esxcli $Namespace is not allowlisted." }
    $obj = $EsxCli
    $parts = $Namespace.Split('.')
    foreach ($p in $parts) { $obj = $obj.$p }
    if ($Arguments) { return $obj.Invoke($Arguments) }
    return $obj.Invoke()
}

function Get-VsatMoRef { param($View) return [string]$View.MoRef.Value }

function ConvertTo-VsatSecurityPolicy {
    param($Policy)
    if ($null -eq $Policy) { return $null }
    $o = [ordered]@{}
    foreach ($n in 'AllowPromiscuous', 'MacChanges', 'ForgedTransmits') {
        $v = $Policy.$n
        if ($null -ne $v -and $v.PSObject.Properties['Value']) { $v = $v.Value }
        $o[$n.Substring(0, 1).ToLower() + $n.Substring(1)] = $v
    }
    return $o
}

function Invoke-VsatVSphereCollection {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Endpoint, [Parameter(Mandatory)]$Connection)
    $ep = $Endpoint.id
    $srv = $Connection
    $about = $srv.ExtensionData.Content.About
    $Endpoint.product = [string]$about.FullName
    $Endpoint.version = [string]$about.Version
    $Endpoint.build = [string]$about.Build
    $Endpoint.instanceUuid = [string]$about.InstanceUuid
    $Endpoint.apiVersion = [string]$about.ApiVersion
    $isVc = ($about.ApiType -eq 'VirtualCenter')
    if (-not $isVc) { $Endpoint.type = 'esxi' }
    $rootId = "${ep}:root"
    $root = Add-VsatAsset -Evidence $Evidence -Id $rootId -Type $(if ($isVc) { 'vcenter' } else { 'esxi-endpoint' }) -Name $Endpoint.address -Endpoint $ep -Version $about.Version -Build $about.Build -Props ([ordered]@{ product = $about.FullName; instanceUuid = $about.InstanceUuid; apiType = $about.ApiType })
    $hostIndex = @{}; $netIndex = @{}; $dsIndex = @{}

    Invoke-VsatCollector -Evidence $Evidence -Name 'vsphere.vcenter' -Endpoint $ep -Affects @('VC-*') -Script {
        if (-not $isVc) { return @{ count = 0; status = 'skipped'; error = 'Direct ESXi connection' } }
        Invoke-VsatFact $root 'extensions' {
            $em = Get-View -Server $srv -Id $srv.ExtensionData.Content.ExtensionManager -Property ExtensionList
            @($em.ExtensionList | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ key = $_.Key; company = $_.Company; version = $_.Version; urls = @($_.Server | Where-Object { $null -ne $_ } | ForEach-Object { $_.Url }) } })
        }
        Invoke-VsatFact $root 'permissions' {
            @(Get-VIPermission -Server $srv -ErrorAction Stop | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ principal = $_.Principal; role = $_.Role; entity = [string]$_.Entity; entityId = $_.EntityId; propagate = $_.Propagate; isGroup = $_.IsGroup } })
        }
        Invoke-VsatFact $root 'roles' {
            @(Get-VIRole -Server $srv -ErrorAction Stop | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ name = $_.Name; system = $_.IsSystem; privilegeCount = @($_.PrivilegeList).Count } })
        }
        Invoke-VsatFact $root 'settings' {
            $om = Get-View -Server $srv -Id $srv.ExtensionData.Content.Setting -Property Setting
            $h = [ordered]@{}
            foreach ($s in $om.Setting) { if ($s.Key -match '^(config\.vpxd\.(hostPasswordLength|event\.maxAge|task\.maxAge)|VirtualCenter\.VimPasswordExpirationInDays|log\.level|config\.log\.level|vpxd\.event\.maxAge|event\.maxAge|task\.maxAge|config\.vpxd\.sso\..*)$') { $h[$s.Key] = [string]$s.Value } }
            $h
        }
        Invoke-VsatFact $root 'keyProviders' {
            $cm = Get-View -Server $srv -Id $srv.ExtensionData.Content.CryptoManager -ErrorAction Stop
            @($cm.KmipServers | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ cluster = $_.ClusterId.Id; servers = @($_.Servers | Where-Object { $null -ne $_ } | ForEach-Object { $_.Name }) } })
        }
        1
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'vsphere.inventory' -Endpoint $ep -Affects @('CL-*') -Script {
        $dcs = Get-View -Server $srv -ViewType Datacenter -Property Name, HostFolder
        foreach ($dc in $dcs) {
            $dcId = "${ep}:" + (Get-VsatMoRef $dc)
            [void](Add-VsatAsset -Evidence $Evidence -Id $dcId -Type 'datacenter' -Name $dc.Name -Endpoint $ep)
            if ($isVc) { Add-VsatRelationship -Evidence $Evidence -Source $rootId -Target $dcId -Type contains -Provenance 'vsphere.inventory' }
            $clusters = Get-View -Server $srv -ViewType ClusterComputeResource -SearchRoot $dc.MoRef -Property Name, Host, ConfigurationEx, Summary
            foreach ($cl in $clusters) {
                $clId = "${ep}:" + (Get-VsatMoRef $cl)
                $cfg = $cl.ConfigurationEx
                $ha = $cfg.DasConfig
                $a = Add-VsatAsset -Evidence $Evidence -Id $clId -Type 'cluster' -Name $cl.Name -Endpoint $ep
                Add-VsatRelationship -Evidence $Evidence -Source $dcId -Target $clId -Type contains -Provenance 'vsphere.inventory'
                Set-VsatFact -Asset $a -Name 'ha' -Value ([ordered]@{
                        enabled = [bool]$ha.Enabled; admissionControl = [bool]$ha.AdmissionControlEnabled
                        policy = $(if ($ha.AdmissionControlPolicy) { $ha.AdmissionControlPolicy.GetType().Name } else { $null })
                        hostMonitoring = [string]$ha.HostMonitoring; vmMonitoring = [string]$ha.VmMonitoring
                        isolationResponse = $(if ($ha.DefaultVmSettings) { [string]$ha.DefaultVmSettings.IsolationResponse } else { $null })
                        heartbeatDatastorePolicy = [string]$ha.HBDatastoreCandidatePolicy
                    })
                Set-VsatFact -Asset $a -Name 'drs' -Value ([ordered]@{ enabled = [bool]$cfg.DrsConfig.Enabled; behavior = [string]$cfg.DrsConfig.DefaultVmBehavior; rules = @($cfg.Rule | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ name = $_.Name; type = $_.GetType().Name; enabled = $_.Enabled } }) })
                Set-VsatFact -Asset $a -Name 'summary' -Value ([ordered]@{ hosts = [int]$cl.Summary.NumHosts; effectiveHosts = [int]$cl.Summary.NumEffectiveHosts })
                foreach ($h in $cl.Host) { $hostIndex[[string]$h.Value] = $clId }
            }
        }
        @($dcs).Count
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'vsphere.hosts' -Endpoint $ep -Affects @('ESXI-*') -Script {
        $props = 'Name', 'Parent', 'Runtime', 'Summary.Config.Product', 'Config.LockdownMode', 'Config.AdminDisabled', 'Config.Certificate', 'Config.Network', 'Config.DateTimeInfo', 'Config.Option', 'Config.Service', 'Config.Firewall', 'Config.StorageDevice', 'Capability', 'ConfigManager', 'Datastore', 'Hardware.SystemInfo'
        $hosts = Get-View -Server $srv -ViewType HostSystem -Property $props
        $n = 0
        foreach ($h in $hosts) {
            if (Test-VsatCancel) { break }
            $hid = "${ep}:" + (Get-VsatMoRef $h)
            $prod = $h.Summary.Config.Product
            $a = Add-VsatAsset -Evidence $Evidence -Id $hid -Type 'host' -Name $h.Name -Endpoint $ep -Version $prod.Version -Build $prod.Build -Props ([ordered]@{
                    product = $prod.FullName; connectionState = [string]$h.Runtime.ConnectionState; powerState = [string]$h.Runtime.PowerState
                    maintenance = [bool]$h.Runtime.InMaintenanceMode; vendor = $h.Hardware.SystemInfo.Vendor; model = $h.Hardware.SystemInfo.Model
                })
            if ($hostIndex.ContainsKey((Get-VsatMoRef $h))) { Add-VsatRelationship -Evidence $Evidence -Source $hostIndex[(Get-VsatMoRef $h)] -Target $hid -Type contains -Provenance 'vsphere.inventory' }
            elseif ($isVc) { Add-VsatRelationship -Evidence $Evidence -Source $rootId -Target $hid -Type contains -Provenance 'vsphere.inventory' -Confidence inferred }
            if ([string]$h.Runtime.ConnectionState -ne 'connected') {
                foreach ($f in 'lockdown', 'advanced', 'services', 'ntp', 'firewall') { Set-VsatFact -Asset $a -Name $f -Status error -Value $null -ErrorMessage "Host is $($h.Runtime.ConnectionState); configuration not readable" }
                continue
            }
            # HostConfigInfo.lockdownMode is the authoritative enum; adminDisabled is a deprecated Boolean.
            $lm = $h.Config.LockdownMode
            if ($null -ne $lm) { Set-VsatFact -Asset $a -Name 'lockdown' -Value ([ordered]@{ mode = [string]$lm }) }
            else { Set-VsatFact -Asset $a -Name 'lockdown' -Status unsupported -Value $null -ErrorMessage 'lockdownMode not exposed by this host version' }
            Invoke-VsatFact $a 'advanced' { $o = [ordered]@{}; foreach ($opt in $h.Config.Option) { $o[$opt.Key] = $opt.Value }; $o }
            Invoke-VsatFact $a 'services' { @($h.Config.Service.Service | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ key = $_.Key; label = $_.Label; running = [bool]$_.Running; policy = [string]$_.Policy } }) }
            Invoke-VsatFact $a 'ntp' { [ordered]@{ servers = @($h.Config.DateTimeInfo.NtpConfig.Server); protocol = [string]$h.Config.DateTimeInfo.Protocol } }
            Invoke-VsatFact $a 'firewall' {
                $fw = $h.Config.Firewall
                [ordered]@{
                    defaultIncomingBlocked = [bool]$fw.DefaultPolicy.IncomingBlocked; defaultOutgoingBlocked = [bool]$fw.DefaultPolicy.OutgoingBlocked
                    rulesets = @($fw.Ruleset | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ key = $_.Key; enabled = [bool]$_.Enabled; allIp = [bool]$_.AllowedHosts.AllIp; allowedIps = @($_.AllowedHosts.IpAddress) + @($_.AllowedHosts.IpNetwork | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.Network)/$($_.PrefixLength)" }) } })
                }
            }
            Invoke-VsatFact $a 'certificate' {
                if (-not $h.Config.Certificate) { return $null }
                $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$h.Config.Certificate)
                [ordered]@{ subject = $x.Subject; issuer = $x.Issuer; notAfter = $x.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); selfSigned = ($x.Subject -eq $x.Issuer); vmcaSigned = ($x.Issuer -match 'VMCA|CA,.*VMware|O=VMware') }
            }
            Invoke-VsatFact $a 'secureBoot' {
                $cap = $h.Capability
                [ordered]@{ uefiSecureBoot = $cap.UefiSecureBoot; tpmSupported = $cap.TpmSupported; tpmVersion = $cap.TpmVersion }
            }
            Invoke-VsatFact $a 'attestation' {
                $h2 = Get-View -Server $srv -Id $h.MoRef -Property 'Runtime.TpmAttestation', 'Summary.TpmAttestation' -ErrorAction Stop
                $t = $h2.Runtime.TpmAttestation
                if ($null -eq $t) { return $null }
                [ordered]@{ status = [string]$t.Status; message = $(if ($t.Message) { $t.Message.Message } else { $null }) }
            }
            $esx = $null
            try { $esx = Get-EsxCli -Server $srv -VMHost (Get-VMHost -Server $srv -Id $h.MoRef -ErrorAction Stop) -V2 -ErrorAction Stop }
            catch { foreach ($f in 'acceptance', 'coredump', 'syslog', 'kernel', 'modules', 'iscsiAdapters') { Set-VsatFact -Asset $a -Name $f -Status (Get-VsatErrorClass $_) -Value $null -ErrorMessage $_.Exception.Message } }
            if ($esx) {
                Invoke-VsatFact $a 'acceptance' { [string](Invoke-VsatEsxcli $esx 'software.acceptance.get') }
                Invoke-VsatFact $a 'kernel' { $o = [ordered]@{}; foreach ($k in (Invoke-VsatEsxcli $esx 'system.settings.kernel.list')) { $o[$k.Name] = $k.Configured }; $o }
                Invoke-VsatFact $a 'modules' { @(Invoke-VsatEsxcli $esx 'system.module.list' | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ name = $_.Name; loaded = $_.IsLoaded; enabled = $_.IsEnabled } }) }
                Invoke-VsatFact $a 'coredump' {
                    $net = Invoke-VsatEsxcli $esx 'system.coredump.network.get'
                    $file = @(Invoke-VsatEsxcli $esx 'system.coredump.file.list')
                    [ordered]@{ networkEnabled = [bool]($net.Enabled -eq 'true' -or $net.Enabled -eq $true); networkServer = $net.NetworkServerIP; fileActive = @($file | Where-Object { $_.Active -eq 'true' -or $_.Active -eq $true }).Count }
                }
                Invoke-VsatFact $a 'syslog' { $s = Invoke-VsatEsxcli $esx 'system.syslog.config.get'; [ordered]@{ remoteHost = [string]$s.RemoteHost; logDir = [string]$s.LocalLogOutput; logDirUnique = $s.LocalLogOutputIsPersistent } }
                Invoke-VsatFact $a 'iscsiAdapters' {
                    $ads = @(Invoke-VsatEsxcli $esx 'iscsi.adapter.list')
                    @(foreach ($ad in $ads) {
                            $chap = $null; $mchap = $null
                            try { $chap = Invoke-VsatEsxcli $esx 'iscsi.adapter.auth.chap.get' @{ adapter = $ad.Adapter; direction = 'uni' } } catch { }
                            try { $mchap = Invoke-VsatEsxcli $esx 'iscsi.adapter.auth.chap.get' @{ adapter = $ad.Adapter; direction = 'mutual' } } catch { }
                            [ordered]@{ adapter = $ad.Adapter; chapLevel = $(if ($chap) { [string]$chap.Level } else { $null }); mutualChapLevel = $(if ($mchap) { [string]$mchap.Level } else { $null }) }
                        })
                }
            }
            Add-VsatHostNetwork -Evidence $Evidence -Asset $a -HostView $h -Server $srv -NetIndex $netIndex -Endpoint $ep
            foreach ($ds in $h.Datastore) { $dsIndex[[string]$ds.Value] = $true; Add-VsatRelationship -Evidence $Evidence -Source $hid -Target ("${ep}:" + $ds.Value) -Type depends -Provenance 'vsphere.hosts' -Props ([ordered]@{ kind = 'mount' }) }
            $n++
        }
        $n
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'vsphere.vds' -Endpoint $ep -Affects @('NET-VDS-*') -Script {
        if (-not $isVc) { return @{ count = 0; status = 'skipped'; error = 'Distributed switches require vCenter' } }
        $vdsSec = @{}
        $dvs = Get-View -Server $srv -ViewType VmwareDistributedVirtualSwitch -Property Name, Config, Summary
        foreach ($d in $dvs) {
            $did = "${ep}:" + (Get-VsatMoRef $d)
            $cfg = $d.Config
            $def = $cfg.DefaultPortConfig
            $a = Add-VsatAsset -Evidence $Evidence -Id $did -Type 'vds' -Name $d.Name -Endpoint $ep -Version $cfg.ProductInfo.Version
            Set-VsatFact -Asset $a -Name 'policy' -Value ([ordered]@{
                    security = (ConvertTo-VsatSecurityPolicy $def.SecurityPolicy)
                    netflow = [ordered]@{ collectorIp = $(if ($cfg.IpfixConfig) { $cfg.IpfixConfig.CollectorIpAddress } else { $null }); collectorPort = $(if ($cfg.IpfixConfig) { $cfg.IpfixConfig.CollectorPort } else { $null }) }
                    healthCheck = @($cfg.HealthCheckConfig | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ type = $_.GetType().Name; enabled = [bool]$_.Enable } })
                    mirroring = @($cfg.VspanSession | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled; destinations = @($_.DestinationPort.IpAddress) } })
                    lacp = [string]$cfg.LacpApiVersion; mtu = $cfg.MaxMtu
                    uplinks = @($cfg.UplinkPortPolicy.UplinkPortName)
                })
            foreach ($hm in $cfg.Host) { Add-VsatRelationship -Evidence $Evidence -Source $did -Target ("${ep}:" + $hm.Config.Host.Value) -Type depends -Provenance 'vsphere.vds' -Props ([ordered]@{ kind = 'member-host' }) }
            $vdsSec[$did] = $a.facts.policy.value.security
        }
        $pgs = Get-View -Server $srv -ViewType DistributedVirtualPortgroup -Property Name, Config, Key
        foreach ($pg in $pgs) {
            $pid2 = "${ep}:" + (Get-VsatMoRef $pg)
            $c = $pg.Config
            $dp = $c.DefaultPortConfig
            $vlan = $null; $vlanType = $null
            if ($dp -and $dp.Vlan) {
                $vlanType = $dp.Vlan.GetType().Name
                if ($dp.Vlan.PSObject.Properties['VlanId']) { $v = $dp.Vlan.VlanId; $vlan = $(if ($v -is [array]) { @($v | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.Start)-$($_.End)" }) } else { $v }) }
                elseif ($dp.Vlan.PSObject.Properties['PvlanId']) { $vlan = $dp.Vlan.PvlanId }
            }
            $ov = $c.Policy
            $a = Add-VsatAsset -Evidence $Evidence -Id $pid2 -Type 'dvportgroup' -Name $pg.Name -Endpoint $ep -Props ([ordered]@{ key = [string]$pg.Key; uplink = [bool]$c.Uplink; vlan = $vlan; vlanType = $vlanType; backingType = [string]$c.BackingType; segmentId = $c.SegmentId; logicalSwitchUuid = $c.LogicalSwitchUuid })
            # Effective policy: portgroup value where set, otherwise inherited from the switch default.
            $own = ConvertTo-VsatSecurityPolicy $(if ($dp) { $dp.SecurityPolicy } else { $null })
            $parent = if ($c.DistributedVirtualSwitch) { $vdsSec["${ep}:" + $c.DistributedVirtualSwitch.Value] } else { $null }
            $eff = [ordered]@{}
            foreach ($k in 'allowPromiscuous', 'macChanges', 'forgedTransmits') {
                $v = if ($own -and $null -ne $own[$k]) { $own[$k] } elseif ($parent) { $parent[$k] } else { $null }
                $eff[$k] = $v
            }
            Set-VsatFact -Asset $a -Name 'policy' -Value ([ordered]@{
                    security = $eff
                    overrides = [ordered]@{
                        security = [bool]$ov.SecurityPolicyOverrideAllowed; vlan = [bool]$ov.VlanOverrideAllowed; shaping = [bool]($ov.ShapingOverrideAllowed); blockOverride = [bool]$ov.BlockOverrideAllowed
                        uplinkTeaming = [bool]$ov.UplinkTeamingOverrideAllowed; ipfix = [bool]$ov.IpfixOverrideAllowed; resetAtDisconnect = [bool]$ov.PortConfigResetAtDisconnect
                    }
                    ipfixEnabled = $(if ($dp.IpfixEnabled) { [bool]$dp.IpfixEnabled.Value } else { $null })
                    teaming = $(if ($dp.UplinkTeamingPolicy -and $dp.UplinkTeamingPolicy.UplinkPortOrder) { [ordered]@{ active = @($dp.UplinkTeamingPolicy.UplinkPortOrder.ActiveUplinkPort); standby = @($dp.UplinkTeamingPolicy.UplinkPortOrder.StandbyUplinkPort) } } else { $null })
                })
            if ($c.DistributedVirtualSwitch) { Add-VsatRelationship -Evidence $Evidence -Source ("${ep}:" + $c.DistributedVirtualSwitch.Value) -Target $pid2 -Type contains -Provenance 'vsphere.vds' }
            $netIndex[[string]$pg.MoRef.Value] = $pid2
            # Per-port effective settings: overrides that diverge from the portgroup default.
            if ($ov.SecurityPolicyOverrideAllowed -and -not $c.Uplink) {
                Invoke-VsatFact $a 'portOverrides' {
                    $dvsView = Get-View -Server $srv -Id $c.DistributedVirtualSwitch -Property Name
                    $crit = New-Object VMware.Vim.DistributedVirtualSwitchPortCriteria
                    $crit.PortgroupKey = @($pg.Key); $crit.Inside = $true
                    $ports = $dvsView.FetchDVPorts($crit)
                    @($ports | Where-Object { $null -ne $_ } | ForEach-Object {
                            $sp = ConvertTo-VsatSecurityPolicy $_.Config.Setting.SecurityPolicy
                            if ($sp -and ($sp.allowPromiscuous -or $sp.macChanges -or $sp.forgedTransmits)) { [ordered]@{ port = $_.Key; connectee = $(if ($_.Connectee) { $_.Connectee.ConnectedEntity.Value } else { $null }); security = $sp } }
                        })
                }
            }
        }
        @($dvs).Count + @($pgs).Count
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'vsphere.datastores' -Endpoint $ep -Affects @('ST-*') -Script {
        $dss = Get-View -Server $srv -ViewType Datastore -Property Name, Summary, Info, Host
        foreach ($d in $dss) {
            $did = "${ep}:" + (Get-VsatMoRef $d)
            $info = $d.Info
            $nas = if ($info.PSObject.Properties['Nas'] -and $info.Nas) { [ordered]@{ remoteHost = $info.Nas.RemoteHost; remoteHosts = @($info.Nas.RemoteHostNames); type = $info.Nas.Type; securityType = $info.Nas.SecurityType } } else { $null }
            $a = Add-VsatAsset -Evidence $Evidence -Id $did -Type 'datastore' -Name $d.Name -Endpoint $ep -Props ([ordered]@{ type = [string]$d.Summary.Type; capacityGB = [math]::Round($d.Summary.Capacity / 1GB, 1); freeGB = [math]::Round($d.Summary.FreeSpace / 1GB, 1); accessible = [bool]$d.Summary.Accessible; multipleHostAccess = $d.Summary.MultipleHostAccess; hostCount = @($d.Host).Count })
            if ($nas) { Set-VsatFact -Asset $a -Name 'nas' -Value $nas }
            if ([string]$d.Summary.Type -eq 'vsan') {
                Invoke-VsatFact $a 'vsan' {
                    $cl = Get-Cluster -Server $srv -ErrorAction Stop | Where-Object { $_.VsanEnabled } | Select-Object -First 1
                    if (-not $cl) { return $null }
                    $cfg = Get-VsanClusterConfiguration -Server $srv -Cluster $cl -ErrorAction Stop
                    [ordered]@{ cluster = $cl.Name; encryption = [bool]$cfg.EncryptionEnabled; dataInTransitEncryption = [bool]$cfg.DataInTransitEncryptionEnabled; stretched = [bool]$cfg.StretchedClusterEnabled }
                }
            }
        }
        @($dss).Count
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'vsphere.vms' -Endpoint $ep -Affects @('VM-*') -Script {
        $props = 'Name', 'Runtime.Host', 'Runtime.PowerState', 'Config.Uuid', 'Config.InstanceUuid', 'Config.Template', 'Config.Firmware', 'Config.BootOptions', 'Config.ExtraConfig', 'Config.Hardware.Device', 'Config.Version', 'Config.KeyId', 'Config.GuestFullName', 'Config.Flags', 'Config.MaxMksConnections', 'Guest.ToolsVersionStatus2', 'Guest.ToolsRunningStatus', 'Guest.Net', 'Snapshot', 'Datastore', 'Network', 'ResourceConfig'
        $vms = Get-View -Server $srv -ViewType VirtualMachine -Property $props
        $n = 0
        $now = [DateTime]::UtcNow
        foreach ($v in $vms) {
            if (Test-VsatCancel) { break }
            $vid = "${ep}:" + (Get-VsatMoRef $v)
            $c = $v.Config
            if ($null -eq $c) {
                $a = Add-VsatAsset -Evidence $Evidence -Id $vid -Type 'vm' -Name $v.Name -Endpoint $ep
                foreach ($f in 'extraConfig', 'devices', 'security') { Set-VsatFact -Asset $a -Name $f -Status error -Value $null -ErrorMessage 'VM configuration unavailable (orphaned or inaccessible)' }
                continue
            }
            $ips = @($v.Guest.Net | Where-Object { $null -ne $_ } | ForEach-Object { $_.IpAddress } | Where-Object { $_ })
            $a = Add-VsatAsset -Evidence $Evidence -Id $vid -Type 'vm' -Name $v.Name -Endpoint $ep -Props ([ordered]@{
                    instanceUuid = $c.InstanceUuid; biosUuid = $c.Uuid; template = [bool]$c.Template; powerState = [string]$v.Runtime.PowerState
                    hardwareVersion = $c.Version; guest = $c.GuestFullName; ipAddresses = $ips
                })
            if ($v.Runtime.Host) { Add-VsatRelationship -Evidence $Evidence -Source $vid -Target ("${ep}:" + $v.Runtime.Host.Value) -Type runs-on -Provenance 'vsphere.vms' }
            foreach ($ds in $v.Datastore) { Add-VsatRelationship -Evidence $Evidence -Source $vid -Target ("${ep}:" + $ds.Value) -Type stores -Provenance 'vsphere.vms' }
            Invoke-VsatFact $a 'extraConfig' { $o = [ordered]@{}; foreach ($e in $c.ExtraConfig) { $o[$e.Key] = $e.Value }; $o }
            Invoke-VsatFact $a 'security' {
                [ordered]@{
                    firmware = [string]$c.Firmware; secureBoot = $(if ($c.BootOptions) { [bool]$c.BootOptions.EfiSecureBootEnabled } else { $false })
                    vtpm = [bool](@($c.Hardware.Device | Where-Object { $_.GetType().Name -eq 'VirtualTPM' }).Count)
                    encrypted = [bool]$c.KeyId; keyProvider = $(if ($c.KeyId) { $c.KeyId.ProviderId.Id } else { $null })
                    maxMksConnections = $c.MaxMksConnections
                    toolsStatus = [string]$v.Guest.ToolsVersionStatus2; toolsRunning = [string]$v.Guest.ToolsRunningStatus
                }
            }
            Invoke-VsatFact $a 'devices' {
                @(foreach ($d in $c.Hardware.Device) {
                        $t = $d.GetType().Name
                        if ($t -match '^(VirtualFloppy|VirtualCdrom|VirtualSerialPort|VirtualParallelPort|VirtualUSB|VirtualUSBController|VirtualUSBXHCIController|VirtualPCIPassthrough|VirtualSriovEthernetCard|VirtualE1000|VirtualE1000e|VirtualVmxnet3|VirtualVmxnet2|VirtualPCNet32|VirtualDisk|VirtualTPM)$') {
                            $o = [ordered]@{ type = $t; label = $d.DeviceInfo.Label; connected = $(if ($d.Connectable) { [bool]$d.Connectable.Connected } else { $null }); startConnected = $(if ($d.Connectable) { [bool]$d.Connectable.StartConnected } else { $null }) }
                            if ($t -eq 'VirtualDisk') { $o.mode = [string]$d.Backing.DiskMode; $o.datastore = $(if ($d.Backing.Datastore) { $d.Backing.Datastore.Value } else { $null }) }
                            if ($t -eq 'VirtualSerialPort' -and $d.Backing) { $o.backing = $d.Backing.GetType().Name; $o.serviceUri = $(if ($d.Backing.PSObject.Properties['ServiceURI']) { $d.Backing.ServiceURI } else { $null }) }
                            if ($d.PSObject.Properties['MacAddress']) {
                                $o.mac = $d.MacAddress
                                $b = $d.Backing
                                if ($b -and $b.PSObject.Properties['Port'] -and $b.Port) { $o.network = $netIndex[[string]$b.Port.PortgroupKey]; $o.portgroupKey = $b.Port.PortgroupKey; $o.port = $b.Port.PortKey }
                                elseif ($b -and $b.PSObject.Properties['OpaqueNetworkId']) { $o.opaqueNetworkId = $b.OpaqueNetworkId }
                                elseif ($b -and $b.PSObject.Properties['DeviceName'] -and $b.DeviceName -and $v.Runtime.Host) { $o.network = "${ep}:" + $v.Runtime.Host.Value + '/pg/' + $b.DeviceName; $o.networkName = $b.DeviceName }
                            }
                            $o
                        }
                    })
            }
            foreach ($d in @($a.facts.devices.value | Where-Object { $_.Contains('mac') })) {
                if ($d.network) { Add-VsatRelationship -Evidence $Evidence -Source $vid -Target $d.network -Type connects -Provenance 'vsphere.vms' -Props ([ordered]@{ nic = $d.label }) }
                elseif ($d.portgroupKey) {
                    # dvPortgroup keys may differ from MoRef values on older releases; record for correlation.
                    Add-VsatRelationship -Evidence $Evidence -Source $vid -Target ("${ep}:dvpg-key:" + $d.portgroupKey) -Type connects -Provenance 'vsphere.vms' -Confidence inferred -Props ([ordered]@{ nic = $d.label })
                }
                elseif ($d.opaqueNetworkId) { Add-VsatRelationship -Evidence $Evidence -Source $vid -Target ("opaque:" + $d.opaqueNetworkId) -Type connects -Provenance 'vsphere.vms' -Props ([ordered]@{ nic = $d.label }) }
            }
            Invoke-VsatFact $a 'snapshots' {
                if (-not $v.Snapshot) { return @() }
                $list = [System.Collections.Generic.List[object]]::new()
                $stack = New-Object System.Collections.Stack
                foreach ($s in $v.Snapshot.RootSnapshotList) { $stack.Push($s) }
                while ($stack.Count -gt 0) {
                    $s = $stack.Pop()
                    $list.Add([ordered]@{ name = $s.Name; createdUtc = $s.CreateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); ageDays = [int]($now - $s.CreateTime.ToUniversalTime()).TotalDays })
                    foreach ($ch in $s.ChildSnapshotList) { $stack.Push($ch) }
                }
                , $list.ToArray()
            }
            $n++
        }
        $n
    }
}

function Add-VsatHostNetwork {
    param($Evidence, $Asset, $HostView, $Server, [hashtable]$NetIndex, [string]$Endpoint)
    $ep = $Endpoint; $hid = $Asset.id
    $net = $HostView.Config.Network
    if (-not $net) { Set-VsatFact -Asset $Asset -Name 'network' -Status error -Value $null -ErrorMessage 'Host network configuration unavailable'; return }
    $pnicIds = @{}
    foreach ($p in $net.Pnic) {
        $pid2 = "${hid}/pnic/" + $p.Device
        $pa = Add-VsatAsset -Evidence $Evidence -Id $pid2 -Type 'pnic' -Name ("{0} {1}" -f $Asset.name, $p.Device) -Endpoint $ep -Props ([ordered]@{ device = $p.Device; mac = $p.Mac; linkUp = [bool]$p.LinkSpeed; speedMb = $(if ($p.LinkSpeed) { $p.LinkSpeed.SpeedMb } else { 0 }) })
        Add-VsatRelationship -Evidence $Evidence -Source $hid -Target $pid2 -Type contains -Provenance 'vsphere.hosts'
        $pnicIds[$p.Key] = $pid2
    }
    # LLDP/CDP hints give immediate-neighbor evidence only, not the physical fabric.
    try {
        $ns = Get-View -Server $Server -Id $HostView.ConfigManager.NetworkSystem -ErrorAction Stop
        $hints = $ns.QueryNetworkHint($null)
        foreach ($hint in $hints) {
            $pid2 = "${hid}/pnic/" + $hint.Device
            $nb = $null
            if ($hint.ConnectedSwitchPort) { $nb = [ordered]@{ proto = 'CDP'; device = $hint.ConnectedSwitchPort.DevId; port = $hint.ConnectedSwitchPort.PortId; vlan = $hint.ConnectedSwitchPort.Vlan; mgmt = $hint.ConnectedSwitchPort.MgmtAddr } }
            elseif ($hint.LldpInfo) { $nb = [ordered]@{ proto = 'LLDP'; device = $hint.LldpInfo.ChassisId; port = $hint.LldpInfo.PortId; name = @($hint.LldpInfo.Parameter | Where-Object { $_.Key -eq 'System Name' } | Where-Object { $null -ne $_ } | ForEach-Object { $_.Value })[0]; vlan = @($hint.LldpInfo.Parameter | Where-Object { $_.Key -eq 'Vlan ID' } | Where-Object { $null -ne $_ } | ForEach-Object { $_.Value })[0] } }
            if ($nb -and $nb.device) {
                $nid = "physical:" + ([string]$nb.device).ToLowerInvariant()
                [void](Add-VsatAsset -Evidence $Evidence -Id $nid -Type 'physical-neighbor' -Name $(if ($nb.name) { $nb.name } else { $nb.device }) -Endpoint $ep -Props ([ordered]@{ protocol = $nb.proto; mgmt = $nb.mgmt }))
                Add-VsatRelationship -Evidence $Evidence -Source $pid2 -Target $nid -Type neighbor -Provenance 'vsphere.networkhint' -Props ([ordered]@{ port = $nb.port; nativeVlan = $nb.vlan })
            }
        }
        Set-VsatFact -Asset $Asset -Name 'neighbors' -Value @($hints | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ device = $_.Device; cdp = [bool]$_.ConnectedSwitchPort; lldp = [bool]$_.LldpInfo } })
    }
    catch { Set-VsatFact -Asset $Asset -Name 'neighbors' -Status (Get-VsatErrorClass $_) -Value $null -ErrorMessage $_.Exception.Message }

    foreach ($vs in $net.Vswitch) {
        $sid = "${hid}/vss/" + $vs.Name
        $sa = Add-VsatAsset -Evidence $Evidence -Id $sid -Type 'vss' -Name ("{0} {1}" -f $Asset.name, $vs.Name) -Endpoint $ep -Props ([ordered]@{ mtu = $vs.Mtu; uplinks = @($vs.Pnic | Where-Object { $null -ne $_ } | ForEach-Object { $pnicIds[$_] }) })
        Set-VsatFact -Asset $sa -Name 'policy' -Value ([ordered]@{ security = (ConvertTo-VsatSecurityPolicy $vs.Spec.Policy.Security); teaming = $(if ($vs.Spec.Policy.NicTeaming -and $vs.Spec.Policy.NicTeaming.NicOrder) { [ordered]@{ active = @($vs.Spec.Policy.NicTeaming.NicOrder.ActiveNic); standby = @($vs.Spec.Policy.NicTeaming.NicOrder.StandbyNic) } } else { $null }) })
        Add-VsatRelationship -Evidence $Evidence -Source $hid -Target $sid -Type contains -Provenance 'vsphere.hosts'
        foreach ($pk in $vs.Pnic) { if ($pnicIds[$pk]) { Add-VsatRelationship -Evidence $Evidence -Source $sid -Target $pnicIds[$pk] -Type uplink -Provenance 'vsphere.hosts' } }
    }
    foreach ($pg in $net.Portgroup) {
        $spec = $pg.Spec
        $gid = "${hid}/pg/" + $spec.Name
        # Effective policy = portgroup override merged over the parent vSwitch policy.
        $vs = $net.Vswitch | Where-Object { $_.Name -eq $spec.VswitchName } | Select-Object -First 1
        $parent = if ($vs) { ConvertTo-VsatSecurityPolicy $vs.Spec.Policy.Security } else { $null }
        $own = ConvertTo-VsatSecurityPolicy $spec.Policy.Security
        $eff = [ordered]@{}
        foreach ($k in 'allowPromiscuous', 'macChanges', 'forgedTransmits') {
            $ov = if ($own) { $own[$k] } else { $null }
            $eff[$k] = if ($null -ne $ov) { $ov } elseif ($parent) { $parent[$k] } else { $null }
        }
        $ga = Add-VsatAsset -Evidence $Evidence -Id $gid -Type 'portgroup' -Name ("{0} {1}" -f $Asset.name, $spec.Name) -Endpoint $ep -Props ([ordered]@{ portgroup = $spec.Name; vlan = $spec.VlanId; vswitch = $spec.VswitchName })
        Set-VsatFact -Asset $ga -Name 'policy' -Value ([ordered]@{ security = $eff; overridden = [bool]($own -and (@($own.Values | Where-Object { $null -ne $_ }).Count)) })
        Add-VsatRelationship -Evidence $Evidence -Source "${hid}/vss/$($spec.VswitchName)" -Target $gid -Type contains -Provenance 'vsphere.hosts'
        $NetIndex['net:' + $spec.Name] = $gid   # host-local: last host wins for name-based VSS backings (marked inferred on use)
    }
    $vmk = foreach ($v in $net.Vnic) {
        [ordered]@{ device = $v.Device; portgroup = $v.Portgroup; ip = $v.Spec.Ip.IpAddress; netstack = $v.Spec.NetStackInstanceKey; dvPortgroup = $(if ($v.Spec.DistributedVirtualPort) { $v.Spec.DistributedVirtualPort.PortgroupKey } else { $null }) }
    }
    try {
        $vnm = Get-View -Server $Server -Id $HostView.ConfigManager.VirtualNicManager -Property Info -ErrorAction Stop
        $svc = @{}
        foreach ($c in $vnm.Info.NetConfig) { foreach ($sel in $c.SelectedVnic) { $dev = ($sel -split '-')[-1]; if (-not $svc[$dev]) { $svc[$dev] = @() }; $svc[$dev] += $c.NicType } }
        foreach ($m in $vmk) { $m.services = @($svc[$m.device]) }
    }
    catch { }
    Set-VsatFact -Asset $Asset -Name 'vmkernel' -Value @($vmk)
}

#endregion vSphere collector
