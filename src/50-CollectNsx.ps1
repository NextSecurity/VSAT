#region NSX collector
# Read-only NSX (NSX-T 3.2 / NSX 4.x / 9.x Policy + Manager API) collection.
# Every API call goes through Invoke-VsatRest, which enforces the read-only allowlist.

function Connect-VsatNsx {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][pscredential]$Credential)
    $s = New-VsatRestSession -Address $Address -Kind nsx
    $user = $Credential.UserName
    $pass = $Credential.GetNetworkCredential().Password
    Register-VsatSecret $pass
    try {
        $body = 'j_username=' + [uri]::EscapeDataString($user) + '&j_password=' + [uri]::EscapeDataString($pass)
        $r = Invoke-VsatRest -Session $s -Method POST -Path '/api/session/create' -Body $body -ContentType 'application/x-www-form-urlencoded' -Raw
        $xsrf = $null
        $vals = $null
        if ($r.headers.TryGetValues('X-XSRF-TOKEN', [ref]$vals)) { $xsrf = @($vals)[0] }
        if (-not $xsrf) { throw "NSX Manager $Address did not return a session token; check the account and that the Policy API is available." }
        Register-VsatSecret $xsrf
        $s.headers['X-XSRF-TOKEN'] = $xsrf
    }
    catch {
        Close-VsatRestSession $s
        throw
    }
    finally { $pass = $null; $body = $null }
    return $s
}

function Invoke-VsatNsxGet {
    # Records a fact on an asset from one NSX GET; returns the value or $null.
    param($Session, $Asset, [string]$Fact, [string]$Path, [switch]$Paged)
    try {
        if ($Paged) {
            $r = Get-VsatNsxPaged -Session $Session -Path $Path
            if ($r.truncated) {
                Set-VsatFact -Asset $Asset -Name $Fact -Status error -Value $r.items -ErrorMessage "Result truncated: received $($r.items.Count) of $($r.expected)"
                return $r.items
            }
            Set-VsatFact -Asset $Asset -Name $Fact -Status ok -Value $r.items
            return $r.items
        }
        $v = Invoke-VsatRest -Session $Session -Path $Path
        Set-VsatFact -Asset $Asset -Name $Fact -Status $(if ($null -eq $v) { 'absent' } else { 'ok' }) -Value $v
        return $v
    }
    catch {
        $cls = Get-VsatErrorClass $_
        Set-VsatFact -Asset $Asset -Name $Fact -Status $cls -Value $null -ErrorMessage $_.Exception.Message
        return $null
    }
}

function ConvertTo-VsatNsxRef {
    # Normalizes NSX group/service references: "ANY" stays ANY, paths are kept verbatim.
    param($Values)
    $list = @($Values | Where-Object { $null -ne $_ } | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    if ($list.Count -eq 0 -or $list -contains 'ANY') { return @('ANY') }
    return $list
}

function Invoke-VsatNsxCollection {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Endpoint, [Parameter(Mandatory)]$Session)
    $ep = $Endpoint.id
    $mgrId = "${ep}:manager"
    $mgr = Add-VsatAsset -Evidence $Evidence -Id $mgrId -Type 'nsx-manager' -Name $Endpoint.address -Endpoint $ep

    Invoke-VsatCollector -Evidence $Evidence -Name 'nsx.manager' -Endpoint $ep -Affects @('NSX-MGR-*') -Script {
        $ver = Invoke-VsatNsxGet $Session $mgr 'version' '/api/v1/node/version'
        if ($ver) {
            $mgr.version = [string](Get-VsatProp $ver 'product_version' (Get-VsatProp $ver 'node_version'))
            $Endpoint.product = 'NSX'; $Endpoint.version = $mgr.version
            $Endpoint.build = [string](Get-VsatProp $ver 'node_version')
        }
        [void](Invoke-VsatNsxGet $Session $mgr 'clusterStatus' '/api/v1/cluster/status')
        [void](Invoke-VsatNsxGet $Session $mgr 'backupConfig' '/api/v1/cluster/backups/config')
        [void](Invoke-VsatNsxGet $Session $mgr 'syslogExporters' '/api/v1/node/services/syslog/exporters')
        [void](Invoke-VsatNsxGet $Session $mgr 'authPolicy' '/api/v1/node/aaa/auth-policy')
        [void](Invoke-VsatNsxGet $Session $mgr 'ntp' '/api/v1/node/services/ntp')
        [void](Invoke-VsatNsxGet $Session $mgr 'certificatesRaw' '/api/v1/trust-management/certificates' -Paged)
        $raw = $mgr.facts.certificatesRaw
        $mgr.facts.Remove('certificatesRaw')
        if ($raw.status -notin @('ok', 'absent')) { Set-VsatFact -Asset $mgr -Name 'certificates' -Status $raw.status -Value $null -ErrorMessage (Get-VsatProp $raw 'error') }
        else {
            $parsed = foreach ($c in @($raw.value | Where-Object { $null -ne $_ })) {
                $info = [ordered]@{ id = Get-VsatProp $c 'id'; name = Get-VsatProp $c 'display_name'; usedBy = @(Get-VsatProp $c 'used_by' @() | Where-Object { $null -ne $_ } | ForEach-Object { Get-VsatProp $_ 'service_types' }); notAfter = $null; selfSigned = $null; subject = $null }
                try {
                    $pem = [string](Get-VsatProp $c 'pem_encoded')
                    $b64 = ($pem -split '-----END CERTIFICATE-----')[0] -replace '-----BEGIN CERTIFICATE-----', '' -replace '\s', ''
                    $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String($b64))
                    $info.notAfter = $x.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    $info.selfSigned = ($x.Subject -eq $x.Issuer)
                    $info.subject = $x.Subject
                }
                catch { }
                $info
            }
            Set-VsatFact -Asset $mgr -Name 'certificates' -Status $(if (@($parsed).Count) { 'ok' } else { 'absent' }) -Value @($parsed)
        }
        $cms = Invoke-VsatNsxGet $Session $mgr 'computeManagers' '/api/v1/fabric/compute-managers' -Paged
        [void](Invoke-VsatNsxGet $Session $mgr 'transportNodeStates' '/api/v1/transport-nodes/state' -Paged)
        [void](Invoke-VsatNsxGet $Session $mgr 'dfwSettings' '/policy/api/v1/infra/settings/firewall/security')
        [void](Invoke-VsatNsxGet $Session $mgr 'excludeList' '/policy/api/v1/infra/settings/firewall/security/exclude-list')
        [void](Invoke-VsatNsxGet $Session $mgr 'idsClusters' '/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs' -Paged)
        [void](Invoke-VsatNsxGet $Session $mgr 'federation' '/policy/api/v1/infra/federation-config')
        if ($cms) {
            foreach ($cm in $cms) { Add-VsatRelationship -Evidence $Evidence -Source $mgrId -Target ("vcenter:" + [string](Get-VsatProp $cm 'server')) -Type manages -Provenance 'nsx.compute-managers' -Props ([ordered]@{ server = Get-VsatProp $cm 'server'; name = Get-VsatProp $cm 'display_name' }) }
        }
        1
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'nsx.fabric' -Endpoint $ep -Affects @('NSX-TN-*') -Script {
        $tns = Get-VsatNsxPaged -Session $Session -Path '/api/v1/transport-nodes'
        foreach ($tn in $tns.items) {
            $id = "${ep}:tn/" + (Get-VsatProp $tn 'node_id' (Get-VsatProp $tn 'id'))
            $info = Get-VsatProp $tn 'node_deployment_info'
            $a = Add-VsatAsset -Evidence $Evidence -Id $id -Type 'nsx-transport-node' -Name (Get-VsatProp $tn 'display_name') -Endpoint $ep -Props ([ordered]@{ resourceType = Get-VsatProp $info 'resource_type'; externalId = Get-VsatProp $info 'external_id'; fqdn = Get-VsatProp $info 'fqdn' })
            Add-VsatRelationship -Evidence $Evidence -Source $mgrId -Target $id -Type manages -Provenance 'nsx.fabric'
        }
        $ecs = Get-VsatNsxPaged -Session $Session -Path '/api/v1/edge-clusters'
        foreach ($ec in $ecs.items) {
            $id = "${ep}:edge-cluster/" + (Get-VsatProp $ec 'id')
            $members = @(Get-VsatProp $ec 'members' @())
            $a = Add-VsatAsset -Evidence $Evidence -Id $id -Type 'nsx-edge-cluster' -Name (Get-VsatProp $ec 'display_name') -Endpoint $ep -Props ([ordered]@{ memberCount = $members.Count })
            foreach ($m in $members) {
                $tnId = "${ep}:tn/" + (Get-VsatProp $m 'transport_node_id')
                Add-VsatRelationship -Evidence $Evidence -Source $id -Target $tnId -Type contains -Provenance 'nsx.fabric'
            }
        }
        $(if ($tns.truncated -or $ecs.truncated) { @{ count = $tns.items.Count; status = 'partial'; error = 'Truncated transport node or edge cluster listing' } } else { $tns.items.Count + $ecs.items.Count })
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'nsx.networking' -Endpoint $ep -Affects @('NSX-NET-*') -Script {
        $count = 0
        $t0s = Get-VsatNsxPaged -Session $Session -Path '/policy/api/v1/infra/tier-0s'
        foreach ($g in $t0s.items) {
            $path = [string](Get-VsatProp $g 'path'); $id = "${ep}:$path"
            $a = Add-VsatAsset -Evidence $Evidence -Id $id -Type 'nsx-t0' -Name (Get-VsatProp $g 'display_name') -Endpoint $ep -Props ([ordered]@{ path = $path; haMode = Get-VsatProp $g 'ha_mode'; failoverMode = Get-VsatProp $g 'failover_mode' })
            Add-VsatNsxLocaleServices -Evidence $Evidence -Session $Session -Asset $a -Path $path -Endpoint $ep
            $count++
        }
        $t1s = Get-VsatNsxPaged -Session $Session -Path '/policy/api/v1/infra/tier-1s'
        foreach ($g in $t1s.items) {
            $path = [string](Get-VsatProp $g 'path'); $id = "${ep}:$path"
            $t0 = Get-VsatProp $g 'tier0_path'
            $a = Add-VsatAsset -Evidence $Evidence -Id $id -Type 'nsx-t1' -Name (Get-VsatProp $g 'display_name') -Endpoint $ep -Props ([ordered]@{ path = $path; tier0Path = $t0; routeAdvertisement = @(Get-VsatProp $g 'route_advertisement_types' @()) })
            if ($t0) { Add-VsatRelationship -Evidence $Evidence -Source $id -Target "${ep}:$t0" -Type routes -Provenance 'nsx.networking' }
            Add-VsatNsxLocaleServices -Evidence $Evidence -Session $Session -Asset $a -Path $path -Endpoint $ep
            try {
                $nat = Get-VsatNsxPaged -Session $Session -Path "/policy/api/v1$path/nat/USER/nat-rules"
                Set-VsatFact -Asset $a -Name 'natRules' -Value @($nat.items | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ id = Get-VsatProp $_ 'id'; action = Get-VsatProp $_ 'action'; source = Get-VsatProp $_ 'source_network'; destination = Get-VsatProp $_ 'destination_network'; translated = Get-VsatProp $_ 'translated_network'; enabled = [bool](Get-VsatProp $_ "enabled" $true); firewallMatch = Get-VsatProp $_ 'firewall_match' } })
            }
            catch { Set-VsatFact -Asset $a -Name 'natRules' -Status (Get-VsatErrorClass $_) -Value $null -ErrorMessage $_.Exception.Message }
            $count++
        }
        $segs = Get-VsatNsxPaged -Session $Session -Path '/policy/api/v1/infra/segments'
        foreach ($s in $segs.items) {
            $path = [string](Get-VsatProp $s 'path'); $id = "${ep}:$path"
            $subnets = @(Get-VsatProp $s 'subnets' @() | Where-Object { $null -ne $_ } | ForEach-Object { Get-VsatProp $_ 'gateway_address' })
            $conn = Get-VsatProp $s 'connectivity_path'
            $a = Add-VsatAsset -Evidence $Evidence -Id $id -Type 'nsx-segment' -Name (Get-VsatProp $s 'display_name') -Endpoint $ep -Props ([ordered]@{ path = $path; uniqueId = Get-VsatProp $s 'unique_id'; vlanIds = @(Get-VsatProp $s 'vlan_ids' @()); transportZone = Get-VsatProp $s 'transport_zone_path'; connectivityPath = $conn; subnets = $subnets; adminState = Get-VsatProp $s 'admin_state'; type = $(if (@(Get-VsatProp $s 'vlan_ids' @()).Count -gt 0) { 'vlan' } else { 'overlay' }) })
            if ($conn) { Add-VsatRelationship -Evidence $Evidence -Source $id -Target "${ep}:$conn" -Type routes -Provenance 'nsx.networking' }
            $count++
        }
        $(if ($t0s.truncated -or $t1s.truncated -or $segs.truncated) { @{ count = $count; status = 'partial'; error = 'Truncated gateway or segment listing' } } else { $count })
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'nsx.groups' -Endpoint $ep -Affects @('NSX-DFW-*', 'NSX-EFF-*') -Script {
        $groups = Get-VsatNsxPaged -Session $Session -Path '/policy/api/v1/infra/domains/default/groups'
        $n = 0
        foreach ($g in $groups.items) {
            $path = [string](Get-VsatProp $g 'path'); $id = "${ep}:$path"
            $a = Add-VsatAsset -Evidence $Evidence -Id $id -Type 'nsx-group' -Name (Get-VsatProp $g 'display_name') -Endpoint $ep -Props ([ordered]@{ path = $path; expressionCount = @(Get-VsatProp $g 'expression' @()).Count; tags = @(Get-VsatProp $g 'tags' @() | Where-Object { $null -ne $_ } | ForEach-Object { "$(Get-VsatProp $_ 'scope')=$(Get-VsatProp $_ 'tag')" }) })
            if (Test-VsatCancel) { break }
            # Effective (realized) membership; configured expressions alone are insufficient.
            try {
                $vms = Get-VsatNsxPaged -Session $Session -Path "/policy/api/v1$path/members/virtual-machines" -PageSize 1000
                $ips = Get-VsatNsxPaged -Session $Session -Path "/policy/api/v1$path/members/ip-addresses" -PageSize 1000
                $st = if ($vms.truncated -or $ips.truncated) { 'error' } else { 'ok' }
                Set-VsatFact -Asset $a -Name 'members' -Status $st -Value ([ordered]@{
                        vms = @($vms.items | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ externalId = Get-VsatProp $_ 'external_id'; name = Get-VsatProp $_ 'display_name' } })
                        ips = @($ips.items | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
                    })
            }
            catch { Set-VsatFact -Asset $a -Name 'members' -Status (Get-VsatErrorClass $_) -Value $null -ErrorMessage $_.Exception.Message }
            $n++
        }
        $(if ($groups.truncated) { @{ count = $n; status = 'partial'; error = 'Truncated group listing' } } else { $n })
    }

    Invoke-VsatCollector -Evidence $Evidence -Name 'nsx.dfw' -Endpoint $ep -Affects @('NSX-DFW-*', 'NSX-EFF-*') -Script {
        Add-VsatNsxPolicies -Evidence $Evidence -Session $Session -Endpoint $ep -Kind 'security-policies' -ManagerId $mgrId
    }
    Invoke-VsatCollector -Evidence $Evidence -Name 'nsx.gfw' -Endpoint $ep -Affects @('NSX-GFW-*') -Script {
        Add-VsatNsxPolicies -Evidence $Evidence -Session $Session -Endpoint $ep -Kind 'gateway-policies' -ManagerId $mgrId
    }
    Invoke-VsatCollector -Evidence $Evidence -Name 'nsx.inventory' -Endpoint $ep -Affects @('NSX-EFF-*') -Script {
        $vms = Get-VsatNsxPaged -Session $Session -Path '/api/v1/fabric/virtual-machines'
        Set-VsatFact -Asset $mgr -Name 'fabricVms' -Status $(if ($vms.truncated) { 'error' } else { 'ok' }) -Value @($vms.items | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ externalId = Get-VsatProp $_ 'external_id'; name = Get-VsatProp $_ 'display_name'; sourceId = Get-VsatProp $_ 'source.target_id'; powerState = Get-VsatProp $_ 'power_state' } })
        $vms.items.Count
    }
}

function Add-VsatNsxLocaleServices {
    param($Evidence, $Session, $Asset, [string]$Path, [string]$Endpoint)
    try {
        $ls = Get-VsatNsxPaged -Session $Session -Path "/policy/api/v1$Path/locale-services"
        $bgp = @()
        foreach ($l in $ls.items) {
            $ec = Get-VsatProp $l 'edge_cluster_path'
            if ($ec) {
                $ecId = "${Endpoint}:edge-cluster/" + ($ec -split '/')[-1]
                Add-VsatRelationship -Evidence $Evidence -Source $Asset.id -Target $ecId -Type depends -Provenance 'nsx.networking'
            }
            if ($Asset.type -eq 'nsx-t0') {
                try {
                    $b = Invoke-VsatRest -Session $Session -Path ("/policy/api/v1$Path/locale-services/" + (Get-VsatProp $l 'id') + '/bgp')
                    $bgp += [ordered]@{ enabled = Get-VsatProp $b 'enabled'; localAs = Get-VsatProp $b 'local_as_num'; gracefulRestart = Get-VsatProp $b 'graceful_restart_config.mode' }
                }
                catch { }
            }
        }
        Set-VsatFact -Asset $Asset -Name 'localeServices' -Value @($ls.items | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ id = Get-VsatProp $_ 'id'; edgeClusterPath = Get-VsatProp $_ 'edge_cluster_path' } })
        if ($Asset.type -eq 'nsx-t0') { Set-VsatFact -Asset $Asset -Name 'bgp' -Value $bgp }
    }
    catch { Set-VsatFact -Asset $Asset -Name 'localeServices' -Status (Get-VsatErrorClass $_) -Value $null -ErrorMessage $_.Exception.Message }
}

function Add-VsatNsxPolicies {
    param($Evidence, $Session, [string]$Endpoint, [ValidateSet('security-policies', 'gateway-policies')][string]$Kind, [string]$ManagerId)
    $ep = $Endpoint
    $policies = Get-VsatNsxPaged -Session $Session -Path "/policy/api/v1/infra/domains/default/$Kind"
    $count = 0; $partial = $policies.truncated
    $ptype = if ($Kind -eq 'security-policies') { 'dfw' } else { 'gfw' }
    foreach ($p in $policies.items) {
        $path = [string](Get-VsatProp $p 'path'); $polId = "${ep}:$path"
        $pa = Add-VsatAsset -Evidence $Evidence -Id $polId -Type 'nsx-policy' -Name (Get-VsatProp $p 'display_name') -Endpoint $ep -Props ([ordered]@{
                path = $path; firewall = $ptype; category = Get-VsatProp $p 'category'; sequence = [long](Get-VsatProp $p 'sequence_number' 0)
                scope = @(ConvertTo-VsatNsxRef (Get-VsatProp $p 'scope')); stateful = Get-VsatProp $p 'stateful'; isDefault = [bool](Get-VsatProp $p 'is_default' $false)
            })
        try {
            $rules = Get-VsatNsxPaged -Session $Session -Path "/policy/api/v1$path/rules"
            if ($rules.truncated) { $partial = $true }
            foreach ($r in $rules.items) {
                $rpath = [string](Get-VsatProp $r 'path'); $rid = "${ep}:$rpath"
                $ra = Add-VsatAsset -Evidence $Evidence -Id $rid -Type 'nsx-rule' -Name (Get-VsatProp $r 'display_name') -Endpoint $ep -Props ([ordered]@{
                        path = $rpath; firewall = $ptype; policy = $polId; policyName = $pa.name; category = $pa.props.category
                        policySequence = $pa.props.sequence; sequence = [long](Get-VsatProp $r 'sequence_number' 0); ruleId = Get-VsatProp $r 'rule_id'
                        action = [string](Get-VsatProp $r 'action'); direction = Get-VsatProp $r 'direction' 'IN_OUT'; ipProtocol = Get-VsatProp $r 'ip_protocol' 'IPV4_IPV6'
                        sources = @(ConvertTo-VsatNsxRef (Get-VsatProp $r 'source_groups')); sourcesExcluded = [bool](Get-VsatProp $r 'sources_excluded' $false)
                        destinations = @(ConvertTo-VsatNsxRef (Get-VsatProp $r 'destination_groups')); destinationsExcluded = [bool](Get-VsatProp $r 'destinations_excluded' $false)
                        services = @(ConvertTo-VsatNsxRef (Get-VsatProp $r 'services')); profiles = @(ConvertTo-VsatNsxRef (Get-VsatProp $r 'profiles'))
                        appliedTo = @(ConvertTo-VsatNsxRef (Get-VsatProp $r 'scope')); policyAppliedTo = $pa.props.scope
                        disabled = [bool](Get-VsatProp $r 'disabled' $false); logged = [bool](Get-VsatProp $r 'logged' $false)
                        isDefault = ($pa.props.isDefault -or ([string](Get-VsatProp $r 'id') -match '^default-layer[23]-rule$'))
                    })
                Add-VsatRelationship -Evidence $Evidence -Source $polId -Target $rid -Type contains -Provenance "nsx.$ptype"
                foreach ($g in @($ra.props.appliedTo + $ra.props.policyAppliedTo | Where-Object { $_ -ne 'ANY' } | Select-Object -Unique)) {
                    Add-VsatRelationship -Evidence $Evidence -Source $rid -Target "${ep}:$g" -Type applies-to -Provenance "nsx.$ptype"
                }
                $count++
            }
        }
        catch {
            $partial = $true
            Set-VsatFact -Asset $pa -Name 'rules' -Status (Get-VsatErrorClass $_) -Value $null -ErrorMessage $_.Exception.Message
        }
    }
    if ($partial) { return @{ count = $count; status = 'partial'; error = 'One or more policy rule listings were truncated or failed' } }
    return $count
}

#endregion NSX collector
