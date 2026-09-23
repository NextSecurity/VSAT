#region Coverage and status
# Coverage is computed per domain from collector outcomes and check results. UNKNOWN
# and ERROR results never improve coverage, and NSX is a mandatory domain whenever
# VMware infrastructure is in scope.

$script:VsatDomains = @(
    [ordered]@{ id = 'vcenter'; name = 'vCenter'; mandatory = $true; platform = 'vmware'; collectors = @('vsphere.vcenter'); assetTypes = @('vcenter') }
    [ordered]@{ id = 'esxi'; name = 'ESX/ESXi hosts'; mandatory = $true; platform = 'vmware'; collectors = @('vsphere.hosts'); assetTypes = @('host') }
    [ordered]@{ id = 'cluster'; name = 'Clusters'; mandatory = $true; platform = 'vmware'; collectors = @('vsphere.inventory'); assetTypes = @('cluster') }
    [ordered]@{ id = 'vm'; name = 'Virtual machines'; mandatory = $true; platform = 'vmware'; collectors = @('vsphere.vms'); assetTypes = @('vm') }
    [ordered]@{ id = 'network'; name = 'Virtual networking'; mandatory = $true; platform = 'vmware'; collectors = @('vsphere.hosts', 'vsphere.vds'); assetTypes = @('vss', 'vds', 'portgroup', 'dvportgroup') }
    [ordered]@{ id = 'nsx'; name = 'NSX'; mandatory = $true; platform = 'vmware'; collectors = @('nsx.manager', 'nsx.fabric', 'nsx.networking', 'nsx.groups', 'nsx.dfw', 'nsx.gfw', 'nsx.inventory'); assetTypes = @('nsx-manager') }
    [ordered]@{ id = 'storage'; name = 'Storage and recovery'; mandatory = $true; platform = 'vmware'; collectors = @('vsphere.datastores'); assetTypes = @('datastore') }
    [ordered]@{ id = 'hyperv-host'; name = 'Hyper-V hosts'; mandatory = $true; platform = 'hyperv'; collectors = @('hyperv.host'); assetTypes = @('hyperv-host') }
    [ordered]@{ id = 'hyperv-vm'; name = 'Hyper-V virtual machines'; mandatory = $true; platform = 'hyperv'; collectors = @('hyperv.vms'); assetTypes = @('hyperv-vm') }
    [ordered]@{ id = 'hyperv-network'; name = 'Hyper-V virtual switches'; mandatory = $true; platform = 'hyperv'; collectors = @('hyperv.network'); assetTypes = @('hyperv-vswitch') }
    [ordered]@{ id = 'kvm-host'; name = 'KVM/libvirt hosts'; mandatory = $true; platform = 'kvm'; collectors = @('kvm.host'); assetTypes = @('kvm-host') }
    [ordered]@{ id = 'kvm-vm'; name = 'KVM virtual machines'; mandatory = $true; platform = 'kvm'; collectors = @('kvm.vms'); assetTypes = @('kvm-vm') }
    [ordered]@{ id = 'kvm-network'; name = 'KVM virtual networks'; mandatory = $true; platform = 'kvm'; collectors = @('kvm.network'); assetTypes = @('kvm-network') }
)

function Update-VsatNsxDiscovery {
    # Determines whether NSX exists in the vSphere scope from vCenter evidence.
    param([Parameter(Mandatory)]$Evidence)
    $ev = [System.Collections.Generic.List[string]]::new()
    $mgrs = [System.Collections.Generic.List[string]]::new()
    $detected = $false; $unknown = $false; $checked = 0; $legacy = $false
    foreach ($vc in @($Evidence.assets | Where-Object { $_.type -eq 'vcenter' })) {
        $f = if ($vc.facts.Contains('extensions')) { $vc.facts.extensions } else { $null }
        if (-not $f -or ($f.status -ne 'ok' -and $f.status -ne 'absent')) {
            $unknown = $true
            $ev.Add("Cannot read extension list on $($vc.name) ($(if ($f) { $f.status } else { 'not collected' }))")
            continue
        }
        $checked++
        foreach ($x in @($f.value)) {
            if ([string]$x.key -match '(?i)^com\.vmware\.nsx') {
                $detected = $true
                $ev.Add("vCenter $($vc.name) has extension $($x.key) $($x.version)")
                foreach ($u in @($x.urls)) { try { $h = ([uri]$u).Host; if ($h -and -not $mgrs.Contains($h)) { $mgrs.Add($h) } } catch { } }
            }
            elseif ([string]$x.key -match '(?i)vShieldManager') {
                $detected = $true; $legacy = $true
                $ev.Add("vCenter $($vc.name) has NSX-V/vShield extension $($x.key) (legacy; modern adapters cannot assess it)")
            }
        }
        if (-not $detected) { $ev.Add("vCenter $($vc.name): extension list readable, no NSX extension registered") }
    }
    $nsxNets = @($Evidence.assets | Where-Object { $_.type -eq 'dvportgroup' -and ($_.props.backingType -eq 'nsx' -or $_.props.segmentId -or $_.props.logicalSwitchUuid) })
    if ($nsxNets.Count) { $detected = $true; $ev.Add("$($nsxNets.Count) NSX-backed distributed port group(s) found (e.g. $($nsxNets[0].name))") }
    $opaque = @($Evidence.relationships | Where-Object { $_.target -like 'opaque:*' })
    if ($opaque.Count) { $detected = $true; $ev.Add("$($opaque.Count) VM adapter(s) attached to NSX opaque networks") }
    $vsphereEps = @($Evidence.scope.endpoints | Where-Object { $_.type -in @('vcenter', 'esxi') })
    if (-not $detected -and $checked -eq 0) {
        $unknown = $true
        if ($vsphereEps.Count -and -not @($vsphereEps | Where-Object { $_.type -eq 'vcenter' }).Count) { $ev.Add('Only direct ESXi endpoints in scope; NSX registration cannot be determined without vCenter') }
    }
    $status = if ($detected) { 'detected' } elseif ($unknown) { 'unknown' } else { 'not-detected' }
    $Evidence.nsx.discovery = [ordered]@{ status = $status; evidence = @($ev); managersDiscovered = @($mgrs); legacyNsxV = $legacy }
    return $Evidence.nsx.discovery
}

function Get-VsatNsxCoverage {
    param([Parameter(Mandatory)]$Evidence)
    $d = $Evidence.nsx.discovery
    $nsxEps = @($Evidence.scope.endpoints | Where-Object { $_.type -eq 'nsx' })
    $vsEps = @($Evidence.scope.endpoints | Where-Object { $_.type -in @('vcenter', 'esxi') })
    $declared = [bool]$Evidence.scope.nsxDeclaredAbsent
    $evList = @($d.evidence)
    $missing = [System.Collections.Generic.List[string]]::new()
    if ($vsEps.Count -eq 0 -and $nsxEps.Count -eq 0) {
        return [ordered]@{ state = 'NOT_APPLICABLE'; label = 'NOT APPLICABLE: NO VMWARE ENDPOINTS IN SCOPE'; detail = 'NSX applies to VMware infrastructure; no vCenter, ESXi or NSX endpoints are in scope.'; evidence = @('Scope contains no VMware endpoints'); missing = @() }
    }
    if ($nsxEps.Count -gt 0) {
        $failed = @($nsxEps | Where-Object { $_.status -in @('failed', 'not-attempted') })
        $coll = @($Evidence.collection.collectors | Where-Object { $_.name -like 'nsx.*' })
        $bad = @($coll | Where-Object { $_.status -notin @('ok') })
        foreach ($f in $failed) { $missing.Add("NSX Manager $($f.address): $(if ($f.errors.Count) { $f.errors[0] } else { 'not assessed' })") }
        foreach ($b in $bad) { $missing.Add("$($b.name) on $($b.endpoint): $($b.status)$(if ($b.error) { " - $($b.error)" })") }
        $covered = @($nsxEps | ForEach-Object { $_.address.ToLowerInvariant() })
        $undisclosed = @($d.managersDiscovered | Where-Object { $covered -notcontains $_.ToLowerInvariant() })
        # Managers are often registered by VIP/FQDN while the operator used a node address; flag for review.
        foreach ($u in $undisclosed) { $missing.Add("NSX manager registered in vCenter but not in scope: $u (add it, or confirm it is the same cluster)") }
        if ($d.legacyNsxV) { $missing.Add('NSX-V detected: legacy platform requires manual assessment') }
        foreach ($cm in @(Get-VsatProp $Evidence.nsx 'unmatchedComputeManagers' @())) { $missing.Add("NSX compute manager $cm is not in the vCenter scope; its workloads and correlation are not assessed") }
        if ($failed.Count -eq $nsxEps.Count) {
            return [ordered]@{ state = 'INCOMPLETE'; label = 'INCOMPLETE: NSX NOT ASSESSED'; detail = 'NSX Manager endpoints were supplied but could not be assessed.'; evidence = $evList; missing = @($missing) }
        }
        if ($missing.Count) {
            return [ordered]@{ state = 'PARTIAL'; label = 'PARTIAL: NSX PARTLY ASSESSED'; detail = 'Some NSX evidence is missing or additional NSX domains exist; affected checks are UNKNOWN.'; evidence = $evList; missing = @($missing) }
        }
        return [ordered]@{ state = 'ASSESSED'; label = 'NSX ASSESSED'; detail = "$($nsxEps.Count) NSX Manager endpoint(s) assessed."; evidence = $evList; missing = @() }
    }
    if ($declared) {
        switch ($d.status) {
            'not-detected' { return [ordered]@{ state = 'NOT_APPLICABLE'; label = 'NOT APPLICABLE: NSX NOT DEPLOYED'; detail = 'Operator declared NSX absent and discovery evidence agrees. This is not an NSX security pass.'; evidence = @('Operator declaration recorded') + $evList; missing = @() } }
            'detected' { return [ordered]@{ state = 'INCOMPLETE'; label = 'INCOMPLETE: NSX NOT ASSESSED'; detail = 'Operator declared NSX absent, but discovery found NSX. Supply NSX Manager access.'; evidence = @('Operator declaration recorded (conflicts with discovery)') + $evList; missing = @('NSX Manager endpoint and credentials') } }
            default { return [ordered]@{ state = 'REVIEW'; label = 'REVIEW: NSX DECLARED ABSENT, NOT VERIFIED'; detail = 'Operator declared NSX absent; discovery could not confirm. Applicability requires review.'; evidence = @('Operator declaration recorded') + $evList; missing = @('vCenter extension read access (or NSX evidence) to confirm absence') } }
        }
    }
    switch ($d.status) {
        'detected' { return [ordered]@{ state = 'INCOMPLETE'; label = 'INCOMPLETE: NSX NOT ASSESSED'; detail = 'NSX was detected but no NSX Manager endpoint or credentials were supplied.'; evidence = $evList; missing = @('NSX Manager endpoint and credentials' + $(if ($d.managersDiscovered.Count) { " (discovered: $($d.managersDiscovered -join ', '))" } else { '' })) } }
        'not-detected' { return [ordered]@{ state = 'NOT_APPLICABLE'; label = 'NOT APPLICABLE: NSX NOT DEPLOYED'; detail = 'No NSX registration or NSX-backed networks found in the assessed vCenter scope. This is not an NSX security pass.'; evidence = $evList; missing = @() } }
        default { return [ordered]@{ state = 'UNKNOWN'; label = 'UNKNOWN: NSX COVERAGE NOT DETERMINED'; detail = 'NSX presence could not be determined. Supply an NSX Manager endpoint or declare absence with -NsxDeclaredAbsent.'; evidence = $evList; missing = @('NSX Manager endpoint, or vCenter extension read access') } }
    }
}

function Get-VsatCoverage {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)
    $domains = [System.Collections.Generic.List[object]]::new()
    $vsEps = @($Evidence.scope.endpoints | Where-Object { $_.type -in @('vcenter', 'esxi') })
    $hasVc = @($vsEps | Where-Object { $_.type -eq 'vcenter' }).Count -gt 0
    foreach ($def in (Get-VsatDomainDefinitions)) {
        $df = @($Findings | Where-Object { $_.domain -eq $def.id })
        $checks = [ordered]@{ total = $df.Count; PASS = 0; FAIL = 0; MANUAL = 0; UNKNOWN = 0; ERROR = 0; NOT_APPLICABLE = 0 }
        foreach ($f in $df) { $checks[$f.result] = [int]$checks[$f.result] + 1 }
        $d = [ordered]@{ id = $def.id; name = $def.name; mandatory = $def.mandatory; platform = $def.platform; state = 'ASSESSED'; label = ''; detail = ''; evidence = @(); missing = @(); checks = $checks }
        if ($def.id -eq 'nsx') {
            $c = Get-VsatNsxCoverage -Evidence $Evidence
            foreach ($k in 'state', 'label', 'detail', 'evidence', 'missing') { $d[$k] = $c[$k] }
            if ($d.state -eq 'ASSESSED' -and ($checks.UNKNOWN + $checks.ERROR) -gt 0) {
                $d.state = 'PARTIAL'; $d.label = 'PARTIAL: NSX PARTLY ASSESSED'
                $d.missing = @($d.missing) + "$($checks.UNKNOWN + $checks.ERROR) NSX check(s) lack evidence"
            }
            $domains.Add($d); continue
        }
        $platformEps = @(Get-VsatPlatformEndpoints -Evidence $Evidence -Platform $def.platform)
        if ($platformEps.Count -eq 0) {
            $d.state = 'NOT_APPLICABLE'; $d.label = "NOT APPLICABLE: NO $($def.platform.ToUpperInvariant()) ENDPOINTS"; $d.detail = "No $($def.platform) endpoints in scope."
            $d.mandatory = $false
            $domains.Add($d); continue
        }
        if ($def.id -eq 'vcenter' -and $def.platform -eq 'vmware' -and -not $hasVc) {
            $d.state = 'PARTIAL'; $d.label = 'PARTIAL: DIRECT ESXI ONLY'; $d.detail = 'Direct ESXi connections expose no vCenter-level configuration.'; $d.missing = @('vCenter endpoint for centralized configuration')
            $domains.Add($d); continue
        }
        $colls = @($Evidence.collection.collectors | Where-Object { $def.collectors -contains $_.name })
        $failed = @($colls | Where-Object { $_.status -in @('denied', 'error', 'unsupported') })
        $partial = @($colls | Where-Object { $_.status -eq 'partial' })
        $skipped = @($colls | Where-Object { $_.status -eq 'skipped' })
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $failed + $partial) { $missing.Add("$($c.name) on $($c.endpoint): $($c.status)$(if ($c.error) { " - $($c.error)" })") }
        foreach ($c in $skipped) { if ($c.error -ne 'Direct ESXi connection' -and $c.error -ne 'Distributed switches require vCenter') { $missing.Add("$($c.name) skipped: $($c.error)") } }
        if ($colls.Count -eq 0) { $missing.Add('No collector ran for this domain') }
        $gaps = $checks.UNKNOWN + $checks.ERROR
        if ($gaps) { $missing.Add("$gaps check(s) lack evidence (UNKNOWN/ERROR)") }
        $count = @($Evidence.assets | Where-Object { $def.assetTypes -contains $_.type }).Count
        if ($colls.Count -gt 0 -and $failed.Count -eq $colls.Count) { $d.state = 'INCOMPLETE'; $d.label = "INCOMPLETE: $($def.name.ToUpperInvariant()) NOT ASSESSED" }
        elseif ($missing.Count) { $d.state = 'PARTIAL'; $d.label = "PARTIAL: $($def.name.ToUpperInvariant())" }
        else { $d.state = 'ASSESSED'; $d.label = "$($def.name.ToUpperInvariant()) ASSESSED" }
        $d.detail = "$count object(s) in scope; $($checks.total) check result(s)."
        if ($count -eq 0 -and $d.state -eq 'ASSESSED') { $d.detail = 'Collector succeeded; no objects of this type exist in scope (empty scope, not a pass).' }
        $d.missing = @($missing)
        $domains.Add($d)
    }
    $known = @($Findings | Where-Object { $_.result -in @('PASS', 'FAIL', 'NOT_APPLICABLE') }).Count
    return [ordered]@{ domains = $domains.ToArray(); automated = [ordered]@{ known = $known; total = @($Findings | Where-Object { $_.result -ne 'MANUAL' }).Count } }
}

function Get-VsatDomainDefinitions {
    # Platform modules append their domains to $script:VsatDomains at load time.
    return $script:VsatDomains
}

function Get-VsatPlatformEndpoints {
    param($Evidence, [string]$Platform)
    $types = switch ($Platform) { 'vmware' { @('vcenter', 'esxi', 'nsx') } default { @($Platform) } }
    return @($Evidence.scope.endpoints | Where-Object { $types -contains $_.type })
}

function Get-VsatRunStatus {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Coverage, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)
    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($Evidence.run.status -eq 'canceled') {
        return [ordered]@{ overall = 'canceled'; label = 'CANCELED: PARTIAL RESULTS PRESERVED'; exitCode = 4; reasons = @('The run was canceled; collected evidence was preserved.') }
    }
    $eps = @($Evidence.scope.endpoints)
    if ($Evidence.run.mode -eq 'live' -and ($eps.Count -eq 0 -or @($eps | Where-Object { $_.status -in @('collected', 'partial') }).Count -eq 0)) {
        foreach ($e in $eps) { $reasons.Add("$($e.type) $($e.address): $($e.status)$(if ($e.errors.Count) { " - $($e.errors[0])" })") }
        if ($eps.Count -eq 0) { $reasons.Add('No endpoints were supplied.') }
        return [ordered]@{ overall = 'failed'; label = 'FAILED: NO ENDPOINT COULD BE ASSESSED'; exitCode = 3; reasons = @($reasons) }
    }
    $incomplete = @($Coverage.domains | Where-Object { $_.mandatory -and $_.state -notin @('ASSESSED', 'NOT_APPLICABLE') })
    foreach ($d in $incomplete) {
        $reasons.Add("$($d.name): $($d.label)$(if (@($d.missing).Count) { ' - ' + (@($d.missing) | Select-Object -First 2) -join '; ' })")
    }
    $fails = @($Findings | Where-Object { $_.result -eq 'FAIL' }).Count
    $manual = @($Findings | Where-Object { $_.result -eq 'MANUAL' }).Count
    if ($incomplete.Count) {
        $nsx = @($incomplete | Where-Object { $_.id -eq 'nsx' -and $_.state -in @('INCOMPLETE', 'UNKNOWN', 'REVIEW') }) | Select-Object -First 1
        $label = if ($nsx) { $nsx.label } else { 'INCOMPLETE: ' + ((@($incomplete | ForEach-Object { $_.name })) -join ', ').ToUpperInvariant() + ' NOT FULLY ASSESSED' }
        if ($fails) { $reasons.Add("$fails failing automated control(s) found in the assessed scope.") }
        return [ordered]@{ overall = 'incomplete'; label = $label; exitCode = 2; reasons = @($reasons) }
    }
    if ($manual) { $reasons.Add("$manual control(s) require manual review; completion is not certification.") }
    if ($fails) { return [ordered]@{ overall = 'complete'; label = 'COMPLETE: FINDINGS PRESENT'; exitCode = 1; reasons = @("$fails failing automated control(s).") + @($reasons) } }
    return [ordered]@{ overall = 'complete'; label = 'COMPLETE: NO FAILING AUTOMATED CONTROLS'; exitCode = 0; reasons = @($reasons) }
}

#endregion Coverage and status
