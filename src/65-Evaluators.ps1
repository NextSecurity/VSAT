#region Script evaluators
# Named evaluators referenced by rules with check.type = "script".
# Signature: -Rule -Asset -Check -Context ; return one finding.

function Get-VsatBranch {
    param([string]$Version, [int]$Parts = 2)
    if (-not $Version) { return $null }
    $p = $Version.Split('.')
    if ($p.Count -lt $Parts) { return $Version }
    return ($p[0..($Parts - 1)] -join '.')
}

function Get-VsatProductKey {
    param($Asset)
    switch ($Asset.type) {
        'host' { return 'esxi' }
        'vcenter' { return 'vcenter' }
        'nsx-manager' { return 'nsx' }
        default { return $Asset.type }
    }
}

function Invoke-VsatCheckAdvisory {
    param($Rule, $Asset, $Check, $Context)
    $data = Get-VsatAdvisoryData
    $product = Get-VsatProductKey $Asset
    $snap = "advisory snapshot $($data.snapshotDate)"
    $ver = [string]$Asset.version
    if (-not $ver) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Product version not collected' -Expected "No applicable unpatched advisories ($snap)") }
    $branch = Get-VsatBranch $ver
    $build = 0L
    $byVersion = ($product -eq 'nsx')
    if (-not $byVersion -and -not [long]::TryParse([string]$Asset.build, [ref]$build)) {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Build number not collected (version $ver)" -Expected "No applicable unpatched advisories ($snap)")
    }
    $exposed = [System.Collections.Generic.List[object]]::new()
    $hadData = $false
    foreach ($adv in @($data.advisories)) {
        $entries = @($adv.affected | Where-Object { $_.product -eq $product -and $_.branch -eq $branch })
        if ($entries.Count -eq 0) { continue }
        $hadData = $true
        # Select the fix line(s): greatest lower bound not above the observed build/version.
        if ($byVersion) {
            $cand = @($entries | Where-Object { -not $_.Contains('minVersion') -or (Compare-VsatVersion $ver $_.minVersion) -ge 0 })
            if ($cand.Count -eq 0) { continue }
            $best = ($cand | ForEach-Object { if ($_.Contains('minVersion')) { $_.minVersion } else { '0' } } | Sort-Object { [version](($_ + '.0.0.0').Split('.')[0..3] -join '.') } | Select-Object -Last 1)
            $sel = @($cand | Where-Object { ($(if ($_.Contains('minVersion')) { $_.minVersion } else { '0' })) -eq $best })
            foreach ($e in $sel) {
                if ($null -eq $e.fixedVersionNumber -or (Compare-VsatVersion $ver $e.fixedVersionNumber) -lt 0) { $exposed.Add([ordered]@{ id = $adv.id; severity = $adv.severity; kev = [bool]$adv.knownExploited; fix = $e.fixedVersion; cves = @($(if ($e.Contains('cves')) { $e.cves } else { $adv.cves })) }) }
            }
        }
        else {
            # Broadcom build numbers are not ordered across update lines (e.g. 8.0 U2d > 8.0 U3 GA),
            # so select the fix line by update level first and compare builds only within it.
            $hostUpd = $null
            $vp = $ver.Split('.')
            if ($vp.Count -ge 3) { $tmp = 0; if ([int]::TryParse($vp[2], [ref]$tmp)) { $hostUpd = $tmp } }
            $withUpd = @($entries | ForEach-Object { $u = $null; if ([string]$_.fixedVersion -match 'Update\s+(\d+)') { $u = [int]$Matches[1] } elseif ($_.fixedVersion) { $u = 0 }; @{ e = $_; u = $u } })
            $sel = @()
            if ($null -ne $hostUpd -and @($withUpd | Where-Object { $null -ne $_.u }).Count -eq $withUpd.Count) {
                $same = @($withUpd | Where-Object { $_.u -eq $hostUpd })
                if ($same.Count) { $sel = @($same | ForEach-Object { $_.e }) }
                else {
                    $higher = @($withUpd | Where-Object { $_.u -gt $hostUpd } | Sort-Object { $_.u })
                    if ($higher.Count) { $lowest = $higher[0].u; $sel = @($higher | Where-Object { $_.u -eq $lowest } | ForEach-Object { $_.e }) }
                    else { $top = ($withUpd | ForEach-Object { $_.u } | Measure-Object -Maximum).Maximum; $sel = @($withUpd | Where-Object { $_.u -eq $top } | ForEach-Object { $_.e }) }
                }
            }
            if ($sel.Count -eq 0) {
                $cand = @($entries | Where-Object { [long](Get-VsatProp $_ 'minBuild' 0) -le $build })
                if ($cand.Count -eq 0) { continue }
                $maxMin = ($cand | ForEach-Object { [long](Get-VsatProp $_ 'minBuild' 0) } | Measure-Object -Maximum).Maximum
                $sel = @($cand | Where-Object { [long](Get-VsatProp $_ 'minBuild' 0) -eq $maxMin })
            }
            foreach ($e in $sel) {
                $fb = Get-VsatProp $e 'fixedBuild'
                if ($null -eq $fb -or $build -lt [long]$fb) {
                    $exposed.Add([ordered]@{ id = $adv.id; severity = $adv.severity; kev = [bool]$adv.knownExploited; fix = $(if ($e.fixedVersion) { $e.fixedVersion } else { 'no public fix for this line' }); cves = @($(if ($e.Contains('cves')) { $e.cves } else { $adv.cves })) })
                }
            }
        }
    }
    $obsBase = "$product $ver" + $(if ($build) { " build $build" } else { '' })
    if (-not $hadData) {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "$obsBase; no advisory data for branch $branch in $snap" -Expected 'Build at or above fixed builds of applicable advisories' -Note 'Absence of advisory data is not evidence of safety.')
    }
    if ($exposed.Count -eq 0) {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "$obsBase; not below fixed builds of advisories in $snap" -Expected 'Build at or above fixed builds of applicable advisories' -Note 'Advisories published after the snapshot date are not evaluated.')
    }
    $uniq = @{}
    foreach ($x in $exposed) { $uniq[$x.id] = $x }
    $items = @($uniq.Values)
    $sev = 'medium'
    if (@($items | Where-Object { $_.severity -eq 'critical' -or $_.kev }).Count) { $sev = 'critical' }
    elseif (@($items | Where-Object { $_.severity -eq 'important' }).Count) { $sev = 'high' }
    $desc = ($items | Sort-Object { $_.id } | ForEach-Object { "$($_.id)$(if ($_.kev) { ' [known exploited]' }) -> $($_.fix)" }) -join '; '
    $f = New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "$obsBase exposed: $desc" -Expected "Build at or above fixed builds ($snap)" -Severity $sev -Note 'Version exposure is not proof of exploitability; verify vendor workarounds and OEM images.'
    $f.advisories = $items
    return $f
}

function Invoke-VsatCheckLifecycle {
    param($Rule, $Asset, $Check, $Context)
    $data = Get-VsatAdvisoryData
    $product = Get-VsatProductKey $Asset
    $ver = [string]$Asset.version
    if (-not $ver) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Version not collected' -Expected 'Supported release') }
    $branch = Get-VsatBranch $ver
    $major = $ver.Split('.')[0]
    $row = @($data.lifecycle | Where-Object { $_.product -eq $product -and ($_.branch -eq $branch -or $_.branch -eq "$major.x") }) | Select-Object -First 1
    if (-not $row) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "$product $ver; no lifecycle data for $branch" -Expected 'Release within general support') }
    $now = $Context.now
    $eogs = Get-VsatProp $row 'endOfGeneralSupport'; $eotg = Get-VsatProp $row 'endOfTechnicalGuidance'
    if ($eogs -and [DateTime]::Parse($eogs, [Globalization.CultureInfo]::InvariantCulture) -lt $now) {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "$product $branch end of general support $eogs$(if ($eotg) { "; technical guidance ends $eotg" })" -Expected 'Release within general support' -Note 'Out-of-support releases no longer receive routine security fixes.')
    }
    if (-not $eogs) {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result MANUAL -Observed "$product $branch end-of-general-support date not verified in data snapshot$(if ($eotg) { "; technical guidance ends $eotg" })" -Expected 'Confirm support status in the vendor lifecycle portal')
    }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "$product $branch general support until $eogs" -Expected 'Release within general support')
}

function Invoke-VsatCheckPasswordQuality {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'advanced' -Key 'Security.PasswordQualityControl'
    $min = [int]$Check.minLength
    $exp = "Security.PasswordQualityControl enforces minimum length >= $min for every character-class count"
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($r.state -eq 'missing-key') { 'UNKNOWN' } else { Get-VsatEvidenceGapResult $r.state }) -Observed (Get-VsatGapText $r 'advanced') -Expected $exp -Facts @('advanced')) }
    $v = [string]$r.value
    if ($v -notmatch 'min=([^\s]+)') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Security.PasswordQualityControl = $v" -Expected $exp -Facts @('advanced')) }
    $parts = $Matches[1].Split(',')
    $numeric = @($parts | Where-Object { $_ -ne 'disabled' })
    $ok = ($parts.Count -eq 5 -and $numeric.Count -gt 0 -and @($numeric | Where-Object { [int]$_ -lt $min }).Count -eq 0)
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($ok) { 'PASS' } else { 'FAIL' }) -Observed "Security.PasswordQualityControl = $v" -Expected $exp -Facts @('advanced'))
}

function Invoke-VsatCheckNtp {
    param($Rule, $Asset, $Check, $Context)
    $n = Resolve-VsatFactValue -Asset $Asset -Fact 'ntp'
    $s = Resolve-VsatFactValue -Asset $Asset -Fact 'services'
    $minServers = [int](Get-VsatProp $Check 'minServers' 1)
    $exp = "At least $minServers time source(s) configured and the time service running"
    if ($n.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $n.state) -Observed (Get-VsatGapText $n 'ntp') -Expected $exp -Facts @('ntp')) }
    $servers = @($n.value.servers | Where-Object { $_ })
    $running = $null
    if ($s.state -eq 'ok') { $running = [bool](@($s.value | Where-Object { $_.key -in @('ntpd', 'ptpd') -and $_.running }).Count) }
    $ok = ($servers.Count -ge $minServers -and $running -ne $false)
    $obs = "servers: $(Format-VsatValue $servers); service running: $(if ($null -eq $running) { 'unknown' } else { $running })"
    $res = if ($ok -and $null -eq $running) { 'UNKNOWN' } elseif ($ok) { 'PASS' } else { 'FAIL' }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $res -Observed $obs -Expected $exp -Facts @('ntp', 'services'))
}

function Invoke-VsatCheckSyslogRemote {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'advanced' -Key 'Syslog.global.logHost'
    $exp = 'Syslog.global.logHost set to an authorized remote collector'
    if ($r.state -eq 'missing-key') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed 'Syslog.global.logHost not set' -Expected $exp -Facts @('advanced')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'advanced') -Expected $exp -Facts @('advanced')) }
    $v = [string]$r.value
    if (-not $v.Trim()) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed 'Syslog.global.logHost is empty' -Expected $exp -Facts @('advanced')) }
    $auth = @($Context.scope.authorizedSyslogTargets)
    if ($auth.Count -gt 0) {
        $targets = @($v.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $bad = @($targets | Where-Object { $t = $_; -not @($auth | Where-Object { $t -like "*$_*" }).Count })
        if ($bad.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Unauthorized syslog target(s): $($bad -join ', ')" -Expected $exp -Facts @('advanced')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "Syslog.global.logHost = $v" -Expected $exp -Facts @('advanced'))
    }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "Syslog.global.logHost = $v" -Expected $exp -Facts @('advanced') -Note 'Authorized targets not supplied in scope; destination not validated.')
}

function Invoke-VsatCheckCoredump {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'coredump'
    $exp = 'Network core dump collector enabled'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'coredump') -Expected $exp -Facts @('coredump')) }
    $ok = [bool]$r.value.networkEnabled
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($ok) { 'PASS' } else { 'FAIL' }) -Observed "network enabled: $($r.value.networkEnabled); server: $(Format-VsatValue $r.value.networkServer); active dump files: $($r.value.fileActive)" -Expected $exp -Facts @('coredump'))
}

function Invoke-VsatCheckFirewallAllIp {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'firewall'
    $exp = 'Enabled management rulesets restrict allowed source IPs'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'firewall') -Expected $exp -Facts @('firewall')) }
    $mgmt = @($Check.rulesets)
    $open = @($r.value.rulesets | Where-Object { $_.enabled -and $_.allIp -and $mgmt -contains $_.key } | ForEach-Object { $_.key })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($open.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($open.Count) { "Open to all IPs: $($open -join ', ')" } else { 'No enabled management ruleset allows all IPs' }) -Expected $exp -Facts @('firewall'))
}

function Invoke-VsatCheckCertExpiry {
    param($Rule, $Asset, $Check, $Context)
    $fact = [string]$Check.fact
    $r = Resolve-VsatFactValue -Asset $Asset -Fact $fact
    $days = [int](Get-VsatProp $Check 'days' 30)
    $exp = "Certificates valid for more than $days days"
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'No certificate reported' -Expected $exp -Facts @($fact)) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r $fact) -Expected $exp -Facts @($fact)) }
    $certs = @($r.value)
    $bad = @(); $unknown = 0
    foreach ($c in $certs) {
        if (-not $c.notAfter) { $unknown++; continue }
        $na = [DateTime]::Parse($c.notAfter, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
        if ($na -lt $Context.now.AddDays($days)) { $bad += "$(if ($c.Contains('name') -and $c.name) { $c.name } else { $c.subject }) expires $($c.notAfter)" }
    }
    if ($bad.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed ($bad -join '; ') -Expected $exp -Facts @($fact)) }
    if ($unknown -eq $certs.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Certificate expiry could not be parsed' -Expected $exp -Facts @($fact)) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "$($certs.Count - $unknown) certificate(s) valid beyond $days days" -Expected $exp -Facts @($fact))
}

function Invoke-VsatCheckIscsiChap {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'iscsiAdapters'
    $exp = 'Every iSCSI adapter requires unidirectional and mutual CHAP'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'iscsiAdapters') -Expected $exp -Facts @('iscsiAdapters')) }
    $ads = @($r.value)
    if ($ads.Count -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No iSCSI adapters' -Expected $exp -Facts @('iscsiAdapters')) }
    $bad = @($ads | Where-Object { $_.chapLevel -ne 'required' -or $_.mutualChapLevel -ne 'required' } | ForEach-Object { "$($_.adapter) chap=$(Format-VsatValue $_.chapLevel) mutual=$(Format-VsatValue $_.mutualChapLevel)" })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { $bad -join '; ' } else { "$($ads.Count) adapter(s) require mutual CHAP" }) -Expected $exp -Facts @('iscsiAdapters'))
}

function Invoke-VsatCheckVmkSeparation {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'vmkernel'
    $exp = 'Management, vMotion and storage traffic on separate VMkernel adapters'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'vmkernel') -Expected $exp -Facts @('vmkernel')) }
    $shared = @($r.value | Where-Object { $s = @($_.services); ($s -contains 'management') -and (($s -contains 'vmotion') -or ($s -contains 'vsan') -or ($s -contains 'vSphereProvisioning')) } | ForEach-Object { "$($_.device): $(@($_.services) -join ',')" })
    $noSvc = @($r.value | Where-Object { -not $_.Contains('services') }).Count
    if ($noSvc -eq @($r.value).Count -and $noSvc -gt 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'VMkernel service tags not readable' -Expected $exp -Facts @('vmkernel')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($shared.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($shared.Count) { "Shared: $($shared -join '; ')" } else { "$(@($r.value).Count) VMkernel adapter(s), no management sharing" }) -Expected $exp -Facts @('vmkernel') -Note 'VLAN separation is not proof of firewall isolation.')
}

function Invoke-VsatCheckVmDevices {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'devices'
    $types = @($Check.deviceTypes)
    $connectedOnly = [bool](Get-VsatProp $Check 'connectedOnly' $false)
    $exp = if ($connectedOnly) { "No connected $($types -join '/') devices" } else { "No $($types -join '/') devices present" }
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No devices reported' -Expected $exp -Facts @('devices')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'devices') -Expected $exp -Facts @('devices')) }
    $hits = @($r.value | Where-Object { $types -contains $_.type -and (-not $connectedOnly -or $_.connected -or $_.startConnected) })
    if ($Check.Contains('diskMode')) { $hits = @($r.value | Where-Object { $_.type -eq 'VirtualDisk' -and @($Check.diskMode) -contains $_.mode }) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($hits.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($hits.Count) { ($hits | ForEach-Object { "$($_.label)$(if ($_.connected) { ' (connected)' })" }) -join '; ' } else { 'None' }) -Expected $exp -Facts @('devices'))
}

function Invoke-VsatCheckSnapshotAge {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'snapshots'
    $max = [int]$Check.maxDays
    $exp = "No snapshots older than $max days"
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No snapshots' -Expected $exp -Facts @('snapshots')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'snapshots') -Expected $exp -Facts @('snapshots')) }
    $old = @($r.value | Where-Object { [int]$_.ageDays -gt $max })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($old.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($old.Count) { ($old | ForEach-Object { "'$($_.name)' $($_.ageDays)d" }) -join '; ' } else { "$(@($r.value).Count) snapshot(s), none older than $max days" }) -Expected $exp -Facts @('snapshots') -Note 'A snapshot is not a backup.')
}

function Invoke-VsatCheckVmTools {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'security'
    $exp = 'VMware Tools current or supported'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'security') -Expected $exp -Facts @('security')) }
    $st = [string]$r.value.toolsStatus
    if ($Asset.props.powerState -ne 'poweredOn') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "VM is $($Asset.props.powerState); Tools status not evaluated" -Expected $exp -Facts @('security')) }
    $res = switch -Regex ($st) { '^guestTools(Current|Supported|Unmanaged)$' { 'PASS' } '^guestTools(NeedUpgrade|TooOld|Blacklisted|TooNew|NotInstalled)$' { 'FAIL' } default { 'UNKNOWN' } }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $res -Observed "toolsVersionStatus2 = $(Format-VsatValue $st)" -Expected $exp -Facts @('security'))
}

function Invoke-VsatCheckNativeVlan {
    param($Rule, $Asset, $Check, $Context)
    $vlan = $Asset.props.vlan
    $exp = 'Port group VLAN differs from the upstream native VLAN'
    $scoped = @($Context.scope.nativeVlans | Where-Object { $_.switch -eq '*' -or $Asset.name -like "*$($_.switch)*" -or [string]$Asset.props.vswitch -eq $_.switch })
    $native = $null; $source = $null
    if ($scoped.Count) { $native = [int]$scoped[0].vlan; $source = 'operator scope' }
    else {
        # CDP reports the upstream native VLAN for the uplink; LLDP may report the port VLAN ID.
        $hostId = ($Asset.id -split '/pg/')[0]
        $vals = @()
        foreach ($rel in @($Context.out[$hostId])) {
            if ($rel.type -ne 'contains') { continue }
            foreach ($n in @($Context.out[$rel.target])) { if ($n.type -eq 'neighbor' -and $n.props.nativeVlan) { $vals += [int]$n.props.nativeVlan } }
        }
        $vals = @($vals | Select-Object -Unique)
        if ($vals.Count -eq 1) { $native = $vals[0]; $source = 'CDP/LLDP neighbor evidence' }
    }
    if ($null -eq $native) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "VLAN $vlan; upstream native VLAN not known (supply nativeVlans in the scope file or enable CDP/LLDP)" -Expected $exp -Facts @('props')) }
    $ok = ([int]$vlan -ne $native)
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($ok) { 'PASS' } else { 'FAIL' }) -Observed "VLAN $vlan; native VLAN $native ($source)" -Expected $exp -Facts @('props') -Confidence $(if ($source -eq 'operator scope') { 'observed' } else { 'inferred' }))
}

function Invoke-VsatCheckReservedVlan {
    param($Rule, $Asset, $Check, $Context)
    $vlans = @($Asset.props.vlan)
    $reserved = @($Check.reserved)
    $exp = "VLAN not in reserved range(s) $($reserved -join ', ')"
    $bad = @()
    foreach ($v in $vlans) {
        $n = 0
        if (-not [int]::TryParse([string]$v, [ref]$n)) { continue }
        foreach ($rg in $reserved) { $p = $rg.Split('-'); if ($n -ge [int]$p[0] -and $n -le [int]$p[-1]) { $bad += $n } }
    }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed "VLAN $(Format-VsatValue $vlans)" -Expected $exp -Facts @('props'))
}

function Invoke-VsatCheckNetflowCollector {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'policy' -Path 'netflow'
    $exp = 'NetFlow/IPFIX exported only to authorized collectors'
    if ($r.state -eq 'missing-key') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'IPFIX not configured' -Expected $exp -Facts @('policy')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'policy') -Expected $exp -Facts @('policy')) }
    $ip = [string]$r.value.collectorIp
    if (-not $ip) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No IPFIX collector configured' -Expected $exp -Facts @('policy')) }
    $auth = @($Context.scope.authorizedNetflowCollectors)
    if ($auth.Count -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result MANUAL -Observed "Collector $ip (authorized list not supplied)" -Expected $exp -Facts @('policy')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($auth -contains $ip) { 'PASS' } else { 'FAIL' }) -Observed "Collector $ip" -Expected $exp -Facts @('policy'))
}

function Invoke-VsatCheckHealthCheck {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'policy' -Path 'healthCheck'
    $exp = 'VDS health check disabled'
    if ($r.state -eq 'missing-key') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No health check configuration reported' -Expected $exp -Facts @('policy') -Confidence inferred) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'policy') -Expected $exp -Facts @('policy')) }
    $on = @($r.value | Where-Object { $_.enabled } | ForEach-Object { $_.type })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($on.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($on.Count) { "Enabled: $($on -join ', ')" } else { 'Disabled' }) -Expected $exp -Facts @('policy'))
}

function Invoke-VsatCheckPortOverrides {
    param($Rule, $Asset, $Check, $Context)
    $exp = 'No individual ports override the portgroup security policy to accept'
    if (-not $Asset.facts.Contains('portOverrides')) {
        $allowed = Get-VsatProp $Asset.facts 'policy.value.overrides.security'
        if ($allowed -eq $false) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'Security policy override not allowed' -Expected $exp -Facts @('policy')) }
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Per-port settings not collected' -Expected $exp -Facts @('policy'))
    }
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'portOverrides'
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No permissive port overrides' -Expected $exp -Facts @('portOverrides')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'portOverrides') -Expected $exp -Facts @('portOverrides')) }
    $bad = @($r.value)
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { ($bad | ForEach-Object { "port $($_.port): $(Format-VsatValue $_.security)" }) -join '; ' } else { 'No permissive port overrides' }) -Expected $exp -Facts @('portOverrides'))
}

function Invoke-VsatCheckUplinkRedundancy {
    param($Rule, $Asset, $Check, $Context)
    $up = @($Asset.props.uplinks | Where-Object { $_ })
    $exp = 'At least two physical uplinks'
    if ($Asset.type -eq 'vds') { $up = @(Get-VsatProp $Asset.facts 'policy.value.uplinks' @()) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($up.Count -ge 2) { 'PASS' } else { 'FAIL' }) -Observed "$($up.Count) uplink(s)" -Expected $exp -Facts @('props'))
}

function Invoke-VsatCheckVcAdminUsers {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'permissions'
    $exp = 'Administrator role granted to groups, not individual users (break-glass account excepted)'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'permissions') -Expected $exp -Facts @('permissions')) }
    $users = @($r.value | Where-Object { $_.role -eq 'Admin' -and -not $_.isGroup -and $_.principal -notmatch '^(VSPHERE\.LOCAL\\Administrator|administrator@vsphere\.local)$' -and $_.principal -notmatch '(?i)vpxd-extension|vsphere-webclient|vpxd-|machine-' } | ForEach-Object { "$($_.principal) on $($_.entity)" })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($users.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($users.Count) { $users -join '; ' } else { 'Only groups or the SSO administrator hold Admin' }) -Expected $exp -Facts @('permissions'))
}

# ---- NSX evaluators --------------------------------------------------------

function Get-VsatNsxRules {
    param($Context, [string]$Endpoint, [string]$Firewall = 'dfw')
    return @($Context.evidence.assets | Where-Object { $_.type -eq 'nsx-rule' -and $_.endpoint -eq $Endpoint -and $_.props.firewall -eq $Firewall } |
            Sort-Object { Get-VsatCategoryOrder $_.props.category }, { [long]$_.props.policySequence }, { [long]$_.props.sequence })
}

function Get-VsatCategoryOrder {
    param([string]$Category)
    $order = @('Ethernet', 'Emergency', 'Infrastructure', 'Environment', 'Application', 'SystemRules', 'SharedPreRules', 'LocalGatewayRules', 'AutoServiceRules', 'Default')
    $i = [array]::IndexOf($order, $Category)
    if ($i -lt 0) { return 50 }
    return $i
}

function Invoke-VsatCheckNsxDefaultRule {
    param($Rule, $Asset, $Check, $Context)
    $rules = @(Get-VsatNsxRules $Context $Asset.endpoint 'dfw')
    $def = @($rules | Where-Object { $_.props.isDefault -and $_.props.category -eq 'Application' -and $_.props.path -match 'layer3' }) | Select-Object -Last 1
    if (-not $def) { $def = @($rules | Where-Object { $_.props.isDefault }) | Select-Object -Last 1 }
    $mode = [string](Get-VsatProp $Check 'mode' 'action')
    $exp = if ($mode -eq 'log') { 'Default layer-3 rule logs matched traffic' } else { 'Default layer-3 DFW rule action is DROP or REJECT' }
    if (-not $def) {
        $coll = @($Context.evidence.collection.collectors | Where-Object { $_.name -eq 'nsx.dfw' -and $_.endpoint -eq $Asset.endpoint }) | Select-Object -First 1
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($coll -and $coll.status -eq 'ok') { 'UNKNOWN' } else { 'UNKNOWN' }) -Observed "Default layer-3 rule not found in collected policy (collector: $(if ($coll) { $coll.status } else { 'not run' }))" -Expected $exp)
    }
    if ($mode -eq 'log') {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($def.props.logged) { 'PASS' } else { 'FAIL' }) -Observed "$($def.name): logged=$($def.props.logged)" -Expected $exp)
    }
    $ok = @('DROP', 'REJECT') -contains ([string]$def.props.action).ToUpperInvariant()
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($ok) { 'PASS' } else { 'FAIL' }) -Observed "$($def.name): action=$($def.props.action)" -Expected $exp)
}

function Invoke-VsatCheckNsxRuleBroad {
    param($Rule, $Asset, $Check, $Context)
    $p = $Asset.props
    $mode = [string]$Check.mode
    if ($p.isDefault) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Default rule (evaluated separately)' -Expected '' -Facts @('props')) }
    if ($p.disabled) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Rule disabled' -Expected '' -Facts @('props')) }
    if (([string]$p.action).ToUpperInvariant() -ne 'ALLOW') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "action=$($p.action)" -Expected 'Not a broad allow' -Facts @('props')) }
    $anySrc = (@($p.sources) -contains 'ANY') -and -not $p.sourcesExcluded
    $anyDst = (@($p.destinations) -contains 'ANY') -and -not $p.destinationsExcluded
    $anySvc = (@($p.services) -contains 'ANY')
    $anyScope = (@($p.appliedTo) -contains 'ANY') -and (@($p.policyAppliedTo) -contains 'ANY')
    $obs = "sources=$(Format-VsatValue $p.sources); destinations=$(Format-VsatValue $p.destinations); services=$(Format-VsatValue $p.services); appliedTo=$(Format-VsatValue $p.appliedTo)"
    switch ($mode) {
        'anyany' { $bad = ($anySrc -and $anyDst -and $anySvc); $exp = 'No enabled ALLOW rule with source, destination and service all ANY' }
        'anyservice' { $bad = (-not ($anySrc -and $anyDst)) -and $anySvc -and ($anySrc -or $anyDst); $exp = 'ALLOW rules with ANY source or destination restrict services' }
        'appliedto' { $bad = $anyScope; $exp = 'ALLOW rules scope Applied-To to relevant groups instead of DFW-wide' }
        default { throw "Unknown mode $mode" }
    }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad) { 'FAIL' } else { 'PASS' }) -Observed $obs -Expected $exp -Facts @('props'))
}

function Invoke-VsatCheckNsxRuleHygiene {
    param($Rule, $Asset, $Check, $Context)
    $p = $Asset.props
    switch ([string]$Check.mode) {
        'disabled' { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($p.disabled) { 'FAIL' } else { 'PASS' }) -Observed "disabled=$($p.disabled)" -Expected 'No stale disabled rules' -Facts @('props')) }
        'logging' {
            if ($p.disabled -or $p.isDefault) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Disabled or default rule' -Expected '' -Facts @('props')) }
            $deny = @('DROP', 'REJECT') -contains ([string]$p.action).ToUpperInvariant()
            if (-not $deny) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "action=$($p.action)" -Expected '' -Facts @('props')) }
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($p.logged) { 'PASS' } else { 'FAIL' }) -Observed "action=$($p.action) logged=$($p.logged)" -Expected 'Deny rules log matched traffic' -Facts @('props'))
        }
    }
}

function Invoke-VsatCheckNsxEmptyGroups {
    param($Rule, $Asset, $Check, $Context)
    $p = $Asset.props
    $exp = 'Every group referenced by the rule has realized effective members'
    if ($p.disabled) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Rule disabled' -Expected $exp -Facts @('props')) }
    $refs = @(@($p.sources) + @($p.destinations) + @($p.appliedTo) | Where-Object { $_ -ne 'ANY' -and $_ -like '*/groups/*' } | Select-Object -Unique)
    if ($refs.Count -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Rule references no groups' -Expected $exp -Facts @('props')) }
    $empty = @(); $unknown = @()
    foreach ($g in $refs) {
        $ga = $Context.assets["$($Asset.endpoint):$g"]
        if (-not $ga -or -not $ga.facts.Contains('members') -or $ga.facts.members.status -ne 'ok') { $unknown += $g; continue }
        $m = $ga.facts.members.value
        if (@($m.vms).Count -eq 0 -and @($m.ips).Count -eq 0) { $empty += $ga.name }
    }
    if ($empty.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Groups with no effective members: $($empty -join ', ')" -Expected $exp -Facts @('props') -Note 'Configured policy without effective members may not enforce as intended (Broadcom KB 414765).') }
    if ($unknown.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Effective membership unavailable for: $($unknown -join ', ')" -Expected $exp -Facts @('props')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "$($refs.Count) referenced group(s) have effective members" -Expected $exp -Facts @('props'))
}

function Test-VsatNsxSetCovers {
    # $true when set A (earlier rule) covers set B (later rule) for the same dimension.
    param($A, $B)
    if (@($A) -contains 'ANY') { return $true }
    if (@($B) -contains 'ANY') { return $false }
    foreach ($x in @($B)) { if (@($A) -notcontains $x) { return $false } }
    return $true
}

function Invoke-VsatCheckNsxShadow {
    param($Rule, $Asset, $Check, $Context)
    $p = $Asset.props
    $exp = 'Rule is reachable (not fully covered by an earlier enabled rule)'
    if ($p.disabled -or $p.isDefault) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Disabled or default rule' -Expected $exp -Facts @('props')) }
    if ($p.sourcesExcluded -or $p.destinationsExcluded -or (@($p.profiles) -notcontains 'ANY')) {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result MANUAL -Observed 'Rule uses negation or context profiles; shadowing requires manual review' -Expected $exp -Facts @('props'))
    }
    $key = "shadow:$($Asset.endpoint):$($p.firewall)"
    if (-not $Context.Contains($key)) { $Context[$key] = @(Get-VsatNsxRules $Context $Asset.endpoint $p.firewall) }
    $ordered = $Context[$key]
    foreach ($e in $ordered) {
        if ($e.id -eq $Asset.id) { break }
        $q = $e.props
        if ($q.disabled -or $q.sourcesExcluded -or $q.destinationsExcluded -or (@($q.profiles) -notcontains 'ANY')) { continue }
        if (([string]$q.action).ToUpperInvariant() -eq 'JUMP_TO_APPLICATION') { continue }
        $dirOk = ($q.direction -eq 'IN_OUT' -or $q.direction -eq $p.direction)
        $protoOk = ($q.ipProtocol -eq 'IPV4_IPV6' -or $q.ipProtocol -eq $p.ipProtocol)
        $scopeA = if (@($q.appliedTo) -contains 'ANY') { $q.policyAppliedTo } else { $q.appliedTo }
        $scopeB = if (@($p.appliedTo) -contains 'ANY') { $p.policyAppliedTo } else { $p.appliedTo }
        if ($dirOk -and $protoOk -and (Test-VsatNsxSetCovers $q.sources $p.sources) -and (Test-VsatNsxSetCovers $q.destinations $p.destinations) -and (Test-VsatNsxSetCovers $q.services $p.services) -and (Test-VsatNsxSetCovers $scopeA $scopeB)) {
            $same = ([string]$q.action -eq [string]$p.action)
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Fully covered by earlier rule '$($e.name)' ($($q.category) / $($q.policyName)); earlier action $($q.action)$(if ($same) { ' (redundant)' } else { ' (conflicting - this rule never matches)' })" -Expected $exp -Facts @('props') -Confidence inferred -Severity $(if ($same) { 'low' } else { 'medium' }))
        }
    }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'No earlier rule fully covers this rule' -Expected $exp -Facts @('props') -Confidence inferred)
}

function Invoke-VsatCheckNsxExcludeList {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'excludeList'
    $exp = 'DFW exclusion list contains only system-required members'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'excludeList') -Expected $exp -Facts @('excludeList')) }
    $members = @(Get-VsatProp $r.value 'members' @()) + @(Get-VsatProp $r.value 'member.members' @())
    $members = @($members | Where-Object { $_ -and [string]$_ -notmatch '(?i)system|nsx-manager|edge|service-vm|SVM' })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($members.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($members.Count) { "Excluded: $(Format-VsatValue $members)" } else { 'No user-defined exclusions' }) -Expected $exp -Facts @('excludeList') -Note 'Excluded workloads receive no distributed firewall enforcement.')
}

function Invoke-VsatCheckNsxGatewayDefault {
    param($Rule, $Asset, $Check, $Context)
    $rules = @(Get-VsatNsxRules $Context $Asset.endpoint 'gfw' | Where-Object { $_.props.isDefault -or $_.props.category -eq 'Default' })
    $exp = 'Gateway firewall default rules drop unmatched traffic on Tier-0/Tier-1 gateways'
    $coll = @($Context.evidence.collection.collectors | Where-Object { $_.name -eq 'nsx.gfw' -and $_.endpoint -eq $Asset.endpoint }) | Select-Object -First 1
    if (-not $coll -or $coll.status -notin @('ok', 'partial')) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "Gateway policy not collected ($(if ($coll) { $coll.status } else { 'not run' }))" -Expected $exp) }
    if ($rules.Count -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result MANUAL -Observed 'No default gateway rules returned; confirm per-gateway default action in the UI' -Expected $exp) }
    $allow = @($rules | Where-Object { ([string]$_.props.action).ToUpperInvariant() -eq 'ALLOW' -and -not $_.props.disabled } | ForEach-Object { "$($_.name) [$(Format-VsatValue $_.props.appliedTo)]" })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($allow.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($allow.Count) { "Default ALLOW: $($allow -join '; ')" } else { "$($rules.Count) default gateway rule(s) deny" }) -Expected $exp)
}

function Invoke-VsatCheckNsxIds {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'idsClusters'
    $exp = 'Distributed IDS/IPS enabled where licensed and required'
    if ($r.state -eq 'unsupported' -or $r.state -eq 'denied') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "IDS/IPS API $($r.state) (feature may be unlicensed or unavailable in this release)" -Expected $exp -Facts @('idsClusters') -Note 'A missing license is a capability gap, not a benchmark violation.') }
    if ($r.state -ne 'ok' -and $r.state -ne 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'idsClusters') -Expected $exp -Facts @('idsClusters')) }
    $on = @(@($r.value) | Where-Object { Get-VsatProp $_ 'ids_enabled' $false })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($on.Count) { 'PASS' } else { 'FAIL' }) -Observed "IDS enabled on $($on.Count) of $(@($r.value).Count) cluster(s)" -Expected $exp -Facts @('idsClusters') -Note 'Detection capability gap; confirm licensing before treating as a violation.')
}

function Invoke-VsatCheckNsxTransportNodes {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'transportNodeStates'
    $exp = 'All transport nodes realized successfully'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'transportNodeStates') -Expected $exp -Facts @('transportNodeStates')) }
    $bad = @(@($r.value) | Where-Object { [string](Get-VsatProp $_ 'state') -ne 'success' } | ForEach-Object { "$(Get-VsatProp $_ 'transport_node_id'): $(Get-VsatProp $_ 'state')" })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { $bad -join '; ' } else { "$(@($r.value).Count) node(s) in state success" }) -Expected $exp -Facts @('transportNodeStates') -Note 'Realization failures can leave configured policy unenforced.')
}

function Invoke-VsatCheckNsxBackup {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'backupConfig'
    $exp = 'Scheduled NSX backups enabled to a remote file server'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'backupConfig') -Expected $exp -Facts @('backupConfig')) }
    $en = [bool](Get-VsatProp $r.value 'backup_enabled' $false)
    $sched = Get-VsatProp $r.value 'backup_schedule'
    $srv = Get-VsatProp $r.value 'remote_file_server.server'
    $ok = $en -and $sched -and $srv
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($ok) { 'PASS' } else { 'FAIL' }) -Observed "enabled=$en; schedule=$(if ($sched) { Get-VsatProp $sched 'resource_type' 'set' } else { 'none' }); server=$(Format-VsatValue $srv)" -Expected $exp -Facts @('backupConfig') -Note 'Successful backup jobs are not proof of a successful restore.')
}

function Invoke-VsatCheckNsxNatBypass {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'natRules'
    $exp = 'NAT rules do not bypass the gateway firewall'
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No NAT rules' -Expected $exp -Facts @('natRules')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'natRules') -Expected $exp -Facts @('natRules')) }
    if (@($r.value).Count -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No NAT rules' -Expected $exp -Facts @('natRules')) }
    $bad = @(@($r.value) | Where-Object { $_.enabled -and [string]$_.firewallMatch -eq 'BYPASS' } | ForEach-Object { "$($_.id) ($($_.action))" })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { "Firewall bypass: $($bad -join ', ')" } else { "$(@($r.value).Count) NAT rule(s) use firewall matching" }) -Expected $exp -Facts @('natRules'))
}

function Invoke-VsatCheckNsxUnprotectedVm {
    param($Rule, $Asset, $Check, $Context)
    $exp = 'VM is a member of at least one group used by an enabled, non-default DFW rule'
    $st = $Context.nsxState
    if ($st -eq 'NOT_APPLICABLE') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'NSX not deployed in scope (evidence recorded in coverage)' -Expected $exp) }
    if ($Asset.props.template) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Template' -Expected $exp) }
    if (-not $Context.Contains('nsxMembership')) { $Context.nsxMembership = Get-VsatNsxMembershipIndex $Context }
    $idx = $Context.nsxMembership
    if ($idx.managers -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "NSX policy not assessed (NSX coverage: $st)" -Expected $exp) }
    $uuid = [string]$Asset.props.instanceUuid
    if (-not $uuid) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'VM instance UUID not collected; cannot correlate with NSX' -Expected $exp) }
    if (-not $idx.fabric.ContainsKey($uuid)) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'VM not present in NSX inventory (not on an NSX-prepared host or different NSX domain)' -Expected $exp -Confidence inferred) }
    if ($idx.incomplete) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Effective group membership incomplete; protection cannot be determined' -Expected $exp) }
    $groups = @($idx.vmGroups[$uuid])
    if ($groups.Count -gt 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "Protected by groups: $((@($groups | Select-Object -First 5)) -join ', ')" -Expected $exp -Confidence inferred) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "Not in any group referenced by an enabled rule; default rule action: $($idx.defaultAction)" -Expected $exp -Confidence inferred -Severity $(if ($idx.defaultAction -eq 'ALLOW') { 'high' } else { 'low' }))
}

function Get-VsatNsxMembershipIndex {
    param($Context)
    $idx = @{ managers = 0; fabric = @{}; vmGroups = @{}; incomplete = $false; defaultAction = 'unknown' }
    $mgrs = @($Context.evidence.assets | Where-Object { $_.type -eq 'nsx-manager' })
    $idx.managers = $mgrs.Count
    foreach ($m in $mgrs) {
        if ($m.facts.Contains('fabricVms') -and $m.facts.fabricVms.status -eq 'ok') { foreach ($v in @($m.facts.fabricVms.value)) { $idx.fabric[[string]$v.externalId] = $true } }
        else { $idx.incomplete = $true }
    }
    $used = @{}
    foreach ($r in @($Context.evidence.assets | Where-Object { $_.type -eq 'nsx-rule' -and -not $_.props.disabled -and -not $_.props.isDefault -and $_.props.firewall -eq 'dfw' })) {
        foreach ($g in @(@($r.props.sources) + @($r.props.destinations) + @($r.props.appliedTo) + @($r.props.policyAppliedTo))) { if ($g -ne 'ANY') { $used["$($r.endpoint):$g"] = $true } }
        if ((@($r.props.appliedTo) -contains 'ANY') -and (@($r.props.policyAppliedTo) -contains 'ANY') -and ((@($r.props.sources) -contains 'ANY') -or (@($r.props.destinations) -contains 'ANY'))) { $used['*'] = $true }
    }
    foreach ($gid in $used.Keys) {
        if ($gid -eq '*') { continue }
        $ga = $Context.assets[$gid]
        if (-not $ga) { continue }
        if (-not $ga.facts.Contains('members') -or $ga.facts.members.status -ne 'ok') { $idx.incomplete = $true; continue }
        foreach ($v in @($ga.facts.members.value.vms)) {
            $u = [string]$v.externalId
            if (-not $idx.vmGroups.ContainsKey($u)) { $idx.vmGroups[$u] = [System.Collections.Generic.List[string]]::new() }
            $idx.vmGroups[$u].Add($ga.name)
        }
    }
    if ($used.ContainsKey('*')) { foreach ($u in @($idx.fabric.Keys)) { if (-not $idx.vmGroups.ContainsKey($u)) { $idx.vmGroups[$u] = [System.Collections.Generic.List[string]]::new() }; $idx.vmGroups[$u].Add('(DFW-wide rule with ANY)') } }
    $def = @($Context.evidence.assets | Where-Object { $_.type -eq 'nsx-rule' -and $_.props.isDefault -and $_.props.firewall -eq 'dfw' }) | Select-Object -Last 1
    if ($def) { $idx.defaultAction = ([string]$def.props.action).ToUpperInvariant() }
    return $idx
}

#endregion Script evaluators
