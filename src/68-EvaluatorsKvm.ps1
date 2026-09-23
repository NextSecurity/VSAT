#region KVM evaluators

function Test-VsatLoopback {
    param([string]$Address)
    if (-not $Address) { return $false }
    return ($Address -match '^(127\.|::1$|\[::1\]|localhost$)')
}

function Invoke-VsatCheckKvm {
    # One evaluator with explicit modes keeps KVM logic reviewable in one place.
    param($Rule, $Asset, $Check, $Context)
    $mode = [string]$Check.mode
    $gap = { param($fact) $r = Resolve-VsatFactValue -Asset $Asset -Fact $fact; if ($r.state -notin @('ok', 'absent')) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r $fact) -Expected $Rule.title -Facts @($fact)) }; $null }
    switch ($mode) {
        'svirt' {
            foreach ($fct in 'qemuConf', 'mac') { $g = & $gap $fct; if ($g) { return $g } }
            $drv = [string](Get-VsatProp $Asset.facts 'qemuConf.value.security_driver' '')
            $mac = $Asset.facts.mac.value
            $bad = @()
            if ($drv -match '(?i)^"?none"?$') { $bad += 'security_driver = none' }
            if (-not $mac.enforcing) { $bad += "no enforcing MAC (SELinux: $(Format-VsatValue $mac.selinux); AppArmor: $(Format-VsatValue $mac.apparmor))" }
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { $bad -join '; ' } else { "sVirt active (security_driver: $(if ($drv) { $drv } else { 'default' }); SELinux: $(Format-VsatValue $mac.selinux); AppArmor: $(Format-VsatValue $mac.apparmor))" }) -Expected 'sVirt confinement with SELinux or AppArmor enforcing' -Facts @('qemuConf', 'mac'))
        }
        'libvirt-tcp' {
            $conf = Get-VsatProp $Asset.facts 'libvirtConf.value' ([ordered]@{})
            $ports = @(Get-VsatProp $Asset.facts 'listening.value' @())
            $tcp = [string](Get-VsatProp $conf 'listen_tcp' '0'); $auth = [string](Get-VsatProp $conf 'auth_tcp' 'sasl')
            $exposed = @($ports | Where-Object { $_.port -eq 16509 -and -not (Test-VsatLoopback $_.address) })
            if ($tcp -eq '1' -and $auth -match '(?i)none') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed 'listen_tcp = 1 with auth_tcp = none (unauthenticated remote root-equivalent access)' -Expected 'No unauthenticated libvirt TCP listener' -Facts @('libvirtConf') -Severity critical) }
            if ($exposed.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed "libvirt TCP 16509 listening on $($exposed[0].address) (auth_tcp: $auth)" -Expected 'Remote libvirt only over TLS (16514) or SSH' -Facts @('listening', 'libvirtConf')) }
            if ((Get-VsatProp $Asset.facts 'listening.status') -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Listening sockets not collected' -Expected 'No unauthenticated libvirt TCP listener' -Facts @('listening')) }
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "listen_tcp = $tcp; no plain TCP listener" -Expected 'No unauthenticated libvirt TCP listener' -Facts @('libvirtConf', 'listening'))
        }
        'qemu-user' {
            $g = & $gap 'qemuConf'; if ($g) { return $g }
            $u = [string](Get-VsatProp $Asset.facts 'qemuConf.value.user' '')
            $isRoot = $u -match '(?i)^"?(root|\+0)"?$'
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($isRoot) { 'FAIL' } else { 'PASS' }) -Observed $(if ($u) { "user = $u" } else { 'user not set (distribution default unprivileged account)' }) -Expected 'QEMU processes run as an unprivileged user' -Facts @('qemuConf') -Confidence $(if ($u) { 'observed' } else { 'inferred' }))
        }
        'vnc-tls' {
            $g = & $gap 'qemuConf'; if ($g) { return $g }
            $listen = [string](Get-VsatProp $Asset.facts 'qemuConf.value.vnc_listen' '127.0.0.1')
            $tls = [string](Get-VsatProp $Asset.facts 'qemuConf.value.vnc_tls' '0')
            if (Test-VsatLoopback ($listen.Trim('"'))) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed "vnc_listen = $listen" -Expected 'VNC on loopback, or TLS enabled' -Facts @('qemuConf')) }
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($tls -eq '1') { 'PASS' } else { 'FAIL' }) -Observed "vnc_listen = $listen; vnc_tls = $tls" -Expected 'VNC on loopback, or TLS enabled' -Facts @('qemuConf'))
        }
        'firewall' {
            $g = & $gap 'services'; if ($g) { return $g }
            $act = @(@($Asset.facts.services.value) | Where-Object { $_.key -in @('firewalld', 'nftables', 'ufw') -and $_.running } | ForEach-Object { $_.key })
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($act.Count) { 'PASS' } else { 'FAIL' }) -Observed $(if ($act.Count) { "Active: $($act -join ', ')" } else { 'No active firewalld, nftables or ufw service' }) -Expected 'A host firewall service is active' -Facts @('services') -Note 'A custom iptables ruleset without these services may exist; verify manually if FAIL.')
        }
        'vm-seclabel' {
            $g = & $gap 'domain'; if ($g) { return $g }
            $labels = @($Asset.facts.domain.value.seclabels)
            $bad = @($labels | Where-Object { $_.type -eq 'none' -or $_.relabel -eq 'no' } | ForEach-Object { "$($_.model): type=$($_.type) relabel=$($_.relabel)" })
            if ($bad.Count) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result FAIL -Observed ($bad -join '; ') -Expected 'Dynamic sVirt labeling (no type=none / relabel=no)' -Facts @('domain')) }
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed $(if ($labels.Count) { ($labels | ForEach-Object { "$($_.model):$($_.type)" }) -join ', ' } else { 'No per-domain override (host default labeling applies)' }) -Expected 'Dynamic sVirt labeling' -Facts @('domain') -Confidence $(if ($labels.Count) { 'observed' } else { 'inferred' }))
        }
        'vm-graphics' {
            $g = & $gap 'domain'; if ($g) { return $g }
            $exp = @(@($Asset.facts.domain.value.graphics) | Where-Object { $_.type -in @('vnc', 'spice') -and $_.listenType -notin @('socket', 'none') -and -not (Test-VsatLoopback $_.listen) } | ForEach-Object { "$($_.type) listen=$(if ($_.listen) { $_.listen } else { '(host default)' })" })
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($exp.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($exp.Count) { $exp -join '; ' } else { 'Console not network-exposed' }) -Expected 'VNC/SPICE consoles bound to loopback or a UNIX socket' -Facts @('domain') -Note 'Console passwords are deliberately not collected (no --security-info).')
        }
        'vm-hostdev' {
            $g = & $gap 'domain'; if ($g) { return $g }
            $n = @($Asset.facts.domain.value.hostdevs).Count
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($n) { 'FAIL' } else { 'PASS' }) -Observed "$n host device(s) passed through" -Expected 'No PCI/USB host device passthrough' -Facts @('domain'))
        }
        'vm-console-net' {
            $g = & $gap 'domain'; if ($g) { return $g }
            $bad = @(@($Asset.facts.domain.value.consoles) | Where-Object { $_.type -in @('tcp', 'udp', 'telnet') } | ForEach-Object { "$($_.kind): $($_.type)" })
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { $bad -join '; ' } else { 'No network-backed serial/console devices' }) -Expected 'No TCP/UDP/telnet serial consoles' -Facts @('domain'))
        }
        'vm-redir' {
            $g = & $gap 'domain'; if ($g) { return $g }
            $n = [int]$Asset.facts.domain.value.redirdevs
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($n) { 'FAIL' } else { 'PASS' }) -Observed "$n USB redirection device(s)" -Expected 'No USB redirection' -Facts @('domain'))
        }
        'vm-nwfilter' {
            $g = & $gap 'domain'; if ($g) { return $g }
            $ifs = @(@($Asset.facts.domain.value.interfaces) | Where-Object { $_.type -in @('network', 'bridge') })
            if ($ifs.Count -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No network/bridge interfaces' -Expected '' -Facts @('domain')) }
            $bad = @($ifs | Where-Object { -not $_.filter } | ForEach-Object { "$($_.mac) on $($_.source)" })
            return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { "No nwfilter: $($bad -join '; ')" } else { 'All interfaces have an nwfilter' }) -Expected 'Interfaces use an anti-spoofing nwfilter (e.g. clean-traffic)' -Facts @('domain'))
        }
        default { throw "Unknown KVM check mode $mode" }
    }
}

#endregion KVM evaluators
