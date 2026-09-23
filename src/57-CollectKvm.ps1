#region KVM / libvirt collector
# Read-only KVM/libvirt collection. A POSIX shell script runs on the host (over SSH with
# key authentication and a pinned host key, or exported with -ExportCollector kvm for
# air-gapped hosts) and prints delimited sections. virsh is always used with --readonly;
# domain XML is dumped WITHOUT --security-info so console passwords are never collected.

$script:VsatKvmCollector = @'
#!/bin/sh
# VSAT KVM/libvirt collector (read-only). Usage: sh vsat-kvm-collect.sh > kvm-<host>.txt
# Import with: vsat.ps1 -KvmEvidence kvm-<host>.txt
# It only reads configuration and state; it writes nothing and changes nothing.
LC_ALL=C; export LC_ALL
V="virsh --readonly -c qemu:///system"
sec() { printf '\n==VSAT:SECTION %s==\n' "$1"; }
sec meta; printf 'collector=1\ncollected_utc=%s\nhostname=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname -f 2>/dev/null || hostname)"
sec os-release; cat /etc/os-release 2>/dev/null
sec kernel; uname -r
sec virsh-version; $V version 2>&1
sec qemu-conf; grep -E '^[[:space:]]*(security_driver|user|group|dynamic_ownership|remember_owner|vnc_tls|vnc_listen|vnc_auto_unix_socket|spice_tls|spice_listen|seccomp_sandbox|set_process_name)[[:space:]]*=' /etc/libvirt/qemu.conf 2>&1
sec libvirtd-conf; for f in /etc/libvirt/libvirtd.conf /etc/libvirt/virtproxyd.conf /etc/libvirt/virtqemud.conf; do [ -r "$f" ] && grep -E '^[[:space:]]*(listen_tls|listen_tcp|auth_tcp|auth_tls|auth_unix_rw|auth_unix_ro|unix_sock_group|unix_sock_rw_perms|tls_no_verify_certificate|tcp_port)[[:space:]]*=' "$f" | sed "s|^|$f: |"; done
sec services; for s in libvirtd virtqemud virtproxyd libvirtd-tcp.socket libvirtd-tls.socket virtproxyd-tcp.socket virtproxyd-tls.socket firewalld nftables ufw sshd ssh; do printf '%s=%s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo unknown)"; done
sec listening; (ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null) | awk '{print $4}'
sec mac; (getenforce 2>/dev/null && echo "selinux") ; (cat /sys/module/apparmor/parameters/enabled 2>/dev/null | sed 's/^/apparmor=/')
sec secureboot; (mokutil --sb-state 2>/dev/null || (od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | awk '{print "efivar="$NF}'))
sec nested; cat /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested 2>/dev/null
sec sshd; grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
sec groups; getent group libvirt kvm libvirt-qemu 2>/dev/null
sec packages; (rpm -q qemu-kvm qemu-kvm-core libvirt-daemon libvirt 2>/dev/null; dpkg-query -W -f='${Package} ${Version}\n' qemu-system-x86 libvirt-daemon libvirt-daemon-system 2>/dev/null) | grep -v 'not installed'
sec last-update; (rpm -qa --last 2>/dev/null | head -1; [ -f /var/log/dpkg.log ] && tail -n 1 /var/log/dpkg.log; stat -c 'aptlists=%Y' /var/lib/apt/lists 2>/dev/null; stat -c 'dpkgstatus=%Y' /var/lib/dpkg/status 2>/dev/null; stat -c 'rpmdb=%Y' /var/lib/rpm 2>/dev/null) 2>/dev/null
sec now; date -u +%s
sec domains; $V list --all --name 2>&1
for d in $($V list --all --name 2>/dev/null); do
  sec "domain:$d"; $V dumpxml "$d" 2>&1
  sec "dominfo:$d"; $V dominfo "$d" 2>&1
  sec "snapshots:$d"; $V snapshot-list "$d" --parent 2>/dev/null
done
sec networks; $V net-list --all --name 2>&1
for n in $($V net-list --all --name 2>/dev/null); do sec "network:$n"; $V net-dumpxml "$n" 2>&1; done
sec pools; $V pool-list --all --name 2>&1
for p in $($V pool-list --all --name 2>/dev/null); do sec "pool:$p"; $V pool-dumpxml "$p" 2>&1; done
sec end
'@

$script:VsatSshReadOnlyPreamble = 'sh -s'

function Invoke-VsatKvmRemote {
    # Runs the collector over SSH using key-based auth only (BatchMode). The host key must
    # already be trusted (known_hosts) or pinned with -TrustedThumbprint "host=SHA256:...".
    param([Parameter(Mandatory)][string]$Address, [string]$User)
    $ssh = Get-Command ssh -ErrorAction SilentlyContinue
    if (-not $ssh) { throw 'ssh client not found; use -ExportCollector kvm and -KvmEvidence for offline collection.' }
    $hp = Split-VsatAddress $Address -DefaultPort 22
    $target = if ($User) { "$User@$($hp.host)" } else { $hp.host }
    $sshArgs = @('-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15', '-o', 'LogLevel=ERROR', '-p', [string]$hp.port)
    $pin = $script:VsatSshPins[$Address.ToLowerInvariant()]
    $kh = $null
    if ($pin) {
        # Verify the presented host key against the operator-approved SHA256 fingerprint,
        # then use a one-off known_hosts file containing only that key.
        $scan = & ssh-keyscan -p $hp.port -T 10 $hp.host 2>$null
        $match = $null
        foreach ($line in @($scan)) {
            if (-not $line -or $line.StartsWith('#')) { continue }
            $tmp = [IO.Path]::GetTempFileName()
            try {
                Set-Content -LiteralPath $tmp -Value $line
                $fp = (& ssh-keygen -lf $tmp -E sha256 2>$null) -join ' '
                if ($fp -match 'SHA256:([A-Za-z0-9+/=]+)' -and ('SHA256:' + $Matches[1]) -eq $pin) { $match = $line }
            }
            finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
        if (-not $match) { throw "SSH host key of $Address does not match the approved fingerprint; refusing to connect." }
        $kh = [IO.Path]::GetTempFileName()
        Set-Content -LiteralPath $kh -Value $match
        $sshArgs += @('-o', "UserKnownHostsFile=$kh", '-o', 'GlobalKnownHostsFile=/dev/null')
    }
    try {
        $out = $script:VsatKvmCollector | & ssh @sshArgs $target $script:VsatSshReadOnlyPreamble 2>&1
        if ($LASTEXITCODE -ne 0 -and -not ($out -join "`n").Contains('==VSAT:SECTION end==')) { throw "ssh to $Address failed (exit $LASTEXITCODE): $((@($out) | Select-Object -Last 3) -join ' ')" }
        return ($out -join "`n")
    }
    finally { if ($kh) { Remove-Item -LiteralPath $kh -Force -ErrorAction SilentlyContinue } }
}

$script:VsatSshPins = @{}

function ConvertFrom-VsatKvmSections {
    param([Parameter(Mandatory)][string]$Text)
    $sections = [ordered]@{}
    $cur = $null; $buf = [System.Text.StringBuilder]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^==VSAT:SECTION (.+)==$') {
            if ($cur) { $sections[$cur] = $buf.ToString().Trim() }
            $cur = $Matches[1]; [void]$buf.Clear(); continue
        }
        if ($cur) { [void]$buf.AppendLine($line) }
    }
    if ($cur) { $sections[$cur] = $buf.ToString().Trim() }
    return $sections
}

function ConvertFrom-VsatKeyValue {
    param([string]$Text, [string]$Separator = '=')
    $h = [ordered]@{}
    foreach ($l in ($Text -split "`r?`n")) {
        $i = $l.IndexOf($Separator)
        if ($i -gt 0) { $k = $l.Substring(0, $i).Trim(); if ($k -notmatch '^\s*#') { $h[$k] = $l.Substring($i + $Separator.Length).Trim().Trim('"') } }
    }
    return $h
}

function Read-VsatXml {
    # Parses untrusted XML safely (no DTD processing, no external resolution).
    param([string]$Text)
    if (-not $Text -or -not $Text.TrimStart().StartsWith('<')) { return $null }
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 10MB
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($Text), $settings)
    try { $doc = [System.Xml.XmlDocument]::new(); $doc.XmlResolver = $null; $doc.Load($reader); return $doc }
    catch { Write-VsatLog -Level warn -Source 'kvm' -Message "Rejected malformed or unsafe XML: $($_.Exception.Message)"; return $null }
    finally { $reader.Dispose() }
}

function Add-VsatKvmEvidence {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Endpoint, [Parameter(Mandatory)][string]$Text)
    $ep = $Endpoint.id
    $s = ConvertFrom-VsatKvmSections $Text
    if (-not $s.Contains('end')) { throw 'KVM collector output is incomplete (missing end marker).' }
    $meta = ConvertFrom-VsatKeyValue $s['meta']
    $osr = ConvertFrom-VsatKeyValue $s['os-release']
    $Endpoint.product = [string]$osr['PRETTY_NAME']; $Endpoint.version = [string]$osr['VERSION_ID']; $Endpoint.build = [string]$s['kernel']
    $hid = "${ep}:host"
    $name = if ($meta['hostname']) { $meta['hostname'] } else { $Endpoint.address }
    $ha = Add-VsatAsset -Evidence $Evidence -Id $hid -Type 'kvm-host' -Name $name -Endpoint $ep -Version ([string]$osr['VERSION_ID']) -Build ([string]$s['kernel']) -Props ([ordered]@{ osId = [string]$osr['ID']; osName = [string]$osr['PRETTY_NAME']; kernel = [string]$s['kernel'] })
    $okOrAbsent = { param($v) if ($null -eq $v -or $v -eq '') { 'absent' } else { 'ok' } }
    Set-VsatFact $ha 'qemuConf' -Status (& $okOrAbsent $s['qemu-conf']) -Value (ConvertFrom-VsatKeyValue ([string]$s['qemu-conf']))
    $lconf = [ordered]@{}
    foreach ($l in (([string]$s['libvirtd-conf']) -split "`r?`n")) { if ($l -match '^(\S+):\s*([^=]+?)\s*=\s*(.+)$') { $lconf[$Matches[2].Trim()] = $Matches[3].Trim().Trim('"') } }
    Set-VsatFact $ha 'libvirtConf' -Status $(if ($lconf.Count) { 'ok' } else { 'absent' }) -Value $lconf
    Set-VsatFact $ha 'services' -Value @((ConvertFrom-VsatKeyValue ([string]$s['services'])).GetEnumerator() | ForEach-Object { [ordered]@{ key = $_.Key; running = ($_.Value -eq 'active'); policy = $_.Value } })
    $ports = @(([string]$s['listening']) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { if ($_ -match '[:.](\d+)$') { [ordered]@{ address = ($_ -replace '[:.]\d+$', ''); port = [int]$Matches[1] } } })
    Set-VsatFact $ha 'listening' -Status $(if ($s['listening']) { 'ok' } else { 'unsupported' }) -Value $ports
    $macText = [string]$s['mac']
    $selinux = if ($macText -match '(?m)^(Enforcing|Permissive|Disabled)$') { $Matches[1] } else { $null }
    $apparmor = if ($macText -match 'apparmor=Y') { $true } elseif ($macText -match 'apparmor=N') { $false } else { $null }
    Set-VsatFact $ha 'mac' -Value ([ordered]@{ selinux = $selinux; apparmor = $apparmor; enforcing = ($selinux -eq 'Enforcing' -or $apparmor -eq $true) })
    $sbText = [string]$s['secureboot']
    $sb = if ($sbText -match 'SecureBoot enabled|efivar=1') { $true } elseif ($sbText -match 'SecureBoot disabled|efivar=0') { $false } else { $null }
    Set-VsatFact $ha 'secureBoot' -Status $(if ($null -eq $sb) { 'unsupported' } else { 'ok' }) -Value $sb
    $nested = @(([string]$s['nested']) -split "`r?`n" | Where-Object { $_ })
    Set-VsatFact $ha 'nested' -Status $(if ($nested.Count) { 'ok' } else { 'absent' }) -Value ([bool](@($nested | Where-Object { $_ -in @('Y', '1') }).Count))
    $sshd = [ordered]@{}
    foreach ($l in (([string]$s['sshd']) -split "`r?`n")) { $l2 = $l -replace '^[^:]+:', ''; if ($l2 -match '^\s*(\S+)\s+(\S+)') { if (-not $sshd.Contains($Matches[1])) { $sshd[$Matches[1]] = $Matches[2] } } }
    Set-VsatFact $ha 'sshd' -Status $(if ($sshd.Count) { 'ok' } else { 'absent' }) -Value $sshd
    Set-VsatFact $ha 'groups' -Status (& $okOrAbsent $s['groups']) -Value @(([string]$s['groups']) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { $p = $_.Split(':'); [ordered]@{ group = $p[0]; members = @($p[-1].Split(',') | Where-Object { $_ }) } })
    Set-VsatFact $ha 'packages' -Status (& $okOrAbsent $s['packages']) -Value @(([string]$s['packages']) -split "`r?`n" | Where-Object { $_ })
    # Patch age: newest of package database / apt lists / dpkg log timestamps.
    $now = 0L; [void][long]::TryParse(([string]$s['now']).Trim(), [ref]$now)
    $stamps = @()
    foreach ($m in [regex]::Matches([string]$s['last-update'], '(?:aptlists|dpkgstatus|rpmdb)=(\d+)')) { $stamps += [long]$m.Groups[1].Value }
    if ($now -gt 0 -and $stamps.Count) { $age = [int](($now - ($stamps | Measure-Object -Maximum).Maximum) / 86400); Set-VsatFact $ha 'updates' -Value ([ordered]@{ ageDays = $age; source = 'package database timestamp' }) }
    else { Set-VsatFact $ha 'updates' -Status 'unsupported' -Value $null -ErrorMessage 'Package update timestamp not available' }
    Set-VsatFact $ha 'libvirt' -Status $(if ([string]$s['virsh-version'] -match 'library|Using') { 'ok' } else { 'error' }) -Value ([string]$s['virsh-version']) -ErrorMessage $(if ([string]$s['virsh-version'] -notmatch 'library|Using') { [string]$s['virsh-version'] } else { $null })

    foreach ($key in @($s.Keys | Where-Object { $_ -like 'network:*' })) {
        $n = $key.Substring(8)
        $x = Read-VsatXml $s[$key]
        $fwd = if ($x) { [string]$x.network.forward.mode } else { $null }
        $nid = "${ep}:net/$n"
        $na = Add-VsatAsset -Evidence $Evidence -Id $nid -Type 'kvm-network' -Name "$name $n" -Endpoint $ep -Props ([ordered]@{ network = $n; forwardMode = $(if ($fwd) { $fwd } elseif ($x) { 'isolated' } else { $null }); bridge = $(if ($x) { [string]$x.network.bridge.name } else { $null }) })
        Add-VsatRelationship -Evidence $Evidence -Source $hid -Target $nid -Type contains -Provenance 'kvm.network'
    }
    foreach ($key in @($s.Keys | Where-Object { $_ -like 'domain:*' })) {
        $d = $key.Substring(7)
        $x = Read-VsatXml $s[$key]
        $vid = "${ep}:vm/" + $(if ($x -and $x.domain.uuid) { [string]$x.domain.uuid } else { $d })
        $info = ConvertFrom-VsatKeyValue ([string]$s["dominfo:$d"]) ':'
        $va = Add-VsatAsset -Evidence $Evidence -Id $vid -Type 'kvm-vm' -Name $d -Endpoint $ep -Props ([ordered]@{ uuid = $(if ($x) { [string]$x.domain.uuid } else { $null }); state = [string]$info['State']; autostart = [string]$info['Autostart']; persistent = [string]$info['Persistent'] })
        Add-VsatRelationship -Evidence $Evidence -Source $vid -Target $hid -Type runs-on -Provenance 'kvm.vms'
        if (-not $x) { Set-VsatFact $va 'domain' -Status error -Value $null -ErrorMessage "Domain XML unavailable: $([string]$s[$key])"; continue }
        $dom = $x.domain
        $seclabels = @($dom.SelectNodes('seclabel') | ForEach-Object { [ordered]@{ type = $_.GetAttribute('type'); model = $_.GetAttribute('model'); relabel = $_.GetAttribute('relabel') } })
        $loader = $dom.SelectSingleNode('os/loader')
        $graphics = @($dom.SelectNodes('devices/graphics') | ForEach-Object {
                $listen = $_.GetAttribute('listen'); $ln = $_.SelectSingleNode('listen'); if ($ln -and $ln.GetAttribute('address')) { $listen = $ln.GetAttribute('address') }
                $lt = if ($ln) { $ln.GetAttribute('type') } else { $null }
                [ordered]@{ type = $_.GetAttribute('type'); listen = $listen; listenType = $lt; autoport = $_.GetAttribute('autoport') } })
        $ifaces = @($dom.SelectNodes('devices/interface') | ForEach-Object {
                [ordered]@{ type = $_.GetAttribute('type'); source = $(if ($_.source) { ($_.source.GetAttribute('network') + $_.source.GetAttribute('bridge')) } else { $null }); mac = $(if ($_.mac) { $_.mac.GetAttribute('address') } else { $null }); filter = $(if ($_.filterref) { $_.filterref.GetAttribute('filter') } else { $null }) } })
        $consoles = @($dom.SelectNodes('devices/serial | devices/console | devices/channel') | ForEach-Object { [ordered]@{ kind = $_.LocalName; type = $_.GetAttribute('type') } })
        $hostdevs = @($dom.SelectNodes('devices/hostdev') | ForEach-Object { [ordered]@{ mode = $_.GetAttribute('mode'); type = $_.GetAttribute('type') } })
        Set-VsatFact $va 'domain' -Value ([ordered]@{
                seclabels = $seclabels
                firmware = $(if ($dom.os.GetAttribute('firmware')) { $dom.os.GetAttribute('firmware') } elseif ($loader) { 'efi' } else { 'bios' })
                secureBoot = $(if ($loader) { $loader.GetAttribute('secure') -eq 'yes' } else { $false })
                tpm = [bool]$dom.SelectSingleNode('devices/tpm')
                graphics = $graphics; interfaces = $ifaces; consoles = $consoles; hostdevs = $hostdevs
                redirdevs = @($dom.SelectNodes('devices/redirdev')).Count
                memoryBacking = [bool]$dom.SelectSingleNode('memoryBacking')
            })
        foreach ($i in $ifaces) { if ($i.type -eq 'network' -and $i.source) { Add-VsatRelationship -Evidence $Evidence -Source $vid -Target "${ep}:net/$($i.source)" -Type connects -Provenance 'kvm.vms' -Props ([ordered]@{ mac = $i.mac }) } }
        $snaps = @(([string]$s["snapshots:$d"]) -split "`r?`n" | Where-Object { $_ -match '^\s*\S+\s+\d{4}-\d{2}-\d{2}' } | ForEach-Object {
                $p = ($_.Trim() -split '\s{2,}')
                $t = [DateTime]::MinValue
                if ([DateTime]::TryParse(($p[1] -replace '\s+[+-]\d{4}$', ''), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$t)) { [ordered]@{ name = $p[0]; createdUtc = $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); ageDays = $(if ($now -gt 0) { [int](([DateTimeOffset]::FromUnixTimeSeconds($now).UtcDateTime - $t.ToUniversalTime()).TotalDays) } else { $null }) } }
            })
        Set-VsatFact $va 'snapshots' -Status $(if ($snaps.Count) { 'ok' } else { 'absent' }) -Value @($snaps)
    }
}

function Invoke-VsatKvmCollection {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Endpoint, [string]$User, [string]$ImportedText)
    $vsatKvmEndpoint = $Endpoint
    $txt = $ImportedText
    Invoke-VsatCollector -Evidence $Evidence -Name 'kvm.host' -Endpoint $Endpoint.id -Affects @('KVM-*') -Script {
        if (-not $txt) { $txt = Invoke-VsatKvmRemote -Address $vsatKvmEndpoint.address -User $User }
        Add-VsatKvmEvidence -Evidence $Evidence -Endpoint $vsatKvmEndpoint -Text $txt
        1
    }
    $ok = @($Evidence.collection.collectors | Where-Object { $_.name -eq 'kvm.host' -and $_.endpoint -eq $Endpoint.id })[-1]
    foreach ($n in 'kvm.vms', 'kvm.network') {
        $Evidence.collection.collectors.Add([ordered]@{ name = $n; endpoint = $Endpoint.id; status = $(if ($ok.status -eq 'ok') { 'ok' } else { 'skipped' }); startedUtc = (Get-VsatUtcNow); endedUtc = (Get-VsatUtcNow); objectCount = @($Evidence.assets | Where-Object { $_.endpoint -eq $Endpoint.id -and $_.type -eq $(if ($n -eq 'kvm.vms') { 'kvm-vm' } else { 'kvm-network' }) }).Count; error = $(if ($ok.status -eq 'ok') { $null } else { 'Host collection failed' }); affects = @() })
    }
    if ($ok.status -eq 'ok') { $Endpoint.status = 'collected' } else { $Endpoint.status = 'failed'; if ($ok.error) { $Endpoint.errors.Add($ok.error) } }
}

#endregion KVM / libvirt collector
