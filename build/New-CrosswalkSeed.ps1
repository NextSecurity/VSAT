<#
.SYNOPSIS
    Generates data/frameworks/catalogs.json and data/frameworks/crosswalk.json (reproducible).
.DESCRIPTION
    Inputs, all in the repository:
      - rules/*.json                      every VSAT rule (id, attack.mitigation)
      - build/crosswalk/catalog-base.json framework metadata, control IDs and VSAT paraphrases
      - build/crosswalk/imported/*.json   importer output (build/Import-StigXccdf.ps1, build/Import-CisMapping.ps1)
      - data/attack/attack-catalog.json   pinned ATT&CK catalog (edition, mitigation IDs)
    NIST SP 800-53 and IEC 62443-3-3 rows come from the category table below, matched against the rule
    ID. They are "proposed": a starting point a reviewer confirms (docs/compliance-mapping.md). Every rule
    must match at least one row, so a new rule cannot ship without a mapping decision. ATT&CK rows mirror
    each rule's attack.mitigation. Imported rows keep the status the importer gave them.

    Output is deterministic (sorted, LF, no timestamps): tests/Compliance.Tests.ps1 regenerates it and
    compares it byte for byte with the committed files.
.PARAMETER OutDir
    Folder to write to. Defaults to data/frameworks.
#>
[CmdletBinding()]
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'data/frameworks' }
$inv = [Globalization.CultureInfo]::InvariantCulture

# Category table: rule ID pattern -> NIST SP 800-53 Rev. 5 and IEC 62443-3-3 SR IDs. A rule collects
# the union of every row it matches. Keep the basis a short VSAT reason, never standards text.
$table = @(
    @{ m = '-ADV$'; nist = 'SI-2', 'RA-5'; iec = @(); basis = 'known security advisories: flaw remediation and vulnerability monitoring' }
    @{ m = 'PATCH-AGE$|^VM-TOOLS$'; nist = 'SI-2'; iec = @(); basis = 'current updates: flaw remediation' }
    @{ m = 'LIFECYCLE$'; nist = 'SA-22', 'SI-2'; iec = @(); basis = 'vendor support ended: unsupported components' }
    @{ m = '^ESXI-SVC-|^HV-SPOOLER$|^HV-SERVER-CORE$|^ESXI-MOB$|^ESXI-DVFILTER$|^VM-DVFILTER$|^KVM-NESTED$|^NET-VDS-HEALTHCHECK$|^HV-VM-GUESTSERVICE$|^HV-ENHANCED-SESSION$|^HV-SMB1$|^KVM-LIBVIRT-TCP$|^HV-VSWITCH-EXTENSIONS$'; nist = 'CM-7'; iec = 'SR 7.7'; basis = 'unneeded service or interface disabled: least functionality' }
    @{ m = '^VM-(FLOPPY|CDROM|SERIAL|PARALLEL|USB|3D)$|^HV-VM-MEDIA$|^KVM-VM-(CONSOLE-NET|USBREDIR)$'; nist = 'CM-7'; iec = 'SR 7.7'; basis = 'unneeded virtual device removed: least functionality' }
    @{ m = '^VM-(COPY|PASTE|DND)-DISABLE$|^VM-GUIOPTIONS$|^VM-DISKSHRINK$|^VM-DISKWIPER$|^VM-DEVICE-CONNECTABLE$|^VM-HOSTINFO$|^VM-SETINFO-LIMIT$|^VM-NONPERSISTENT$'; nist = 'CM-6', 'CM-7'; iec = 'SR 7.6', 'SR 7.7'; basis = 'VM isolation setting: secure configuration' }
    @{ m = '^VM-(COPY|PASTE|DND)-DISABLE$|^VM-HOSTINFO$|^ESXI-SALT$'; nist = 'SC-4'; iec = @(); basis = 'guest/host or guest/guest information leak through shared resources' }
    @{ m = 'ADMIN|PERMISSIONS-REVIEW$|^ESXI-LOCAL-ACCOUNTS$|^ESXI-DCUI-ACCESS$|^ESXI-LOCKDOWN$|^KVM-LIBVIRT-GROUP$|^VC-ADMIN-USERS$'; nist = 'AC-2', 'AC-3', 'AC-6'; iec = 'SR 1.3', 'SR 2.1'; basis = 'administrative access and accounts: account management and least privilege' }
    @{ m = 'SHARED-ADMIN$|^OT-IT-ADMIN$'; nist = 'AC-5'; iec = @(); basis = 'one identity administers separate domains: separation of duties' }
    @{ m = '^KVM-QEMU-USER$'; nist = 'AC-6', 'SC-39'; iec = 'SR 5.4'; basis = 'hypervisor process runs without root: least privilege' }
    @{ m = '-PASS-|PASSWORD|^KVM-SSH-ROOT$|^VC-SSO-POLICY$'; nist = 'IA-5'; iec = 'SR 1.5', 'SR 1.7'; basis = 'password policy and credentials: authenticator management' }
    @{ m = '^KVM-SSH-PASSWORD$|^KVM-SSH-ROOT$|^HV-RDP-NLA$|^HV-MIGRATION-AUTH$|^HV-REPLICA-AUTH$'; nist = 'IA-2'; iec = 'SR 1.1'; basis = 'strong authentication for administrative or service access' }
    @{ m = '^ESXI-ISCSI-CHAP$|^ST-NFS-AUTH$'; nist = 'IA-3', 'SC-8'; iec = 'SR 1.2'; basis = 'storage peers authenticate each other' }
    @{ m = 'ACCOUNT-LOCK$|ACCOUNT-UNLOCK$|AUTH-LOCKOUT|^VC-SSO-POLICY$'; nist = 'AC-7'; iec = 'SR 1.11'; basis = 'account lockout after failed logons' }
    @{ m = 'TIMEOUT$|^ESXI-SHELL-IDLE$'; nist = 'AC-11', 'AC-12'; iec = 'SR 2.5', 'SR 2.6'; basis = 'idle sessions end automatically' }
    @{ m = '^ESXI-SHELL-IDLE$|^ESXI-HOSTCLIENT-TIMEOUT$'; nist = 'SC-10'; iec = @(); basis = 'idle connections are closed' }
    @{ m = '^VM-CONSOLE-CONNECTIONS$'; nist = 'AC-10'; iec = 'SR 2.7'; basis = 'one console connection at a time: concurrent session control' }
    @{ m = 'SYSLOG'; nist = 'AU-4', 'AU-6', 'AU-9'; iec = 'SR 2.8', 'SR 2.9', 'SR 3.9', 'SR 6.1'; basis = 'logs kept off-host and persistent: audit storage and protection' }
    @{ m = '^ESXI-LOG-LEVEL$|DENY-LOG$|DEFAULT-LOG$'; nist = 'AU-12'; iec = 'SR 2.8'; basis = 'security events are logged' }
    @{ m = 'DENY-LOG$|DEFAULT-LOG$|^NSX-IDS$|^ESXI-SHELL-WARNING$'; nist = 'SI-4'; iec = 'SR 6.2'; basis = 'visibility of attacks and risky states: system monitoring' }
    @{ m = '^VM-LOG-(KEEPOLD|ROTATE)$|^VC-EVENT-RETENTION$'; nist = 'AU-4', 'AU-11'; iec = 'SR 2.9'; basis = 'log capacity and retention' }
    @{ m = '^ESXI-COREDUMP$'; nist = 'AU-4', 'AU-9'; iec = 'SR 3.9'; basis = 'crash data collected centrally and protected' }
    @{ m = 'NTP$'; nist = 'AU-8'; iec = 'SR 2.11'; basis = 'synchronized time for audit records' }
    @{ m = 'CERT-'; nist = 'SC-17', 'IA-5'; iec = 'SR 1.8'; basis = 'trusted, valid certificates' }
    @{ m = 'FW-|FIREWALL|^NSX-DFW-|^NSX-GFW-|^NSX-NAT-BYPASS$|^NSX-EFF-UNPROTECTED$|^NSX-TN-STATE$'; nist = 'SC-7', 'AC-4'; iec = 'SR 5.1', 'SR 5.2'; basis = 'firewall policy at host, segment or gateway boundaries' }
    @{ m = '^NET-VSS-|^NET-VDS-(PROMISC|MAC|FORGED|OVERRIDE-ALLOWED|PORT-OVERRIDES|DEFAULT-POLICY)$|^HV-VM-(MACSPOOF|DHCPGUARD|ROUTERGUARD)$|^KVM-VM-NWFILTER$|^ESXI-BPDU$'; nist = 'SC-7', 'AC-4'; iec = 'SR 5.1'; basis = 'layer-2 isolation between guests on a virtual switch' }
    @{ m = 'VLAN|^HV-VM-TRUNK$|^ESXI-VMK-SEPARATION$|^HV-VSWITCH-MGMTOS$|^HV-MIGRATION-NETWORK$|^KVM-NET-OPEN$|^AI-SRIOV-HOST$|^AI-K8S-CP-EXPOSED$|^ST-SAN-SEGREGATION$'; nist = 'SC-7', 'AC-4'; iec = 'SR 5.1'; basis = 'network segmentation of management, storage and workload traffic' }
    @{ m = 'MIRROR$|^NET-VDS-NETFLOW$'; nist = 'AC-4'; iec = 'SR 4.1'; basis = 'copies of traffic go only to authorized destinations' }
    @{ m = '^KVM-VM-GRAPHICS$|^KVM-VNC-TLS$'; nist = 'AC-17'; iec = 'SR 1.13'; basis = 'guest consoles are not open on the network' }
    @{ m = 'SECUREBOOT$|TPM|^HV-VBS-HVCI$|^ESXI-ACCEPTANCE$|^ESXI-EXEC-INSTALLED-ONLY$|^HV-VM-GEN2$'; nist = 'SI-7'; iec = 'SR 3.4'; basis = 'boot chain and code integrity' }
    @{ m = '^HV-VBS-(HVCI|CREDGUARD)$|^KVM-SVIRT$|^KVM-SECCOMP$|^KVM-VM-SECLABEL$|^AI-(IOMMU-OFF|IOMMU-IR|ACS-OVERRIDE|IOMMU-GROUP-SHARED|GPU-SHARED-NO-MIG)$|PASSTHROUGH$|HOSTDEV$|^HV-VM-DDA$'; nist = 'SC-39'; iec = 'SR 5.4'; basis = 'hypervisor-enforced isolation between guests, devices and the host' }
    @{ m = '^AI-GPU-SHARED-NO-MIG$|^AI-IOMMU-GROUP-SHARED$'; nist = 'SC-4'; iec = @(); basis = 'shared accelerator or IOMMU group can leak data between guests' }
    @{ m = '^ST-VSAN-ENCRYPTION$|^VM-ENCRYPTION$'; nist = 'SC-28'; iec = 'SR 4.1'; basis = 'data at rest is encrypted' }
    @{ m = '^ST-VSAN-DIT$|^HV-SMB-SIGNING$|^KVM-VNC-TLS$|^AI-SHARE-PLAINTEXT$|^HV-VM-ENCRYPT-STATE$|^AI-SHARE-SMB$'; nist = 'SC-8'; iec = 'SR 3.1', 'SR 4.1'; basis = 'data in transit is signed or encrypted' }
    @{ m = '^AI-SHARE-(WORLD|SMB)$'; nist = 'AC-3', 'AC-6'; iec = 'SR 2.1'; basis = 'model and dataset shares restrict who can read and write' }
    @{ m = '^VC-KEY-PROVIDER$'; nist = 'SC-12'; iec = 'SR 4.3'; basis = 'encryption key provider is redundant and independent' }
    @{ m = 'BACKUP|RECOVERY-EVIDENCE$|^VC-APPLIANCE$'; nist = 'CP-9'; iec = 'SR 7.3'; basis = 'backups exist and are protected' }
    @{ m = 'RECOVERY-EVIDENCE$|^RW-BACKUP-(COLOCATED|SHARED-ADMIN)$|^CL-HA$|^CL-HA-ADMISSION$|^CL-MULTIHOST$|^NSX-MGR-CLUSTER$|^ST-DATASTORE-ACCESSIBLE$'; nist = 'CP-10'; iec = 'SR 7.4'; basis = 'the service can be recovered after a failure or attack' }
    @{ m = '^RW-BACKUP-REACHABLE$|^RW-BACKUP-COLOCATED$'; nist = 'SC-7', 'SC-32'; iec = 'SR 5.1'; basis = 'backups are isolated from the production attack surface' }
    @{ m = '^CL-DRS$|^NET-UPLINK-REDUNDANCY$'; nist = 'SC-6'; iec = 'SR 7.1', 'SR 7.2'; basis = 'capacity and path redundancy keep resources available' }
    @{ m = 'SNAPSHOT-AGE$|CHECKPOINT-AGE$'; nist = 'CM-6', 'SI-12'; iec = 'SR 7.6'; basis = 'old snapshots hold stale data and weaken configuration control' }
    @{ m = '^VC-APPLIANCE$'; nist = 'CM-6', 'CM-7'; iec = 'SR 7.6', 'SR 7.7'; basis = 'appliance shell, SSH and firewall configuration' }
    @{ m = '^NSX-FEDERATION$'; nist = 'CM-8'; iec = 'SR 7.8'; basis = 'every management scope is known and assessed' }
    @{ m = '^OT-SHARED-(HOST|VSWITCH|MGMT)$'; nist = 'SC-7', 'SC-32', 'AC-4'; iec = 'SR 5.1', 'SR 5.4'; basis = 'OT and IT workloads do not share virtualization infrastructure' }
    @{ m = '^OT-IT-ADMIN$'; nist = 'AC-6'; iec = 'SR 1.3', 'SR 2.1'; basis = 'OT and IT administration are separate' }
    @{ m = '^OT-(IT-PATH|DMZ-BYPASS)$'; nist = 'SC-7', 'AC-4'; iec = 'SR 5.1', 'SR 5.2'; basis = 'IT to OT traffic passes a controlled zone boundary' }
)

function Read-Json([string]$Path) { return ([IO.File]::ReadAllText($Path) | ConvertFrom-Json -AsHashtable) }
function ConvertTo-Line($Object) { return ($Object | ConvertTo-Json -Depth 8 -Compress) }

$rules = foreach ($f in Get-ChildItem -LiteralPath (Join-Path $root 'rules') -Filter '*.json' | Sort-Object Name) {
    if ($f.Name -eq 'pack.json') { continue }
    foreach ($r in @((Read-Json $f.FullName).rules)) { $r }
}
$base = Read-Json (Join-Path $root 'build/crosswalk/catalog-base.json')
$attack = Read-Json (Join-Path $root 'data/attack/attack-catalog.json')
$imported = @(Get-ChildItem -LiteralPath (Join-Path $root 'build/crosswalk/imported') -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { Read-Json $_.FullName })

$frameworks = [System.Collections.Generic.List[object]]::new()
$hasCis = @($imported | Where-Object { ([string]$_.framework.id).StartsWith('cis-') }).Count -gt 0
foreach ($fw in $base.frameworks) {
    if ($fw.id -eq 'cis-benchmarks' -and $hasCis) { continue }   # a licensed import replaces the placeholder
    if ($fw.id -eq 'mitre-attack-mitigations') { $fw.edition = "Enterprise ATT&CK v$($attack.source.attack.version); ATLAS $($attack.source.atlas.version)" }
    $frameworks.Add($fw)
}
foreach ($doc in $imported) {
    $f = $doc.framework
    $entry = [ordered]@{ id = $f.id; name = $f.name; edition = $f.edition; publisher = $f.publisher; license = $f.license; url = $f.url }
    if ($f.Contains('source')) { $entry.source = [ordered]@{ package = $f.source.package; sha256 = $f.source.sha256; url = $f.source.url; file = $f.source.file; fileSha256 = $f.source.fileSha256 } }
    $entry.note = if ($f.license -eq 'licensed-ids-only') { 'Imported from a licensed review (build/Import-CisMapping.ps1); recommendation numbers only.' } else { 'Imported from the pinned DISA XCCDF by build/Import-StigXccdf.ps1; rows are proposed until reviewed.' }
    $entry.controls = @()
    $frameworks.Add($entry)
}
$known = @{}; foreach ($fw in $frameworks) { $known[$fw.id] = @{}; foreach ($c in @($fw.controls)) { $known[$fw.id][$c.id] = $true } }

$mappings = [System.Collections.Generic.List[object]]::new()
$seedRef = 'VSAT category table (build/New-CrosswalkSeed.ps1)'
foreach ($r in $rules) {
    $nist = [ordered]@{}; $iec = [ordered]@{}
    foreach ($row in $table) {
        if ($r.id -notmatch $row.m) { continue }
        foreach ($c in @($row.nist)) { if ($c -and -not $nist.Contains($c)) { $nist[$c] = $row.basis } }
        foreach ($c in @($row.iec)) { if ($c -and -not $iec.Contains($c)) { $iec[$c] = $row.basis } }
    }
    if (-not $nist.Count) { throw "Rule $($r.id) matches no NIST row in the category table; add a mapping decision." }
    foreach ($pair in @(@{ fw = 'nist-800-53r5'; map = $nist }, @{ fw = 'iec-62443-3-3'; map = $iec })) {
        foreach ($c in $pair.map.Keys) {
            if (-not $known[$pair.fw].ContainsKey($c)) { throw "Control $c ($($pair.fw)) is not in build/crosswalk/catalog-base.json." }
            $mappings.Add([ordered]@{ ruleId = $r.id; framework = $pair.fw; control = $c; relation = 'supports'; status = 'proposed'; basis = $pair.map[$c]; sourceRef = $seedRef })
        }
    }
    $mit = if ($r.Contains('attack') -and $r.attack -is [System.Collections.IDictionary]) { [string]$r.attack.mitigation } else { '' }
    if ($mit) {
        if (-not $attack.mitigations.Contains($mit)) { throw "Rule $($r.id) names mitigation $mit, which is not in the pinned ATT&CK catalog." }
        $mappings.Add([ordered]@{ ruleId = $r.id; framework = 'mitre-attack-mitigations'; control = $mit; relation = 'supports'; status = [string]$r.attack.status; basis = 'rule attack.mitigation'; sourceRef = "rules attack.mitigation; ATT&CK v$($attack.source.attack.version)" })
    }
}
$ruleIds = @{}; foreach ($r in $rules) { $ruleIds[$r.id] = $true }
foreach ($doc in $imported) {
    foreach ($m in @($doc.mappings)) {
        if (-not $ruleIds.ContainsKey($m.ruleId)) { throw "Imported mapping for unknown rule $($m.ruleId) ($($doc.framework.id))." }
        $row = [ordered]@{ ruleId = $m.ruleId; framework = $m.framework; control = $m.control; relation = $m.relation; status = $m.status; basis = $m.basis; sourceRef = $m.sourceRef }
        foreach ($k in 'reviewer', 'reviewedUtc') { if ($m.Contains($k) -and $m[$k]) { $row[$k] = $m[$k] } }
        $mappings.Add($row)
    }
}
$fwOrder = @{}; $i = 0; foreach ($fw in $frameworks) { $fwOrder[$fw.id] = $i++ }
$sorted = @($mappings | Sort-Object { $fwOrder[$_.framework] }, { $_.ruleId }, { $_.control } -Culture $inv)

# One framework or mapping per line keeps the embedded file compact and diffs readable.
$nl = "`n"
$cat = [System.Text.StringBuilder]::new()
[void]$cat.Append('{' + $nl + '  "notes": "Generated by build/New-CrosswalkSeed.ps1. Do not edit by hand. Control IDs are public identifiers; paraphrases are VSAT-written. No standards text.",' + $nl + '  "frameworks": [' + $nl)
[void]$cat.Append((@($frameworks | ForEach-Object { '    ' + (ConvertTo-Line $_) }) -join (',' + $nl)))
[void]$cat.Append($nl + '  ]' + $nl + '}' + $nl)
$cw = [System.Text.StringBuilder]::new()
[void]$cw.Append('{' + $nl + '  "notes": "Generated by build/New-CrosswalkSeed.ps1. Do not edit by hand. status: verified (reviewer, date, edition and source reference), proposed (not reviewed), derived (from a published mapping).",' + $nl + '  "mappings": [' + $nl)
[void]$cw.Append((@($sorted | ForEach-Object { '    ' + (ConvertTo-Line $_) }) -join (',' + $nl)))
[void]$cw.Append($nl + '  ]' + $nl + '}' + $nl)
if (-not (Test-Path -LiteralPath $OutDir)) { [void](New-Item -ItemType Directory -Path $OutDir -Force) }
$enc = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $OutDir 'catalogs.json'), $cat.ToString(), $enc)
[IO.File]::WriteAllText((Join-Path $OutDir 'crosswalk.json'), $cw.ToString(), $enc)
$by = $sorted | Group-Object { $_.framework } | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host ("Wrote {0}: {1} frameworks, {2} mappings ({3})" -f $OutDir, $frameworks.Count, $sorted.Count, ($by -join ', '))
