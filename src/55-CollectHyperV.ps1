#region Hyper-V collector
# Read-only Microsoft Hyper-V collection. One self-contained script runs on the host
# (via PowerShell remoting, locally, or exported for air-gapped hosts with
# -ExportCollector hyperv) and returns JSON facts in the VSAT evidence format.
# The script uses Get-* cmdlets and CIM reads only; see tests/ReadOnly.Tests.ps1.

$script:VsatHyperVCollector = @'
# VSAT Hyper-V collector (read-only). Compatible with Windows PowerShell 5.1 and PowerShell 7.
# Output: JSON document on stdout. It never changes configuration.
# Optional: -Since yyyy-MM-dd (engagement start) for the event history; default 30 days back.
param([string]$Since)
$ErrorActionPreference = 'Stop'
function F([scriptblock]$s) {
    try { $v = & $s; if ($null -eq $v) { return @{ status = 'absent'; value = $null } }; return @{ status = 'ok'; value = $v } }
    catch {
        $m = $_.Exception.Message
        $st = 'error'
        if ($m -match 'denied|not have permission|Unauthorized|privilege') { $st = 'denied' }
        elseif ($m -match 'not recognized|not supported|Invalid class|Invalid namespace|not found|cannot find') { $st = 'unsupported' }
        return @{ status = $st; value = $null; error = $m }
    }
}
$now = [DateTime]::UtcNow
$since = $now.Date.AddDays(-30)
if ($Since) { $since = [DateTime]::ParseExact($Since, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal) }
function W([string]$log, [int[]]$ids, [int]$max) {
    # One event log since the window start. A denied read is reported, never an empty list.
    $src = @{ log = $log; status = 'ok'; oldestUtc = $null; oldestId = $null; full = $false; count = 0; truncated = $false }
    $list = @()
    try {
        $info = Get-WinEvent -ListLog $log -ErrorAction Stop
        if ($info.MaximumSizeInBytes -gt 0) { $src.full = ([double]$info.FileSize -ge 0.9 * [double]$info.MaximumSizeInBytes) }
        try { $o = Get-WinEvent -LogName $log -MaxEvents 1 -Oldest -ErrorAction Stop; if ($o) { $src.oldestUtc = $o.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); $src.oldestId = $o.Id } }
        catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' -and $_.Exception.Message -notmatch 'No events were found') { throw } }
        $fh = @{ LogName = $log; StartTime = $since }
        if ($ids) { $fh.Id = $ids }
        try { $list = @(Get-WinEvent -FilterHashtable $fh -MaxEvents $max -ErrorAction Stop) }
        catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' -and $_.Exception.Message -notmatch 'No events were found') { throw } }
    }
    catch {
        $m = $_.Exception.Message
        $src.error = $m
        if ($m -match 'unauthorized|denied|not have permission|privilege') { $src.status = 'denied' }
        elseif ($m -match 'There is not an event log|not found|does not exist') { $src.status = 'unsupported' }
        else { $src.status = 'error' }
    }
    $entries = @(foreach ($e in $list) {
            $user = $null; $target = ''
            $p = @($e.Properties)
            if ($log -eq 'Security' -and $p.Count -ge 8) { $user = "$($p[7].Value)\$($p[6].Value)"; $target = "$($p[3].Value)\$($p[2].Value)" }
            elseif ($e.UserId) { try { $user = $e.UserId.Translate([Security.Principal.NTAccount]).Value } catch { $user = [string]$e.UserId } }
            if ($log -eq 'System' -and $p.Count) { $target = [string]$p[0].Value }
            elseif ($log -like '*Firewall*' -and $p.Count -ge 2) { $target = [string]$p[1].Value }
            $msg = [string]$e.Message
            $first = if ($msg) { ($msg -split "`r?`n")[0] } else { "Event $($e.Id)" }
            if ($first.Length -gt 300) { $first = $first.Substring(0, 300) }
            @{ utc = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); log = $log; id = $e.Id; user = $user; message = $first; target = $target }
        })
    $src.count = $entries.Count
    $src.truncated = ($entries.Count -ge $max)
    return @{ source = $src; entries = $entries }
}
$out = @{ collectorVersion = '1'; collectedUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ'); host = @{}; vms = @(); switches = @() }
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$out.host.name = $cs.DNSHostName
$out.host.domain = $cs.Domain
$out.host.fqdn = if ($cs.PartOfDomain) { "$($cs.DNSHostName).$($cs.Domain)".ToLowerInvariant() } else { $cs.DNSHostName.ToLowerInvariant() }
$out.host.os = @{ caption = $os.Caption; version = $os.Version; build = [string]$os.BuildNumber; installationType = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).InstallationType; ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR }
$f = @{}
$f.vmhost = F { $h = Get-VMHost; @{ migrationEnabled = [bool]$h.VirtualMachineMigrationEnabled; migrationAuth = [string]$h.VirtualMachineMigrationAuthenticationType; anyNetworkForMigration = [bool]$h.UseAnyNetworkForMigration; enhancedSessionMode = [bool]$h.EnableEnhancedSessionMode; numaSpanning = [bool]$h.NumaSpanningEnabled; logicalProcessors = $h.LogicalProcessorCount; memoryGB = [math]::Round($h.MemoryCapacity / 1GB, 1) } }
$f.hotfix = F { $hf = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending); if ($hf.Count -eq 0) { return $null }; @{ lastInstalledUtc = ([DateTime]$hf[0].InstalledOn).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); lastId = $hf[0].HotFixID; count = $hf.Count; ageDays = [int]($now - ([DateTime]$hf[0].InstalledOn).ToUniversalTime()).TotalDays } }
$f.deviceGuard = F { $d = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; @{ vbsStatus = [int]$d.VirtualizationBasedSecurityStatus; servicesRunning = @($d.SecurityServicesRunning | ForEach-Object { [int]$_ }); servicesConfigured = @($d.SecurityServicesConfigured | ForEach-Object { [int]$_ }) } }
$f.secureBoot = F { [bool](Confirm-SecureBootUEFI) }
$f.tpm = F { $t = Get-Tpm; @{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady } }
$f.firewall = F { @(Get-NetFirewallProfile | ForEach-Object { @{ name = [string]$_.Name; enabled = [string]$_.Enabled; defaultInbound = [string]$_.DefaultInboundAction } }) }
$f.smb = F { $s = Get-SmbServerConfiguration; @{ smb1 = [bool]$s.EnableSMB1Protocol; requireSigning = [bool]$s.RequireSecuritySignature; encryptData = [bool]$s.EncryptData } }
$f.services = F { @(Get-Service -Name Spooler, WinRM, RemoteRegistry, TermService, sshd -ErrorAction SilentlyContinue | ForEach-Object { @{ key = $_.Name; running = ($_.Status -eq 'Running'); policy = [string]$_.StartType } }) }
$f.rdp = F { $t = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"; @{ nla = [bool]$t.UserAuthenticationRequired; securityLayer = [int]$t.SecurityLayer } }
$f.replica = F { $r = Get-VMReplicationServer; @{ enabled = [bool]$r.ReplicationEnabled; auth = [string]$r.AllowedAuthenticationType; kerberosPort = $r.KerberosAuthenticationPort; certPort = $r.CertificateAuthenticationPort } }
$f.admins = F { @(Get-LocalGroupMember -Group Administrators | ForEach-Object { @{ name = [string]$_.Name; class = [string]$_.ObjectClass } }) }
$f.hvAdmins = F { @(Get-LocalGroupMember -SID 'S-1-5-32-578' | ForEach-Object { @{ name = [string]$_.Name; class = [string]$_.ObjectClass } }) }
$f.cluster = F { if (-not (Get-Command Get-Cluster -ErrorAction SilentlyContinue)) { return $null }; $c = Get-Cluster; @{ name = [string]$c.Name; nodes = @(Get-ClusterNode | ForEach-Object { [string]$_.Name }) } }
# Change history: service start types, security group membership, firewall rules, Hyper-V VMMS.
# The Security log needs Event Log Readers membership (or local admin).
$evs = @{ windowStartUtc = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); account = [Security.Principal.WindowsIdentity]::GetCurrent().Name; sources = @(); entries = @() }
foreach ($spec in @(
        @{ log = 'System'; ids = @(7040) }
        @{ log = 'Security'; ids = @(4728, 4729, 4732, 4733, 4756, 4757) }
        @{ log = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; ids = @(2004, 2005, 2006, 2052, 2097, 2099) }
        @{ log = 'Microsoft-Windows-Hyper-V-VMMS-Admin'; ids = $null })) {
    $r = W $spec.log $spec.ids 2000
    $evs.sources += $r.source
    $evs.entries += $r.entries
}
$denied = @($evs.sources | Where-Object { $_.status -eq 'denied' })
$f.events = @{ status = $(if ($denied.Count) { 'denied' } else { 'ok' }); value = $evs }
if ($denied.Count) { $f.events.error = (@($denied | ForEach-Object { "$($_.log): $($_.error)" }) -join '; ') }
$out.host.facts = $f
foreach ($sw in @(Get-VMSwitch)) {
    $out.switches += @{ id = [string]$sw.Id; name = $sw.Name; type = [string]$sw.SwitchType; allowManagementOS = [bool]$sw.AllowManagementOS; embeddedTeaming = [bool]$sw.EmbeddedTeamingEnabled; iov = [bool]$sw.IovEnabled
        uplinks = @($sw.NetAdapterInterfaceDescriptions); extensions = @(Get-VMSwitchExtension -VMSwitch $sw -ErrorAction SilentlyContinue | Where-Object { $_.Enabled } | ForEach-Object { $_.Name }) }
}
foreach ($vm in @(Get-VM)) {
    $vf = @{}
    $vf.security = F { $s = Get-VMSecurity -VM $vm; @{ tpm = [bool]$s.TpmEnabled; shielded = [bool]$s.Shielded; encryptState = [bool]$s.EncryptStateAndVmMigrationTraffic } }
    $vf.firmware = F { if ($vm.Generation -ne 2) { return @{ generation = 1 } }; $fw = Get-VMFirmware -VM $vm; @{ generation = 2; secureBoot = [string]$fw.SecureBoot; template = [string]$fw.SecureBootTemplate } }
    $vf.adapters = F { @(Get-VMNetworkAdapter -VM $vm | ForEach-Object { $v = Get-VMNetworkAdapterVlan -VMNetworkAdapter $_; @{ name = $_.Name; switch = $_.SwitchName; switchId = [string]$_.SwitchId; mac = $_.MacAddress; macSpoofing = [string]$_.MacAddressSpoofing; dhcpGuard = [string]$_.DhcpGuard; routerGuard = [string]$_.RouterGuard; portMirroring = [string]$_.PortMirroringMode; vlanMode = [string]$v.OperationMode; accessVlan = $v.AccessVlanId; allowedVlans = [string]$v.AllowedVlanIdListString; ips = @($_.IPAddresses) } }) }
    $vf.integration = F { @(Get-VMIntegrationService -VM $vm | ForEach-Object { @{ name = $_.Name; enabled = [bool]$_.Enabled } }) }
    $vf.checkpoints = F { @(Get-VMSnapshot -VM $vm | ForEach-Object { @{ name = $_.Name; createdUtc = $_.CreationTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); ageDays = [int]($now - $_.CreationTime.ToUniversalTime()).TotalDays } }) }
    $vf.devices = F { @(@(Get-VMDvdDrive -VM $vm | ForEach-Object { @{ type = 'dvd'; path = $_.Path } }) + @(Get-VMComPort -VM $vm | ForEach-Object { @{ type = 'com'; path = $_.Path } }) + @(Get-VMAssignableDevice -VM $vm -ErrorAction SilentlyContinue | ForEach-Object { @{ type = 'dda'; path = $_.LocationPath } }) + @(Get-VMHardDiskDrive -VM $vm | ForEach-Object { @{ type = 'disk'; path = $_.Path; controller = [string]$_.ControllerType } })) }
    $out.vms += @{ id = [string]$vm.Id; name = $vm.Name; state = [string]$vm.State; generation = $vm.Generation; configVersion = [string]$vm.Version; clustered = [bool]$vm.IsClustered; automaticStart = [string]$vm.AutomaticStartAction; checkpointType = [string]$vm.CheckpointType; facts = $vf }
}
$out | ConvertTo-Json -Depth 10 -Compress
'@

function Export-VsatCollector {
    param([Parameter(Mandatory)][ValidateSet('hyperv', 'kvm')][string]$Platform, [Parameter(Mandatory)][string]$OutputDir)
    if (-not (Test-Path -LiteralPath $OutputDir)) { [void](New-Item -ItemType Directory -Path $OutputDir -Force) }
    if ($Platform -eq 'hyperv') {
        $p = Join-Path $OutputDir 'vsat-hyperv-collect.ps1'
        Write-VsatFile -Path $p -Content ("# Run on the Hyper-V host (elevated): powershell -NoProfile -File vsat-hyperv-collect.ps1 -Since <engagement start yyyy-MM-dd> > hyperv-<host>.json`n# Then import with: vsat.ps1 -HyperVEvidence hyperv-<host>.json`n" + $script:VsatHyperVCollector)
    }
    else {
        $p = Join-Path $OutputDir 'vsat-kvm-collect.sh'
        Write-VsatFile -Path $p -Content $script:VsatKvmCollector
    }
    return $p
}

function Invoke-VsatHyperVRemote {
    # Runs the read-only collector on the host. "localhost" runs in-process; "https://host"
    # uses WinRM over HTTPS; otherwise WinRM with Kerberos/Negotiate (message encryption).
    param([Parameter(Mandatory)][string]$Address, [pscredential]$Credential, [string]$Since)
    $sb = [scriptblock]::Create($script:VsatHyperVCollector)
    if ($Address -in @('localhost', '.', '127.0.0.1')) { return [string](& $sb $Since) }
    $useSsl = $Address -like 'https://*'
    $target = $Address -replace '^https?://', ''
    $params = @{ ComputerName = $target; ScriptBlock = $sb; ArgumentList = @($Since); ErrorAction = 'Stop' }
    if ($Credential) { $params.Credential = $Credential }
    if ($useSsl) { $params.UseSSL = $true }
    return [string](Invoke-Command @params)
}

function Add-VsatHyperVEvidence {
    # Maps collector JSON into assets/relationships. Used for live and imported evidence.
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Endpoint, [Parameter(Mandatory)]$Data)
    $ep = $Endpoint.id
    $h = $Data.host
    $os = $h.os
    $Endpoint.product = [string]$os.caption; $Endpoint.version = [string]$os.version; $Endpoint.build = "$($os.build).$($os.ubr)"
    $hid = "${ep}:host"
    $ha = Add-VsatAsset -Evidence $Evidence -Id $hid -Type 'hyperv-host' -Name $(if ($h.fqdn) { $h.fqdn } else { $Endpoint.address }) -Endpoint $ep -Version ([string]$os.version) -Build ([string]$os.build) -Props ([ordered]@{ product = $os.caption; installationType = $os.installationType; ubr = $os.ubr; domain = $h.domain })
    foreach ($k in @($h.facts.Keys)) { $ha.facts[$k] = $h.facts[$k] }
    $cl = Get-VsatProp $h.facts 'cluster.value'
    if ($cl -and $cl.name) {
        $cid = "hvcluster:" + ([string]$cl.name).ToLowerInvariant()
        [void](Add-VsatAsset -Evidence $Evidence -Id $cid -Type 'hyperv-cluster' -Name $cl.name -Endpoint $ep -Props ([ordered]@{ nodes = @($cl.nodes) }))
        Add-VsatRelationship -Evidence $Evidence -Source $cid -Target $hid -Type contains -Provenance 'hyperv.host'
    }
    foreach ($s in @($Data.switches | Where-Object { $_ })) {
        $sid = "${ep}:vswitch/" + $s.id
        $sa = Add-VsatAsset -Evidence $Evidence -Id $sid -Type 'hyperv-vswitch' -Name "$($ha.name) $($s.name)" -Endpoint $ep -Props ([ordered]@{ switchType = $s.type; allowManagementOS = [bool]$s.allowManagementOS; embeddedTeaming = [bool]$s.embeddedTeaming; iov = [bool]$s.iov; uplinks = @($s.uplinks); extensions = @($s.extensions) })
        Add-VsatRelationship -Evidence $Evidence -Source $hid -Target $sid -Type contains -Provenance 'hyperv.network'
    }
    foreach ($v in @($Data.vms | Where-Object { $_ })) {
        $vid = "${ep}:vm/" + $v.id
        $ips = @($v.facts.adapters.value | Where-Object { $_ } | ForEach-Object { @($_.ips) } | Where-Object { $_ })
        $va = Add-VsatAsset -Evidence $Evidence -Id $vid -Type 'hyperv-vm' -Name $v.name -Endpoint $ep -Props ([ordered]@{ vmId = $v.id; state = $v.state; generation = $v.generation; configVersion = $v.configVersion; clustered = [bool]$v.clustered; automaticStart = $v.automaticStart; checkpointType = $v.checkpointType; ipAddresses = $ips })
        foreach ($k in @($v.facts.Keys)) { $va.facts[$k] = $v.facts[$k] }
        Add-VsatRelationship -Evidence $Evidence -Source $vid -Target $hid -Type runs-on -Provenance 'hyperv.vms'
        foreach ($ad in @($v.facts.adapters.value | Where-Object { $_ -and $_.switchId })) {
            Add-VsatRelationship -Evidence $Evidence -Source $vid -Target ("${ep}:vswitch/" + $ad.switchId) -Type connects -Provenance 'hyperv.vms' -Props ([ordered]@{ nic = $ad.name; vlanMode = $ad.vlanMode; vlan = $ad.accessVlan })
        }
    }
}

function Invoke-VsatHyperVCollection {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Endpoint, [pscredential]$Credential, [string]$ImportedJson)
    $vsatHvEndpoint = $Endpoint
    $json = $ImportedJson
    $vsatHvSince = (Get-VsatChangeWindow -Evidence $Evidence).startUtc.Substring(0, 10)
    Invoke-VsatCollector -Evidence $Evidence -Name 'hyperv.host' -Endpoint $Endpoint.id -Affects @('HV-*') -Script {
        if (-not $json) { $json = Invoke-VsatHyperVRemote -Address $vsatHvEndpoint.address -Credential $Credential -Since $vsatHvSince }
        $script:VsatHvData = ConvertFrom-VsatJson $json
        Add-VsatHyperVEvidence -Evidence $Evidence -Endpoint $vsatHvEndpoint -Data $script:VsatHvData
        1
    }
    $ok = @($Evidence.collection.collectors | Where-Object { $_.name -eq 'hyperv.host' -and $_.endpoint -eq $Endpoint.id })[-1].status -eq 'ok'
    foreach ($n in 'hyperv.vms', 'hyperv.network') {
        $cnt = if ($ok) { if ($n -eq 'hyperv.vms') { @($script:VsatHvData.vms).Count } else { @($script:VsatHvData.switches).Count } } else { 0 }
        $Evidence.collection.collectors.Add([ordered]@{ name = $n; endpoint = $Endpoint.id; status = $(if ($ok) { 'ok' } else { 'skipped' }); startedUtc = (Get-VsatUtcNow); endedUtc = (Get-VsatUtcNow); objectCount = $cnt; error = $(if ($ok) { $null } else { 'Host collection failed' }); affects = @() })
    }
    $Endpoint.status = if ($ok) { 'collected' } else { 'failed' }
}

#endregion Hyper-V collector
