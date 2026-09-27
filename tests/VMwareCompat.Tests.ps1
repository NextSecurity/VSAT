BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

# Version and build values below come from Broadcom KB 316595 (ESX/ESXi builds),
# KB 326316 (vCenter builds), VMSA-2025-0013, VMSA-2026-0006 and VMSA-2025-0012.

Describe 'Version parsing across VMware releases 7.0 to 9.x' {
    It 'Compare-VsatVersion <A> vs <B> = <Expected>' -ForEach @(
        @{ A = '9.0.0'; B = '8.0.3'; Expected = 1 }
        @{ A = '7.0.3'; B = '9.0.0'; Expected = -1 }
        @{ A = '9.0.2.0100'; B = '9.0.2'; Expected = 1 }
        @{ A = '9.1.0'; B = '9.0.2.0100'; Expected = 1 }
        @{ A = '9.0'; B = '9.0.0.0'; Expected = 0 }
        @{ A = '4.2.1.3.0.24533884'; B = '4.2.1.3'; Expected = 1 }
        @{ A = '9.0.1.0.24952111'; B = '4.2.2'; Expected = 1 }
        @{ A = '4.1.2'; B = '4.1.2.6'; Expected = -1 }
    ) { Compare-VsatVersion $A $B | Should -Be $Expected }

    It 'Get-VsatBranch <Version> = <Branch>' -ForEach @(
        @{ Version = '7.0.3'; Branch = '7.0' }
        @{ Version = '8.0.3'; Branch = '8.0' }
        @{ Version = '9.0.0'; Branch = '9.0' }
        @{ Version = '9.0.2.0100'; Branch = '9.0' }
        @{ Version = '9.1.1.0'; Branch = '9.1' }
        @{ Version = '4.1.2'; Branch = '4.1' }
        @{ Version = '4.2.2.1'; Branch = '4.2' }
        @{ Version = '9.0.1.0.24952111'; Branch = '9.0' }
    ) { Get-VsatBranch $Version | Should -Be $Branch }

    It 'treats maxVersion as inclusive of every update of that branch' {
        $rule = @{ id = 'T-MAX'; applies = @{ maxVersion = '8.0' } }
        foreach ($v in '7.0.3', '8.0.0', '8.0.3', '8.0.3.01000') { Test-VsatApplies -Rule $rule -Asset @{ version = $v; props = @{} } -Context $null | Should -BeNullOrEmpty -Because $v }
        foreach ($v in '9.0.0', '9.1.1.0') { Test-VsatApplies -Rule $rule -Asset @{ version = $v; props = @{} } -Context $null | Should -Match 'up to version 8.0' -Because $v }
    }

    It 'minVersion 7.0 rules apply to ESX 9.x' {
        $rule = @((Get-VsatRulePack).rules | Where-Object { $_.id -eq 'ESXI-EXEC-INSTALLED-ONLY' })[0]
        Test-VsatApplies -Rule $rule -Asset @{ version = '9.0.2'; props = @{} } -Context $null | Should -BeNullOrEmpty
    }

    It 'CIM and SLP service rules are not applicable on ESX 9.x (removed in ESX 9.0) and still apply to 8.0' {
        foreach ($id in 'ESXI-SVC-SLP', 'ESXI-SVC-CIM') {
            $rule = @((Get-VsatRulePack).rules | Where-Object { $_.id -eq $id })[0]
            $rule.applies.source | Should -Match '^https://techdocs\.broadcom\.com/'
            Test-VsatApplies -Rule $rule -Asset @{ version = '9.0.2'; props = @{} } -Context $null | Should -Match 'removed' -Because $id
            Test-VsatApplies -Rule $rule -Asset @{ version = '8.0.3'; props = @{} } -Context $null | Should -BeNullOrEmpty -Because $id
        }
    }
}

Describe 'Advisory and lifecycle evaluation for 7.0, 8.0 and 9.x' {
    BeforeAll {
        $script:AdvRule = @{ id = 'T-ADV'; title = 't'; domain = 'esxi'; severity = 'critical'; rationale = 'r'; check = @{ type = 'script'; name = 'Advisory' } }
        $script:LcRule = @{ id = 'T-LC'; title = 't'; domain = 'esxi'; severity = 'high'; rationale = 'r'; check = @{ type = 'script'; name = 'Lifecycle' } }
        $script:Ctx = @{ now = [DateTime]'2026-09-23' }
        function New-VAsset([string]$Type, [string]$Version, [string]$Build) { [ordered]@{ id = "t:$Type-$Version-$Build"; name = "$Type $Version"; type = $Type; endpoint = 't'; observedUtc = 'x'; version = $Version; build = $Build; props = [ordered]@{}; facts = [ordered]@{} } }
    }

    It '<Type> <Version> build <Build> => <Result>' -ForEach @(
        @{ Type = 'host'; Version = '7.0.3'; Build = '24784741'; Result = 'FAIL'; Has = @('VMSA-2026-0006'); Not = @('VMSA-2025-0013') }
        @{ Type = 'host'; Version = '8.0.3'; Build = '25595708'; Result = 'PASS'; Has = @(); Not = @() }
        @{ Type = 'host'; Version = '9.0.0'; Build = '24755229'; Result = 'FAIL'; Has = @('VMSA-2025-0013', 'VMSA-2026-0006'); Not = @() }
        @{ Type = 'host'; Version = '9.0.1'; Build = '24957456'; Result = 'FAIL'; Has = @('VMSA-2026-0006'); Not = @('VMSA-2025-0013') }
        @{ Type = 'host'; Version = '9.0.2'; Build = '25595025'; Result = 'PASS'; Has = @(); Not = @() }
        @{ Type = 'host'; Version = '9.1.0'; Build = '25370933'; Result = 'FAIL'; Has = @('VMSA-2026-0006'); Not = @() }
        @{ Type = 'host'; Version = '9.1.0'; Build = '25557999'; Result = 'PASS'; Has = @(); Not = @() }
        @{ Type = 'host'; Version = '9.1.1'; Build = '25714478'; Result = 'PASS'; Has = @(); Not = @() }
        @{ Type = 'vcenter'; Version = '8.0.3'; Build = '25600417'; Result = 'PASS'; Has = @(); Not = @() }
        @{ Type = 'vcenter'; Version = '9.0.2'; Build = '25148086'; Result = 'FAIL'; Has = @('VMSA-2026-0006'); Not = @() }
        @{ Type = 'vcenter'; Version = '9.0.2'; Build = '25629525'; Result = 'PASS'; Has = @(); Not = @() }
        @{ Type = 'vcenter'; Version = '9.1.0'; Build = '25573614'; Result = 'FAIL'; Has = @('VMSA-2026-0006'); Not = @() }
        @{ Type = 'vcenter'; Version = '9.1.1'; Build = '25712839'; Result = 'PASS'; Has = @(); Not = @() }
        @{ Type = 'nsx-manager'; Version = '4.1.2'; Build = ''; Result = 'FAIL'; Has = @('VMSA-2025-0012'); Not = @() }
        @{ Type = 'nsx-manager'; Version = '4.2.2.1'; Build = ''; Result = 'PASS'; Has = @(); Not = @() }
    ) {
        $f = Invoke-VsatCheckAdvisory -Rule $script:AdvRule -Asset (New-VAsset $Type $Version $Build) -Check $script:AdvRule.check -Context $script:Ctx
        $f.result | Should -Be $Result -Because $f.observed
        $ids = @($f.advisories | ForEach-Object { $_.id })
        foreach ($h in $Has) { $ids | Should -Contain $h }
        foreach ($n in $Not) { $ids | Should -Not -Contain $n }
    }

    It 'uses the per-entry severity of the 9.0 row (VMSA-2025-0013 is Important for ESX 9.0)' {
        $f = Invoke-VsatCheckAdvisory -Rule $script:AdvRule -Asset (New-VAsset 'host' '9.0.0' '24755229') -Check $script:AdvRule.check -Context $script:Ctx
        (@($f.advisories | Where-Object { $_.id -eq 'VMSA-2025-0013' })[0]).severity | Should -Be 'important'
    }

    It 'labels KEV per CVE: <Type> <Version> build <Build> <Adv> kev=<Kev>' -ForEach @(
        @{ Type = 'host'; Version = '9.0.0'; Build = '24755229'; Adv = 'VMSA-2026-0006'; Kev = $false; Sev = 'critical' }
        @{ Type = 'host'; Version = '8.0.3'; Build = '24022510'; Adv = 'VMSA-2026-0006'; Kev = $false; Sev = 'critical' }
        @{ Type = 'host'; Version = '7.0.3'; Build = '24784741'; Adv = 'VMSA-2026-0006'; Kev = $false; Sev = 'critical' }
        @{ Type = 'vcenter'; Version = '9.0.2'; Build = '25148086'; Adv = 'VMSA-2026-0006'; Kev = $true; Sev = 'critical' }
        @{ Type = 'vcenter'; Version = '8.0.3'; Build = '24022515'; Adv = 'VMSA-2026-0006'; Kev = $true; Sev = 'critical' }
        @{ Type = 'host'; Version = '7.0.3'; Build = '21424296'; Adv = 'VMSA-2024-0013'; Kev = $true; Sev = 'moderate' }
        @{ Type = 'vcenter'; Version = '7.0.3'; Build = '21477706'; Adv = 'VMSA-2024-0013'; Kev = $false; Sev = 'moderate' }
        @{ Type = 'host'; Version = '8.0.3'; Build = '24022510'; Adv = 'VMSA-2025-0004'; Kev = $true; Sev = 'critical' }
    ) {
        $f = Invoke-VsatCheckAdvisory -Rule $script:AdvRule -Asset (New-VAsset $Type $Version $Build) -Check $script:AdvRule.check -Context $script:Ctx
        $hit = @($f.advisories | Where-Object { $_.id -eq $Adv })
        $hit.Count | Should -Be 1 -Because $f.observed
        [bool]$hit[0].kev | Should -Be $Kev
        $hit[0].severity | Should -Be $Sev
    }

    It 'every known-exploited advisory lists its KEV CVEs, all within the advisory' {
        foreach ($a in @((Get-VsatAdvisoryData).advisories | Where-Object { $_.knownExploited })) {
            @($a.knownExploitedCves).Count | Should -BeGreaterThan 0 -Because $a.id
            foreach ($c in $a.knownExploitedCves) { @($a.cves) | Should -Contain $c -Because $a.id }
        }
    }

    It 'NSX 9.x without advisory data is UNKNOWN, never PASS and never a crash' {
        $f = Invoke-VsatCheckAdvisory -Rule $script:AdvRule -Asset (New-VAsset 'nsx-manager' '9.0.1.0.24952111' '') -Check $script:AdvRule.check -Context $script:Ctx
        $f.result | Should -Be 'UNKNOWN'
        $f.observed | Should -Match 'branch 9\.0'
    }

    It 'lifecycle <Type> <Version> => <Result>' -ForEach @(
        @{ Type = 'host'; Version = '7.0.3'; Result = 'FAIL' }
        @{ Type = 'vcenter'; Version = '7.0.3'; Result = 'FAIL' }
        @{ Type = 'host'; Version = '8.0.3'; Result = 'MANUAL' }
        @{ Type = 'host'; Version = '9.0.2'; Result = 'MANUAL' }
        @{ Type = 'host'; Version = '9.1.1'; Result = 'MANUAL' }
        @{ Type = 'vcenter'; Version = '9.0.2'; Result = 'MANUAL' }
        @{ Type = 'nsx-manager'; Version = '4.2.2.1'; Result = 'MANUAL' }
        @{ Type = 'nsx-manager'; Version = '9.0.1.0'; Result = 'MANUAL' }
    ) {
        $f = Invoke-VsatCheckLifecycle -Rule $script:LcRule -Asset (New-VAsset $Type $Version '1') -Check $script:LcRule.check -Context $script:Ctx
        $f.result | Should -Be $Result -Because $f.observed
    }
}

Describe 'vCenter mode: every managed host is collected, unreachable hosts are UNKNOWN' {
    BeforeAll {
        function New-MoRef([string]$Type, [string]$Value) { [pscustomobject]@{ Type = $Type; Value = $Value } }
        function New-FakeHost([string]$Id, [string]$Name, [string]$State, [string]$Version, [string]$Build, [bool]$Maintenance = $false) {
            $svc = @(
                [pscustomobject]@{ Key = 'TSM-SSH'; Label = 'SSH'; Running = $false; Policy = 'off' }
                [pscustomobject]@{ Key = 'TSM'; Label = 'ESXi Shell'; Running = $false; Policy = 'off' }
            )
            $opts = @(
                [pscustomobject]@{ Key = 'UserVars.DcuiTimeOut'; Value = 600 }
                [pscustomobject]@{ Key = 'Security.AccountUnlockTime'; Value = 900 }
            )
            [pscustomobject]@{
                MoRef     = New-MoRef 'HostSystem' $Id
                Name      = $Name
                Parent    = New-MoRef 'ClusterComputeResource' 'domain-c1'
                Runtime   = [pscustomobject]@{ ConnectionState = $State; PowerState = 'poweredOn'; InMaintenanceMode = $Maintenance }
                Summary   = [pscustomobject]@{ Config = [pscustomobject]@{ Product = [pscustomobject]@{ FullName = "VMware ESX $Version build-$Build"; Version = $Version; Build = $Build } } }
                Config    = [pscustomobject]@{
                    LockdownMode = 'lockdownNormal'; AdminDisabled = $true; Certificate = $null; Network = $null
                    DateTimeInfo = [pscustomobject]@{ NtpConfig = [pscustomobject]@{ Server = @('ntp1.example.local') }; Protocol = 'ntp' }
                    Option = $opts
                    Service = [pscustomobject]@{ Service = $svc }
                    Firewall = [pscustomobject]@{ DefaultPolicy = [pscustomobject]@{ IncomingBlocked = $true; OutgoingBlocked = $true }; Ruleset = @() }
                }
                Capability    = [pscustomobject]@{ UefiSecureBoot = $true; TpmSupported = $true; TpmVersion = '2.0' }
                ConfigManager = [pscustomobject]@{ NetworkSystem = New-MoRef 'HostNetworkSystem' "ns-$Id"; VirtualNicManager = New-MoRef 'HostVirtualNicManager' "vnm-$Id" }
                Datastore = @()
                Hardware  = [pscustomobject]@{ SystemInfo = [pscustomobject]@{ Vendor = 'Example'; Model = 'X1' } }
            }
        }
        $script:FakeHosts = @(
            New-FakeHost 'host-10' 'esx90-a.example.local' 'connected' '9.0.2' '25595025'
            New-FakeHost 'host-11' 'esx80-b.example.local' 'connected' '8.0.3' '25595708'
            New-FakeHost 'host-12' 'esx90-c.example.local' 'connected' '9.0.2' '25595025' $true
            New-FakeHost 'host-13' 'esx90-down.example.local' 'notResponding' '9.0.2' '25595025'
            New-FakeHost 'host-14' 'esx90-off.example.local' 'disconnected' '9.1.1' '25714478'
        )
        $cluster = [pscustomobject]@{
            MoRef = New-MoRef 'ClusterComputeResource' 'domain-c1'; Name = 'cl01'; Host = @($script:FakeHosts | ForEach-Object { $_.MoRef })
            ConfigurationEx = [pscustomobject]@{ DasConfig = [pscustomobject]@{ Enabled = $true; AdmissionControlEnabled = $true; AdmissionControlPolicy = $null; HostMonitoring = 'enabled'; VmMonitoring = 'vmMonitoringDisabled'; DefaultVmSettings = $null; HBDatastoreCandidatePolicy = 'allFeasibleDsWithUserPreference' }; DrsConfig = [pscustomobject]@{ Enabled = $true; DefaultVmBehavior = 'fullyAutomated' }; Rule = @() }
            Summary = [pscustomobject]@{ NumHosts = 5; NumEffectiveHosts = 3 }
        }
        function New-FakeVm([string]$Id, [string]$Name, [string]$HostId) {
            [pscustomobject]@{
                MoRef = New-MoRef 'VirtualMachine' $Id; Name = $Name
                Runtime = [pscustomobject]@{ Host = New-MoRef 'HostSystem' $HostId; PowerState = 'poweredOn' }
                Config = [pscustomobject]@{
                    Uuid = "bios-$Id"; InstanceUuid = "inst-$Id"; Template = $false; Firmware = 'efi'; BootOptions = [pscustomobject]@{ EfiSecureBootEnabled = $true }
                    ExtraConfig = @([pscustomobject]@{ Key = 'isolation.tools.copy.disable'; Value = 'TRUE' }, [pscustomobject]@{ Key = 'isolation.tools.paste.disable'; Value = 'TRUE' })
                    Hardware = [pscustomobject]@{ Device = @() }; Version = 'vmx-21'; KeyId = $null; GuestFullName = 'Linux'; Flags = $null; MaxMksConnections = 1
                }
                Guest = [pscustomobject]@{ ToolsVersionStatus2 = 'guestToolsCurrent'; ToolsRunningStatus = 'guestToolsRunning'; Net = @() }
                Snapshot = $null; Datastore = @(); Network = @(); ResourceConfig = $null
            }
        }
        $script:FakeInventory = @{
            VirtualMachine = @((New-FakeVm 'vm-1' 'vm-on-a' 'host-10'), (New-FakeVm 'vm-2' 'vm-on-down' 'host-13'), (New-FakeVm 'vm-3' 'vm-on-off' 'host-14'))
            Datacenter = @([pscustomobject]@{ MoRef = New-MoRef 'Datacenter' 'datacenter-1'; Name = 'dc01'; HostFolder = New-MoRef 'Folder' 'group-h1' })
            ClusterComputeResource = @($cluster)
            HostSystem = $script:FakeHosts
        }
        $script:HostCalls = [System.Collections.Generic.List[string]]::new()
        # PowerCLI stand-ins: read-only shapes only, enough for the collector's property reads.
        function global:Get-View {
            param($Server, $ViewType, $Id, $Property, $SearchRoot, $ErrorAction)
            if ($ViewType) { if ($script:FakeInventory.ContainsKey($ViewType)) { return $script:FakeInventory[$ViewType] }; return @() }
            if ($Id -and $Id.PSObject.Properties['Value'] -and $Id.Value -like 'host-*') { $script:HostCalls.Add("attestation:$($Id.Value)"); return [pscustomobject]@{ Runtime = [pscustomobject]@{ TpmAttestation = [pscustomobject]@{ Status = 'accepted'; Message = $null } } } }
            throw 'The operation is not supported on the object.'
        }
        function global:Get-VMHost { param($Server, $Id, $ErrorAction) $script:HostCalls.Add("vmhost:$($Id.Value)"); [pscustomobject]@{ Id = $Id } }
        function global:Get-EsxCli { param($Server, $VMHost, [switch]$V2, $ErrorAction) $script:HostCalls.Add("esxcli:$($VMHost.Id.Value)"); throw 'esxcli is not available in this test double' }
        function global:Get-VIPermission { param($Server, $ErrorAction) @() }
        function global:Get-VIRole { param($Server, $ErrorAction) @() }

        $script:Ev = New-VsatEvidence -Mode fixture
        $script:Ep = Add-VsatEndpoint -Evidence $script:Ev -Type vcenter -Address 'vc90.example.local'
        $about = [pscustomobject]@{ FullName = 'VMware vCenter 9.0.2 build-25629525'; Version = '9.0.2'; Build = '25629525'; InstanceUuid = '11111111-2222-3333-4444-555555555555'; ApiVersion = '9.0.0.0'; ApiType = 'VirtualCenter' }
        $content = [pscustomobject]@{ About = $about; ExtensionManager = New-MoRef 'ExtensionManager' 'ExtensionManager'; Setting = New-MoRef 'OptionManager' 'VpxSettings'; CryptoManager = New-MoRef 'CryptoManager' 'CryptoManager' }
        $srv = [pscustomobject]@{ ExtensionData = [pscustomobject]@{ Content = $content } }
        Invoke-VsatVSphereCollection -Evidence $script:Ev -Endpoint $script:Ep -Connection $srv
        $script:Hosts = @($script:Ev.assets | Where-Object { $_.type -eq 'host' })
        $script:Res = Invoke-VsatRules -Evidence $script:Ev
    }
    AfterAll { foreach ($f in 'Get-View', 'Get-VMHost', 'Get-EsxCli', 'Get-VIPermission', 'Get-VIRole') { Remove-Item "function:global:$f" -ErrorAction SilentlyContinue } }

    It 'records the vCenter 9 endpoint version and API version' {
        $script:Ep.type | Should -Be 'vcenter'
        $script:Ep.version | Should -Be '9.0.2'
        $script:Ep.apiVersion | Should -Be '9.0.0.0'
        @($script:Ev.assets | Where-Object { $_.type -eq 'vcenter' }).Count | Should -Be 1
    }
    It 'inventories every host managed by the vCenter, on 8.0 and 9.x' {
        $script:Hosts.Count | Should -Be 5
    }
    It 'reports the hosts collector as partial and names the unreachable hosts count' {
        $rec = @($script:Ev.collection.collectors | Where-Object { $_.name -eq 'vsphere.hosts' })[0]
        $rec.status | Should -Be 'partial'
        $rec.error | Should -Match '2 of 5 hosts'
        $rec.objectCount | Should -Be 3
    }
    It 'evaluates VMs on connected hosts normally' {
        $fs = @($script:Res.findings | Where-Object { $_.assetName -eq 'vm-on-a' })
        $fs.Count | Should -BeGreaterThan 3
        @($fs | Where-Object { $_.result -eq 'PASS' }).Count | Should -BeGreaterThan 0
    }
    It 'never passes a VM whose host is disconnected or not responding (cached config)' {
        foreach ($n in 'vm-on-down', 'vm-on-off') {
            $fs = @($script:Res.findings | Where-Object { $_.assetName -eq $n })
            $fs.Count | Should -BeGreaterThan 3
            @($fs | Where-Object { $_.result -in @('PASS', 'ERROR') }) | Should -BeNullOrEmpty -Because $n
            @($fs | Where-Object { $_.result -eq 'UNKNOWN' -and $_.observed -match 'runs on host .*\(not connected\)' }).Count | Should -BeGreaterThan 0 -Because $n
        }
    }
    It 'collects host configuration facts for each connected host (including maintenance mode)' {
        foreach ($h in @($script:Hosts | Where-Object { $_.props.connectionState -eq 'connected' })) {
            foreach ($f in 'lockdown', 'advanced', 'services', 'ntp', 'firewall', 'secureBoot', 'attestation') { $h.facts[$f].status | Should -Be 'ok' -Because "$($h.name) $f" }
            foreach ($f in 'acceptance', 'kernel', 'modules', 'coredump', 'syslog', 'iscsiAdapters') { $h.facts[$f].status | Should -Be 'error' -Because "$($h.name) $f (esxcli failed per host)" }
        }
        foreach ($id in 'host-10', 'host-11', 'host-12') { $script:HostCalls | Should -Contain "esxcli:$id" }
    }
    It 'never calls esxcli or per-host reads on unreachable hosts' {
        foreach ($id in 'host-13', 'host-14') { @($script:HostCalls | Where-Object { $_ -like "*:$id" }) | Should -BeNullOrEmpty }
    }
    It 'marks every host configuration fact of an unreachable host as error with the connection state' {
        foreach ($h in @($script:Hosts | Where-Object { $_.props.connectionState -ne 'connected' })) {
            foreach ($f in 'lockdown', 'advanced', 'services', 'ntp', 'firewall', 'certificate', 'secureBoot', 'attestation', 'acceptance', 'kernel', 'modules', 'coredump', 'syslog', 'iscsiAdapters', 'network', 'vmkernel') {
                $h.facts[$f].status | Should -Be 'error' -Because "$($h.name) $f"
                $h.facts[$f].error | Should -Match ([regex]::Escape($h.props.connectionState))
            }
        }
    }
    It 'evaluates connected hosts normally' {
        (Get-TestFinding $script:Res 'ESXI-SVC-SSH' 'esx90-a.example.local').result | Should -Be 'PASS'
        (Get-TestFinding $script:Res 'ESXI-LOCKDOWN' 'esx80-b.example.local').result | Should -Be 'PASS'
        (Get-TestFinding $script:Res 'ESXI-PATCH-ADV' 'esx90-a.example.local').result | Should -Be 'PASS'
    }
    It 'yields UNKNOWN, never PASS or ERROR, for every check on a disconnected or not-responding host' {
        foreach ($n in 'esx90-down.example.local', 'esx90-off.example.local') {
            $fs = @($script:Res.findings | Where-Object { $_.assetName -eq $n })
            $fs.Count | Should -BeGreaterThan 10
            @($fs | Where-Object { $_.result -in @('PASS', 'ERROR') }) | Should -BeNullOrEmpty -Because $n
            (@($fs | Where-Object { $_.ruleId -eq 'ESXI-SVC-SSH' })[0]).result | Should -Be 'UNKNOWN'
            (@($fs | Where-Object { $_.ruleId -eq 'ESXI-PATCH-ADV' })[0]).result | Should -Be 'UNKNOWN'
            (@($fs | Where-Object { $_.ruleId -eq 'ESXI-PATCH-ADV' })[0]).observed | Should -Match 'not connected'
        }
    }
    It 'keeps collecting the remaining hosts when one host throws mid-collection' {
        $bad = New-FakeHost 'host-20' 'esx-broken.example.local' 'connected' '9.0.2' '25595025'
        $bad.Config | Add-Member -NotePropertyName Network -NotePropertyValue ([pscustomobject]@{ Pnic = 'x' }) -Force
        $bad.Config.Network | Add-Member -MemberType ScriptProperty -Name Vswitch -Value { throw 'simulated property fault' }
        $saved = $script:FakeInventory.HostSystem
        try {
            $script:FakeInventory.HostSystem = @($bad) + @($saved[0])
            $ev = New-VsatEvidence -Mode fixture
            $ep = Add-VsatEndpoint -Evidence $ev -Type vcenter -Address 'vc90b.example.local'
            $about = [pscustomobject]@{ FullName = 'VMware vCenter 9.0.2'; Version = '9.0.2'; Build = '25629525'; InstanceUuid = 'x'; ApiVersion = '9.0.0.0'; ApiType = 'VirtualCenter' }
            $srv = [pscustomobject]@{ ExtensionData = [pscustomobject]@{ Content = [pscustomobject]@{ About = $about; ExtensionManager = $null; Setting = $null; CryptoManager = $null } } }
            Invoke-VsatVSphereCollection -Evidence $ev -Endpoint $ep -Connection $srv
            $hs = @($ev.assets | Where-Object { $_.type -eq 'host' })
            $hs.Count | Should -Be 2
            $rec = @($ev.collection.collectors | Where-Object { $_.name -eq 'vsphere.hosts' })[0]
            $rec.status | Should -Be 'partial'
            $rec.error | Should -Match '1 of 2 hosts'
            (@($hs | Where-Object { $_.name -eq 'esx90-a.example.local' })[0]).facts.services.status | Should -Be 'ok'
            (@($hs | Where-Object { $_.name -eq 'esx-broken.example.local' })[0]).facts.network.status | Should -Be 'error'
        }
        finally { $script:FakeInventory.HostSystem = $saved }
    }
}

Describe 'PowerCLI install forms (VCF.PowerCLI 9.x and VMware.PowerCLI 13.x)' {
    BeforeAll { function New-M([string]$Name, [string]$Version) { [pscustomobject]@{ Name = $Name; Version = [version]$Version } } }
    It 'accepts VCF.PowerCLI 9.x' {
        $s = Get-VsatPowerCliStatus -Modules @((New-M 'VCF.PowerCLI' '9.1.1.25718932'), (New-M 'VMware.VimAutomation.Core' '13.5.1.25718932'))
        $s.status | Should -Be 'ok'
        $s.detail | Should -Match 'VCF\.PowerCLI 9\.1\.1'
    }
    It 'accepts VMware.PowerCLI 13.x' {
        $s = Get-VsatPowerCliStatus -Modules @((New-M 'VMware.PowerCLI' '13.3.0.24145081'), (New-M 'VMware.VimAutomation.Core' '13.3.0.24145081'))
        $s.status | Should -Be 'ok'
        $s.detail | Should -Match 'VMware\.PowerCLI 13\.3'
    }
    It 'accepts the Core module alone (offline package layout)' {
        (Get-VsatPowerCliStatus -Modules @(New-M 'VMware.VimAutomation.Core' '13.5.1.25718932')).status | Should -Be 'ok'
    }
    It 'notes when both install forms are present' {
        $s = Get-VsatPowerCliStatus -Modules @((New-M 'VCF.PowerCLI' '9.1.1.25718932'), (New-M 'VMware.PowerCLI' '13.3.0.24145081'), (New-M 'VMware.VimAutomation.Core' '13.5.1.25718932'))
        $s.status | Should -Be 'ok'
        $s.detail | Should -Match 'Uninstall-Module VMware.PowerCLI'
    }
    It 'fails with the pinned VCF.PowerCLI install command when Core is missing' {
        $s = Get-VsatPowerCliStatus -Modules @()
        $s.status | Should -Be 'fail'
        $lock = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'runtime.lock.json')
        $s.detail | Should -Match ([regex]::Escape("Install-Module VCF.PowerCLI -Scope CurrentUser -RequiredVersion $(($lock.powercli.distribution -split '\s+')[1])"))
    }
    It 'warns (not fails) when only replay/demo is intended' {
        (Get-VsatPowerCliStatus -Modules @() -OfflineOnly).status | Should -Be 'warn'
    }
    It 'warns on a Core module older than 13.x' {
        (Get-VsatPowerCliStatus -Modules @(New-M 'VMware.VimAutomation.Core' '12.7.0.20091293')).status | Should -Be 'warn'
    }
}
