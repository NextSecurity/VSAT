BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Fx = Join-Path $PSScriptRoot 'fixtures/changes'
    $script:RunStart = '2026-09-26T10:00:00Z'
    $script:Window = '2026-09-12T00:00:00Z'

    function Get-FxVIEvents {
        # Fixture records become objects typed like PowerCLI's VMware.Vim.* event classes.
        $j = Get-Content -Raw (Join-Path $script:Fx 'vcenter-events.json') | ConvertFrom-Json
        $objs = foreach ($e in $j.events) { $e.PSObject.TypeNames.Insert(0, "VMware.Vim.$($e.type)"); $e }
        return @{ events = @($objs); account = $j.account; sessionKey = $j.currentSessionKey }
    }
    function New-FxVCenterFact {
        param([bool]$Covers = $true, [int]$MaxSamples = 50000)
        $v = Get-FxVIEvents
        return (ConvertTo-VsatVIEventFact -Events $v.events -WindowStartUtc $script:Window -Account $v.account -SessionKey $v.sessionKey -CoversWindowStart $Covers -MaxSamples $MaxSamples)
    }
    function Get-FxEvidence {
        # Demo lab with a fixed run time and engagement start, and the vCenter fixture as its events fact.
        param([bool]$Covers = $true)
        $ev = Get-TestEvidence
        $ev.run.startedUtc = $script:RunStart; $ev.run.endedUtc = '2026-09-26T10:05:00Z'
        $ev.run.engagementStartUtc = $script:Window
        $root = Get-TestAsset $ev 'vc01.example.local' 'vcenter'
        Set-VsatFact -Asset $root -Name 'events' -Value (New-FxVCenterFact -Covers $Covers)
        return $ev
    }
    function Get-KvmText {
        param([string]$Changes = 'kvm-changes.txt')
        $base = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/kvm-collector.txt'))
        $add = [IO.File]::ReadAllText((Join-Path $script:Fx $Changes))
        return $base.Replace('==VSAT:SECTION end==', $add.TrimEnd() + "`n`n==VSAT:SECTION end==")
    }
    function Add-FxKvm {
        param($Evidence, [string]$Changes = 'kvm-changes.txt')
        $ep = Add-VsatEndpoint -Evidence $Evidence -Type kvm -Address 'kvm01.example.local'
        Invoke-VsatKvmCollection -Evidence $Evidence -Endpoint $ep -ImportedText (Get-KvmText $Changes)
        return $ep
    }
    function Add-FxHyperV {
        param($Evidence)
        $hv = ConvertFrom-VsatJson ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/hyperv-collector.json')))
        $hv.host.facts.events = ConvertFrom-VsatJson ([IO.File]::ReadAllText((Join-Path $script:Fx 'windows-events.json')))
        $ep = Add-VsatEndpoint -Evidence $Evidence -Type hyperv -Address 'hv01.example.local'
        Invoke-VsatHyperVCollection -Evidence $Evidence -Endpoint $ep -ImportedJson (ConvertTo-VsatJson $hv)
        return $ep
    }
    function Get-ChangeDomain { param($Results) return @($Results.coverage.domains | Where-Object { $_.id -eq 'change-history' })[0] }
    function Invoke-FxMain {
        param([hashtable]$A)
        $base = @{ Cli = $true; NoBrowser = $true; Profile = 'standard' }
        foreach ($k in $A.Keys) { $base[$k] = $A[$k] }
        return (Invoke-VsatMain -A $base)
    }
}

Describe 'Receipt code' {
    BeforeAll {
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('vsat-rc-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $script:Tmp)
        $script:Pkg = Join-Path $script:Tmp 'fixed.vsat.zip'
        [IO.File]::WriteAllBytes($script:Pkg, [Text.Encoding]::UTF8.GetBytes('VSAT receipt test package'))
    }
    AfterAll { Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue }
    It 'is deterministic and shaped VSAT-XXXX-XXXX-XXXX-XXXX (Crockford base32)' {
        $a = Get-VsatReceipt -Path $script:Pkg
        $a | Should -Match '^VSAT(-[0-9A-HJKMNP-TV-Z]{4}){4}$'
        Get-VsatReceipt -Path $script:Pkg | Should -Be $a
    }
    It 'encodes the first 80 bits of the SHA-256 of the package' {
        $h = [Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($script:Pkg))
        $alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
        $bits = -join ($h[0..9] | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') })
        $code = -join (0..15 | ForEach-Object { $alphabet[[Convert]::ToInt32($bits.Substring($_ * 5, 5), 2)] })
        Get-VsatReceipt -Path $script:Pkg | Should -Be ('VSAT-' + $code.Substring(0, 4) + '-' + $code.Substring(4, 4) + '-' + $code.Substring(8, 4) + '-' + $code.Substring(12, 4))
    }
    It 'changes when one byte of the package changes' {
        $a = Get-VsatReceipt -Path $script:Pkg
        $p2 = Join-Path $script:Tmp 'changed.vsat.zip'
        $b = [IO.File]::ReadAllBytes($script:Pkg); $b[3] = $b[3] -bxor 1
        [IO.File]::WriteAllBytes($p2, $b)
        Get-VsatReceipt -Path $p2 | Should -Not -Be $a
    }
    It 'accepts the code as read aloud (case, dashes, spaces, O/I/L aliases)' {
        $a = Get-VsatReceipt -Path $script:Pkg
        Test-VsatReceipt -Path $script:Pkg -Code $a.ToLowerInvariant() | Should -BeTrue
        Test-VsatReceipt -Path $script:Pkg -Code ($a -replace '-', ' ') | Should -BeTrue
        Test-VsatReceipt -Path $script:Pkg -Code ($a.Substring(5) -replace '-', '') | Should -BeTrue
        Test-VsatReceipt -Path $script:Pkg -Code ($a.Replace('0', 'O').Replace('1', 'I')) | Should -BeTrue
        Test-VsatReceipt -Path $script:Pkg -Code 'VSAT-0000-0000-0000-0000' | Should -BeFalse
        { Test-VsatReceipt -Path $script:Pkg -Code 'VSAT-12' } | Should -Throw '*format*'
    }
}

Describe 'Collect-only, receipt and replay (-CollectOnly, -Replay -Receipt)' {
    BeforeAll {
        $script:Base = Join-Path ([IO.Path]::GetTempPath()) ('vsat-co-' + [guid]::NewGuid().ToString('N'))
        $script:CoDir = Join-Path $script:Base 'collect'
        $script:CoExit = Invoke-FxMain @{ Demo = $true; CollectOnly = $true; OutputPath = $script:CoDir }
        $script:Zip = Join-Path $script:CoDir 'assessment.vsat.zip'
        $script:Manifest = Get-Content -Raw (Join-Path $script:CoDir 'manifest.json') | ConvertFrom-Json
    }
    AfterAll { Remove-Item -Recurse -Force $script:Base -ErrorAction SilentlyContinue }
    It 'exits 0 and writes exactly assessment.vsat.zip, collection.log and manifest.json' {
        $script:CoExit | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:CoDir -Force | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('assessment.vsat.zip', 'collection.log', 'manifest.json')
    }
    It 'records the receipt in manifest.json and collection.log' {
        $script:Manifest.receipt | Should -Be (Get-VsatReceipt -Path $script:Zip)
        (Get-Content -Raw (Join-Path $script:CoDir 'collection.log')) | Should -Match ([regex]::Escape($script:Manifest.receipt))
        $script:Manifest.package.sha256 | Should -Be (Get-VsatSha256 -Path $script:Zip)
    }
    It 'packages evidence only (no findings or report)' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [IO.Compression.ZipFile]::OpenRead($script:Zip)
        try { @($z.Entries | ForEach-Object { $_.FullName } | Sort-Object) | Should -Be @('collection.log', 'evidence.json', 'manifest.json') } finally { $z.Dispose() }
    }
    It 'replays with a matching receipt into the full report, marked verified' {
        $d = Join-Path $script:Base 'replay-ok'
        $x = Invoke-FxMain @{ Replay = $script:Zip; Receipt = $script:Manifest.receipt; OutputPath = $d }
        $x | Should -BeIn @(0, 1, 2)
        Join-Path $d 'report.html' | Should -Exist
        Join-Path $d 'changes.csv' | Should -Exist
        $r = Get-Content -Raw (Join-Path $d 'results.json') | ConvertFrom-Json
        $r.receiptVerification.verified | Should -BeTrue
        $r.receiptVerification.code | Should -Be $script:Manifest.receipt
        @($r.analysis.changes.entries).Count | Should -BeGreaterThan 0
    }
    It 'exits 3 on a wrong receipt code' {
        $x = Invoke-FxMain @{ Replay = $script:Zip; Receipt = 'VSAT-0000-0000-0000-0000'; OutputPath = (Join-Path $script:Base 'replay-bad') }
        $x | Should -Be 3
        Join-Path $script:Base 'replay-bad/report.html' | Should -Not -Exist
    }
    It 'exits 3 on a tampered package' {
        $t = Join-Path $script:Base 'tampered.vsat.zip'
        Copy-Item $script:Zip $t
        $fs = [IO.File]::Open($t, 'Append'); $fs.WriteByte(0); $fs.Dispose()
        Invoke-FxMain @{ Replay = $t; Receipt = $script:Manifest.receipt; OutputPath = (Join-Path $script:Base 'replay-tampered') } | Should -Be 3
    }
    It 'refuses -Receipt without -Replay' {
        { Invoke-FxMain @{ Demo = $true; Receipt = $script:Manifest.receipt; OutputPath = (Join-Path $script:Base 'noreplay') } } | Should -Throw '*-Replay*'
    }
    It 'prints the receipt as the last CLI line of a normal run' {
        $d = Join-Path $script:Base 'normal'
        $out = & pwsh -NoProfile -File $script:VsatScript -Demo -Cli -NoBrowser -OutputPath $d 6>&1 2>&1 | Out-String
        $m = Get-Content -Raw (Join-Path $d 'manifest.json') | ConvertFrom-Json
        $m.receipt | Should -Be (Get-VsatReceipt -Path (Join-Path $d 'assessment.vsat.zip'))
        (@($out.TrimEnd() -split "`r?`n") | Where-Object { $_.Trim() })[-1] | Should -Match ([regex]::Escape($m.receipt))
    }
}

Describe 'Engagement window (-EngagementStart)' {
    It 'parses yyyy-MM-dd as UTC midnight' {
        (Resolve-VsatEngagementStart -Value '2026-09-12' -RunStartUtc $script:RunStart).utc | Should -Be '2026-09-12T00:00:00Z'
    }
    It 'rejects other formats and future dates' {
        { Resolve-VsatEngagementStart -Value '12/09/2026' -RunStartUtc $script:RunStart } | Should -Throw '*yyyy-MM-dd*'
        { Resolve-VsatEngagementStart -Value '2026-10-30' -RunStartUtc $script:RunStart } | Should -Throw '*future*'
    }
    It 'limits the lookback to 180 days' {
        $r = Resolve-VsatEngagementStart -Value '2025-01-01' -RunStartUtc $script:RunStart
        $r.clamped | Should -BeTrue
        $r.utc | Should -Be '2026-03-30T00:00:00Z'
    }
    It 'defaults to 30 days before the run' {
        $ev = Get-TestEvidence
        $ev.run.startedUtc = $script:RunStart
        $ev.run.Remove('engagementStartUtc')
        (Get-VsatChangeWindow -Evidence $ev).startUtc | Should -Be '2026-08-27T00:00:00Z'
        (Get-VsatChangeWindow -Evidence $ev).source | Should -Be 'default'
    }
}

Describe 'vCenter events' {
    It 'records oldestUtc, truncated, the account and only categorized records' {
        $f = New-FxVCenterFact
        $f.truncated | Should -BeFalse
        $f.oldestUtc | Should -Be '2026-09-05T12:00:00Z'
        $f.account | Should -Be 'EXAMPLE\svc-vsat'
        $f.coversWindowStart | Should -BeTrue
        # powerOn (no category) and the solution-user login are dropped
        @($f.records | Where-Object { $_.descriptionId -eq 'VirtualMachine.powerOn' }).Count | Should -Be 0
        @($f.records | Where-Object { $_.user -like '*vpxd-extension*' }).Count | Should -Be 0
        @($f.records).Count | Should -Be 11
    }
    It 'marks the result truncated when MaxSamples is reached' {
        (New-FxVCenterFact -MaxSamples 13).truncated | Should -BeTrue
    }
    It 'normalizes into categorized entries on the right assets, inside the window only' {
        $ch = Get-VsatChangeAnalysis -Evidence (Get-FxEvidence)
        $ch.windowStartUtc | Should -Be $script:Window
        $svc = @($ch.entries | Where-Object { $_.category -eq 'service' -and $_.utc -eq '2026-09-23T14:03:11Z' })[0]
        $svc.assetId | Should -Be 'ep-vc01:host-10'
        $svc.endpointId | Should -Be 'ep-vc01'
        $svc.user | Should -Be 'EXAMPLE\jdoe'
        $svc.source | Should -Be 'vcenter-event'
        $svc.id | Should -Match '^C-[0-9a-f]{8}$'
        (@($ch.entries | Where-Object { $_.category -eq 'access' -and $_.assetId -eq 'ep-vc01:domain-c8' })).Count | Should -Be 1
        (@($ch.entries | Where-Object { $_.category -eq 'vm' -and $_.assetId -eq 'ep-vc01:vm-201' })).Count | Should -Be 1
        (@($ch.entries | Where-Object { $_.category -eq 'settings' -and $_.assetId -eq 'ep-vc01:host-50' })).Count | Should -Be 1
        (@($ch.entries | Where-Object { $_.utc -lt $script:Window })).Count | Should -Be 0
        $ch.historyStartUtcByEndpoint['ep-vc01'] | Should -Be $script:Window
        # time-ordered, newest first
        $ch.entries[0].utc | Should -BeGreaterOrEqual $ch.entries[-1].utc
    }
    It 'uses a denied events fact as UNKNOWN coverage, never as an empty history' {
        $ev = Get-TestEvidence
        $root = Get-TestAsset $ev 'vc01.example.local' 'vcenter'
        Set-VsatFact -Asset $root -Name 'events' -Status denied -Value $null -ErrorMessage 'NoPermission: System.View'
        $d = Get-ChangeDomain (Get-TestResults $ev)
        $d.state | Should -Be 'UNKNOWN'
        ($d.missing -join ' ') | Should -Match 'denied'
    }
}

Describe 'Hyper-V events and KVM changes' {
    It 'maps Windows events to entries and reports the denied Security log as UNKNOWN' {
        $ev = Get-FxEvidence
        $ep = Add-FxHyperV $ev
        $host1 = @($ev.assets | Where-Object { $_.type -eq 'hyperv-host' })[0]
        $host1.facts.events.status | Should -Be 'denied'
        $ch = Get-VsatChangeAnalysis -Evidence $ev
        $svc = @($ch.entries | Where-Object { $_.source -eq 'windows-event' -and $_.category -eq 'service' })
        $svc.Count | Should -Be 1
        $svc[0].assetId | Should -Be $host1.id
        $svc[0].user | Should -Be 'EXAMPLE\jdoe'
        (@($ch.entries | Where-Object { $_.source -eq 'windows-event' -and $_.category -eq 'firewall' })).Count | Should -Be 1
        (@($ch.entries | Where-Object { $_.source -eq 'windows-event' -and $_.category -eq 'vm' })).Count | Should -Be 1
        # 7045 has no category mapping
        (@($ch.entries | Where-Object { $_.source -eq 'windows-event' })).Count | Should -Be 3
        $d = Get-ChangeDomain (Get-TestResults $ev)
        $d.state | Should -Be 'UNKNOWN'
        ($d.missing -join ' ') | Should -Match 'Security'
    }
    It 'parses KVM file mtimes, package history and logins into entries' {
        $ev = Get-FxEvidence
        [void](Add-FxKvm $ev)
        $kh = @($ev.assets | Where-Object { $_.type -eq 'kvm-host' })[0]
        $kh.facts.changes.status | Should -Be 'ok'
        $kh.facts.changes.value.account | Should -Be 'vsat'
        $ch = Get-VsatChangeAnalysis -Evidence $ev
        $k = @($ch.entries | Where-Object { $_.endpointId -eq $kh.endpoint })
        @($k | Where-Object { $_.source -eq 'file-mtime' -and $_.category -eq 'access' -and $_.action -match 'sshd_config' }).Count | Should -Be 1
        $vmAsset = @($ev.assets | Where-Object { $_.type -eq 'kvm-vm' -and $_.name -eq 'web-kvm01' })[0]
        @($k | Where-Object { $_.source -eq 'file-mtime' -and $_.category -eq 'vm' })[0].assetId | Should -Be $vmAsset.id
        @($k | Where-Object { $_.source -eq 'file-mtime' -and $_.category -eq 'firewall' }).Count | Should -Be 1
        @($k | Where-Object { $_.action -match '/etc/group' }).Count | Should -Be 0
        $pkg = @($k | Where-Object { $_.source -eq 'package-log' })
        $pkg.Count | Should -BeGreaterOrEqual 1
        $pkg[0].category | Should -Be 'patch'
        ($pkg.action -join ' ') | Should -Match 'openssl'
        $logins = @($k | Where-Object { $_.source -eq 'wtmp' })
        $logins.Count | Should -Be 3
        @($logins | Where-Object { $_.user -eq 'vsat' -and $_.utc -eq '2026-09-24T21:10:00Z' }).Count | Should -Be 1
        $s = @($ch.accountSessions | Where-Object { $_.endpointId -eq $kh.endpoint })[0]
        $s.count | Should -Be 2
    }
    It 'records denied KVM reads as a denied fact with the unreadable sources, and UNKNOWN coverage' {
        $ev = Get-TestEvidence
        [void](Add-FxKvm $ev 'kvm-changes-denied.txt')
        $kh = @($ev.assets | Where-Object { $_.type -eq 'kvm-host' })[0]
        $kh.facts.changes.status | Should -Be 'denied'
        $kh.facts.changes.value.deniedPaths | Should -Contain '/etc/sudoers.d'
        $kh.facts.changes.value.packages.status | Should -Be 'denied'
        $kh.facts.changes.value.logins.status | Should -Be 'denied'
        $d = Get-ChangeDomain (Get-TestResults $ev)
        $d.state | Should -Be 'UNKNOWN'
        ($d.missing -join ' ') | Should -Match 'sudoers\.d'
        ($d.missing -join ' ') | Should -Match 'wtmp'
    }
}

Describe 'NSX entries from _last_modified_*' {
    It 'converts NSX epoch-millisecond timestamps' {
        $m = ConvertTo-VsatNsxModified ([pscustomobject]@{ _last_modified_time = 1790070191000; _last_modified_user = 'admin' })
        $m.lastModifiedUtc | Should -Be '2026-09-22T09:43:11Z'
        $m.lastModifiedUser | Should -Be 'admin'
        (ConvertTo-VsatNsxModified ([pscustomobject]@{ display_name = 'x' })).Count | Should -Be 0
    }
    It 'keeps only objects modified inside the window' {
        $ev = Get-FxEvidence
        $rules = @($ev.assets | Where-Object { $_.type -eq 'nsx-rule' } | Sort-Object { $_.id })
        foreach ($r in $rules) { $r.props.Remove('lastModifiedUtc'); $r.props.Remove('lastModifiedUser') }
        $rules[0].props.lastModifiedUtc = '2026-09-22T09:43:11Z'; $rules[0].props.lastModifiedUser = 'admin'
        $rules[1].props.lastModifiedUtc = '2026-08-01T00:00:00Z'; $rules[1].props.lastModifiedUser = 'admin'
        $ch = Get-VsatChangeAnalysis -Evidence $ev
        $nsx = @($ch.entries | Where-Object { $_.source -eq 'nsx-object' -and $_.assetId -in @($rules[0].id, $rules[1].id) })
        $nsx.Count | Should -Be 1
        $nsx[0].assetId | Should -Be $rules[0].id
        $nsx[0].category | Should -Be 'firewall'
        $nsx[0].user | Should -Be 'admin'
    }
}

Describe 'Changed during engagement' {
    BeforeAll { $script:Res = Get-TestResults (Get-FxEvidence) }
    It 'annotates a PASS whose asset changed in the rule category, and keeps it a PASS' {
        $f = Get-TestFinding $script:Res 'ESXI-SVC-SSH' 'esx01.example.local'
        $f.result | Should -Be 'PASS'
        @($f.changedInWindow).Count | Should -BeGreaterOrEqual 1
        $ids = @($script:Res.analysis.changes.entries | Where-Object { $_.assetId -eq 'ep-vc01:host-10' -and $_.category -eq 'service' } | ForEach-Object { $_.id })
        @($f.changedInWindow | Where-Object { $ids -notcontains $_ }).Count | Should -Be 0
    }
    It 'does not annotate a finding whose rule category differs' {
        $f = Get-TestFinding $script:Res 'ESXI-LOCKDOWN' 'esx01.example.local'
        @($f.changedInWindow | Where-Object { $_ }).Count | Should -Be 0
    }
    It 'counts passing checks that changed during the engagement' {
        $script:Res.analysis.changes.summary.changedPassing | Should -BeGreaterOrEqual 1
    }
    It 'gives every automated rule that matters a changeCategory from the category list' {
        $cats = @((Get-VsatChangeCategories).categories.Keys)
        $withCat = @((Get-VsatRulePack).rules | Where-Object { Get-VsatProp $_ 'changeCategory' })
        $withCat.Count | Should -BeGreaterThan 20
        foreach ($r in $withCat) { $cats | Should -Contain ([string]$r.changeCategory) -Because $r.id }
        foreach ($id in 'ESXI-SVC-SSH', 'ESXI-LOCKDOWN', 'ESXI-FW-ALLIP', 'ESXI-PATCH-ADV', 'HV-FIREWALL', 'KVM-SSH-ROOT', 'NSX-DFW-ANYANY', 'VM-COPY-DISABLE') {
            (Get-VsatProp (@((Get-VsatRulePack).rules | Where-Object { $_.id -eq $id })[0]) 'changeCategory') | Should -Not -BeNullOrEmpty -Because $id
        }
    }
}

Describe 'History gaps (change-history coverage)' {
    It 'is ASSESSED when every endpoint history covers the window' {
        (Get-ChangeDomain (Get-TestResults (Get-FxEvidence))).state | Should -Be 'ASSESSED'
    }
    It 'is PARTIAL with both dates when vCenter history starts after the engagement start' {
        $ev = Get-FxEvidence -Covers $false
        $root = Get-TestAsset $ev 'vc01.example.local' 'vcenter'
        $root.facts.events.value.oldestUtc = '2026-09-15T08:00:00Z'
        $d = Get-ChangeDomain (Get-TestResults $ev)
        $d.state | Should -Be 'PARTIAL'
        $txt = (@($d.missing) + $d.detail) -join ' '
        $txt | Should -Match 'History starts 2026-09-15'
        $txt | Should -Match 'engagement started 2026-09-12'
        $d.mandatory | Should -BeFalse
    }
    It 'is PARTIAL when the KVM package log starts after the engagement start' {
        $ev = Get-FxEvidence
        [void](Add-FxKvm $ev)
        $d = Get-ChangeDomain (Get-TestResults $ev)
        $d.state | Should -Be 'PARTIAL'
        ($d.missing -join ' ') | Should -Match 'History starts 2026-09-15'
    }
    It 'never changes the exit code (non-mandatory)' {
        $a = Get-TestResults (Get-FxEvidence)
        $ev = Get-FxEvidence -Covers $false
        (Get-TestAsset $ev 'vc01.example.local' 'vcenter').facts.events.value.oldestUtc = '2026-09-15T08:00:00Z'
        (Get-TestResults $ev).status.exitCode | Should -Be $a.status.exitCode
    }
}

Describe 'Earlier-runs detector (account sessions)' {
    It 'counts three earlier logins of the VSAT account and excludes the current session' {
        $ch = Get-VsatChangeAnalysis -Evidence (Get-FxEvidence)
        $s = @($ch.accountSessions | Where-Object { $_.endpointId -eq 'ep-vc01' })[0]
        $s.user | Should -Be 'EXAMPLE\svc-vsat'
        $s.count | Should -Be 3
        $s.firstUtc | Should -Be '2026-09-17T12:00:00Z'
        $s.lastUtc | Should -Be '2026-09-24T21:10:00Z'
    }
}

Describe 'Replay of packages without change history' {
    It 'reports change-history UNKNOWN with a clear reason for a 2.0 package, without error' {
        $txt = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/evidence-2.0.json'))
        $ev = ConvertTo-VsatLiveEvidence (ConvertFrom-VsatJson $txt)
        $r = Invoke-VsatAnalysisPipeline -Evidence $ev
        $d = Get-ChangeDomain $r
        $d.state | Should -BeIn @('UNKNOWN', 'NOT_APPLICABLE')
        $d.detail | Should -Match 'before VSAT 2\.4|no change history'
        @($r.analysis.changes.entries).Count | Should -Be 0
    }
}

Describe 'Demo lab' {
    BeforeAll { $script:Demo = Get-TestResults }
    It 'shows a non-empty timeline, a changed PASS and an earlier VSAT-account session' {
        @($script:Demo.analysis.changes.entries).Count | Should -BeGreaterThan 3
        @($script:Demo.findings | Where-Object { $_.result -eq 'PASS' -and @($_.changedInWindow).Count }).Count | Should -BeGreaterOrEqual 1
        @($script:Demo.analysis.changes.accountSessions | Where-Object { $_.count -ge 1 }).Count | Should -BeGreaterOrEqual 1
        (Get-ChangeDomain $script:Demo).state | Should -Be 'ASSESSED'
    }
    It 'marks only the checks for a named setting or service, not the whole category' {
        $named = @($script:Demo.analysis.changes.entries | Where-Object { $_.category -in @('settings', 'service') -and $_.action -match '\([^()]+\)\s*$' } | ForEach-Object { $_.id })
        $named.Count | Should -BeGreaterThan 0
        $marked = @($script:Demo.findings | Where-Object { @($_.changedInWindow | Where-Object { $named -contains $_ }).Count } | ForEach-Object { $_.ruleId } | Sort-Object -Unique)
        $marked | Should -Be @('ESXI-ACCOUNT-LOCK', 'ESXI-SVC-SSH')
    }
}

Describe 'Change outputs' {
    BeforeAll {
        $script:Out = Join-Path ([IO.Path]::GetTempPath()) ('vsat-chg-' + [guid]::NewGuid().ToString('N'))
        $ev = Get-FxEvidence
        $root = Get-TestAsset $ev 'vc01.example.local' 'vcenter'
        $root.facts.events.value.records += [ordered]@{ utc = '2026-09-25T10:00:00Z'; type = 'TaskEvent'; descriptionId = 'host.ServiceSystem.start'; eventTypeId = $null; user = '=cmd|calc'; message = '=HYPERLINK("x")'; entity = [ordered]@{ type = 'HostSystem'; moref = 'host-10'; name = 'esx01.example.local' }; sessionId = $null }
        $res = Get-TestResults $ev
        [void](Write-VsatOutputs -Evidence $ev -Results $res -OutputDir $script:Out)
    }
    AfterAll { Remove-Item -Recurse -Force $script:Out -ErrorAction SilentlyContinue }
    It 'writes changes.csv with formula injection neutralized' {
        $csv = Get-Content -Raw (Join-Path $script:Out 'changes.csv')
        $csv | Should -Match '^"?id"?,'
        $csv | Should -Match ([regex]::Escape('"''=cmd|calc"'))
        $csv | Should -Not -Match ',"=cmd'
    }
    It 'keeps on-disk manifest hashes valid after the receipt is added' {
        $m = Get-Content -Raw (Join-Path $script:Out 'manifest.json') | ConvertFrom-Json
        $m.receipt | Should -Be (Get-VsatReceipt -Path (Join-Path $script:Out 'assessment.vsat.zip'))
        foreach ($f in $m.files) { (Get-VsatSha256 -Path (Join-Path $script:Out $f.name)) | Should -Be $f.sha256 -Because $f.name }
        @($m.files.name) | Should -Contain 'changes.csv'
    }
    It 'report carries the timeline, badge and receipt screens' {
        $js = Get-VsatEmbeddedText 'assets/report/report.js'
        $js | Should -Match 'Engagement timeline'
        $js | Should -Match 'Changed during engagement'
        $js | Should -Match 'Receipt verified'
        Get-VsatEmbeddedText 'assets/ui/app.js' | Should -Match 'Read this code to your auditor'
    }
    It 'keeps changedInWindow on compact PASS rows in the report data' {
        $res = Get-TestResults (Get-FxEvidence)
        $d = Get-VsatReportData $res
        @($d.findings | Where-Object { $_.result -eq 'PASS' -and $_.changedInWindow }).Count | Should -BeGreaterOrEqual 1
    }
}

Describe 'Collectors and CLI wiring' {
    It 'vSphere collector reads events with Get-VIEvent, bounded by -Start and -MaxSamples 50000' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:VsatScript, [ref]$null, [ref]$null)
        $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-VIEvent' }, $true))
        $calls.Count | Should -BeGreaterThan 0
        foreach ($c in $calls) { $c.Extent.Text | Should -Match '-Start' ; $c.Extent.Text | Should -Match '-MaxSamples' }
        ($calls.Extent.Text -join ' ') | Should -Match '50000'
    }
    It 'Hyper-V collector reads the listed event logs with Get-WinEvent -FilterHashtable' {
        $s = $script:VsatHyperVCollector
        $s | Should -Match 'Get-WinEvent'
        $s | Should -Match 'FilterHashtable'
        foreach ($id in 7040, 4728, 4729, 4732, 4733, 4756, 4757, 2004, 2005, 2006) { $s | Should -Match "\b$id\b" }
        $s | Should -Match 'Microsoft-Windows-Hyper-V-VMMS-Admin'
        $s | Should -Match '2000'
    }
    It 'KVM collector reads mtimes, package history and logins' {
        $s = $script:VsatKvmCollector
        $s | Should -Match "stat -c '%Y %n'"
        $s | Should -Match 'last -F'
        $s | Should -Match 'dnf\.rpm\.log'
        $s | Should -Match 'apt/history\.log'
    }
    It 'forwards the new parameters from the launcher' {
        $txt = [IO.File]::ReadAllText($script:VsatScript)
        foreach ($p in 'EngagementStart', 'CollectOnly', 'Receipt') {
            $txt | Should -Match "\[(string|switch)\]\`$$p\b"
            $txt | Should -Match "'$p'"
        }
    }
    It 'documents the parameters and the customer-run workflow' {
        $u = Get-Content -Raw (Join-Path $script:RepoRoot 'docs/usage.md')
        foreach ($p in '-EngagementStart', '-CollectOnly', '-Receipt') { $u | Should -Match ([regex]::Escape("``$p")) }
        $u | Should -Match 'When the customer runs VSAT'
    }
}
