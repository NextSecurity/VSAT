BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $ev = New-VsatEvidence -Mode fixture
    $ep = Add-VsatEndpoint -Evidence $ev -Type kvm -Address 'kvm01.example.local'
    Invoke-VsatKvmCollection -Evidence $ev -Endpoint $ep -ImportedText ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/kvm-collector.txt')))
    $ev.run.status = 'complete'
    $script:KvmEv = $ev
    $script:Kvm = Get-TestResults $ev
}

Describe 'KVM/libvirt (2.2) collection import' {
    It 'imports host, networks and domains' {
        @($script:KvmEv.assets | Where-Object { $_.type -eq 'kvm-vm' }).Count | Should -Be 3
        @($script:KvmEv.assets | Where-Object { $_.type -eq 'kvm-network' }).Count | Should -Be 2
        (Get-TestAsset $script:KvmEv 'kvm01.example.local' 'kvm-host').version | Should -Be '22.04'
    }
    It 'refuses DTD/XXE in untrusted domain XML and records an error fact instead of passing' {
        $a = Get-TestAsset $script:KvmEv '<img src=x onerror=alert(9)>' 'kvm-vm'
        $a.facts.domain.status | Should -Be 'error'
        @($script:Kvm.findings | Where-Object { $_.assetId -eq $a.id -and $_.result -eq 'PASS' }) | Should -BeNullOrEmpty
        (ConvertTo-VsatJson $script:KvmEv) | Should -Not -Match 'root:x:0'
    }
    It 'rejects truncated collector output' {
        $e2 = New-VsatEvidence -Mode fixture
        $p2 = Add-VsatEndpoint -Evidence $e2 -Type kvm -Address 'kvm02.example.local'
        Invoke-VsatKvmCollection -Evidence $e2 -Endpoint $p2 -ImportedText "==VSAT:SECTION meta==`nhostname=x"
        $p2.status | Should -Be 'failed'
    }
    It 'KVM domains are assessed; the ERROR domain makes kvm-vm PARTIAL (honest), NSX not applicable' {
        ($script:Kvm.coverage.domains | Where-Object id -eq 'kvm-host').state | Should -Be 'ASSESSED'
        ($script:Kvm.coverage.domains | Where-Object id -eq 'kvm-vm').state | Should -Be 'PARTIAL'
        ($script:Kvm.coverage.domains | Where-Object id -eq 'nsx').state | Should -Be 'NOT_APPLICABLE'
    }
}

Describe 'KVM rules' {
    It '<Rule> on <Asset> => <Expected>' -ForEach @(
        @{ Rule = 'KVM-LIBVIRT-TCP'; Asset = 'kvm01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'KVM-QEMU-USER'; Asset = 'kvm01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'KVM-VNC-TLS'; Asset = 'kvm01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'KVM-SVIRT'; Asset = 'kvm01.example.local'; Expected = 'PASS' }
        @{ Rule = 'KVM-FIREWALL'; Asset = 'kvm01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'KVM-SSH-ROOT'; Asset = 'kvm01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'KVM-SECUREBOOT'; Asset = 'kvm01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'KVM-OS-PATCH-AGE'; Asset = 'kvm01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'KVM-OS-LIFECYCLE'; Asset = 'kvm01.example.local'; Expected = 'PASS' }
        @{ Rule = 'KVM-SECCOMP'; Asset = 'kvm01.example.local'; Expected = 'PASS' }
        @{ Rule = 'KVM-VM-SECLABEL'; Asset = 'nva-kvm01'; Expected = 'FAIL' }
        @{ Rule = 'KVM-VM-SECLABEL'; Asset = 'web-kvm01'; Expected = 'PASS' }
        @{ Rule = 'KVM-VM-GRAPHICS'; Asset = 'nva-kvm01'; Expected = 'FAIL' }
        @{ Rule = 'KVM-VM-GRAPHICS'; Asset = 'web-kvm01'; Expected = 'PASS' }
        @{ Rule = 'KVM-VM-HOSTDEV'; Asset = 'nva-kvm01'; Expected = 'FAIL' }
        @{ Rule = 'KVM-VM-CONSOLE-NET'; Asset = 'nva-kvm01'; Expected = 'FAIL' }
        @{ Rule = 'KVM-VM-USBREDIR'; Asset = 'nva-kvm01'; Expected = 'FAIL' }
        @{ Rule = 'KVM-VM-NWFILTER'; Asset = 'nva-kvm01'; Expected = 'FAIL' }
        @{ Rule = 'KVM-VM-NWFILTER'; Asset = 'web-kvm01'; Expected = 'PASS' }
        @{ Rule = 'KVM-VM-SNAPSHOT-AGE'; Asset = 'web-kvm01'; Expected = 'FAIL' }
        @{ Rule = 'KVM-NET-OPEN'; Asset = 'kvm01.example.local open-net'; Expected = 'FAIL' }
        @{ Rule = 'KVM-NET-OPEN'; Asset = 'kvm01.example.local default'; Expected = 'PASS' }
    ) { (Get-TestFinding $script:Kvm $Rule $Asset).result | Should -Be $Expected }
    It 'flags unauthenticated libvirt TCP as critical' { (Get-TestFinding $script:Kvm 'KVM-LIBVIRT-TCP').severity | Should -Be 'critical' }
}

Describe 'KVM collector script is read-only' {
    It 'uses virsh only in --readonly mode, never --security-info, and writes no files' {
        $s = $script:VsatKvmCollector
        $s | Should -Match 'V="virsh --readonly'
        ($s -split "`n" | Where-Object { $_ -match '(^|[;\s("])virsh\s' -and $_ -notmatch '--readonly' -and $_ -notmatch '^\s*#' }) | Should -BeNullOrEmpty
        $s | Should -Not -Match 'security-info'
        $code = ($s -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match '(^|[^2&])>\s*[/\w]'
        $code | Should -Not -Match '\b(rm|mv|cp|tee|chmod|chown|sed -i|systemctl (start|stop|restart|enable|disable)|virsh (start|destroy|define|undefine|edit))\b'
    }
}
