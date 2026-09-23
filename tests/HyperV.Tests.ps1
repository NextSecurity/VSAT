BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    function Get-HvEvidence {
        $ev = New-VsatEvidence -Mode fixture
        $ep = Add-VsatEndpoint -Evidence $ev -Type hyperv -Address 'hv01.example.local'
        Invoke-VsatHyperVCollection -Evidence $ev -Endpoint $ep -ImportedJson ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/hyperv-collector.json')))
        $ev.run.status = 'complete'
        return $ev
    }
    $script:HvEv = Get-HvEvidence
    $script:Hv = Get-TestResults $script:HvEv
}

Describe 'Hyper-V (2.1) collection import and coverage' {
    It 'imports host, switches and VMs with stable namespaced ids' {
        @($script:HvEv.assets | Where-Object { $_.type -eq 'hyperv-vm' }).Count | Should -Be 7
        @($script:HvEv.assets | Where-Object { $_.type -eq 'hyperv-vswitch' }).Count | Should -Be 2
        @($script:HvEv.assets | Where-Object { $_.type -eq 'hyperv-vm' } | Where-Object { $_.id -notlike 'ep-hv01:vm/*' }) | Should -BeNullOrEmpty
    }
    It 'assesses Hyper-V domains and marks VMware/NSX not applicable (no VMware endpoints)' {
        foreach ($d in 'hyperv-host', 'hyperv-vm', 'hyperv-network') { ($script:Hv.coverage.domains | Where-Object id -eq $d).state | Should -Be 'ASSESSED' }
        ($script:Hv.coverage.domains | Where-Object id -eq 'nsx').state | Should -Be 'NOT_APPLICABLE'
        ($script:Hv.coverage.domains | Where-Object id -eq 'esxi').mandatory | Should -BeFalse
        $script:Hv.status.overall | Should -Be 'complete'
    }
    It 'failed host collection yields INCOMPLETE coverage, never passes' {
        $ev = New-VsatEvidence -Mode fixture
        $ep = Add-VsatEndpoint -Evidence $ev -Type hyperv -Address 'hv99.example.local'
        Invoke-VsatHyperVCollection -Evidence $ev -Endpoint $ep -ImportedJson '{ not json'
        $r = Get-TestResults $ev
        ($r.coverage.domains | Where-Object id -eq 'hyperv-host').state | Should -Be 'INCOMPLETE'
        @($r.findings | Where-Object { $_.result -eq 'PASS' }) | Should -BeNullOrEmpty
    }
}

Describe 'Hyper-V rules' {
    It '<Rule> on <Asset> => <Expected>' -ForEach @(
        @{ Rule = 'HV-OS-PATCH-AGE'; Asset = 'hv01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'HV-OS-LIFECYCLE'; Asset = 'hv01.example.local'; Expected = 'PASS' }
        @{ Rule = 'HV-FIREWALL'; Asset = 'hv01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'HV-SMB1'; Asset = 'hv01.example.local'; Expected = 'PASS' }
        @{ Rule = 'HV-SMB-SIGNING'; Asset = 'hv01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'HV-SPOOLER'; Asset = 'hv01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'HV-VBS-HVCI'; Asset = 'hv01.example.local'; Expected = 'PASS' }
        @{ Rule = 'HV-MIGRATION-AUTH'; Asset = 'hv01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'HV-REPLICA-AUTH'; Asset = 'hv01.example.local'; Expected = 'FAIL' }
        @{ Rule = 'HV-VSWITCH-MGMTOS'; Asset = 'hv01.example.local vSwitch-Ext'; Expected = 'FAIL' }
        @{ Rule = 'HV-VSWITCH-MGMTOS'; Asset = 'hv01.example.local vSwitch-Int'; Expected = 'NOT_APPLICABLE' }
        @{ Rule = 'HV-VM-MACSPOOF'; Asset = 'nva-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-MACSPOOF'; Asset = 'web-hv01'; Expected = 'PASS' }
        @{ Rule = 'HV-VM-TRUNK'; Asset = 'nva-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-PORTMIRROR'; Asset = 'ids-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-GUESTSERVICE'; Asset = 'ids-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-CHECKPOINT-AGE'; Asset = 'ids-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-CHECKPOINT-AGE'; Asset = 'web-hv01'; Expected = 'PASS' }
        @{ Rule = 'HV-VM-SECUREBOOT'; Asset = 'gpu-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-SECUREBOOT'; Asset = 'legacy-hv01'; Expected = 'NOT_APPLICABLE' }
        @{ Rule = 'HV-VM-GEN2'; Asset = 'legacy-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-DDA'; Asset = 'gpu-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-MEDIA'; Asset = 'gpu-hv01'; Expected = 'FAIL' }
        @{ Rule = 'HV-VM-DHCPGUARD'; Asset = '<svg onload=alert(7)>'; Expected = 'FAIL' }
    ) { (Get-TestFinding $script:Hv $Rule $Asset).result | Should -Be $Expected }
    It 'models failover: clustered VMs restart, non-clustered VMs are an outage' {
        $imp = @($script:Hv.analysis.impact | Where-Object { $_.componentType -eq 'hyperv-host' })[0]
        $legacy = ($script:HvEv.assets | Where-Object { $_.name -eq 'legacy-hv01' }).id
        ($imp.affected | Where-Object { $_.asset -eq $legacy }).effect | Should -Be 'outage'
        ($imp.affected | Where-Object { $_.asset -ne $legacy } | Select-Object -First 1).effect | Should -Be 'restart-expected'
    }
    It 'exports a read-only offline collector' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('hvx-' + [guid]::NewGuid().ToString('N'))
        $p = Export-VsatCollector -Platform hyperv -OutputDir $d
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Select-Object -Unique)
        $allowedNonGet = @('ConvertTo-Json', 'Where-Object', 'ForEach-Object', 'Sort-Object', 'F', 'Confirm-SecureBootUEFI')
        @($cmds | Where-Object { $_ -notlike 'Get-*' -and $allowedNonGet -notcontains $_ }) | Should -BeNullOrEmpty
        Remove-Item -Recurse -Force $d
    }
}
