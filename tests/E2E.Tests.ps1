BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    # The OSS end-to-end scenario: one demo run with the audit pack, then the auditor's replay of that
    # package with its receipt, the same package as baseline, and the audit pack again.
    $script:Base = Join-Path ([IO.Path]::GetTempPath()) ('vsat-e2e-' + [guid]::NewGuid().ToString('N'))
    $script:Demo = Join-Path $script:Base 'demo-out'
    $script:Replay = Join-Path $script:Base 'replay-out'
    & pwsh -NoProfile -File $script:VsatScript -Demo -Cli -AuditPack -NoBrowser -OutputPath $script:Demo *> $null
    $script:DemoExit = $LASTEXITCODE
    $script:Zip = Join-Path $script:Demo 'assessment.vsat.zip'
    $script:Code = (Get-Content -Raw (Join-Path $script:Demo 'manifest.json') | ConvertFrom-Json).receipt
    & pwsh -NoProfile -File $script:VsatScript -Replay $script:Zip -Receipt $script:Code -Baseline $script:Zip -AuditPack -Cli -NoBrowser -OutputPath $script:Replay *> $null
    $script:ReplayExit = $LASTEXITCODE
    $script:Results = Get-Content -Raw (Join-Path $script:Replay 'results.json') | ConvertFrom-Json -AsHashtable
}
AfterAll { Remove-Item -Recurse -Force $script:Base -ErrorAction SilentlyContinue }

Describe 'End-to-end: demo, audit pack, receipt-verified replay with baseline' {
    It 'exits 1 twice (the synthetic lab has findings)' {
        $script:DemoExit | Should -Be 1
        $script:ReplayExit | Should -Be 1
    }
    It 'verifies the receipt read out for the package' {
        $script:Code | Should -Match '^VSAT-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$'
        $script:Results.receiptVerification.verified | Should -BeTrue
        $script:Results.receiptVerification.code | Should -Be $script:Code
    }
    It 'writes the audit pack on both runs' {
        foreach ($d in $script:Demo, $script:Replay) { Join-Path $d 'audit-pack/control-matrix.csv' | Should -Exist }
        (Get-Content -Raw (Join-Path $script:Replay 'audit-pack/manifest.json') | ConvertFrom-Json).receipt | Should -Be (Get-VsatReceipt -Path (Join-Path $script:Replay 'assessment.vsat.zip'))
    }
    It 'carries blast radius paths, changes, ransomware, AI workloads and compliance' {
        @($script:Results.analysis.blastRadius.paths).Count | Should -BeGreaterThan 0
        $script:Results.analysis.Contains('changes') | Should -BeTrue
        $script:Results.analysis.changes | Should -Not -BeNullOrEmpty
        $script:Results.analysis.ransomware | Should -Not -BeNullOrEmpty
        $script:Results.analysis.Contains('aiWorkloads') | Should -BeTrue
        $script:Results.compliance.frameworks | Should -Not -BeNullOrEmpty
        $script:Results.analysis.drift | Should -Not -BeNullOrEmpty
    }
    It 'writes no fix-kit, OSCAL or signature files anywhere' {
        @(Get-ChildItem -Recurse -Force $script:Base | Where-Object { $_.Name -eq 'fix-kit' -or $_.Name -eq 'oscal' -or $_.Name -like '*.sig' }) | Should -BeNullOrEmpty
    }
}
