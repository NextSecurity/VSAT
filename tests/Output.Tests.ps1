BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Out = Join-Path ([IO.Path]::GetTempPath()) ('vsat-test-' + [guid]::NewGuid().ToString('N'))
    $script:Ev = Get-TestEvidence
    $script:Res = Get-TestResults $script:Ev
    Register-VsatSecret 'CanarySecret-7731'
    Write-VsatLog -Level debug -Message 'login failed for user with password=CanarySecret-7731 token x-xsrf-token: abcdefghijkl'
    $script:Files = Write-VsatOutputs -Evidence $script:Ev -Results $script:Res -OutputDir $script:Out -Redact
}
AfterAll { Remove-Item -Recurse -Force $script:Out -ErrorAction SilentlyContinue }

Describe 'Outputs' {
    It 'writes all artifacts' { foreach ($f in 'report.html', 'results.json', 'evidence.json', 'findings.csv', 'worklist.csv', 'collection.log', 'manifest.json', 'assessment.vsat.zip', 'report.redacted.html', 'assessment.redacted.vsat.zip') { Join-Path $script:Out $f | Should -Exist } }
    It 'neutralizes spreadsheet formulas in CSV' {
        $csv = Get-Content -Raw (Join-Path $script:Out 'findings.csv')
        $csv | Should -Match ([regex]::Escape('"''=cmd|'))
        $csv | Should -Not -Match ',"=cmd'
        ConvertTo-VsatCsvCell '+1' | Should -Be '"''+1"'
        ConvertTo-VsatCsvCell '@SUM(A1)' | Should -Be '"''@SUM(A1)"'
        ConvertTo-VsatCsvCell "-2" | Should -Be '"''-2"'
    }
    It 'embeds report data without raw markup and with a hash-based CSP' {
        $html = Get-Content -Raw (Join-Path $script:Out 'report.html')
        $m = [regex]::Match($html, '<script id="vsat-data" type="application/json">(.*?)</script>', 'Singleline')
        $m.Success | Should -BeTrue
        $m.Groups[1].Value | Should -Not -Match '<'
        $html | Should -Match "script-src 'sha256-"
        $html | Should -Not -Match "unsafe-inline|unsafe-eval"
        $html | Should -Not -Match 'https?://(?!www\.w3\.org)'
    }
    It 'CSP hash matches the inline script' {
        $html = Get-Content -Raw (Join-Path $script:Out 'report.html')
        $js = Get-VsatEmbeddedText 'assets/report/report.js'
        $html | Should -Match ([regex]::Escape("sha256-$(Get-VsatSha256Base64 $js)"))
    }
    It 'keeps secrets out of logs and every output' {
        foreach ($f in Get-ChildItem -Recurse -File $script:Out) {
            if ($f.Extension -eq '.zip') { continue }
            (Get-Content -Raw $f.FullName) | Should -Not -Match 'CanarySecret-7731' -Because $f.Name
        }
        Protect-VsatText 'Authorization: Basic dXNlcjpwYXNz' | Should -Not -Match 'dXNlcjpwYXNz'
    }
    It 'strips terminal control characters from untrusted text' {
        Protect-VsatText ("evil" + [char]27 + "[31mred") | Should -Not -Match ([char]27)
    }
    It 'produces a manifest whose hashes match' {
        $m = Get-Content -Raw (Join-Path $script:Out 'manifest.json') | ConvertFrom-Json
        foreach ($f in $m.files) { (Get-VsatSha256 -Path (Join-Path $script:Out $f.name)) | Should -Be $f.sha256 }
    }
    It 'redacts names, addresses and principals consistently while preserving graph relationships' {
        $red = Get-Content -Raw (Join-Path $script:Out 'redacted/results.json')
        foreach ($s in 'esx01.example.local', 'vc01.example.local', 'nsx01.example.local', '10.10.3.11', 'EXAMPLE\\j.doe', 'db01') { $red | Should -Not -Match ([regex]::Escape($s)) }
        $r = $red | ConvertFrom-Json
        $ids = @{}; foreach ($a in $r.assets) { $ids[$a.id] = $true }
        @($r.relationships | Where-Object { -not $ids.ContainsKey($_.source) -or -not $ids.ContainsKey($_.target) }).Count | Should -Be 0
        @($r.findings).Count | Should -Be @($script:Res.findings).Count
    }
}

Describe 'Evidence package import safety' {
    BeforeAll { Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem }
    It 'round-trips and verifies integrity' {
        $p = Read-VsatPackage -Path (Join-Path $script:Out 'assessment.vsat.zip')
        $p.integrity | Should -Match 'verified'
        @($p.evidence.assets).Count | Should -Be @($script:Ev.assets).Count
    }
    It 'rejects a tampered evidence.json' {
        $z = Join-Path $script:Out 'tampered.zip'
        Copy-Item (Join-Path $script:Out 'assessment.vsat.zip') $z
        $zip = [IO.Compression.ZipFile]::Open($z, 'Update')
        $zip.GetEntry('evidence.json').Delete()
        $e = $zip.CreateEntry('evidence.json'); $s = $e.Open(); $b = [Text.Encoding]::UTF8.GetBytes('{"schemaVersion":"2.0","assets":[]}'); $s.Write($b, 0, $b.Length); $s.Dispose(); $zip.Dispose()
        { Read-VsatPackage -Path $z } | Should -Throw '*integrity*'
    }
    It 'rejects path traversal entries (zip-slip)' {
        $z = Join-Path $script:Out 'slip.zip'
        $zip = [IO.Compression.ZipFile]::Open($z, 'Create'); $e = $zip.CreateEntry('../evil.ps1'); $s = $e.Open(); $s.WriteByte(65); $s.Dispose(); $e2 = $zip.CreateEntry('evidence.json'); $s = $e2.Open(); $s.WriteByte(123); $s.Dispose(); $zip.Dispose()
        { Read-VsatPackage -Path $z } | Should -Throw '*unsafe path*'
    }
    It 'rejects decompression bombs' {
        $z = Join-Path $script:Out 'bomb.zip'
        $zip = [IO.Compression.ZipFile]::Open($z, 'Create'); $e = $zip.CreateEntry('evidence.json', 'Optimal'); $s = $e.Open(); $buf = New-Object byte[] (1MB); for ($i = 0; $i -lt 40; $i++) { $s.Write($buf, 0, $buf.Length) }; $s.Dispose(); $zip.Dispose()
        { Read-VsatPackage -Path $z } | Should -Throw '*ratio*'
    }
    It 'rejects unsupported schema versions' {
        $z = Join-Path $script:Out 'schema.zip'
        $zip = [IO.Compression.ZipFile]::Open($z, 'Create'); $e = $zip.CreateEntry('evidence.json'); $s = $e.Open(); $b = [Text.Encoding]::UTF8.GetBytes('{"schemaVersion":"1.0"}'); $s.Write($b, 0, $b.Length); $s.Dispose(); $zip.Dispose()
        { Read-VsatPackage -Path $z } | Should -Throw '*schema*'
    }
}

Describe 'Replay and drift' {
    It 'replay re-evaluates to identical findings' {
        $p = Read-VsatPackage -Path (Join-Path $script:Out 'assessment.vsat.zip')
        $ev = ConvertTo-VsatLiveEvidence $p.evidence
        $r = Get-TestResults $ev
        (@($r.findings | ForEach-Object { "$($_.key)=$($_.result)" }) -join "`n") | Should -Be (@($script:Res.findings | ForEach-Object { "$($_.key)=$($_.result)" }) -join "`n")
    }
    It 'missing facts in replayed evidence never become passes' {
        $ev = Get-TestEvidence
        foreach ($h in @($ev.assets | Where-Object { $_.type -eq 'host' })) { $h.facts.Remove('advanced') }
        $r = Get-TestResults $ev
        @(Get-TestFinding $r 'ESXI-DCUI-TIMEOUT' | Where-Object { $_.result -eq 'PASS' }) | Should -BeNullOrEmpty
    }
    It 'reports resolved, new and unassessed items; removed access is not resolved' {
        $base = Get-TestEvidence
        $cur = Get-TestEvidence
        ((Get-TestAsset $cur 'esx02.example.local' 'host').facts.services.value | Where-Object { $_.key -eq 'TSM-SSH' }).running = $false
        ((Get-TestAsset $cur 'esx02.example.local' 'host').facts.services.value | Where-Object { $_.key -eq 'TSM-SSH' }).policy = 'off'
        (Get-TestAsset $cur 'esx05.example.local' 'host').facts.advanced = [ordered]@{ status = 'denied'; value = $null }
        ((Get-TestAsset $cur 'esx04.example.local' 'host').facts.services.value | Where-Object { $_.key -eq 'TSM-SSH' }).running = $true
        $cur.assets = New-VsatList @($cur.assets | Where-Object { $_.name -ne 'db01' })
        $r = Get-TestResults -Evidence $cur -Baseline $base
        $d = $r.analysis.drift
        @($d.items | Where-Object { $_.ruleId -eq 'ESXI-SVC-SSH' -and $_.assetName -eq 'esx02.example.local' })[0].change | Should -Be 'resolved'
        @($d.items | Where-Object { $_.ruleId -eq 'ESXI-SVC-SSH' -and $_.assetName -eq 'esx04.example.local' })[0].change | Should -Be 'new'
        @($d.items | Where-Object { $_.ruleId -eq 'ESXI-ACCOUNT-LOCK' -and $_.assetName -eq 'esx05.example.local' })[0].change | Should -Be 'unassessed'
        @($d.items | Where-Object { $_.assetName -eq 'db01' -and $_.change -eq 'resolved' }) | Should -BeNullOrEmpty
        @($d.items | Where-Object { $_.assetName -eq 'db01' -and $_.change -eq 'unassessed' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Analysis features' {
    It 'models failure impact with redundancy and honest notes' {
        $i = @($script:Res.analysis.impact)
        $dmzHost = $i | Where-Object { $_.componentType -eq 'host' -and $_.component -eq 'ep-vc01:host-40' }
        $dmzHost.redundancy | Should -Be 'none'          # cl-dmz has HA disabled
        ($i | Where-Object { $_.componentType -eq 'host' -and $_.component -eq 'ep-vc01:host-10' }).redundancy | Should -Be 'redundant'
        ($i | Where-Object { $_.componentType -eq 'nsx-edge-cluster' }).redundancy | Should -Be 'redundant'
        ($i | Where-Object { $_.componentType -eq 'host' } | Select-Object -First 1).notes -join ' ' | Should -Match 'not proof'
    }
    It 'groups remediation into work packages with rollback and validation' {
        foreach ($w in $script:Res.analysis.workPackages) { $w.rollback | Should -Not -BeNullOrEmpty; $w.validation | Should -Not -BeNullOrEmpty }
    }
    It 'shows three separate dimensions (findings, coverage, confidence)' {
        $script:Res.summary.severity | Should -Not -BeNullOrEmpty
        $script:Res.coverage.domains | Should -Not -BeNullOrEmpty
        $script:Res.summary.confidence.inferred | Should -BeGreaterThan 0
    }
}
