BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Build = Join-Path $script:RepoRoot 'build'
    function New-TmpPath([string]$Ext = '') { Join-Path ([IO.Path]::GetTempPath()) ('vsat-cmp-' + [guid]::NewGuid().ToString('N') + $Ext) }
}

Describe 'Crosswalk integrity gate' {
    BeforeAll {
        $script:X = Get-VsatCrosswalk
        $script:Pack = Get-VsatRulePack
        $script:Ids = @($script:Pack.rules.id)
        $script:Fw = @{}; foreach ($f in $script:X.catalogs.frameworks) { $script:Fw[$f.id] = $f }
    }
    It 'every mapping references an existing rule and framework' {
        @($script:X.mappings).Count | Should -BeGreaterThan 0
        foreach ($m in $script:X.mappings) { $script:Ids | Should -Contain $m.ruleId; $script:Fw.Keys | Should -Contain $m.framework }
    }
    It 'uses only the documented statuses and relations' {
        foreach ($m in $script:X.mappings) {
            $m.status | Should -BeIn @('verified', 'proposed', 'derived')
            $m.relation | Should -BeIn @('equivalent', 'subset', 'supports')
            $m.basis | Should -Not -BeNullOrEmpty
        }
    }
    It 'verified mappings carry reviewer, date, sourceRef and a confirmed edition' {
        foreach ($m in @($script:X.mappings | Where-Object status -eq 'verified')) {
            $m.reviewer | Should -Not -BeNullOrEmpty; $m.reviewedUtc | Should -Match '^\d{4}-\d{2}-\d{2}'; $m.sourceRef | Should -Not -BeNullOrEmpty
            $script:Fw[$m.framework].edition | Should -Not -Match '(?i)to be confirmed|unknown|tbd|none imported'
        }
    }
    It 'the verified-mapping gate fails a mapping without provenance' {
        $cat = $script:X.catalogs
        $good = [ordered]@{ ruleId = 'ESXI-SVC-SSH'; framework = 'nist-800-53r5'; control = 'CM-7'; relation = 'supports'; status = 'verified'; basis = 'b'; reviewer = 'auditor1'; reviewedUtc = '2026-09-01'; sourceRef = 'NIST SP 800-53 Rev. 5' }
        @(Test-VsatMappingProvenance -Mapping $good -Catalogs $cat).Count | Should -Be 0
        foreach ($k in 'reviewer', 'reviewedUtc', 'sourceRef') {
            $bad = [ordered]@{}; foreach ($x in $good.Keys) { $bad[$x] = $good[$x] }; $bad.Remove($k)
            @(Test-VsatMappingProvenance -Mapping $bad -Catalogs $cat).Count | Should -BeGreaterThan 0 -Because "missing $k"
        }
        $noEdition = [ordered]@{ frameworks = @([ordered]@{ id = 'nist-800-53r5'; name = 'n'; edition = 'TBD'; license = 'public-domain'; controls = @() }) }
        @(Test-VsatMappingProvenance -Mapping $good -Catalogs $noEdition).Count | Should -BeGreaterThan 0
        # The loader never trusts an unproven verified row: it is shown as proposed.
        $c = ConvertTo-VsatCrosswalk -Catalogs $cat -Mappings @($good, ([ordered]@{ ruleId = 'ESXI-SVC-SHELL'; framework = 'nist-800-53r5'; control = 'CM-7'; relation = 'supports'; status = 'verified'; basis = 'b' }))
        @($c.byRule['ESXI-SVC-SSH'])[0].status | Should -Be 'verified'
        @($c.byRule['ESXI-SVC-SHELL'])[0].status | Should -Be 'proposed'
    }
    It 'controls carry an ID and at most a short VSAT paraphrase; licensed catalogs list no controls' {
        foreach ($fw in $script:X.catalogs.frameworks) {
            $fw.license | Should -BeIn @('public-domain', 'copyrighted-ids-only', 'licensed-ids-only')
            if ($fw.license -eq 'licensed-ids-only') { @($fw.controls).Count | Should -Be 0 -Because $fw.id }
            foreach ($c in @($fw.controls)) {
                @($c.Keys | Where-Object { $_ -notin @('id', 'paraphrase') }) | Should -BeNullOrEmpty -Because "$($fw.id) $($c.id)"
                if ($c.paraphrase) { ($c.paraphrase -split '\s+').Count | Should -BeLessOrEqual 12 }
            }
        }
    }
    It 'NIST and IEC mappings reference controls in the catalog' {
        foreach ($id in 'nist-800-53r5', 'iec-62443-3-3') {
            $known = @($script:Fw[$id].controls.id)
            foreach ($m in @($script:X.mappings | Where-Object framework -eq $id)) { $known | Should -Contain $m.control -Because $m.ruleId }
        }
    }
    It 'covers every rule with at least one NIST SP 800-53 mapping' {
        $mapped = @($script:X.mappings | Where-Object framework -eq 'nist-800-53r5' | ForEach-Object { $_.ruleId } | Sort-Object -Unique)
        foreach ($id in $script:Ids) { $mapped | Should -Contain $id }
        foreach ($p in 'OT-', 'RW-', 'AI-', 'ESXI-', 'HV-', 'KVM-', 'NSX-', 'VM-', 'NET-') { @($mapped | Where-Object { $_.StartsWith($p) }).Count | Should -BeGreaterThan 0 -Because $p }
    }
    It 'ATT&CK mitigation mappings mirror the rules (attack.mitigation) and the pinned catalog' {
        $cat = Get-VsatAttackCatalog
        $want = @($script:Pack.rules | Where-Object { Get-VsatProp $_ 'attack.mitigation' } | ForEach-Object { "$($_.id)|$($_.attack.mitigation)" } | Sort-Object)
        $got = @($script:X.mappings | Where-Object framework -eq 'mitre-attack-mitigations' | ForEach-Object { "$($_.ruleId)|$($_.control)" } | Sort-Object)
        $got | Should -Be $want
        foreach ($m in @($script:X.mappings | Where-Object framework -eq 'mitre-attack-mitigations')) { $cat.mitigations.Contains($m.control) | Should -BeTrue; $m.status | Should -Be 'proposed' }
    }
    It 'never ships CIS mappings (bring your license) and never claims verified IEC or STIG rows' {
        @($script:X.mappings | Where-Object { $_.framework -like 'cis-*' }) | Should -BeNullOrEmpty
        @($script:X.mappings | Where-Object { $_.framework -like 'iec-*' -or $_.framework -like 'disa-stig-*' } | Where-Object status -eq 'verified') | Should -BeNullOrEmpty
        $script:Fw['cis-benchmarks'].importRequired | Should -BeTrue
    }
    It 'STIG frameworks pin their DISA source by SHA-256 and map only real STIG IDs from it' {
        foreach ($fw in @($script:X.catalogs.frameworks | Where-Object { $_.id -like 'disa-stig-*' })) {
            $fw.source.sha256 | Should -Match '^[0-9a-f]{64}$'
            $fw.source.package | Should -Match '^U_.*STIG.*\.zip$'
            foreach ($m in @($script:X.mappings | Where-Object framework -eq $fw.id)) { $m.control | Should -Match '^[A-Z0-9]+-\d{2}-\d{6}$'; $m.sourceRef | Should -Match $fw.source.sha256.Substring(0, 12) }
        }
    }
    It 'ships ISO/IEC 27001 only as derived rows' {
        @($script:X.mappings | Where-Object { $_.framework -like 'iso27001*' -and $_.status -ne 'derived' }) | Should -BeNullOrEmpty
    }
    It 'legacy 1.x CIS ids surface as legacy-unverified (never verified)' {
        $r = @($script:Pack.rules | Where-Object { $_.Contains('cis') })[0]
        @($r.frameworks | Where-Object { $_.control -eq $r.cis })[0].mappingStatus | Should -Be 'legacy-unverified'
    }
    It 'rule framework lists carry the crosswalk rows with display name, edition and status' {
        $r = @($script:Pack.rules | Where-Object id -eq 'ESXI-SVC-SSH')[0]
        $n = @($r.frameworks | Where-Object frameworkId -eq 'nist-800-53r5')
        $n.Count | Should -BeGreaterThan 0
        $n[0].framework | Should -Match 'NIST'
        $n[0].edition | Should -Not -BeNullOrEmpty
        $n[0].mappingStatus | Should -Be 'proposed'
    }
    It 'the seed is reproducible from build/New-CrosswalkSeed.ps1' {
        $d = New-TmpPath; New-Item -ItemType Directory $d | Out-Null
        & pwsh -NoProfile -File (Join-Path $script:Build 'New-CrosswalkSeed.ps1') -OutDir $d | Out-Null
        foreach ($f in 'catalogs.json', 'crosswalk.json') {
            (Get-VsatSha256 -Path (Join-Path $d $f)) | Should -Be (Get-VsatSha256 -Path (Join-Path $script:RepoRoot "data/frameworks/$f")) -Because $f
        }
        Remove-Item -Recurse -Force $d
    }
    It 'report counts verified vs unverified per framework' {
        $res = Get-TestResults
        $res.compliance.frameworks | Should -Not -BeNullOrEmpty
        foreach ($f in $res.compliance.frameworks) { $f.Contains('verifiedMappings') | Should -BeTrue; $f.Contains('unverifiedMappings') | Should -BeTrue }
    }
}

Describe 'STIG importer' {
    It 'proposes mappings by exact setting-name match and never marks them verified' {
        $out = New-TmpPath '.json'
        & (Join-Path $script:Build 'Import-StigXccdf.ps1') -XccdfPath (Join-Path $PSScriptRoot 'fixtures/stig-sample.xml') -Framework 'disa-stig-esxi-8' -Out $out
        $doc = Get-Content $out -Raw | ConvertFrom-Json
        $m = $doc.mappings
        @($m).Count | Should -BeGreaterThan 0
        @($m | Where-Object status -ne 'proposed') | Should -BeNullOrEmpty
        @($m | Where-Object { $_.ruleId -eq 'ESXI-SVC-SSH' }).Count | Should -Be 1
        @($m | Where-Object { $_.ruleId -eq 'ESXI-SVC-SSH' })[0].control | Should -Be 'ESXI-80-000193'
        @($m | Where-Object { $_.ruleId -eq 'ESXI-DCUI-TIMEOUT' })[0].control | Should -Be 'ESXI-80-000008'
        # TSM (ESXi Shell) must not match inside TSM-SSH.
        @($m | Where-Object { $_.ruleId -eq 'ESXI-SVC-SHELL' }) | Should -BeNullOrEmpty
        @($m | Where-Object { $_.control -eq 'ESXI-80-000999' }) | Should -BeNullOrEmpty
        $doc.framework.source.sha256 | Should -Match '^[0-9a-f]{64}$'
        # No DISA text is copied: only IDs, severity and CCIs.
        (Get-Content $out -Raw) | Should -Not -Match 'SSH service'
        Remove-Item $out
    }
    It 'derives NIST rows from CCIs only when a CCI list is given, marked derived' {
        $out = New-TmpPath '.json'
        & (Join-Path $script:Build 'Import-StigXccdf.ps1') -XccdfPath (Join-Path $PSScriptRoot 'fixtures/stig-sample.xml') -Framework 'disa-stig-esxi-8' -Out $out -CciPath (Join-Path $PSScriptRoot 'fixtures/cci-sample.xml')
        $d = @((Get-Content $out -Raw | ConvertFrom-Json).derived)
        $d.Count | Should -BeGreaterThan 0
        foreach ($x in $d) { $x.framework | Should -Be 'nist-800-53r5'; $x.status | Should -Be 'derived'; $x.sourceRef | Should -Match 'CCI' }
        @($d | Where-Object { $_.ruleId -eq 'ESXI-SVC-SSH' }).control | Should -Contain 'CM-7'
        Remove-Item $out
    }
    It 'rejects XCCDF with a DTD (XXE)' {
        $bad = New-TmpPath '.xml'
        Set-Content $bad '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><Benchmark>&e;</Benchmark>'
        { & (Join-Path $script:Build 'Import-StigXccdf.ps1') -XccdfPath $bad -Framework 'disa-stig-esxi-8' -Out (New-TmpPath '.json') } | Should -Throw
        Remove-Item $bad
    }
}

Describe 'CIS importer (bring your license)' {
    BeforeAll {
        $script:Csv = New-TmpPath '.csv'
        Set-Content $script:Csv "recommendation,ruleId,relation`n1.1.1,ESXI-SVC-SSH,equivalent`n9.9.9,NO-SUCH-RULE,supports"
    }
    AfterAll { Remove-Item $script:Csv -ErrorAction SilentlyContinue }
    It 'refuses to run without -SourceEdition' {
        { & (Join-Path $script:Build 'Import-CisMapping.ps1') -CsvPath $script:Csv -Framework 'cis-esxi-8' -Reviewer 'r' -ReviewedUtc '2026-09-01' -Out (New-TmpPath '.json') } | Should -Throw '*SourceEdition*'
    }
    It 'writes reviewed rows with provenance and rejects unknown rules' {
        $out = New-TmpPath '.json'
        & (Join-Path $script:Build 'Import-CisMapping.ps1') -CsvPath $script:Csv -Framework 'cis-esxi-8' -FrameworkName 'CIS VMware ESXi 8.0 Benchmark' -SourceEdition 'v1.2.0' -Reviewer 'licensed reviewer' -ReviewedUtc '2026-09-01' -Out $out 3>$null
        $doc = Get-Content $out -Raw | ConvertFrom-Json
        @($doc.mappings).Count | Should -Be 1
        $doc.mappings[0].status | Should -Be 'verified'
        $doc.mappings[0].reviewer | Should -Be 'licensed reviewer'
        $doc.mappings[0].sourceRef | Should -Match 'v1\.2\.0'
        $doc.framework.license | Should -Be 'licensed-ids-only'
        Remove-Item $out
    }
}

Describe 'Registers and control matrix' {
    BeforeAll {
        $script:Ev = Get-TestEvidence
        $man = @((Get-TestResults $script:Ev).findings | Where-Object result -eq 'MANUAL')[0]
        $script:Man = $man
        $script:Ev.scope.signoffs = @(
            @{ ruleId = $man.ruleId; asset = "name:$($man.assetName)"; reviewer = 'auditor1'; decision = 'satisfied'; evidenceRef = 'TKT-1'; dateUtc = '2026-10-01' },
            @{ ruleId = 'NO-SUCH-RULE'; asset = 'name:x'; reviewer = 'a'; decision = 'satisfied'; evidenceRef = 'y'; dateUtc = '2026-10-01' },
            @{ ruleId = $man.ruleId; asset = "name:$($man.assetName)"; reviewer = 'auditor2'; decision = 'satisfied'; evidenceRef = 'old'; dateUtc = '2020-01-01'; expires = '2021-01-01' }
        )
        # A denied read on one host: its advanced-setting checks become UNKNOWN (never a pass).
        $h = @($script:Ev.assets | Where-Object type -eq 'host' | Sort-Object { $_.id })[0]
        $h.facts.advanced = [ordered]@{ status = 'denied'; value = $null; error = 'NoPermission' }
        $script:R = Get-TestResults $script:Ev
    }
    It 'valid sign-off attaches to the MANUAL finding; orphan and expired are flagged' {
        @($script:R.compliance.signoffs | Where-Object { $_.findingKey -eq $script:Man.key -and $_.reviewer -eq 'auditor1' })[0].state | Should -Be 'valid'
        @($script:R.compliance.signoffs | Where-Object ruleId -eq 'NO-SUCH-RULE')[0].state | Should -Be 'orphan'
        @($script:R.compliance.signoffs | Where-Object reviewer -eq 'auditor2')[0].state | Should -Be 'expired'
    }
    It 'a satisfied sign-off on an automated FAIL is a conflict and changes nothing' {
        $ev = Get-TestEvidence
        $f = @((Get-TestResults $ev).findings | Where-Object result -eq 'FAIL')[0]
        $ev.scope.signoffs = @(@{ ruleId = $f.ruleId; asset = "name:$($f.assetName)"; reviewer = 'a'; decision = 'satisfied'; evidenceRef = 'e'; dateUtc = '2026-10-01' })
        $r = Get-TestResults $ev
        @($r.compliance.signoffs)[0].state | Should -Be 'conflict'
        @(Get-TestFinding $r $f.ruleId $f.assetName)[0].result | Should -Be 'FAIL'
    }
    It 'a control with any UNKNOWN is never satisfied' {
        $n = 0
        foreach ($fw in $script:R.compliance.frameworks) { foreach ($c in $fw.controls) { if ($c.counts.UNKNOWN -gt 0 -or $c.counts.ERROR -gt 0) { $n++; $c.state | Should -BeIn @('not-assessed', 'not-satisfied') } } }
        $n | Should -BeGreaterThan 0
    }
    It 'a control with an unexcepted FAIL is not-satisfied' {
        foreach ($fw in $script:R.compliance.frameworks) { foreach ($c in $fw.controls) { if ($c.counts.FAIL -gt 0) { $c.state | Should -Be 'not-satisfied' } } }
    }
    It 'keeps every state apart (precedence)' {
        $s = {
            param($c)
            $k = [ordered]@{ PASS = 0; FAIL = 0; MANUAL = 0; UNKNOWN = 0; ERROR = 0; NOT_APPLICABLE = 0; EXCEPTED = 0; SIGNED_OFF = 0; SIGNED_NOT_SATISFIED = 0 }
            foreach ($x in $c.Keys) { $k[$x] = $c[$x] }
            Get-VsatControlState -Counts $k
        }
        & $s @{ PASS = 3 } | Should -Be 'satisfied'
        & $s @{ PASS = 3; FAIL = 1; UNKNOWN = 1 } | Should -Be 'not-satisfied'
        & $s @{ PASS = 3; UNKNOWN = 1 } | Should -Be 'not-assessed'
        & $s @{ PASS = 3; ERROR = 1; MANUAL = 1 } | Should -Be 'not-assessed'
        & $s @{ MANUAL = 2 } | Should -Be 'manual-open'
        & $s @{ MANUAL = 2; SIGNED_OFF = 2 } | Should -Be 'manual-signed-off'
        & $s @{ MANUAL = 2; SIGNED_OFF = 1; SIGNED_NOT_SATISFIED = 1 } | Should -Be 'not-satisfied'
        & $s @{ EXCEPTED = 1 } | Should -Be 'excepted'
        & $s @{ PASS = 2; EXCEPTED = 1 } | Should -Be 'partial'
        & $s @{ PASS = 2; MANUAL = 1 } | Should -Be 'partial'
        & $s @{ NOT_APPLICABLE = 4 } | Should -Be 'not-assessed'
        & $s @{} | Should -Be 'not-assessed'
    }
    It 'exceptions without approver are flagged unapproved and do not count as excepted' {
        $ev = Get-TestEvidence
        $f = @((Get-TestResults $ev).findings | Where-Object result -eq 'FAIL')[0]
        $ev.scope.exceptions = @(@{ ruleId = $f.ruleId; asset = '*'; owner = 'infra'; rationale = 'r'; expires = '2099-01-01' })
        $r = Get-TestResults $ev
        @($r.compliance.exceptions)[0].flags | Should -Contain 'unapproved'
        foreach ($fw in $r.compliance.frameworks) { foreach ($c in @($fw.controls | Where-Object { $_.rules -contains $f.ruleId })) { $c.counts.EXCEPTED | Should -Be 0 } }
    }
    It 'approved active exceptions carry the new fields and count as excepted, never as a pass' {
        $ev = Get-TestEvidence
        $f = @((Get-TestResults $ev).findings | Where-Object result -eq 'FAIL')[0]
        $ev.scope.exceptions = @(@{ ruleId = $f.ruleId; asset = '*'; owner = 'infra'; approver = 'CISO'; compensatingControl = 'jump host'; ticket = 'CHG-7'; rationale = 'r'; expires = '2099-01-01' })
        $r = Get-TestResults $ev
        $x = @($r.compliance.exceptions)[0]
        $x.approver | Should -Be 'CISO'; $x.ticket | Should -Be 'CHG-7'; $x.compensatingControl | Should -Be 'jump host'; $x.flags | Should -Not -Contain 'unapproved'
        @(Get-TestFinding $r $f.ruleId $f.assetName)[0].exception.approver | Should -Be 'CISO'
        @(Get-TestFinding $r $f.ruleId $f.assetName)[0].result | Should -Be 'FAIL'
        $hit = @(foreach ($fw in $r.compliance.frameworks) { foreach ($c in @($fw.controls | Where-Object { $_.rules -contains $f.ruleId })) { $c } })
        $hit.Count | Should -BeGreaterThan 0
        foreach ($c in $hit) { $c.counts.EXCEPTED | Should -BeGreaterThan 0; $c.state | Should -Not -Be 'satisfied' }
    }
    It 'shows verified and unverified results separately; unverified never feed a verified headline' {
        foreach ($fw in $script:R.compliance.frameworks) {
            $fw.states.verified.Keys | Should -Contain 'satisfied'
            $fw.states.unverified.Keys | Should -Contain 'satisfied'
            $v = 0; foreach ($k in $fw.states.verified.Keys) { $v += $fw.states.verified[$k] }
            $v | Should -Be @($fw.controls | Where-Object mappingStatus -eq 'verified').Count
        }
    }
    It 'shows frameworks with no shipped mappings as import required' {
        $cis = @($script:R.compliance.frameworks | Where-Object id -eq 'cis-benchmarks')[0]
        $cis.importRequired | Should -BeTrue
        @($cis.controls).Count | Should -Be 0
    }
}

Describe 'Audit pack' {
    BeforeAll {
        $script:Out = New-TmpPath
        $ev = Get-TestEvidence
        $man = @((Get-TestResults $ev).findings | Where-Object result -eq 'MANUAL')[0]
        $ev.scope.signoffs = @(@{ ruleId = $man.ruleId; asset = "name:$($man.assetName)"; reviewer = '=cmd|calc'; decision = 'satisfied'; evidenceRef = '+1'; dateUtc = '2026-10-01' })
        $ev.scope.exceptions = @(@{ ruleId = 'ESXI-SVC-SSH'; asset = '*'; owner = '@SUM(A1)'; approver = 'CISO'; rationale = 'r'; expires = '2099-01-01' })
        $script:Res = Get-TestResults $ev
        [void](Write-VsatOutputs -Evidence $ev -Results $script:Res -OutputDir $script:Out)
        $script:Pack = Write-VsatAuditPack -Results $script:Res -OutputDir $script:Out
        $script:Dir = Join-Path $script:Out 'audit-pack'
    }
    AfterAll { Remove-Item -Recurse -Force $script:Out -ErrorAction SilentlyContinue }
    It 'writes the matrix, registers, a package copy and a manifest' {
        foreach ($f in 'control-matrix.csv', 'control-matrix.html', 'signoffs.csv', 'exceptions.csv', 'assessment.vsat.zip', 'manifest.json') { Join-Path $script:Dir $f | Should -Exist }
    }
    It 'manifest hashes every file and records the package receipt' {
        $m = Get-Content -Raw (Join-Path $script:Dir 'manifest.json') | ConvertFrom-Json
        @($m.files).Count | Should -Be 5
        foreach ($f in $m.files) { (Get-VsatSha256 -Path (Join-Path $script:Dir $f.name)) | Should -Be $f.sha256 }
        $m.receipt | Should -Be (Get-VsatReceipt -Path (Join-Path $script:Out 'assessment.vsat.zip'))
        $m.receipt | Should -Be (Get-Content -Raw (Join-Path $script:Out 'manifest.json') | ConvertFrom-Json).receipt
        (Get-VsatSha256 -Path (Join-Path $script:Dir 'assessment.vsat.zip')) | Should -Be (Get-VsatSha256 -Path (Join-Path $script:Out 'assessment.vsat.zip'))
    }
    It 'neutralizes spreadsheet formulas in every CSV' {
        $s = Get-Content -Raw (Join-Path $script:Dir 'signoffs.csv')
        $s | Should -Match ([regex]::Escape('"''=cmd|calc"'))
        $s | Should -Match ([regex]::Escape('"''+1"'))
        (Get-Content -Raw (Join-Path $script:Dir 'exceptions.csv')) | Should -Match ([regex]::Escape('"''@SUM(A1)"'))
    }
    It 'the control matrix CSV keeps states and mapping status apart' {
        $rows = @(Import-Csv (Join-Path $script:Dir 'control-matrix.csv'))
        $rows.Count | Should -BeGreaterThan 0
        foreach ($r in $rows) {
            $r.state.Trim("'") | Should -BeIn @('not-assessed', 'manual-open', 'manual-signed-off', 'excepted', 'partial', 'not-satisfied', 'satisfied')
            $r.mappingStatus | Should -BeIn @('verified', 'unverified')
        }
        @($rows.framework | Sort-Object -Unique) | Should -Contain 'nist-800-53r5'
        @($rows.framework | Sort-Object -Unique) | Should -Contain 'iec-62443-3-3'
    }
    It 'the control matrix HTML is standalone and offline, with a strict CSP and no script' {
        $html = Get-Content -Raw (Join-Path $script:Dir 'control-matrix.html')
        $html | Should -Match "default-src 'none'"
        $html | Should -Match "style-src 'sha256-"
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '(src|href)="https?://'
        $html | Should -Not -Match 'unsafe-inline'
        $html | Should -Match 'NIST SP 800-53'
        $html | Should -Match 'Import required'
        $css = [regex]::Match($html, '<style>(.*?)</style>', 'Singleline').Groups[1].Value
        $html | Should -Match ([regex]::Escape("sha256-$(Get-VsatSha256Base64 $css)"))
    }
    It 'writes no Pro artifacts (no OSCAL, no signatures)' {
        @(Get-ChildItem -Recurse -Force $script:Out | Where-Object { $_.Name -match '(?i)oscal|\.sig$|fix-kit' }) | Should -BeNullOrEmpty
    }
    It 'the report has a Compliance page' {
        $html = Get-Content -Raw (Join-Path $script:Out 'report.html')
        $html | Should -Match 'data-page="compliance"'
    }
}
