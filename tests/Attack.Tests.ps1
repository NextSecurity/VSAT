BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Cat = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'data/attack/attack-catalog.json')
    $script:EdgeMap = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'data/attack/edge-techniques.json')
    # A technique ID is usable only when it exists in the pinned catalog and is neither revoked nor deprecated.
    function Test-AttackUsable([string]$Id) {
        if (-not $script:Cat.techniques.Contains($Id)) { return $false }
        $t = $script:Cat.techniques[$Id]
        return (-not $t.revoked -and -not $t.deprecated)
    }
    # The verified gate (same as the framework crosswalk): reviewer, review date and source reference.
    function Test-AttackStatusGate($Block, [string]$Because) {
        $Block.status | Should -BeIn @('proposed', 'verified') -Because $Because
        if ($Block.status -eq 'verified') {
            [string]$Block.reviewer | Should -Not -BeNullOrEmpty -Because "$Because (verified needs a reviewer)"
            [string]$Block.reviewedUtc | Should -Match '^\d{4}-\d{2}-\d{2}' -Because "$Because (verified needs a review date)"
            [string]$Block.sourceRef | Should -Not -BeNullOrEmpty -Because "$Because (verified needs a source reference)"
        }
    }
}

Describe 'ATT&CK catalog (pinned official data)' {
    It 'records its pinned sources and hashes' {
        $script:Cat.source.attack.sha256 | Should -Match '^[0-9a-f]{64}$'
        $script:Cat.source.atlas.sha256 | Should -Match '^[0-9a-f]{64}$'
        $script:Cat.source.attack.url | Should -Match '^https://github\.com/mitre-attack/attack-stix-data/'
        $script:Cat.source.atlas.url | Should -Match '^https://github\.com/mitre-atlas/atlas-data/'
        $script:Cat.source.attack.version | Should -Match '^\d+\.\d+$'
    }
    It 'matches the pins in build/runtime.lock.json and in the importer' {
        $lock = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'runtime.lock.json')
        foreach ($k in 'attack', 'atlas') {
            $lock.attack[$k].version | Should -Be $script:Cat.source[$k].version
            $lock.attack[$k].url | Should -Be $script:Cat.source[$k].url
            $lock.attack[$k].sha256 | Should -Be $script:Cat.source[$k].sha256
        }
        $imp = Get-Content -Raw (Join-Path $script:RepoRoot 'build/Import-AttackCatalog.ps1')
        $imp | Should -Match $script:Cat.source.attack.sha256
        $imp | Should -Match $script:Cat.source.atlas.sha256
    }
    It 'flags revoked techniques instead of dropping them (T1562.004 was revoked by T1686)' {
        $t = $script:Cat.techniques['T1562.004']
        $t.revoked | Should -BeTrue
        $t.revokedBy | Should -Be 'T1686'
        Test-AttackUsable 'T1562.004' | Should -BeFalse
        Test-AttackUsable 'T1686' | Should -BeTrue
    }
    It 'keeps legacy pre-2018 mitigation objects (T-numbered) out of both maps' {
        # The STIX bundle has deprecated course-of-action objects that reuse technique IDs (e.g. "Valid Accounts Mitigation" = T1078).
        $script:Cat.techniques['T1078'].name | Should -Be 'Valid Accounts'
        foreach ($m in $script:Cat.mitigations.Keys) { $m | Should -Match '^(M\d{4}|AML\.M\d{4})$' }
    }
    It 'contains the ATLAS techniques under their AML ids' {
        $script:Cat.techniques['AML.T0020'].domain | Should -Be 'atlas'
        $script:Cat.techniques['AML.T0020'].name | Should -Be 'Training Data Poisoning'
        $script:Cat.techniques['AML.T0035'].name | Should -Be 'AI Artifact Collection'
    }
}

Describe 'ATT&CK mapping integrity (no hallucinated IDs)' {
    It 'every rule has an attack block' {
        foreach ($r in (Get-VsatRulePack).rules) { $r.Contains('attack') | Should -BeTrue -Because $r.id }
    }
    It 'every technique referenced by rules exists and is not revoked or deprecated in the pinned catalog' {
        foreach ($r in (Get-VsatRulePack).rules | Where-Object { $_.Contains('attack') }) {
            foreach ($t in @($r.attack.mitigates)) { Test-AttackUsable $t | Should -BeTrue -Because "$($r.id) -> $t" }
            if ($r.attack.mitigation) {
                $script:Cat.mitigations.Contains($r.attack.mitigation) | Should -BeTrue -Because "$($r.id) -> $($r.attack.mitigation)"
                $script:Cat.mitigations[$r.attack.mitigation].deprecated | Should -BeFalse -Because "$($r.id) -> $($r.attack.mitigation)"
                $script:Cat.mitigations[$r.attack.mitigation].revoked | Should -BeFalse -Because "$($r.id) -> $($r.attack.mitigation)"
            }
        }
    }
    It 'every rule mitigation is one ATT&CK itself links to at least one technique the rule lists' {
        foreach ($r in (Get-VsatRulePack).rules | Where-Object { $_.Contains('attack') -and $_.attack.mitigation }) {
            $linked = @($script:Cat.mitigations[$r.attack.mitigation].techniques)
            $hit = @($r.attack.mitigates | Where-Object { $_ -in $linked -or ($_ -split '\.')[0] -in $linked })
            $hit.Count | Should -BeGreaterThan 0 -Because "$($r.id): $($r.attack.mitigation) must mitigate one of $(@($r.attack.mitigates) -join ', ') in ATT&CK"
        }
    }
    It 'rules without a technique say why' {
        foreach ($r in (Get-VsatRulePack).rules | Where-Object { $_.Contains('attack') -and -not @($_.attack.mitigates).Count }) {
            [string]$r.attack.none | Should -Not -BeNullOrEmpty -Because $r.id
        }
    }
    It 'rule attack mappings pass the proposed/verified gate' {
        foreach ($r in (Get-VsatRulePack).rules | Where-Object { $_.Contains('attack') }) { Test-AttackStatusGate $r.attack $r.id }
    }
    It 'every edge mapping technique exists in the catalog and is usable' {
        foreach ($m in $script:EdgeMap.mappings) { if ($m.technique) { Test-AttackUsable $m.technique | Should -BeTrue -Because $m.technique } }
    }
    It 'edge mappings pass the proposed/verified gate' {
        foreach ($m in $script:EdgeMap.mappings) { if ($m.technique) { Test-AttackStatusGate $m "$($m.kind) -> $($m.technique)" } }
    }
    It 'every graph edge kind has a mapping (embodies maps to no technique)' {
        $kinds = @($script:EdgeMap.mappings | ForEach-Object { $_.kind })
        foreach ($k in 'admin-of', 'controls', 'embodies', 'network-allow', 'mgmt-reach', 'credential-exposure', 'member-of') { $kinds | Should -Contain $k }
        @($script:EdgeMap.mappings | Where-Object { $_.kind -eq 'embodies' -and $_.technique }) | Should -BeNullOrEmpty
    }
    It 'the verified gate rejects a verified mapping without reviewer, date and source' {
        { Test-AttackStatusGate ([ordered]@{ status = 'verified' }) 'synthetic' } | Should -Throw
        { Test-AttackStatusGate ([ordered]@{ status = 'guessed' }) 'synthetic' } | Should -Throw
        { Test-AttackStatusGate ([ordered]@{ status = 'verified'; reviewer = 'a'; reviewedUtc = '2026-09-24'; sourceRef = 'https://attack.mitre.org/' }) 'synthetic' } | Should -Not -Throw
    }
}

Describe 'Get-VsatAttackForEdge' {
    BeforeAll {
        $script:G = [ordered]@{ nodes = @{
                'ad:example\ops' = @{ id = 'ad:example\ops'; type = 'group' }; 'local:ep-kvm01:ops' = @{ id = 'local:ep-kvm01:ops'; type = 'user' }
                'ep-kvm01:host' = @{ id = 'ep-kvm01:host'; type = 'kvm-host' }; 'ep-kvm01:vm/1' = @{ id = 'ep-kvm01:vm/1'; type = 'kvm-vm' }
                'ep-hv01:host' = @{ id = 'ep-hv01:host'; type = 'hyperv-host' }; 'ep-hv01:vm/1' = @{ id = 'ep-hv01:vm/1'; type = 'hyperv-vm' }
                'ep-vc01:host-1' = @{ id = 'ep-vc01:host-1'; type = 'host' }; 'ep-vc01:vm-1' = @{ id = 'ep-vc01:vm-1'; type = 'vm' }
                'ep-nsx01:mgr' = @{ id = 'ep-nsx01:mgr'; type = 'nsx-manager' }
            }
        }
        function New-E([string]$Kind, [string]$S, [string]$T, $Ports) { $e = [ordered]@{ kind = $Kind; source = $S; target = $T }; if ($null -ne $Ports) { $e.ports = @($Ports) }; return $e }
    }
    It 'maps admin-of by principal prefix' {
        (Get-VsatAttackForEdge -Edge (New-E 'admin-of' 'ad:example\ops' 'ep-kvm01:host') -Graph $script:G).technique | Should -Be 'T1078.002'
        (Get-VsatAttackForEdge -Edge (New-E 'admin-of' 'upn:ops@other.corp' 'ep-kvm01:host') -Graph $script:G).technique | Should -Be 'T1078.002'
        (Get-VsatAttackForEdge -Edge (New-E 'admin-of' 'local:ep-kvm01:ops' 'ep-kvm01:host') -Graph $script:G).technique | Should -Be 'T1078.003'
    }
    It 'maps controls by source type' {
        (Get-VsatAttackForEdge -Edge (New-E 'controls' 'ep-vc01:host-1' 'ep-vc01:vm-1') -Graph $script:G).technique | Should -Be 'T1675'
        (Get-VsatAttackForEdge -Edge (New-E 'controls' 'ep-kvm01:host' 'ep-kvm01:vm/1') -Graph $script:G).technique | Should -Be 'T1059.012'
        (Get-VsatAttackForEdge -Edge (New-E 'controls' 'ep-hv01:host' 'ep-hv01:vm/1') -Graph $script:G).technique | Should -Be 'T1059.001'
        (Get-VsatAttackForEdge -Edge (New-E 'controls' 'ep-nsx01:mgr' 'ep-vc01:vm-1') -Graph $script:G).technique | Should -Be 'T1686'
    }
    It 'maps mgmt-reach to SSH only when port 22 is in the edge evidence' {
        (Get-VsatAttackForEdge -Edge (New-E 'mgmt-reach' 'ep-kvm01:vm/1' 'ep-kvm01:host' @(22, 16509)) -Graph $script:G).technique | Should -Be 'T1021.004'
        (Get-VsatAttackForEdge -Edge (New-E 'mgmt-reach' 'ep-kvm01:vm/1' 'ep-kvm01:host' @(16509)) -Graph $script:G).technique | Should -Be 'T1021'
        (Get-VsatAttackForEdge -Edge (New-E 'mgmt-reach' 'ep-hv01:vm/1' 'ep-hv01:host' $null) -Graph $script:G).technique | Should -Be 'T1021'
    }
    It 'returns the catalog name (parent: sub-technique) and the mapping status' {
        $a = Get-VsatAttackForEdge -Edge (New-E 'admin-of' 'ad:example\ops' 'ep-kvm01:host') -Graph $script:G
        $a.name | Should -Be 'Valid Accounts: Domain Accounts'
        $a.mappingStatus | Should -Be 'proposed'
    }
    It 'returns null for embodies and unknown kinds' {
        Get-VsatAttackForEdge -Edge (New-E 'embodies' 'ep-hv01:vm/1' 'ep-vc01:host-1') -Graph $script:G | Should -BeNullOrEmpty
        Get-VsatAttackForEdge -Edge (New-E 'no-such-kind' 'a' 'b') -Graph $script:G | Should -BeNullOrEmpty
    }
}

Describe 'ATT&CK in results' {
    BeforeAll { $script:R = Get-TestResults (Get-XplatEvidence) }
    It 'blast-radius edges carry technique ids, embodies edges carry none' {
        @($script:R.analysis.blastRadius.edges | Where-Object { $_.kind -eq 'admin-of' -and $_.source -like 'ad:*' })[0].attack.technique | Should -Be 'T1078.002'
        @($script:R.analysis.blastRadius.edges | Where-Object { $_.kind -eq 'admin-of' -and $_.source -like 'local:*' })[0].attack.technique | Should -Be 'T1078.003'
        @($script:R.analysis.blastRadius.edges | Where-Object kind -eq 'embodies' | Where-Object { $_.attack }) | Should -BeNullOrEmpty
    }
    It 'every labelled edge uses a usable catalog technique' {
        foreach ($e in @($script:R.analysis.blastRadius.edges | Where-Object { $_.attack })) { Test-AttackUsable $e.attack.technique | Should -BeTrue -Because "$($e.kind) $($e.attack.technique)" }
    }
    It 'mgmt-reach edges record the listening ports they rely on (P10)' {
        $kvm = @($script:R.analysis.blastRadius.edges | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq 'ep-kvm01:host' })[0]
        @($kvm.ports) | Should -Contain 22
        $kvm.attack.technique | Should -Be 'T1021.004'
        $hv = @($script:R.analysis.blastRadius.edges | Where-Object { $_.kind -eq 'mgmt-reach' -and $_.target -eq 'ep-hv01:host' })[0]
        $hv.attack.technique | Should -Be 'T1021'
    }
    It 'results.rules carry the attack block' {
        $r = @($script:R.rules | Where-Object id -eq 'ESXI-SVC-SSH')[0]
        @($r.attack.mitigates) | Should -Contain 'T1021.004'
        $r.attack.mitigation | Should -Be 'M1042'
    }
    It 'Navigator layer is valid and scores only techniques that exist' {
        $l = New-VsatAttackLayer -Results $script:R
        $l.domain | Should -Be 'enterprise-attack'; $l.versions.layer | Should -Be '4.5'
        foreach ($t in $l.techniques) { $script:Cat.techniques.Contains($t.techniqueID) | Should -BeTrue; $t.score | Should -BeGreaterThan 0 }
    }
    It 'Navigator layer meets the layer format 4.5 contract' {
        $l = New-VsatAttackLayer -Results $script:R
        [string]$l.name | Should -Not -BeNullOrEmpty
        $l.versions.navigator | Should -Match '^\d+\.\d+\.\d+$'
        [version]$l.versions.navigator | Should -BeGreaterOrEqual ([version]'4.9.0')
        $l.versions.attack | Should -Be (($script:Cat.source.attack.version -split '\.')[0])
        @($l.techniques).Count | Should -BeGreaterThan 0
        foreach ($t in $l.techniques) {
            $t.techniqueID | Should -Match '^T\d{4}(\.\d{3})?$'
            Test-AttackUsable $t.techniqueID | Should -BeTrue
            $t.enabled | Should -BeTrue
            $t.score | Should -BeOfType [int]
            [string]$t.comment | Should -Not -BeNullOrEmpty
        }
        @($l.gradient.colors).Count | Should -BeGreaterOrEqual 2
        $l.gradient.maxValue | Should -BeGreaterThan $l.gradient.minValue
        foreach ($li in $l.legendItems) { [string]$li.label | Should -Not -BeNullOrEmpty; $li.color | Should -Match '^#[0-9a-fA-F]{6}$' }
        $ids = @($l.techniques | ForEach-Object { $_.techniqueID })
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        # Round-trips as JSON (what the Navigator reads).
        { ConvertTo-VsatJson $l | ConvertFrom-Json } | Should -Not -Throw
    }
    It 'scores = open paths using the technique + FAIL findings whose rule mitigates it' {
        $l = New-VsatAttackLayer -Results $script:R
        $br = $script:R.analysis.blastRadius
        $eb = @{}; foreach ($e in $br.edges) { $eb[$e.id] = $e }
        $paths = @($br.paths | Where-Object { @($_.edgeIds | Where-Object { $eb[$_].attack.technique -eq 'T1078.002' }).Count })
        $rules = @{}; foreach ($r in $script:R.rules) { $rules[$r.id] = $r }
        $fails = @($script:R.findings | Where-Object { $_.result -eq 'FAIL' -and 'T1078.002' -in @($rules[$_.ruleId].attack.mitigates) })
        $t = @($l.techniques | Where-Object techniqueID -eq 'T1078.002')[0]
        $t.score | Should -Be ($paths.Count + $fails.Count)
        $t.comment | Should -Match ([regex]::Escape([string]$paths[0].id))
    }
    It 'omits ATLAS techniques from the enterprise layer' {
        $l = New-VsatAttackLayer -Results $script:R
        @($l.techniques | Where-Object { $_.techniqueID -like 'AML.*' }) | Should -BeNullOrEmpty
    }
    It 'is deterministic for the same results' {
        (ConvertTo-VsatJson (New-VsatAttackLayer -Results $script:R)) | Should -Be (ConvertTo-VsatJson (New-VsatAttackLayer -Results $script:R))
    }
}

Describe 'attack-layer.json output' {
    BeforeAll {
        $script:Out = Join-Path ([IO.Path]::GetTempPath()) ('vsat-attack-' + [guid]::NewGuid().ToString('N'))
        $ev = Get-TestEvidence
        $res = Get-TestResults $ev
        $script:Files = Write-VsatOutputs -Evidence $ev -Results $res -OutputDir $script:Out
    }
    AfterAll { Remove-Item -Recurse -Force $script:Out -ErrorAction SilentlyContinue }
    It 'writes attack-layer.json, lists it in the manifest and packs it in the zip' {
        $p = Join-Path $script:Out 'attack-layer.json'
        $p | Should -Exist
        $script:Files | Should -Contain 'attack-layer.json'
        $l = Get-Content -Raw $p | ConvertFrom-Json
        $l.versions.layer | Should -Be '4.5'
        $m = Get-Content -Raw (Join-Path $script:Out 'manifest.json') | ConvertFrom-Json
        $f = @($m.files | Where-Object name -eq 'attack-layer.json')[0]
        $f.sha256 | Should -Be (Get-VsatSha256 -Path $p)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [IO.Compression.ZipFile]::OpenRead((Join-Path $script:Out 'assessment.vsat.zip'))
        try { @($z.Entries | ForEach-Object { $_.FullName }) | Should -Contain 'attack-layer.json' } finally { $z.Dispose() }
    }
}
