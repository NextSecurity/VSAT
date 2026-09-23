#region Results pipeline

function Invoke-VsatAnalysisPipeline {
    # Evidence -> findings, coverage, status, analysis. Pure function of evidence + rule pack,
    # which is what makes collect-once/replay possible.
    param([Parameter(Mandatory)]$Evidence, [string]$ProfileName = 'standard', $BaselineEvidence)
    Update-VsatProgress -Phase 'analyzing' -Message 'Correlating inventory'
    if (-not $script:VsatAssetIndex -or $script:VsatAssetIndex.Count -ne @($Evidence.assets).Count) {
        $script:VsatAssetIndex = @{}; foreach ($a in $Evidence.assets) { $script:VsatAssetIndex[$a.id] = $a }
    }
    if (-not (Get-VsatProp $Evidence.nsx 'correlated' $false)) {
        [void](Update-VsatNsxDiscovery -Evidence $Evidence)
        Invoke-VsatCorrelation -Evidence $Evidence
        $Evidence.nsx.correlated = $true
    }
    Set-VsatScopeAnnotations -Evidence $Evidence
    Update-VsatProgress -Message 'Evaluating rules'
    $eval = Invoke-VsatRules -Evidence $Evidence -ProfileName $ProfileName
    $findings = $eval.findings
    Set-VsatExceptions -Evidence $Evidence -Findings $findings
    $coverage = Get-VsatCoverage -Evidence $Evidence -Findings $findings
    $status = Get-VsatRunStatus -Evidence $Evidence -Coverage $coverage -Findings $findings
    Update-VsatProgress -Message 'Modeling attack paths and failure impact'
    $paths = Get-VsatAttackPaths -Context $eval.context
    $pathTargets = @{}
    foreach ($p in @($paths.attackPaths | Where-Object { $_.decision -eq 'allow' })) { $pathTargets[$p.target] = $true }
    Set-VsatPriority -Findings $findings -Context $eval.context -PathTargets $pathTargets
    $impact = Get-VsatImpact -Context $eval.context
    $wps = Get-VsatWorkPackages -Findings $findings
    $results = New-VsatResultsObject -Evidence $Evidence -Eval $eval -Coverage $coverage -Status $status -ProfileName $ProfileName
    $results.analysis = [ordered]@{ attackPaths = @($paths.attackPaths); privilegePaths = @($paths.privilegePaths); chokepoints = @($paths.chokepoints); pathNotes = @($paths.notes); impact = @($impact); workPackages = @($wps); drift = $null }
    if ($BaselineEvidence) {
        Update-VsatProgress -Message 'Comparing with baseline'
        $saveIdx = $script:VsatAssetIndex
        $b = Invoke-VsatBaselineResults -Evidence $BaselineEvidence -ProfileName $ProfileName
        $script:VsatAssetIndex = $saveIdx
        $results.analysis.drift = Get-VsatDrift -Current $results -Baseline $b
    }
    return $results
}

function Invoke-VsatBaselineResults {
    param($Evidence, [string]$ProfileName)
    $script:VsatAssetIndex = @{}; foreach ($a in $Evidence.assets) { $script:VsatAssetIndex[$a.id] = $a }
    if (-not (Get-VsatProp $Evidence.nsx 'correlated' $false)) { [void](Update-VsatNsxDiscovery -Evidence $Evidence); Invoke-VsatCorrelation -Evidence $Evidence; $Evidence.nsx.correlated = $true }
    $eval = Invoke-VsatRules -Evidence $Evidence -ProfileName $ProfileName
    return [ordered]@{ run = $Evidence.run; findings = $eval.findings; assets = @($Evidence.assets) }
}

function New-VsatResultsObject {
    param($Evidence, $Eval, $Coverage, $Status, [string]$ProfileName)
    $findings = $Eval.findings
    $sum = [ordered]@{ PASS = 0; FAIL = 0; MANUAL = 0; UNKNOWN = 0; ERROR = 0; NOT_APPLICABLE = 0 }
    $sev = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
    $conf = [ordered]@{ observed = 0; inferred = 0 }
    foreach ($f in $findings) {
        $sum[$f.result] = [int]$sum[$f.result] + 1
        if ($f.result -eq 'FAIL') { $sev[[string]$f.severity] = [int]$sev[[string]$f.severity] + 1 }
        if ($f.result -in @('PASS', 'FAIL')) { $conf[[string]$f.confidence] = [int]$conf[[string]$f.confidence] + 1 }
    }
    $byAsset = @{}
    $rank = @{ critical = 5; high = 4; medium = 3; low = 2; info = 1 }
    foreach ($f in $findings) {
        if (-not $byAsset.ContainsKey($f.assetId)) { $byAsset[$f.assetId] = @{ counts = [ordered]@{}; worst = $null } }
        $e = $byAsset[$f.assetId]
        $e.counts[$f.result] = [int]$e.counts[$f.result] + 1
        if ($f.result -eq 'FAIL' -and ($null -eq $e.worst -or $rank[[string]$f.severity] -gt $rank[[string]$e.worst])) { $e.worst = $f.severity }
    }
    $assetTypes = [ordered]@{}
    $assets = foreach ($a in $Evidence.assets) {
        $assetTypes[$a.type] = [int]$assetTypes[$a.type] + 1
        $o = [ordered]@{}
        foreach ($k in $a.Keys) { if ($k -ne 'facts') { $o[$k] = $a[$k] } }
        $o.factStatus = [ordered]@{}; foreach ($k in $a.facts.Keys) { $o.factStatus[$k] = $a.facts[$k].status }
        $o.findingCounts = $(if ($byAsset.ContainsKey($a.id)) { $byAsset[$a.id].counts } else { [ordered]@{} })
        $o.worstSeverity = $(if ($byAsset.ContainsKey($a.id)) { $byAsset[$a.id].worst } else { $null })
        $o
    }
    $adv = Get-VsatAdvisoryData
    $age = [int]([DateTime]::UtcNow - [DateTime]::Parse($adv.snapshotDate, [Globalization.CultureInfo]::InvariantCulture)).TotalDays
    return [ordered]@{
        schemaVersion = $script:VsatSchemaVersion
        tool = [ordered]@{ name = 'VSAT'; version = $script:VsatVersion }
        run = $Evidence.run
        generatedUtc = (Get-VsatUtcNow)
        rulePack = [ordered]@{ version = $Eval.rulePackVersion; profile = $ProfileName; ruleCount = @($Eval.rules).Count; excludedAssets = $Eval.excluded }
        advisory = [ordered]@{ snapshotDate = $adv.snapshotDate; ageDays = $age }
        status = $Status
        coverage = $Coverage
        summary = [ordered]@{ results = $sum; severity = $sev; confidence = $conf; assets = $assetTypes }
        findings = @($findings)
        assets = @($assets)
        relationships = @($Evidence.relationships)
        analysis = $null
        rules = @($Eval.rules | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; domain = $_.domain; severity = $_.severity; assetType = $_.assetType; rationale = $_.rationale; mitigation = $_.mitigation; frameworks = $_.frameworks; limitations = (Get-VsatProp $_ 'limitations' ''); automated = ($_.check.type -ne 'manual'); profiles = @(Get-VsatProp $_ 'profilesEnabled' @('standard', 'strict')) } })
        scope = $Evidence.scope
        collection = [ordered]@{ collectors = @($Evidence.collection.collectors); log = @($Evidence.collection.log | Select-Object -Last 500) }
        nsx = $Evidence.nsx
    }
}

#endregion Results pipeline

#region Report rendering

function ConvertTo-VsatScriptJson {
    # JSON safe to embed inside <script type="application/json">: no '<', '>', '&', U+2028/9.
    param([Parameter(Mandatory)]$Object)
    $json = ConvertTo-VsatJson $Object -Compress
    $bs = [string][char]92
    return $json.Replace('<', $bs + 'u003c').Replace('>', $bs + 'u003e').Replace('&', $bs + 'u0026').Replace([string][char]0x2028, $bs + 'u2028').Replace([string][char]0x2029, $bs + 'u2029')
}

function Get-VsatReportData {
    # Compact PASS/NOT_APPLICABLE findings; full detail stays in results.json.
    param([Parameter(Mandatory)]$Results)
    $data = [ordered]@{}
    foreach ($k in $Results.Keys) { $data[$k] = $Results[$k] }
    $data.findings = @(foreach ($f in $Results.findings) {
            if ($f.result -in @('PASS', 'NOT_APPLICABLE')) {
                [ordered]@{ id = $f.id; key = $f.key; ruleId = $f.ruleId; title = $f.title; domain = $f.domain; assetId = $f.assetId; assetName = $f.assetName; assetType = $f.assetType; result = $f.result; severity = $f.severity; observed = $f.observed; expected = $f.expected; confidence = $f.confidence; exception = $f.exception }
            }
            else { $f }
        })
    $data.scope = [ordered]@{ endpoints = @($Results.scope.endpoints | ForEach-Object { [ordered]@{ id = $_.id; type = $_.type; address = $_.address; status = $_.status; product = $_.product; version = $_.version; build = $_.build } }); nsxDeclaredAbsent = $Results.scope.nsxDeclaredAbsent }
    return $data
}

function New-VsatHtmlDocument {
    param([Parameter(Mandatory)][string]$Template, [Parameter(Mandatory)][string]$Css, [Parameter(Mandatory)][string]$Js, $DataJson = $null, [string]$Title = 'VSAT Report', [string]$ExtraCsp = '')
    $cssHash = Get-VsatSha256Base64 $Css
    $jsHash = Get-VsatSha256Base64 $Js
    $csp = "default-src 'none'; script-src 'sha256-$jsHash'; style-src 'sha256-$cssHash'; img-src data: blob:; font-src 'none'; base-uri 'none'; form-action 'none'$ExtraCsp"
    $safeTitle = [System.Net.WebUtility]::HtmlEncode($Title)
    # Replace tokens with literal (non-regex) substitution; data first so no token inside data is expanded.
    $parts = $Template
    $parts = $parts.Replace('__VSAT_TITLE__', $safeTitle).Replace('__VSAT_CSP__', $csp)
    $parts = $parts.Replace('__VSAT_CSS__', $Css)
    if ($null -ne $DataJson) { $idx = $parts.IndexOf('__VSAT_DATA__'); if ($idx -ge 0) { $parts = $parts.Substring(0, $idx) + '__VSAT_DATA_SLOT__' + $parts.Substring($idx + 13) } }
    $idx = $parts.IndexOf('__VSAT_JS__')
    if ($idx -ge 0) { $parts = $parts.Substring(0, $idx) + $Js + $parts.Substring($idx + 11) }
    if ($null -ne $DataJson) { $idx = $parts.IndexOf('__VSAT_DATA_SLOT__'); $parts = $parts.Substring(0, $idx) + $DataJson + $parts.Substring($idx + 18) }
    return $parts
}

function New-VsatReportHtml {
    param([Parameter(Mandatory)]$Results, [string]$Title)
    if (-not $Title) { $Title = "VSAT Report - $($Results.status.label)" }
    $data = ConvertTo-VsatScriptJson (Get-VsatReportData $Results)
    return (New-VsatHtmlDocument -Template (Get-VsatEmbeddedText 'assets/report/report.html') -Css (Get-VsatEmbeddedText 'assets/report/report.css') -Js (Get-VsatEmbeddedText 'assets/report/report.js') -DataJson $data -Title $Title)
}

#endregion Report rendering

#region Output files and evidence package

function Get-VsatFindingRows {
    param([object[]]$Findings)
    foreach ($f in $Findings) {
        [ordered]@{
            id = $f.id; result = $f.result; severity = $f.severity; priority = (Get-VsatProp $f 'priority.score'); ruleId = $f.ruleId; title = $f.title; domain = $f.domain
            assetType = $f.assetType; assetName = $f.assetName; assetId = $f.assetId; observed = $f.observed; expected = $f.expected; confidence = $f.confidence
            mitigation = (Get-VsatProp $f 'mitigation.summary'); workPackage = (Get-VsatProp $f 'mitigation.workPackage')
            frameworks = (@($f.frameworks | ForEach-Object { "$($_.framework) $($_.control) [$($_.mappingStatus)]" }) -join '; ')
            exception = $(if ($f.exception) { "$($f.exception.owner) until $($f.exception.expires) ($(if ($f.exception.active) { 'active' } else { 'EXPIRED' }))" } else { '' })
        }
    }
}

function Write-VsatOutputs {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Results, [Parameter(Mandatory)][string]$OutputDir, [switch]$Redact)
    if (-not (Test-Path -LiteralPath $OutputDir)) { [void](New-Item -ItemType Directory -Path $OutputDir -Force) }
    [void](Protect-VsatDirectory -Path $OutputDir)
    $Evidence.collection.log = @($script:VsatLog)
    $files = [ordered]@{}
    $files['evidence.json'] = ConvertTo-VsatJson $Evidence
    $files['results.json'] = ConvertTo-VsatJson $Results
    $files['report.html'] = New-VsatReportHtml -Results $Results
    foreach ($name in $files.Keys) { Write-VsatFile -Path (Join-Path $OutputDir $name) -Content $files[$name] }
    $rows = @(Get-VsatFindingRows $Results.findings)
    Export-VsatCsv -Rows $rows -Columns @('id', 'result', 'severity', 'priority', 'ruleId', 'title', 'domain', 'assetType', 'assetName', 'assetId', 'observed', 'expected', 'confidence', 'mitigation', 'workPackage', 'frameworks', 'exception') -Path (Join-Path $OutputDir 'findings.csv')
    $wl = foreach ($wp in @($Results.analysis.workPackages)) {
        foreach ($fid in $wp.findingIds) {
            $f = @($Results.findings | Where-Object { $_.id -eq $fid })[0]
            [ordered]@{ workPackage = $wp.id; title = $wp.title; team = $wp.team; maintenanceWindow = $wp.maintenanceWindow; findingId = $fid; severity = $f.severity; ruleId = $f.ruleId; asset = $f.assetName; action = (Get-VsatProp $f 'mitigation.summary'); validation = $wp.validation; rollback = $wp.rollback }
        }
    }
    Export-VsatCsv -Rows @($wl) -Columns @('workPackage', 'title', 'team', 'maintenanceWindow', 'findingId', 'severity', 'ruleId', 'asset', 'action', 'validation', 'rollback') -Path (Join-Path $OutputDir 'worklist.csv')
    $logText = ($script:VsatLog | ForEach-Object { "{0} [{1}] {2}: {3}" -f $_.t, $_.level, $_.source, $_.message }) -join [Environment]::NewLine
    Write-VsatFile -Path (Join-Path $OutputDir 'collection.log') -Content $logText
    $manifest = New-VsatManifest -Results $Results -OutputDir $OutputDir -Names @('evidence.json', 'results.json', 'report.html', 'findings.csv', 'worklist.csv', 'collection.log')
    Write-VsatFile -Path (Join-Path $OutputDir 'manifest.json') -Content (ConvertTo-VsatJson $manifest)
    $zip = Join-Path $OutputDir 'assessment.vsat.zip'
    New-VsatPackage -Path $zip -SourceDir $OutputDir -Names @('evidence.json', 'results.json', 'report.html', 'findings.csv', 'worklist.csv', 'collection.log', 'manifest.json')
    $out = @('report.html', 'results.json', 'evidence.json', 'findings.csv', 'worklist.csv', 'collection.log', 'manifest.json', 'assessment.vsat.zip')
    if ($Redact) {
        $red = Get-VsatRedactedCopy -Evidence $Evidence -Results $Results
        $rdir = Join-Path $OutputDir 'redacted'
        [void](New-Item -ItemType Directory -Path $rdir -Force)
        Write-VsatFile -Path (Join-Path $rdir 'evidence.json') -Content (ConvertTo-VsatJson $red.evidence)
        Write-VsatFile -Path (Join-Path $rdir 'results.json') -Content (ConvertTo-VsatJson $red.results)
        Write-VsatFile -Path (Join-Path $rdir 'report.html') -Content (New-VsatReportHtml -Results $red.results -Title "VSAT Report (redacted) - $($red.results.status.label)")
        Export-VsatCsv -Rows @(Get-VsatFindingRows $red.results.findings) -Columns @('id', 'result', 'severity', 'priority', 'ruleId', 'title', 'domain', 'assetType', 'assetName', 'assetId', 'observed', 'expected', 'confidence', 'mitigation', 'workPackage', 'frameworks', 'exception') -Path (Join-Path $rdir 'findings.csv')
        $rm = New-VsatManifest -Results $red.results -OutputDir $rdir -Names @('evidence.json', 'results.json', 'report.html', 'findings.csv')
        $rm.redacted = $true
        Write-VsatFile -Path (Join-Path $rdir 'manifest.json') -Content (ConvertTo-VsatJson $rm)
        New-VsatPackage -Path (Join-Path $OutputDir 'assessment.redacted.vsat.zip') -SourceDir $rdir -Names @('evidence.json', 'results.json', 'report.html', 'findings.csv', 'manifest.json')
        Copy-Item -LiteralPath (Join-Path $rdir 'report.html') -Destination (Join-Path $OutputDir 'report.redacted.html') -Force
        $out += @('report.redacted.html', 'assessment.redacted.vsat.zip')
    }
    return $out
}

function New-VsatManifest {
    param($Results, [string]$OutputDir, [string[]]$Names)
    $pcli = $null
    try { $m = Get-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue | Select-Object -First 1; if ($m) { $pcli = [string]$m.Version } } catch { }
    return [ordered]@{
        schemaVersion = $script:VsatSchemaVersion
        tool = [ordered]@{ name = 'VSAT'; version = $script:VsatVersion; buildCommit = $script:VsatBuildCommit }
        rulePack = $Results.rulePack.version; advisorySnapshot = $Results.advisory.snapshotDate
        runId = $Results.run.id; startedUtc = $Results.run.startedUtc; endedUtc = $Results.run.endedUtc; mode = $Results.run.mode
        status = $Results.status.overall; statusLabel = $Results.status.label; exitCode = $Results.status.exitCode
        coverage = @($Results.coverage.domains | ForEach-Object { [ordered]@{ domain = $_.id; state = $_.state } })
        dependencies = [ordered]@{ powershell = [string]$PSVersionTable.PSVersion; edition = [string]$PSVersionTable.PSEdition; os = [string][Environment]::OSVersion.VersionString; powercli = $pcli }
        files = @($Names | ForEach-Object { $p = Join-Path $OutputDir $_; [ordered]@{ name = $_; sha256 = (Get-VsatSha256 -Path $p); bytes = (Get-Item -LiteralPath $p).Length } })
        note = 'SHA-256 hashes provide integrity checking of this package, not proof that source systems reported truthfully. Contains sensitive infrastructure data.'
    }
}

function New-VsatPackage {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$SourceDir, [Parameter(Mandatory)][string[]]$Names)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($n in $Names) {
                $e = $zip.CreateEntry($n, [System.IO.Compression.CompressionLevel]::Optimal)
                $e.LastWriteTime = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $s = $e.Open()
                try { $b = [System.IO.File]::ReadAllBytes((Join-Path $SourceDir $n)); $s.Write($b, 0, $b.Length) } finally { $s.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $fs.Dispose() }
}

$script:VsatZipLimits = @{ MaxEntries = 64; MaxEntryBytes = 512MB; MaxTotalBytes = 1GB; MaxRatio = 200 }

function Read-VsatPackage {
    # Reads an evidence package without extracting to disk: fixed entry names only,
    # path validation, entry/size/ratio limits (zip-slip and decompression-bomb safe).
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    if ($full -match '\.json$') {
        $txt = [System.IO.File]::ReadAllText($full)
        return [ordered]@{ evidence = (ConvertFrom-VsatJson $txt); integrity = 'not-verified (plain evidence.json)'; manifest = $null }
    }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($full)
    try {
        if ($zip.Entries.Count -gt $script:VsatZipLimits.MaxEntries) { throw "Package has too many entries ($($zip.Entries.Count))." }
        $total = 0L
        $wanted = @{}
        foreach ($e in $zip.Entries) {
            $n = $e.FullName
            if ($n -match '(^|[\\/])\.\.([\\/]|$)' -or $n.StartsWith('/') -or $n.StartsWith('\') -or $n -match '^[A-Za-z]:' -or $n.Contains('\')) { throw "Package entry has an unsafe path: $n" }
            if ($e.Length -gt $script:VsatZipLimits.MaxEntryBytes) { throw "Package entry $n exceeds the size limit." }
            if ($e.CompressedLength -gt 0 -and ($e.Length / [double]$e.CompressedLength) -gt $script:VsatZipLimits.MaxRatio) { throw "Package entry $n exceeds the compression ratio limit." }
            $total += $e.Length
            if ($total -gt $script:VsatZipLimits.MaxTotalBytes) { throw 'Package exceeds the total size limit.' }
            if ($n -in @('evidence.json', 'manifest.json')) { $wanted[$n] = $e }
        }
        if (-not $wanted.ContainsKey('evidence.json')) { throw 'Package does not contain evidence.json.' }
        $read = {
            param($entry)
            $s = $entry.Open(); $ms = New-Object System.IO.MemoryStream
            try {
                $buf = New-Object byte[] 65536; $sum = 0L
                while (($r = $s.Read($buf, 0, $buf.Length)) -gt 0) { $sum += $r; if ($sum -gt $script:VsatZipLimits.MaxEntryBytes) { throw 'Entry exceeded size limit while reading.' }; $ms.Write($buf, 0, $r) }
                return , $ms.ToArray()
            }
            finally { $s.Dispose(); $ms.Dispose() }
        }
        $evBytes = & $read $wanted['evidence.json']
        $integrity = 'no-manifest'
        $manifest = $null
        if ($wanted.ContainsKey('manifest.json')) {
            $manifest = ConvertFrom-VsatJson ([System.Text.Encoding]::UTF8.GetString((& $read $wanted['manifest.json'])))
            $expected = @($manifest.files | Where-Object { $_.name -eq 'evidence.json' })[0].sha256
            $actual = Get-VsatSha256 -Bytes $evBytes
            if ($expected -and $expected -ne $actual) { throw 'Evidence package integrity check failed: evidence.json does not match manifest.json.' }
            $integrity = 'verified (manifest SHA-256)'
        }
        $text = [System.Text.Encoding]::UTF8.GetString($evBytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        $ev = ConvertFrom-VsatJson $text
        if ([string]$ev.schemaVersion -notmatch '^2\.') { throw "Unsupported evidence schema version '$($ev.schemaVersion)'." }
        return [ordered]@{ evidence = $ev; integrity = $integrity; manifest = $manifest }
    }
    finally { $zip.Dispose() }
}

function ConvertTo-VsatLiveEvidence {
    # Replayed JSON arrays become fixed-size; restore the mutable lists the pipeline expects.
    param([Parameter(Mandatory)]$Evidence)
    $Evidence.assets = New-VsatList $Evidence.assets
    $Evidence.relationships = New-VsatList $Evidence.relationships
    $Evidence.collection.collectors = New-VsatList $Evidence.collection.collectors
    $Evidence.scope = New-VsatScope $Evidence.scope
    foreach ($a in $Evidence.assets) {
        if (-not $a.Contains('facts') -or $null -eq $a.facts) { $a.facts = [ordered]@{} }
        if (-not $a.Contains('props') -or $null -eq $a.props) { $a.props = [ordered]@{} }
    }
    foreach ($e in $Evidence.scope.endpoints) { if (-not $e.Contains('errors') -or $null -eq $e.errors) { $e.errors = @() } }
    if (-not $Evidence.Contains('nsx') -or $null -eq $Evidence.nsx) { $Evidence.nsx = [ordered]@{ discovery = [ordered]@{ status = 'unknown'; evidence = @(); managersDiscovered = @() } } }
    $script:VsatAssetIndex = @{}; foreach ($a in $Evidence.assets) { $script:VsatAssetIndex[$a.id] = $a }
    return $Evidence
}

#endregion Output files and evidence package

#region Redaction

function Get-VsatRedactedCopy {
    # Consistent pseudonyms preserve graph relationships; original evidence is untouched.
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Results)
    $map = @{}
    $counters = @{}
    $add = {
        param([string]$Value, [string]$Kind)
        if (-not $Value -or $Value.Length -lt 3 -or $map.ContainsKey($Value)) { return }
        $counters[$Kind] = [int]$counters[$Kind] + 1
        $map[$Value] = '{0}-{1:d4}' -f $Kind, $counters[$Kind]
    }
    foreach ($e in $Evidence.scope.endpoints) { & $add $e.address $e.type }
    foreach ($a in $Evidence.assets) {
        & $add $a.name $a.type
        if ($a.props.Contains('path') -and $a.props.path) { foreach ($seg in ([string]$a.props.path).Split('/')) { if ($seg -and $seg -notin @('infra', 'domains', 'default', 'segments', 'groups', 'security-policies', 'gateway-policies', 'rules', 'tier-0s', 'tier-1s', 'locale-services', 'nat', 'USER')) { & $add $seg 'obj' } } }
        foreach ($t in @($a.tags)) { & $add ([string]$t) 'tag' }
        if ($a.props.Contains('portgroup')) { & $add ([string]$a.props.portgroup) 'portgroup' }
        if ($a.props.Contains('vswitch')) { & $add ([string]$a.props.vswitch) 'vswitch' }
        if ($a.props.Contains('fqdn')) { & $add ([string]$a.props.fqdn) 'fqdn' }
        if ($a.facts.Contains('permissions') -and $a.facts.permissions.value) { foreach ($p in @($a.facts.permissions.value)) { & $add ([string]$p.principal) 'principal' } }
    }
    foreach ($m in @($Evidence.nsx.discovery.managersDiscovered)) { & $add $m 'nsx' }
    $keys = @($map.Keys | Sort-Object { - $_.Length })
    $ipMap = @{}
    # One compiled alternation keeps redaction linear in the size of each string.
    $nameRx = if ($keys.Count) { [regex]::new('(?<![A-Za-z0-9_.-])(?:' + (($keys | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![A-Za-z0-9_-])') } else { $null }
    $ipRx = [regex]::new('\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
    $macRx = [regex]::new('(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b')
    $uuidRx = [regex]::new('(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
    $ctx = @{ map = $map; ipMap = $ipMap; nameRx = $nameRx; ipRx = $ipRx; macRx = $macRx; uuidRx = $uuidRx }
    $ev = Invoke-VsatRedactValue -Value $Evidence -Ctx $ctx
    $res = Invoke-VsatRedactValue -Value $Results -Ctx $ctx
    $res.redacted = [ordered]@{ pseudonyms = $map.Count; ipAddresses = $ctx.ipMap.Count; note = 'Names, addresses, UUIDs and principals replaced with consistent pseudonyms. Review before sharing.' }
    return [ordered]@{ evidence = $ev; results = $res }
}

function Invoke-VsatRedactValue {
    # Walks the object graph and rewrites string values only (never JSON text), so
    # escaping stays intact and dictionary keys (setting names) are preserved.
    param($Value, $Ctx)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (Protect-VsatRedactString -Text $Value -Ctx $Ctx) }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) { $o[$k] = Invoke-VsatRedactValue -Value $Value[$k] -Ctx $Ctx }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $Value) { $l.Add((Invoke-VsatRedactValue -Value $i -Ctx $Ctx)) }
        return , $l.ToArray()
    }
    return $Value
}

function Protect-VsatRedactString {
    param([string]$Text, $Ctx)
    if (-not $Text) { return $Text }
    $t = $Text
    if ($Ctx.nameRx) { $t = $Ctx.nameRx.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $Ctx.map[$m.Value] }) }
    $t = $Ctx.ipRx.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            if (-not $Ctx.ipMap.ContainsKey($m.Value)) { $n = $Ctx.ipMap.Count + 1; $Ctx.ipMap[$m.Value] = '198.18.{0}.{1}' -f [int][Math]::Floor($n / 250), (($n % 250) + 1) }
            $Ctx.ipMap[$m.Value]
        })
    $t = $Ctx.macRx.Replace($t, '00:00:5e:00:53:00')
    $t = $Ctx.uuidRx.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] { param($m) '00000000-0000-4000-8000-' + (Get-VsatSha256 -Text $m.Value.ToLowerInvariant()).Substring(0, 12) })
    return $t
}

#endregion Redaction
