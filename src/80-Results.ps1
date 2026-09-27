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
    Update-VsatProgress -Message 'Building the engagement change timeline'
    $changes = Get-VsatChangeAnalysis -Evidence $Evidence
    Set-VsatChangedInWindow -Findings $findings -Changes $changes
    $coverage = Get-VsatCoverage -Evidence $Evidence -Findings $findings -Changes $changes
    $status = Get-VsatRunStatus -Evidence $Evidence -Coverage $coverage -Findings $findings
    Update-VsatProgress -Message 'Modeling attack paths and failure impact'
    $paths = Get-VsatAttackPaths -Context $eval.context
    $pathTargets = @{}
    foreach ($p in @($paths.attackPaths | Where-Object { $_.decision -eq 'allow' })) { $pathTargets[$p.target] = $true }
    # Always rebuild the graph here, after rule evaluation, so edge and fix-plan findingKeys are filled (P17).
    Update-VsatProgress -Message 'Building cross-platform security graph'
    $graph = New-VsatSecurityGraph -Context $eval.context -Findings $findings
    $blast = Get-VsatBlastRadius -Graph $graph -Context $eval.context
    $blast.fixPlan = @(Get-VsatFixPlan -Paths $blast.paths -Graph $graph -Bounds $blast.bounds)
    foreach ($p in @($blast.paths)) { $pathTargets[[string]$p.crown] = $true }
    Set-VsatPriority -Findings $findings -Context $eval.context -PathTargets $pathTargets
    $impact = Get-VsatImpact -Context $eval.context
    $wps = Get-VsatWorkPackages -Findings $findings
    $results = New-VsatResultsObject -Evidence $Evidence -Eval $eval -Coverage $coverage -Status $status -ProfileName $ProfileName
    $results.analysis = [ordered]@{ attackPaths = @($paths.attackPaths); privilegePaths = @($paths.privilegePaths); chokepoints = @($paths.chokepoints); pathNotes = @($paths.notes); impact = @($impact); workPackages = @($wps); drift = $null; blastRadius = $blast; workPackageCatalog = @(Get-VsatWorkPackageCatalog); changes = $changes }
    if ($BaselineEvidence) {
        Update-VsatProgress -Message 'Comparing with baseline'
        $saveIdx = $script:VsatAssetIndex
        $b = Invoke-VsatBaselineResults -Evidence $BaselineEvidence -ProfileName $ProfileName
        $script:VsatAssetIndex = $saveIdx
        $results.analysis.drift = Get-VsatDrift -Current $results -Baseline $b
    }
    return $results
}

function Get-VsatWorkPackageCatalog {
    # Every work package the rule pack defines (id, title, team), so the report can title fixes
    # whose work package has no finding in this run (analysis.workPackages lists only those with findings).
    return @(foreach ($w in @((Get-VsatRulePackMeta).workPackages)) { if ($w) { [ordered]@{ id = [string]$w.id; title = [string]$w.title; team = [string](Get-VsatProp $w 'team' '') } } })
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
        rules = @($Eval.rules | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; domain = $_.domain; severity = $_.severity; assetType = $_.assetType; rationale = $_.rationale; mitigation = $_.mitigation; frameworks = $_.frameworks; attack = (Get-VsatProp $_ 'attack' $null); limitations = (Get-VsatProp $_ 'limitations' ''); automated = ($_.check.type -ne 'manual'); profiles = @(Get-VsatProp $_ 'profilesEnabled' @('standard', 'strict')) } })
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
                $c = [ordered]@{ id = $f.id; key = $f.key; ruleId = $f.ruleId; title = $f.title; domain = $f.domain; assetId = $f.assetId; assetName = $f.assetName; assetType = $f.assetType; result = $f.result; severity = $f.severity; observed = $f.observed; expected = $f.expected; confidence = $f.confidence; exception = $f.exception }
                if ($f.Contains('changedInWindow')) { $c.changedInWindow = $f.changedInWindow }
                $c
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
    # ATT&CK Navigator layer (format 4.5): open it in the Navigator, offline, with no VSAT knowledge.
    $files['attack-layer.json'] = ConvertTo-VsatJson (New-VsatAttackLayer -Results $Results)
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
    Export-VsatCsv -Rows @(Get-VsatChangeRows -Results $Results) -Columns @('id', 'utc', 'endpointId', 'assetId', 'assetName', 'user', 'category', 'action', 'source', 'checks') -Path (Join-Path $OutputDir 'changes.csv')
    Write-VsatFile -Path (Join-Path $OutputDir 'collection.log') -Content (Get-VsatLogText)
    $names = @('evidence.json', 'results.json', 'report.html', 'attack-layer.json', 'findings.csv', 'worklist.csv', 'changes.csv', 'collection.log')
    $manifest = New-VsatManifest -Results $Results -OutputDir $OutputDir -Names $names
    Write-VsatFile -Path (Join-Path $OutputDir 'manifest.json') -Content (ConvertTo-VsatJson $manifest)
    $zip = Join-Path $OutputDir 'assessment.vsat.zip'
    New-VsatPackage -Path $zip -SourceDir $OutputDir -Names @($names + 'manifest.json')
    $script:VsatLastReceipt = Complete-VsatReceipt -OutputDir $OutputDir -Manifest $manifest -Names $names
    $out = @('report.html', 'results.json', 'evidence.json', 'attack-layer.json', 'findings.csv', 'worklist.csv', 'changes.csv', 'collection.log', 'manifest.json', 'assessment.vsat.zip')
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

function Get-VsatLogText {
    return (($script:VsatLog | ForEach-Object { "{0} [{1}] {2}: {3}" -f $_.t, $_.level, $_.source, $_.message }) -join [Environment]::NewLine)
}

function Complete-VsatReceipt {
    # The receipt is computed AFTER the zip is written (no circularity): it goes into the
    # on-disk manifest.json and collection.log only. The copies inside the zip stay as zipped,
    # and the on-disk manifest is re-hashed so its file list keeps matching the folder.
    param([Parameter(Mandatory)][string]$OutputDir, [Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string[]]$Names)
    $zip = Join-Path $OutputDir 'assessment.vsat.zip'
    $code = Get-VsatReceipt -Path $zip
    $sha = Get-VsatSha256 -Path $zip
    Write-VsatLog -Source 'receipt' -Message "Receipt code $code (SHA-256 of assessment.vsat.zip: $sha). Read this code to your auditor."
    Write-VsatFile -Path (Join-Path $OutputDir 'collection.log') -Content (Get-VsatLogText)
    $Manifest.files = @($Names | ForEach-Object { $p = Join-Path $OutputDir $_; [ordered]@{ name = $_; sha256 = (Get-VsatSha256 -Path $p); bytes = (Get-Item -LiteralPath $p).Length } })
    $Manifest.package = [ordered]@{ name = 'assessment.vsat.zip'; sha256 = $sha; bytes = (Get-Item -LiteralPath $zip).Length }
    $Manifest.receipt = $code
    $Manifest.receiptNote = 'Receipt = first 80 bits of the SHA-256 of assessment.vsat.zip (Crockford base32). Verify with: vsat.ps1 -Replay assessment.vsat.zip -Receipt <code>. This file and collection.log were updated after the zip was written; the copies inside the zip do not contain the receipt.'
    Write-VsatFile -Path (Join-Path $OutputDir 'manifest.json') -Content (ConvertTo-VsatJson $Manifest)
    return $code
}

function Write-VsatCollectOnly {
    # -CollectOnly: evidence package, log and manifest only. No findings, no report, so the
    # easy "run, read, fix, rerun" loop is gone; the auditor replays the package later.
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)][string]$OutputDir)
    if (-not (Test-Path -LiteralPath $OutputDir)) { [void](New-Item -ItemType Directory -Path $OutputDir -Force) }
    [void](Protect-VsatDirectory -Path $OutputDir)
    Write-VsatLog -Source 'collect-only' -Message 'Collect-only run: writing the evidence package without findings or report'
    $Evidence.collection.log = @($script:VsatLog)
    $Evidence.run.collectOnly = $true
    Write-VsatFile -Path (Join-Path $OutputDir 'evidence.json') -Content (ConvertTo-VsatJson $Evidence)
    Write-VsatFile -Path (Join-Path $OutputDir 'collection.log') -Content (Get-VsatLogText)
    $manifest = New-VsatManifest -Evidence $Evidence -OutputDir $OutputDir -Names @('evidence.json', 'collection.log')
    Write-VsatFile -Path (Join-Path $OutputDir 'manifest.json') -Content (ConvertTo-VsatJson $manifest)
    New-VsatPackage -Path (Join-Path $OutputDir 'assessment.vsat.zip') -SourceDir $OutputDir -Names @('evidence.json', 'collection.log', 'manifest.json')
    # evidence.json lives only inside the package; the folder holds exactly three files.
    Remove-Item -LiteralPath (Join-Path $OutputDir 'evidence.json') -Force
    $manifest.packageFiles = @('evidence.json', 'collection.log', 'manifest.json')
    $code = Complete-VsatReceipt -OutputDir $OutputDir -Manifest $manifest -Names @('collection.log')
    return [ordered]@{ receipt = $code; files = @('assessment.vsat.zip', 'collection.log', 'manifest.json') }
}

function New-VsatManifest {
    # With -Results: a full assessment. With -Evidence only: a collect-only package.
    param($Results, [string]$OutputDir, [string[]]$Names, $Evidence)
    $pcli = $null
    try { $m = Get-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue | Select-Object -First 1; if ($m) { $pcli = [string]$m.Version } } catch { }
    $run = if ($Results) { $Results.run } else { $Evidence.run }
    return [ordered]@{
        schemaVersion = $script:VsatSchemaVersion
        tool = [ordered]@{ name = 'VSAT'; version = $script:VsatVersion; buildCommit = $script:VsatBuildCommit }
        rulePack = $(if ($Results) { $Results.rulePack.version } else { (Get-VsatRulePack).version }); advisorySnapshot = $(if ($Results) { $Results.advisory.snapshotDate } else { (Get-VsatAdvisoryData).snapshotDate })
        runId = $run.id; startedUtc = $run.startedUtc; endedUtc = $run.endedUtc; mode = $run.mode
        engagementStartUtc = (Get-VsatProp $run 'engagementStartUtc')
        status = $(if ($Results) { $Results.status.overall } else { 'collected' }); statusLabel = $(if ($Results) { $Results.status.label } else { 'COLLECTED: EVIDENCE ONLY (replay to evaluate)' }); exitCode = $(if ($Results) { $Results.status.exitCode } else { $null })
        coverage = @(if ($Results) { $Results.coverage.domains | ForEach-Object { [ordered]@{ domain = $_.id; state = $_.state } } })
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
    # Blast-radius principals. Normalized keys (ad:example\j.doe, local:ep-kvm01:root) are specific,
    # so they join the global map; so do domain-qualified names (EXAMPLE\x, user@domain). Bare local
    # names (root, admin, ops) are replaced only in principal-bearing blast-radius fields below.
    $bare = [ordered]@{}
    foreach ($n in @(Get-VsatProp $Results 'analysis.blastRadius.nodes' @())) {
        if (-not $n -or [string]$n.kind -ne 'principal') { continue }
        & $add ([string]$n.id) 'principal'
        $nm = [string]$n.name
        if ($nm -match '[\\@]') { & $add $nm 'principal' }
        elseif ($nm.Length -ge 1 -and -not $bare.Contains($nm)) { $counters['principal'] = [int]$counters['principal'] + 1; $bare[$nm] = '{0}-{1:d4}' -f 'principal', $counters['principal'] }
    }
    # Change timeline users: domain-qualified names join the global map; bare local names
    # (root, admin, vsat) are replaced only in the timeline's user fields below.
    $changeUsers = [ordered]@{}
    $ch = Get-VsatProp $Results 'analysis.changes' $null
    foreach ($u in @(@(Get-VsatProp $ch 'entries' @()) + @(Get-VsatProp $ch 'accountSessions' @()) | Where-Object { $_ } | ForEach-Object { [string]$_.user } | Where-Object { $_ })) {
        if ($u -match '[\\@]') { & $add $u 'principal' }
        elseif (-not $changeUsers.Contains($u)) { $counters['user'] = [int]$counters['user'] + 1; $changeUsers[$u] = '{0}-{1:d4}' -f 'user', $counters['user'] }
    }
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
    if ($bare.Count) { Protect-VsatRedactBlastPrincipals -Blast (Get-VsatProp $res 'analysis.blastRadius' $null) -Bare $bare }
    $rch = Get-VsatProp $res 'analysis.changes' $null
    if ($rch -and $changeUsers.Count) { foreach ($x in @(@($rch.entries) + @($rch.accountSessions))) { if ($x -and $x.user -and $changeUsers.Contains([string]$x.user)) { $x.user = $changeUsers[[string]$x.user] } } }
    $res.redacted = [ordered]@{ pseudonyms = $map.Count; ipAddresses = $ctx.ipMap.Count; note = 'Names, addresses, UUIDs and principals replaced with consistent pseudonyms. Review before sharing.' }
    return [ordered]@{ evidence = $ev; results = $res }
}

function Protect-VsatRedactBlastPrincipals {
    # Bare principal names: rewrite only the fields that name a principal (principal node names, the
    # narratives, explanations of edges leaving a principal, and revoke fix titles), never other text.
    param($Blast, [System.Collections.IDictionary]$Bare)
    if (-not $Blast) { return }
    $keys = @($Bare.Keys | Sort-Object { - ([string]$_).Length })
    $rx = [regex]::new('(?<![A-Za-z0-9_.\\@-])(?:' + (($keys | ForEach-Object { [regex]::Escape([string]$_) }) -join '|') + ')(?![A-Za-z0-9_@-])')
    $sub = { param([string]$t) if (-not $t) { return $t }; $rx.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $Bare[$m.Value] }) }
    $principals = @{}
    foreach ($n in @($Blast.nodes)) { if ($n -and [string]$n.kind -eq 'principal') { $principals[[string]$n.id] = $true; if ($Bare.Contains([string]$n.name)) { $n.name = $Bare[[string]$n.name] } } }
    foreach ($e in @($Blast.edges)) { if ($e -and $principals.ContainsKey([string]$e.source)) { $e.explanation = & $sub ([string]$e.explanation) } }
    foreach ($p in @(@($Blast.paths) + @($Blast.needsEvidence))) { if ($p) { $p.narrative = & $sub ([string]$p.narrative) } }
    foreach ($f in @($Blast.fixPlan)) { if ($f -and ([string]$f.fixId).StartsWith('revoke')) { $f.title = & $sub ([string]$f.title) } }
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
