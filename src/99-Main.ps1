#region Orchestration

$script:VsatSessions = [ordered]@{}

function Get-VsatScopeFile {
    param([string]$Path)
    if (-not $Path) { return $null }
    $txt = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).ProviderPath)
    $scope = ConvertFrom-VsatJson $txt
    # A scope file is credential-free by contract; refuse anything that looks like a secret.
    if ($txt -match '(?i)"(password|secret|token|apikey|api_key)"\s*:') { throw 'Scope files must not contain credentials. Remove password/secret/token fields.' }
    return $scope
}

function Connect-VsatTarget {
    # Connects one endpoint and records the outcome on the evidence endpoint entry.
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Target)
    $ep = Add-VsatEndpoint -Evidence $Evidence -Type $Target.type -Address $Target.address
    $key = "$($Target.type)|$($Target.address)"
    if ($script:VsatSessions.Contains($key) -and $script:VsatSessions[$key].connected) { return $ep }
    Update-VsatProgress -Message "Connecting to $($Target.address)"
    try {
        if ($Target.thumbprint) { Register-VsatPins @("$($Target.address)=$($Target.thumbprint)") }
        if ($Target.type -eq 'nsx') { $sess = Connect-VsatNsx -Address $Target.address -Credential $Target.credential; $script:VsatSessions[$key] = @{ connected = $true; kind = 'nsx'; session = $sess; endpointId = $ep.id } }
        else { $conn = Connect-VsatVSphere -Address $Target.address -Credential $Target.credential; $script:VsatSessions[$key] = @{ connected = $true; kind = 'vsphere'; session = $conn; endpointId = $ep.id } }
        Write-VsatLog -Source 'session' -Message "Connected to $($Target.type) $($Target.address)"
    }
    catch {
        $msg = Protect-VsatText $_.Exception.Message
        $ep.status = 'failed'
        $ep.errors.Add($msg)
        Write-VsatLog -Level error -Source 'session' -Message "Cannot connect to $($Target.type) $($Target.address): $msg"
    }
    return $ep
}

function Disconnect-VsatAll {
    foreach ($k in @($script:VsatSessions.Keys)) {
        $s = $script:VsatSessions[$k]
        try {
            if ($s.kind -eq 'nsx') { Close-VsatRestSession $s.session }
            elseif ($s.session) { Disconnect-VIServer -Server $s.session -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
        }
        catch { }
        $s.connected = $false
    }
    $script:VsatSessions = [ordered]@{}
}

function Invoke-VsatLiveCollection {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)][object[]]$Targets)
    $vs = @($Targets | Where-Object { $_.type -in @('vcenter', 'esxi') })
    $nsx = @($Targets | Where-Object { $_.type -eq 'nsx' })
    $script:VsatProgress.totalSteps = ($vs.Count * 6) + ($nsx.Count * 7)
    $script:VsatProgress.step = 0
    try {
        foreach ($t in $vs) {
            if (Test-VsatCancel) { break }
            $ep = Connect-VsatTarget -Evidence $Evidence -Target $t
            $s = $script:VsatSessions["$($t.type)|$($t.address)"]
            if (-not $s -or -not $s.connected) { continue }
            Update-VsatProgress -Phase 'collecting'
            Invoke-VsatVSphereCollection -Evidence $Evidence -Endpoint $ep -Connection $s.session
            Set-VsatEndpointStatus -Evidence $Evidence -Endpoint $ep
        }
        foreach ($t in $nsx) {
            if (Test-VsatCancel) { break }
            $ep = Connect-VsatTarget -Evidence $Evidence -Target $t
            $s = $script:VsatSessions["$($t.type)|$($t.address)"]
            if (-not $s -or -not $s.connected) { continue }
            Update-VsatProgress -Phase 'collecting'
            Invoke-VsatNsxCollection -Evidence $Evidence -Endpoint $ep -Session $s.session
            Set-VsatEndpointStatus -Evidence $Evidence -Endpoint $ep
        }
    }
    finally {
        Disconnect-VsatAll
        $Evidence.run.endedUtc = Get-VsatUtcNow
        $Evidence.run.status = if (Test-VsatCancel) { 'canceled' } elseif (@($Evidence.scope.endpoints | Where-Object { $_.status -ne 'collected' }).Count) { 'partial' } else { 'complete' }
    }
}

function Set-VsatEndpointStatus {
    param($Evidence, $Endpoint)
    $c = @($Evidence.collection.collectors | Where-Object { $_.endpoint -eq $Endpoint.id })
    $bad = @($c | Where-Object { $_.status -notin @('ok', 'skipped') })
    $Endpoint.status = if ($c.Count -eq 0) { 'failed' } elseif ($bad.Count -eq 0) { 'collected' } elseif ($bad.Count -eq $c.Count) { 'failed' } else { 'partial' }
}

function Get-VsatDemoEvidence {
    $ev = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'fixtures/demo-evidence.json')
    $ev.run.id = [guid]::NewGuid().ToString()
    $ev.run.startedUtc = Get-VsatUtcNow
    $ev.run.endedUtc = Get-VsatUtcNow
    $ev.run.mode = 'demo'
    return (ConvertTo-VsatLiveEvidence $ev)
}

function Resolve-VsatOutputDir {
    param([string]$Path)
    if ($Path) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path (Get-Location).ProviderPath ('vsat-output/' + [DateTime]::Now.ToString('yyyyMMdd-HHmmss'))))
}

function Open-VsatBrowser {
    param([Parameter(Mandatory)][string]$Target)
    try {
        if (Test-VsatIsWindows) { Start-Process $Target | Out-Null }
        elseif ($IsMacOS) { & open $Target }
        else { & xdg-open $Target 2>$null | Out-Null }
    }
    catch { Write-Host "Open this address in a browser: $Target" }
}

function Write-VsatSummary {
    param([Parameter(Mandatory)]$Results, [string]$OutputDir, [string[]]$Files)
    $st = $Results.status
    $color = switch ($st.overall) { 'complete' { if ($st.exitCode -eq 0) { 'Green' } else { 'Yellow' } } default { 'Red' } }
    Write-Host ''
    Write-Host ("=" * 78)
    Write-Host (" STATUS: {0}" -f $st.label) -ForegroundColor $color
    foreach ($r in @($st.reasons | Select-Object -First 6)) { Write-Host ("   - {0}" -f (Protect-VsatText $r)) }
    Write-Host ("=" * 78)
    Write-Host ' Coverage' -ForegroundColor Cyan
    foreach ($d in $Results.coverage.domains) {
        $c = switch ($d.state) { 'ASSESSED' { 'Green' } 'NOT_APPLICABLE' { 'Gray' } 'PARTIAL' { 'Yellow' } default { 'Red' } }
        Write-Host ("   {0,-24} {1,-15} {2}" -f $d.name, $d.state, $(if ($d.mandatory) { 'mandatory' } else { '' })) -ForegroundColor $c
    }
    $s = $Results.summary
    Write-Host ' Findings (FAIL by severity)' -ForegroundColor Cyan
    Write-Host ("   critical {0}  high {1}  medium {2}  low {3}  info {4}" -f $s.severity.critical, $s.severity.high, $s.severity.medium, $s.severity.low, $s.severity.info)
    Write-Host ("   results: PASS {0}  FAIL {1}  MANUAL {2}  UNKNOWN {3}  ERROR {4}  N/A {5}" -f $s.results.PASS, $s.results.FAIL, $s.results.MANUAL, $s.results.UNKNOWN, $s.results.ERROR, $s.results.NOT_APPLICABLE)
    $top = @($Results.findings | Where-Object { $_.result -eq 'FAIL' -and $_.priority } | Sort-Object { - $_.priority.score } | Select-Object -First 10)
    if ($top.Count) {
        Write-Host ' Top priorities' -ForegroundColor Cyan
        foreach ($f in $top) { Write-Host ("   [{0,3}] {1,-8} {2} - {3}" -f $f.priority.score, $f.severity, (Protect-VsatText $f.assetName), $f.title) }
    }
    Write-Host (" Advisory data snapshot: {0} ({1} days old). Rule pack {2}, profile {3}." -f $Results.advisory.snapshotDate, $Results.advisory.ageDays, $Results.rulePack.version, $Results.rulePack.profile)
    if ($OutputDir) {
        Write-Host ' Output (contains sensitive infrastructure data)' -ForegroundColor Cyan
        foreach ($f in @($Files)) { Write-Host ("   {0}" -f (Join-Path $OutputDir $f)) }
    }
    Write-Host ''
}

function Complete-VsatRun {
    # Shared tail for CLI, replay and demo: analysis, outputs, summary.
    param($Evidence, [string]$ProfileName, [string]$OutputDir, $BaselineEvidence, [switch]$Redact)
    $results = Invoke-VsatAnalysisPipeline -Evidence $Evidence -ProfileName $ProfileName -BaselineEvidence $BaselineEvidence
    Update-VsatProgress -Phase 'writing' -Message 'Writing report and evidence package'
    $files = Write-VsatOutputs -Evidence $Evidence -Results $results -OutputDir $OutputDir -Redact:$Redact
    return @{ results = $results; files = $files }
}

function Read-VsatBaseline {
    param([string]$Path)
    if (-not $Path) { return $null }
    $b = Read-VsatPackage -Path $Path
    Write-VsatLog -Source 'drift' -Message "Baseline $Path loaded (integrity: $($b.integrity))"
    return (ConvertTo-VsatLiveEvidence $b.evidence)
}

function Get-VsatCliTargets {
    param([string[]]$Servers, [string[]]$NsxServers, $Scope, [pscredential]$Credential, [pscredential]$NsxCred, [switch]$Interactive)
    $targets = [System.Collections.Generic.List[object]]::new()
    $srv = @($Servers) + @(Get-VsatProp $Scope 'endpoints' @() | Where-Object { $_.type -in @('vcenter', 'esxi') } | ForEach-Object { $_.address }) | Where-Object { $_ } | Select-Object -Unique
    $nsx = @($NsxServers) + @(Get-VsatProp $Scope 'endpoints' @() | Where-Object { $_.type -eq 'nsx' } | ForEach-Object { $_.address }) | Where-Object { $_ } | Select-Object -Unique
    if ($Interactive -and @($srv).Count -eq 0) {
        $a = Read-Host 'vCenter or ESXi address'
        if ($a) { $srv = @($a.Trim()) }
    }
    if (@($srv).Count -and -not $Credential) { $Credential = Get-Credential -Message 'vCenter/ESXi credentials (read-only role is sufficient)' }
    foreach ($s in @($srv)) { $targets.Add(@{ type = 'vcenter'; address = $s.ToLowerInvariant(); credential = $Credential }) }
    $declared = $false
    if ($Interactive -and @($nsx).Count -eq 0 -and -not $script:VsatArgs.NsxDeclaredAbsent -and -not (Get-VsatProp $Scope 'nsxDeclaredAbsent' $false)) {
        Write-Host 'NSX is a mandatory audit domain.' -ForegroundColor Cyan
        $a = Read-Host "NSX Manager address (Enter = unknown, 'none' = NSX is not deployed in this scope)"
        if ($a -eq 'none') { $declared = $true }
        elseif ($a) { $nsx = @($a.Trim()) }
    }
    if (@($nsx).Count -and -not $NsxCred) { $NsxCred = Get-Credential -Message 'NSX Manager credentials (Auditor role is sufficient)' }
    foreach ($n in @($nsx)) { $targets.Add(@{ type = 'nsx'; address = $n.ToLowerInvariant(); credential = $NsxCred }) }
    return @{ targets = @($targets); declaredAbsent = $declared }
}

function Invoke-VsatMain {
    param([hashtable]$A)
    $script:VsatArgs = $A
    $script:VsatRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).ProviderPath }
    $modDir = Join-Path $script:VsatRoot 'modules'
    if (Test-Path -LiteralPath $modDir) {
        # Process-local module resolution; no global installation or profile changes.
        $env:PSModulePath = $modDir + [IO.Path]::PathSeparator + $env:PSModulePath
    }
    if ($A.Version) { [Console]::Out.WriteLine("VSAT $($script:VsatVersion) (rule pack $((Get-VsatRulePack).version), advisory snapshot $((Get-VsatAdvisoryData).snapshotDate), schema $script:VsatSchemaVersion)"); return 0 }
    Register-VsatPins $A.TrustedThumbprint
    $profileName = if ($A.Profile) { $A.Profile } else { 'standard' }
    Initialize-VsatProgress
    $scope = Get-VsatScopeFile $A.ScopeFile
    if ($A.NsxDeclaredAbsent) { if (-not $scope) { $scope = [ordered]@{} }; $scope.nsxDeclaredAbsent = $true }

    if ($A.Doctor) {
        $checks = Invoke-VsatDoctor -Endpoints (@($A.Server) + @($A.NsxServer)) -OutputDir (Resolve-VsatOutputDir $A.OutputPath)
        Write-VsatDoctorReport $checks
        if (@($checks | Where-Object { $_.status -eq 'fail' }).Count) { return 3 }
        return 0
    }

    $outDir = Resolve-VsatOutputDir $A.OutputPath
    [void](New-Item -ItemType Directory -Path $outDir -Force)
    [void](Protect-VsatDirectory -Path $outDir)
    $script:VsatLogFile = Join-Path $outDir 'collection.log'
    Write-VsatLog -Message "VSAT $($script:VsatVersion) starting; output: $outDir"
    $baseline = Read-VsatBaseline $A.Baseline

    if ($A.Replay) {
        $pkg = Read-VsatPackage -Path $A.Replay
        Write-VsatLog -Source 'replay' -Message "Replaying evidence from $($A.Replay) (integrity: $($pkg.integrity)); no connectivity or credentials used"
        $ev = ConvertTo-VsatLiveEvidence $pkg.evidence
        $ev.run.replayedUtc = Get-VsatUtcNow
        if ($scope) { foreach ($k in @('exclusions', 'nativeVlans', 'authorizedNetflowCollectors', 'authorizedSyslogTargets', 'criticalAssets', 'zones', 'exceptions')) { $v = Get-VsatProp $scope $k; if ($null -ne $v) { $ev.scope[$k] = $v } } }
        $r = Complete-VsatRun -Evidence $ev -ProfileName $profileName -OutputDir $outDir -BaselineEvidence $baseline -Redact:$A.Redact
        Write-VsatSummary -Results $r.results -OutputDir $outDir -Files $r.files
        if (-not $A.Cli -and -not $A.NoBrowser) { Open-VsatBrowser (Join-Path $outDir 'report.html') }
        return $r.results.status.exitCode
    }

    if ($A.Demo -and $A.Cli) {
        Write-VsatLog -Source 'demo' -Message 'Running against the built-in synthetic lab (no connectivity)'
        $ev = Get-VsatDemoEvidence
        $r = Complete-VsatRun -Evidence $ev -ProfileName $profileName -OutputDir $outDir -BaselineEvidence $baseline -Redact:$A.Redact
        Write-VsatSummary -Results $r.results -OutputDir $outDir -Files $r.files
        return $r.results.status.exitCode
    }

    if ($A.Cli) {
        $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
        $t = Get-VsatCliTargets -Servers $A.Server -NsxServers $A.NsxServer -Scope $scope -Credential $A.Credential -NsxCred $A.NsxCredential -Interactive:$interactive
        if ($t.declaredAbsent) { if (-not $scope) { $scope = [ordered]@{} }; $scope.nsxDeclaredAbsent = $true }
        $ev = New-VsatEvidence -Mode live -Scope $scope
        $cancelHandler = $null
        try {
            [Console]::TreatControlCAsInput = $false
            Invoke-VsatLiveCollection -Evidence $ev -Targets $t.targets
        }
        catch { Write-VsatLog -Level error -Message "Collection aborted: $($_.Exception.Message)" }
        $r = Complete-VsatRun -Evidence $ev -ProfileName $profileName -OutputDir $outDir -BaselineEvidence $baseline -Redact:$A.Redact
        Write-VsatSummary -Results $r.results -OutputDir $outDir -Files $r.files
        return $r.results.status.exitCode
    }

    return (Invoke-VsatUi -A $A -Scope $scope -OutputDir $outDir -ProfileName $profileName -Baseline $baseline)
}

function Invoke-VsatUi {
    param([hashtable]$A, $Scope, [string]$OutputDir, [string]$ProfileName, $Baseline)
    $state = [hashtable]::Synchronized(@{})
    $state.version = $script:VsatVersion
    $state.mode = $(if ($A.Demo) { 'demo' } else { 'live' })
    $state.profile = $ProfileName
    $state.phase = 'setup'
    $state.token = New-VsatToken
    $state.cookieToken = New-VsatToken
    $state.queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $state.shutdown = $false
    $state.endpoints = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $state.nsx = @{ discovery = @{ status = 'unknown'; evidence = @(); managersDiscovered = @() }; declaredAbsent = [bool](Get-VsatProp $Scope 'nsxDeclaredAbsent' $false); coverageHint = 'Add an NSX Manager or declare that NSX is not deployed.' }
    $state.result = $null
    $state.reportHtml = $null
    $state.progress = [hashtable]::Synchronized(@{})
    Initialize-VsatProgress -Shared $state.progress
    $state.doctor = @{ checks = @(Invoke-VsatDoctor -OutputDir $OutputDir -OfflineOnly:$A.Demo) }
    $css = Get-VsatEmbeddedText 'assets/ui/app.css'; $js = Get-VsatEmbeddedText 'assets/ui/app.js'
    $state.appHtml = New-VsatHtmlDocument -Template (Get-VsatEmbeddedText 'assets/ui/app.html') -Css $css -Js $js -Title 'VSAT' -ExtraCsp "; connect-src 'self'"
    $state.appCsp = "default-src 'none'; script-src 'sha256-$(Get-VsatSha256Base64 $js)'; style-src 'sha256-$(Get-VsatSha256Base64 $css)'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    $rcss = Get-VsatEmbeddedText 'assets/report/report.css'; $rjs = Get-VsatEmbeddedText 'assets/report/report.js'
    $state.reportCsp = "default-src 'none'; script-src 'sha256-$(Get-VsatSha256Base64 $rjs)'; style-src 'sha256-$(Get-VsatSha256Base64 $rcss)'; img-src data: blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    $targets = [ordered]@{}
    foreach ($s in @($A.Server)) { if ($s) { [void]$state.endpoints.Add(@{ id = "pending-$($state.endpoints.Count)"; type = 'vcenter'; address = $s; authenticated = $false; status = 'needs credentials'; error = $null }) } }
    foreach ($s in @($A.NsxServer)) { if ($s) { [void]$state.endpoints.Add(@{ id = "pending-$($state.endpoints.Count)"; type = 'nsx'; address = $s; authenticated = $false; status = 'needs credentials'; error = $null }) } }
    $server = Start-VsatServer -State $state -Port $A.Port
    $url = "http://127.0.0.1:$($state.port)/#token=$($state.token)"
    Write-Host ''
    Write-Host 'VSAT is running locally. Open this private link (do not share it):' -ForegroundColor Cyan
    Write-Host "  $url"
    Write-Host 'Press Ctrl+C or use Finish in the browser to stop.'
    Write-Host ''
    if (-not $A.NoBrowser) { Open-VsatBrowser $url }
    $evidenceScope = $Scope
    $lastEvidence = $null; $exit = 2
    try {
        while (-not $state.shutdown) {
            $cmd = $null
            if (-not $state.queue.TryDequeue([ref]$cmd)) { Start-Sleep -Milliseconds 150; continue }
            switch ($cmd.type) {
                'add-endpoint' {
                    $addr = $cmd.address
                    $existing = @($state.endpoints | Where-Object { $_.address -eq $addr -and $_.type -eq $cmd.endpointType })
                    foreach ($x in $existing) { $state.endpoints.Remove($x) }
                    $entry = @{ id = ('ep-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); type = $cmd.endpointType; address = $addr; authenticated = $false; status = 'connecting'; error = $null }
                    [void]$state.endpoints.Add($entry)
                    if ($state.mode -eq 'demo') {
                        $entry.authenticated = $true; $entry.status = 'demo (not contacted)'
                        $targets[$entry.id] = @{ type = $cmd.endpointType; address = $addr; credential = $cmd.credential; thumbprint = $cmd.thumbprint }
                        break
                    }
                    $probe = New-VsatEvidence -Mode live
                    $ep = Connect-VsatTarget -Evidence $probe -Target @{ type = $cmd.endpointType; address = $addr; credential = $cmd.credential; thumbprint = $cmd.thumbprint }
                    if ($ep.status -eq 'failed') { $entry.status = 'failed'; $entry.error = (Get-VsatFriendlyError $ep.errors[0]) }
                    else {
                        $entry.authenticated = $true; $entry.status = 'authenticated'
                        $targets[$entry.id] = @{ type = $cmd.endpointType; address = $addr; credential = $cmd.credential; thumbprint = $cmd.thumbprint }
                    }
                }
                'remove-endpoint' {
                    $x = @($state.endpoints | Where-Object { $_.id -eq $cmd.id })
                    foreach ($e in $x) { $state.endpoints.Remove($e); if ($targets.Contains($e.id)) { $targets.Remove($e.id) } }
                    Disconnect-VsatAll
                }
                'nsx' { $state.nsx.declaredAbsent = [bool]$cmd.declaredAbsent }
                'discover' {
                    $state.phase = 'discovering'
                    try {
                        if ($state.mode -eq 'demo') { $dev = Get-VsatDemoEvidence; $state.nsx.discovery = Update-VsatNsxDiscovery -Evidence $dev }
                        else {
                            $dev = New-VsatEvidence -Mode live
                            foreach ($t in @($targets.Values | Where-Object { $_.type -eq 'vcenter' -or $_.type -eq 'esxi' })) {
                                $ep = Connect-VsatTarget -Evidence $dev -Target $t
                                $s = $script:VsatSessions["$($t.type)|$($t.address)"]
                                if ($s -and $s.connected) {
                                    $about = $s.session.ExtensionData.Content.About
                                    if ($about.ApiType -eq 'VirtualCenter') {
                                        $root = Add-VsatAsset -Evidence $dev -Id "$($ep.id):root" -Type vcenter -Name $t.address -Endpoint $ep.id
                                        Invoke-VsatFact $root 'extensions' { $em = Get-View -Server $s.session -Id $s.session.ExtensionData.Content.ExtensionManager -Property ExtensionList; @($em.ExtensionList | ForEach-Object { [ordered]@{ key = $_.Key; version = $_.Version; urls = @($_.Server | ForEach-Object { $_.Url }) } }) }
                                    }
                                }
                            }
                            $state.nsx.discovery = Update-VsatNsxDiscovery -Evidence $dev
                        }
                    }
                    catch { Write-VsatLog -Level warn -Source 'discovery' -Message "Discovery failed: $($_.Exception.Message)" }
                    $state.nsx.coverageHint = switch ($state.nsx.discovery.status) { 'detected' { 'NSX detected: add every NSX Manager, otherwise the report will be INCOMPLETE: NSX NOT ASSESSED.' } 'not-detected' { 'No NSX found in vCenter. You may declare NSX not deployed; the report records the evidence.' } default { 'NSX presence could not be determined; add an NSX Manager or the report will show NSX coverage UNKNOWN/REVIEW.' } }
                    $state.phase = 'ready'
                }
                'run' {
                    $state.phase = 'running'
                    $state.progress.cancel = $false
                    $state.profile = $cmd.profile
                    try {
                        $sc = if ($evidenceScope) { $evidenceScope } else { [ordered]@{} }
                        $sc.nsxDeclaredAbsent = [bool]$state.nsx.declaredAbsent
                        if ($state.mode -eq 'demo') {
                            $ev = Get-VsatDemoEvidence
                            $ev.scope.nsxDeclaredAbsent = $sc.nsxDeclaredAbsent
                            $state.progress.totalSteps = 3
                            foreach ($i in 1..3) { Update-VsatProgress -Phase 'collecting' -Message "Loading synthetic lab ($i/3)" -Step; Start-Sleep -Milliseconds 300 }
                        }
                        else {
                            $ev = New-VsatEvidence -Mode live -Scope $sc
                            Invoke-VsatLiveCollection -Evidence $ev -Targets @($targets.Values)
                        }
                        $r = Complete-VsatRun -Evidence $ev -ProfileName $cmd.profile -OutputDir $OutputDir -BaselineEvidence $Baseline -Redact:$A.Redact
                        $state.reportHtml = [System.IO.File]::ReadAllText((Join-Path $OutputDir 'report.html'))
                        $state.result = @{ status = $r.results.status; summary = $r.results.summary; outputDir = $OutputDir; reportUrl = '/report'; files = @($r.files) }
                        $state.phase = $(if ($r.results.status.overall -eq 'canceled') { 'canceled' } else { 'done' })
                        $exit = $r.results.status.exitCode
                        Write-VsatSummary -Results $r.results -OutputDir $OutputDir -Files $r.files
                    }
                    catch {
                        Write-VsatLog -Level error -Message "Assessment failed: $($_.Exception.Message)"
                        $state.phase = 'failed'; $exit = 3
                    }
                }
                'shutdown' { $state.shutdown = $true }
            }
        }
    }
    finally {
        $state.shutdown = $true
        Disconnect-VsatAll
        Stop-VsatServer $server
        foreach ($k in @($targets.Keys)) { $targets[$k].credential = $null }
    }
    return $exit
}

function Get-VsatFriendlyError {
    param([string]$Message)
    if ($Message -match '(?i)incorrect user name or password|Cannot complete login|401|invalid credentials') { return 'The user name or password was rejected.' }
    if ($Message -match '(?i)certificate|SSL|TLS|trust') { return "The server certificate is not trusted by this machine. Import the issuing CA, or approve the exact fingerprint (see -Doctor output). Details: $Message" }
    if ($Message -match '(?i)timed out|timeout|No such host|could not resolve|refused|unreachable') { return "The server could not be reached on port 443. Details: $Message" }
    if ($Message -match '(?i)PowerCLI') { return $Message }
    return $Message
}

#endregion Orchestration
