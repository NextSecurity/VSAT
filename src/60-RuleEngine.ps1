#region Rule engine
# Rules are data (rules/*.json, embedded at build time). Each canonical check runs once
# per applicable asset and may map to several framework controls. Only facts with
# status ok/absent can produce PASS/FAIL; anything else becomes UNKNOWN or ERROR.

$script:VsatRuleCache = $null
$script:VsatAdvisoryCache = $null

function Get-VsatRulePack {
    if ($script:VsatRuleCache) { return $script:VsatRuleCache }
    $rules = [System.Collections.Generic.List[object]]::new()
    $meta = $null
    foreach ($name in (Get-VsatEmbeddedNames 'rules/')) {
        $pack = ConvertFrom-VsatJson (Get-VsatEmbeddedText $name)
        if ($name -eq 'rules/pack.json') { $meta = $pack; continue }
        foreach ($r in @($pack.rules)) { $rules.Add($r) }
    }
    $ids = @{}
    $wps = @{}; foreach ($w in @($meta.workPackages)) { $wps[$w.id] = $w }
    foreach ($r in $rules) {
        if ($ids.ContainsKey($r.id)) { throw "Duplicate rule id $($r.id)" }
        $ids[$r.id] = $true
        # Expand compact framework references into explicit, honestly-labelled mappings.
        $fw = [System.Collections.Generic.List[object]]::new()
        if ($r.Contains('cis')) { $fw.Add([ordered]@{ framework = 'CIS VMware ESXi Benchmark'; edition = 'VSAT 1.x legacy mapping (ESXi 7.0 edition not recorded)'; control = [string]$r.cis; mappingStatus = 'unverified' }) }
        if ($r.Contains('scg')) { $fw.Add([ordered]@{ framework = 'Broadcom vSphere/NSX Security Configuration Guide'; edition = 'edition to be confirmed'; control = [string]$r.scg; mappingStatus = 'unverified' }) }
        if ($r.Contains('vsat') -or $fw.Count -eq 0) { $fw.Add([ordered]@{ framework = 'VSAT'; edition = $meta.version; control = $r.id; mappingStatus = 'verified' }) }
        $r.frameworks = @($fw)
        $m = if ($r.Contains('mitigation')) { $r.mitigation } else { [ordered]@{} }
        $wp = $wps[[string](Get-VsatProp $m 'workPackage' '')]
        if ($wp) {
            foreach ($k in 'validation', 'rollback', 'impact', 'maintenanceWindow') { if (-not $m.Contains($k)) { $m[$k] = $wp[$k] } }
        }
        $r.mitigation = $m
    }
    $script:VsatRuleCache = [ordered]@{ version = $meta.version; schemaVersion = $meta.schemaVersion; rules = $rules.ToArray(); meta = $meta }
    return $script:VsatRuleCache
}

function Get-VsatRulePackMeta { return (Get-VsatRulePack).meta }

function Get-VsatAdvisoryData {
    if ($script:VsatAdvisoryCache) { return $script:VsatAdvisoryCache }
    $script:VsatAdvisoryCache = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'data/advisories.json')
    return $script:VsatAdvisoryCache
}

function Resolve-VsatFactValue {
    # Returns @{ state = ok|absent|missing-key|denied|error|unsupported|no-fact; value; error }
    param($Asset, [string]$Fact, [string]$Key, [string]$Path)
    if ($Fact -eq 'props') {
        $v = if ($Path) { Get-VsatProp $Asset.props $Path } else { $Asset.props }
        return @{ state = $(if ($null -eq $v) { 'missing-key' } else { 'ok' }); value = $v }
    }
    if (-not $Asset.facts.Contains($Fact)) { return @{ state = 'no-fact'; value = $null; error = "Fact '$Fact' was not collected" } }
    $f = $Asset.facts[$Fact]
    $st = [string]$f.status
    if ($st -ne 'ok' -and $st -ne 'absent') { return @{ state = $st; value = $null; error = (Get-VsatProp $f 'error') } }
    if ($st -eq 'absent') { return @{ state = 'absent'; value = $null } }
    $v = $f.value
    if ($Key) {
        if ($v -is [System.Collections.IDictionary]) {
            $hit = $null
            foreach ($k in $v.Keys) { if ([string]$k -eq $Key) { $hit = $k; break } }
            if ($null -eq $hit) { foreach ($k in $v.Keys) { if ([string]::Equals([string]$k, $Key, 'OrdinalIgnoreCase')) { $hit = $k; break } } }
            if ($null -eq $hit) { return @{ state = 'missing-key'; value = $null } }
            $v = $v[$hit]
        }
        else { return @{ state = 'missing-key'; value = $null } }
    }
    if ($Path) {
        $v = Get-VsatProp $v $Path
        if ($null -eq $v) { return @{ state = 'missing-key'; value = $null } }
    }
    return @{ state = 'ok'; value = $v }
}

function ConvertTo-VsatComparable {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $s = [string]$Value
    if ($s -match '^(?i:true|false)$') { return [bool]::Parse($s) }
    $d = 0.0
    if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    return $s
}

function Test-VsatOperator {
    param($Actual, [string]$Op, $Expected)
    $a = ConvertTo-VsatComparable $Actual
    switch ($Op) {
        'eq' { $e = ConvertTo-VsatComparable $Expected; if ($a -is [string] -or $e -is [string]) { return [string]::Equals([string]$a, [string]$e, 'OrdinalIgnoreCase') }; return ($a -eq $e) }
        'ne' { return -not (Test-VsatOperator $Actual 'eq' $Expected) }
        'le' { if ($a -isnot [double]) { return $false }; return ($a -le [double]$Expected) }
        'ge' { if ($a -isnot [double]) { return $false }; return ($a -ge [double]$Expected) }
        'lt' { if ($a -isnot [double]) { return $false }; return ($a -lt [double]$Expected) }
        'gt' { if ($a -isnot [double]) { return $false }; return ($a -gt [double]$Expected) }
        'range' { if ($a -isnot [double]) { return $false }; return ($a -ge [double]$Expected[0] -and $a -le [double]$Expected[1]) }
        'in' { foreach ($e in @($Expected)) { if (Test-VsatOperator $Actual 'eq' $e) { return $true } }; return $false }
        'notin' { return -not (Test-VsatOperator $Actual 'in' $Expected) }
        'empty' { return ($null -eq $Actual -or [string]$Actual -eq '' -or ($Actual -is [array] -and $Actual.Count -eq 0)) }
        'notempty' { return -not (Test-VsatOperator $Actual 'empty' $null) }
        'match' { return ((Format-VsatValue $Actual) -match [string]$Expected) }
        'notmatch' { return -not ((Format-VsatValue $Actual) -match [string]$Expected) }
        default { throw "Unknown operator $Op" }
    }
}

function Format-VsatValue {
    param($Value)
    if ($null -eq $Value) { return '(not set)' }
    if ($Value -is [System.Collections.IDictionary]) { return ((@($Value.Keys | ForEach-Object { "$_=$(Format-VsatValue $Value[$_])" })) -join ', ') }
    if ($Value -is [array]) { if ($Value.Count -eq 0) { return '(none)' }; return ((@($Value | ForEach-Object { Format-VsatValue $_ })) -join '; ') }
    return [string]$Value
}

function Format-VsatExpectation {
    param([string]$Op, $Expected)
    switch ($Op) {
        'eq' { return "= $(Format-VsatValue $Expected)" }
        'ne' { return "!= $(Format-VsatValue $Expected)" }
        'le' { return "<= $Expected" }
        'ge' { return ">= $Expected" }
        'lt' { return "< $Expected" }
        'gt' { return "> $Expected" }
        'range' { return "between $($Expected[0]) and $($Expected[1])" }
        'in' { return "one of: $(Format-VsatValue $Expected)" }
        'notin' { return "not one of: $(Format-VsatValue $Expected)" }
        'empty' { return 'empty / not set' }
        'notempty' { return 'configured (non-empty)' }
        'match' { return "matches /$Expected/" }
        'notmatch' { return "does not match /$Expected/" }
    }
}

function Get-VsatRuleCheck {
    # Applies profile overrides on top of the base check definition.
    param($Rule, [string]$ProfileName)
    $check = [ordered]@{}
    foreach ($k in $Rule.check.Keys) { $check[$k] = $Rule.check[$k] }
    $prof = Get-VsatProp $Rule "profiles.$ProfileName"
    if ($prof) { foreach ($k in $prof.Keys) { $check[$k] = $prof[$k] } }
    return $check
}

function Test-VsatApplies {
    # Returns $null when applicable, otherwise a reason string (NOT_APPLICABLE).
    param($Rule, $Asset, $Context)
    $ap = Get-VsatProp $Rule 'applies'
    if (-not $ap) { return $null }
    $minV = Get-VsatProp $ap 'minVersion'; $maxV = Get-VsatProp $ap 'maxVersion'
    $ver = if ($Asset.version) { $Asset.version } else { $null }
    if (($minV -or $maxV) -and -not $ver) { return $null }  # version unknown: evaluate, facts decide
    if ($minV -and (Compare-VsatVersion $ver $minV) -lt 0) { return "Requires version $minV or later (observed $ver)" }
    if ($maxV -and (Compare-VsatVersion $ver $maxV) -gt 0) { return "Applies up to version $maxV (observed $ver)" }
    foreach ($c in @(Get-VsatProp $ap 'props' @())) {
        $v = Get-VsatProp $Asset.props $c.path
        if (-not (Test-VsatOperator $v $c.op (Get-VsatProp $c 'value'))) { return "Not applicable: $($c.path) is $(Format-VsatValue $v)" }
    }
    return $null
}

function New-VsatFinding {
    param($Rule, $Asset, [string]$Result, [string]$Observed, [string]$Expected, [string]$Note, [string[]]$Facts = @(), [string]$Confidence = 'observed', $Severity)
    $sev = if ($Severity) { $Severity } else { $Rule.severity }
    $f = [ordered]@{
        id = $null
        key = "$($Rule.id)|$($Asset.id)"
        ruleId = $Rule.id; ruleVersion = [int](Get-VsatProp $Rule 'version' 1)
        title = $Rule.title; domain = $Rule.domain
        assetId = $Asset.id; assetName = $Asset.name; assetType = $Asset.type
        result = $Result; severity = $sev
        priority = $null
        rationale = $(if ($Note) { "$($Rule.rationale) $Note".Trim() } else { $Rule.rationale })
        observed = $Observed; expected = $Expected
        evidence = @($Facts | ForEach-Object {
                $fs = if ($_ -eq 'props') { 'ok' } elseif ($Asset.facts.Contains($_)) { $Asset.facts[$_].status } else { 'not-collected' }
                [ordered]@{ fact = $_; status = $fs; endpoint = $Asset.endpoint; observedUtc = $Asset.observedUtc }
            })
        frameworks = @(Get-VsatProp $Rule 'frameworks' @())
        mitigation = (Get-VsatProp $Rule 'mitigation' ([ordered]@{}))
        limitations = (Get-VsatProp $Rule 'limitations' '')
        confidence = $Confidence
        exception = $null
    }
    return $f
}

function Invoke-VsatRuleOnAsset {
    param($Rule, $Asset, $Context)
    $na = Test-VsatApplies -Rule $Rule -Asset $Asset -Context $Context
    if ($na) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'NOT_APPLICABLE' -Observed $na -Expected '' ) }
    $check = Get-VsatRuleCheck -Rule $Rule -ProfileName $Context.profile
    try {
        switch ($check.type) {
            'setting' { return (Invoke-VsatSettingCheck -Rule $Rule -Asset $Asset -Check $check) }
            'service' { return (Invoke-VsatServiceCheck -Rule $Rule -Asset $Asset -Check $check) }
            'manual' {
                $obs = ''
                if ($check.Contains('fact')) {
                    $r = Resolve-VsatFactValue -Asset $Asset -Fact $check.fact -Key (Get-VsatProp $check 'key') -Path (Get-VsatProp $check 'path')
                    $obs = if ($r.state -eq 'ok') { Format-VsatValue $r.value } else { "evidence: $($r.state)" }
                }
                return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'MANUAL' -Observed $obs -Expected (Get-VsatProp $check 'guidance' 'Operator review required') -Facts @(Get-VsatProp $check 'fact' @()))
            }
            'script' {
                $fn = "Invoke-VsatCheck$($check.name)"
                if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { throw "Evaluator $fn not found" }
                $out = & $fn -Rule $Rule -Asset $Asset -Check $check -Context $Context
                return $out
            }
            default { throw "Unknown check type '$($check.type)'" }
        }
    }
    catch {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'ERROR' -Observed ("Evaluator error: " + (Protect-VsatText $_.Exception.Message)) -Expected '')
    }
}

function Get-VsatEvidenceGapResult {
    param([string]$State)
    switch ($State) {
        'denied' { return 'UNKNOWN' }
        'unsupported' { return 'UNKNOWN' }
        'no-fact' { return 'UNKNOWN' }
        'error' { return 'ERROR' }
        default { return 'UNKNOWN' }
    }
}

function Get-VsatGapText {
    param($Resolved, [string]$Fact)
    switch ($Resolved.state) {
        'denied' { return "Cannot read $Fact (permission denied); this check is incomplete." }
        'unsupported' { return "$Fact is not exposed by this product version or API." }
        'no-fact' { return "$Fact was not collected (collector skipped or failed)." }
        'error' { return "Collection of $Fact failed: $($Resolved.error)" }
        default { return "$Fact unavailable ($($Resolved.state))." }
    }
}

function Invoke-VsatSettingCheck {
    param($Rule, $Asset, $Check)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact $Check.fact -Key (Get-VsatProp $Check 'key') -Path (Get-VsatProp $Check 'path')
    $label = if ($Check.Contains('key')) { $Check.key } elseif ($Check.Contains('path')) { "$($Check.fact).$($Check.path)" } else { $Check.fact }
    $expText = "$label " + (Format-VsatExpectation $Check.op (Get-VsatProp $Check 'value'))
    $conf = 'observed'
    $value = $r.value
    if ($r.state -eq 'missing-key' -or $r.state -eq 'absent') {
        $absent = Get-VsatProp $Check 'absent' 'fail'
        switch ($absent) {
            'default' { $value = $Check.default; $conf = 'inferred' }
            'pass' { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'PASS' -Observed "$label not set" -Expected $expText -Facts @($Check.fact) -Confidence inferred) }
            'na' { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'NOT_APPLICABLE' -Observed "$label not present" -Expected $expText -Facts @($Check.fact)) }
            'unknown' { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'UNKNOWN' -Observed "$label not reported" -Expected $expText -Facts @($Check.fact)) }
            default { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'FAIL' -Observed "$label not set" -Expected $expText -Facts @($Check.fact)) }
        }
    }
    elseif ($r.state -ne 'ok') {
        return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r $Check.fact) -Expected $expText -Facts @($Check.fact))
    }
    $ok = Test-VsatOperator $value $Check.op (Get-VsatProp $Check 'value')
    $obs = "$label = $(Format-VsatValue $value)"
    if ($conf -eq 'inferred') { $obs += ' (not set; product default assumed)' }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($ok) { 'PASS' } else { 'FAIL' }) -Observed $obs -Expected $expText -Facts @($Check.fact) -Confidence $conf)
}

function Invoke-VsatServiceCheck {
    param($Rule, $Asset, $Check)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'services'
    $exp = "running=$($Check.running), policy=$($Check.policy)"
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'services') -Expected $exp -Facts @('services')) }
    $svc = @($r.value | Where-Object { $_.key -eq $Check.key }) | Select-Object -First 1
    if (-not $svc) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result 'NOT_APPLICABLE' -Observed "Service $($Check.key) not present on this host" -Expected $exp -Facts @('services')) }
    $ok = ([bool]$svc.running -eq [bool]$Check.running) -and ([string]$svc.policy -eq [string]$Check.policy -or ($Check.policy -eq 'off' -and [string]$svc.policy -eq 'off'))
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($ok) { 'PASS' } else { 'FAIL' }) -Observed "running=$([bool]$svc.running), policy=$($svc.policy)" -Expected $exp -Facts @('services'))
}

function Test-VsatAssetExcluded {
    param($Asset, $Scope)
    foreach ($ex in @(Get-VsatProp $Scope 'exclusions' @())) {
        $pat = [string](Get-VsatProp $ex 'pattern')
        if ($pat -match '^(\w[\w-]*):(.*)$') {
            if ($Asset.type -like $Matches[1] -and ($Asset.name -like $Matches[2] -or $Asset.id -like $Matches[2])) { return $true }
        }
        elseif ($Asset.name -like $pat -or $Asset.id -like $pat) { return $true }
    }
    return $false
}

function Invoke-VsatRules {
    param([Parameter(Mandatory)]$Evidence, [string]$ProfileName = 'standard')
    $pack = Get-VsatRulePack
    $ctx = New-VsatRuleContext -Evidence $Evidence -ProfileName $ProfileName
    $findings = [System.Collections.Generic.List[object]]::new()
    $byType = @{}
    foreach ($a in $Evidence.assets) {
        if (-not $byType.ContainsKey($a.type)) { $byType[$a.type] = [System.Collections.Generic.List[object]]::new() }
        $byType[$a.type].Add($a)
    }
    $excluded = 0
    foreach ($rule in $pack.rules) {
        $profiles = @(Get-VsatProp $rule 'profilesEnabled' @('standard', 'strict'))
        if ($profiles -notcontains $ProfileName) { continue }
        foreach ($t in @($rule.assetType)) {
            if (-not $byType.ContainsKey($t)) { continue }
            foreach ($a in $byType[$t]) {
                if (Test-VsatAssetExcluded -Asset $a -Scope $Evidence.scope) { $excluded++; continue }
                foreach ($f in @(Invoke-VsatRuleOnAsset -Rule $rule -Asset $a -Context $ctx)) { if ($f) { $findings.Add($f) } }
            }
        }
    }
    $i = 0
    foreach ($f in $findings) { $i++; $f.id = 'F-{0:d6}' -f $i }
    return [ordered]@{ findings = $findings.ToArray(); rules = $pack.rules; rulePackVersion = $pack.version; excluded = $excluded; context = $ctx }
}

function New-VsatRuleContext {
    param($Evidence, [string]$ProfileName)
    $ctx = [ordered]@{ profile = $ProfileName; evidence = $Evidence; scope = $Evidence.scope; now = [DateTime]::UtcNow }
    # Indexes used by cross-asset evaluators.
    $ctx.assets = @{}; foreach ($a in $Evidence.assets) { $ctx.assets[$a.id] = $a }
    $ctx.out = @{}; $ctx.in = @{}
    foreach ($r in $Evidence.relationships) {
        if (-not $ctx.out.ContainsKey($r.source)) { $ctx.out[$r.source] = [System.Collections.Generic.List[object]]::new() }
        if (-not $ctx.in.ContainsKey($r.target)) { $ctx.in[$r.target] = [System.Collections.Generic.List[object]]::new() }
        $ctx.out[$r.source].Add($r); $ctx.in[$r.target].Add($r)
    }
    $ctx.nsxState = (Get-VsatNsxCoverage -Evidence $Evidence).state
    return $ctx
}

#endregion Rule engine
