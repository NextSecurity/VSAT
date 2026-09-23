#region Platform evaluators (Hyper-V, KVM, shared host checks)

function Get-VsatOsLifecycleData {
    if ($script:VsatOsLifecycle) { return $script:VsatOsLifecycle }
    if ((Get-VsatEmbeddedNames 'data/') -contains 'data/os-lifecycle.json') { $script:VsatOsLifecycle = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'data/os-lifecycle.json') }
    else { $script:VsatOsLifecycle = [ordered]@{ lifecycle = @() } }
    return $script:VsatOsLifecycle
}

function Invoke-VsatCheckPatchAge {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact $Check.fact
    $max = [int]$Check.maxDays
    $exp = "Updates installed within the last $max days"
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r $Check.fact) -Expected $exp -Facts @($Check.fact)) }
    $age = Get-VsatProp $r.value 'ageDays'
    if ($null -eq $age) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed 'Update age not available' -Expected $exp -Facts @($Check.fact)) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ([int]$age -le $max) { 'PASS' } else { 'FAIL' }) -Observed "Last update $age day(s) ago$(if ($r.value.lastId) { " ($($r.value.lastId))" })" -Expected $exp -Facts @($Check.fact) -Confidence inferred)
}

function Invoke-VsatCheckOsLifecycle {
    param($Rule, $Asset, $Check, $Context)
    $data = Get-VsatOsLifecycleData
    if ($Asset.type -eq 'hyperv-host') { $product = 'windows-server'; $branch = [string]$Asset.build }
    else {
        $product = [string]$Asset.props.osId
        $v = [string]$Asset.version
        $branch = if ($product -in @('ubuntu')) { $v } else { ($v -split '\.')[0] }
    }
    $row = @($data.lifecycle | Where-Object { $_.product -eq $product -and [string]$_.branch -eq $branch }) | Select-Object -First 1
    $exp = 'Operating system release within vendor security support'
    if (-not $row) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result UNKNOWN -Observed "${product} ${branch}: no lifecycle data in snapshot" -Expected $exp -Note 'Absence of lifecycle data is not evidence of support.') }
    $eos = Get-VsatProp $row 'endOfSupport'
    if (-not $eos) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result MANUAL -Observed "$($row.name): end-of-support date not verified in snapshot" -Expected $exp) }
    $d = [DateTime]::Parse($eos, [Globalization.CultureInfo]::InvariantCulture)
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($d -lt $Context.now) { 'FAIL' } else { 'PASS' }) -Observed "$($row.name) security support ends $eos" -Expected $exp)
}

function Invoke-VsatCheckHvDeviceGuard {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'deviceGuard'
    $svc = [int]$Check.service
    $label = if ($svc -eq 1) { 'Credential Guard' } else { 'HVCI' }
    $exp = "$label running"
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'deviceGuard') -Expected $exp -Facts @('deviceGuard')) }
    $running = @($r.value.servicesRunning) -contains $svc
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($running) { 'PASS' } else { 'FAIL' }) -Observed "VBS status $($r.value.vbsStatus); services running: $(Format-VsatValue $r.value.servicesRunning)" -Expected $exp -Facts @('deviceGuard'))
}

function Invoke-VsatCheckHvFirewall {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'firewall'
    $exp = 'Domain, Private and Public profiles enabled with inbound Block'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'firewall') -Expected $exp -Facts @('firewall')) }
    $bad = @(@($r.value) | Where-Object { [string]$_.enabled -ne 'True' -or [string]$_.defaultInbound -eq 'Allow' } | ForEach-Object { "$($_.name): enabled=$($_.enabled) inbound=$($_.defaultInbound)" })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { $bad -join '; ' } else { 'All profiles enabled; inbound not Allow' }) -Expected $exp -Facts @('firewall'))
}

function Invoke-VsatCheckHvMigration {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'vmhost'
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'vmhost') -Expected 'Live migration secured' -Facts @('vmhost')) }
    if (-not $r.value.migrationEnabled) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Live migration disabled' -Expected '' -Facts @('vmhost')) }
    if ($Check.mode -eq 'auth') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($r.value.migrationAuth -eq 'Kerberos') { 'PASS' } else { 'FAIL' }) -Observed "Authentication: $($r.value.migrationAuth)" -Expected 'Kerberos' -Facts @('vmhost')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($r.value.anyNetworkForMigration) { 'FAIL' } else { 'PASS' }) -Observed "UseAnyNetworkForMigration = $($r.value.anyNetworkForMigration)" -Expected 'Dedicated migration networks only' -Facts @('vmhost'))
}

function Invoke-VsatCheckHvReplica {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'replica'
    $exp = 'Replica disabled, or certificate-based (HTTPS) authentication only'
    if ($r.state -eq 'unsupported') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Hyper-V Replica not available' -Expected $exp -Facts @('replica')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'replica') -Expected $exp -Facts @('replica')) }
    if (-not $r.value.enabled) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'Replication server disabled' -Expected $exp -Facts @('replica')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($r.value.auth -eq 'Certificate') { 'PASS' } else { 'FAIL' }) -Observed "Allowed authentication: $($r.value.auth)" -Expected $exp -Facts @('replica'))
}

function Invoke-VsatCheckHvAdapters {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'adapters'
    $field = [string]$Check.field; $badVals = @($Check.bad)
    $exp = "No adapter with $field in $($badVals -join '/')"
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No network adapters' -Expected $exp -Facts @('adapters')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'adapters') -Expected $exp -Facts @('adapters')) }
    $ads = @($r.value)
    if ($ads.Count -eq 0) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed 'No network adapters' -Expected $exp -Facts @('adapters')) }
    $bad = @($ads | Where-Object { $badVals -contains [string]$_[$field] } | ForEach-Object { "$($_.name) ($($_.switch)): $field=$($_[$field])" })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($bad.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($bad.Count) { $bad -join '; ' } else { "$($ads.Count) adapter(s) compliant" }) -Expected $exp -Facts @('adapters'))
}

function Invoke-VsatCheckHvIntegration {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'integration'
    $exp = "$($Check.service) disabled"
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'integration') -Expected $exp -Facts @('integration')) }
    $svc = @(@($r.value) | Where-Object { $_.name -eq $Check.service })[0]
    if (-not $svc) { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result NOT_APPLICABLE -Observed "$($Check.service) not present" -Expected $exp -Facts @('integration')) }
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($svc.enabled) { 'FAIL' } else { 'PASS' }) -Observed "enabled=$($svc.enabled)" -Expected $exp -Facts @('integration'))
}

function Invoke-VsatCheckHvCheckpointAge {
    param($Rule, $Asset, $Check, $Context)
    $fact = if ($Check.Contains('fact')) { $Check.fact } else { 'checkpoints' }
    $r = Resolve-VsatFactValue -Asset $Asset -Fact $fact
    $max = [int]$Check.maxDays
    $exp = "No checkpoints/snapshots older than $max days"
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'None' -Expected $exp -Facts @($fact)) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r $fact) -Expected $exp -Facts @($fact)) }
    $old = @(@($r.value) | Where-Object { $null -ne $_.ageDays -and [int]$_.ageDays -gt $max })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($old.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($old.Count) { ($old | ForEach-Object { "'$($_.name)' $($_.ageDays)d" }) -join '; ' } else { "$(@($r.value).Count) item(s), none older than $max days" }) -Expected $exp -Facts @($fact) -Note 'A checkpoint or snapshot is not a backup.')
}

function Invoke-VsatCheckHvDevices {
    param($Rule, $Asset, $Check, $Context)
    $r = Resolve-VsatFactValue -Asset $Asset -Fact 'devices'
    $types = @($Check.types)
    $exp = "No attached $($types -join '/') devices"
    if ($r.state -eq 'absent') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result PASS -Observed 'None' -Expected $exp -Facts @('devices')) }
    if ($r.state -ne 'ok') { return (New-VsatFinding -Rule $Rule -Asset $Asset -Result (Get-VsatEvidenceGapResult $r.state) -Observed (Get-VsatGapText $r 'devices') -Expected $exp -Facts @('devices')) }
    $hits = @(@($r.value) | Where-Object { $types -contains $_.type -and $_.path })
    return (New-VsatFinding -Rule $Rule -Asset $Asset -Result $(if ($hits.Count) { 'FAIL' } else { 'PASS' }) -Observed $(if ($hits.Count) { ($hits | ForEach-Object { "$($_.type): $($_.path)" }) -join '; ' } else { 'None' }) -Expected $exp -Facts @('devices'))
}

#endregion Platform evaluators
