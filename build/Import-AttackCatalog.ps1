<#
.SYNOPSIS
    Maintainer-side: generates data/attack/attack-catalog.json from MITRE's official releases.
.DESCRIPTION
    VSAT never trusts ATT&CK or ATLAS IDs from memory. This script reads the pinned MITRE ATT&CK
    Enterprise STIX 2.1 bundle and the pinned MITRE ATLAS data release, verifies both files against
    the SHA-256 pins below, and writes a small catalog (IDs, names, tactics, revoked/deprecated
    flags and ATT&CK "mitigates" links; no descriptions). tests/Attack.Tests.ps1 fails the build if
    any rule, edge mapping or layer references an ID that is missing, revoked or deprecated here.

    The two input files are downloaded once by the maintainer. They are never downloaded at runtime
    and are not committed (only the generated catalog is):
        curl -LO https://github.com/mitre-attack/attack-stix-data/releases/download/v19.2/enterprise-attack.json
        curl -LO https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/ATLAS-2026.09.yaml

    To move to a newer release: download it, update the pins here AND the "attack" block of
    build/runtime.lock.json, re-run this script, re-check every mapping the tests flag, and record
    the reason in CHANGELOG.md.
.EXAMPLE
    pwsh -NoProfile -File build/Import-AttackCatalog.ps1 -AttackStix ./enterprise-attack.json -AtlasYaml ./ATLAS-2026.09.yaml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AttackStix,
    [Parameter(Mandatory)][string]$AtlasYaml,
    [string]$Out
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $root 'data/attack/attack-catalog.json' }

# Pinned sources. Keep in sync with build/runtime.lock.json ("attack"); the tests compare them.
$pins = [ordered]@{
    attack = [ordered]@{
        version = '19.2'
        url     = 'https://github.com/mitre-attack/attack-stix-data/releases/download/v19.2/enterprise-attack.json'
        sha256  = 'dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4'
    }
    atlas  = [ordered]@{
        version = '2026.09'
        url     = 'https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/ATLAS-2026.09.yaml'
        sha256  = '935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688'
    }
}

function Get-Sorted($keys) { $a = [string[]]@($keys | Where-Object { $_ } | Select-Object -Unique); [Array]::Sort($a, [StringComparer]::Ordinal); return , $a }
function Get-FileSha256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
foreach ($k in 'attack', 'atlas') {
    $p = if ($k -eq 'attack') { $AttackStix } else { $AtlasYaml }
    $h = Get-FileSha256 $p
    if ($h -ne $pins[$k].sha256) { throw "$k input $p has SHA-256 $h, expected the pinned $($pins[$k].sha256). Update the pins deliberately (see .DESCRIPTION)." }
}
$lock = Get-Content -Raw -LiteralPath (Join-Path $root 'build/runtime.lock.json') | ConvertFrom-Json
foreach ($k in 'attack', 'atlas') {
    $l = $lock.attack.$k
    if (-not $l -or $l.version -ne $pins[$k].version -or $l.url -ne $pins[$k].url -or $l.sha256 -ne $pins[$k].sha256) { throw "build/runtime.lock.json attack.$k does not match the pins in this script." }
}

# ---------------------------------------------------------------- ATT&CK Enterprise (STIX 2.1)
$bundle = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $AttackStix)) | ConvertFrom-Json -AsHashtable
$collection = @($bundle.objects | Where-Object { $_.type -eq 'x-mitre-collection' })[0]
if (-not $collection -or [string]$collection.x_mitre_version -ne $pins.attack.version) { throw "STIX bundle collection version '$($collection.x_mitre_version)' is not the pinned $($pins.attack.version)." }
function Get-AttackId($o) {
    foreach ($r in @($o.external_references)) { if ($r -and $r.source_name -eq 'mitre-attack' -and $r.external_id) { return [string]$r.external_id } }
    return $null
}
$byStix = @{}
foreach ($o in $bundle.objects) { if ($o.id) { $byStix[$o.id] = $o } }
$active = { param($o) -not [bool]$o.revoked -and -not [bool]$o.x_mitre_deprecated }
$revokedBy = @{}
$mitLinks = @{}
foreach ($o in $bundle.objects) {
    if ($o.type -ne 'relationship' -or -not (& $active $o)) { continue }
    $s = $byStix[$o.source_ref]; $t = $byStix[$o.target_ref]
    if (-not $s -or -not $t) { continue }
    if ($o.relationship_type -eq 'revoked-by') { $revokedBy[$o.source_ref] = Get-AttackId $t }
    elseif ($o.relationship_type -eq 'mitigates' -and $s.type -eq 'course-of-action' -and (& $active $s) -and (& $active $t)) {
        $mid = Get-AttackId $s; $tid = Get-AttackId $t
        if ($mid -and $tid) { if (-not $mitLinks.ContainsKey($mid)) { $mitLinks[$mid] = [System.Collections.Generic.HashSet[string]]::new() }; [void]$mitLinks[$mid].Add($tid) }
    }
}
$techniques = @{}
$mitigations = @{}
foreach ($o in $bundle.objects) {
    if ($o.type -notin @('attack-pattern', 'course-of-action')) { continue }
    $id = Get-AttackId $o
    if (-not $id) { continue }
    $entry = [ordered]@{ name = [string]$o.name }
    if ($o.type -eq 'attack-pattern') {
        $entry.domain = 'enterprise-attack'
        $entry.tactics = [string[]](Get-Sorted @($o.kill_chain_phases | Where-Object { $_ -and $_.kill_chain_name -eq 'mitre-attack' } | ForEach-Object { [string]$_.phase_name }))
    }
    elseif ($id -notmatch '^M\d{4}$') { continue }   # legacy pre-2018 mitigations reuse technique IDs (T1078 etc.); all deprecated
    else { $entry.domain = 'enterprise-attack' }
    $entry.revoked = [bool]$o.revoked
    $entry.deprecated = [bool]$o.x_mitre_deprecated
    if ($entry.revoked -and $revokedBy.ContainsKey($o.id) -and $revokedBy[$o.id]) { $entry.revokedBy = $revokedBy[$o.id] }
    if ($o.type -eq 'course-of-action') { $entry.techniques = @($(if ($mitLinks.ContainsKey($id)) { Get-Sorted @($mitLinks[$id]) })) }
    $map = if ($o.type -eq 'attack-pattern') { $techniques } else { $mitigations }
    if ($map.ContainsKey($id)) {
        # Two STIX objects with one ID: keep the active one; two active ones is a data error.
        $prevActive = -not $map[$id].revoked -and -not $map[$id].deprecated
        $curActive = -not $entry.revoked -and -not $entry.deprecated
        if ($prevActive -and $curActive) { throw "Two active STIX objects share ATT&CK id $id" }
        if ($prevActive) { continue }
    }
    $map[$id] = $entry
}

# ---------------------------------------------------------------- ATLAS (YAML subset reader)
# ATLAS.yaml keys techniques and mitigations by id under two top-level maps:
#   techniques:\n  AML.T0000:\n    name: ...\n    id: AML.T0000
# Only the 2-space entry keys and their 4-space `name:`/`id:` scalars are read.
function ConvertFrom-YamlScalar([string]$v) {
    $v = $v.Trim()
    if ($v.Length -ge 2 -and $v[0] -eq "'" -and $v[-1] -eq "'") { return $v.Substring(1, $v.Length - 2).Replace("''", "'") }
    if ($v.Length -ge 2 -and $v[0] -eq '"' -and $v[-1] -eq '"') { return [string](ConvertFrom-Json -InputObject $v) }   # YAML double-quoted ~ JSON string
    return $v
}
$lines = [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $AtlasYaml))
$atlasVersion = $null
$section = $null; $cur = $null; $curName = $null; $curId = $null
$atlasTech = @{}; $atlasMit = @{}
$flush = {
    if ($cur) {
        if (-not $curName) { throw "ATLAS entry $cur has no single-line name" }
        if ($curId -and $curId -ne $cur) { throw "ATLAS entry key $cur does not match its id $curId" }
        $target = if ($section -eq 'techniques') { $atlasTech } else { $atlasMit }
        $target[$cur] = $curName
    }
}
for ($i = 0; $i -lt $lines.Length; $i++) {
    $ln = $lines[$i]
    if ($ln -match '^(\S[^:]*):') {
        & $flush; $cur = $null; $curName = $null; $curId = $null
        $section = if ($Matches[1] -in @('techniques', 'mitigations')) { $Matches[1] } else { $null }
        continue
    }
    if (-not $atlasVersion -and $ln -match "^  version: '?([0-9.]+)'?\s*$") { $atlasVersion = $Matches[1] }
    if (-not $section) { continue }
    if ($ln -match '^  (AML\.[A-Z]+\d{4}(?:\.\d{3})?):\s*$') { & $flush; $cur = $Matches[1]; $curName = $null; $curId = $null; continue }
    if ($cur -and $ln -match '^    name:\s(.+)$') {
        if ($i + 1 -lt $lines.Length -and $lines[$i + 1] -match '^      \S') { throw "ATLAS entry $cur has a multi-line name; convert ATLAS.yaml to JSON instead (see the plan)." }
        $curName = ConvertFrom-YamlScalar $Matches[1]; continue
    }
    if ($cur -and $ln -match '^    id:\s(.+)$') { $curId = ConvertFrom-YamlScalar $Matches[1] }
}
& $flush
if ($atlasVersion -ne $pins.atlas.version) { throw "ATLAS collection version '$atlasVersion' is not the pinned $($pins.atlas.version)." }
if ($atlasTech.Count -lt 50) { throw "ATLAS reader found only $($atlasTech.Count) techniques; the file layout may have changed." }
foreach ($id in $atlasTech.Keys) { $techniques[$id] = [ordered]@{ name = $atlasTech[$id]; domain = 'atlas'; tactics = @(); revoked = $false; deprecated = $false } }
foreach ($id in $atlasMit.Keys) { $mitigations[$id] = [ordered]@{ name = $atlasMit[$id]; domain = 'atlas'; revoked = $false; deprecated = $false; techniques = @() } }

# ---------------------------------------------------------------- deterministic output
# One entry per line, keys sorted ordinally, LF line endings: small diffs on catalog updates.
function ConvertTo-J($v) { return (ConvertTo-Json -InputObject $v -Compress -Depth 5) }
$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append("{`n")
[void]$sb.Append('  "notes": ' + (ConvertTo-J 'Generated by build/Import-AttackCatalog.ps1 from the pinned MITRE ATT&CK Enterprise STIX bundle and MITRE ATLAS data release. IDs, names, tactics and flags only. Do not edit by hand. ATT&CK and ATLAS are trademarks of The MITRE Corporation; data (c) The MITRE Corporation, used under the ATT&CK Terms of Use.') + ",`n")
[void]$sb.Append('  "source": ' + (ConvertTo-J $pins) + ",`n")
foreach ($part in @(@{ key = 'techniques'; map = $techniques; last = $false }, @{ key = 'mitigations'; map = $mitigations; last = $true })) {
    [void]$sb.Append("  `"$($part.key)`": {`n")
    $ks = Get-Sorted $part.map.Keys
    for ($i = 0; $i -lt $ks.Length; $i++) {
        [void]$sb.Append('    ' + (ConvertTo-J $ks[$i]) + ': ' + (ConvertTo-J $part.map[$ks[$i]]) + $(if ($i -lt $ks.Length - 1) { ',' } else { '' }) + "`n")
    }
    [void]$sb.Append('  }' + $(if ($part.last) { '' } else { ',' }) + "`n")
}
[void]$sb.Append("}`n")
$dir = Split-Path -Parent $Out
if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
[IO.File]::WriteAllText($Out, $sb.ToString(), [Text.UTF8Encoding]::new($false))
$act = @($techniques.Values | Where-Object { -not $_.revoked -and -not $_.deprecated })
Write-Host ("Wrote {0}: {1} techniques ({2} active; {3} ATLAS), {4} mitigations" -f $Out, $techniques.Count, $act.Count, $atlasTech.Count, $mitigations.Count)
