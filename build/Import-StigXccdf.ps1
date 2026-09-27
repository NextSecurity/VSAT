<#
.SYNOPSIS
    Proposes DISA STIG mappings for VSAT rules from an official XCCDF file (maintainer-side, offline).
.DESCRIPTION
    Reads a DISA STIG XCCDF (1.1 or 1.2) with DTD processing prohibited, and proposes a mapping from a
    VSAT rule to a STIG rule when a setting or service name the VSAT rule checks (check.key, check.fact,
    the leaf of check.path, check.service) appears verbatim in the STIG check text. Every row it writes is
    status "proposed": a maintainer confirms it against the STIG check and fix text before it may become
    "verified" (docs/compliance-mapping.md).

    Only IDs are written (STIG ID, rule ID, severity, CCIs). No DISA text is copied. The source file is
    pinned by SHA-256. With -CciPath (DISA U_CCI_List.xml) it also derives NIST SP 800-53 Rev. 5 rows
    from the CCIs, marked "derived".

    Never embedded in vsat.ps1; the output feeds build/New-CrosswalkSeed.ps1 via build/crosswalk/imported/.
.EXAMPLE
    pwsh ./build/Import-StigXccdf.ps1 -XccdfPath ./U_VMW_vSphere_8-0-ESXi_STIG_V2R4_Manual-xccdf.xml -Framework disa-stig-esxi-8 `
        -AssetTypes host,portgroup,vss -SourcePackage U_VMW_vSphere_8-0_Y26M07_STIG.zip -SourcePackageSha256 <sha> -Out ./build/crosswalk/imported/disa-stig-esxi-8.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$XccdfPath,
    [Parameter(Mandatory)][string]$Framework,
    [Parameter(Mandatory)][string]$Out,
    [string]$FrameworkName,
    [string[]]$AssetTypes,
    [string]$SourcePackage,
    [string]$SourcePackageSha256,
    [string]$SourceUrl,
    [string]$CciPath
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# pwsh -File passes "host,vss" as one string; accept both forms.
$AssetTypes = @($AssetTypes | ForEach-Object { ([string]$_).Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Read-SafeXml([string]$Path) {
    # DTDs are prohibited (no XXE, no entity expansion); no resolver, so nothing is fetched.
    $s = [System.Xml.XmlReaderSettings]::new()
    $s.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $s.XmlResolver = $null
    $r = [System.Xml.XmlReader]::Create((Resolve-Path -LiteralPath $Path).ProviderPath, $s)
    try { $d = [System.Xml.XmlDocument]::new(); $d.XmlResolver = $null; $d.Load($r); return $d } finally { $r.Dispose() }
}

function Get-FileSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).ProviderPath)
    try { return (($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $fs.Dispose(); $sha.Dispose() }
}

$doc = Read-SafeXml $XccdfPath
$ns = [System.Xml.XmlNamespaceManager]::new($doc.NameTable)
$ns.AddNamespace('x', $doc.DocumentElement.NamespaceURI)
if ($doc.DocumentElement.LocalName -ne 'Benchmark') { throw "Not an XCCDF Benchmark: $XccdfPath" }
$title = [string]$doc.SelectSingleNode('/x:Benchmark/x:title', $ns).InnerText
$ver = [string]$doc.SelectSingleNode('/x:Benchmark/x:version', $ns).InnerText
$rel = [string]$doc.SelectSingleNode("/x:Benchmark/x:plain-text[@id='release-info']", $ns).InnerText
$edition = if ($rel -match 'Release:\s*(\d+)\s+Benchmark Date:\s*(.+)$') { "V$($ver)R$($Matches[1]) ($($Matches[2].Trim()))" } else { "V$ver" }
$fileSha = Get-FileSha256 $XccdfPath
$pinSha = if ($SourcePackageSha256) { $SourcePackageSha256.ToLowerInvariant() } else { $fileSha }
$pinName = if ($SourcePackage) { $SourcePackage } else { [IO.Path]::GetFileName($XccdfPath) }

# VSAT rules straight from rules/*.json, so the importer does not depend on a built vsat.ps1.
$rules = foreach ($f in Get-ChildItem -LiteralPath (Join-Path $root 'rules') -Filter '*.json' | Sort-Object Name) {
    if ($f.Name -eq 'pack.json') { continue }
    @(([IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json -AsHashtable).rules)
}
# Needles: exact identifiers only. Service keys always count (TSM, slpd); anything else must look like
# an identifier (dotted, hyphenated, snake_case or camelCase, 6+ characters). Fact names that are
# collection containers, not settings, never count.
$stop = @('extraConfig', 'advanced', 'settings', 'security', 'policy', 'props', 'secureBoot', 'services')
$needles = @{}
foreach ($r in $rules) {
    if ($AssetTypes -and -not @(@($r.assetType) | Where-Object { $_ -in $AssetTypes }).Count) { continue }
    $c = $r.check
    $list = [System.Collections.Generic.List[string]]::new()
    if ($c.type -eq 'service' -and $c.key) { $list.Add([string]$c.key) }
    foreach ($n in @($c.key, $c.fact, $(if ($c.path) { ([string]$c.path).Split('.')[-1] }), $c.service)) {
        if ($n -isnot [string] -or -not $n -or $n -in $stop -or $list.Contains($n)) { continue }
        if ($n.Length -ge 6 -and ($n -match '[.\-_]' -or $n -cmatch '[a-z][A-Z]')) { $list.Add($n) }
    }
    if ($list.Count) { $needles[$r.id] = @($list) }
}

$mappings = [System.Collections.Generic.List[object]]::new()
$stigCci = @{}
foreach ($rule in $doc.SelectNodes('//x:Group/x:Rule', $ns)) {
    $stigId = [string]$rule.SelectSingleNode('x:version', $ns).InnerText
    $text = (@($rule.SelectNodes('.//x:check-content', $ns) | ForEach-Object { $_.InnerText }) -join "`n")
    $ccis = @($rule.SelectNodes("x:ident[@system='http://cyber.mil/cci']", $ns) | ForEach-Object { $_.InnerText.Trim() } | Sort-Object -Unique)
    $stigCci[$stigId] = $ccis
    foreach ($rid in @($needles.Keys | Sort-Object)) {
        foreach ($n in $needles[$rid]) {
            # Whole identifier only: TSM never matches inside TSM-SSH, a trailing sentence period is fine.
            if (-not [regex]::IsMatch($text, '(?i)(?<![\w-]|\w\.)' + [regex]::Escape($n) + '(?![\w-]|\.\w)')) { continue }
            $mappings.Add([ordered]@{
                    ruleId = $rid; framework = $Framework; control = $stigId; relation = 'supports'; status = 'proposed'
                    basis = "setting '$n' appears in STIG check text"
                    sourceRef = "DISA $title $edition ($pinName sha256 $($pinSha.Substring(0, 12)))"
                    stigRuleId = [string]$rule.GetAttribute('id'); severity = [string]$rule.GetAttribute('severity'); cci = $ccis
                })
            break
        }
    }
}
$sorted = @($mappings | Sort-Object { $_.ruleId }, { $_.control } -Culture ([Globalization.CultureInfo]::InvariantCulture))

$derived = @()
if ($CciPath) {
    $cdoc = Read-SafeXml $CciPath
    $cns = [System.Xml.XmlNamespaceManager]::new($cdoc.NameTable)
    $cns.AddNamespace('c', $cdoc.DocumentElement.NamespaceURI)
    $cver = [string]$cdoc.SelectSingleNode('/c:cci_list/c:metadata/c:version', $cns).InnerText
    $nist = @{}
    foreach ($item in $cdoc.SelectNodes('//c:cci_item', $cns)) {
        $refs = @($item.SelectNodes("c:references/c:reference[@version='5']", $cns) | ForEach-Object { if ($_.GetAttribute('index') -match '^([A-Z]{2}-\d+)') { $Matches[1] } })
        if ($refs.Count) { $nist[$item.GetAttribute('id')] = @($refs | Sort-Object -Unique) }
    }
    $seen = @{}
    $derived = @(foreach ($m in $sorted) {
            foreach ($cci in @($m.cci)) {
                foreach ($ctl in @($nist[$cci])) {
                    if (-not $ctl -or $seen.ContainsKey("$($m.ruleId)|$ctl")) { continue }
                    $seen["$($m.ruleId)|$ctl"] = $true
                    [ordered]@{ ruleId = $m.ruleId; framework = 'nist-800-53r5'; control = $ctl; relation = 'supports'; status = 'derived'; basis = "via $($m.control) $cci"; sourceRef = "DISA CCI list $cver ($($m.control))" }
                }
            }
        })
}

$fwName = if ($FrameworkName) { $FrameworkName } else { "DISA $title" }
$outDoc = [ordered]@{
    notes = "Generated by build/Import-StigXccdf.ps1. IDs only; no DISA text. Every mapping is proposed until a maintainer reviews it (docs/compliance-mapping.md)."
    framework = [ordered]@{
        id = $Framework; name = $fwName; edition = $edition; publisher = 'DISA'; license = 'public-domain'; url = 'https://public.cyber.mil/stigs/downloads/'
        source = [ordered]@{ package = $pinName; sha256 = $pinSha; url = $SourceUrl; file = [IO.Path]::GetFileName($XccdfPath); fileSha256 = $fileSha; benchmark = $title }
    }
    mappings = $sorted
    derived = $derived
}
$dir = Split-Path -Parent ([IO.Path]::GetFullPath($Out))
if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Out), (($outDoc | ConvertTo-Json -Depth 8).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Write-Host ("Wrote {0}: {1} proposed mapping(s), {2} derived NIST row(s) from {3} {4}" -f $Out, $sorted.Count, $derived.Count, $title, $edition)
