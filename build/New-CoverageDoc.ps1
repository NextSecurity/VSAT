<#
.SYNOPSIS
    Generates docs/coverage.md (control coverage matrix) from the embedded rule pack.
#>
[CmdletBinding()]
param([string]$OutFile)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutFile) { $OutFile = Join-Path $root 'docs/coverage.md' }
. (Join-Path $root 'vsat.ps1') -LibraryMode
$pack = Get-VsatRulePack
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('# Control coverage matrix')
[void]$sb.AppendLine()
[void]$sb.AppendLine("Generated from rule pack **$($pack.version)** for VSAT **$script:VsatVersion** by ``build/New-CoverageDoc.ps1``. Do not edit by hand.")
[void]$sb.AppendLine()
[void]$sb.AppendLine('- **Automated** checks evaluate collected evidence; missing or denied evidence yields UNKNOWN, never PASS.')
[void]$sb.AppendLine('- **Manual** checks always produce MANUAL results with guidance; completion is not certification.')
[void]$sb.AppendLine('- CIS control IDs are carried over from the VSAT 1.x mapping and are marked **unverified** until reviewed against the licensed CIS ESXi 8.0 v1.4.0 / 7.0 v1.6.0 documents. CIS publishes no vCenter or NSX benchmark; those checks use vendor guidance or VSAT-native logic.')
[void]$sb.AppendLine('- NIST SP 800-53, IEC 62443-3-3, MITRE ATT&CK mitigation and DISA STIG references come from the crosswalk in `data/frameworks` (see [compliance-mapping.md](compliance-mapping.md)); *(proposed)* rows are not reviewed yet.')
[void]$sb.AppendLine('- Profiles: `standard` (default) and `strict`. Rules marked *strict only* run only with `-Profile strict`.')
[void]$sb.AppendLine()
$domains = [ordered]@{}
foreach ($r in $pack.rules) { if (-not $domains.Contains($r.domain)) { $domains[$r.domain] = [System.Collections.Generic.List[object]]::new() }; $domains[$r.domain].Add($r) }
[void]$sb.AppendLine('| Domain | Rules | Automated | Manual |')
[void]$sb.AppendLine('|---|---:|---:|---:|')
foreach ($d in $domains.Keys) { $l = $domains[$d]; [void]$sb.AppendLine("| $d | $($l.Count) | $(@($l | Where-Object { $_.check.type -ne 'manual' }).Count) | $(@($l | Where-Object { $_.check.type -eq 'manual' }).Count) |") }
[void]$sb.AppendLine("| **total** | **$(@($pack.rules).Count)** | **$(@($pack.rules | Where-Object { $_.check.type -ne 'manual' }).Count)** | **$(@($pack.rules | Where-Object { $_.check.type -eq 'manual' }).Count)** |")
[void]$sb.AppendLine()
foreach ($d in $domains.Keys) {
    [void]$sb.AppendLine("## $d")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Rule | Title | Asset | Severity | Type | Profiles | Framework references |')
    [void]$sb.AppendLine('|---|---|---|---|---|---|---|')
    foreach ($r in $domains[$d]) {
        # Legacy and VSAT references in full; crosswalk rows (data/frameworks) compact, one line per framework.
        $legacy = @($r.frameworks | Where-Object { $_.frameworkId -in @('cis-esxi-legacy', 'scg', 'vsat') } | ForEach-Object { "$($_.framework) $($_.control)$(if ($_.mappingStatus -ne 'verified') { ' *(unverified)*' })" })
        $cross = @($r.frameworks | Where-Object { $_.frameworkId -notin @('cis-esxi-legacy', 'scg', 'vsat') } | Group-Object { $_.framework } | ForEach-Object { "$($_.Name): $(@($_.Group | ForEach-Object { $_.control }) -join ', ')$(if (@($_.Group | Where-Object { $_.mappingStatus -ne 'verified' }).Count) { ' *(proposed)*' })" })
        $fw = (@($legacy) + @($cross)) -join '<br>'
        $prof = (@(Get-VsatProp $r 'profilesEnabled' @('standard', 'strict')) -join ', ')
        [void]$sb.AppendLine("| ``$($r.id)`` | $($r.title) | $(@($r.assetType) -join ', ') | $($r.severity) | $(if ($r.check.type -eq 'manual') { 'manual' } else { 'automated' }) | $prof | $fw |")
    }
    [void]$sb.AppendLine()
}
[System.IO.File]::WriteAllText($OutFile, $sb.ToString().Replace("`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $OutFile"
