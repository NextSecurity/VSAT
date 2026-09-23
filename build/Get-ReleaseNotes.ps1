<#
.SYNOPSIS
    Extracts the CHANGELOG.md section for a version and appends release boilerplate.
#>
param([Parameter(Mandatory)][string]$Version)
$root = Split-Path -Parent $PSScriptRoot
$text = Get-Content -Raw (Join-Path $root 'CHANGELOG.md')
$m = [regex]::Match($text, "(?ms)^## \[$([regex]::Escape($Version))\][^\n]*\n(.*?)(?=^## \[|\z)")
$body = if ($m.Success) { $m.Groups[1].Value.Trim() } else { "See CHANGELOG.md." }
@"
$body

---
**Verify downloads:** ``sha256sum -c SHA256SUMS.txt`` (Linux/macOS) or ``Get-FileHash -Algorithm SHA256`` (Windows). Assets are **not code-signed**; checksums verify integrity only.

**Offline package:** run ``build/New-OfflinePackage.ps1`` from ``VSAT-$Version-offline-builder.zip`` on a connected machine to produce the complete ``VSAT-$Version-win-x64-offline.zip`` (pinned PowerShell runtime + PowerCLI, hash-verified), then transfer it into the isolated environment.

**Status:** prerelease. Not yet validated against a live vSphere/NSX lab; see docs/limitations.md.
"@
