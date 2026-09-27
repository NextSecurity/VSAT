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
## Download

| File | What it is |
|---|---|
| ``vsat.ps1`` | **The whole tool.** One plain PowerShell file: no binaries, no encoded content. This is the file your security team reviews and your file scanner checks. |
| ``SHA256SUMS.txt`` | SHA-256 of every file here. Check ``vsat.ps1`` against it before review and after transfer. |
| ``VSAT-$Version-offline-builder.zip`` | Optional. Only for networks without PowerShell 7 and PowerCLI: sources, build script, dependency lock and SBOM, plus a builder that produces a portable Windows package on a connected machine. |

Verify: ``sha256sum -c SHA256SUMS.txt --ignore-missing`` (Linux/macOS) or ``(Get-FileHash .\vsat.ps1).Hash`` (Windows). Security review guide: [docs/security-review.md](https://github.com/NextSecurity/VSAT/blob/v$Version/docs/security-review.md).

## What's new

$body
"@
