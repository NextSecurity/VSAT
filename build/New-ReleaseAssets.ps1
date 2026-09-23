<#
.SYNOPSIS
    Assembles release assets: vsat.ps1, offline package builder kit, sample sanitized
    report/evidence, SPDX SBOM, dependency lock and SHA256SUMS.
.DESCRIPTION
    The fully populated offline ZIP is produced by the operator with
    build/New-OfflinePackage.ps1 on a connected machine, because redistribution rights for
    the PowerShell runtime and PowerCLI inside VSAT's own release have not been confirmed.
#>
[CmdletBinding()]
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'release' }
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Path $OutDir | Out-Null
$version = (Get-Content -Raw (Join-Path $root 'build/version.json') | ConvertFrom-Json).version
Copy-Item (Join-Path $root 'vsat.ps1') $OutDir

# Offline package builder kit (connected side)
$kit = Join-Path ([IO.Path]::GetTempPath()) ("vsat-kit-" + [guid]::NewGuid().ToString('N'))
$kitRoot = Join-Path $kit "VSAT-$version-offline-builder"
New-Item -ItemType Directory -Path (Join-Path $kitRoot 'build'), (Join-Path $kitRoot 'docs') -Force | Out-Null
Copy-Item (Join-Path $root 'vsat.ps1'), (Join-Path $root 'README.md'), (Join-Path $root 'LICENSE'), (Join-Path $root 'CHANGELOG.md') $kitRoot
Copy-Item (Join-Path $root 'build/New-OfflinePackage.ps1'), (Join-Path $root 'build/runtime.lock.json'), (Join-Path $root 'build/version.json'), (Join-Path $root 'build/Build-Vsat.ps1') (Join-Path $kitRoot 'build')
foreach ($d in 'src', 'rules', 'data', 'assets') { Copy-Item -Recurse (Join-Path $root $d) $kitRoot }
New-Item -ItemType Directory -Force (Join-Path $kitRoot 'tests/fixtures') | Out-Null
Copy-Item (Join-Path $root 'tests/fixtures/demo-evidence.json') (Join-Path $kitRoot 'tests/fixtures')
Copy-Item (Join-Path $root 'docs/*.md') (Join-Path $kitRoot 'docs')
Compress-Archive -Path $kitRoot -DestinationPath (Join-Path $OutDir "VSAT-$version-offline-builder.zip")
Remove-Item -Recurse -Force $kit

# Sample sanitized report and evidence package (synthetic lab only)
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('vsat-sample-' + [guid]::NewGuid().ToString('N'))
& pwsh -NoProfile -File (Join-Path $root 'vsat.ps1') -Demo -Cli -OutputPath $tmp | Out-Null
Copy-Item (Join-Path $tmp 'report.html') (Join-Path $OutDir "VSAT-$version-sample-report.html")
Copy-Item (Join-Path $tmp 'assessment.vsat.zip') (Join-Path $OutDir "VSAT-$version-sample-evidence.vsat.zip")
Remove-Item -Recurse -Force $tmp

Copy-Item (Join-Path $root 'build/runtime.lock.json') (Join-Path $OutDir 'dependency-lock.json')

# SPDX 2.3 SBOM (VSAT has no bundled third-party code; runtime dependencies are declared)
$lock = Get-Content -Raw (Join-Path $root 'build/runtime.lock.json') | ConvertFrom-Json
$sha = (Get-FileHash -Algorithm SHA256 (Join-Path $root 'vsat.ps1')).Hash.ToLowerInvariant()
$sbom = [ordered]@{
    spdxVersion = 'SPDX-2.3'; dataLicense = 'CC0-1.0'; SPDXID = 'SPDXRef-DOCUMENT'; name = "VSAT-$version"
    documentNamespace = "https://github.com/NextSecurity/VSAT/spdx/$version"
    creationInfo = [ordered]@{ created = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); creators = @('Tool: VSAT build/New-ReleaseAssets.ps1') }
    packages = @(
        [ordered]@{ SPDXID = 'SPDXRef-vsat'; name = 'VSAT'; versionInfo = $version; downloadLocation = 'https://github.com/NextSecurity/VSAT'; licenseConcluded = 'MIT'; licenseDeclared = 'MIT'; copyrightText = 'NOASSERTION'; checksums = @([ordered]@{ algorithm = 'SHA256'; checksumValue = $sha }) }
        [ordered]@{ SPDXID = 'SPDXRef-pwsh'; name = 'PowerShell'; versionInfo = $lock.powershell.version; downloadLocation = $lock.powershell.url; licenseConcluded = 'MIT'; licenseDeclared = 'MIT'; copyrightText = 'NOASSERTION'; checksums = @([ordered]@{ algorithm = 'SHA256'; checksumValue = $lock.powershell.sha256 }) }
        [ordered]@{ SPDXID = 'SPDXRef-powercli'; name = 'VMware.VimAutomation.Core'; versionInfo = @($lock.powercli.modules)[0].version; downloadLocation = 'https://www.powershellgallery.com/packages/VMware.VimAutomation.Core'; licenseConcluded = 'NOASSERTION'; licenseDeclared = 'NOASSERTION'; copyrightText = 'NOASSERTION'; comment = "Distributed in $($lock.powercli.distribution)" }
    )
    relationships = @(
        [ordered]@{ spdxElementId = 'SPDXRef-DOCUMENT'; relationshipType = 'DESCRIBES'; relatedSpdxElement = 'SPDXRef-vsat' }
        [ordered]@{ spdxElementId = 'SPDXRef-vsat'; relationshipType = 'DEPENDS_ON'; relatedSpdxElement = 'SPDXRef-pwsh' }
        [ordered]@{ spdxElementId = 'SPDXRef-vsat'; relationshipType = 'DEPENDS_ON'; relatedSpdxElement = 'SPDXRef-powercli' }
    )
}
$sbom | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $OutDir "VSAT-$version.spdx.json") -Encoding utf8

# Checksums (integrity only; artifacts are unsigned unless a signature file is attached)
$sums = Get-ChildItem -File $OutDir | Sort-Object Name | ForEach-Object { "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant())  $($_.Name)" }
Set-Content -Path (Join-Path $OutDir 'SHA256SUMS.txt') -Value $sums -Encoding ascii
Get-ChildItem $OutDir | ForEach-Object { Write-Host $_.Name }

# The sample demo run exits 1 (findings present) by design; asset assembly succeeded.
exit 0
