<#
.SYNOPSIS
    Connected-side builder for the portable offline package (VSAT-<ver>-win-x64-offline.zip).
.DESCRIPTION
    Run this on an internet-connected build machine. It produces a fully populated ZIP that
    is then transported into the isolated environment; nothing inside the ZIP ever downloads
    anything. Inputs are pinned by build/runtime.lock.json:
      - PowerShell runtime ZIP (official GitHub release), verified by SHA-256
      - VCF.PowerCLI modules saved with Save-Module at the pinned version
    Redistribution of the PowerShell runtime (MIT) and PowerCLI (Broadcom license) inside a
    public release has not been confirmed for VSAT, so this builder uses legitimate vendor
    downloads on the operator's side instead of VSAT shipping them. The ZIP fails the build
    if any required component is missing.
.PARAMETER RuntimeZip
    Use a locally downloaded PowerShell ZIP instead of downloading (hash still verified).
.PARAMETER ModulesPath
    Use an existing folder of saved modules instead of Save-Module.
.PARAMETER SkipRuntime
    Build a package that relies on an installed PowerShell 7 (for testing only).
.EXAMPLE
    pwsh ./build/New-OfflinePackage.ps1 -OutDir ./dist
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string]$RuntimeZip,
    [string]$ModulesPath,
    [switch]$SkipRuntime
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }
$lock = Get-Content -Raw (Join-Path $root 'build/runtime.lock.json') | ConvertFrom-Json
$version = (Get-Content -Raw (Join-Path $root 'build/version.json') | ConvertFrom-Json).version
$name = "VSAT-$version-win-x64-offline"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("vsat-pkg-" + [guid]::NewGuid().ToString('N'))
$pkg = Join-Path $stage $name
New-Item -ItemType Directory -Path $pkg, (Join-Path $pkg 'modules'), (Join-Path $pkg 'docs') -Force | Out-Null
try {

function Get-Sha256([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

# 1. Application (single generated script, rebuilt to guarantee it matches src/)
& pwsh -NoProfile -File (Join-Path $root 'build/Build-Vsat.ps1') -Check | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'vsat.ps1 is out of date; run build/Build-Vsat.ps1 first.' }
Copy-Item (Join-Path $root 'vsat.ps1') $pkg

# 2. PowerShell runtime
if (-not $SkipRuntime) {
    if (-not $RuntimeZip) {
        $RuntimeZip = Join-Path $stage $lock.powershell.file
        Write-Host "Downloading $($lock.powershell.url)"
        Invoke-WebRequest -Uri $lock.powershell.url -OutFile $RuntimeZip -UseBasicParsing
    }
    $h = Get-Sha256 $RuntimeZip
    if ($lock.powershell.sha256 -and $h -ne $lock.powershell.sha256.ToLowerInvariant()) { throw "PowerShell runtime hash mismatch: got $h, expected $($lock.powershell.sha256)" }
    if (-not $lock.powershell.sha256) { Write-Warning "runtime.lock.json has no sha256 for the runtime; recording observed hash $h. Verify it against the official release page before shipping." }
    Expand-Archive -LiteralPath $RuntimeZip -DestinationPath (Join-Path $pkg 'runtime') -Force
    if (-not (Test-Path (Join-Path $pkg 'runtime/pwsh.exe'))) { throw 'Runtime ZIP did not contain pwsh.exe' }
}

# 3. PowerCLI modules (process-local; never installed globally on the target)
if ($ModulesPath) { Copy-Item -Recurse -Path (Join-Path $ModulesPath '*') -Destination (Join-Path $pkg 'modules') }
else {
    foreach ($m in $lock.powercli.modules) {
        Write-Host "Saving $($m.name) $($m.version) (with dependencies) from $($lock.powercli.repository)"
        Save-Module -Name $m.name -RequiredVersion $m.version -Repository $lock.powercli.repository -Path (Join-Path $pkg 'modules') -AcceptLicense
    }
}
if (-not (Get-ChildItem -Directory (Join-Path $pkg 'modules') -Filter 'VMware.VimAutomation.Core' -ErrorAction SilentlyContinue)) { throw 'VMware.VimAutomation.Core missing from modules; the package would require downloads in the isolated environment.' }

# 4. Launcher: bundled runtime, no profile, bypass nothing (execution policy is respected)
@'
@echo off
setlocal
set "VSAT_HOME=%~dp0"
if exist "%VSAT_HOME%runtime\pwsh.exe" (
  "%VSAT_HOME%runtime\pwsh.exe" -NoProfile -NoLogo -File "%VSAT_HOME%vsat.ps1" %*
) else (
  pwsh.exe -NoProfile -NoLogo -File "%VSAT_HOME%vsat.ps1" %*
)
exit /b %ERRORLEVEL%
'@ | Set-Content -LiteralPath (Join-Path $pkg 'VSAT.cmd') -Encoding ascii

# 5. Documentation and notices
foreach ($f in 'README.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md') { if (Test-Path (Join-Path $root $f)) { Copy-Item (Join-Path $root $f) $pkg } }
foreach ($f in 'usage.md', 'offline-package.md', 'privileges.md', 'limitations.md', 'coverage.md', 'threat-model.md') { if (Test-Path (Join-Path $root "docs/$f")) { Copy-Item (Join-Path $root "docs/$f") (Join-Path $pkg 'docs') } }
@"
Third-party components in this package (obtained by the package builder from vendor sources):
- PowerShell $($lock.powershell.version) - MIT License - $($lock.powershell.url)
- VMware PowerCLI modules from $($lock.powercli.distribution): $((@($lock.powercli.modules | ForEach-Object { "$($_.name) $($_.version)" })) -join ', ') and dependencies - Broadcom license (see modules/*/*/license*) - PowerShell Gallery
VSAT itself is MIT licensed. Embedded report/UI code is original VSAT code with no third-party libraries.
"@ | Set-Content -LiteralPath (Join-Path $pkg 'THIRD-PARTY-NOTICES.txt') -Encoding utf8

# 6. Manifest with hashes of every file (integrity, not proof of provenance)
$files = Get-ChildItem -Recurse -File $pkg | Sort-Object FullName | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($pkg.Length + 1).Replace('\', '/'); sha256 = (Get-Sha256 $_.FullName); bytes = $_.Length }
}
$modules = Get-ChildItem -Directory (Join-Path $pkg 'modules') | ForEach-Object { [ordered]@{ name = $_.Name; versions = @(Get-ChildItem -Directory $_.FullName | ForEach-Object { $_.Name }) } }
[ordered]@{
    package = $name; vsat = $version; builtUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    runtime = $(if ($SkipRuntime) { 'not bundled (test build)' } else { $lock.powershell })
    modules = @($modules); files = @($files)
    note = 'Hashes verify package integrity after transport. Unsigned unless a detached signature accompanies this package.'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $pkg 'package-manifest.json') -Encoding utf8

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$zip = Join-Path $OutDir "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $pkg -DestinationPath $zip
$hash = Get-Sha256 $zip
"$hash  $name.zip" | Set-Content -LiteralPath "$zip.sha256" -Encoding ascii
Write-Host "Package: $zip"
Write-Host "SHA-256: $hash"
}
finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
