<#
.SYNOPSIS
    Builds the GitHub Pages site output: copies site/ and generates the synthetic demo
    report (site/demo/report.html) from the built-in synthetic lab. No real data is used.
#>
[CmdletBinding()]
param([string]$OutDir, [switch]$Screenshots)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root '_site' }
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
Copy-Item -Recurse (Join-Path $root 'site') $OutDir
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('vsat-site-' + [guid]::NewGuid().ToString('N'))
& pwsh -NoProfile -File (Join-Path $root 'vsat.ps1') -Demo -Cli -OutputPath $tmp | Out-Null
New-Item -ItemType Directory -Force (Join-Path $OutDir 'demo') | Out-Null
Copy-Item (Join-Path $tmp 'report.html') (Join-Path $OutDir 'demo/report.html')
Copy-Item (Join-Path $tmp 'findings.csv') (Join-Path $OutDir 'demo/findings.csv')
Copy-Item (Join-Path $tmp 'assessment.vsat.zip') (Join-Path $OutDir 'demo/assessment.vsat.zip')
Copy-Item (Join-Path $root 'CHANGELOG.md') (Join-Path $OutDir 'CHANGELOG.md') -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $tmp
if ($Screenshots) {
    $chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    if (-not (Test-Path $chrome)) { $chrome = (Get-Command google-chrome, chromium, chrome -ErrorAction SilentlyContinue | Select-Object -First 1).Source }
    if ($chrome) {
        $report = 'file://' + (Join-Path $OutDir 'demo/report.html')
        & $chrome --headless=new --disable-gpu --hide-scrollbars --window-size=1440,900 --virtual-time-budget=4000 "--screenshot=$(Join-Path $root 'site/assets/screenshot-overview.png')" $report 2>$null
        & $chrome --headless=new --disable-gpu --hide-scrollbars --window-size=1440,900 --virtual-time-budget=4000 "--screenshot=$(Join-Path $root 'site/assets/screenshot-topology.png')" "$report#topology" 2>$null
        Copy-Item (Join-Path $root 'site/assets/screenshot-*.png') (Join-Path $OutDir 'assets') -Force
    }
}
Write-Host "Site built in $OutDir"
