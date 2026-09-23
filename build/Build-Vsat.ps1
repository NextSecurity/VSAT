<#
.SYNOPSIS
    Generates the single-file vsat.ps1 from src/, rules/, data/ and assets/.
.DESCRIPTION
    Deterministic: files are processed in ordinal order, line endings are normalized to
    LF, embedded resources are base64-encoded UTF-8, and no timestamps are written. The
    same sources always produce a byte-identical vsat.ps1 (verified in CI with -Check).
.PARAMETER Check
    Fail if the committed vsat.ps1 differs from a fresh build.
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [switch]$Check
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutFile) { $OutFile = Join-Path $root 'vsat.ps1' }
$version = (Get-Content -Raw -LiteralPath (Join-Path $root 'build/version.json') | ConvertFrom-Json).version

function Get-Normalized([string]$Path) {
    $t = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ($t.Length -gt 0 -and $t[0] -eq [char]0xFEFF) { $t = $t.Substring(1) }
    return $t.Replace("`r`n", "`n")
}

$srcFiles = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.ps1' | Sort-Object { $_.Name } -Culture ([Globalization.CultureInfo]::InvariantCulture)
$resources = New-Object System.Collections.Generic.List[object]
foreach ($dir in @('rules', 'data')) {
    Get-ChildItem -LiteralPath (Join-Path $root $dir) -Filter '*.json' | Sort-Object Name | ForEach-Object { $resources.Add(@{ name = "$dir/$($_.Name)"; path = $_.FullName }) }
}
foreach ($f in @('assets/report/report.html', 'assets/report/report.css', 'assets/report/report.js', 'assets/ui/app.html', 'assets/ui/app.css', 'assets/ui/app.js')) {
    $resources.Add(@{ name = $f; path = (Join-Path $root $f) })
}
$resources.Add(@{ name = 'fixtures/demo-evidence.json'; path = (Join-Path $root 'tests/fixtures/demo-evidence.json') })
foreach ($r in $resources) { if (-not (Test-Path -LiteralPath $r.path)) { throw "Missing build input: $($r.path)" } }

# JSON resources are validated at build time so a malformed rule pack never ships.
foreach ($r in $resources) { if ($r.name -like '*.json') { [void](Get-Normalized $r.path | ConvertFrom-Json) } }

$sb = New-Object System.Text.StringBuilder
$header = Get-Normalized $srcFiles[0].FullName
[void]$sb.Append($header.TrimEnd("`n")).Append("`n`n")
$sourceHashInput = New-Object System.Text.StringBuilder
[void]$sourceHashInput.Append($version).Append($header)
[void]$sb.Append("# ---------------------------------------------------------------------------`n")
[void]$sb.Append("# GENERATED FILE - do not edit. Source: https://github.com/NextSecurity/VSAT (src/)`n")
[void]$sb.Append("# Build: pwsh ./build/Build-Vsat.ps1`n")
[void]$sb.Append("# ---------------------------------------------------------------------------`n`n")
[void]$sb.Append("`$script:VsatVersion = '$version'`n")
[void]$sb.Append("`$script:VsatBuildCommit = '__SOURCE_HASH__'`n`n")
foreach ($f in $srcFiles | Select-Object -Skip 1) {
    $t = Get-Normalized $f.FullName
    [void]$sourceHashInput.Append($f.Name).Append($t)
    [void]$sb.Append("# ---- src/$($f.Name) ----`n").Append($t.TrimEnd("`n")).Append("`n`n")
}
[void]$sb.Append("#region Embedded resources (base64 UTF-8; data only, never executed)`n")
[void]$sb.Append("`$script:VsatEmbedded = [ordered]@{`n")
foreach ($r in $resources) {
    $t = Get-Normalized $r.path
    [void]$sourceHashInput.Append($r.name).Append($t)
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($t))
    [void]$sb.Append("    '$($r.name)' = '$b64'`n")
}
[void]$sb.Append("}`n")
[void]$sb.Append(@'
function Get-VsatEmbeddedNames {
    param([string]$Prefix = '')
    return @($script:VsatEmbedded.Keys | Where-Object { $_.StartsWith($Prefix) })
}
function Get-VsatEmbeddedText {
    param([Parameter(Mandatory)][string]$Name)
    if (-not $script:VsatEmbedded.Contains($Name)) { throw "Embedded resource '$Name' not found" }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script:VsatEmbedded[$Name]))
}
#endregion Embedded resources

if (-not $LibraryMode) {
    $vsatArgs = @{
        Server = $Server; NsxServer = $NsxServer; Credential = $Credential; NsxCredential = $NsxCredential
        NsxDeclaredAbsent = [bool]$NsxDeclaredAbsent; ScopeFile = $ScopeFile; Profile = $AuditProfile; OutputPath = $OutputPath
        Cli = [bool]$Cli; Doctor = [bool]$Doctor; Replay = $Replay; Baseline = $Baseline; Redact = [bool]$Redact
        TrustedThumbprint = $TrustedThumbprint; Port = $Port; NoBrowser = [bool]$NoBrowser; Demo = [bool]$Demo; Version = [bool]$Version
    }
    foreach ($vsatOpt in 'HyperVServer', 'HyperVCredential', 'HyperVEvidence', 'ExportCollector', 'KvmServer', 'KvmUser', 'KvmEvidence') {
        $vsatVar = Get-Variable -Name $vsatOpt -Scope Script -ErrorAction SilentlyContinue
        if ($vsatVar) { $vsatArgs[$vsatOpt] = $vsatVar.Value }
    }
    try { $vsatExit = Invoke-VsatMain -A $vsatArgs }
    catch {
        Write-Host ("VSAT fatal error: {0}" -f (Protect-VsatText $_.Exception.Message)) -ForegroundColor Red
        $vsatExit = 3
    }
    exit $vsatExit
}
'@)
$sha = [System.Security.Cryptography.SHA256]::Create()
$srcHash = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sourceHashInput.ToString())) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 16)
# Normalize everything (including this script's own here-strings, which are CRLF on Windows checkouts).
$out = $sb.ToString().Replace("`r`n", "`n").Replace('__SOURCE_HASH__', "src-$srcHash")
$enc = New-Object System.Text.UTF8Encoding($true)   # BOM: Windows PowerShell reads non-ASCII correctly
if ($Check) {
    $existing = if (Test-Path -LiteralPath $OutFile) { [System.IO.File]::ReadAllText($OutFile) } else { '' }
    if ($existing.Replace("`r`n", "`n") -ne $out) { Write-Error "vsat.ps1 is out of date. Run: pwsh ./build/Build-Vsat.ps1"; exit 1 }
    Write-Host "vsat.ps1 is up to date ($version, src-$srcHash)"
    exit 0
}
[System.IO.File]::WriteAllText($OutFile, $out, $enc)
$tokens = $null; $errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($OutFile, [ref]$tokens, [ref]$errs)
if ($errs.Count) { $errs | ForEach-Object { Write-Error ("{0}:{1} {2}" -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message) }; exit 1 }
Write-Host ("Built {0} ({1} bytes, version {2}, src-{3})" -f $OutFile, (Get-Item $OutFile).Length, $version, $srcHash)
