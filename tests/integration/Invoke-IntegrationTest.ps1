<#
.SYNOPSIS
    Live-protocol integration test: VSAT against govmomi vcsim (vSphere API simulator) and a
    mock NSX Manager, over TLS with per-endpoint certificate pinning.
.DESCRIPTION
    Requires: vcsim binary, python3, openssl, and PowerCLI (VMware.VimAutomation.Core) either
    installed or in -ModulesPath. Verifies real PowerCLI/REST code paths that fixture tests
    cannot: property paths, pagination, session handling, redirect refusal, error
    classification, read-only behavior and secret hygiene. A simulator is not a real lab;
    passing this test does not establish product support for any vSphere/NSX version.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VcsimPath,
    [string]$ModulesPath,
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) ('vsat-it-' + [guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$failures = [System.Collections.Generic.List[string]]::new()
function Assert-It([bool]$Condition, [string]$Message) { if ($Condition) { Write-Host "  PASS $Message" -ForegroundColor Green } else { Write-Host "  FAIL $Message" -ForegroundColor Red; $failures.Add($Message) } }

$vc = $null; $mock = $null
try {
    Copy-Item (Join-Path $PSScriptRoot 'nsx_mock.py') $WorkDir
    & openssl req -x509 -newkey rsa:2048 -nodes -keyout (Join-Path $WorkDir 'key.pem') -out (Join-Path $WorkDir 'cert.pem') -days 2 -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' 2>$null
    $vc = Start-Process -FilePath $VcsimPath -ArgumentList '-l', '127.0.0.1:18989', '-dc', '1', '-cluster', '2', '-host', '2', '-vm', '2', '-standalone-host', '1', '-pod', '0', '-ds', '2', '-pg', '2' -PassThru -RedirectStandardOutput (Join-Path $WorkDir 'vcsim.log') -RedirectStandardError (Join-Path $WorkDir 'vcsim.err')
    $mock = Start-Process -FilePath python3 -ArgumentList 'nsx_mock.py', '18443' -WorkingDirectory $WorkDir -PassThru -RedirectStandardOutput (Join-Path $WorkDir 'mock.out') -RedirectStandardError (Join-Path $WorkDir 'mock.err')
    Start-Sleep -Seconds 3

    $app = Join-Path $WorkDir 'app'
    New-Item -ItemType Directory -Force $app | Out-Null
    Copy-Item (Join-Path $root 'vsat.ps1') $app
    if ($ModulesPath) { Copy-Item -Recurse $ModulesPath (Join-Path $app 'modules') }

    . (Join-Path $root 'vsat.ps1') -LibraryMode
    $fpVc = (Get-VsatCertificateInfo -HostName '127.0.0.1:18989').sha256
    $fpNsx = (Get-VsatCertificateInfo -HostName '127.0.0.1:18443').sha256
    $out = Join-Path $WorkDir 'out'
    $script = @"
`$c = New-Object System.Management.Automation.PSCredential('user', (ConvertTo-SecureString 'pass' -AsPlainText -Force))
`$n = New-Object System.Management.Automation.PSCredential('auditor', (ConvertTo-SecureString 'S3cret!pw' -AsPlainText -Force))
& '$app/vsat.ps1' -Cli -Server 127.0.0.1:18989 -NsxServer 127.0.0.1:18443 -Credential `$c -NsxCredential `$n -TrustedThumbprint '127.0.0.1:18989=$fpVc','127.0.0.1:18443=$fpNsx' -Redact -OutputPath '$out'
exit `$LASTEXITCODE
"@
    Set-Content -Path (Join-Path $WorkDir 'run.ps1') -Value $script
    & pwsh -NoProfile -File (Join-Path $WorkDir 'run.ps1') *> (Join-Path $WorkDir 'vsat.out')
    $exit = $LASTEXITCODE
    Write-Host "VSAT exit code: $exit"
    $r = Get-Content -Raw (Join-Path $out 'results.json') | ConvertFrom-Json
    $ev = Get-Content -Raw (Join-Path $out 'evidence.json') | ConvertFrom-Json

    Assert-It ($exit -eq 2) 'exit code 2 (incomplete: simulator lacks esxcli/NSX scope)'
    Assert-It (@($ev.scope.endpoints | Where-Object { $_.status -in @('collected', 'partial') }).Count -eq 2) 'both endpoints collected'
    foreach ($c in 'vsphere.vcenter', 'vsphere.inventory', 'vsphere.hosts', 'vsphere.vds', 'vsphere.datastores', 'vsphere.vms', 'nsx.manager', 'nsx.networking', 'nsx.groups', 'nsx.dfw', 'nsx.inventory') {
        $rec = @($ev.collection.collectors | Where-Object { $_.name -eq $c })[0]
        Assert-It ($rec -and $rec.status -eq 'ok') "collector $c ok ($($rec.status) $($rec.error))"
    }
    Assert-It (@($ev.assets | Where-Object { $_.type -eq 'host' }).Count -eq 5) 'five simulated hosts inventoried'
    Assert-It (@($ev.assets | Where-Object { $_.type -eq 'vm' }).Count -ge 6) 'simulated VMs inventoried'
    Assert-It (@($ev.assets | Where-Object { $_.type -eq 'nsx-group' }).Count -eq 3) 'paginated NSX groups (3 over 2 pages)'
    $f = { param($id, $name) @($r.findings | Where-Object { $_.ruleId -eq $id -and (-not $name -or $_.assetName -eq $name) })[0] }
    Assert-It ((& $f 'NSX-DFW-ANYANY' 'any-any').result -eq 'FAIL') 'any-any allow rule detected'
    Assert-It ((& $f 'NSX-DFW-EMPTY-GROUP' 'to-empty').result -eq 'FAIL') 'rule referencing empty realized group detected'
    Assert-It ((& $f 'NSX-DFW-DEFAULT').result -eq 'PASS') 'default DROP rule recognized'
    Assert-It ((& $f 'NSX-NAT-BYPASS').result -eq 'FAIL') 'NAT firewall bypass detected'
    Assert-It ((& $f 'NSX-IDS').result -eq 'UNKNOWN') '403 classified as UNKNOWN (not PASS)'
    $mgr = @($ev.assets | Where-Object { $_.type -eq 'nsx-manager' })[0]
    Assert-It ($mgr.facts.ntp.status -eq 'error' -and $mgr.facts.ntp.error -match 'redirect') 'credential-bearing redirect refused'
    Assert-It ($mgr.facts.federation.status -eq 'unsupported') '404 classified as unsupported'
    Assert-It (($r.coverage.domains | Where-Object { $_.id -eq 'nsx' }).state -eq 'PARTIAL') 'out-of-scope compute manager => NSX PARTIAL'
    $log = Get-Content -Raw (Join-Path $WorkDir 'requests.log')
    Assert-It ($log -notmatch 'MUTATION') 'no mutating API calls reached NSX'
    Assert-It ($log -match 'POST /api/session/destroy') 'NSX session logged out'
    $leak = @(Get-ChildItem -Recurse -File $out | Where-Object { $_.Extension -ne '.zip' -and (Get-Content -Raw $_.FullName) -match [regex]::Escape('S3cret!pw') })
    Assert-It ($leak.Count -eq 0) 'NSX password absent from every output'
    Assert-It (-not ((Get-Content -Raw (Join-Path $WorkDir 'vsat.out')) -match [regex]::Escape('S3cret!pw'))) 'NSX password absent from console output'
    Assert-It ((Get-Content -Raw (Join-Path $out 'report.html')) -notmatch '<script>alert\(1\)</script>') 'hostile NSX segment name not rendered as markup'
}
finally {
    foreach ($p in @($vc, $mock)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}
if ($failures.Count) { Write-Host "$($failures.Count) integration assertion(s) failed. Work dir: $WorkDir" -ForegroundColor Red; exit 1 }
Write-Host 'Integration test passed.' -ForegroundColor Green
Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
exit 0
