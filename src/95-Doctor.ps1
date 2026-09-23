#region Doctor

function Invoke-VsatDoctor {
    # Readiness checks in plain language. Nothing here contacts the internet.
    param([string[]]$Endpoints = @(), [string]$OutputDir, [switch]$OfflineOnly)
    $checks = [System.Collections.Generic.List[object]]::new()
    $add = { param($name, $status, $detail) $checks.Add([ordered]@{ name = $name; status = $status; detail = $detail }) }

    $v = $PSVersionTable.PSVersion
    if ($v.Major -ge 7 -and ($v.Major -gt 7 -or $v.Minor -ge 4)) { & $add 'PowerShell runtime' 'ok' "PowerShell $v ($($PSVersionTable.PSEdition))" }
    elseif ($v.Major -ge 7) { & $add 'PowerShell runtime' 'warn' "PowerShell $v; 7.4 or later is recommended (use the runtime in the offline package)" }
    else { & $add 'PowerShell runtime' 'warn' "Windows PowerShell $v is deprecated for PowerCLI; use the PowerShell 7 runtime shipped in the offline package" }

    $lm = $ExecutionContext.SessionState.LanguageMode
    if ($lm -eq 'FullLanguage') { & $add 'Language mode' 'ok' 'FullLanguage' }
    else { & $add 'Language mode' 'fail' "$lm - application control restricts PowerShell; VSAT does not bypass it. Ask your administrator to allow the signed package." }

    try { & $add 'Execution policy' 'ok' ("Effective policy: {0} (VSAT never changes it)" -f (Get-ExecutionPolicy)) } catch { & $add 'Execution policy' 'ok' 'Not applicable on this platform' }

    $modDir = Join-Path $script:VsatRoot 'modules'
    if (Test-Path -LiteralPath $modDir) { & $add 'Offline modules folder' 'ok' "Using process-local modules from $modDir" }
    else { & $add 'Offline modules folder' 'warn' 'No ./modules folder next to vsat.ps1; using modules already installed on this machine' }

    $pc = Get-Module -ListAvailable -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($pc) { & $add 'VMware PowerCLI' 'ok' "VMware.VimAutomation.Core $($pc.Version) found" }
    elseif ($OfflineOnly) { & $add 'VMware PowerCLI' 'warn' 'Not found - only needed for live vCenter/ESXi collection (replay and demo work without it)' }
    else { & $add 'VMware PowerCLI' 'fail' 'VMware.VimAutomation.Core not found. Use the complete offline package, or install VCF.PowerCLI on a connected machine and copy it into ./modules' }

    if (Initialize-VsatTls) { & $add 'TLS helper' 'ok' 'Certificate probing and per-endpoint pinning available' }
    else { & $add 'TLS helper' 'warn' 'Unavailable; endpoints must present certificates trusted by this machine' }

    if ($OutputDir) {
        try {
            $probeDir = if (Test-Path -LiteralPath $OutputDir) { $OutputDir } else { Split-Path -Parent ([IO.Path]::GetFullPath($OutputDir)) }
            if (-not (Test-Path -LiteralPath $probeDir)) { [void](New-Item -ItemType Directory -Path $probeDir -Force) }
            $t = Join-Path $probeDir ('.vsat-write-test-' + [guid]::NewGuid().ToString('N'))
            Set-Content -LiteralPath $t -Value 'x'; Remove-Item -LiteralPath $t -Force
            & $add 'Output folder' 'ok' "Writable: $probeDir"
        }
        catch { & $add 'Output folder' 'fail' "Cannot write to output location: $($_.Exception.Message)" }
    }

    try {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $p = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
        & $add 'Local UI listener' 'ok' "Can listen on 127.0.0.1 (tested port $p) without administrator rights"
    }
    catch { & $add 'Local UI listener' 'warn' "Cannot open a loopback listener ($($_.Exception.Message)); use -Cli" }

    foreach ($e in @($Endpoints | Where-Object { $_ })) {
        try {
            $c = Get-VsatCertificateInfo -HostName $e
            if (-not $c) { & $add "Endpoint $e" 'warn' 'TLS helper unavailable; connectivity not probed'; continue }
            if ($c.trusted) { & $add "Endpoint $e" 'ok' "Reachable; certificate trusted ($($c.subject), expires $($c.notAfter))" }
            else { & $add "Endpoint $e" 'warn' "Reachable; certificate NOT trusted ($($c.policyErrors)). Import the issuing CA, or approve this exact fingerprint with -TrustedThumbprint `"$e=$($c.sha256)`" after verifying it out of band." }
        }
        catch { & $add "Endpoint $e" 'fail' "Cannot reach ${e}:443 - $($_.Exception.Message)" }
    }
    & $add 'Internet access' 'ok' 'Not required: VSAT performs no downloads, telemetry or online lookups'
    return @($checks)
}

function Write-VsatDoctorReport {
    param([object[]]$Checks)
    Write-Host ''
    Write-Host 'VSAT readiness check' -ForegroundColor Cyan
    foreach ($c in $Checks) {
        $color = switch ($c.status) { 'ok' { 'Green' } 'warn' { 'Yellow' } default { 'Red' } }
        Write-Host ("  [{0,-4}] {1}: {2}" -f $c.status.ToUpperInvariant(), $c.name, (Protect-VsatText $c.detail)) -ForegroundColor $color
    }
    Write-Host ''
}

#endregion Doctor
