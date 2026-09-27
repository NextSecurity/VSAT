#region Doctor

function Get-VsatPowerCliFixCommand {
    # The install command for the pinned PowerCLI distribution (build/runtime.lock.json).
    try {
        $lock = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'runtime.lock.json')
        $distParts = $lock.powercli.distribution -split '\s+'
        return "Install-Module $($distParts[0]) -Scope CurrentUser -RequiredVersion $($distParts[1])"
    }
    catch { return 'Install-Module VCF.PowerCLI -Scope CurrentUser' }
}

function Get-VsatPowerCliStatus {
    # Accepts either install form: VCF.PowerCLI 9.x (current name) or VMware.PowerCLI 13.x
    # (older meta-module). Both ship VMware.VimAutomation.Core 13.x, the only module VSAT loads.
    param([object[]]$Modules = @(), [switch]$OfflineOnly)
    $fix = Get-VsatPowerCliFixCommand
    $pick = { param($n) @($Modules | Where-Object { $_ -and $_.Name -eq $n } | Sort-Object { [version]$_.Version } -Descending)[0] }
    $core = & $pick 'VMware.VimAutomation.Core'
    $vcf = & $pick 'VCF.PowerCLI'
    $old = & $pick 'VMware.PowerCLI'
    if (-not $core) {
        if ($OfflineOnly) { return [ordered]@{ status = 'warn'; detail = 'Not found - only needed for live vCenter/ESXi collection (replay and demo work without it)' } }
        return [ordered]@{ status = 'fail'; detail = "VMware.VimAutomation.Core not found. Fix: $fix (or use the complete offline package)" }
    }
    $dist = if ($vcf) { " (VCF.PowerCLI $($vcf.Version))" } elseif ($old) { " (VMware.PowerCLI $($old.Version))" } else { ' (module only, e.g. the offline package)' }
    if (([version]$core.Version).Major -lt 13) {
        return [ordered]@{ status = 'warn'; detail = "VMware.VimAutomation.Core $($core.Version)$dist is older than 13.x. Fix: $fix" }
    }
    $detail = "VMware.VimAutomation.Core $($core.Version) found$dist"
    if ($vcf -and $old) { $detail += ". Both VCF.PowerCLI and VMware.PowerCLI are installed; Broadcom recommends keeping only VCF.PowerCLI (Uninstall-Module VMware.PowerCLI -AllVersions)" }
    return [ordered]@{ status = 'ok'; detail = $detail }
}

function Invoke-VsatDoctor {
    # Readiness checks in plain language. Nothing here contacts the internet.
    param([string[]]$Endpoints = @(), [string]$OutputDir, [switch]$OfflineOnly)
    $checks = [System.Collections.Generic.List[object]]::new()
    $add = { param($name, $status, $detail) $checks.Add([ordered]@{ name = $name; status = $status; detail = $detail }) }

    $v = $PSVersionTable.PSVersion
    $isWindowsHost = [bool]$IsWindows
    $pwshUpgradeCmd = if ($isWindowsHost) { 'winget install --id Microsoft.PowerShell -e' }
    elseif (Test-Path '/etc/debian_version') { 'sudo apt-get install -y powershell' }
    elseif (Test-Path '/etc/redhat-release') { 'sudo dnf install -y powershell' }
    elseif ($IsMacOS) { 'brew install --cask powershell' }
    else { 'see https://aka.ms/install-powershell for your distro command' }
    if ($v.Major -ge 7 -and ($v.Major -gt 7 -or $v.Minor -ge 4)) { & $add 'PowerShell runtime' 'ok' "PowerShell $v ($($PSVersionTable.PSEdition))" }
    elseif ($v.Major -ge 7) { & $add 'PowerShell runtime' 'warn' "PowerShell $v is below the recommended 7.4. Fix: $pwshUpgradeCmd (or use the runtime in the offline package)" }
    else { & $add 'PowerShell runtime' 'warn' "Windows PowerShell $v is deprecated for PowerCLI. Fix: $pwshUpgradeCmd (or use the PowerShell 7 runtime shipped in the offline package)" }

    $lm = $ExecutionContext.SessionState.LanguageMode
    if ($lm -eq 'FullLanguage') { & $add 'Language mode' 'ok' 'FullLanguage' }
    else { & $add 'Language mode' 'fail' "$lm - application control restricts PowerShell; VSAT does not bypass it. Ask your administrator to allow the signed package." }

    try { & $add 'Execution policy' 'ok' ("Effective policy: {0} (VSAT never changes it)" -f (Get-ExecutionPolicy)) } catch { & $add 'Execution policy' 'ok' 'Not applicable on this platform' }

    $modDir = Join-Path $script:VsatRoot 'modules'
    if (Test-Path -LiteralPath $modDir) { & $add 'Offline modules folder' 'ok' "Using process-local modules from $modDir" }
    else { & $add 'Offline modules folder' 'warn' 'No ./modules folder next to vsat.ps1; using modules already installed on this machine' }

    $pcMods = @(Get-Module -ListAvailable -Name 'VMware.VimAutomation.Core', 'VCF.PowerCLI', 'VMware.PowerCLI' -ErrorAction SilentlyContinue)
    $pcs = Get-VsatPowerCliStatus -Modules $pcMods -OfflineOnly:$OfflineOnly
    & $add 'VMware PowerCLI' $pcs.status $pcs.detail

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
