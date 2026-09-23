#region Transport
# Read-only HTTPS client for NSX and the vCenter appliance REST API.
# - Only GET, plus an explicit allowlist of session create/destroy operations.
# - Redirects are never followed (credentials must not be forwarded to another host).
# - TLS validation uses the OS trust store; an operator-approved per-endpoint SHA-256
#   pin is the only alternative. Global validation is never disabled.

$script:VsatPins = @{}
$script:VsatPinTypeLoaded = $false
$script:VsatRestAllowlist = @(
    @{ Method = 'POST';   Path = '/api/session/create' }    # NSX session login
    @{ Method = 'POST';   Path = '/api/session/destroy' }   # NSX session logout
    @{ Method = 'POST';   Path = '/api/session' }           # vCenter REST session login
    @{ Method = 'DELETE'; Path = '/api/session' }           # vCenter REST session logout
)
$script:VsatRestMaxBytes = 64MB
$script:VsatRestTimeoutSec = 60
$script:VsatRestOperations = [System.Collections.Generic.List[string]]::new()

function Initialize-VsatTls {
    if ($script:VsatPinTypeLoaded) { return $true }
    try {
        if ($PSVersionTable.PSVersion.Major -lt 6) { Add-Type -AssemblyName System.Net.Http }
        if (-not ('VsatTls' -as [type])) {
            $refs = @('System.Net.Http', 'System.Net.Primitives', 'System.Net.Security', 'System.Net.Sockets', 'System.Security.Cryptography.X509Certificates', 'System.Security.Cryptography', 'System.Runtime', 'System.Collections')
            $src = @'
using System;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public static class VsatTls {
    public static string Sha256(X509Certificate cert) {
        using (var sha = SHA256.Create()) {
            return BitConverter.ToString(sha.ComputeHash(cert.GetRawCertData())).Replace("-", "").ToLowerInvariant();
        }
    }
    // Accepts a certificate only when it chains to a trusted root with a matching name,
    // or when its SHA-256 fingerprint equals the operator-approved pin for this endpoint.
    public static HttpClientHandler CreateHandler(string pin) {
        var h = new HttpClientHandler();
        h.AllowAutoRedirect = false;
        h.UseCookies = true;
        h.CookieContainer = new System.Net.CookieContainer();
        h.UseProxy = false;
        h.UseDefaultCredentials = false;
        if (!String.IsNullOrEmpty(pin)) {
            string expected = pin.Replace(":", "").ToLowerInvariant();
            h.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) => {
                if (cert == null) return false;
                return String.Equals(Sha256(cert), expected, StringComparison.Ordinal);
            };
        }
        return h;
    }
    // Reads the presented certificate without sending any application data or credentials.
    public static string[] Probe(string host, int port, int timeoutMs) {
        using (var client = new TcpClient()) {
            var ar = client.BeginConnect(host, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) throw new TimeoutException("TCP connect timeout");
            client.EndConnect(ar);
            X509Certificate seen = null; SslPolicyErrors seenErrors = SslPolicyErrors.None;
            using (var ssl = new SslStream(client.GetStream(), false, (s, c, ch, e) => { seen = c; seenErrors = e; return true; })) {
                ssl.ReadTimeout = timeoutMs; ssl.WriteTimeout = timeoutMs;
                ssl.AuthenticateAsClient(host);
                var c2 = new X509Certificate2(seen);
                return new string[] { Sha256(seen), c2.Subject, c2.Issuer, c2.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), seenErrors.ToString() };
            }
        }
    }
}
'@
            Add-Type -TypeDefinition $src -Language CSharp -ReferencedAssemblies $refs -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
        }
        $script:VsatPinTypeLoaded = $true
        return $true
    }
    catch {
        Write-VsatLog -Level warn -Source 'tls' -Message "TLS helper unavailable (Add-Type blocked?): $($_.Exception.Message). Certificate pinning disabled; OS trust store is still enforced."
        return $false
    }
}

function Register-VsatPins {
    param([string[]]$Pins)
    foreach ($p in @($Pins)) {
        if (-not $p) { continue }
        if ($p -match '^\s*([^=\s]+)\s*=\s*(SHA256:[A-Za-z0-9+/]{43}=?)\s*$') { $script:VsatSshPins[$Matches[1].ToLowerInvariant()] = $Matches[2].TrimEnd('='); continue }
        if ($p -notmatch '^\s*([^=\s]+)\s*=\s*([0-9A-Fa-f:]{64,95})\s*$') { throw "Invalid -TrustedThumbprint '$p'. Expected host=SHA256HEX." }
        $hex = ($Matches[2] -replace ':', '').ToLowerInvariant()
        if ($hex.Length -ne 64) { throw "Invalid SHA-256 fingerprint for $($Matches[1])." }
        $script:VsatPins[$Matches[1].ToLowerInvariant()] = $hex
    }
}

function Split-VsatAddress {
    # "host", "host:port", "[v6]:port" or bare IPv6 -> @{ host; port }
    param([Parameter(Mandatory)][string]$Address, [int]$DefaultPort = 443)
    if ($Address -match '^\[(.+)\](?::(\d+))?$') { return @{ host = $Matches[1]; port = $(if ($Matches[2]) { [int]$Matches[2] } else { $DefaultPort }) } }
    if ($Address -match '^([^:]+):(\d{1,5})$') { return @{ host = $Matches[1]; port = [int]$Matches[2] } }
    return @{ host = $Address; port = $DefaultPort }
}

function Get-VsatCertificateInfo {
    param([Parameter(Mandatory)][string]$HostName, [int]$Port = 0)
    if (-not (Initialize-VsatTls)) { return $null }
    $a = Split-VsatAddress $HostName
    if ($Port -eq 0) { $Port = $a.port }
    $r = [VsatTls]::Probe($a.host, $Port, 8000)
    return [ordered]@{ sha256 = $r[0]; subject = $r[1]; issuer = $r[2]; notAfter = $r[3]; policyErrors = $r[4]; trusted = ($r[4] -eq 'None') }
}

function Assert-VsatRestAllowed {
    # Read-only is defined by operation semantics: GET, or an allowlisted session operation.
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path)
    $m = $Method.ToUpperInvariant()
    $p = ($Path -split '\?')[0]
    if ($p -notmatch '^/[A-Za-z0-9_\-./%:=,~@]*$' -or $p -match '\.\.|//|\\') { throw "VSAT read-only guard: rejected path '$Path'." }
    if ($m -eq 'GET') { return }
    foreach ($a in $script:VsatRestAllowlist) { if ($a.Method -eq $m -and $a.Path -eq $p) { return } }
    throw "VSAT read-only guard: $m $p is not an approved session/read operation."
}

function New-VsatRestSession {
    param([Parameter(Mandatory)][string]$Address, [ValidateSet('nsx', 'vcenter')][string]$Kind = 'nsx')
    if (-not (Initialize-VsatTls)) {
        $pinned = $script:VsatPins.ContainsKey($Address.ToLowerInvariant())
        if ($pinned) { throw "A certificate pin was supplied for $Address but the TLS helper is unavailable; refusing to connect without the requested pin." }
        if ($PSVersionTable.PSVersion.Major -lt 6) { Add-Type -AssemblyName System.Net.Http }
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false
        $handler.CookieContainer = New-Object System.Net.CookieContainer
    }
    else {
        $pin = $script:VsatPins[$Address.ToLowerInvariant()]
        $handler = [VsatTls]::CreateHandler($pin)
    }
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($script:VsatRestTimeoutSec)
    $baseAddr = if ($Address -match '^[0-9a-fA-F:]+$' -and $Address.Contains(':')) { "[$Address]" } else { $Address }
    return [ordered]@{ address = $Address; base = "https://$baseAddr"; kind = $Kind; client = $client; handler = $handler; headers = @{}; calls = 0 }
}

function Invoke-VsatRest {
    param(
        [Parameter(Mandatory)]$Session,
        [ValidateSet('GET', 'POST', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [string]$Body,
        [string]$ContentType = 'application/json',
        [hashtable]$Headers,
        [switch]$Raw
    )
    Assert-VsatRestAllowed -Method $Method -Path $Path
    $attempt = 0
    while ($true) {
        $attempt++
        $req = New-Object System.Net.Http.HttpRequestMessage((New-Object System.Net.Http.HttpMethod($Method)), ($Session.base + $Path))
        [void]$req.Headers.TryAddWithoutValidation('Accept', 'application/json')
        foreach ($k in $Session.headers.Keys) { [void]$req.Headers.TryAddWithoutValidation($k, [string]$Session.headers[$k]) }
        if ($Headers) { foreach ($k in $Headers.Keys) { [void]$req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k]) } }
        if ($null -ne $Body) { $req.Content = New-Object System.Net.Http.StringContent($Body, [System.Text.Encoding]::UTF8, $ContentType) }
        $Session.calls++
        $script:VsatRestOperations.Add("$Method $($Session.address)$(($Path -split '\?')[0])")
        try {
            $resp = $Session.client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        }
        catch {
            $inner = $_.Exception
            while ($inner.InnerException) { $inner = $inner.InnerException }
            throw "Connection to $($Session.address) failed: $($inner.Message)"
        }
        finally { $req.Dispose() }
        $code = [int]$resp.StatusCode
        if (($code -eq 429 -or $code -eq 503) -and $attempt -lt 4) {
            $delay = [Math]::Min(30, [Math]::Pow(2, $attempt))
            $ra = $resp.Headers.RetryAfter
            if ($ra -and $ra.Delta) { $delay = [Math]::Min(60, $ra.Delta.TotalSeconds) }
            $resp.Dispose()
            Write-VsatLog -Level warn -Source 'rest' -Message "$($Session.address) throttled ($code); backing off $delay s"
            Start-Sleep -Seconds $delay
            continue
        }
        if ($code -ge 300 -and $code -lt 400) {
            $resp.Dispose()
            throw "Endpoint $($Session.address) returned redirect $code for $Path; redirects are not followed to protect credentials."
        }
        $len = $resp.Content.Headers.ContentLength
        if ($len -and $len -gt $script:VsatRestMaxBytes) { $resp.Dispose(); throw "Response from $Path exceeds size limit." }
        $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($text.Length -gt $script:VsatRestMaxBytes) { $resp.Dispose(); throw "Response from $Path exceeds size limit." }
        if ($code -ge 400) {
            $resp.Dispose()
            $snippet = if ($text.Length -gt 300) { $text.Substring(0, 300) } else { $text }
            throw ("HTTP {0} {1} on {2}: {3}" -f $code, $resp.ReasonPhrase, ($Path -split '\?')[0], (Protect-VsatText $snippet))
        }
        if ($Raw) { $out = @{ status = $code; headers = $resp.Headers; body = $text }; $resp.Dispose(); return $out }
        $resp.Dispose()
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        return (ConvertFrom-VsatJson $text)
    }
}

function Get-VsatNsxPaged {
    # Follows NSX cursors; detects repeated cursors and truncated result sets.
    param([Parameter(Mandatory)]$Session, [Parameter(Mandatory)][string]$Path, [int]$MaxPages = 2000, [int]$PageSize = 1000)
    $items = [System.Collections.Generic.List[object]]::new()
    $cursor = $null; $seen = @{}; $expected = $null; $pages = 0
    do {
        $sep = if ($Path.Contains('?')) { '&' } else { '?' }
        $p = "$Path${sep}page_size=$PageSize"
        if ($cursor) { $p += '&cursor=' + [uri]::EscapeDataString($cursor) }
        $r = Invoke-VsatRest -Session $Session -Path $p
        $pages++
        foreach ($i in @(Get-VsatProp $r 'results' @())) { $items.Add($i) }
        $rc = Get-VsatProp $r 'result_count'
        if ($null -ne $rc) { $expected = [int]$rc }
        $cursor = Get-VsatProp $r 'cursor'
        if ($cursor) {
            if ($seen.ContainsKey($cursor)) { throw "NSX pagination loop detected on $Path" }
            $seen[$cursor] = $true
        }
        if ($pages -ge $MaxPages) { throw "NSX pagination exceeded $MaxPages pages on $Path" }
    } while ($cursor)
    $truncated = ($null -ne $expected -and $items.Count -lt $expected)
    return [ordered]@{ items = $items.ToArray(); truncated = $truncated; expected = $expected }
}

function Close-VsatRestSession {
    param($Session)
    if (-not $Session) { return }
    try {
        if ($Session.kind -eq 'nsx' -and $Session.headers.ContainsKey('X-XSRF-TOKEN')) { [void](Invoke-VsatRest -Session $Session -Method POST -Path '/api/session/destroy' -Raw) }
        elseif ($Session.kind -eq 'vcenter' -and $Session.headers.ContainsKey('vmware-api-session-id')) { [void](Invoke-VsatRest -Session $Session -Method DELETE -Path '/api/session' -Raw) }
    }
    catch { Write-VsatLog -Level debug -Source 'rest' -Message "Logout from $($Session.address) failed: $($_.Exception.Message)" }
    finally {
        $Session.headers.Clear()
        try { $Session.client.Dispose() } catch { }
    }
}

#endregion Transport
