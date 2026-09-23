#region Local UI server
# Loopback-only HTTP server for the guided UI. Loopback is not an authentication
# boundary, so every API call requires a per-run random token (delivered in the URL
# fragment, never sent in requests' URLs or logged), Host/Origin validation defeats
# DNS rebinding and cross-site requests, and no CORS headers are ever emitted.
# Implemented on TcpListener: no admin-only URL reservation (http.sys) is needed.

function New-VsatToken {
    $b = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return ([Convert]::ToBase64String($b) -replace '[+/=]', '')
}

function Start-VsatServer {
    param([Parameter(Mandatory)][hashtable]$State, [int]$Port = 0)
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.ExclusiveAddressUse = $true
        $listener.Start()
    }
    catch {
        if ($Port -ne 0) {
            Write-VsatLog -Level warn -Source 'ui' -Message "Port $Port on 127.0.0.1 is not available ($($_.Exception.Message)); selecting a free loopback port."
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
        }
        else { throw }
    }
    $State.port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $State.listener = $listener
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'MTA'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('State', $State)
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($script:VsatServerScript)
    $handle = $ps.BeginInvoke()
    return @{ ps = $ps; rs = $rs; handle = $handle; listener = $listener }
}

function Stop-VsatServer {
    param($Server)
    if (-not $Server) { return }
    try { $Server.listener.Stop() } catch { }
    try { $Server.ps.Stop(); $Server.ps.Dispose() } catch { }
    try { $Server.rs.Close(); $Server.rs.Dispose() } catch { }
}

$script:VsatServerScript = {
    $ErrorActionPreference = 'Stop'
    $enc = New-Object System.Text.UTF8Encoding($false)

    function Test-Eq([string]$a, [string]$b) {
        # Constant-time comparison for tokens.
        if ($null -eq $a -or $null -eq $b) { return $false }
        $x = $enc.GetBytes($a); $y = $enc.GetBytes($b)
        $diff = $x.Length -bxor $y.Length
        for ($i = 0; $i -lt [Math]::Min($x.Length, $y.Length); $i++) { $diff = $diff -bor ($x[$i] -bxor $y[$i]) }
        return ($diff -eq 0)
    }

    function Send-Response($stream, [int]$code, [string]$ctype, [byte[]]$body, [hashtable]$extra) {
        $reason = @{ 200 = 'OK'; 202 = 'Accepted'; 400 = 'Bad Request'; 401 = 'Unauthorized'; 403 = 'Forbidden'; 404 = 'Not Found'; 405 = 'Method Not Allowed'; 409 = 'Conflict'; 413 = 'Payload Too Large'; 421 = 'Misdirected Request'; 500 = 'Internal Server Error' }[$code]
        $h = New-Object System.Text.StringBuilder
        [void]$h.Append("HTTP/1.1 $code $reason`r`n")
        [void]$h.Append("Content-Type: $ctype`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n")
        [void]$h.Append("Cache-Control: no-store`r`nPragma: no-cache`r`nX-Content-Type-Options: nosniff`r`nX-Frame-Options: DENY`r`nReferrer-Policy: no-referrer`r`n")
        [void]$h.Append("Cross-Origin-Opener-Policy: same-origin`r`nCross-Origin-Resource-Policy: same-origin`r`nPermissions-Policy: camera=(), microphone=(), geolocation=()`r`n")
        if ($extra) { foreach ($k in $extra.Keys) { [void]$h.Append("${k}: $($extra[$k])`r`n") } }
        [void]$h.Append("`r`n")
        $hb = $enc.GetBytes($h.ToString())
        $stream.Write($hb, 0, $hb.Length)
        if ($body.Length) { $stream.Write($body, 0, $body.Length) }
        $stream.Flush()
    }

    function Send-Json($stream, [int]$code, $obj) {
        $json = ConvertTo-Json -InputObject $obj -Depth 12 -Compress
        Send-Response $stream $code 'application/json; charset=utf-8' ($enc.GetBytes($json)) $null
    }

    function Read-Request($client) {
        $client.ReceiveTimeout = 5000; $client.SendTimeout = 5000
        $stream = $client.GetStream()
        $buf = New-Object byte[] 1
        $head = [System.Collections.Generic.List[byte]]::new()
        while ($true) {
            $n = $stream.Read($buf, 0, 1)
            if ($n -le 0) { return $null }
            $head.Add($buf[0])
            if ($head.Count -gt 16384) { throw 'header-too-large' }
            $c = $head.Count
            if ($c -ge 4 -and $head[$c - 4] -eq 13 -and $head[$c - 3] -eq 10 -and $head[$c - 2] -eq 13 -and $head[$c - 1] -eq 10) { break }
        }
        $text = [System.Text.Encoding]::ASCII.GetString($head.ToArray())
        $lines = $text -split "`r`n"
        $rl = $lines[0] -split ' '
        if ($rl.Count -ne 3 -or $rl[2] -notmatch '^HTTP/1\.[01]$') { throw 'bad-request-line' }
        $headers = @{}
        foreach ($l in $lines[1..($lines.Count - 1)]) {
            if (-not $l) { continue }
            $i = $l.IndexOf(':')
            if ($i -lt 1) { throw 'bad-header' }
            $k = $l.Substring(0, $i).Trim().ToLowerInvariant()
            if ($headers.ContainsKey($k)) { throw 'duplicate-header' }
            $headers[$k] = $l.Substring($i + 1).Trim()
        }
        $body = ''
        if ($headers.ContainsKey('content-length')) {
            $len = 0
            if (-not [int]::TryParse($headers['content-length'], [ref]$len) -or $len -lt 0) { throw 'bad-length' }
            if ($len -gt 65536) { throw 'too-large' }
            $bb = New-Object byte[] $len; $off = 0
            while ($off -lt $len) { $r = $stream.Read($bb, $off, $len - $off); if ($r -le 0) { break }; $off += $r }
            $body = $enc.GetString($bb, 0, $off)
        }
        if ($headers.ContainsKey('transfer-encoding')) { throw 'chunked-not-supported' }
        return @{ method = $rl[0]; target = $rl[1]; headers = $headers; body = $body; stream = $stream }
    }

    function Get-PublicState {
        $p = $State.progress
        return [ordered]@{
            version = $State.version; mode = $State.mode; profile = $State.profile; phase = $State.phase
            doctor = $State.doctor; endpoints = @($State.endpoints); nsx = $State.nsx
            progress = [ordered]@{ phase = $p.phase; message = $p.message; step = $p.step; totalSteps = $p.totalSteps; counts = $p.counts; log = @($p.log | Select-Object -Last 50) }
            result = $State.result
        }
    }

    function Test-Str($v, [int]$max, [string]$pattern) {
        if ($v -isnot [string] -or $v.Length -gt $max) { return $false }
        if ($pattern -and $v -notmatch $pattern) { return $false }
        return $true
    }

    $listener = $State.listener
    $allowedHosts = @("127.0.0.1:$($State.port)", "localhost:$($State.port)")
    $allowedOrigins = @("http://127.0.0.1:$($State.port)", "http://localhost:$($State.port)")
    while (-not $State.shutdown) {
        $client = $null
        try { $client = $listener.AcceptTcpClient() } catch { break }
        try {
            $req = $null
            try { $req = Read-Request $client } catch { try { Send-Response $client.GetStream() 400 'text/plain' ($enc.GetBytes('Bad request')) $null } catch { }; continue }
            if (-not $req) { continue }
            $s = $req.stream; $h = $req.headers
            # DNS-rebinding defense: the Host header must be the literal loopback authority.
            if (-not $h.ContainsKey('host') -or $allowedHosts -notcontains $h['host'].ToLowerInvariant()) { Send-Response $s 421 'text/plain' ($enc.GetBytes('Invalid Host')) $null; continue }
            if ($h.ContainsKey('origin') -and $allowedOrigins -notcontains $h['origin'].ToLowerInvariant()) { Send-Response $s 403 'text/plain' ($enc.GetBytes('Cross-origin request rejected')) $null; continue }
            if ($h.ContainsKey('sec-fetch-site') -and $h['sec-fetch-site'] -eq 'cross-site') { Send-Response $s 403 'text/plain' ($enc.GetBytes('Cross-site request rejected')) $null; continue }
            $path = ($req.target -split '\?')[0]
            $method = $req.method
            if ($method -eq 'GET' -and $path -eq '/') {
                Send-Response $s 200 'text/html; charset=utf-8' ($enc.GetBytes($State.appHtml)) @{ 'Content-Security-Policy' = $State.appCsp }
                continue
            }
            if ($method -eq 'GET' -and $path -eq '/favicon.ico') { Send-Response $s 404 'text/plain' ($enc.GetBytes('')) $null; continue }
            $cookieOk = $false
            if ($h.ContainsKey('cookie')) { foreach ($c in $h['cookie'].Split(';')) { $kv = $c.Trim().Split('=', 2); if ($kv.Count -eq 2 -and $kv[0] -eq 'vsat_s' -and (Test-Eq $kv[1] $State.cookieToken)) { $cookieOk = $true } } }
            if ($method -eq 'GET' -and $path -eq '/report') {
                if (-not $cookieOk) { Send-Response $s 401 'text/plain' ($enc.GetBytes('Open the report from the VSAT window.')) $null; continue }
                if (-not $State.reportHtml) { Send-Response $s 404 'text/plain' ($enc.GetBytes('No report yet.')) $null; continue }
                Send-Response $s 200 'text/html; charset=utf-8' ($enc.GetBytes($State.reportHtml)) @{ 'Content-Security-Policy' = $State.reportCsp }
                continue
            }
            if (-not $path.StartsWith('/api/')) { Send-Response $s 404 'text/plain' ($enc.GetBytes('Not found')) $null; continue }
            if (-not $h.ContainsKey('x-vsat-token') -or -not (Test-Eq $h['x-vsat-token'] $State.token)) { Send-Json $s 401 @{ ok = $false; error = 'Missing or invalid session token. Open VSAT from the link printed in the terminal.' }; continue }
            if ($method -eq 'GET' -and $path -eq '/api/state') {
                Send-Response $s 200 'application/json; charset=utf-8' ($enc.GetBytes((ConvertTo-Json -InputObject (Get-PublicState) -Depth 14 -Compress))) @{ 'Set-Cookie' = "vsat_s=$($State.cookieToken); Path=/; HttpOnly; SameSite=Strict" }
                continue
            }
            if ($method -ne 'POST') { Send-Json $s 405 @{ ok = $false; error = 'Method not allowed' }; continue }
            if (-not $h.ContainsKey('content-type') -or $h['content-type'] -notmatch '^application/json(;|$)') { Send-Json $s 400 @{ ok = $false; error = 'JSON body required' }; continue }
            $body = $null
            try { $body = if ($req.body) { $req.body | ConvertFrom-Json } else { [pscustomobject]@{} } } catch { Send-Json $s 400 @{ ok = $false; error = 'Malformed JSON' }; continue }
            $busy = $State.phase -in @('running', 'discovering')
            switch ($path) {
                '/api/endpoints' {
                    if ($busy) { Send-Json $s 409 @{ ok = $false; error = 'An operation is in progress.' }; break }
                    $t = [string]$body.type; $addr = $body.address; $user = $body.username; $pw = $body.password; $tp = $body.thumbprint
                    if ($t -notin @('vcenter', 'esxi', 'nsx')) { Send-Json $s 400 @{ ok = $false; error = 'Endpoint type must be vcenter, esxi or nsx.' }; break }
                    if (-not (Test-Str $addr 253 '^[A-Za-z0-9][A-Za-z0-9.\-:\[\]]*$')) { Send-Json $s 400 @{ ok = $false; error = 'Enter a host name or IP address.' }; break }
                    if (-not (Test-Str $user 256 '^[^\x00-\x1f]+$')) { Send-Json $s 400 @{ ok = $false; error = 'Enter a user name.' }; break }
                    if (-not (Test-Str $pw 1024 '')) { Send-Json $s 400 @{ ok = $false; error = 'Enter a password.' }; break }
                    if ($tp -and -not (Test-Str $tp 100 '^[0-9A-Fa-f:]{64,95}$')) { Send-Json $s 400 @{ ok = $false; error = 'Fingerprint must be a SHA-256 hex value.' }; break }
                    $sec = New-Object System.Security.SecureString
                    foreach ($ch in $pw.ToCharArray()) { $sec.AppendChar($ch) }
                    $sec.MakeReadOnly()
                    $pw = $null; $body.password = $null
                    $cred = New-Object System.Management.Automation.PSCredential($user, $sec)
                    $State.queue.Enqueue(@{ type = 'add-endpoint'; endpointType = $t; address = $addr.ToLowerInvariant(); credential = $cred; thumbprint = $tp })
                    Send-Json $s 202 @{ ok = $true; endpoint = @{ type = $t; address = $addr; status = 'connecting' } }
                }
                '/api/endpoints/remove' {
                    if ($busy) { Send-Json $s 409 @{ ok = $false; error = 'An operation is in progress.' }; break }
                    if (-not (Test-Str $body.id 40 '^[a-z0-9-]+$')) { Send-Json $s 400 @{ ok = $false; error = 'Invalid endpoint id' }; break }
                    $State.queue.Enqueue(@{ type = 'remove-endpoint'; id = $body.id }); Send-Json $s 202 @{ ok = $true }
                }
                '/api/nsx' {
                    if ($body.declaredAbsent -isnot [bool]) { Send-Json $s 400 @{ ok = $false; error = 'declaredAbsent must be true or false' }; break }
                    $State.queue.Enqueue(@{ type = 'nsx'; declaredAbsent = $body.declaredAbsent }); Send-Json $s 202 @{ ok = $true }
                }
                '/api/discover' { if ($busy) { Send-Json $s 409 @{ ok = $false; error = 'An operation is in progress.' }; break }; $State.queue.Enqueue(@{ type = 'discover' }); Send-Json $s 202 @{ ok = $true } }
                '/api/run' {
                    if ($busy) { Send-Json $s 409 @{ ok = $false; error = 'An operation is in progress.' }; break }
                    $pf = [string]$body.profile; if (-not $pf) { $pf = 'standard' }
                    if ($pf -notin @('standard', 'strict')) { Send-Json $s 400 @{ ok = $false; error = 'Profile must be standard or strict.' }; break }
                    $State.phase = 'running'
                    $State.queue.Enqueue(@{ type = 'run'; profile = $pf }); Send-Json $s 202 @{ ok = $true }
                }
                '/api/cancel' { $State.progress.cancel = $true; Send-Json $s 202 @{ ok = $true } }
                '/api/shutdown' { $State.queue.Enqueue(@{ type = 'shutdown' }); Send-Json $s 202 @{ ok = $true } }
                default { Send-Json $s 404 @{ ok = $false; error = 'Unknown API' } }
            }
        }
        catch { try { Send-Json $client.GetStream() 500 @{ ok = $false; error = 'Internal error' } } catch { } }
        finally { if ($client) { try { $client.Close() } catch { } } }
    }
}

#endregion Local UI server
