BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $state = [hashtable]::Synchronized(@{})
    $state.version = 'test'; $state.mode = 'demo'; $state.profile = 'standard'; $state.phase = 'setup'
    $state.token = New-VsatToken; $state.cookieToken = New-VsatToken
    $state.queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $state.shutdown = $false
    $state.endpoints = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $state.nsx = @{ discovery = @{ status = 'unknown' }; declaredAbsent = $false }
    $state.progress = [hashtable]::Synchronized(@{ phase = 'setup'; message = ''; step = 0; totalSteps = 0; counts = @{}; log = @(); cancel = $false })
    $state.doctor = @{ checks = @() }
    $state.appHtml = '<html>app</html>'; $state.appCsp = "default-src 'none'"
    $state.reportHtml = '<html>report</html>'; $state.reportCsp = "default-src 'none'"
    $state.result = $null
    $script:State = $state
    $script:Srv = Start-VsatServer -State $state -Port 0
    $script:Base = "http://127.0.0.1:$($state.port)"
    function Invoke-Raw([string]$Method, [string]$Path, [hashtable]$Headers, [string]$Body) {
        # Raw TCP so the test fully controls Host/Origin headers.
        $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $script:State.port)
        $s = $c.GetStream()
        $h = @{ Host = "127.0.0.1:$($script:State.port)" }
        if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
        $b = if ($Body) { [Text.Encoding]::UTF8.GetBytes($Body) } else { @() }
        $req = "$Method $Path HTTP/1.1`r`n" + (($h.Keys | ForEach-Object { "${_}: $($h[$_])" }) -join "`r`n") + "`r`nContent-Length: $($b.Length)`r`n`r`n"
        $rb = [Text.Encoding]::ASCII.GetBytes($req); $s.Write($rb, 0, $rb.Length); if ($b.Length) { $s.Write($b, 0, $b.Length) }
        $sr = New-Object IO.StreamReader($s); $resp = $sr.ReadToEnd(); $c.Close()
        $code = [int]($resp -split ' ')[1]
        return @{ code = $code; text = $resp }
    }
}
AfterAll { $script:State.shutdown = $true; Stop-VsatServer $script:Srv }

Describe 'Local UI server security' {
    It 'binds to loopback only' { $script:Srv.listener.LocalEndpoint.Address.ToString() | Should -Be '127.0.0.1' }
    It 'serves the app with a CSP and security headers' {
        $r = Invoke-Raw GET '/'
        $r.code | Should -Be 200
        $r.text | Should -Match 'Content-Security-Policy:'
        $r.text | Should -Match 'X-Frame-Options: DENY'
        $r.text | Should -Not -Match 'Access-Control-Allow-Origin'
    }
    It 'rejects DNS-rebinding Host headers' { (Invoke-Raw GET '/api/state' @{ Host = "attacker.example:$($script:State.port)"; 'X-VSAT-Token' = $script:State.token }).code | Should -Be 421 }
    It 'rejects cross-origin requests' { (Invoke-Raw GET '/api/state' @{ Origin = 'http://attacker.example'; 'X-VSAT-Token' = $script:State.token }).code | Should -Be 403 }
    It 'rejects requests without the session token' { (Invoke-Raw GET '/api/state').code | Should -Be 401 }
    It 'rejects a wrong token' { (Invoke-Raw GET '/api/state' @{ 'X-VSAT-Token' = 'x' + $script:State.token }).code | Should -Be 401 }
    It 'refuses CORS preflight' { (Invoke-Raw OPTIONS '/api/run' @{ 'X-VSAT-Token' = $script:State.token }).code | Should -Be 405 }
    It 'requires a JSON content type (blocks simple-request CSRF)' { (Invoke-Raw POST '/api/run' @{ 'X-VSAT-Token' = $script:State.token; 'Content-Type' = 'text/plain' } '{}').code | Should -Be 400 }
    It 'validates input schemas' { (Invoke-Raw POST '/api/endpoints' @{ 'X-VSAT-Token' = $script:State.token; 'Content-Type' = 'application/json' } '{"type":"vcenter","address":"$(rm -rf)","username":"u","password":"p"}').code | Should -Be 400 }
    It 'requires the HttpOnly SameSite cookie for the report' {
        (Invoke-Raw GET '/report').code | Should -Be 401
        $r = Invoke-Raw GET '/api/state' @{ 'X-VSAT-Token' = $script:State.token }
        $r.text | Should -Match 'Set-Cookie: vsat_s=[^;]+; Path=/; HttpOnly; SameSite=Strict'
        (Invoke-Raw GET '/report' @{ Cookie = "vsat_s=$($script:State.cookieToken)" }).code | Should -Be 200
    }
    It 'queues credentials as SecureString and never echoes the password' {
        $r = Invoke-Raw POST '/api/endpoints' @{ 'X-VSAT-Token' = $script:State.token; 'Content-Type' = 'application/json' } '{"type":"nsx","address":"nsx01.example.local","username":"auditor","password":"Canary-Pw-555"}'
        $r.code | Should -Be 202
        $r.text | Should -Not -Match 'Canary-Pw-555'
        $cmd = $null; $script:State.queue.TryDequeue([ref]$cmd) | Should -BeTrue
        $cmd.credential.Password | Should -BeOfType [System.Security.SecureString]
    }
    It 'rejects oversized bodies' {
        # The server refuses before reading the body; the client sees either 400 or a reset.
        $code = try { (Invoke-Raw POST '/api/run' @{ 'X-VSAT-Token' = $script:State.token; 'Content-Type' = 'application/json' } ('{"a":"' + ('x' * 70000) + '"}')).code } catch { 'reset' }
        $code | Should -BeIn @(400, 'reset')
        $script:State.queue.Count | Should -Be 0
    }
}
