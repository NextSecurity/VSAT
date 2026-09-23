#region Util

$script:VsatSecrets = [System.Collections.Generic.List[string]]::new()
$script:VsatLog = [System.Collections.Generic.List[object]]::new()
$script:VsatLogFile = $null
$script:VsatQuiet = $false

function Register-VsatSecret {
    # Values registered here are masked in every log line and console message.
    param([string]$Value)
    if ($Value -and $Value.Length -ge 4 -and -not $script:VsatSecrets.Contains($Value)) {
        $script:VsatSecrets.Add($Value)
    }
}

function Protect-VsatText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return $null }
    $out = $Text
    foreach ($s in $script:VsatSecrets) { $out = $out.Replace($s, '********') }
    # Generic token/credential shapes that can appear in exception text.
    $out = [regex]::Replace($out, '(?i)(authorization|proxy-authorization)(\s*[:=]\s*)(?:(?:basic|bearer|negotiate|ntlm|digest)\s+)?[^\s";,&]+', '$1$2********')
    $out = [regex]::Replace($out, '(?i)(x-xsrf-token|vmware-api-session-id|cookie|set-cookie|password|passwd|j_password|secret|token)(\s*[:=]\s*)("?)[^\s";,&]+', '$1$2$3********')
    # Terminal control characters from untrusted content must not reach the console.
    $out = [regex]::Replace($out, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x9B]', '?')
    return $out
}

function Get-VsatUtcNow { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-VsatLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('info', 'warn', 'error', 'debug')][string]$Level = 'info',
        [string]$Source = 'vsat'
    )
    $safe = Protect-VsatText $Message
    $entry = [ordered]@{ t = (Get-VsatUtcNow); level = $Level; source = $Source; message = $safe }
    $script:VsatLog.Add($entry)
    if ($script:VsatProgress) {
        [void]$script:VsatProgress.log.Add($entry)
        while ($script:VsatProgress.log.Count -gt 200) { $script:VsatProgress.log.RemoveAt(0) }
    }
    if ($script:VsatLogFile) {
        try { Add-Content -LiteralPath $script:VsatLogFile -Value ("{0} [{1}] {2}: {3}" -f $entry.t, $Level, $Source, $safe) -Encoding UTF8 } catch { }
    }
    if (-not $script:VsatQuiet -and $Level -ne 'debug') {
        $color = switch ($Level) { 'warn' { 'Yellow' } 'error' { 'Red' } default { 'Gray' } }
        Write-Host ("[{0}] {1}" -f $Source, $safe) -ForegroundColor $color
    }
}

function ConvertTo-VsatJson {
    param([Parameter(Mandatory)][AllowNull()]$InputObject, [switch]$Compress)
    if ($Compress) { return (ConvertTo-Json -InputObject $InputObject -Depth 40 -Compress) }
    return (ConvertTo-Json -InputObject $InputObject -Depth 40)
}

function ConvertFrom-VsatJson {
    # Returns nested hashtables/arrays on both Windows PowerShell 5.1 and PowerShell 7.
    param([Parameter(Mandatory)][string]$Json)
    $obj = $Json | ConvertFrom-Json
    return (ConvertTo-VsatHashtable $obj)
}

function ConvertTo-VsatHashtable {
    param([AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $h[[string]$k] = ConvertTo-VsatHashtable $InputObject[$k] }
        return $h
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-VsatHashtable $p.Value }
        return $h
    }
    if ($InputObject -is [string]) { return $InputObject }
    # PowerShell 7 ConvertFrom-Json turns ISO-8601 strings into DateTime; keep them as UTC strings.
    if ($InputObject -is [datetime]) { return $InputObject.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $InputObject) { $list.Add((ConvertTo-VsatHashtable $i)) }
        return , $list.ToArray()
    }
    return $InputObject
}

function Get-VsatProp {
    # Safe nested property lookup on hashtables/objects: Get-VsatProp $o 'a.b.c'
    param([AllowNull()]$Object, [Parameter(Mandatory)][string]$Path, $Default = $null)
    $cur = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $Default }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($part)) { $cur = $cur[$part] } else { return $Default }
        }
        else {
            $p = $cur.PSObject.Properties[$part]
            if ($null -eq $p) { return $Default }
            $cur = $p.Value
        }
    }
    if ($null -eq $cur) { return $Default }
    return $cur
}

function Get-VsatSha256 {
    param([Parameter(Mandatory, ParameterSetName = 'Bytes')][byte[]]$Bytes,
          [Parameter(Mandatory, ParameterSetName = 'Text')][AllowEmptyString()][string]$Text,
          [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Text') { $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text) }
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $fs = [System.IO.File]::OpenRead($Path)
            try { $hash = $sha.ComputeHash($fs) } finally { $fs.Dispose() }
        }
        else { $hash = $sha.ComputeHash($Bytes) }
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $sha.Dispose() }
}

function Get-VsatSha256Base64 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))) }
    finally { $sha.Dispose() }
}

function ConvertTo-VsatCsvCell {
    # Neutralizes spreadsheet formula injection (CWE-1236) and quotes the value.
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '""' }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) { $Value = (@($Value) -join '; ') }
    $s = [string]$Value
    if ($s.Length -gt 0 -and @('=', '+', '-', '@', "`t", "`r") -contains [string]$s[0]) { $s = "'" + $s }
    return '"' + $s.Replace('"', '""') + '"'
}

function Export-VsatCsv {
    param([Parameter(Mandatory)][object[]]$Rows, [Parameter(Mandatory)][string[]]$Columns, [Parameter(Mandatory)][string]$Path)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine((($Columns | ForEach-Object { ConvertTo-VsatCsvCell $_ }) -join ','))
    foreach ($r in $Rows) {
        $cells = foreach ($c in $Columns) { ConvertTo-VsatCsvCell (Get-VsatProp $r $c) }
        [void]$sb.AppendLine(($cells -join ','))
    }
    Write-VsatFile -Path $Path -Content $sb.ToString()
}

function Write-VsatFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Test-VsatIsWindows {
    if ($PSVersionTable.PSVersion.Major -lt 6) { return $true }
    return [bool]$IsWindows
}

function Protect-VsatDirectory {
    # Restrict output folder to the current user where the platform supports it.
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (Test-VsatIsWindows) {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true, $false)
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
            $sys = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sys, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            Set-Acl -LiteralPath $Path -AclObject $acl
        }
        else {
            & chmod 700 -- $Path 2>$null
        }
        return $true
    }
    catch {
        Write-VsatLog -Level warn -Message "Could not restrict permissions on output folder: $($_.Exception.Message)"
        return $false
    }
}

function Compare-VsatVersion {
    # Returns -1/0/1 comparing dotted numeric versions; non-numeric parts compare as 0.
    param([string]$A, [string]$B)
    $pa = @(([string]$A).Split('.') | ForEach-Object { $n = 0; [void][int]::TryParse(($_ -replace '[^0-9].*$', ''), [ref]$n); $n })
    $pb = @(([string]$B).Split('.') | ForEach-Object { $n = 0; [void][int]::TryParse(($_ -replace '[^0-9].*$', ''), [ref]$n); $n })
    $len = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $len; $i++) {
        $x = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}

function Test-VsatWildcard {
    param([AllowNull()][string]$Value, [Parameter(Mandatory)][string]$Pattern)
    if ($null -eq $Value) { return $false }
    return ($Value -like $Pattern)
}

function New-VsatList {
    # Mutable list from any enumerable; returned unwrapped so callers get List[object].
    param([AllowNull()]$Items)
    $l = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Items) { foreach ($i in $Items) { $l.Add($i) } }
    return , $l
}

#endregion Util
