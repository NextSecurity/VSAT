#region Canonical JSON
# Deterministic JSON used for hashing and signing (RFC 8785 subset): ordinal key
# order, no insignificant whitespace, invariant numbers, hand-rolled string escaping.
#
# Note: the single-argument [System.Text.Json.JsonSerializer]::Serialize($x) does not
# bind from PowerShell (it is a generic method with no plain object overload), and the
# default encoder escapes '<', '>' and '&' as \uXXXX, which this format does not want.
# String encoding is therefore implemented directly below rather than via JsonSerializer.

function ConvertTo-VsatJsonString {
    # Encodes a raw string as a JSON string literal: '"', '\', and control characters
    # (U+0000-U+001F) are escaped; everything else, including '<', '>' and '&', passes
    # through unchanged so output is stable across runtimes.
    param([string]$Value)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $sb = [System.Text.StringBuilder]::new($Value.Length + 2)
    [void]$sb.Append('"')
    $i = 0
    while ($i -lt $Value.Length) {
        $ch = $Value[$i]
        $code = [int]$ch
        if ([char]::IsHighSurrogate($ch)) {
            if (($i + 1) -lt $Value.Length -and [char]::IsLowSurrogate($Value[$i + 1])) {
                # Valid surrogate pair: emit both UTF-16 code units raw; they form one scalar.
                [void]$sb.Append($ch)
                [void]$sb.Append($Value[$i + 1])
                $i += 2
                continue
            }
            # Lone high surrogate: not a valid scalar on its own. [System.Text.Encoding]::UTF8
            # maps every unpaired surrogate to U+FFFD, so leaving it raw would let distinct lone
            # surrogates collide once hashed. Escape it instead so the hash stays injective.
            [void]$sb.Append('\u' + $code.ToString('x4', $inv))
            $i++
            continue
        }
        if ([char]::IsLowSurrogate($ch)) {
            # Reached only for a low surrogate not consumed as the second half of a pair above,
            # i.e. a lone low surrogate (including one at the very start of the string). Escape
            # it for the same reason as a lone high surrogate.
            [void]$sb.Append('\u' + $code.ToString('x4', $inv))
            $i++
            continue
        }
        # Switch on the integer code point, not the char/string itself: PowerShell's
        # default switch/-eq comparison is culture-aware and can treat distinct control
        # characters (e.g. U+0001 and U+0008) as equal under some cultures' collation.
        switch ($code) {
            0x22 { [void]$sb.Append('\"') }
            0x5C { [void]$sb.Append('\\') }
            0x08 { [void]$sb.Append('\b') }
            0x0C { [void]$sb.Append('\f') }
            0x0A { [void]$sb.Append('\n') }
            0x0D { [void]$sb.Append('\r') }
            0x09 { [void]$sb.Append('\t') }
            default {
                if ($code -lt 0x20) {
                    [void]$sb.Append('\u' + $code.ToString('x4', $inv))
                } else {
                    [void]$sb.Append($ch)
                }
            }
        }
        $i++
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-VsatCanonicalJson {
    param([AllowNull()]$Value)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [datetime]) { return (ConvertTo-VsatJsonString $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv)) }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid] -or $Value -is [enum]) { return (ConvertTo-VsatJsonString ([string]$Value)) }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        if (($Value -is [double] -or $Value -is [single]) -and ([double]::IsNaN($Value) -or [double]::IsInfinity($Value))) { throw 'Canonical JSON: non-finite number' }
        if ($Value -is [decimal]) { return $Value.ToString($inv) }
        # Documented divergence from RFC 8785's ECMAScript number form: 'R' round-trips
        # ('-0' stays '-0' rather than '0', and large/small magnitudes render as '1E+21' /
        # '1E-07' rather than ECMAScript's '1e+21' / '1e-7'). This format is stable within
        # .NET 8 (the pinned runtime), so it is an intra-VSAT canonical form, not RFC 8785's.
        return ([double]$Value).ToString('R', $inv)
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [sbyte] -or $Value -is [uint16]) { return $Value.ToString($inv) }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = [string[]]@($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $parts = foreach ($k in $keys) { (ConvertTo-VsatJsonString $k) + ':' + (ConvertTo-VsatCanonicalJson $Value[$k]) }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $d = [ordered]@{}; foreach ($p in $Value.PSObject.Properties) { $d[$p.Name] = $p.Value }
        return (ConvertTo-VsatCanonicalJson $d)
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($i in $Value) { ConvertTo-VsatCanonicalJson $i }
        return '[' + (@($parts) -join ',') + ']'
    }
    return (ConvertTo-VsatJsonString $Value.ToString())
}

function Get-VsatCanonicalHash {
    param([AllowNull()]$Value)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-VsatCanonicalJson $Value))
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}
#endregion Canonical JSON
