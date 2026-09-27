BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Canonical JSON' {
    It 'sorts keys ordinally and removes whitespace' {
        ConvertTo-VsatCanonicalJson ([ordered]@{ b = 1; a = @{ z = $true; B = $null } }) | Should -Be '{"a":{"B":null,"z":true},"b":1}'
    }
    It 'is independent of key insertion order and container type' {
        $h1 = Get-VsatCanonicalHash ([ordered]@{ x = 1; y = 'é' })
        $h2 = Get-VsatCanonicalHash ([pscustomobject]@{ y = 'é'; x = 1 })
        $h1 | Should -Be $h2
        $h1 | Should -Match '^[0-9a-f]{64}$'
    }
    It 'formats numbers invariantly regardless of culture' {
        $old = [Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [Threading.Thread]::CurrentThread.CurrentCulture = 'de-DE'
            ConvertTo-VsatCanonicalJson @(1.5, 10, [long]9007199254740993) | Should -Be '[1.5,10,9007199254740993]'
        } finally { [Threading.Thread]::CurrentThread.CurrentCulture = $old }
    }
    It 'rejects NaN and Infinity' { { ConvertTo-VsatCanonicalJson ([double]::NaN) } | Should -Throw '*non-finite*' }
    It 'escapes control and markup characters deterministically' {
        ConvertTo-VsatCanonicalJson "a`n<b>&" | Should -Be '"a\n<b>&"'
    }
    It 'serializes DateTime as UTC ISO-8601 seconds' {
        ConvertTo-VsatCanonicalJson ([datetime]::new(2026, 9, 23, 10, 0, 0, [DateTimeKind]::Utc)) | Should -Be '"2026-09-23T10:00:00Z"'
    }
    It 'renders an empty object and an empty array' {
        ConvertTo-VsatCanonicalJson ([ordered]@{}) | Should -Be '{}'
        ConvertTo-VsatCanonicalJson @() | Should -Be '[]'
    }
    It 'canonicalizes a nested array of dictionaries' {
        $value = @(
            [ordered]@{ b = 2; a = 1 },
            [ordered]@{ d = @(3, 4); c = @{} }
        )
        ConvertTo-VsatCanonicalJson $value | Should -Be '[{"a":1,"b":2},{"c":{},"d":[3,4]}]'
    }
    It 'escapes quotes, backslashes and remaining control characters' {
        ConvertTo-VsatCanonicalJson "quote`"back\slash`ttab" | Should -Be '"quote\"back\\slash\ttab"'
        ConvertTo-VsatCanonicalJson "$([char]0x01)" | Should -Be '"\u0001"'
    }
    It 'hashes deterministically for the same logical value' {
        Get-VsatCanonicalHash ([ordered]@{ a = 1; b = 2 }) | Should -Be (Get-VsatCanonicalHash ([ordered]@{ b = 2; a = 1 }))
    }
    It 'hashes distinct lone surrogates to distinct values' {
        # UTF8.GetBytes maps every unpaired surrogate to U+FFFD; if they were left raw, two
        # different lone surrogates would hash the same, which would be a collision in a
        # tamper-evidence primitive. They must be escaped as \uXXXX so the hash stays injective.
        $h1 = Get-VsatCanonicalHash ([string][char]0xD800)
        $h2 = Get-VsatCanonicalHash ([string][char]0xD801)
        $h1 | Should -Not -Be $h2
    }
    It 'passes a valid surrogate pair through raw' {
        $emoji = [char]::ConvertFromUtf32(0x1F600)
        ConvertTo-VsatCanonicalJson $emoji | Should -Be ('"' + $emoji + '"')
    }
    It 'escapes a lone high surrogate at the end of a string and a lone low surrogate at the start' {
        ConvertTo-VsatCanonicalJson ('a' + [string][char]0xD800) | Should -Be '"a\ud800"'
        ConvertTo-VsatCanonicalJson ([string][char]0xDC00 + 'b') | Should -Be '"\udc00b"'
    }
    It 'does not unroll a single-element array' {
        ConvertTo-VsatCanonicalJson @(5) | Should -Be '[5]'
        ConvertTo-VsatCanonicalJson @([pscustomobject]@{ a = 1 }) | Should -Be '[{"a":1}]'
    }
}
