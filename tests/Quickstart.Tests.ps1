BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Ver = (Get-Content (Join-Path $script:Root 'build/version.json') -Raw | ConvertFrom-Json).version
}

Describe 'Quick start stays correct' {
    It 'README and site one-liners default to the newest release, verify the checksum, and never pipe to iex' {
        foreach ($f in 'README.md', 'site/index.html') {
            $t = Get-Content (Join-Path $script:Root $f) -Raw
            $t | Should -Match 'releases/latest/download'
            $t | Should -Match 'SHA256SUMS\.txt'
            $t | Should -Not -Match '(?i)\|\s*iex|Invoke-Expression'
        }
    }

    It 'README documents a pinned-version variant that matches build/version.json' {
        $t = Get-Content (Join-Path $script:Root 'README.md') -Raw
        $t | Should -Match ([regex]::Escape("v='$($script:Ver)'"))
        $t | Should -Match ([regex]::Escape("v=$($script:Ver)"))
    }

    It 'site/index.html documents a pinned-version variant (placeholder or literal version)' {
        $t = Get-Content (Join-Path $script:Root 'site/index.html') -Raw
        $winTokens = @('__VSAT_VERSION__', $script:Ver) | ForEach-Object { [regex]::Escape("v='$_'") }
        $unixTokens = @('__VSAT_VERSION__', $script:Ver) | ForEach-Object { [regex]::Escape("v=$_;") }
        $t | Should -Match ('(' + ($winTokens -join '|') + ')')
        $t | Should -Match ('(' + ($unixTokens -join '|') + ')')
    }

    It 'the one-liner verification logic rejects a tampered file' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()); New-Item -ItemType Directory $d | Out-Null
        Set-Content (Join-Path $d 'vsat.ps1') 'x'; Set-Content (Join-Path $d 'SHA256SUMS.txt') ("{0}  vsat.ps1" -f ('0' * 64))
        Push-Location $d
        try { { $h = ((Get-Content SHA256SUMS.txt | Where-Object { $_ -match '\svsat\.ps1$' }) -split '\s+')[0]; if ((Get-FileHash vsat.ps1).Hash -ne $h) { throw 'checksum mismatch - do not run' } } | Should -Throw '*checksum mismatch*' } finally { Pop-Location }
    }
}

Describe 'No prerelease disclaimers' {
    It 'ships no alpha/prerelease/beta/not-validated disclaimer language' {
        $pattern = '(?i)\balpha\b|\bprerelease\b|\bbeta\b|not (yet )?been validated|not validated|validated in a lab|live labs?\b|no code-signing|not code-signed|redistribution rights|performance measurements|decision support|\bnone yet\b|to be validated|\bprobably yes\b|\[!WARNING\]|\[!NOTE\]'
        $files = [System.Collections.Generic.List[string]]::new()
        foreach ($f in 'README.md', 'site/index.html', 'CONTRIBUTING.md', 'SECURITY.md', 'SUPPORT.md', 'CHANGELOG.md', 'build/Get-ReleaseNotes.ps1') { $files.Add($f) }
        foreach ($dir in 'docs', 'docs/architecture') {
            Get-ChildItem (Join-Path $script:Root $dir) -Filter '*.md' | ForEach-Object { $files.Add("$dir/$($_.Name)") }
        }
        foreach ($f in $files) {
            $t = Get-Content (Join-Path $script:Root $f) -Raw
            $t | Should -Not -Match $pattern -Because "disclaimer language found in $f"
        }
    }
}

Describe 'Reviewable single script' {
    It 'vsat.ps1 embeds resources as plain text, with no encoded blobs' {
        $t = Get-Content (Join-Path $script:Root 'vsat.ps1') -Raw
        [regex]::Matches($t, '[A-Za-z0-9+/]{200,}={0,2}').Count | Should -Be 0 -Because 'a security reviewer must be able to read every line'
        # The only base64 decoding is of TLS certificates returned by NSX.
        [regex]::Matches($t, 'FromBase64String').Count | Should -Be 1
        $t | Should -Not -Match '(?i)Invoke-Expression|DownloadString|EncodedCommand'
    }
}
