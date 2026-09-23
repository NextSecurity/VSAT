BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Single-file build' {
    It 'parses without errors' {
        $t = $null; $e = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:VsatScript, [ref]$t, [ref]$e)
        $e.Count | Should -Be 0
    }
    It 'is up to date with src/ (deterministic build)' {
        $out = Join-Path ([IO.Path]::GetTempPath()) ("vsat-build-" + [guid]::NewGuid().ToString('N') + '.ps1')
        & pwsh -NoProfile -File (Join-Path $script:RepoRoot 'build/Build-Vsat.ps1') -OutFile $out | Out-Null
        $a = [IO.File]::ReadAllText($out).Replace("`r`n", "`n")
        $b = [IO.File]::ReadAllText($script:VsatScript).Replace("`r`n", "`n")
        Remove-Item $out -Force
        $a | Should -BeExactly $b
    }
    It 'embeds all rule packs, advisory data, report and UI assets' {
        $names = Get-VsatEmbeddedNames
        foreach ($n in 'rules/pack.json', 'data/advisories.json', 'assets/report/report.js', 'assets/ui/app.js', 'fixtures/demo-evidence.json') { $names | Should -Contain $n }
    }
    It 'contains no dynamic code execution on data' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:VsatScript, [ref]$null, [ref]$null)
        $bad = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Invoke-Expression', 'iex', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer', 'Install-Module', 'Save-Module', 'Update-Module') }, $true)
        @($bad).Count | Should -Be 0
    }
    It 'reports its version' {
        $out = & pwsh -NoProfile -File $script:VsatScript -Version
        $out | Should -Match '^VSAT 2\.\d+\.\d+'
    }
}
