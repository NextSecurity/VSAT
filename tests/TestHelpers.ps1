# Shared helpers: load the GENERATED single-file script in library mode so tests
# exercise exactly what ships.
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:VsatScript = Join-Path $script:RepoRoot 'vsat.ps1'
. $script:VsatScript -LibraryMode
Initialize-VsatProgress
$script:VsatQuiet = $true

function Get-TestEvidence {
    # Fresh, mutable copy of the synthetic lab.
    return (Get-VsatDemoEvidence)
}

function Get-TestResults {
    param($Evidence, [string]$ProfileName = 'standard', $Baseline)
    if (-not $Evidence) { $Evidence = Get-TestEvidence }
    return (Invoke-VsatAnalysisPipeline -Evidence $Evidence -ProfileName $ProfileName -BaselineEvidence $Baseline)
}

function Get-TestFinding {
    param($Results, [string]$RuleId, [string]$AssetName)
    return @($Results.findings | Where-Object { $_.ruleId -eq $RuleId -and (-not $AssetName -or $_.assetName -eq $AssetName) })
}

function Get-TestAsset {
    param($Evidence, [string]$Name, [string]$Type)
    return @($Evidence.assets | Where-Object { $_.name -eq $Name -and (-not $Type -or $_.type -eq $Type) })[0]
}

function Remove-TestNsx {
    # Removes every NSX asset, endpoint and collector from evidence.
    param($Evidence)
    $keep = @($Evidence.assets | Where-Object { $_.endpoint -ne 'ep-nsx01' })
    $Evidence.assets = New-VsatList $keep
    $Evidence.relationships = New-VsatList @($Evidence.relationships | Where-Object { $_.source -notlike 'ep-nsx01:*' -and $_.target -notlike 'ep-nsx01:*' })
    $Evidence.collection.collectors = New-VsatList @($Evidence.collection.collectors | Where-Object { $_.endpoint -ne 'ep-nsx01' })
    $Evidence.scope.endpoints = New-VsatList @($Evidence.scope.endpoints | Where-Object { $_.type -ne 'nsx' })
    $script:VsatAssetIndex = @{}; foreach ($a in $Evidence.assets) { $script:VsatAssetIndex[$a.id] = $a }
}
