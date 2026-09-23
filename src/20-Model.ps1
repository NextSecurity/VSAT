#region Model

$script:VsatSchemaVersion = '2.0'

function New-VsatEvidence {
    param([ValidateSet('live', 'fixture', 'replay', 'demo')][string]$Mode = 'live', $Scope)
    $ev = [ordered]@{
        schemaVersion = $script:VsatSchemaVersion
        tool          = [ordered]@{ name = 'VSAT'; version = $script:VsatVersion }
        run           = [ordered]@{ id = [guid]::NewGuid().ToString(); startedUtc = (Get-VsatUtcNow); endedUtc = $null; mode = $Mode; status = 'partial' }
        scope         = (New-VsatScope $Scope)
        assets        = [System.Collections.Generic.List[object]]::new()
        relationships = [System.Collections.Generic.List[object]]::new()
        collection    = [ordered]@{ collectors = [System.Collections.Generic.List[object]]::new(); log = @() }
        nsx           = [ordered]@{ discovery = [ordered]@{ status = 'unknown'; evidence = @(); managersDiscovered = @() } }
    }
    $script:VsatAssetIndex = @{}
    return $ev
}

function New-VsatScope {
    param($Scope)
    $s = [ordered]@{
        endpoints                   = @()
        exclusions                  = @()
        nativeVlans                 = @()
        authorizedNetflowCollectors = @()
        authorizedSyslogTargets     = @()
        criticalAssets              = @()
        zones                       = @()
        exceptions                  = @()
        nsxDeclaredAbsent           = $false
    }
    if ($Scope) {
        foreach ($k in @($s.Keys)) {
            $v = Get-VsatProp $Scope $k
            if ($null -ne $v) { $s[$k] = $v }
        }
    }
    $s.endpoints = New-VsatList $s.endpoints
    return $s
}

function Add-VsatEndpoint {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)][ValidateSet('vcenter', 'esxi', 'nsx')][string]$Type, [Parameter(Mandatory)][string]$Address)
    $existing = $Evidence.scope.endpoints | Where-Object { $_.address -eq $Address -and $_.type -eq $Type } | Select-Object -First 1
    if ($existing) { return $existing }
    $prefix = if ($Type -eq 'nsx') { 'ep-nsx' } else { 'ep-vc' }
    $n = @($Evidence.scope.endpoints | Where-Object { $_.id -like "$prefix*" }).Count + 1
    $ep = [ordered]@{ id = ('{0}{1:d2}' -f $prefix, $n); type = $Type; address = $Address; status = 'not-attempted'; product = $null; version = $null; build = $null; instanceUuid = $null; apiVersion = $null; errors = [System.Collections.Generic.List[string]]::new() }
    $Evidence.scope.endpoints.Add($ep)
    return $ep
}

function Add-VsatAsset {
    param(
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Type,
        [AllowNull()][string]$Name,
        [Parameter(Mandatory)][string]$Endpoint,
        [string]$Version, [string]$Build, [string]$Site,
        [string[]]$Tags = @(),
        [System.Collections.IDictionary]$Props
    )
    if ($script:VsatAssetIndex.ContainsKey($Id)) { return $script:VsatAssetIndex[$Id] }
    $a = [ordered]@{
        id = $Id; type = $Type; name = $(if ($Name) { $Name } else { $Id }); endpoint = $Endpoint
        version = $Version; build = $Build; site = $Site; zone = $null; tags = @($Tags)
        criticality = $null; criticalitySource = $null; observedUtc = (Get-VsatUtcNow)
        props = $(if ($Props) { $Props } else { [ordered]@{} })
        facts = [ordered]@{}
    }
    $Evidence.assets.Add($a)
    $script:VsatAssetIndex[$Id] = $a
    return $a
}

function Get-VsatAsset {
    param([Parameter(Mandatory)][string]$Id)
    if ($script:VsatAssetIndex -and $script:VsatAssetIndex.ContainsKey($Id)) { return $script:VsatAssetIndex[$Id] }
    return $null
}

function Set-VsatFact {
    param(
        [Parameter(Mandatory)]$Asset,
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('ok', 'absent', 'denied', 'error', 'unsupported')][string]$Status = 'ok',
        [AllowNull()]$Value,
        [string]$ErrorMessage
    )
    $f = [ordered]@{ status = $Status; value = $Value }
    if ($ErrorMessage) { $f.error = (Protect-VsatText $ErrorMessage) }
    $Asset.facts[$Name] = $f
}

function Invoke-VsatFact {
    # Runs a collection scriptblock and records its value or a classified failure as a fact.
    # Parameter names are deliberately unusual: script blocks run in this function's scope
    # (dynamic scoping), so common names like $Asset or $Name would shadow the caller's.
    param([Parameter(Mandatory)][Alias('Asset')]$VsatFactAsset, [Parameter(Mandatory)][Alias('Name')][string]$VsatFactName, [Parameter(Mandatory)][Alias('Script')][scriptblock]$VsatFactScript)
    try {
        $vsatFactValue = & $VsatFactScript
        if ($null -eq $vsatFactValue) { Set-VsatFact -Asset $VsatFactAsset -Name $VsatFactName -Status absent -Value $null }
        else { Set-VsatFact -Asset $VsatFactAsset -Name $VsatFactName -Status ok -Value $vsatFactValue }
    }
    catch {
        Set-VsatFact -Asset $VsatFactAsset -Name $VsatFactName -Status (Get-VsatErrorClass $_) -Value $null -ErrorMessage $_.Exception.Message
    }
}

function Get-VsatErrorClass {
    param($ErrorRecord)
    $msg = [string]$ErrorRecord.Exception.Message
    $type = $ErrorRecord.Exception.GetType().Name
    if ($msg -match '(?i)NoPermission|permission to perform|not authori[sz]ed|access denied|forbidden|\b403\b|\b401\b' -or $type -match 'NoPermission|ViSecurity') { return 'denied' }
    if ($msg -match "(?i)not supported|NotSupported|not implemented|\b404\b|no such (method|property)|method not found|specified path is not correct|Element '[^']+' doesn't exist|InvalidProperty") { return 'unsupported' }
    return 'error'
}

function Add-VsatRelationship {
    param(
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][ValidateSet('contains', 'runs-on', 'connects', 'uplink', 'neighbor', 'member-of', 'enforces', 'applies-to', 'routes', 'depends', 'manages', 'stores')][string]$Type,
        [string]$Provenance = 'vsat',
        [ValidateSet('observed', 'inferred')][string]$Confidence = 'observed',
        [System.Collections.IDictionary]$Props
    )
    $r = [ordered]@{ source = $Source; target = $Target; type = $Type; provenance = $Provenance; confidence = $Confidence; props = $(if ($Props) { $Props } else { [ordered]@{} }) }
    $Evidence.relationships.Add($r)
}

function Invoke-VsatCollector {
    # Wraps one collector: timing, object count, classified errors, never aborts the run.
    # Parameter/local names are prefixed because the collector script block runs in this
    # function's scope and must see the caller's $Evidence/$Endpoint objects, not ours.
    param(
        [Parameter(Mandatory)][Alias('Evidence')]$VsatCollEvidence,
        [Parameter(Mandatory)][Alias('Name')][string]$VsatCollName,
        [Parameter(Mandatory)][Alias('Endpoint')][string]$VsatCollEndpoint,
        [Parameter(Mandatory)][Alias('Script')][scriptblock]$VsatCollScript,
        [Alias('Affects')][string[]]$VsatCollAffects = @()
    )
    $vsatCollRec = [ordered]@{ name = $VsatCollName; endpoint = $VsatCollEndpoint; status = 'ok'; startedUtc = (Get-VsatUtcNow); endedUtc = $null; objectCount = 0; error = $null; affects = $VsatCollAffects }
    Update-VsatProgress -Message "Collecting $VsatCollName ($VsatCollEndpoint)" -Step
    if (Test-VsatCancel) {
        $vsatCollRec.status = 'skipped'; $vsatCollRec.error = 'Run canceled'; $vsatCollRec.endedUtc = (Get-VsatUtcNow)
        $VsatCollEvidence.collection.collectors.Add($vsatCollRec)
        return
    }
    try {
        $vsatCollCount = & $VsatCollScript
        if ($vsatCollCount -is [array]) { $vsatCollCount = $vsatCollCount[-1] }
        if ($vsatCollCount -is [int]) { $vsatCollRec.objectCount = $vsatCollCount }
        elseif ($vsatCollCount -is [System.Collections.IDictionary]) {
            $vsatCollRec.objectCount = [int](Get-VsatProp $vsatCollCount 'count' 0)
            if ($vsatCollCount.Contains('status')) { $vsatCollRec.status = $vsatCollCount.status }
            if ($vsatCollCount.Contains('error')) { $vsatCollRec.error = Protect-VsatText $vsatCollCount.error }
        }
    }
    catch {
        $vsatCollRec.status = Get-VsatErrorClass $_
        $vsatCollRec.error = Protect-VsatText $_.Exception.Message
        Write-VsatLog -Level warn -Source $VsatCollName -Message "Collector $VsatCollName on $VsatCollEndpoint failed ($($vsatCollRec.status)): $($vsatCollRec.error)"
    }
    $vsatCollRec.endedUtc = (Get-VsatUtcNow)
    $VsatCollEvidence.collection.collectors.Add($vsatCollRec)
}

#endregion Model

#region Progress

$script:VsatProgress = $null

function Initialize-VsatProgress {
    param([hashtable]$Shared)
    if ($Shared) { $script:VsatProgress = $Shared }
    else { $script:VsatProgress = [hashtable]::Synchronized(@{}) }
    $script:VsatProgress.phase = 'setup'
    $script:VsatProgress.message = ''
    $script:VsatProgress.step = 0
    $script:VsatProgress.totalSteps = 0
    $script:VsatProgress.counts = @{}
    $script:VsatProgress.cancel = $false
    if (-not $script:VsatProgress.ContainsKey('log')) { $script:VsatProgress.log = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) }
}

function Update-VsatProgress {
    param([string]$Phase, [string]$Message, [switch]$Step)
    if (-not $script:VsatProgress) { return }
    if ($Phase) { $script:VsatProgress.phase = $Phase }
    if ($Message) { $script:VsatProgress.message = (Protect-VsatText $Message) }
    if ($Step) { $script:VsatProgress.step = [int]$script:VsatProgress.step + 1 }
}

function Test-VsatCancel {
    return [bool]($script:VsatProgress -and $script:VsatProgress.cancel)
}

#endregion Progress
