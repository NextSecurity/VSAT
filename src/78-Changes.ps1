#region Change timeline, engagement window and receipt
# 2.4 Audit Integrity. The change records the platforms already keep (vCenter events, NSX
# object timestamps, Windows event logs, KVM file mtimes / package history / wtmp) are
# normalized into one time-ordered list for the engagement window. Nothing here prevents a
# customer from fixing, re-running or editing; it makes those things visible. Missing or
# denied history is reported (coverage domain change-history), never shown as "no changes".

$script:VsatChangeMaxLookbackDays = 180
$script:VsatChangeDefaultDays = 30
$script:VsatVIEventMaxSamples = 50000
$script:VsatChangeMaxRecords = 10000
$script:VsatCrockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

function Get-VsatChangeCategories {
    if ($script:VsatChangeCategoryCache) { return $script:VsatChangeCategoryCache }
    $script:VsatChangeCategoryCache = ConvertFrom-VsatJson (Get-VsatEmbeddedText 'data/change-categories.json')
    return $script:VsatChangeCategoryCache
}

function ConvertTo-VsatChangeDate {
    # Any timestamp VSAT records (UTC string, DateTime of any kind) -> UTC DateTime, or $null.
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $d = [DateTime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([DateTime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Format-VsatUtc {
    param([Parameter(Mandatory)][datetime]$Time)
    return $Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Resolve-VsatEngagementStart {
    # -EngagementStart yyyy-MM-dd -> UTC midnight; never in the future, at most 180 days back.
    param([Parameter(Mandatory)][string]$Value, [string]$RunStartUtc)
    $d = [DateTime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTime]::TryParseExact($Value.Trim(), 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) {
        throw "-EngagementStart must be a date in yyyy-MM-dd format (got '$Value')."
    }
    $run = ConvertTo-VsatChangeDate $RunStartUtc
    if (-not $run) { $run = [DateTime]::UtcNow }
    if ($d -gt $run) { throw "-EngagementStart $Value is in the future." }
    $min = $run.Date.AddDays(-$script:VsatChangeMaxLookbackDays)
    $clamped = $d -lt $min
    if ($clamped) { $d = $min }
    return [ordered]@{ utc = (Format-VsatUtc $d); clamped = $clamped }
}

function Get-VsatChangeWindow {
    # The window is part of the evidence (run.engagementStartUtc), so a replay shows the same
    # timeline. Without it: 30 days before the run.
    param([Parameter(Mandatory)]$Evidence)
    $run = $Evidence.run
    $runStart = ConvertTo-VsatChangeDate (Get-VsatProp $run 'startedUtc')
    if (-not $runStart) { $runStart = [DateTime]::UtcNow }
    $start = ConvertTo-VsatChangeDate (Get-VsatProp $run 'engagementStartUtc')
    $source = 'operator'
    if (-not $start) { $start = $runStart.Date.AddDays(-$script:VsatChangeDefaultDays); $source = 'default' }
    $end = ConvertTo-VsatChangeDate (Get-VsatProp $run 'endedUtc')
    if (-not $end -or $end -lt $runStart) { $end = $runStart }
    return [ordered]@{ startUtc = (Format-VsatUtc $start); endUtc = (Format-VsatUtc $end); runStartUtc = (Format-VsatUtc $runStart); source = $source }
}

function ConvertTo-VsatAccountKey {
    # DOMAIN\user, user@domain and user compare equal (case-insensitive).
    param([AllowNull()][string]$User)
    if (-not $User) { return '' }
    $u = $User.Trim().ToLowerInvariant()
    if ($u.Contains('\')) { $u = $u.Substring($u.LastIndexOf('\') + 1) }
    if ($u.Contains('@')) { $u = $u.Substring(0, $u.IndexOf('@')) }
    return $u
}

function Get-VsatVCenterEventCategory {
    param([string]$Type, [string]$DescriptionId, [string]$EventTypeId)
    $m = (Get-VsatChangeCategories).vcenter
    if ($Type -and $m.eventTypes.Contains($Type)) { return [string]$m.eventTypes[$Type] }
    if ($DescriptionId) { foreach ($p in @($m.descriptionIdPrefixes)) { if ($DescriptionId.StartsWith([string]$p.prefix, [StringComparison]::Ordinal)) { return [string]$p.category } } }
    if ($EventTypeId) { foreach ($p in @($m.eventTypeIdPrefixes)) { if ($EventTypeId.StartsWith([string]$p.prefix, [StringComparison]::Ordinal)) { return [string]$p.category } } }
    return $null
}

function ConvertTo-VsatVIEventFact {
    # Projects Get-VIEvent output into the 'events' fact. Keeps categorized records only, and
    # sign-ins only for the account VSAT itself uses (the earlier-runs detector).
    param([AllowEmptyCollection()][object[]]$Events = @(), [Parameter(Mandatory)][string]$WindowStartUtc, [string]$Account, [string]$SessionKey, [bool]$CoversWindowStart, [int]$MaxSamples = $script:VsatVIEventMaxSamples)
    $acct = ConvertTo-VsatAccountKey $Account
    $records = [System.Collections.Generic.List[object]]::new()
    $oldest = $null; $n = 0; $capped = $false
    foreach ($e in @($Events | Where-Object { $null -ne $_ })) {
        $n++
        $t = ConvertTo-VsatChangeDate (Get-VsatProp $e 'CreatedTime')
        if (-not $t) { continue }
        if (-not $oldest -or $t -lt $oldest) { $oldest = $t }
        $type = ([string]$e.PSObject.TypeNames[0] -split '\.')[-1]
        $desc = [string](Get-VsatProp $e 'Info.DescriptionId' '')
        $etid = [string](Get-VsatProp $e 'EventTypeId' '')
        $cat = Get-VsatVCenterEventCategory -Type $type -DescriptionId $desc -EventTypeId $etid
        if (-not $cat) { continue }
        $user = [string](Get-VsatProp $e 'UserName' '')
        if ($cat -eq 'login' -and (-not $acct -or (ConvertTo-VsatAccountKey $user) -ne $acct)) { continue }
        if ($records.Count -ge $script:VsatChangeMaxRecords) { $capped = $true; continue }
        # Most specific entity argument first; datacenter is on almost every event.
        $entity = $null
        foreach ($pair in @(@('Vm', 'Vm'), @('Host', 'Host'), @('ComputeResource', 'ComputeResource'), @('Ds', 'Datastore'), @('Dvs', 'Dvs'), @('Net', 'Network'), @('Entity', 'Entity'), @('Datacenter', 'Datacenter'))) {
            $arg = Get-VsatProp $e $pair[0]
            $ref = Get-VsatProp $arg $pair[1]
            if ($ref -and (Get-VsatProp $ref 'Value')) { $entity = [ordered]@{ type = [string](Get-VsatProp $ref 'Type' ''); moref = [string]$ref.Value; name = [string](Get-VsatProp $arg 'Name' '') }; break }
        }
        $msg = Protect-VsatText ([string](Get-VsatProp $e 'FullFormattedMessage' ''))
        if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
        $records.Add([ordered]@{ utc = (Format-VsatUtc $t); type = $type; descriptionId = $(if ($desc) { $desc } else { $null }); eventTypeId = $(if ($etid) { $etid } else { $null }); user = $user; message = $msg; entity = $entity; sessionId = $(if ($cat -eq 'login') { [string](Get-VsatProp $e 'SessionId' '') } else { $null }) })
    }
    return [ordered]@{
        windowStartUtc = $WindowStartUtc; oldestUtc = $(if ($oldest) { Format-VsatUtc $oldest } else { $null }); coversWindowStart = [bool]$CoversWindowStart
        truncated = ($n -ge $MaxSamples); maxSamples = $MaxSamples; recordsCapped = $capped
        account = $Account; currentSessionKey = $SessionKey; records = $records.ToArray()
    }
}

function ConvertTo-VsatNsxModified {
    # NSX objects carry _last_modified_time (epoch ms) and _last_modified_user on every GET.
    param([AllowNull()]$Object)
    $o = [ordered]@{}
    $ms = Get-VsatProp $Object '_last_modified_time'
    if ($null -eq $ms) { return $o }
    try { $o.lastModifiedUtc = Format-VsatUtc ([DateTimeOffset]::FromUnixTimeMilliseconds([long]$ms).UtcDateTime) } catch { return [ordered]@{} }
    $o.lastModifiedUser = [string](Get-VsatProp $Object '_last_modified_user' '')
    return $o
}

function ConvertTo-VsatOffset {
    # "+0200" / "-0530" / "Z" -> TimeSpan.
    param([string]$Text)
    if ($Text -match '^([+-])(\d{2}):?(\d{2})$') { $ts = [TimeSpan]::new([int]$Matches[2], [int]$Matches[3], 0); if ($Matches[1] -eq '-') { $ts = $ts.Negate() }; return $ts }
    return [TimeSpan]::Zero
}

function ConvertFrom-VsatLocalTime {
    # Host-local wall clock text + host UTC offset -> UTC string (or $null).
    param([string]$Text, [string[]]$Formats, [TimeSpan]$Offset)
    $d = [DateTime]::MinValue
    $t = ($Text -replace '\s+', ' ').Trim()
    if (-not [DateTime]::TryParseExact($t, $Formats, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $null }
    return (Format-VsatUtc ([DateTimeOffset]::new($d, $Offset).UtcDateTime))
}

function ConvertFrom-VsatIsoOffsetTime {
    # dnf.rpm.log timestamps: 2026-09-23T10:11:12+0000.
    param([string]$Text)
    $t = $Text -replace '([+-]\d{2})(\d{2})$', '$1:$2'
    $d = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return (Format-VsatUtc $d.UtcDateTime) }
    return $null
}

function ConvertFrom-VsatKvmChanges {
    # KVM collector sections change-window, file-mtimes, package-log, logins -> 'changes' fact.
    # Returns $null for collector output from before 2.4 (no change-window section).
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Sections)
    if (-not $Sections.Contains('change-window')) { return $null }
    $cw = ConvertFrom-VsatKeyValue ([string]$Sections['change-window'])
    $tzText = [string]$cw['tz']
    $tz = ConvertTo-VsatOffset $tzText
    $since = 0L; [void][long]::TryParse([string]$cw['since'], [ref]$since)
    $v = [ordered]@{
        windowStartUtc = $(if ($since -gt 0) { Format-VsatUtc ([DateTimeOffset]::FromUnixTimeSeconds($since).UtcDateTime) } else { $null })
        account = [string]$cw['account']; tz = $tzText
        files = @(); deniedPaths = @()
        packages = [ordered]@{ status = 'absent'; source = $null; firstUtc = $null; records = @() }
        logins = [ordered]@{ status = 'absent'; beginsUtc = $null; records = @() }
    }
    $files = [System.Collections.Generic.List[object]]::new(); $denied = [System.Collections.Generic.List[string]]::new()
    foreach ($l in (([string]$Sections['file-mtimes']) -split "`r?`n")) {
        if ($l -match '^(\d+) (/.+)$') { $files.Add([ordered]@{ path = $Matches[2]; mtimeUtc = (Format-VsatUtc ([DateTimeOffset]::FromUnixTimeSeconds([long]$Matches[1]).UtcDateTime)) }) }
        elseif ($l -match '^denied (/.+)$') { $denied.Add($Matches[1]) }
        elseif ($l -match "cannot stat '([^']+)': Permission denied") { $denied.Add($Matches[1]) }
    }
    $v.files = $files.ToArray(); $v.deniedPaths = $denied.ToArray()

    $pk = $v.packages
    $recs = [System.Collections.Generic.List[object]]::new()
    $apt = $null
    $flushApt = { if ($apt -and $apt.utc -and @($apt.packages).Count) { $recs.Add([ordered]@{ utc = $apt.utc; action = (@($apt.packages) -join '; '); user = $apt.user }) } }
    foreach ($l in (([string]$Sections['package-log']) -split "`r?`n")) {
        if ($l -match '^denied=(.+)$') { $pk.status = 'denied'; $pk.source = $Matches[1]; continue }
        if ($l -match '^source=(.+)$') { $pk.status = 'ok'; $pk.source = $Matches[1]; continue }
        if ($l -match '^first=(.*)$') {
            $f = $Matches[1]
            if ($f -match '^(\d{4}-\d{2}-\d{2}T\S+)') { $pk.firstUtc = ConvertFrom-VsatIsoOffsetTime $Matches[1] }
            elseif ($f -match '^Start-Date:\s*(.+)$') { $pk.firstUtc = ConvertFrom-VsatLocalTime -Text $Matches[1] -Formats @('yyyy-MM-dd HH:mm:ss') -Offset $tz }
            continue
        }
        if ($l -match '^(\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+(Upgraded|Installed|Erased|Removed|Downgraded|Reinstalled|Obsoleted|Upgrade|Erase|Install):\s*(\S+)') {
            $u = ConvertFrom-VsatIsoOffsetTime $Matches[1]
            if ($u) { $recs.Add([ordered]@{ utc = $u; action = "$($Matches[2]) $($Matches[3])"; user = $null }) }
            continue
        }
        if ($l -match '^Start-Date:\s*(.+)$') { & $flushApt; $apt = @{ utc = (ConvertFrom-VsatLocalTime -Text $Matches[1] -Formats @('yyyy-MM-dd HH:mm:ss') -Offset $tz); user = $null; packages = @() }; continue }
        if ($apt -and $l -match '^Requested-By:\s*(\S+)') { $apt.user = $Matches[1]; continue }
        if ($apt -and $l -match '^(Install|Upgrade|Remove|Purge|Downgrade|Reinstall):\s*(.+)$') {
            $names = @([regex]::Matches($Matches[2], '(?:^|\),\s*)([^\s:,()]+)(?::[^\s(]+)?\s*\(') | ForEach-Object { $_.Groups[1].Value })
            $apt.packages = @($apt.packages) + @("$($Matches[1]) $($names -join ', ')")
        }
    }
    & $flushApt
    $pk.records = $recs.ToArray()

    $lg = $v.logins
    $ltext = [string]$Sections['logins']
    $lrecs = [System.Collections.Generic.List[object]]::new()
    if ($ltext -match 'unsupported=last') { $lg.status = 'unsupported' }
    elseif ($ltext -match '(?i)permission denied|cannot open') { $lg.status = 'denied' }
    elseif ($ltext.Trim()) {
        $lg.status = 'ok'
        $fmt = @('ddd MMM d HH:mm:ss yyyy')
        foreach ($l in ($ltext -split "`r?`n")) {
            if ($l -match '^wtmp begins (.+)$') { $lg.beginsUtc = ConvertFrom-VsatLocalTime -Text $Matches[1] -Formats $fmt -Offset $tz; continue }
            if ($l -match '^(reboot|shutdown|runlevel)\s') { continue }
            if ($l -match '^(?<user>\S+)\s+(?<tty>\S+)\s+(?:(?<from>\S+)\s+)?(?<when>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})') {
                $u = ConvertFrom-VsatLocalTime -Text $Matches['when'] -Formats $fmt -Offset $tz
                if ($u) { $lrecs.Add([ordered]@{ utc = $u; user = $Matches['user']; tty = $Matches['tty']; from = $(if ($Matches['from']) { $Matches['from'] } else { $null }) }) }
            }
        }
    }
    $lg.records = $lrecs.ToArray()

    $reasons = @()
    if ($v.deniedPaths.Count) { $reasons += "cannot read $($v.deniedPaths -join ', ')" }
    if ($pk.status -eq 'denied') { $reasons += "package history $($pk.source): access denied" }
    if ($lg.status -eq 'denied') { $reasons += 'logins (wtmp): access denied' }
    return [ordered]@{ status = $(if ($reasons.Count) { 'denied' } else { 'ok' }); value = $v; error = ($reasons -join '; ') }
}

function Get-VsatKvmFileCategory {
    param([string]$Path)
    foreach ($p in @((Get-VsatChangeCategories).kvm.files)) {
        $rx = '^' + [regex]::Escape([string]$p.pattern).Replace('\*', '[^/]*') + '$'
        if ($Path -match $rx) { return [string]$p.category }
    }
    return $null
}

function New-VsatChangeEntry {
    param([string]$Utc, [string]$EndpointId, [string]$AssetId, [string]$User, [string]$Category, [string]$Action, [string]$Source)
    $asset = Get-VsatAsset $AssetId
    $id = 'C-' + (Get-VsatSha256 -Text ("$Source|$Utc|$EndpointId|$AssetId|$Category|$User|$Action")).Substring(0, 8)
    return [ordered]@{ id = $id; utc = $Utc; endpointId = $EndpointId; assetId = $AssetId; assetName = $(if ($asset) { $asset.name } else { $AssetId }); user = $(if ($User) { $User } else { $null }); category = $Category; action = (Protect-VsatText $Action); source = $Source }
}

function Get-VsatChangeAnalysis {
    # Evidence -> results.analysis.changes. Pure function of evidence, so replay reproduces it.
    param([Parameter(Mandatory)]$Evidence)
    if (-not $script:VsatAssetIndex -or $script:VsatAssetIndex.Count -ne @($Evidence.assets).Count) {
        $script:VsatAssetIndex = @{}; foreach ($a in $Evidence.assets) { $script:VsatAssetIndex[$a.id] = $a }
    }
    $win = Get-VsatChangeWindow -Evidence $Evidence
    $ws = ConvertTo-VsatChangeDate $win.startUtc
    # Records up to a few minutes after the run end still belong to this run's timeline.
    $we = (ConvertTo-VsatChangeDate $win.endUtc).AddMinutes(10)
    $runStart = ConvertTo-VsatChangeDate $win.runStartUtc
    $map = Get-VsatChangeCategories
    $entries = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $sources = [System.Collections.Generic.List[object]]::new()
    $historyBy = [ordered]@{}
    $logins = [System.Collections.Generic.List[object]]::new()   # @{ endpointId; entry; sessionId }
    $accounts = [ordered]@{}   # endpointId -> @{ user; sessionKey; loginsReadable }
    $inWindow = { param($u) $t = ConvertTo-VsatChangeDate $u; return ($t -and $t -ge $ws -and $t -le $we) }
    $add = {
        param($entry)
        if (-not $entry -or $seen.ContainsKey($entry.id)) { return }
        $seen[$entry.id] = $true
        $entries.Add($entry)
    }
    $byEndpoint = @{}; foreach ($a in $Evidence.assets) { if (-not $byEndpoint.ContainsKey([string]$a.endpoint)) { $byEndpoint[[string]$a.endpoint] = [System.Collections.Generic.List[object]]::new() }; $byEndpoint[[string]$a.endpoint].Add($a) }
    foreach ($ep in @($Evidence.scope.endpoints)) {
        $epId = [string]$ep.id
        $assets = if ($byEndpoint.ContainsKey($epId)) { $byEndpoint[$epId] } else { @() }
        $src = [ordered]@{ endpointId = $epId; address = [string]$ep.address; type = [string]$ep.type; status = 'not-collected'; historyStartUtc = $null; reasons = @(); note = $null }
        $reasons = [System.Collections.Generic.List[string]]::new()
        switch ($ep.type) {
            { $_ -in @('vcenter', 'esxi') } {
                $root = @($assets | Where-Object { $_.id -eq "${epId}:root" })[0]
                $f = if ($root -and $root.facts.Contains('events')) { $root.facts.events } else { $null }
                if (-not $f) { $reasons.Add($(if ($root) { 'no event history in this evidence (collected before VSAT 2.4)' } else { 'endpoint was not assessed' })); break }
                if ($f.status -ne 'ok') { $src.status = $(if ($f.status -eq 'denied') { 'denied' } else { 'error' }); $reasons.Add("event history $($f.status)$(if ($f.error) { ": $($f.error)" })"); break }
                $v = $f.value
                $accounts[$epId] = @{ user = [string]$v.account; sessionKey = [string]$v.currentSessionKey; loginsReadable = $true }
                foreach ($r in @($v.records)) {
                    if (-not $r -or -not (& $inWindow $r.utc)) { continue }
                    $cat = Get-VsatVCenterEventCategory -Type ([string]$r.type) -DescriptionId ([string]$r.descriptionId) -EventTypeId ([string]$r.eventTypeId)
                    if (-not $cat) { continue }
                    $aid = "${epId}:root"
                    if ($r.entity -and $r.entity.moref -and (Get-VsatAsset "${epId}:$($r.entity.moref)")) { $aid = "${epId}:$($r.entity.moref)" }
                    $action = if ($r.message) { [string]$r.message } elseif ($r.descriptionId) { [string]$r.descriptionId } else { [string]$r.type }
                    $e = New-VsatChangeEntry -Utc $r.utc -EndpointId $epId -AssetId $aid -User ([string]$r.user) -Category $cat -Action $action -Source 'vcenter-event'
                    if ($cat -eq 'login') {
                        # The current session is this run, not an earlier one.
                        if (($r.sessionId -and $r.sessionId -eq $v.currentSessionKey) -or (ConvertTo-VsatChangeDate $r.utc) -ge $runStart) { continue }
                        $logins.Add(@{ endpointId = $epId; entry = $e })
                    }
                    & $add $e
                }
                $vs = ConvertTo-VsatChangeDate $v.windowStartUtc
                $oldest = ConvertTo-VsatChangeDate $v.oldestUtc
                $hs = $ws
                if ($vs -and $vs -gt $hs) { $hs = $vs; $reasons.Add("events were collected from $($v.windowStartUtc.Substring(0, 10)) only") }
                if ($v.truncated -and $oldest -and $oldest -gt $hs) { $hs = $oldest; $reasons.Add("event query reached $($v.maxSamples) records (older events not read)") }
                elseif (-not $v.coversWindowStart -and $oldest -and $oldest -gt $hs) { $hs = $oldest; $reasons.Add('vCenter keeps no events from before this date (event retention or cleared events)') }
                elseif (-not $v.coversWindowStart -and -not $oldest) { $reasons.Add('vCenter returned no events for the window') ; $hs = $we }
                $src.historyStartUtc = Format-VsatUtc $hs
                $src.status = $(if ($hs -gt $ws) { 'gap' } else { 'covered' })
            }
            'nsx' {
                $mgr = @($assets | Where-Object { $_.type -eq 'nsx-manager' })[0]
                $stamped = @($assets | Where-Object { $_.props -and $_.props.Contains('lastModifiedUtc') })
                if (-not $mgr -or -not $stamped.Count) { $reasons.Add($(if ($mgr) { 'objects carry no modification timestamps (collected before VSAT 2.4)' } else { 'endpoint was not assessed' })); break }
                foreach ($a in $stamped) {
                    $cat = [string](Get-VsatProp $map.nsx.assetTypes $a.type '')
                    if (-not $cat -or -not (& $inWindow $a.props.lastModifiedUtc)) { continue }
                    & $add (New-VsatChangeEntry -Utc $a.props.lastModifiedUtc -EndpointId $epId -AssetId $a.id -User ([string]$a.props.lastModifiedUser) -Category $cat -Action "Last modified: $($a.type -replace '^nsx-', 'NSX ') $($a.name)" -Source 'nsx-object')
                }
                foreach ($k in @($map.nsx.managerFacts.Keys)) {
                    $m = ConvertTo-VsatNsxModified (Get-VsatProp $mgr.facts "$k.value")
                    if ($m.Count -and (& $inWindow $m.lastModifiedUtc)) { & $add (New-VsatChangeEntry -Utc $m.lastModifiedUtc -EndpointId $epId -AssetId $mgr.id -User $m.lastModifiedUser -Category ([string]$map.nsx.managerFacts[$k]) -Action "Last modified: NSX $k" -Source 'nsx-object') }
                }
                $src.status = 'covered'; $src.historyStartUtc = $win.startUtc
                $src.note = 'NSX keeps only the last modification of each object; earlier changes to the same object are not visible.'
            }
            'hyperv' {
                $h = @($assets | Where-Object { $_.type -eq 'hyperv-host' })[0]
                $f = if ($h -and $h.facts.Contains('events')) { $h.facts.events } else { $null }
                if (-not $f) { $reasons.Add($(if ($h) { 'no event history in this evidence (collected before VSAT 2.4)' } else { 'endpoint was not assessed' })); break }
                $v = $f.value
                if (-not $v) { $src.status = $(if ($f.status -eq 'denied') { 'denied' } else { 'error' }); $reasons.Add("event history $($f.status)$(if ($f.error) { ": $($f.error)" })"); break }
                $accounts[$epId] = @{ user = [string]$v.account; sessionKey = $null; loginsReadable = $false }
                foreach ($r in @($v.entries)) {
                    if (-not $r -or -not (& $inWindow $r.utc)) { continue }
                    $logMap = Get-VsatProp $map.windows ([string]$r.log)
                    $cat = if ($logMap) { [string](Get-VsatProp $logMap ([string]$r.id) (Get-VsatProp $logMap '*' '')) } else { '' }
                    if (-not $cat) { continue }
                    $action = [string]$r.message
                    if ($r.target -and $action -notmatch [regex]::Escape([string]$r.target)) { $action = "$action [$($r.target)]" }
                    & $add (New-VsatChangeEntry -Utc $r.utc -EndpointId $epId -AssetId $h.id -User ([string]$r.user) -Category $cat -Action $action -Source 'windows-event')
                }
                $hs = $ws
                $vs = ConvertTo-VsatChangeDate $v.windowStartUtc
                if ($vs -and $vs -gt $hs) { $hs = $vs; $reasons.Add("events were collected from $($v.windowStartUtc.Substring(0, 10)) only") }
                foreach ($s in @($v.sources)) {
                    if (-not $s) { continue }
                    if ($s.status -eq 'denied') { $reasons.Add("$($s.log) log: access denied$(if ($s.error) { " ($($s.error))" }) - add the account to Event Log Readers") ; continue }
                    if ($s.status -ne 'ok') { $reasons.Add("$($s.log) log: $($s.status)$(if ($s.error) { " ($($s.error))" })"); continue }
                    $o = ConvertTo-VsatChangeDate $s.oldestUtc
                    # A quiet log that is not full holds everything since it was created; a full
                    # (rolled over) or cleared log starts at its oldest event.
                    $cleared = [int](Get-VsatProp $s 'oldestId' 0) -in @(104, 1102)
                    if ($o -and $o -gt $ws -and ([bool](Get-VsatProp $s 'full' $false) -or $cleared)) {
                        if ($o -gt $hs) { $hs = $o }
                        $reasons.Add("$($s.log) log $(if ($cleared) { 'was cleared' } else { 'rolled over' }); history starts $($s.oldestUtc.Substring(0, 10))")
                    }
                    if ($s.truncated) { $reasons.Add("$($s.log) log: more than $($s.count) records in the window (older ones not read)") }
                }
                $src.historyStartUtc = Format-VsatUtc $hs
                $src.status = $(if ($f.status -eq 'denied' -or @($v.sources | Where-Object { $_ -and $_.status -eq 'denied' }).Count) { 'denied' } elseif ($hs -gt $ws) { 'gap' } elseif (@($v.sources | Where-Object { $_ -and $_.status -notin @('ok') }).Count) { 'error' } else { 'covered' })
            }
            'kvm' {
                $h = @($assets | Where-Object { $_.type -eq 'kvm-host' })[0]
                $f = if ($h -and $h.facts.Contains('changes')) { $h.facts.changes } else { $null }
                if (-not $f -or -not $f.value) { $reasons.Add($(if ($h) { 'no change history in this evidence (collected before VSAT 2.4)' } else { 'endpoint was not assessed' })); break }
                $v = $f.value
                $accounts[$epId] = @{ user = [string]$v.account; sessionKey = $null; loginsReadable = ($v.logins.status -eq 'ok') }
                foreach ($fi in @($v.files)) {
                    if (-not $fi -or -not (& $inWindow $fi.mtimeUtc)) { continue }
                    $cat = Get-VsatKvmFileCategory ([string]$fi.path)
                    if (-not $cat) { continue }
                    $aid = $h.id
                    $leaf = [IO.Path]::GetFileNameWithoutExtension([string]$fi.path)
                    if ($fi.path -like '/etc/libvirt/qemu/networks/*.xml') { $n = @($assets | Where-Object { $_.type -eq 'kvm-network' -and $_.props.network -eq $leaf })[0]; if ($n) { $aid = $n.id } }
                    elseif ($fi.path -like '/etc/libvirt/qemu/*.xml') { $n = @($assets | Where-Object { $_.type -eq 'kvm-vm' -and $_.name -eq $leaf })[0]; if ($n) { $aid = $n.id } }
                    & $add (New-VsatChangeEntry -Utc $fi.mtimeUtc -EndpointId $epId -AssetId $aid -User '' -Category $cat -Action "Modified $($fi.path)" -Source 'file-mtime')
                }
                # One entry per package transaction (records within the same minute).
                $groups = [ordered]@{}
                foreach ($r in @($v.packages.records)) { if ($r -and (& $inWindow $r.utc)) { $k = $r.utc.Substring(0, 16); if (-not $groups.Contains($k)) { $groups[$k] = [System.Collections.Generic.List[object]]::new() }; $groups[$k].Add($r) } }
                foreach ($k in $groups.Keys) {
                    $g = $groups[$k]
                    $acts = @($g | ForEach-Object { [string]$_.action })
                    $text = if ($acts.Count -gt 6) { (@($acts | Select-Object -First 6) -join '; ') + "; +$($acts.Count - 6) more" } else { $acts -join '; ' }
                    & $add (New-VsatChangeEntry -Utc $g[0].utc -EndpointId $epId -AssetId $h.id -User ([string]$g[0].user) -Category ([string]$map.kvm.packageLog) -Action "Packages: $text" -Source 'package-log')
                }
                foreach ($r in @($v.logins.records)) {
                    if (-not $r -or -not (& $inWindow $r.utc)) { continue }
                    $e = New-VsatChangeEntry -Utc $r.utc -EndpointId $epId -AssetId $h.id -User ([string]$r.user) -Category ([string]$map.kvm.wtmp) -Action ("Login ($($r.tty))" + $(if ($r.from) { " from $($r.from)" } else { '' })) -Source 'wtmp'
                    if ((ConvertTo-VsatChangeDate $r.utc) -lt $runStart) { $logins.Add(@{ endpointId = $epId; entry = $e }) }
                    & $add $e
                }
                $hs = $ws
                $vs = ConvertTo-VsatChangeDate $v.windowStartUtc
                if ($vs -and $vs -gt $hs) { $hs = $vs; $reasons.Add("changes were collected from $($v.windowStartUtc.Substring(0, 10)) only") }
                if ($v.deniedPaths.Count) { $reasons.Add("cannot read $($v.deniedPaths -join ', ') (run the collector as root to include them)") }
                switch ($v.packages.status) {
                    'ok' { $p1 = ConvertTo-VsatChangeDate $v.packages.firstUtc; if ($p1 -and $p1 -gt $ws) { if ($p1 -gt $hs) { $hs = $p1 }; $reasons.Add("package history $($v.packages.source) starts $($v.packages.firstUtc.Substring(0, 10)) (rotated)") } }
                    'denied' { $reasons.Add("package history $($v.packages.source): access denied") }
                    default { $reasons.Add('no package history log found (/var/log/dnf.rpm.log or /var/log/apt/history.log)') }
                }
                switch ($v.logins.status) {
                    'ok' { $b = ConvertTo-VsatChangeDate $v.logins.beginsUtc; if ($b -and $b -gt $ws) { if ($b -gt $hs) { $hs = $b }; $reasons.Add("login records (wtmp) start $($v.logins.beginsUtc.Substring(0, 10))") } }
                    'denied' { $reasons.Add('logins (wtmp): access denied') }
                    default { $reasons.Add("logins: $($v.logins.status)") }
                }
                $src.historyStartUtc = Format-VsatUtc $hs
                $src.status = $(if ($f.status -eq 'denied') { 'denied' } elseif ($hs -gt $ws) { 'gap' } elseif ($v.packages.status -ne 'ok' -or $v.logins.status -ne 'ok') { 'error' } else { 'covered' })
            }
        }
        $src.reasons = $reasons.ToArray()
        if ($src.historyStartUtc) { $historyBy[$epId] = $src.historyStartUtc }
        $sources.Add($src)
    }
    $gaps = @(foreach ($s in $sources) {
            if ($s.status -eq 'gap') { [ordered]@{ endpointId = $s.endpointId; address = $s.address; historyStartUtc = $s.historyStartUtc; windowStartUtc = $win.startUtc; text = "History starts $($s.historyStartUtc.Substring(0, 10)), engagement started $($win.startUtc.Substring(0, 10))" } }
        })
    # Earlier-runs detector: sign-ins by the account VSAT used, before this run, inside the window.
    $sessions = @(foreach ($epId in $accounts.Keys) {
            $acc = $accounts[$epId]
            if (-not $acc.user -or -not $acc.loginsReadable) { continue }
            $key = ConvertTo-VsatAccountKey $acc.user
            $mine = @($logins | Where-Object { $_.endpointId -eq $epId -and (ConvertTo-VsatAccountKey $_.entry.user) -eq $key } | ForEach-Object { $_.entry } | Sort-Object { $_.utc })
            [ordered]@{ endpointId = $epId; user = $acc.user; count = $mine.Count; firstUtc = $(if ($mine.Count) { $mine[0].utc } else { $null }); lastUtc = $(if ($mine.Count) { $mine[-1].utc } else { $null }); entryIds = @($mine | ForEach-Object { $_.id }) }
        })
    $sorted = @($entries | Sort-Object -Property @{ Expression = { $_.utc }; Descending = $true }, @{ Expression = { $_.id }; Descending = $false })
    return [ordered]@{
        windowStartUtc = $win.startUtc; windowEndUtc = $win.endUtc; windowSource = $win.source
        entries = $sorted
        historyStartUtcByEndpoint = $historyBy
        gaps = $gaps
        sources = $sources.ToArray()
        accountSessions = $sessions
        summary = [ordered]@{ entries = $sorted.Count; changedChecks = 0; changedPassing = 0 }
    }
}

function Set-VsatChangedInWindow {
    # A finding gets changedInWindow = [entryId] when its asset has an entry in the rule's
    # changeCategory inside the window. The result itself never changes (a PASS stays a PASS).
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings, [Parameter(Mandatory)]$Changes)
    # When an entry names what changed ("Update option values (Security.AccountLockFailures)",
    # "Stop service (SSH)"), only checks on that setting or service are marked. An entry that
    # names nothing, or names something no check on the asset reads, marks the whole category.
    $cats = @{}; $keys = @{}
    foreach ($r in (Get-VsatRulePack).rules) {
        $c = Get-VsatProp $r 'changeCategory'
        if (-not $c) { continue }
        $cats[[string]$r.id] = @($c)
        $k = [string](Get-VsatProp (Get-VsatProp $r 'check') 'key' '')
        if ($k) { $keys[[string]$r.id] = $k.ToLowerInvariant() }
    }
    $keyed = { param($ruleId, $subject) $rk = $keys[[string]$ruleId]; $rk -and ($rk -eq $subject -or $rk.EndsWith("-$subject", [StringComparison]::Ordinal) -or $rk.EndsWith(".$subject", [StringComparison]::Ordinal)) }
    $assetRules = @{}
    foreach ($f in $Findings) { $a = [string]$f.assetId; if (-not $assetRules.ContainsKey($a)) { $assetRules[$a] = [System.Collections.Generic.List[string]]::new() }; $assetRules[$a].Add([string]$f.ruleId) }
    $idx = @{}; $subjects = @{}
    foreach ($e in @($Changes.entries)) {
        $k = "$($e.assetId)|$($e.category)"
        if (-not $idx.ContainsKey($k)) { $idx[$k] = [System.Collections.Generic.List[string]]::new() }
        $idx[$k].Add([string]$e.id)
        if ($e.category -in @('settings', 'service') -and [string]$e.action -match '\(([^()]+)\)\s*$') {
            $s = ($Matches[1] -split ':')[0].Trim().ToLowerInvariant()
            if (@($assetRules[[string]$e.assetId] | Where-Object { & $keyed $_ $s }).Count) { $subjects[[string]$e.id] = $s }
        }
    }
    $changed = 0; $passing = 0
    foreach ($f in $Findings) {
        if (-not $cats.ContainsKey([string]$f.ruleId)) { continue }
        $ids = @(foreach ($c in $cats[[string]$f.ruleId]) { $k = "$($f.assetId)|$c"; if ($idx.ContainsKey($k)) { $idx[$k] | Where-Object { -not $subjects.ContainsKey($_) -or (& $keyed $f.ruleId $subjects[$_]) } } })
        if (-not $ids.Count) { continue }
        $f.changedInWindow = @($ids | Select-Object -Unique)
        $changed++
        if ($f.result -eq 'PASS') { $passing++ }
    }
    $Changes.summary.changedChecks = $changed
    $Changes.summary.changedPassing = $passing
}

function Get-VsatChangeCoverage {
    # Non-mandatory coverage domain change-history: ASSESSED when every endpoint's history
    # covers the window, PARTIAL on gaps, UNKNOWN when history was denied or is absent.
    param([Parameter(Mandatory)]$Evidence, $Changes)
    if (-not $Changes) { $Changes = Get-VsatChangeAnalysis -Evidence $Evidence }
    $srcs = @($Changes.sources)
    $ws = $Changes.windowStartUtc.Substring(0, 10)
    $winText = "Engagement window $ws to $($Changes.windowEndUtc.Substring(0, 10)) ($(if ($Changes.windowSource -eq 'operator') { 'engagement start given with -EngagementStart' } else { 'default: 30 days before the run' }))."
    if (-not $srcs.Count) {
        return [ordered]@{ state = 'NOT_APPLICABLE'; label = 'NOT APPLICABLE: NO ENDPOINTS IN SCOPE'; detail = 'No endpoints were assessed, so there is no change history to read.'; evidence = @(); missing = @() }
    }
    $name = { param($s) "$($s.type) $($s.address)" }
    $evidence = @(foreach ($s in $srcs) { "$(& $name $s): $($s.status)$(if ($s.historyStartUtc) { ", history from $($s.historyStartUtc.Substring(0, 10))" })$(if ($s.note) { " ($($s.note))" })" })
    $missing = @(foreach ($s in $srcs) {
            if ($s.status -eq 'covered') { continue }
            $lead = if ($s.status -eq 'gap') { "History starts $($s.historyStartUtc.Substring(0, 10)), engagement started $ws. " } else { '' }
            "$(& $name $s): $lead$(@($s.reasons) -join '; ')"
        })
    $count = "$(@($Changes.entries).Count) change(s) recorded."
    if (@($srcs | Where-Object { $_.status -ne 'not-collected' }).Count -eq 0) {
        return [ordered]@{ state = 'UNKNOWN'; label = 'UNKNOWN: NO CHANGE HISTORY IN THIS EVIDENCE'; detail = "This evidence has no change history (collected before VSAT 2.4, or no endpoint was assessed). Changes during the engagement cannot be shown. This is not a pass. $winText"; evidence = $evidence; missing = $missing }
    }
    if (@($srcs | Where-Object { $_.status -eq 'denied' }).Count) {
        return [ordered]@{ state = 'UNKNOWN'; label = 'UNKNOWN: CHANGE HISTORY NOT READABLE'; detail = "Change history could not be read on every endpoint (access denied); changes there cannot be shown. $count $winText"; evidence = $evidence; missing = $missing }
    }
    if ($missing.Count) {
        $g = @($Changes.gaps | Select-Object -First 1)
        return [ordered]@{ state = 'PARTIAL'; label = 'PARTIAL: CHANGE HISTORY INCOMPLETE'; detail = "$(if ($g.Count) { "$($g[0].address): $($g[0].text). " })Changes before the history start are not visible. $count $winText"; evidence = $evidence; missing = $missing }
    }
    return [ordered]@{ state = 'ASSESSED'; label = 'CHANGE HISTORY ASSESSED'; detail = "Every endpoint's change history covers the engagement window. $count $winText"; evidence = $evidence; missing = @() }
}

function Get-VsatChangeRows {
    # changes.csv rows: one per timeline entry, with the checks it touches.
    param([Parameter(Mandatory)]$Results)
    $byEntry = @{}
    foreach ($f in @($Results.findings)) { foreach ($id in @(Get-VsatProp $f 'changedInWindow' @())) { if (-not $byEntry.ContainsKey($id)) { $byEntry[$id] = [System.Collections.Generic.List[string]]::new() }; $byEntry[$id].Add("$($f.ruleId) $($f.result)") } }
    foreach ($e in @(Get-VsatProp $Results 'analysis.changes.entries' @())) {
        [ordered]@{ id = $e.id; utc = $e.utc; endpointId = $e.endpointId; assetId = $e.assetId; assetName = $e.assetName; user = $e.user; category = $e.category; action = $e.action; source = $e.source; checks = $(if ($byEntry.ContainsKey($e.id)) { @($byEntry[$e.id] | Select-Object -Unique) -join '; ' } else { '' }) }
    }
}

function ConvertTo-VsatReceiptCode {
    # First 80 bits of a SHA-256 in Crockford base32, grouped VSAT-XXXX-XXXX-XXXX-XXXX.
    param([Parameter(Mandatory)][byte[]]$Hash)
    $sb = [System.Text.StringBuilder]::new()
    $acc = 0L; $bits = 0
    foreach ($b in $Hash[0..9]) {
        $acc = ($acc -shl 8) -bor [long]$b; $bits += 8
        while ($bits -ge 5) { $bits -= 5; [void]$sb.Append($script:VsatCrockford[[int](($acc -shr $bits) -band 31)]); $acc = $acc -band ((1L -shl $bits) - 1) }
    }
    $c = $sb.ToString()
    return ('VSAT-{0}-{1}-{2}-{3}' -f $c.Substring(0, 4), $c.Substring(4, 4), $c.Substring(8, 4), $c.Substring(12, 4))
}

function Get-VsatReceipt {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).ProviderPath)
    try { return (ConvertTo-VsatReceiptCode -Hash $sha.ComputeHash($fs)) } finally { $fs.Dispose(); $sha.Dispose() }
}

function ConvertTo-VsatReceiptNormalized {
    # Accepts the code as it is read aloud or typed: any case, spaces or dashes, with or without
    # the VSAT prefix, and the Crockford aliases O=0, I=1, L=1.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Code)
    $c = ($Code.ToUpperInvariant() -replace '[\s-]', '')
    if ($c.Length -eq 20 -and $c.StartsWith('VSAT')) { $c = $c.Substring(4) }
    $c = $c.Replace('O', '0').Replace('I', '1').Replace('L', '1')
    if ($c -notmatch '^[0-9A-HJKMNP-TV-Z]{16}$') { throw "Receipt code format is invalid; expected VSAT-XXXX-XXXX-XXXX-XXXX (got '$Code')." }
    return ('VSAT-{0}-{1}-{2}-{3}' -f $c.Substring(0, 4), $c.Substring(4, 4), $c.Substring(8, 4), $c.Substring(12, 4))
}

function Test-VsatReceipt {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Code)
    return ((ConvertTo-VsatReceiptNormalized $Code) -eq (Get-VsatReceipt -Path $Path))
}

#endregion Change timeline, engagement window and receipt
