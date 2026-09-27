#region Identity
# Cross-platform principal keys. Domain principals join across platforms by exact
# normalized name; local principals are namespaced by endpoint and never joined.
$script:VsatLocalDomains = @('builtin', 'nt authority', 'nt service', 'vsphere.local', 'localos', 'window manager', 'font driver host')

function ConvertTo-VsatFoldedLower {
    # Unicode-safe fold for principal-name comparison/keys:
    #  1. NFKC normalization folds width/compatibility confusables (e.g. full-width U+FF21
    #     'Ａ' -> ASCII 'A') before anything else looks at the string.
    #  2. The Turkish dotted-I fix: .ToLowerInvariant() leaves U+0130 'İ' as itself (it does
    #     not fold to ASCII 'i'), which would keep 'EXAMPLE\İSTANBUL' from ever joining
    #     'EXAMPLE\istanbul'. Only U+0130 is folded to ASCII 'i' before the culture-invariant
    #     lowering below (which never touches it again). U+0131 'ı' (dotless i) is deliberately
    #     left alone: it is ALREADY lowercase and a genuinely distinct Turkish letter from ASCII
    #     'i' - folding it too would falsely JOIN two different principals (e.g. 'ısik' and
    #     'isik'), fabricating an attack path across platforms. A false join is worse than a
    #     split: ruling from fix round 2.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $t = $Text.Normalize([System.Text.NormalizationForm]::FormKC)
    $t = $t.Replace([string][char]0x0130, 'i')
    return $t.ToLowerInvariant()
}

function ConvertTo-VsatPrincipalKey {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Endpoint, $Scope, [string]$HostName)
    $n = $Name.Trim()
    $f = ConvertTo-VsatFoldedLower $n
    $map = @{}
    foreach ($d in @(Get-VsatProp $Scope 'identityDomains' @())) {
        $dns = (ConvertTo-VsatFoldedLower ([string]$d.dns)).TrimEnd('.')
        $map[$dns] = ConvertTo-VsatFoldedLower ([string]$d.netbios)
    }
    $hostShort = if ($HostName) { ConvertTo-VsatFoldedLower (($HostName -split '\.')[0]) } else { $null }
    $local = { param($x) [ordered]@{ key = "local:${Endpoint}:$(ConvertTo-VsatFoldedLower $x)"; display = $n; local = $true } }
    if ($f -match '^(?<dom>[^\\]+)\\(?<acct>.+)$') {
        $dom = $Matches.dom
        $acct = $Matches.acct
        if ($script:VsatLocalDomains -contains $dom -or ($hostShort -and $dom -eq $hostShort) -or ($dom -match '^(hv|kvm|esx)[0-9a-z-]*$' -and -not ($map.Values -contains $dom))) { return (& $local $n) }
        return [ordered]@{ key = "ad:$dom\$acct"; display = $n; local = $false }
    }
    if ($f -match '^(?<acct>[^@]+)@(?<dns>.+)$') {
        $acct = $Matches.acct
        $dns = $Matches.dns.TrimEnd('.')
        if ($script:VsatLocalDomains -contains $dns) { return (& $local $n) }
        if ($map.ContainsKey($dns)) { return [ordered]@{ key = "ad:$($map[$dns])\$acct"; display = $n; local = $false } }
        return [ordered]@{ key = "upn:$acct@$dns"; display = $n; local = $false }
    }
    return (& $local $n)
}
#endregion Identity
