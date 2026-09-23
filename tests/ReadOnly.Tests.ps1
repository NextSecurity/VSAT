BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:VsatScript, [ref]$null, [ref]$null)
}

Describe 'Default audit makes only approved session/read operations' {
    It 'uses only allowlisted VMware PowerCLI cmdlets' {
        $allowed = @('Get-View', 'Get-VIPermission', 'Get-VIRole', 'Get-EsxCli', 'Get-VMHost', 'Get-Cluster', 'Get-VsanClusterConfiguration', 'Connect-VIServer', 'Disconnect-VIServer', 'Get-PowerCLIConfiguration', 'Set-PowerCLIConfiguration', 'Get-AdvancedSetting')
        $vmwareVerbs = '^(Set|New|Remove|Start|Stop|Restart|Move|Update|Invoke|Add|Install|Mount|Dismount|Enable|Disable|Suspend|Resume|Export|Import|Copy)-(VM|VMHost|Cluster|Datastore|VirtualSwitch|VirtualPortGroup|VDSwitch|VDPortgroup|Snapshot|AdvancedSetting|VIPermission|VIRole|Esx|HardDisk|NetworkAdapter|Folder|Datacenter|Template|Vsan|Tag|ResourcePool|Nsx|Cis)'
        $cmds = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
        $mutating = @($cmds | Where-Object { $_ -match $vmwareVerbs -and $allowed -notcontains $_ })
        $mutating | Should -BeNullOrEmpty
        @($cmds | Where-Object { $_ -in @('Invoke-VMScript', 'Set-VMHostAdvancedConfiguration', 'Set-AdvancedSetting') }) | Should -BeNullOrEmpty
    }
    It 'never changes PowerCLI configuration outside the current session scope' {
        $calls = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Set-PowerCLIConfiguration' }, $true)
        @($calls).Count | Should -BeGreaterThan 0
        foreach ($c in $calls) { $c.Extent.Text | Should -Match '-Scope Session' }
    }
    It 'invokes no mutating vSphere API methods' {
        $members = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) | ForEach-Object { $_.Member.Extent.Text }
        $deny = '^(Reconfig|Update|Set|Remove|Destroy|Create|Move|Rename|Register|Unregister|Power|Reset|Shutdown|Reboot|Enter|Exit|Apply|Revert|Relocate|Clone|Mark|Upgrade|Install|Uninstall|Refresh|Rescan|Change|Add|Delete)[A-Z]'
        $allowedNames = @('Add', 'AddRange', 'AddAccessRule', 'AppendChar', 'Append', 'AppendLine', 'SetAccessRuleProtection', 'SetVariable', 'AddScript', 'Remove', 'RemoveAt', 'SetEnvironmentVariable', 'CreateHandler', 'AddDays', 'CreateEntry', 'CreateRunspace', 'AddHours', 'AddMinutes')
        $hits = @($members | Where-Object { $_ -cmatch $deny -and $allowedNames -notcontains $_ } | Select-Object -Unique)
        $hits | Should -BeNullOrEmpty
    }
    It 'allowlists only read-only esxcli namespaces' {
        foreach ($ns in $script:VsatEsxcliAllowed) { $ns | Should -Match '\.(get|list)$' }
        { Invoke-VsatEsxcli -EsxCli ([pscustomobject]@{}) -Namespace 'system.maintenanceMode.set' } | Should -Throw '*read-only guard*'
    }
}

Describe 'REST read-only guard' {
    It 'allows GET' { { Assert-VsatRestAllowed -Method GET -Path '/policy/api/v1/infra/segments?cursor=abc' } | Should -Not -Throw }
    It 'allows only the session allowlist for non-GET' {
        { Assert-VsatRestAllowed -Method POST -Path '/api/session/create' } | Should -Not -Throw
        { Assert-VsatRestAllowed -Method DELETE -Path '/api/session' } | Should -Not -Throw
    }
    It 'rejects <Method> <Path>' -ForEach @(
        @{ Method = 'POST'; Path = '/policy/api/v1/infra/domains/default/security-policies/x' }
        @{ Method = 'PATCH'; Path = '/policy/api/v1/infra/segments/web' }
        @{ Method = 'PUT'; Path = '/api/v1/node/aaa/auth-policy' }
        @{ Method = 'DELETE'; Path = '/policy/api/v1/infra/tier-1s/t1' }
        @{ Method = 'POST'; Path = '/api/v1/traceflows' }
        @{ Method = 'GET'; Path = '/api/../etc/passwd' }
        @{ Method = 'GET'; Path = 'https://evil.example/api' }
        @{ Method = 'GET'; Path = '//evil.example/api' }
    ) { { Assert-VsatRestAllowed -Method $Method -Path $Path } | Should -Throw '*read-only guard*' }
    It 'does not follow redirects and does not use a proxy' {
        if (Initialize-VsatTls) {
            $h = [VsatTls]::CreateHandler($null)
            $h.AllowAutoRedirect | Should -BeFalse
            $h.UseProxy | Should -BeFalse
            $h.ServerCertificateCustomValidationCallback | Should -BeNullOrEmpty   # OS trust store validation
        }
    }
    It 'requires a well-formed SHA-256 pin' {
        { Register-VsatPins @('nsx01.example.local=abc') } | Should -Throw
        { Register-VsatPins @(('nsx01.example.local=' + ('ab' * 32))) } | Should -Not -Throw
    }
}
