#region Common
Function Get-SerialPort {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        $VM
    )
    Process {
        Foreach ($VMachine in $VM) {
            Foreach ($Device in $VMachine.ExtensionData.Config.Hardware.Device) {
                If ($Device.gettype().Name -eq "VirtualSerialPort"){
                    $Details = New-Object PsObject
                    $Details | Add-Member Noteproperty VM -Value $VMachine
                    $Details | Add-Member Noteproperty Name -Value $Device.DeviceInfo.Label
                    If ($Device.Backing.FileName) { $Details | Add-Member Noteproperty Filename -Value $Device.Backing.FileName }
                    If ($Device.Backing.Datastore) { $Details | Add-Member Noteproperty Datastore -Value $Device.Backing.Datastore }
                    If ($Device.Backing.DeviceName) { $Details | Add-Member Noteproperty DeviceName -Value $Device.Backing.DeviceName }
                    $Details | Add-Member Noteproperty Connected -Value $Device.Connectable.Connected
                    $Details | Add-Member Noteproperty StartConnected -Value $Device.Connectable.StartConnected
                    $Details
                }
            }
        }
    }
}

Function Get-ParallelPort {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        $VM
    )
    Process {
        Foreach ($VMachine in $VM) {
            Foreach ($Device in $VMachine.ExtensionData.Config.Hardware.Device) {
                If ($Device.gettype().Name -eq "VirtualParallelPort"){
                    $Details = New-Object PsObject
                    $Details | Add-Member Noteproperty VM -Value $VMachine
                    $Details | Add-Member Noteproperty Name -Value $Device.DeviceInfo.Label
                    If ($Device.Backing.FileName) { $Details | Add-Member Noteproperty Filename -Value $Device.Backing.FileName }
                    If ($Device.Backing.Datastore) { $Details | Add-Member Noteproperty Datastore -Value $Device.Backing.Datastore }
                    If ($Device.Backing.DeviceName) { $Details | Add-Member Noteproperty DeviceName -Value $Device.Backing.DeviceName }
                    $Details | Add-Member Noteproperty Connected -Value $Device.Connectable.Connected
                    $Details | Add-Member Noteproperty StartConnected -Value $Device.Connectable.StartConnected
                    $Details
                }
            }
        }
    }
}
#endregion Common

#region AuditModules

#region InstallationAduit
# This module assesses against the following CIS controls:
# 1.1 Ensure ESXi is properly patched
# 1.2 Ensure the Image Profile VIB acceptance level is configured properly
# 1.3 Ensure no unauthorized kernel modules are loaded on the host
# 1.4 Ensure the default value of individual salt per vm is configured

function Ensure-ESXiIsProperlyPatched {
    # CIS 1.1 Ensure ESXi is properly patched
    Write-Host "`n* CIS control 1.1 Ensure ESXi is properly patched" -ForegroundColor Blue

    # Read patches from a json file
    $patches = Get-Content -Path $PSScriptRoot\vmware\patches.json | ConvertFrom-Json

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0
    # Get ESXi patches from the host and compare them to the patches in the json file
    Foreach ($VMHost in Get-VMHost) {
        $EsxCli = Get-EsxCli -VMHost $VMHost -V2
        # Get the name and version of the patch and store them in a hashtable
        $esxPatches = $EsxCli.software.vib.list.invoke() | Select-Object @{Name = 'Name'; Expression = { $_.Name } }, @{Name = 'Version'; Expression = { $_.Version } }

        # Compare the patches in the json file to the patches on the host
        Foreach ($hostpatch in $esxPatches) {
            Foreach ($patch in $patches) {
                if ($hostpatch.Name -eq $patch.Name) {
                    if ($hostpatch.Version -ne $patch.Version) {
                        Write-Host "- $($hostpatch.Name): Fail" -ForegroundColor Red
                        Write-Host "  Expected version: $($patch.Version)" -ForegroundColor Red
                        Write-Host "  Actual version: $($hostpatch.Version)" -ForegroundColor Red
                        $failed++
                        break
                    }
                    else {
                        Write-Host "- $($hostpatch.Name): Pass" -ForegroundColor Green
                        $passed++
                        break
                    }
                }
                else {
                    if ($patch -eq $patches[-1]) {
                        Write-Host "- $($hostpatch.Name): Unknown" -ForegroundColor Yellow
                        Write-Host "  Patch not found in the json file" -ForegroundColor Yellow
                        $unknown++
                    }
                }
            }
        }
    }
    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-VIBAcceptanceLevelIsConfiguredProperly {
    # CIS 1.2 Ensure the Image Profile VIB acceptance level is configured properly
    Write-Host "`n* CIS control 1.2 Ensure the Image Profile VIB acceptance level is configured properly" -ForegroundColor Blue

    $passed = 0
    $failed = 0
    $unknown = 0
    # Get the Image Profile acceptance level for each VIB
    Foreach ($VMHost in Get-VMHost) {
        $EsxCli = Get-EsxCli -VMHost $VMHost -V2
        $vibs = $EsxCli.software.vib.list.invoke() | Select-Object @{Name = 'Name'; Expression = { $_.Name } }, @{Name = 'AcceptanceLevel'; Expression = { $_.AcceptanceLevel } }
        # Compare the acceptance level to the expected value
        Foreach ($vib in $vibs) {
            if ($vib.AcceptanceLevel -ne "CommunitySupported" -and $vib.AcceptanceLevel -ne "PartnerSupported" -and $vib.AcceptanceLevel -ne "VMwareCertified") {
                Write-Host "- $($vib.Name): Fail" -ForegroundColor Red
                Write-Host "  Expected acceptance level: communitySupported" -ForegroundColor Red
                Write-Host "  Actual acceptance level: $($vib.AcceptanceLevel)" -ForegroundColor Red
                $failed++
            }
            else {
                Write-Host "- $($vib.Name): Pass" -ForegroundColor Green
                Write-Host "  Acceptance level: $($vib.AcceptanceLevel)" -ForegroundColor Green
                $passed++
            }
        }
    }
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-UnauthorizedModulesNotLoaded {
    # CIS 1.3 Ensure no unauthorized kernel modules are loaded on the host
    Write-Host "`n* CIS control 1.3 Ensure no unauthorized kernel modules are loaded on the host" -ForegroundColor Blue

    # Get the list of loaded kernel modules and check if they are authorized
    $passed = 0
    $failed = 0
    $unknown = 0
    Foreach ($VMHost in Get-VMHost) {
        $ESXCli = Get-EsxCli -VMHost $VMHost
        $systemModules = $ESXCli.system.module.list() | Foreach {
            $ESXCli.system.module.get($_.Name) | Select @{N = "VMHost"; E = { $VMHost } }, Module, License, Modulefile, Version, ContainingVIB, VIBAcceptanceLevel
        }

        # Check if the module corresponding VIB has an acceptance level is certified, exclude vmkernel module
        Foreach ($module in $systemModules) {
            if ($module.Module -ne "vmkernel") {
                if ($module.VIBAcceptanceLevel -ne "certified") {
                Write-Host "- $($module.Module): Fail" -ForegroundColor Red
                Write-Host "  Containing VIB: $($module.ContainingVIB)" -ForegroundColor Red
                Write-Host "  VIB acceptance level: $($module.VIBAcceptanceLevel)" -ForegroundColor Red
                $failed++
                }
                else {
                    Write-Host "- $($module.Module): Pass" -ForegroundColor Green
                    Write-Host "  Containing VIB: $($module.ContainingVIB)" -ForegroundColor Green
                    Write-Host "  VIB acceptance level: $($module.VIBAcceptanceLevel)" -ForegroundColor Green
                    $passed++
                }
            }
        }
    }
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-DefaultSaultIsConfiguredProperly {
    # CIS 1.4 Ensure the default value of individual salt per vm is configured
    Write-Host "`n* CIS control 1.4 Ensure the default value of individual salt per vm is configured" -ForegroundColor Blue

    $passed = 0
    $failed = 0
    $unknown = 0
    # Get the default value of individual salt per vm using Get-AdvancedSetting
    $expectedSaltValue = 2
    $actualSaltValue = Get-VMHost | Get-AdvancedSetting -Name "Mem.ShareForceSalting" | Select-Object -ExpandProperty Value

    # Compare the value to the expected value
    if ($actualSaltValue -ne $expectedSaltValue) {
        Write-Host "- Default value of individual salt per vm: Fail" -ForegroundColor Red
        Write-Host "  Expected value: $expectedSaltValue" -ForegroundColor Red
        Write-Host "  Actual value: $actualSaltValue" -ForegroundColor Red
        $failed++
    }
    else {
        Write-Host "- Default value of individual salt per vm: Pass" -ForegroundColor Green
        Write-Host "  Expected Value: $actualSaltValue" -ForegroundColor Green
        Write-Host "  Actual Value: $actualSaltValue" -ForegroundColor Green
        $passed++
    }
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

#endregion

#region AccessAudit
# This module assesses against the following CIS controls:
# 4.1 (L1) Ensure a non-root user account exists for local admin access
# 4.2 (L1) Ensure passwords are required to be complex
# 4.3 (L1) Ensure the maximum failed login attempts is set to 5
# 4.4 (L1) Ensure account lockout is set to 15 minutes
# 4.5 (L1) Ensure previous 5 passwords are prohibited
# 4.6 (L1) Ensure Active Directory is used for local user authentication
# 4.7 (L1) Ensure only authorized users and groups belong to the esxAdminsGroup group
# 4.8 (L1) Ensure the Exception Users list is properly configured

function Ensure-NonRootExistsForLocalAdmin {
    # CIS 4.1 (L1) Ensure a non-root user account exists for local admin access
    Write-Host "`n* CIS control 4.1 (L1) Ensure a non-root user account exists for local admin access" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-PasswordsAreRequiredToBeComplex {
    # CIS 4.2 (L1) Ensure passwords are required to be complex
    Write-Host "`n* CIS control 4.2 (L1) Ensure passwords are required to be complex" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-LoginAttemptsIsSetTo5 {
    # CIS 4.3 (L1) Ensure the maximum failed login attempts is set to 5
    Write-Host "`n* CIS control 4.3 (L1) Ensure the maximum failed login attempts is set to 5" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the ESXi hosts
    $VMHosts = Get-VMHost | Select Name, @{N="MaxFailedLogin";E={$_ | Get-AdvancedSetting -Name Security.AccountLockFailures | Select -ExpandProperty Value}}

    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.MaxFailedLogin -eq 5) {
            Write-Host "- $($VMHost.Name): Passed" -ForegroundColor Green
            Write-Host "  The maximum failed login attempts is set to 5. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMHost.Name): Failed" -ForegroundColor Red
            Write-Host "  The maximum failed login attempts is not set to 5. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-AccountLockoutIsSetTo15Minutes {
    # CIS 4.4 (L1) Ensure account lockout is set to 15 minutes
    Write-Host "`n* CIS control 4.4 (L1) Ensure account lockout is set to 15 minutes" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the ESXi hosts
    $VMHosts = Get-VMHost | Select Name, @{N="AccountLockoutDuration";E={$_ | Get-AdvancedSetting -Name Security.AccountUnlockTime | Select -ExpandProperty Value}}

    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.AccountLockoutDuration -eq 900) {
            Write-Host "- $($VMHost.Name): Passed" -ForegroundColor Green
            Write-Host "  The account lockout is set to 15 minutes. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMHost.Name): Failed" -ForegroundColor Red
            Write-Host "  The account lockout is not set to 15 minutes. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-Previous5PasswordsAreProhibited {
    # CIS 4.5 (L1) Ensure previous 5 passwords are prohibited
    Write-Host "`n* CIS control 4.5 (L1) Ensure previous 5 passwords are prohibited" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    $VMHosts = Get-VMHost | Select Name, @{N="PasswordHistory";E={$_ | Get-AdvancedSetting -Name Security.PasswordHistory | Select -ExpandProperty Value}}

    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.PasswordHistory -eq 5) {
            Write-Host "- $($VMHost.Name): Passed" -ForegroundColor Green
            Write-Host "  The previous 5 passwords are prohibited. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMHost.Name): Failed" -ForegroundColor Red
            Write-Host "  The previous 5 passwords are not prohibited. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-ADIsUsedForAuthentication {
    # CIS 4.6 (L1) Ensure AD is used for authentication
    Write-Host "`n* CIS control 4.6 (L1) Ensure AD is used for authentication" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    $VMHosts = Get-VMHost | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus

    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.DomainMembershipStatus -ne $null) {
            Write-Host "- $($VMHost.VmHost): Passed" -ForegroundColor Green
            Write-Host "  AD is used for authentication. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMHost.VmHost): Failed" -ForegroundColor Red
            Write-Host "  AD is not used for authentication. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-OnlyAuthorizedUsersBelongToEsxAdminsGroup {
    # CIS 4.7 (L1) Ensure only authorized users belong to the ESX Admins group
    Write-Host "`n* CIS control 4.7 (L1) Ensure only authorized users belong to the ESX Admins group" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-ExceptionUsersIsConfiguredManually {
    # CIS 4.8 (L1) Ensure exception users is configured manually
    Write-Host "`n* CIS control 4.8 (L1) Ensure exception users is configured manually" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}
#endregion

#region CommunicationAudit
# This module assesses against the following CIS controls:
# 2.1 (L1) Ensure NTP time synchronization is configured properly
# 2.2 (L1) Ensure the ESXi host firewall is configured to restrict access to services running on the host
# 2.3 (L1) Ensure Managed Object Browser (MOB) is disabled
# 2.4 (L2) Ensure default self-signed certificate for ESXi communication is not used
# 2.5 (L1) Ensure SNMP is configured properly
# 2.6 (L1) Ensure dvfilter API is not configured if not used
# 2.7 (L1) Ensure expired and revoked SSL certificates are removed from the ESXi server
# 2.8 (L1) Ensure vSphere Authentication Proxy is used when adding hosts to Active Directory
# 2.9 (L2) Ensure VDS health check is disabled

function Ensure-NTPTimeSynchronizationIsConfiguredProperly {
    # CIS 2.1 Ensure NTP time synchronization is configured properly
    Write-Host "`n* CIS control 2.1 Ensure NTP time synchronization is configured properly" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the NTP servers from the host
    $VMHosts = Get-VMHost | Select Name, @{N="NTPSetting";E={$_ | Get-VMHostNtpServer}}

    # Check if the NTP servers are configured properly
    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.NTPSetting -eq $null) {
            Write-Host "- $($VMHost.Name): Fail" -ForegroundColor Red
            Write-Host "  NTP servers are not configured" -ForegroundColor Red
            $failed++
        }
        else {
            Write-Host "- $($VMHost.Name): Pass" -ForegroundColor Green
            Write-Host "  NtpServers: $($VMHost.NTPSetting)" -ForegroundColor Green
            $passed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-ESXiHostFirewallIsProperlyConfigured {
    # CIS 2.2 Ensure the ESXi host firewall is configured to restrict access to services running on the host
    Write-Host "`n* CIS control 2.2 Ensure the ESXi host firewall is configured to restrict access to services running on the host" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Check if the firewall rules are configured properly
    Foreach ($VMHost in Get-VMHost){
        $FirewallExceptions = Get-VMHost $VMHost | Get-VMHostFirewallException

        # Check if the firewall rules are configured properly

        Foreach ($Rule in $FirewallExceptions) {
            if ($Rule.Enabled -eq $true -and ($Rule.ExtensionData.AllowedHosts.AllIP) -eq $true) {
                Write-Host "- $($VMHost.Name): Fail" -ForegroundColor Red
                Write-Host "  Rule $($Rule.Name) is enabled and allows all hosts" -ForegroundColor Red
                $failed++
            }
            else {
                Write-Host "- $($VMHost.Name): Pass" -ForegroundColor Green
                Write-Host "  Rule $($Rule.Name) is disabled or allows specific hosts" -ForegroundColor Green
                $passed++
            }
        }


    }
    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-MOBIsDisabled {
    # CIS 2.3 Ensure Managed Object Browser (MOB) is disabled
    Write-Host "`n* CIS control 2.3 Ensure Managed Object Browser (MOB) is disabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the MOB status from the host
    $VMHosts = Get-VMHost | Select Name, @{N="MOBStatus";E={$_ | Get-AdvancedSetting -Name "Config.HostAgent.plugins.solo.enableMob"}}

    # Check if the MOB is disabled
    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.MOBStatus -eq $true) {
            Write-Host "- $($VMHost.Name): Fail" -ForegroundColor Red
            Write-Host "  MOB is enabled" -ForegroundColor Red
            $failed++
        }
        else {
            Write-Host "- $($VMHost.Name): Pass" -ForegroundColor Green
            Write-Host "  MOB is disabled" -ForegroundColor Green
            $passed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-DefaultSelfSignedCertificateIsNotUsed {
    # CIS 2.4 (L2) Ensure default self-signed certificate for ESXi communication is not used
    Write-Host "`n* CIS control 2.4 (L2) Ensure default self-signed certificate for ESXi communication is not used" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-SNMPIsConfiguredProperly {
    # CIS 2.5 Ensure SNMP is configured properly
    Write-Host "`n* CIS control 2.5 Ensure SNMP is configured properly" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the SNMP status from the host
    $VMHostSnmp = Get-VMHostSnmp

    # Check if any SNMP server is configured and notify the user that they need to invistigate the issue
    if ($VMHostSnmp -ne $null) {
        Write-Host "- SNMP: Unknown" -ForegroundColor Yellow
        Write-Host "  SNMP is enabled, please refer to the vSphere Monitoring and Performance guide, chapter 8 for steps to verify the parameters." -ForegroundColor Yellow
        $unknown++
    }
    else {
        Write-Host "- SNMP: Pass" -ForegroundColor Green
        Write-Host "  SNMP is not enabled" -ForegroundColor Green
        $passed++
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow
    Write-Host "Failed: $failed" -ForegroundColor Red

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-dvfilterIsDisabled {
    # CIS 2.6 Ensure dvfilter is disabled
    Write-Host "`n* CIS control 2.6 Ensure dvfilter is disabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the dvfilter status from the host
    $VMHosts = Get-VMHost | Select Name, @{N="Net.DVFilterBindIpAddress";E={$_ | Get-AdvancedSetting Net.DVFilterBindIpAddress | Select -ExpandProperty Values}}

    # Check if the dvfilter is disabled
    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.Net.DVFilterBindIpAddress -eq $null) {
            Write-Host "- $($VMHost.Name): Pass" -ForegroundColor Green
            Write-Host "  dvfilter is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMHost.Name): Fail" -ForegroundColor Red
            Write-Host "  dvfilter is enabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-DefaultExpiredOrRevokedCertificateIsNotUsed {
    # CIS 2.7 (L1) Ensure expired and revoked SSL certificates are removed from the ESXi server
    Write-Host "`n* CIS control 2.7	(L1) Ensure expired and revoked SSL certificates are removed from the ESXi server" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-vSphereAuthenticationProxyIsUsedWithAD {
    # CIS 2.8 (L1) Ensure vSphere Authentication Proxy is used with Active Directory
    Write-Host "`n* CIS control 2.8 (L1) Ensure vSphere Authentication Proxy is used with Active Directory" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Check each host and their domain membership status
    $VMHostsAuth = Get-VMHost | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus

    # Check if the hosts are joined to a domain or not
    Foreach ($VMHost in $VMHostsAuth) {
        if ($VMHost.DomainMembershipStatus -eq $null) {
            Write-Host "- $($VMHost.VmHost): Fail" -ForegroundColor Red
            Write-Host "  Host is not joined to a domain" -ForegroundColor Red
            $failed++
        }
        else {
            Write-Host "- $($VMHost.VmHost): Pass" -ForegroundColor Green
            Write-Host "  Host is joined to a domain" -ForegroundColor Green
            $passed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-VDSHealthCheckIsDisabled {
    # CIS 2.9 (L2) Ensure VDS Health Check is disabled
    Write-Host "`n* CIS control 2.9 (L2) Ensure VDS Health Check is disabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the VDS Health Check status from the host
    $vds = Get-VDSwitch
    $HealthCheckConfig = $vds.ExtensionData.Config.HealthCheckConfig

    if ($HealthCheckConfig -ne $null) {
        Write-Host "- VDS Health Check: Fail" -ForegroundColor Red
        Write-Host "  VDS Health Check is enabled" -ForegroundColor Red
        $failed++
    }
    else {
        Write-Host "- VDS Health Check: Pass" -ForegroundColor Green
        Write-Host "  VDS Health Check is disabled" -ForegroundColor Green
        $passed++
    }

    # Check if the VDS Health Check is disabled
    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.Net.VDSHealthCheckEnabled -eq $false) {
            Write-Host "- $($VMHost.Name): Pass" -ForegroundColor Green
            Write-Host "  VDS Health Check is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMHost.Name): Fail" -ForegroundColor Red
            Write-Host "  VDS Health Check is enabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}
#endregion

#region VMachinesAudit
# This module assesses against the following CIS controls:
# 8.1.1 (L1) Ensure informational messages from the VM to the VMX file are limited
# 8.1.2 (L2) Ensure only one remote console connection is permitted to a VM at any time
# 8.2.1 (L1) Ensure unnecessary floppy devices are disconnected
# 8.2.2 (L1) Ensure unnecessary CD/DVD devices are disconnected
# 8.2.3	(L1) Ensure unnecessary parallel ports are disconnected
# 8.2.4 (L1) Ensure unnecessary serial ports are disconnected
# 8.2.5 (L1) Ensure unnecessary USB devices are disconnected
# 8.2.6	(L1) Ensure unauthorized modification and disconnection of devices is disabled
# 8.2.7	(L1) Ensure unauthorized connection of devices is disabled
# 8.2.8	(L1) Ensure PCI and PCIe device passthrough is disabled
# 8.4.2 (L2) Ensure Autologon is disabled
# 8.4.3	(L2) Ensure BIOS BBS is disabled
# 8.4.4 (L1) Ensure Guest Host Interaction Protocol Handler is set to disabled
# 8.4.5	(L2) Ensure Unity Taskbar is disabled
# 8.4.6	(L2) Ensure Unity Active is disabled
# 8.4.7	(L2) Ensure Unity Window Contents is disabled
# 8.4.8	(L2) Ensure Unity Push Update is disabled
# 8.4.9 (L2) Ensure Drag and Drop Version Get is disabled
# 8.4.10 (L2) Ensure Drag and Drop Version Set is disabled
# 8.4.11 (L2) Ensure Shell Action is disabled
# 8.4.12 (L2) Ensure Request Disk Topology is disabled
# 8.4.13 (L2) Ensure Trash Folder State is disabled
# 8.4.14 (L2) Ensure Guest Host Interaction Tray Icon is disabled
# 8.4.15 (L2) Ensure Unity is disabled
# 8.4.16 (L2) Ensure Unity Interlock is disabled
# 8.4.17 (L2) Ensure GetCreds is disabled
# 8.4.18 (L2) Ensure Host Guest File System Server is disabled
# 8.4.19 (L2) Ensure Guest Host Interaction Launch Menu is disabled
# 8.4.20 (L2) Ensure memSchedFakeSampleStats is disabled
# 8.4.21 (L2) Ensure VM Console Copy operations are disabled
# 8.4.22 (L2) Ensure VM Console Drag and Drop operations is disabled
# 8.4.23 (L1) Ensure VM Console GUI Options is disabled
# 8.4.24 (L1) Ensure VM Console Paste operations are disabled

# Import utility functions

function Ensure-InformationalMessagesFromVMToVMXLimited {
    # CIS 8.1.1 (L1) Ensure informational messages from the VM to the VMX file are limited
    Write-Host "`n* CIS control 8.1.1 (L1) Ensure informational messages from the VM to the VMX file are limited" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Recommended value
    $recommendedsizeLimit = 1048576

    # Get size limit from VM
    $sizeLimitByVM = Get-VM | Select Name, @{N = "SizeLimit"; E = { Get-AdvancedSetting -Entity $_ -Name "tools.setInfo.sizeLimit" | Select -ExpandProperty Value } }

    # Check if the size limit is set to the recommended value
    Foreach ($sizeLimit in $sizeLimitByVM) {
        if ($sizeLimit.SizeLimit -eq $recommendedsizeLimit) {
            Write-Host "- $($sizeLimit.Name): Passed" -ForegroundColor Green
            Write-Host "  Size limit is set to the recommended value of $recommendedsizeLimit" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($sizeLimit.Name): Failed" -ForegroundColor Red
            Write-Host "  Size limit : $($sizeLimit.SizeLimit)" -ForegroundColor Red
            Write-Host "  Recommended size limit: $recommendedsizeLimit" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-OnlyOneRemoteConnectionIsPermittedToVMAtAnyTime {
    # CIS 8.1.2 (L2) Ensure only one remote console connection is permitted to a VM at any time
    Write-Host "`n* CIS control 8.1.2 (L2) Ensure only one remote console connection is permitted to a VM at any time" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Recommended value
    $recommendedMaxConnections = 1

    # Get max connections from VM
    $maxConnectionsByVM = Get-VM | Select Name, @{N = "MaxConnections"; E = { Get-AdvancedSetting -Entity $_ -Name "RemoteDisplay.maxConnections" | Select -ExpandProperty Value } }

    # Check if the max connections is set to the recommended value
    Foreach ($maxConnections in $maxConnectionsByVM) {
        if ($maxConnections.MaxConnections -eq $recommendedMaxConnections) {
            Write-Host "- $($maxConnections.Name): Passed" -ForegroundColor Green
            Write-Host "  Max connections is set to the recommended value of $recommendedMaxConnections" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($maxConnections.Name): Failed" -ForegroundColor Red
            Write-Host "  Max connections : $($maxConnections.MaxConnections)" -ForegroundColor Red
            Write-Host "  Recommended max connections: $recommendedMaxConnections" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-UnnecessaryFloppyDevicesAreDisconnected {
    # CIS 8.2.1 (L1) Ensure unnecessary floppy devices are disconnected
    Write-Host "`n* CIS control 8.2.1 (L1) Ensure unnecessary floppy devices are disconnected" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get floppy devices from VM
    $floppyDevicesByVM = Get-VM | Get-FloppyDrive | Select @{N = "VM"; E = { $_.Parent } }, Name, ConnectionState

    # Check if the ConnectionState.Connected is set to false
    Foreach ($floppyDevice in $floppyDevicesByVM) {
        if ($floppyDevice.ConnectionState.Connected -eq $false) {
            Write-Host "- $($floppyDevice.VM): Passed" -ForegroundColor Green
            Write-Host "  Floppy device $($floppyDevice.Name) is disconnected" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($floppyDevice.VM): Failed" -ForegroundColor Red
            Write-Host "  Floppy device $($floppyDevice.Name) is connected" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnnecessaryCdDvdDevicesAreDisconnected {
    # CIS 8.2.2 (L1) Ensure unnecessary CD/DVD devices are disconnected
    Write-Host "`n* CIS control 8.2.2 (L1) Ensure unnecessary CD/DVD devices are disconnected" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get CD/DVD devices from VM
    $cdDvdDevicesByVM = Get-VM | Get-CDDrive | Select @{N = "VM"; E = { $_.Parent } }, Name, ConnectionState

    # Check if the ConnectionState.Connected is set to false
    Foreach ($cdDvdDevice in $cdDvdDevicesByVM) {
        if ($cdDvdDevice.ConnectionState.Connected -eq $false) {
            Write-Host "- $($cdDvdDevice.VM): Passed" -ForegroundColor Green
            Write-Host "  CD/DVD device $($cdDvdDevice.Name) is disconnected" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($cdDvdDevice.VM): Failed" -ForegroundColor Red
            Write-Host "  CD/DVD device $($cdDvdDevice.Name) is connected" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-UnnecessaryParallelPortsAreDisconnected {
    # CIS 8.2.3 (L1) Ensure unnecessary parallel ports are disconnected
    Write-Host "`n* CIS control 8.2.3 (L1) Ensure unnecessary parallel ports are disconnected" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get parallel ports from VM
    $parallelPortsByVM = Get-VM | Get-ParallelPort | Select VM, Name, Connected

    # Check if the Connected is set to false, if none is found, the test is passed
    Foreach ($parallelPort in $parallelPortsByVM) {
        if ($parallelPort.Connected -eq $false) {
            Write-Host "- $($parallelPort.VM): Passed" -ForegroundColor Green
            Write-Host "  Parallel port $($parallelPort.Name) is disconnected" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($parallelPort.VM): Failed" -ForegroundColor Red
            Write-Host "  Parallel port $($parallelPort.Name) is connected" -ForegroundColor Red
            $failed++
        }
    }

    # if none is found, the test is passed
    if ($parallelPortsByVM.Count -eq 0) {
        Write-Host "- Passed" -ForegroundColor Green
        Write-Host "  No parallel ports found" -ForegroundColor Green
        $passed++
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-UnnecessarySerialPortsAreDisabled {
    # CIS 8.2.4 (L1) Ensure unnecessary serial ports are disabled
    Write-Host "`n* CIS control 8.2.4 (L1) Ensure unnecessary serial ports are disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get serial ports from VM
    $serialPortsByVM = Get-VM | Get-SerialPort | Select VM, Name, Connected

    # Check if the Connected is set to false, if none is found, the test is passed
    Foreach ($serialPort in $serialPortsByVM) {
        if ($serialPort.Connected -eq $false) {
            Write-Host "- $($serialPort.VM): Passed" -ForegroundColor Green
            Write-Host "  Serial port $($serialPort.Name) is disconnected" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($serialPort.VM): Failed" -ForegroundColor Red
            Write-Host "  Serial port $($serialPort.Name) is connected" -ForegroundColor Red
            $failed++
        }
    }

    # if none is found, the test is passed
    if ($serialPortsByVM.Count -eq 0) {
        Write-Host "- Passed" -ForegroundColor Green
        Write-Host "  No serial ports found" -ForegroundColor Green
        $passed++
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnnecessaryUsbDevicesAreDisconnected {
    # CIS 8.2.5 (L1) Ensure unnecessary USB devices are disconnected
    Write-Host "`n* CIS control 8.2.5 (L1) Ensure unnecessary USB devices are disconnected" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get USB devices from VM
    $usbDevicesByVM = Get-VM | Get-USBDevice | Select @{N = "VM"; E = { $_.Parent } }, Name, ConnectionState

    # Check if the ConnectionState.Connected is set to false
    Foreach ($usbDevice in $usbDevicesByVM) {
        if ($usbDevice.ConnectionState.Connected -eq $false) {
            Write-Host "- $($usbDevice.VM): Passed" -ForegroundColor Green
            Write-Host "  USB device $($usbDevice.Name) is disconnected" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($usbDevice.VM): Failed" -ForegroundColor Red
            Write-Host "  USB device $($usbDevice.Name) is connected" -ForegroundColor Red
            $failed++
        }
    }

    # if none is found, the test is passed
    if ($usbDevicesByVM.Count -eq 0) {
        Write-Host "- Passed" -ForegroundColor Green
        Write-Host "  No USB devices found" -ForegroundColor Green
        $passed++
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnauthorizedModificationOrDisconnectionOfDevicesIsDisabled {
    # CIS 8.2.6 (L1) Ensure unauthorized modification or disconnection of devices is disabled
    Write-Host "`n* CIS control 8.2.6 (L1) Ensure unauthorized modification or disconnection of devices is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "EditDisable"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.device.edit.disable" | Select -ExpandProperty Value } }

    # Check if the EditDisable is set to true
    Foreach ($vm in $vms) {
        if ($vm.EditDisable -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unauthorized modification or disconnection of devices is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unauthorized modification or disconnection of devices is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnauthorizedConnectionOfDevicesIsDisabled {
    # CIS 8.2.7 (L1) Ensure unauthorized connection of devices is disabled
    Write-Host "`n* CIS control 8.2.7 (L1) Ensure unauthorized connection of devices is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "ConnectDisable"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.device.connectable.disable" | Select -ExpandProperty Value } }

    # Check if the ConnectDisable is set to true
    Foreach ($vm in $vms) {
        if ($vm.ConnectDisable -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unauthorized connection of devices is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unauthorized connection of devices is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-PciPcieDevicePassthroughIsDisabled {
    # CIS 8.2.8 (L1) Ensure PCI/PCIe device passthrough is disabled
    Write-Host "`n* CIS control 8.2.8 (L1) Ensure PCI/PCIe device passthrough is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "PassthroughDisable"; E = { Get-AdvancedSetting -Entity $_ -Name "pciPassthru*.present" | Select -ExpandProperty Value } }

    # Check if the PassthroughDisable is not set to true
    Foreach ($vm in $vms) {
        if ($vm.PassthroughDisable -ne $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  PCI/PCIe device passthrough is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  PCI/PCIe device passthrough is enabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnnecessaryFunctionsInsideVMsAreDisabled {
    # CIS 8.3.1 (L1) Ensure unnecessary or superfluous functions inside VMs are disabled
    Write-Host "`n* CIS control 8.3.1 (L1) Ensure unnecessary or superfluous functions inside VMs are disabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

}

function Ensure-UseOfTheVMConsoleIsLimited {
    # CIS 8.3.2	(L1) Ensure use of the VM console is limited (Manual)
    Write-Host "`n* CIS control 8.3.2 (L1) Ensure use of the VM console is limited" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-SecureProtocolsAreUsedForVirtualSerialPortAccess {
    # CIS 8.3.3	(L1) Ensure secure protocols are used for virtual serial port access
    Write-Host "`n* CIS control 8.3.3 (L1) Ensure secure protocols are used for virtual serial port access" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-StandardProcessesAreUsedForVMDeployment {
    # CIS 8.3.4	(L1) Ensure standard processes are used for VM deployment
    Write-Host "`n* CIS control 8.3.4 (L1) Ensure standard processes are used for VM deployment" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-AccessToVMsThroughDvFilterNetworkAPIsIsConfiguredCorrectly {
    # CIS 8.4.1	(L1) Ensure access to VMs through the dvfilter network APIs is configured correctly
    Write-Host "`n* CIS control 8.4.1 (L1) Ensure access to VMs through the dvfilter network APIs is configured correctly" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-AutologonIsDisabled {
    # CIS 8.4.2 (L1) Ensure Autologon is disabled
    Write-Host "`n* CIS control 8.4.2 (L2) Ensure Autologon is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "AutoLogon"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.ghi.autologon.disable" | Select -ExpandProperty Value } }

    # Check if the AutoLogon is not set to true
    Foreach ($vm in $vms) {
        if ($vm.AutoLogon -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Autologon is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Autologon is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-BIOSBBSIsDisabled {
    # CIS 8.4.3 (L2) Ensure BIOS Boot Specification (BBS) is disabled
    Write-Host "`n* CIS control 8.4.3 (L1) Ensure BIOS Boot Specification (BBS) is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "BBS"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.bios.bbs.disable" | Select -ExpandProperty Value } }

    # Check if the BIOS BBS is set to true
    Foreach ($vm in $vms) {
        if ($vm.BBS -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  BIOS Boot Specification (BBS) is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  BIOS Boot Specification (BBS) is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-GuestHostInteractionProtocolIsDisabled {
    # CIS 8.4.4 (L1) Ensure Guest Host Interaction Protocol Handler is set to disabled
    Write-Host "`n* CIS control 8.4.4 (L1) Ensure Guest Host Interaction Protocol Handler is set to disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "GHI"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.ghi.protocolhandler.info.disable" | Select -ExpandProperty Value } }

    # Check if the GHI is set to true
    Foreach ($vm in $vms) {
        if ($vm.GHI -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Guest Host Interaction Protocol Handler is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Guest Host Interaction Protocol Handler is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnityTaskBarIsDisabled {
    # CIS 8.4.5 (L2) Ensure Unity Taskbar is disabled
    Write-Host "`n* CIS control 8.4.5 (L2) Ensure Unity Taskbar is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.unity.taskbar.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unity Taskbar is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unity Taskbar is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }



}

function Ensure-UnityActiveIsDisabled {
    # CIS 8.4.6 (L2) Ensure Unity Active is disabled
    Write-Host "`n* CIS control 8.4.6 (L2) Ensure Unity Active is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.unityActive.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unity Active is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unity Active is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnityWindowContentsIsDisabled {
    # CIS 8.4.7 (L2) Ensure Unity Window Contents is disabled
    Write-Host "`n* CIS control 8.4.7 (L2) Ensure Unity Window Contents is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.unityWindowContents.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unity Window Contents is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unity Window Contents is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UnityPushUpdateIsDisabled {
    # CIS 8.4.8 (L2) Ensure Unity Push Update is disabled
    Write-Host "`n* CIS control 8.4.8 (L2) Ensure Unity Push Update is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.unity.push.update.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unity Push Update is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unity Push Update is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-DragAndDropVersionGetIsDisabled {
    # CIS 8.4.9 (L2) Ensure Drag and Drop Version Get is disabled
    Write-Host "`n* CIS control 8.4.9 (L2) Ensure Drag and Drop Version Get is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.vmxDnDVersionGet.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Drag and Drop Version Get is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Drag and Drop Version Get is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }



}

function Ensure-DragAndDropVersionSetIsDisabled {
    # CIS 8.4.10 (L2) Ensure Drag and Drop Version Set is disabled
    Write-Host "`n* CIS control 8.4.10 (L2) Ensure Drag and Drop Version Set is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.vmxDnDVersionSet.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Drag and Drop Version Set is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Drag and Drop Version Set is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-ShellActionIsDisabled {
    # CIS 8.4.11 (L2) Ensure Shell Action is disabled
    Write-Host "`n* CIS control 8.4.11 (L2) Ensure Shell Action is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.ghi.host.shellAction.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Shell Action is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Shell Action is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-DiskRequestTopologyIsDisabled {
    # CIS 8.4.12 (L2) Ensure Request Disk Topology is disabled
    Write-Host "`n* CIS control 8.4.12 (L2) Ensure Request Disk Topology is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.dispTopoRequest.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Disk Topology is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Disk Topology is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-TrashFolderStateIsDisabled {
    # CIS 8.4.13 (L2) Ensure Trash Folder State is disabled
    Write-Host "`n* CIS control 8.4.13 (L2) Ensure Trash Folder State is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.trashFolderState.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Trash Folder State is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Trash Folder State is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-GuestHostInterationTrayIconIsDisabled {
    # CIS 8.4.14 (L2) Ensure Guest Host Interation Tray Icon is disabled
    Write-Host "`n* CIS control 8.4.14 (L2) Ensure Guest Host Interation Tray Icon is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.ghi.trayicon.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Guest Host Interation Tray Icon is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Guest Host Interation Tray Icon is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-UnityIsDisabled {
    # CIS 8.4.15 (L2) Ensure Unity is disabled
    Write-Host "`n* CIS control 8.4.15 (L2) Ensure Unity is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.unity.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unity is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unity is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-UnityInterlockIsDisabled {
    # CIS 8.4.16 (L2) Ensure Unity Interlock is disabled
    Write-Host "`n* CIS control 8.4.16 (L2) Ensure Unity Interlock is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.unityInterlockOperation.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Unity Interlock is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Unity Interlock is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-GetCredsIsDisabled {
    # CIS 8.4.17 (L2) Ensure Get Creds is disabled
    Write-Host "`n* CIS control 8.4.17 (L2) Ensure Get Creds is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "Unity"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.getCreds.disable" | Select -ExpandProperty Value } }

    # Check if the Unity is set to true
    Foreach ($vm in $vms) {
        if ($vm.Unity -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Get Creds is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Get Creds is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-HostGuestFileSystemServerIsDisabled {
    # CIS 8.4.18 (L2) Ensure Host-Guest File System Service is disabled
    Write-Host "`n* CIS control 8.4.18 (L2) Ensure Host-Guest File System Service is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "HostGuestFileSystemServer"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.hgfsServerSet.disable" | Select -ExpandProperty Value } }

    # Check if the HostGuestFileSystemServer is set to true
    Foreach ($vm in $vms) {
        if ($vm.HostGuestFileSystemServer -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Host-Guest File System Service is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Host-Guest File System Service is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-GuestHostInteractionLaunchMenuIsDisabled {
    # CIS 8.4.19 (L2) Ensure Guest Host Interaction Service is disabled
    Write-Host "`n* CIS control 8.4.19 (L2) Ensure Guest Host Interaction Service is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "GuestHostInteractionLaunchMenu"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.ghi.launchmenu.change" | Select -ExpandProperty Value } }

    # Check if the GuestHostInteractionLaunchMenu is set to true
    Foreach ($vm in $vms) {
        if ($vm.GuestHostInteractionLaunchMenu -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Guest Host Interaction Service is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Guest Host Interaction Service is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-memSchedFakeSampleStatsIsDisabled {
    # CIS 8.4.20 (L2) Ensure memSchedFakeSampleStats is disabled
    Write-Host "`n* CIS control 8.4.20 (L2) Ensure memSchedFakeSampleStats is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "memSchedFakeSampleStats"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.memSchedFakeSampleStats.disable" | Select -ExpandProperty Value } }

    # Check if the memSchedFakeSampleStats is set to true
    Foreach ($vm in $vms) {
        if ($vm.memSchedFakeSampleStats -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  memSchedFakeSampleStats is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  memSchedFakeSampleStats is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-VMConsoleCopyOperationsAreDisabled {
    # CIS 8.4.21 (L2) Ensure VM Console Copy Operations are disabled
    Write-Host "`n* CIS control 8.4.21 (L2) Ensure VM Console Copy Operations are disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "VMConsoleCopyOperations"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.copy.disable" | Select -ExpandProperty Value } }

    # Check if the VMConsoleCopyOperations is missing or is set to true
    Foreach ($vm in $vms) {
        if ($vm.VMConsoleCopyOperations -eq $null -or $vm.VMConsoleCopyOperations -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  VM Console Copy Operations are disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  VM Console Copy Operations are not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-VMConsoleDragAndDropOprerationsIsDisabled {
    # CIS 8.4.22 (L2) Ensure VM Console Drag and Drop Oprerations are disabled
    Write-Host "`n* CIS control 8.4.22 (L2) Ensure VM Console Drag and Drop Oprerations are disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "VMConsoleDragAndDropOprerations"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.dnd.disable" | Select -ExpandProperty Value } }

    # Check if the VMConsoleDragAndDropOprerations is set to true or is missing
    Foreach ($vm in $vms) {
        if ($vm.VMConsoleDragAndDropOprerations -eq $null -or $vm.VMConsoleDragAndDropOprerations -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  VM Console Drag and Drop Oprerations are disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  VM Console Drag and Drop Oprerations are not disabled" -ForegroundColor Red
            $failed++
        }
    }
    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-VMConsoleGUIOptionsIsDisabled {
    # CIS 8.4.23 (L2) Ensure VM Console GUI Options are disabled
    Write-Host "`n* CIS control 8.4.23 (L2) Ensure VM Console GUI Options are disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "VMConsoleGUIOptions"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.setGUIOptions.enable" | Select -ExpandProperty Value } }

    # Check if the VMConsoleGUIOptions is set to false or is missing
    Foreach ($vm in $vms) {
        if ($vm.VMConsoleGUIOptions -eq $null -or $vm.VMConsoleGUIOptions -eq $false) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  VM Console GUI Options are disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  VM Console GUI Options are not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-VMConsolePasteOperationsAreDisabled {
    # CIS 8.4.24 (L1) Ensure VM Console Paste Operations are disabled
    Write-Host "`n* CIS control 8.4.24 (L1) Ensure VM Console Paste Operations are disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "VMConsolePasteOperations"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.paste.disable" | Select -ExpandProperty Value } }

    # Check if the VMConsolePasteOperations is set to true or missing
    Foreach ($vm in $vms) {
        if ($vm.VMConsolePasteOperations -eq $null -or $vm.VMConsolePasteOperations -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  VM Console Paste Operations are disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  VM Console Paste Operations are not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-VMLimitsAreConfiguredCorrectly {
    # CIS 8.5.1	(L2) Ensure VM limits are configured correctly
    Write-Host "`n* CIS control 8.5.1 (L2) Ensure VM limits are configured correctly" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-HardwareBased3DAccelerationIsDisabled {
    # CIS 8.5.2	(L2) Ensure hardware-based 3D acceleration is disabled
    Write-Host "`n* CIS control 8.5.2 (L2) Ensure hardware-based 3D acceleration is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "HardwareBased3DAcceleration"; E = { Get-AdvancedSetting -Entity $_ -Name "mks.enable3d" | Select -ExpandProperty Value } }

    # Check if the HardwareBased3DAcceleration is set to false
    Foreach ($vm in $vms) {
        if ($vm.HardwareBased3DAcceleration -eq $false) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Hardware-based 3D acceleration is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Hardware-based 3D acceleration is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-NonPersistentDisksAreLimited {
    # CIS 8.6.1	(L2) Ensure non-persistent disks are limited
    Write-Host "`n* CIS control 8.6.1 (L2) Ensure non-persistent disks are limited" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence

    # Verify that persistence is absent or set to a value other than "nonpersistent"
    Foreach ($vm in $vms) {
        if ($vm.Persistence -eq $null -or $vm.Persistence -ne "nonpersistent") {
            Write-Host "- $($vm.Parent): Passed" -ForegroundColor Green
            Write-Host "  Persistence mode : $($vm.Persistence)" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Parent): Failed" -ForegroundColor Red
            Write-Host "  Non-persistent disks are not limited" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-VirtualDiskShrinkingIsDisabled {
    # CIS 8.6.2	(L2) Ensure virtual disk shrinking is disabled
    Write-Host "`n* CIS control 8.6.2 (L2) Ensure virtual disk shrinking is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "VirtualDiskShrinking"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.diskShrink.disable" | Select -ExpandProperty Value } }

    # Check if the VirtualDiskShrinking is set to true
    Foreach ($vm in $vms) {
        if ($vm.VirtualDiskShrinking -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Virtual disk shrinking is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Virtual disk shrinking is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }



}

function Ensure-VirtualDiskWipingIsDisabled {
    # CIS 8.6.3	(L1) Ensure virtual disk wiping is disabled
    Write-Host "`n* CIS control 8.6.3 (L1) Ensure virtual disk wiping is disabled" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "VirtualDiskWiping"; E = { Get-AdvancedSetting -Entity $_ -Name "isolation.tools.diskWiper.disable" | Select -ExpandProperty Value } }

    # Check if the VirtualDiskWiping is set to true
    Foreach ($vm in $vms) {
        if ($vm.VirtualDiskWiping -eq $true) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Virtual disk wiping is disabled" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Virtual disk wiping is not disabled" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-TheNumberOfVMLogFilesIsConfiguredProperly {
    # CIS 8.7.1	(L1) Ensure the number of VM log files is configured properly
    Write-Host "`n* CIS control 8.7.1 (L1) Ensure the number of VM log files is configured properly" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "NumberOfVMLogFiles"; E = { Get-AdvancedSetting -Entity $_ -Name "log.keepOld" | Select -ExpandProperty Value } }

    # Check if the NumberOfVMLogFiles is set to 10
    Foreach ($vm in $vms) {
        if ($vm.NumberOfVMLogFiles -eq 10) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Number of VM log files is configured properly" -ForegroundColor Green
            Write-Host "  Number of VM log files: $($vm.NumberOfVMLogFiles)" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Current value: $($vm.NumberOfVMLogFiles)" -ForegroundColor Red
            Write-Host "  Expected value: 10" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-HostInformationIsNotSentToGuests {
    # CIS 8.7.2	(L2) Ensure host information is not sent to guests
    Write-Host "`n* CIS control 8.7.2 (L2) Ensure host information is not sent to guests" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "HostInformation"; E = { Get-AdvancedSetting -Entity $_ -Name "tools.guestlib.enableHostInfo" | Select -ExpandProperty Value } }

    # Check if the HostInformation is set to false
    Foreach ($vm in $vms) {
        if ($vm.HostInformation -eq $false) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  Host information is not sent to guests" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Host information is sent to guests" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-VMLogFileSizeIsLimited {
    # CIS 8.7.3	(L1) Ensure VM log file size is limited
    Write-Host "`n* CIS control 8.7.3 (L1) Ensure VM log file size is limited" -ForegroundColor Blue

    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMs
    $vms = Get-VM | Select Name, @{N = "VMLogFileSize"; E = { Get-AdvancedSetting -Entity $_ -Name "log.rotateSize" | Select -ExpandProperty Value } }

    # Check if the VMLogFileSize is set to 1024000
    Foreach ($vm in $vms) {
        if ($vm.VMLogFileSize -eq 1024000) {
            Write-Host "- $($vm.Name): Passed" -ForegroundColor Green
            Write-Host "  VM log file size is limited" -ForegroundColor Green
            Write-Host "  VM log file size: $($vm.VMLogFileSize)" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($vm.Name): Failed" -ForegroundColor Red
            Write-Host "  Current value: $($vm.VMLogFileSize)" -ForegroundColor Red
            Write-Host "  Expected value: 1024000" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}
#endregion

#region StorageAudit
# This module assesses against the following CIS controls:
# 6.1 (L1) Ensure bidirectional CHAP authentication for iSCSI traffic is enabled
# 6.2 (L2) Ensure the uniqueness of CHAP authentication secrets for iSCSI traffic
# 6.3 (L1) Ensure storage area network (SAN) resources are segregated properly

function Ensure-BidirectionalCHAPAuthIsEnabled {
    # CIS 6.1 (L1) Ensure bidirectional CHAP authentication for iSCSI traffic is enabled
    Write-Host "`n* CIS control 6.1 (L1) Ensure bidirectional CHAP authentication for iSCSI traffic is enabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Get-VMHostHba | Select VMHost, Type
    # Check for Iscsi HBAs and whether they have bidirectional CHAP enabled
    Foreach ($VMHostHba in $VMhosts ){
        if ($VMHostHba.Type -eq "Iscsi") {
           $iSCSIProperties = Get-VMHost $VMHostHba.VMHost | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}
            Foreach ($iSCSIProperty in $iSCSIProperties) {
                if ($iSCSIProperty.ChapType -eq "Bidirectional") {
                    Write-Host "- Check Passed" -ForegroundColor Green
                    Write-Host "  Bidirectional CHAP authentication is enabled for $($iSCSIProperty.VMHost) on $($iSCSIProperty.Device)" -ForegroundColor Green
                    $passed++
                }
                else {
                    Write-Host "- Check Failed" -ForegroundColor Red
                    Write-Host "  Bidirectional CHAP authentication is not enabled for $($iSCSIProperty.VMHost) on $($iSCSIProperty.Device)" -ForegroundColor Red
                    $failed++
                }
            }
        }
        else {
            if ($VMHostHba -eq $VMhosts[-1]) {
                Write-Host "- Check Unknown" -ForegroundColor Yellow
                Write-Host "  No iSCSI HBAs found" -ForegroundColor Yellow
                $unknown++
            }
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-UniquenessOfCHAPAuthSecretsForiSCSI {
    # CIS 6.2 (L2) Ensure the uniqueness of CHAP authentication secrets for iSCSI traffic
    Write-Host "`n* CIS control 6.2 (L2) Ensure the uniqueness of CHAP authentication secrets for iSCSI traffic" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-SANResourcesAreSegregatedProperly {
    # CIS 6.3 (L1) Ensure storage area network (SAN) resources are segregated properly
    Write-Host "`n* CIS control 6.3 (L1) Ensure storage area network (SAN) resources are segregated properly" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}
#endregion

#region ConsoleAudit
# This module assesses against the following CIS controls:
# 5.1 (L1) Ensure the DCUI timeout is set to 600 seconds or less
# 5.2 (L1) Ensure the ESXi shell is disabled
# 5.3 (L1) Ensure SSH is disabled
# 5.4 (L1) Ensure CIM access is limited
# 5.5 (L1) Ensure Normal Lockdown mode is enabled
# 5.6 (L2) Ensure Strict Lockdown mode is enabled
# 5.7 (L2) Ensure the SSH authorized_keys file is empty
# 5.8 (L1) Ensure idle ESXi shell and SSH sessions time out after 300 seconds or less
# 5.9 (L1) Ensure the shell services timeout is set to 1 hour or less
# 5.10 (L1) Ensure DCUI has a trusted users list for lockdown mode
# 5.11 (L2) Ensure contents of exposed configuration files have not been modified

function Ensure-DCUITimeOutIs600 {
    # CIS 5.1 (L1) Ensure the DCUI timeout is set to 600 seconds or less
    Write-Host "`n* CIS control 5.1 (L1) Ensure the DCUI timeout is set to 600 seconds or less" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Select Name, @{N="DcuiTimeOut";E={$_ | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Select -ExpandProperty Value}}

    # Check the DCUI timeout
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.DcuiTimeOut -le 600) {
            Write-Host "- $($VMhost.Name): Passed" -ForegroundColor Green
            Write-Host "  The DCUI timeout is set to 600 seconds or less. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.Name): Failed" -ForegroundColor Red
            Write-Host "  The DCUI timeout is not set to 600 seconds or less. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-ESXiShellIsDisabled {
    # CIS 5.2 (L1) Ensure the ESXi shell is disabled
    Write-Host "`n* CIS control 5.2 (L1) Ensure the ESXi shell is disabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Get-VMHostService | Where { $_.key -eq "TSM" } | Select VMHost, Policy

    # Check the ESXi shell
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.Policy -eq "off") {
            Write-Host "- $($VMhost.VMHost): Passed" -ForegroundColor Green
            Write-Host "  The ESXi shell is disabled. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.VMHost): Failed" -ForegroundColor Red
            Write-Host "  The ESXi shell is not disabled. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-SSHIsDisabled {
    # CIS 5.3 (L1) Ensure SSH is disabled
    Write-Host "`n* CIS control 5.3 (L1) Ensure SSH is disabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Get-VMHostService | Where { $_.key -eq "TSM-SSH" } | Select VMHost, Policy

    # Check SSH
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.Policy -eq "off") {
            Write-Host "- $($VMhost.VMHost): Passed" -ForegroundColor Green
            Write-Host "  SSH is disabled. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.VMHost): Failed" -ForegroundColor Red
            Write-Host "  SSH is not disabled. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-CIMAccessIsLimited {
    # CIS 5.4 (L1) Ensure CIM access is limited
    Write-Host "`n* CIS control 5.4 (L1) Ensure CIM access is limited" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1


    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-NormalLockDownIsEnabled {
    # CIS 5.5 (L1) Ensure Normal Lockdown mode is enabled
    Write-Host "`n* CIS control 5.5 (L1) Ensure Normal Lockdown mode is enabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

    # Check the lockdown mode
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.Lockdown -eq "Normal") {
            Write-Host "- $($VMhost.Name): Passed" -ForegroundColor Green
            Write-Host "  Normal Lockdown mode is enabled. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.Name): Failed" -ForegroundColor Red
            Write-Host "  Normal Lockdown mode is not enabled. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-StrickLockdownIsEnabled {
    # CIS 5.6 (L2) Ensure Strict Lockdown mode is enabled
    Write-Host "`n* CIS control 5.6 (L2) Ensure Strict Lockdown mode is enabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

    # Check the lockdown mode
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.Lockdown -eq "Strict") {
            Write-Host "- $($VMhost.Name): Passed" -ForegroundColor Green
            Write-Host "  Strict Lockdown mode is enabled. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.Name): Failed" -ForegroundColor Red
            Write-Host "  Strict Lockdown mode is not enabled. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-SSHAuthorisedKeysFileIsEmpty {
    # CIS 5.7 (L2) Ensure SSH Authorized Keys file is empty
    Write-Host "`n* CIS control 5.7 (L2) Ensure SSH Authorized Keys file is empty" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow
    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }
}

function Ensure-IdleESXiShellAndSSHTimeout {
    # CIS 5.8 (L1) Ensure idle ESXi shell and SSH sessions time out after 300 seconds or less
    Write-Host "`n* CIS control 5.8 (L1) Ensure idle ESXi shell and SSH sessions time out after 300 seconds or less" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Select Name, @{N="UserVars.ESXiShellInteractiveTimeOut";E={$_ | Get-AdvancedSetting UserVars.ESXiShellInteractiveTimeOut | Select -ExpandProperty Values}}

    # Check the timeout
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.UserVars.ESXiShellInteractiveTimeOut -le 300 -and $VMhost.UserVars.ESXiShellInteractiveTimeOut -gt 0) {
            Write-Host "- $($VMhost.Name): Passed" -ForegroundColor Green
            Write-Host "  Idle ESXi shell and SSH sessions time out after 300 seconds or less. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.Name): Failed" -ForegroundColor Red
            Write-Host "  Idle ESXi shell and SSH sessions time out not configured properly. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-ShellServicesTimeoutIsProperlyConfigured {
    # CIS 5.9 (L1) Ensure the shell services timeout is set to 1 hour or less
    Write-Host "`n* CIS control 5.9 (L1) Ensure the shell services timeout is set to 1 hour or less" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Select Name, @{N="UserVars.ESXiShellTimeOut";E={$_ | Get-AdvancedSettings UserVars.ESXiShellTimeOut | Select -ExpandProperty Values}}

    # Check the timeout
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.UserVars.ESXiShellTimeOut -le 3600 -and $VMhost.UserVars.ESXiShellTimeOut -gt 0) {
            Write-Host "- $($VMhost.Name): Passed" -ForegroundColor Green
            Write-Host "  The shell services timeout is set to 1 hour or less. " -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.Name): Failed" -ForegroundColor Red
            Write-Host "  The shell services timeout is not set to 1 hour or less. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-DCUIHasTrustedUsersForLockDownMode {
    # CIS 5.10 (L1) Ensure DCUI has trusted users for Lock Down mode
    Write-Host "`n* CIS control 5.10 (L1) Ensure DCUI has trusted users for Lock Down mode" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get VMhosts
    $VMhosts = Get-VMHost | Select Name, @{N="DCUIAccess";E={$_ | Get-AdvancedSetting -Name DCUI.Access | Select -ExpandProperty Value}}

    # Check the DCUI access
    Foreach ($VMhost in $VMhosts) {
        if ($VMhost.DCUIAccess -ne $null) {
            Write-Host "- $($VMhost.Name): Passed" -ForegroundColor Green
            Write-Host "  DCUI has trusted users for Lock Down mode. " -ForegroundColor Green
            Write-Host "  DCUI users: $($VMhost.DCUIAccess)" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- $($VMhost.Name): Failed" -ForegroundColor Red
            Write-Host "  DCUI does not have trusted users for Lock Down mode. " -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-ContentsOfExposedConfigurationsNotModified {
    # CIS 5.11 (L2) Ensure contents of exposed configuration files have not been modified
    Write-Host "`n* CIS control 5.11 (L1) Ensure contents of exposed configurations are not modified" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually, refer to the CIS Benchmark for details
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown++

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}
#endregion

#region LoggingAudit

# This module assesses against the following CIS controls:
# 3.1 (L1) Ensure a centralized location is configured to collect ESXi host core dumps
# 3.2 (L1) Ensure persistent logging is configured for all ESXi hosts
# 3.3 (L1) Ensure remote logging is configured for ESXi hosts

function Ensure-CentralizedESXiHostDumps {
    # CIS 3.1 (L1) Ensure a centralized location is configured to collect ESXi host core dumps
    Write-Host "`n* CIS control 3.1 (L1) Ensure a centralized location is configured to collect ESXi host core dumps" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the ESXiCli for each host
    $vmhosts = Get-VMHost
    # Check for the presence of a centralized location for core dumps
    Foreach ($vmhost in $vmhosts ){
        $esxiCli = Get-EsxCli -VMHost $vmhost -V2
        $ESXiCoreDump = $esxiCli.system.coredump.network.get.Invoke()
        if ($ESXiCoreDump.Enabled -eq $false) {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  No centralized location configured for core dumps on $vmhost" -ForegroundColor Red
            $failed++
        }
        else {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  Centralized location configured for core dumps on $vmhost" -ForegroundColor Green
            $passed++
        }
    }


    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-PersistentLoggingIsConfigured {
    # CIS 3.2 (L1) Ensure persistent logging is configured for all ESXi hosts
    Write-Host "`n* CIS control 3.2 (L1) Ensure persistent logging is configured for all ESXi hosts" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the ESXi hosts
    $VMHosts = Get-VMHost | Select Name, @{N="Syslog.global.logDir";E={$_ | Get-AdvancedConfiguration Syslog.global.logDir | Select -ExpandProperty Values}}

    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.Syslog.global.logDir -ne $null) {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  Persistent logging is configured for $($VMHost.Name)" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  Persistent logging is not configured for $($VMHost.Name)" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow


    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-RemoteLoggingIsConfigured {
    # CIS 3.3 (L1) Ensure remote logging is configured for ESXi hosts
    Write-Host "`n* CIS control 3.3 (L1) Ensure remote logging is configured for ESXi hosts" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the ESXi hosts
    $VMHosts = Get-VMHost | Select Name, @{N="Syslog.global.logHost";E={$_ | Get-AdvancedSetting Syslog.global.logHost}}

    Foreach ($VMHost in $VMHosts) {
        if ($VMHost.Syslog.global.logHost -ne $null) {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  Remote logging is configured for $($VMHost.Name)" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  Remote logging is not configured for $($VMHost.Name)" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}
#endregion

#region NetworkAudit
# This module assesses against the following CIS controls:
# 7.1 (L1) Ensure the vSwitch Forged Transmits policy is set to reject
# 7.2 (L1) Ensure the vSwitch MAC Address Change policy is set to reject
# 7.3 (L1) Ensure the vSwitch Promiscuous Mode policy is set to reject
# 7.4 (L1) Ensure port groups are not configured to the value of the native VLAN
# 7.5 (L1) Ensure port groups are not configured to VLAN values reserved by upstream physical switches
# 7.6 (L1) Ensure port groups are not configured to VLAN 4095 and 0except for Virtual Guest Tagging (VGT)
# 7.7 (L1) Ensure Virtual Distributed Switch Netflow traffic is sent to an authorized collector
# 7.8 (L1) Ensure port-level configuration overrides are disabled

function Ensure-vSwitchForgedTransmitsIsReject {
    # CIS 7.1 (L1) Ensure the vSwitch Forged Transmits policy is set to reject
    Write-Host "`n* CIS control 7.1 (L1) Ensure the vSwitch Forged Transmits policy is set to reject" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the vSwitches
    $vSwitches = Get-VirtualSwitch -Standard | Select VMHost, Name, @{N = "MacChanges"; E = { if ($_.ExtensionData.Spec.Policy.Security.MacChanges) { "Accept" } Else { "Reject" } } }, @{N = "PromiscuousMode"; E = { if ($_.ExtensionData.Spec.Policy.Security.PromiscuousMode) { "Accept" } Else { "Reject" } } }, @{N = "ForgedTransmits"; E = { if ($_.ExtensionData.Spec.Policy.Security.ForgedTransmits) { "Accept" } Else { "Reject" } } }

    # Check the vSwitches
    foreach ($vSwitch in $vSwitches) {
        if ($vSwitch.ForgedTransmits -eq "Reject") {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  $($vSwitch.VMHost) - $($vSwitch.Name)" -ForegroundColor Green
            $passed++
        }
        Else {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  $($vSwitch.VMHost) - $($vSwitch.Name)" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-vSwitchMACAdressChangeIsReject {
    # CIS 7.2 (L1) Ensure the vSwitch MAC Address Change policy is set to reject
    Write-Host "`n* CIS control 7.2 (L1) Ensure the vSwitch MAC Address Change policy is set to reject" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the vSwitches
    $vSwitches = Get-VirtualSwitch -Standard | Select VMHost, Name, @{N = "MacChanges"; E = { if ($_.ExtensionData.Spec.Policy.Security.MacChanges) { "Accept" } Else { "Reject" } } }, @{N = "PromiscuousMode"; E = { if ($_.ExtensionData.Spec.Policy.Security.PromiscuousMode) { "Accept" } Else { "Reject" } } }, @{N = "ForgedTransmits"; E = { if ($_.ExtensionData.Spec.Policy.Security.ForgedTransmits) { "Accept" } Else { "Reject" } } }

    # Check the vSwitches
    foreach ($vSwitch in $vSwitches) {
        if ($vSwitch.MacChanges -eq "Reject") {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  $($vSwitch.VMHost) - $($vSwitch.Name)" -ForegroundColor Green
            $passed++
        }
        Else {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  $($vSwitch.VMHost) - $($vSwitch.Name)" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-vSwitchPromiscuousModeIsReject {
    # CIS 7.3 (L1) Ensure the vSwitch Promiscuous Mode policy is set to reject
    Write-Host "`n* CIS control 7.3 (L1) Ensure the vSwitch Promiscuous Mode policy is set to reject" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the vSwitches
    $vSwitches = Get-VirtualSwitch -Standard | Select VMHost, Name, @{N = "MacChanges"; E = { if ($_.ExtensionData.Spec.Policy.Security.MacChanges) { "Accept" } Else { "Reject" } } }, @{N = "PromiscuousMode"; E = { if ($_.ExtensionData.Spec.Policy.Security.PromiscuousMode) { "Accept" } Else { "Reject" } } }, @{N = "ForgedTransmits"; E = { if ($_.ExtensionData.Spec.Policy.Security.ForgedTransmits) { "Accept" } Else { "Reject" } } }

    # Check the vSwitches
    foreach ($vSwitch in $vSwitches) {
        if ($vSwitch.PromiscuousMode -eq "Reject") {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  $($vSwitch.VMHost) - $($vSwitch.Name)" -ForegroundColor Green
            $passed++
        }
        Else {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  $($vSwitch.VMHost) - $($vSwitch.Name)" -ForegroundColor Red
            $failed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-PortGroupsNotNativeVLAN {
    # CIS 7.4 (L1) Ensure port groups are not configured to the value of the native VLAN
    Write-Host "`n* CIS control 7.4 (L1) Ensure port groups are not configured to the value of the native VLAN" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the vSwitches
    $vSwitches = Get-VirtualPortGroup -Standard | Select  virtualSwitch, Name, VlanID

    # Checking for native VLAN ID 1
    $defaultNativeVLAN = 1
    Write-Host "Checking for native VLAN ID 1, if you have a different native VLAN ID, please change the value of the variable nativeVLANID in the script." -ForegroundColor Yellow

    # Check the vSwitches for port groups with the same VLAN ID as the native VLAN
    foreach ($vSwitch in $vSwitches) {
        if ($vSwitch.VlanID -eq $defaultNativeVLAN) {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  $($vSwitch.virtualSwitch) - $($vSwitch.Name) - VLAN $($vSwitch.VlanID)" -ForegroundColor Red
            $failed++
        }
        Else {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  $($vSwitch.virtualSwitch) - $($vSwitch.Name) - VLAN $($vSwitch.VlanID)" -ForegroundColor Green
            $passed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-PortGroupsNotUpstreamPhysicalSwitches {
    # CIS 7.5 (L1) Ensure port groups are not configured to VLAN values reserved by upstream physical switches
    Write-Host "`n* CIS control 7.5 (L1) Ensure port groups are not configured to VLAN values reserved by upstream physical switches" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the vSwitches
    $vSwitches = Get-VirtualPortGroup -Standard | Select  virtualSwitch, Name, VlanID

    # Checking for Cisco reserved VLAN IDs 1001-1024 and 4094, Nexus reserved VLAN IDs 3968-4047 and 4049
    $reservedVLANs = 1001..1024
    $reservedVLANs += 3968..4047
    $reservedVLANs += 4094
    Write-Host "Checking for Cisco reserved VLAN IDs 1001-1024 and 4094, Nexus reserved VLAN IDs 3968-4047 and 4049, if you have a different reserved VLAN ID range, please change the value of the variable reservedVLANs in the script." -ForegroundColor Yellow

    # Check the vSwitches for port groups with the VLAN IDs reserved by upstream physical switches
    foreach ($vSwitch in $vSwitches) {
        if ($reservedVLANs -contains $vSwitch.VlanID) {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  $($vSwitch.virtualSwitch) - $($vSwitch.Name) - VLAN $($vSwitch.VlanID)" -ForegroundColor Red
            $failed++
        }
        Else {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  $($vSwitch.virtualSwitch) - $($vSwitch.Name) - VLAN $($vSwitch.VlanID)" -ForegroundColor Green
            $passed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}

function Ensure-PortGroupsAreNotConfiguredToVLAN0and4095 {
    # CIS 7.6 (L1) Ensure port groups are not configured to VLAN 0 and 4095
    Write-Host "`n* CIS control 7.6 (L1) Ensure port groups are not configured to VLAN 0 and 4095" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # Get the vSwitches
    $vSwitches = Get-VirtualPortGroup -Standard | Select  virtualSwitch, Name, VlanID

    # Checking for VLAN IDs 0 and 4095
    $reservedVLANs = 0, 4095
    Write-Host "Checking for both VLAN IDs 0 and 4095, if you have set up Virtual Guest Tagging on your vSwitches, please change the value of the variable reservedVLANs in the script." -ForegroundColor Yellow

    # Check the vSwitches for port groups with the VLAN IDs reserved by upstream physical switches
    foreach ($vSwitch in $vSwitches) {
        if ($reservedVLANs -contains $vSwitch.VlanID) {
            Write-Host "- Check Failed" -ForegroundColor Red
            Write-Host "  $($vSwitch.virtualSwitch) - $($vSwitch.Name) - VLAN $($vSwitch.VlanID)" -ForegroundColor Red
            $failed++
        }
        Else {
            Write-Host "- Check Passed" -ForegroundColor Green
            Write-Host "  $($vSwitch.virtualSwitch) - $($vSwitch.Name) - VLAN $($vSwitch.VlanID)" -ForegroundColor Green
            $passed++
        }
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-VirtualDistributedSwitchNetflowTrafficSentToAuthorizedCollector {
    # CIS 7.7 (L1) Ensure virtual distributed switch netflow traffic is sent to an authorized collector
    Write-Host "`n* CIS control 7.7 (L1) Ensure virtual distributed switch netflow traffic is sent to an authorized collector" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    # This control needs to be verified manually
    Write-Host "- Check Unknown" -ForegroundColor Yellow
    Write-Host "  This control needs to be verified manually, refer to the CIS Benchmark for details" -ForegroundColor Yellow
    $unknown = 1

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }

}

function Ensure-PortLevelConfigurationOverridesAreDisabled {
    # CIS 7.8 (L1) Ensure port level configuration overrides are disabled
    Write-Host "`n* CIS control 7.8 (L1) Ensure port level configuration overrides are disabled" -ForegroundColor Blue


    # Results summary
    $passed = 0
    $failed = 0
    $unknown = 0

    #
    $vdPortGroupOverridePolicy = Get-VDPortgroup | Get-VDPortgroupOverridePolicy

    # Check if the port level configuration overrides are disabled
    if ($vdPortGroupOverridePolicy -eq $null) {
        Write-Host "- Check Passed" -ForegroundColor Green
        Write-Host "  Port level configuration overrides are disabled" -ForegroundColor Green
        $passed++
    }
    Else {
        Write-Host "- Check Failed" -ForegroundColor Red
        Write-Host "  Port level configuration overrides are enabled" -ForegroundColor Red
        $failed++
    }

    # Print the results
    Write-Host "`n-- Summary --"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Unknown: $unknown" -ForegroundColor Yellow

    # Return true if all checks passed
    if ($failed -ne 0) {
        return -1
    }
    elseif ($unknown -ne 0) {
        return 0
    }
    else {
        return 1
    }


}
#endregion

#endregion

#region VSAT
# A function to connect to vCenter/ESXi Server using the Connect-VIServer cmdlet and store the connection in a variable
function Connect-VCServer {
    # Asking the user for the vCenter/ESXi Server Hostname or IP Address
    $server = Read-Host -Prompt "Enter the vCenter/ESXi Server Hostname or IP Address"

    # Set InvalidCertificateAction to warn instead of stop without user interaction
    Write-Host "Setting InvalidCertificateAction to Warn instead of Stop..."
    Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction warn -Confirm:$false

    # print the connection details 
    Write-Host "Connecting to $server" 

    # Connect to the vCenter/ESXi Server using https, stop if the connection fails
    Connect-VIServer -Server $server -Protocol https -ErrorAction Stop
    Write-Host "Successfully connected to $server" -ForegroundColor Green

}

function VSAT {
    # Connect to the vCenter/ESXi Server
    Connect-VCServer

    # Run the CIS Benchmark checks and store the results in a variable
    # 1.Install
    Write-Host "`n* These controls contain recommendations for settings related to 1.Install" -ForegroundColor Blue
    Ensure-ESXiIsProperlyPatched
    Ensure-VIBAcceptanceLevelIsConfiguredProperly
    Ensure-UnauthorizedModulesNotLoaded
    Ensure-DefaultSaultIsConfiguredProperly

    # 2.Communication
    Write-Host "`n* These controls contain recommendations for settings related to 2.Communication" -ForegroundColor Blue
    Ensure-NTPTimeSynchronizationIsConfiguredProperly
    Ensure-ESXiHostFirewallIsProperlyConfigured
    Ensure-MOBIsDisabled
    Ensure-DefaultSelfSignedCertificateIsNotUsed
    Ensure-SNMPIsConfiguredProperly
    Ensure-dvfilterIsDisabled
    Ensure-DefaultExpiredOrRevokedCertificateIsNotUsed
    Ensure-vSphereAuthenticationProxyIsUsedWithAD
    Ensure-VDSHealthCheckIsDisabled

    # 3.Logging
    Write-Host "`n* These controls contain recommendations for settings related to 3.Logging" -ForegroundColor Blue
    Ensure-CentralizedESXiHostDumps
    Ensure-PersistentLoggingIsConfigured
    Ensure-RemoteLoggingIsConfigured

    # 4.Access
    Write-Host "`n* These controls contain recommendations for settings related to 4.Access" -ForegroundColor Blue
    Ensure-NonRootExistsForLocalAdmin
    Ensure-PasswordsAreRequiredToBeComplex
    Ensure-LoginAttemptsIsSetTo5
    Ensure-AccountLockoutIsSetTo15Minutes
    Ensure-Previous5PasswordsAreProhibited
    Ensure-ADIsUsedForAuthentication
    Ensure-OnlyAuthorizedUsersBelongToEsxAdminsGroup
    Ensure-ExceptionUsersIsConfiguredManually

    # 5.Console
    Write-Host "`n* These controls contain recommendations for settings related to 5.Console" -ForegroundColor Blue
    Ensure-DCUITimeOutIs600
    Ensure-ESXiShellIsDisabled
    Ensure-SSHIsDisabled
    Ensure-CIMAccessIsLimited
    Ensure-NormalLockDownIsEnabled
    Ensure-StrickLockdownIsEnabled
    Ensure-SSHAuthorisedKeysFileIsEmpty
    Ensure-IdleESXiShellAndSSHTimeout
    Ensure-ShellServicesTimeoutIsProperlyConfigured
    Ensure-DCUIHasTrustedUsersForLockDownMode
    Ensure-ContentsOfExposedConfigurationsNotModified

    # 6.Storage
    Write-Host "`n* These controls contain recommendations for settings related to 6.Storage" -ForegroundColor Blue
    Ensure-BidirectionalCHAPAuthIsEnabled
    Ensure-UniquenessOfCHAPAuthSecretsForiSCSI
    Ensure-SANResourcesAreSegregatedProperly

    # 7.Network
    Write-Host "`n* These controls contain recommendations for settings related to 7.Network" -ForegroundColor Blue
    Ensure-vSwitchForgedTransmitsIsReject
    Ensure-vSwitchMACAdressChangeIsReject
    Ensure-vSwitchPromiscuousModeIsReject
    Ensure-PortGroupsNotNativeVLAN
    Ensure-PortGroupsNotUpstreamPhysicalSwitches
    Ensure-PortGroupsAreNotConfiguredToVLAN0and4095
    Ensure-VirtualDistributedSwitchNetflowTrafficSentToAuthorizedCollector
    Ensure-PortLevelConfigurationOverridesAreDisabled

    # 8.Virual Machines
    Write-Host "`n* These controls contain recommendations for settings related to 8.Virtual Machines" -ForegroundColor Blue
    Ensure-InformationalMessagesFromVMToVMXLimited
    Ensure-OnlyOneRemoteConnectionIsPermittedToVMAtAnyTime
    Ensure-UnnecessaryFloppyDevicesAreDisconnected
    Ensure-UnnecessaryCdDvdDevicesAreDisconnected
    Ensure-UnnecessaryParallelPortsAreDisconnected
    Ensure-UnnecessarySerialPortsAreDisabled
    Ensure-UnnecessaryUsbDevicesAreDisconnected
    Ensure-UnauthorizedModificationOrDisconnectionOfDevicesIsDisabled
    Ensure-UnauthorizedConnectionOfDevicesIsDisabled
    Ensure-PciPcieDevicePassthroughIsDisabled
    Ensure-UnnecessaryFunctionsInsideVMsAreDisabled
    Ensure-UseOfTheVMConsoleIsLimited
    Ensure-SecureProtocolsAreUsedForVirtualSerialPortAccess
    Ensure-StandardProcessesAreUsedForVMDeployment
    Ensure-AccessToVMsThroughDvFilterNetworkAPIsIsConfiguredCorrectly
    Ensure-AutologonIsDisabled
    Ensure-BIOSBBSIsDisabled
    Ensure-GuestHostInteractionProtocolIsDisabled
    Ensure-UnityTaskBarIsDisabled
    Ensure-UnityActiveIsDisabled
    Ensure-UnityWindowContentsIsDisabled
    Ensure-UnityPushUpdateIsDisabled
    Ensure-DragAndDropVersionGetIsDisabled
    Ensure-DragAndDropVersionSetIsDisabled
    Ensure-ShellActionIsDisabled
    Ensure-DiskRequestTopologyIsDisabled
    Ensure-TrashFolderStateIsDisabled
    Ensure-GuestHostInterationTrayIconIsDisabled
    Ensure-UnityIsDisabled
    Ensure-UnityInterlockIsDisabled
    Ensure-GetCredsIsDisabled
    Ensure-HostGuestFileSystemServerIsDisabled
    Ensure-GuestHostInteractionLaunchMenuIsDisabled
    Ensure-memSchedFakeSampleStatsIsDisabled
    Ensure-VMConsoleCopyOperationsAreDisabled
    Ensure-VMConsoleDragAndDropOprerationsIsDisabled
    Ensure-VMConsoleGUIOptionsIsDisabled
    Ensure-VMConsolePasteOperationsAreDisabled
    Ensure-VMLimitsAreConfiguredCorrectly
    Ensure-HardwareBased3DAccelerationIsDisabled
    Ensure-NonPersistentDisksAreLimited
    Ensure-VirtualDiskShrinkingIsDisabled
    Ensure-VirtualDiskWipingIsDisabled
    Ensure-TheNumberOfVMLogFilesIsConfiguredProperly
    Ensure-HostInformationIsNotSentToGuests
    Ensure-VMLogFileSizeIsLimited
}
#endregion

VSAT >> "$PSScriptRoot\VSAT.log"