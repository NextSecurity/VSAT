<#
.SYNOPSIS
    VSAT - Virtualization Security Audit Tool for VMware vSphere, vCenter, ESX/ESXi and NSX.

.DESCRIPTION
    Read-only security assessment of VMware infrastructure including mandatory NSX
    coverage. Produces an offline interactive report, machine-readable findings,
    CSV worklists and an integrity-hashed evidence package.

    VSAT never modifies the assessed infrastructure. Mitigations are guidance only.

.PARAMETER Server
    vCenter Server or ESXi endpoints to assess.
.PARAMETER NsxServer
    NSX Manager endpoints to assess. NSX is a mandatory audit domain.
.PARAMETER Credential
    Credential for -Server endpoints. Prompted securely when omitted.
.PARAMETER NsxCredential
    Credential for -NsxServer endpoints. Prompted securely when omitted.
.PARAMETER NsxDeclaredAbsent
    Operator declaration that NSX is not deployed in scope. Recorded and checked
    against discovery evidence; it never produces an NSX security pass.
.PARAMETER ScopeFile
    Credential-free JSON scope file (endpoints, exclusions, zones, criticality,
    native VLANs, authorized collectors, exceptions).
.PARAMETER AuditProfile
    Evaluation profile: standard (default) or strict. Alias: -Profile.
.PARAMETER OutputPath
    Output folder. Defaults to .\vsat-output\<timestamp>.
.PARAMETER Cli
    Terminal-only workflow; no browser.
.PARAMETER Doctor
    Readiness check only.
.PARAMETER Replay
    Re-open and re-evaluate an evidence package (.vsat.zip) or evidence.json offline.
.PARAMETER Baseline
    Previous evidence package to compare against (drift).
.PARAMETER Redact
    Also write a redacted sharing copy with consistent pseudonyms.
.PARAMETER TrustedThumbprint
    Per-endpoint certificate pin, "host=SHA256HEX". Never weakens global TLS validation.
.PARAMETER Port
    Loopback port for the local UI. 0 selects a free port.
.PARAMETER NoBrowser
    Do not open a browser automatically.
.PARAMETER Demo
    Run against the built-in synthetic lab. No connectivity or credentials.
.PARAMETER Version
    Print version information and exit.
.PARAMETER HyperVServer
    Microsoft Hyper-V hosts to assess over PowerShell remoting (WinRM). Use "https://host"
    for WinRM over HTTPS, or "localhost" to assess the local host.
.PARAMETER HyperVCredential
    Credential for -HyperVServer. Omit to use the current Windows identity (Kerberos).
.PARAMETER HyperVEvidence
    Import Hyper-V collector output (JSON) produced offline by vsat-hyperv-collect.ps1.
.PARAMETER KvmServer
    KVM/libvirt hosts to assess over SSH (key authentication only; host key must be known
    or pinned with -TrustedThumbprint "host=SHA256:<base64>"). Use "host:port" for non-22.
.PARAMETER KvmUser
    SSH user for -KvmServer (read access to libvirt, e.g. a member of the libvirt group).
.PARAMETER KvmEvidence
    Import output of vsat-kvm-collect.sh produced offline on a KVM host.
.PARAMETER ExportCollector
    Write the read-only offline collector script for a platform to -OutputPath and exit.

.EXAMPLE
    .\vsat.ps1
.EXAMPLE
    .\vsat.ps1 -Server vc01.example.local -NsxServer nsx01.example.local -Cli
.EXAMPLE
    .\vsat.ps1 -Replay .\assessment.vsat.zip

.NOTES
    Exit codes: 0 complete/no failing automated controls, 1 complete/findings present,
    2 incomplete/unknown mandatory coverage, 3 fatal failure, 4 canceled.
    https://github.com/NextSecurity/VSAT  (MIT License)
#>
[CmdletBinding()]
param(
    [string[]]$Server,
    [string[]]$NsxServer,
    [System.Management.Automation.PSCredential]$Credential,
    [System.Management.Automation.PSCredential]$NsxCredential,
    [switch]$NsxDeclaredAbsent,
    [string]$ScopeFile,
    [ValidateSet('standard', 'strict')]
    [Alias('Profile')]
    [string]$AuditProfile = 'standard',
    [string]$OutputPath,
    [switch]$Cli,
    [switch]$Doctor,
    [string]$Replay,
    [string]$Baseline,
    [switch]$Redact,
    [string[]]$TrustedThumbprint,
    [ValidateRange(0, 65535)]
    [int]$Port = 0,
    [switch]$NoBrowser,
    [switch]$Demo,
    [switch]$Version,
    [string[]]$HyperVServer,
    [System.Management.Automation.PSCredential]$HyperVCredential,
    [string[]]$HyperVEvidence,
    [string[]]$KvmServer,
    [string]$KvmUser,
    [string[]]$KvmEvidence,
    [ValidateSet('hyperv', 'kvm')]
    [string]$ExportCollector,
    [Parameter(DontShow)]
    [switch]$LibraryMode
)

$ErrorActionPreference = 'Stop'
