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
    [Parameter(DontShow)]
    [switch]$LibraryMode
)

$ErrorActionPreference = 'Stop'
