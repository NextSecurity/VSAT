# Changelog

All notable changes to VSAT are documented in this file.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The tool, rule pack, advisory snapshot and evidence schema each have their own version (see [docs/release.md](docs/release.md)). The rule pack, advisory snapshot and schema versions for each release are recorded in that release's `manifest.json`.

## [Unreleased]

## [2.7.0] - 2026-09-27

Adds the **Audit pack**: one control matrix across frameworks, with sign-offs and exceptions, ready to hand to an auditor.

### Added

- `-AuditPack` (live runs, `-Demo` and `-Replay`) writes `audit-pack/`: `control-matrix.csv`, a standalone `control-matrix.html`, `signoffs.csv`, `exceptions.csv`, a copy of the evidence package and a manifest with the SHA-256 of every file and the package receipt.
- Framework mappings for all 201 rules: NIST SP 800-53 Rev. 5, IEC 62443-3-3 system requirements, MITRE ATT&CK mitigations and DISA STIG for vSphere 8 (ESXi, vCenter, virtual machine), matched by exact setting names from the published DISA package. Mappings carry IDs and VSAT's own wording only, with a review status (`proposed` or `verified`).
- CIS with your own license: `build/Import-CisMapping.ps1` imports a licensed CIS benchmark; VSAT ships no CIS content.
- Scope key `signoffs` for manual checks, and exception fields `approver`, `compensatingControl`, `ticket` and `expires`.
- A Compliance page in the report with a framework selector, the matrix and both registers.
- Control states stay separate: `satisfied`, `not-satisfied`, `partial`, `not-assessed`, `manual-open`, `manual-signed-off`, `excepted`. Missing evidence is always `not-assessed`.
- End-to-end test and CI smoke step covering blast radius, change timeline, receipt, ransomware readiness, AI workloads and the audit pack together.

### Changed

- CIS and Security Configuration Guide IDs carried over from VSAT 1.x are labeled `legacy-unverified`.

## [2.6.0] - 2026-09-27

Adds **AI & GPU isolation** across VMware, Hyper-V and KVM.

### Added

- Ten rules in the new non-mandatory domain `ai-infra`: `AI-IOMMU-OFF`, `AI-IOMMU-IR`, `AI-ACS-OVERRIDE`, `AI-IOMMU-GROUP-SHARED`, `AI-GPU-SHARED-NO-MIG`, `AI-SRIOV-HOST`, `AI-SHARE-WORLD`, `AI-SHARE-SMB`, `AI-SHARE-PLAINTEXT`, `AI-K8S-CP-EXPOSED`.
- Read-only accelerator and storage evidence: ESXi PCI passthrough, graphics and SR-IOV; Hyper-V GPU partitioning, assignable devices, SR-IOV switches and SMB shares; KVM kernel command line, IOMMU groups, mediated devices, `nvidia-smi` MIG state (when installed), NFS exports and mounts; accelerators on every VM.
- Scope key `aiWorkloads` with roles (`k8s-control-plane`, `k8s-worker`, `training`, `inference`, `dataset-store`, `model-registry`). Control planes, model registries and dataset stores become blast-radius crown jewels.
- Findings on hosts list the AI workloads they affect. MITRE ATLAS techniques on the model and dataset storage rules.
- An AI infra page in the report. Work packages `WP-AI-ISOLATION` and `WP-AI-STORAGE`.

## [2.5.0] - 2026-09-27

Adds **Ransomware readiness**: could one stolen account encrypt every hypervisor, and the backups too?

### Added

- Scope key `backupSystems`: declared backup systems become blast-radius crown jewels.
- Three rules in the new non-mandatory domain `ransomware-readiness`: `RW-BACKUP-REACHABLE` (an attacker path reaches the backup system), `RW-BACKUP-COLOCATED` (it runs in the same cluster or on the same host as production), `RW-BACKUP-SHARED-ADMIN` (production hypervisor admins also administer its host).
- "One account reach": for every account, how many hypervisor hosts it administers across VMware, Hyper-V and KVM, worst first.
- 20 existing rules tagged as ransomware-relevant (patching, execInstalledOnly, acceptance level, ESX Admins group, lockdown, SSH/shell/SLP, remote syslog, backups, admin rights).
- A Ransomware page in the report and a summary card in the local UI.
- Work package `WP-RANSOMWARE`.

### Fixed

- Report cards in the same row line up, and severity labels on the overview are no longer clipped.

## [2.4.0] - 2026-09-27

Adds **Audit integrity** for audits the customer runs with their own rights: the auditor can see what changed during the engagement and prove the evidence package is the one from the session.

### Added

- Change timeline from the platforms' own history since the engagement started: vCenter/ESXi events, NSX "last modified" data, Windows event logs on Hyper-V hosts, and file changes, package history and logins on KVM hosts. `-EngagementStart <yyyy-MM-dd>` sets the window (default 30 days, up to 180).
- "Changed during engagement" on findings whose setting or service changed inside the window. The result itself is unchanged.
- Earlier-runs detector: earlier sign-ins by the account VSAT uses.
- Coverage domain `change-history` (non-mandatory): reports when a platform's history starts after the engagement start, when logs were full or cleared, or when reads were denied.
- Receipt code `VSAT-XXXX-XXXX-XXXX-XXXX` at the end of every run, derived from the evidence package hash. `-Replay <zip> -Receipt <code>` verifies it; a mismatch exits with code 3.
- `-CollectOnly`: writes only the evidence package, collection log and manifest, and shows the receipt instead of findings.
- `changes.csv` and an Engagement timeline section on the report's Changes page.

### Fixed

- `-Replay` without `-ScopeFile` no longer fails on an empty scope.

## [2.3.0] - 2026-09-27

Adds **Blast radius**: pick a compromised account or VM and see what an attacker reaches across VMware, NSX, Hyper-V and KVM, and which fixes break the most paths.

### Added

- Blast radius analysis in every run: a cross-platform security graph built from collected evidence (admin rights, VM placement, NSX firewall decisions, shared virtual switches, management networks) with a deterministic path search and a ranked fix list. The report and the local UI get a Blast radius page with a radial map; ticking a fix shows the paths it breaks.
- Hops VSAT cannot verify are listed as "collect this to confirm" and are never ranked.
- MITRE ATT&CK techniques on every graph hop and rule, from a pinned offline ATT&CK catalog. Every run writes `attack-layer.json` for the ATT&CK Navigator.
- OT/ICS segmentation lens: give scope zones a Purdue level and six rules (`OT-*`) check that OT and IT workloads do not share hosts, virtual switches, management planes, admin accounts or network paths. Virtualization layer only.
- Scope file keys `entryPoints`, `identityDomains`, `identityGroups`, `credentialStores` and `zones[].purdueLevel`.
- VMware 9.x: vCenter, ESX and NSX 9.0/9.1 advisory and lifecycle data, version-gated rules (checks for components removed in ESX 9.0 report not applicable), and detection of both `VCF.PowerCLI` and `VMware.PowerCLI` installs.
- One-command start that downloads `vsat.ps1`, verifies it against `SHA256SUMS.txt` and runs the demo, with a pinned-version variant.
- Canonical JSON serialization and hashing for deterministic evidence digests.

### Changed

- Evidence and results schema `2.3` (additive; 2.0–2.2 packages still replay).
- CISA KEV labels apply per CVE instead of per advisory.
- The report and local UI header is a single compact row.
- The release has three files: `vsat.ps1`, `SHA256SUMS.txt` and the optional offline builder ZIP (with the SBOM and dependency lock inside). The sample report and evidence moved to the website demo.
- `vsat.ps1` embeds its rules, data and report assets as plain text instead of base64, so every line is readable. `docs/security-review.md` explains what to download, how to verify it and what the script does.
- A host that vCenter cannot reach no longer aborts collection; its checks report `UNKNOWN`.

## [2.2.0] - 2026-09-23

Adds **KVM/libvirt** as the third audited platform.

### Added

- KVM collection (`-KvmServer`, `-KvmUser`) by running a read-only POSIX shell collector over SSH with key authentication (`BatchMode`) and strict host-key checking; host keys can be pinned per endpoint with `-TrustedThumbprint "host=SHA256:<base64>"`.
- Air-gapped workflow: `-ExportCollector kvm` writes `vsat-kvm-collect.sh` (virsh always `--readonly`, domain XML without `--security-info` so console passwords are never collected, no writes); import its output with `-KvmEvidence`.
- 23 KVM rules (`KVM-*`) across three new domains (hosts, VMs, virtual networks): package update age and OS lifecycle, sVirt (SELinux/AppArmor), unauthenticated libvirt TCP, QEMU running as root, VNC TLS/loopback, seccomp, Secure Boot, host firewall, SSH root/password login, libvirt group review, nested virtualization, per-VM seclabel, network-exposed consoles, host device passthrough, TCP serial consoles, USB redirection, nwfilter anti-spoofing, guest Secure Boot/vTPM, snapshot age, open-forward networks.
- Hyper-V, KVM and VMware can be assessed together in one run and one report.

### Security

- Untrusted XML from collector output is parsed with DTD processing prohibited and no resolver (XXE-safe); malformed or unsafe documents become `ERROR` evidence, never passes.

### Fixed

- CLI runs without vSphere targets, and runs with an empty remediation worklist, no longer fail.

## [2.1.0] - 2026-09-23

Adds **Microsoft Hyper-V** as the second audited platform.

### Added

- Hyper-V collection (`-HyperVServer`, `-HyperVCredential`) through one read-only collector script executed over PowerShell remoting (Kerberos/Negotiate, or `https://host` for WinRM over HTTPS) or locally (`localhost`). Collects host OS/build, update age, VBS/HVCI/Credential Guard, Secure Boot, TPM, Windows Firewall, SMB, services, RDP NLA, live migration, Replica, local/Hyper-V admin groups, failover cluster, virtual switches and per-VM security, firmware, adapters (MAC spoofing, DHCP/router guard, mirroring, VLAN mode), integration services, checkpoints and devices.
- Air-gapped workflow: `-ExportCollector hyperv` writes `vsat-hyperv-collect.ps1` (Windows PowerShell 5.1 compatible, `Get-*`/CIM reads only); import its JSON with `-HyperVEvidence`.
- 32 Hyper-V rules (`HV-*`) across three new mandatory-when-in-scope domains: Hyper-V hosts, virtual machines and virtual switches.
- Verified OS lifecycle snapshot `data/os-lifecycle.json` (Windows Server 2012 R2–2025, RHEL, Rocky, AlmaLinux, Ubuntu, Debian, Proxmox VE) with official sources.
- Failure-impact modeling for Hyper-V: clustered VMs restart on other nodes, non-clustered VMs are an outage.
- Platform-neutral work packages (`WP-HOST-HARDENING`, `WP-HOST-SERVICES`, `WP-HOST-ACCESS`).

### Changed

- Coverage domains are platform-aware: VMware domains (and NSX) are `NOT_APPLICABLE` when no VMware endpoints are in scope; Hyper-V domains are mandatory whenever Hyper-V endpoints are in scope.

### Fixed

- The analysis pipeline no longer fails when a run produces zero findings (for example when every host collection fails); coverage is reported as `INCOMPLETE`.

## [2.0.0] - 2026-09-23

This is a full rewrite of VSAT.

### Breaking

- Replaced the 1.x console script. The new `vsat.ps1` is built from modular sources under `src/`, `rules/`, `data/` and `assets/` by `build/Build-Vsat.ps1`. The 1.x script is preserved unchanged at `legacy/vsat-1.x.ps1`.
- **PowerShell 7.4+ is required.** Windows PowerShell 5.1 is not supported.
- Results use six states: `PASS`, `FAIL`, `MANUAL`, `NOT_APPLICABLE`, `UNKNOWN` and `ERROR`. The 1.x passed/failed/unknown console counters are gone. Several 1.x "passed" outcomes now show up as `UNKNOWN` or `NOT_APPLICABLE` (see [docs/migration-from-1x.md](docs/migration-from-1x.md)).
- Exit codes now carry meaning: `0` complete with no failing automated controls, `1` complete with findings, `2` incomplete or unknown mandatory coverage, `3` fatal, `4` canceled.
- **NSX is a mandatory domain.** If NSX is detected but not assessed, the run is `INCOMPLETE: NSX NOT ASSESSED` with exit code `2`.
- The `vsat.log` file in the script directory has been replaced by `collection.log` and structured outputs in an output folder (`-OutputPath`).
- `vmware/patches.json` has been replaced by the dated advisory snapshot `data/advisories.json`. The old file is kept at `legacy/patches-1.x.json`.

### Added

- A guided local browser UI on `127.0.0.1` with these steps: launch, authenticate, mandatory NSX step, review scope, run, results.
- Terminal mode (`-Cli`) that covers the same mandatory domains and uses the same findings model.
- A readiness check (`-Doctor`) for runtime, modules, output folder permissions, endpoint reachability and TLS trust.
- A built-in synthetic demo lab (`-Demo`) that needs no connectivity.
- Evidence-first data model (schema `2.0`). Each fact records its own collection status (`ok`, `absent`, `denied`, `error`, `unsupported`). Assets have stable IDs namespaced by endpoint, and relationships record provenance and confidence.
- Coverage for seven domains: vCenter, ESXi hosts, clusters, VMs, virtual networking, NSX and storage & recovery. Each domain gets a coverage state (`ASSESSED`, `PARTIAL`, `INCOMPLETE`, `UNKNOWN`, `NOT_APPLICABLE`, `REVIEW`).
- NSX collection through the Policy/Manager REST API: manager, fabric, segments, gateways, distributed and gateway firewall, groups and realization, all read-only.
- Evaluation profiles `standard` and `strict` (`-Profile`).
- A credential-free scope file (`-ScopeFile`) for endpoints, exclusions, native VLANs, authorized collectors, critical assets, zones and time-limited exceptions.
- Outputs: standalone offline `report.html` with interactive topology, `results.json`, `evidence.json`, `findings.csv`, `worklist.csv`, `collection.log`, `manifest.json` (SHA-256) and the evidence package `assessment.vsat.zip`.
- **Drift** against a previous evidence package (`-Baseline`), showing new, resolved, changed and unassessed items and asset/NSX rule changes.
- **Explainable potential attack paths** inferred from configuration, with rule-level explanations, prerequisites and uncertainty. Also privilege paths and chokepoint ranking.
- **Failure-impact explorer**, a configuration model of which workloads depend on a host, uplink, datastore, VDS or NSX Edge/Tier-0.
- **Remediation work packages** grouped by corrective action and team, with impact, maintenance-window, rollback and validation guidance.
- **Collect-once replay** (`-Replay`) that re-evaluates saved evidence offline without credentials, and **redacted sharing** (`-Redact`) that uses consistent pseudonyms and preserves graph relationships.
- Framework references on findings, each with a `mappingStatus`. All CIS mappings in this release are `unverified`.
- A Pester 5 test suite (104 tests) with synthetic fixtures, including regression fixtures for the 1.x defects listed under Fixed, NSX coverage-state scenarios, read-only guards, local-server security, injection and archive-safety cases.
- A protocol-level integration test (`tests/integration/`) against the govmomi vcsim vSphere simulator and a mock NSX Manager over pinned TLS; it runs in CI. It found and fixed several collector defects before release. A simulator is not a supported product version.
- A dated, source-verified advisory and lifecycle snapshot (`data/advisories.json`, 2026-09-23): VMSA-2024-0012, -0013, -0019, VMSA-2025-0004, -0012, -0013 and VMSA-2026-0006, with fix lines selected per update level.
- A connected-side offline package builder (`build/New-OfflinePackage.ps1`) pinned to PowerShell 7.6.6 LTS (SHA-256 verified) and PowerCLI Core/Storage 13.5.1; verified to produce a complete package that loads PowerCLI from `./modules`.
- Release automation: reproducible build check, CI on Windows and Linux, SPDX SBOM, `SHA256SUMS.txt`, sample synthetic report and evidence package.
- Documentation, community files, branding and a GitHub Pages site.

### Changed

- Patch assessment now evaluates product and build against dated advisory ranges instead of comparing package versions.
- Findings include observed and expected values, evidence references, rationale, mitigation, validation, rollback and limitations.
- Priority scoring shows its reasons and keeps findings, coverage and evidence confidence as separate dimensions. `UNKNOWN` results never raise a score.
- vSphere modules are loaded process-locally from the package's `./modules` folder. VSAT does not install modules globally.

### Fixed

These 1.x defects are covered by regression fixtures:

- **Patch check by static VIB equality.** 1.x compared host packages with a fixed ESXi 7.0.3 list, so any other release or later patch was misreported. 2.0 evaluates product/build against advisory ranges, and unknown builds stay `UNKNOWN`.
- **Lockdown mode read from a boolean.** 1.x compared the boolean `adminDisabled` with the strings `Normal`/`Strict`. 2.0 reads the `HostConfigInfo.lockdownMode` enum (`lockdownDisabled`, `lockdownNormal`, `lockdownStrict`) and applies profile-specific expectations.
- **VDS checks based on object existence.** 1.x treated the presence of a switch or policy object as compliance. 2.0 evaluates the effective security policy for each port group, including port group overrides of switch defaults.
- **Hardcoded native VLAN 1.** 1.x assumed VLAN 1 was the native VLAN. 2.0 returns `UNKNOWN` unless the native VLAN is supplied in the scope file.
- **Zero-object loops reported success.** When 1.x collected nothing, whether because of an empty scope, denied access or a collection failure, it could report a pass. 2.0 returns `NOT_APPLICABLE` only when evidence shows the object type is absent, and `UNKNOWN` or `ERROR` otherwise.

### Security

- **Removed the persistent `Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction warn` change** that 1.x made on every connection. VSAT no longer modifies global or user PowerCLI certificate policy. Untrusted certificates are accepted only per endpoint with `-TrustedThumbprint "host=SHA256"`.
- The local UI listens on loopback only. Each run uses a random token in the URL fragment. Host and Origin are validated, a custom request header defends against CSRF, and no CORS is allowed.
- Secrets are kept in memory only as `PSCredential`, are never accepted on the command line, and are redacted from logs and outputs.
- NSX REST calls go through an enforced method/path allowlist. Only GET requests are allowed, apart from session create and destroy POSTs. Credentials are not sent across redirects.
- Reports use a strict Content Security Policy with script/style hashes and safe DOM rendering. Asset names and tags are treated as untrusted.
- CSV outputs neutralize spreadsheet formulas.
- Evidence ZIP imports are read in memory only (never extracted to disk), enforce entry count, size and compression-ratio limits, reject path-traversal entry names, verify `evidence.json` against the package manifest SHA-256, and refuse unsupported schema versions.
- PowerCLI CEIP telemetry is disabled for the VSAT process only (session scope); user settings are untouched.
- The local report route requires an `HttpOnly; SameSite=Strict` session cookie in addition to loopback Host/Origin validation.
- Output files get restrictive permissions where the platform supports it.

### Deprecated / Removed

- Removed the `Ensure-*` console functions and their colored console output.
- Dropped support for Windows PowerShell 5.1. The 2.0 runner target is Windows x64 with PowerShell 7.4+. Linux and macOS runners are not supported or validated. Linux may be added later as a separately tested package.
- Replaced the 1.x roadmap list (Hyper-V, Citrix, KVM, Proxmox, RHV, Nutanix AHV, Xen) with a focused roadmap in the README: Microsoft Hyper-V and KVM/libvirt are planned next. None of the 1.x roadmap items were ever implemented.

## [1.0.0] - 2023-11-21

### Added

- First release: the VMware vSphere security audit script `vsat.ps1`. It had PowerCLI-based `Ensure-*` checks derived from CIS VMware ESXi benchmark controls, console output and `vsat.log`.
- The static ESXi patch list `vmware/patches.json`.

[Unreleased]: https://github.com/NextSecurity/VSAT/compare/v2.7.0...HEAD
[2.7.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.7.0
[2.6.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.6.0
[2.5.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.5.0
[2.4.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.4.0
[2.3.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.3.0
[2.2.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.2.0
[2.1.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.1.0
[2.0.0]: https://github.com/NextSecurity/VSAT/releases/tag/v2.0.0
[1.0.0]: https://github.com/NextSecurity/VSAT/commit/5f7eda7dc99e859566b21258a49bdc7147b457e3
