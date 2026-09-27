# Limitations

This page lists what VSAT does not cover. It is updated with every release.

## Benchmarks and results

- **CIS control IDs** are carried over from the 1.x mapping and carry the `unverified` mapping status in reports. The technical checks are original implementations.
- **VSAT is not certified by, endorsed by or affiliated with CIS, VMware or Broadcom.** A run with no failures does **not** mean compliance with any benchmark or standard.
- "Complete" means every applicable planned check reached a known result. It does not mean every risk was assessed. `MANUAL` controls always need human review.
- Advisory evaluation depends on a dated snapshot. It cannot know about later advisories. Version exposure does not prove exploitability.
- STIG profiles are not currently included. The profiles are `standard` and `strict`.

## Platforms

- **Runner:** Windows x64 with PowerShell 7.4+ (the offline package pins PowerShell 7.6.6 LTS) is the only supported target. CI also runs the test suite on Linux, and development happens on macOS, but neither is a supported assessment runner. Windows PowerShell 5.1 is not supported.
- **vSphere:** targets 8.x and 9.x as modern, and 7.x as legacy. Older versions and historical ESX are inventoried where possible and marked with legacy or manual coverage.
- **NSX:** targets modern NSX via the Policy/Manager API. NSX-V and unsupported versions are reported as such and get manual coverage. NSX Federation (Global Manager), projects and VPCs are not currently modeled.
- **Hyper-V:** Windows Server 2016–2025 hosts over PowerShell remoting or an exported collector script.
- **KVM/libvirt:** Linux hosts over SSH or an exported collector script.

## Scope of assessment

- Guest operating systems are not assessed. Guest metadata and virtual hardware are inventoried only.
- vCenter appliance OS and database hardening is not assessed from inventory. Appliance and SSO checks may be `UNKNOWN` with read-only rights.
- Physical network visibility is limited to LLDP/CDP immediate neighbors. Switch, router and firewall configuration imports are not implemented yet.
- External backup products are not audited. A snapshot is not proof of a backup, and a successful job is not proof of a restore.
- IDS/IPS and licensing-dependent NSX features are inventoried where exposed. A missing license is reported as a capability gap, not a violation.

## Analysis features

- **Attack paths** are *configuration-inferred*. They ignore guest firewalls, upstream ACLs and runtime state that VSAT did not collect, and they list this as uncertainty. They are not proof of reachability or exploitability.
- **Blast radius** paths are configuration-inferred like attack paths. Group nesting, stored credentials and hops VSAT cannot read come only from the scope file and are marked operator-declared. Searches are bounded (depth, paths, sources); when a bound is hit the report says so. On a synthetic graph of 10,000 VMs and 2,000 principals the search finishes in about 9 seconds (PowerShell 7.6, Apple M-series laptop).
- **OT segmentation lens** covers the virtualization layer only. It depends on the Purdue levels you declare; without them it is `NOT_APPLICABLE`. OT networks, industrial protocols and field devices are not assessed.
- **Ransomware readiness** is based on configuration only. Backup systems are the assets you declare in `backupSystems`. VSAT does not check the backup product itself: immutability, offline or air-gapped copies, retention, repository storage and whether restores work are not assessed. One-account reach counts only rights VSAT collects (vCenter permissions, Hyper-V local groups, KVM admin groups). AD group nesting counts only when you declare it in `identityGroups`.
- **Failure impact** is a configuration model. It does not prove failover behavior, and physical redundancy is often `unknown`. VSAT performs no failure injection.
- **Engagement timeline** shows only changes the platforms recorded themselves, inside their retention: vCenter events (up to 50,000 per run), NSX objects' last modification (earlier edits of the same object are not visible), the Hyper-V host's System, Security, firewall and VMMS event logs (the Security log needs Event Log Readers), and on KVM file modification times (latest write only), the current package history log (rotated logs are not read) and `last` login records. Changes made directly on an ESXi host that vCenter did not see, in guest operating systems or on physical devices are not visible. Log clearing and short retention are reported as a history gap, not hidden. Packages from before VSAT 2.4 have no change history (`change-history` `UNKNOWN`).
- **Receipt codes** identify a package; they are not signatures and do not prove who produced it.
- **Drift** needs evidence packages written with a compatible schema. Findings whose evidence has disappeared are shown as `unassessed`, not `resolved`.
- **Traceflow and other active verification** are not implemented. The audit is passive.
- **Topology exports** (SVG/PNG) and the print layout are implemented in the standalone report; very large graphs are capped per expansion level to stay responsive.

## Security

- PowerShell cannot guarantee that secrets are wiped from memory (see [threat-model.md](threat-model.md#residual-risks)).
- Loopback is not an authentication boundary. Run VSAT on a trusted, single-user machine.
- Evidence hashes detect changes to outputs. They are not signatures, and they do not prove what the source systems reported was true.
- Encryption of evidence packages is not implemented. Protect outputs with your own controls.
