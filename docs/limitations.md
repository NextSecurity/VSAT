# Limitations

This page is the full list of limits for VSAT `2.0.0-alpha.1`. It is updated with every release. If something here matters for your use case, wait for a later release or help validate it.

## Release status

- **Not validated against live systems.** Collectors and rules were built from vendor API documentation. They are exercised by unit/fixture tests, the built-in demo lab, and a protocol-level integration test (`tests/integration/`) against the govmomi **vcsim** vSphere simulator (v0.56.0, simulated vCenter 6.5 API) and a mock NSX Manager API. A simulator is not a real product: no vCenter, ESXi or NSX build is listed as tested, and esxcli-based checks could not be exercised (vcsim does not implement esxcli).
- **No code-signing certificate.** Verify SHA-256 checksums. Environments that enforce signed scripts need to allow-list by hash through their own process.
- **Offline package is built by you.** Redistribution rights for PowerShell and PowerCLI inside our release are not confirmed, so `build/New-OfflinePackage.ps1` assembles the package on a connected machine from vendor sources.
- **No performance measurements.** Duration, memory use and API load on large inventories are unknown. The plan's scale dataset (5 vCenters, 100 hosts, 5,000 VMs, 10,000 NSX rules) is a future test target, not a result.

## Benchmarks and results

- **CIS control ID mappings are `unverified`.** They will stay that way until the licensed benchmark documents have been reviewed. The technical checks are original implementations.
- **VSAT is not certified by, endorsed by or affiliated with CIS, VMware or Broadcom.** A run with no failures does **not** mean compliance with any benchmark or standard.
- "Complete" means every applicable planned check reached a known result. It does not mean every risk was assessed. `MANUAL` controls always need human review.
- Advisory evaluation depends on a dated snapshot. It cannot know about later advisories. Version exposure does not prove exploitability.
- STIG profiles are not included in this alpha. The profiles are `standard` and `strict`.

## Platforms

- **Runner:** Windows x64 with PowerShell 7.4+ (the offline package pins PowerShell 7.6.6 LTS) is the only supported target. CI also runs the test suite on Linux, and development happens on macOS, but neither is a supported assessment runner yet. Windows PowerShell 5.1 is not supported.
- **vSphere:** targets 8.x and 9.x as modern, and 7.x as legacy. Older versions and historical ESX are inventoried where possible and marked with legacy or manual coverage.
- **NSX:** targets modern NSX via the Policy/Manager API. NSX-V and unsupported versions are reported as such and get manual coverage. NSX Federation (Global Manager), projects and VPCs are not modeled in this alpha.
- **Other hypervisors:** only VMware is implemented. Hyper-V (2.1) and KVM/libvirt (2.2) are planned and not available.

## Scope of assessment

- Guest operating systems are not assessed. Guest metadata and virtual hardware are inventoried only.
- vCenter appliance OS and database hardening is not assessed from inventory. Appliance and SSO checks may be `UNKNOWN` with read-only rights.
- Physical network visibility is limited to LLDP/CDP immediate neighbors. Switch, router and firewall configuration imports are not implemented yet.
- External backup products are not audited. A snapshot is not proof of a backup, and a successful job is not proof of a restore.
- IDS/IPS and licensing-dependent NSX features are inventoried where exposed. A missing license is reported as a capability gap, not a violation.

## Analysis features

- **Attack paths** are *configuration-inferred*. They ignore guest firewalls, upstream ACLs and runtime state that VSAT did not collect, and they list this as uncertainty. They are not proof of reachability or exploitability.
- **Failure impact** is a configuration model. It does not prove failover behavior, and physical redundancy is often `unknown`. VSAT performs no failure injection.
- **Drift** needs evidence packages written with a compatible schema. Findings whose evidence has disappeared are shown as `unassessed`, not `resolved`.
- **Traceflow and other active verification** are not implemented. The audit is passive.
- **Topology exports** (SVG/PNG) and the print layout are implemented in the standalone report; very large graphs are capped per expansion level to stay responsive.

## Security

- PowerShell cannot guarantee that secrets are wiped from memory (see [threat-model.md](threat-model.md#residual-risks)).
- Loopback is not an authentication boundary. Run VSAT on a trusted, single-user machine.
- Evidence hashes detect changes to outputs. They are not signatures, and they do not prove what the source systems reported was true.
- Encryption of evidence packages is not implemented. Protect outputs with your own controls.
