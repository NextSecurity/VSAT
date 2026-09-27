# Least privileges

VSAT only reads. Give it a **dedicated, read-only account** for each system. Do not use an administrator account.

VSAT reports each missing privilege as `UNKNOWN` evidence with the affected checks, and never as a pass.

## vCenter

**Starting point:** the built-in **Read-only** role, assigned to a dedicated account (for example `svc-vsat@example.local`) at the **vCenter root object with "Propagate to children"**. For inventory that is only visible through global permissions, also assign it as a **global permission**.

The Read-only role grants `System.Anonymous`, `System.View` and `System.Read`. That is enough for most inventory, configuration and network policy reads, including `HostConfigInfo.lockdownMode`, advanced settings, services, firewall rules, port group policies and VM configuration.

| Area | With Read-only |
|---|---|
| Inventory, cluster HA/DRS, VM hardware and advanced settings | Yes |
| Host configuration (lockdown mode, services, firewall, NTP/DNS, advanced options) | Yes, through read-only property access |
| Distributed switch and port group effective policy | Yes |
| Roles and permissions listing | Yes; some deployments restrict it |
| `esxcli`-based reads through `Get-EsxCli` (for example acceptance level and some software details) | **May require `Host.Cli`**, which is not part of Read-only |
| Appliance (VAMI) settings: SSH, backup, appliance firewall | Uses separate appliance APIs and may need additional rights; otherwise reported as `UNKNOWN` |
| SSO and identity source configuration | May need SSO administrator-level read. VSAT does not ask for administrator rights, so these checks may be `UNKNOWN`. |

PCI passthrough, SR-IOV and host graphics state (`HostSystem.config.pciPassthruInfo`, `hardware.pciDevice`, the graphics manager) and VM passthrough devices are plain property reads covered by **Read-only**.

**Do not** grant `Host.Config.*`, `VirtualMachine.Config.*`, `Global.Settings` or any modify privileges. VSAT has no use for them.

If you decide to allow `Host.Cli` for `esxcli` reads, create a custom role by cloning **Read-only** and adding only **Host > CIM/CLI > Host.Cli** (the name varies by version). Understand that `Host.Cli` exposes the whole esxcli namespace, which includes write operations. VSAT only calls read namespaces, but the privilege itself is broader. Leaving it out is a valid choice. The affected checks will then show `UNKNOWN`.

## ESXi (standalone hosts)

When you connect directly to a host, use a local account with the **Read-only** role. Hosts in lockdown mode may reject direct connections. In that case, audit through vCenter.

## NSX

Use the built-in **Auditor** role (read-only across NSX), assigned to a dedicated local or LDAP/vIDM user.

| Area | With Auditor |
|---|---|
| Manager/cluster status, fabric, transport nodes and zones | Yes |
| Segments, Tier-0/Tier-1, NAT, routing configuration | Yes |
| Distributed and gateway firewall policy, groups, effective members, realization | Yes |
| Backup configuration, user and role assignments | Yes |
| Support bundles, Traceflow, any POST other than session create/destroy | Not used by VSAT |

VSAT creates an API session with a POST and destroys it at the end. Every other NSX call is a GET, enforced by the allowlist described in [threat-model.md](threat-model.md).

## Hyper-V

The collector runs elevated on the host (or through PowerShell remoting with an administrator account) and only calls `Get-*` cmdlets. The AI & GPU reads add `Get-VMHostPartitionableGpu` (or `Get-VMPartitionableGpu` on Windows Server 2019), `Get-VMHostAssignableDevice`, `Get-VMGpuPartitionAdapter`, `Get-VMAssignableDevice`, `Get-SmbShare` and `Get-SmbShareAccess`. Share permission reads need local administrator rights; without them the `smbShares` fact is `denied` and `AI-SHARE-SMB` is `UNKNOWN`.

## KVM/libvirt

The collector needs no root for the AI & GPU reads: `/proc/cmdline`, `/proc/mounts`, `/etc/exports`, `/sys/kernel/iommu_groups`, `/sys/class/iommu` and `/sys/bus/mdev` are world-readable on common distributions, `virsh --readonly domifaddr` works on a read-only connection, and `nvidia-smi -q -x` runs only if it is already on the `PATH`. `lspci` hides PCIe ACS capability details from unprivileged users; VSAT then records the `acs` fact as `unsupported` instead of guessing.

## Missing privileges in results

When a read is denied, VSAT:

1. records the fact with status `denied` and the error text (secrets redacted),
2. marks the dependent checks `UNKNOWN` and names the privilege where it is known,
3. lowers the domain's coverage to `PARTIAL` or `INCOMPLETE`, and
4. for NSX, reports `INCOMPLETE: NSX NOT ASSESSED` if policy cannot be read at all.
