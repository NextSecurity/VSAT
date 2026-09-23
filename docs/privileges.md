# Least privileges

VSAT only reads. Give it a **dedicated, read-only account** for each system. Do not use an administrator account.

> **To be validated in a lab.** The guidance below comes from vendor documentation and has **not yet been confirmed against live vCenter, ESXi or NSX systems**. Some checks may need additional read privileges. VSAT reports each missing privilege as `UNKNOWN` evidence with the affected checks, and never as a pass. Please report what you observe: see [CONTRIBUTING.md](../CONTRIBUTING.md#lab-validation-reports).

## vCenter

**Starting point:** the built-in **Read-only** role, assigned to a dedicated account (for example `svc-vsat@example.local`) at the **vCenter root object with "Propagate to children"**. For inventory that is only visible through global permissions, also assign it as a **global permission**.

The Read-only role grants `System.Anonymous`, `System.View` and `System.Read`. That is enough for most inventory, configuration and network policy reads, including `HostConfigInfo.lockdownMode`, advanced settings, services, firewall rules, port group policies and VM configuration.

| Area | Expected with Read-only | Status |
|---|---|---|
| Inventory, cluster HA/DRS, VM hardware and advanced settings | Yes | To be validated |
| Host configuration (lockdown mode, services, firewall, NTP/DNS, advanced options) | Yes, through read-only property access | To be validated |
| Distributed switch and port group effective policy | Yes | To be validated |
| Roles and permissions listing | Probably yes; some deployments restrict this | To be validated |
| `esxcli`-based reads through `Get-EsxCli` (for example acceptance level and some software details) | **May require `Host.Cli`**, which is not part of Read-only | To be validated |
| Appliance (VAMI) settings: SSH, backup, appliance firewall | Uses separate appliance APIs and may need additional rights; otherwise reported as `UNKNOWN` | To be validated |
| SSO and identity source configuration | May need SSO administrator-level read. VSAT does not ask for administrator rights, so these checks may be `UNKNOWN`. | To be validated |

**Do not** grant `Host.Config.*`, `VirtualMachine.Config.*`, `Global.Settings` or any modify privileges. VSAT has no use for them.

If you decide to allow `Host.Cli` for `esxcli` reads, create a custom role by cloning **Read-only** and adding only **Host > CIM/CLI > Host.Cli** (the name varies by version). Understand that `Host.Cli` exposes the whole esxcli namespace, which includes write operations. VSAT only calls read namespaces, but the privilege itself is broader. Leaving it out is a valid choice. The affected checks will then show `UNKNOWN`.

## ESXi (standalone hosts)

When you connect directly to a host, use a local account with the **Read-only** role. Hosts in lockdown mode may reject direct connections. In that case, audit through vCenter.

## NSX

Use the built-in **Auditor** role (read-only across NSX), assigned to a dedicated local or LDAP/vIDM user.

| Area | Expected with Auditor | Status |
|---|---|---|
| Manager/cluster status, fabric, transport nodes and zones | Yes | To be validated |
| Segments, Tier-0/Tier-1, NAT, routing configuration | Yes | To be validated |
| Distributed and gateway firewall policy, groups, effective members, realization | Yes | To be validated |
| Backup configuration, user and role assignments | Probably yes | To be validated |
| Support bundles, Traceflow, any POST other than session create/destroy | Not used by VSAT | — |

VSAT creates an API session with a POST and destroys it at the end. Every other NSX call is a GET, enforced by the allowlist described in [threat-model.md](threat-model.md).

## Missing privileges in results

When a read is denied, VSAT:

1. records the fact with status `denied` and the error text (secrets redacted),
2. marks the dependent checks `UNKNOWN` and names the privilege where it is known,
3. lowers the domain's coverage to `PARTIAL` or `INCOMPLETE`, and
4. for NSX, reports `INCOMPLETE: NSX NOT ASSESSED` if policy cannot be read at all.
