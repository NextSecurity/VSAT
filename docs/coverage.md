# Control coverage matrix

Generated from rule pack **2026.09.0** for VSAT **2.0.0** by `build/New-CoverageDoc.ps1`. Do not edit by hand.

- **Automated** checks evaluate collected evidence; missing or denied evidence yields UNKNOWN, never PASS.
- **Manual** checks always produce MANUAL results with guidance; completion is not certification.
- CIS control IDs are carried over from the VSAT 1.x mapping and are marked **unverified** until reviewed against the licensed CIS ESXi 8.0 v1.4.0 / 7.0 v1.6.0 documents. CIS publishes no vCenter or NSX benchmark; those checks use vendor guidance or VSAT-native logic.
- Profiles: `standard` (default) and `strict`. Rules marked *strict only* run only with `-Profile strict`.

| Domain | Rules | Automated | Manual |
|---|---:|---:|---:|
| esxi | 37 | 35 | 2 |
| storage | 8 | 6 | 2 |
| network | 18 | 17 | 1 |
| nsx | 27 | 26 | 1 |
| vcenter | 9 | 5 | 4 |
| cluster | 4 | 4 | 0 |
| vm | 24 | 23 | 1 |
| **total** | **127** | **116** | **11** |

## esxi

| Rule | Title | Asset | Severity | Type | Profiles | Framework references |
|---|---|---|---|---|---|---|
| `ESXI-PATCH-ADV` | ESXi build is not exposed to known security advisories | host | critical | automated | standard, strict | CIS VMware ESXi Benchmark 1.1 *(unverified)* |
| `ESXI-LIFECYCLE` | ESXi release is within vendor general support | host | high | automated | standard, strict | VSAT ESXI-LIFECYCLE |
| `ESXI-ACCEPTANCE` | Host image acceptance level is not CommunitySupported | host | high | automated | standard, strict | CIS VMware ESXi Benchmark 1.2 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide esxi.acceptance-level *(unverified)* |
| `ESXI-EXEC-INSTALLED-ONLY` | Only installed binaries may execute (execInstalledOnly) | host | high | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide esxi.execinstalledonly *(unverified)* |
| `ESXI-TPM-ATTEST` | TPM attestation of host boot is accepted | host | medium | automated | strict | VSAT ESXI-TPM-ATTEST |
| `ESXI-SVC-SSH` | SSH service is stopped and set to start manually | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 5.3 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide esxi.ssh *(unverified)* |
| `ESXI-SVC-SHELL` | ESXi Shell is stopped and set to start manually | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 5.2 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide esxi.shell *(unverified)* |
| `ESXI-SVC-SLP` | SLP service is stopped and disabled | host | high | automated | standard, strict | VSAT ESXI-SVC-SLP |
| `ESXI-SVC-CIM` | CIM server is not running unless required | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 5.4 *(unverified)* |
| `ESXI-SVC-SNMP` | SNMP agent is not running unless required | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 2.5 *(unverified)* |
| `ESXI-LOCKDOWN` | Lockdown mode is enabled | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 5.5 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide esxi.lockdown-mode *(unverified)* |
| `ESXI-DCUI-TIMEOUT` | DCUI idle timeout is 600 seconds or less | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 5.1 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide UserVars.DcuiTimeOut *(unverified)* |
| `ESXI-SHELL-TIMEOUT` | ESXi Shell and SSH services time out within an hour | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 5.9 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide UserVars.ESXiShellTimeOut *(unverified)* |
| `ESXI-SHELL-IDLE` | Idle ESXi Shell and SSH sessions time out after 300 seconds or less | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 5.8 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide UserVars.ESXiShellInteractiveTimeOut *(unverified)* |
| `ESXI-HOSTCLIENT-TIMEOUT` | Host Client session timeout is 900 seconds or less | host | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide UserVars.HostClientSessionTimeout *(unverified)* |
| `ESXI-ACCOUNT-LOCK` | Failed login attempts before lockout is 5 or fewer | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 4.3 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Security.AccountLockFailures *(unverified)* |
| `ESXI-ACCOUNT-UNLOCK` | Account lockout lasts at least 15 minutes | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 4.4 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Security.AccountUnlockTime *(unverified)* |
| `ESXI-PASS-QUALITY` | Password quality control enforces long passwords | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 4.2 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Security.PasswordQualityControl *(unverified)* |
| `ESXI-PASS-HISTORY` | Previous 5 passwords cannot be reused | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 4.5 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Security.PasswordHistory *(unverified)* |
| `ESXI-AD-ADMINS-GROUP` | AD admin group is not the default 'ESX Admins' | host | high | automated | standard, strict | CIS VMware ESXi Benchmark 4.7 *(unverified)*<br>VSAT ESXI-AD-ADMINS-GROUP |
| `ESXI-AD-ADMINS-AUTOADD` | AD admin group auto-add is disabled | host | high | automated | standard, strict | VSAT ESXI-AD-ADMINS-AUTOADD |
| `ESXI-MOB` | Managed Object Browser is disabled | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 2.3 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Config.HostAgent.plugins.solo.enableMob *(unverified)* |
| `ESXI-DVFILTER` | dvfilter network API is not bound | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 2.6 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Net.DVFilterBindIpAddress *(unverified)* |
| `ESXI-BPDU` | Guest BPDU frames are blocked | host | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide Net.BlockGuestBPDU *(unverified)* |
| `ESXI-SALT` | Transparent page sharing uses per-VM salting | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 1.4 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Mem.ShareForceSalting *(unverified)* |
| `ESXI-SHELL-WARNING` | Shell warnings are not suppressed | host | info | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide UserVars.SuppressShellWarning *(unverified)* |
| `ESXI-LOG-LEVEL` | Host agent log level is info | host | info | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide Config.HostAgent.log.level *(unverified)* |
| `ESXI-NTP` | Time synchronization is configured and running | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 2.1 *(unverified)* |
| `ESXI-SYSLOG-REMOTE` | Remote syslog is configured | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 3.3 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Syslog.global.logHost *(unverified)* |
| `ESXI-SYSLOG-PERSIST` | Logs are stored persistently | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 3.2 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide Syslog.global.logDir *(unverified)* |
| `ESXI-COREDUMP` | Core dumps are sent to a central collector | host | low | automated | standard, strict | CIS VMware ESXi Benchmark 3.1 *(unverified)* |
| `ESXI-FW-DEFAULT` | Host firewall blocks incoming traffic by default | host | high | automated | standard, strict | CIS VMware ESXi Benchmark 2.2 *(unverified)* |
| `ESXI-FW-ALLIP` | Management services restrict allowed source IPs | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 2.2 *(unverified)* |
| `ESXI-CERT-SELFSIGNED` | Host certificate is not self-signed | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 2.4 *(unverified)* |
| `ESXI-CERT-EXPIRY` | Host certificate is not expired or near expiry | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 2.7 *(unverified)* |
| `ESXI-DCUI-ACCESS` | DCUI access and lockdown exception users are reviewed | host | low | manual | standard, strict | CIS VMware ESXi Benchmark 5.10 *(unverified)* |
| `ESXI-LOCAL-ACCOUNTS` | Local accounts are named, least-privilege and reviewed | host | low | manual | standard, strict | CIS VMware ESXi Benchmark 4.1 *(unverified)* |

## storage

| Rule | Title | Asset | Severity | Type | Profiles | Framework references |
|---|---|---|---|---|---|---|
| `ESXI-ISCSI-CHAP` | iSCSI adapters require mutual CHAP | host | medium | automated | standard, strict | CIS VMware ESXi Benchmark 6.1 *(unverified)* |
| `ST-NFS-AUTH` | NFS datastores use Kerberos authentication | datastore | low | automated | standard, strict | CIS VMware ESXi Benchmark 6.3 *(unverified)* |
| `ST-DATASTORE-ACCESSIBLE` | Datastore is accessible | datastore | medium | automated | standard, strict | VSAT ST-DATASTORE-ACCESSIBLE |
| `ST-VSAN-ENCRYPTION` | vSAN data-at-rest encryption is enabled | datastore | medium | automated | standard, strict | VSAT ST-VSAN-ENCRYPTION |
| `ST-VSAN-DIT` | vSAN data-in-transit encryption is enabled | datastore | low | automated | strict | VSAT ST-VSAN-DIT |
| `ST-RECOVERY-EVIDENCE` | Backup and restore-test evidence exists | vcenter | medium | manual | standard, strict | VSAT ST-RECOVERY-EVIDENCE |
| `ST-SAN-SEGREGATION` | SAN resources are segregated (zoning/LUN masking) | vcenter | low | manual | standard, strict | CIS VMware ESXi Benchmark 6.3 *(unverified)* |
| `VM-SNAPSHOT-AGE` | No snapshots older than 7 days | vm | medium | automated | standard, strict | VSAT VM-SNAPSHOT-AGE |

## network

| Rule | Title | Asset | Severity | Type | Profiles | Framework references |
|---|---|---|---|---|---|---|
| `ESXI-VMK-SEPARATION` | Management traffic is separated from vMotion and storage | host | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide vmotion-isolation *(unverified)* |
| `NET-VSS-PROMISC` | Standard port group rejects promiscuous mode (effective policy) | portgroup | high | automated | standard, strict | CIS VMware ESXi Benchmark 7.3 *(unverified)* |
| `NET-VSS-MAC` | Standard port group rejects MAC address changes (effective policy) | portgroup | medium | automated | standard, strict | CIS VMware ESXi Benchmark 7.2 *(unverified)* |
| `NET-VSS-FORGED` | Standard port group rejects forged transmits (effective policy) | portgroup | medium | automated | standard, strict | CIS VMware ESXi Benchmark 7.1 *(unverified)* |
| `NET-VSS-DEFAULT-POLICY` | Standard vSwitch default security policy rejects all three | vss | low | automated | standard, strict | CIS VMware ESXi Benchmark 7.1 *(unverified)* |
| `NET-VDS-PROMISC` | Distributed port group rejects promiscuous mode | dvportgroup | high | automated | standard, strict | CIS VMware ESXi Benchmark 7.3 *(unverified)* |
| `NET-VDS-MAC` | Distributed port group rejects MAC address changes | dvportgroup | medium | automated | standard, strict | CIS VMware ESXi Benchmark 7.2 *(unverified)* |
| `NET-VDS-FORGED` | Distributed port group rejects forged transmits | dvportgroup | medium | automated | standard, strict | CIS VMware ESXi Benchmark 7.1 *(unverified)* |
| `NET-VDS-OVERRIDE-ALLOWED` | Port-level security policy overrides are not allowed | dvportgroup | low | automated | standard, strict | CIS VMware ESXi Benchmark 7.8 *(unverified)* |
| `NET-VDS-PORT-OVERRIDES` | No individual ports accept promiscuous, MAC change or forged transmits | dvportgroup | high | automated | standard, strict | CIS VMware ESXi Benchmark 7.8 *(unverified)* |
| `NET-VDS-DEFAULT-POLICY` | Distributed switch default security policy rejects all three | vds | low | automated | standard, strict | CIS VMware ESXi Benchmark 7.1 *(unverified)* |
| `NET-VLAN-4095` | Port groups do not use VLAN 4095 (trunk to guest) without authorization | portgroup | medium | automated | standard, strict | CIS VMware ESXi Benchmark 7.6 *(unverified)* |
| `NET-VLAN-NATIVE` | Port groups do not use the upstream native VLAN | portgroup | medium | automated | standard, strict | CIS VMware ESXi Benchmark 7.4 *(unverified)* |
| `NET-VLAN-RESERVED` | Port groups do not use VLANs reserved by upstream switches | portgroup, dvportgroup | low | automated | standard, strict | CIS VMware ESXi Benchmark 7.5 *(unverified)* |
| `NET-VDS-NETFLOW` | NetFlow/IPFIX is exported only to authorized collectors | vds | medium | automated | standard, strict | CIS VMware ESXi Benchmark 7.7 *(unverified)* |
| `NET-VDS-HEALTHCHECK` | VDS health check is disabled | vds | low | automated | standard, strict | CIS VMware ESXi Benchmark 2.9 *(unverified)* |
| `NET-VDS-MIRROR` | Port mirroring sessions are authorized | vds | medium | manual | standard, strict | VSAT NET-VDS-MIRROR |
| `NET-UPLINK-REDUNDANCY` | Virtual switch has redundant physical uplinks | vss | low | automated | standard, strict | VSAT NET-UPLINK-REDUNDANCY |

## nsx

| Rule | Title | Asset | Severity | Type | Profiles | Framework references |
|---|---|---|---|---|---|---|
| `NSX-MGR-ADV` | NSX Manager version is not exposed to known security advisories | nsx-manager | high | automated | standard, strict | VSAT NSX-MGR-ADV |
| `NSX-MGR-LIFECYCLE` | NSX release is within vendor general support | nsx-manager | high | automated | standard, strict | VSAT NSX-MGR-LIFECYCLE |
| `NSX-MGR-CLUSTER` | NSX management cluster is stable | nsx-manager | medium | automated | standard, strict | VSAT NSX-MGR-CLUSTER |
| `NSX-MGR-BACKUP` | Scheduled NSX backups are configured | nsx-manager | high | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide nsx.backup *(unverified)* |
| `NSX-MGR-SYSLOG` | NSX Manager forwards logs to remote syslog | nsx-manager | medium | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide nsx.syslog *(unverified)* |
| `NSX-MGR-NTP` | NSX Manager time synchronization is configured | nsx-manager | low | automated | standard, strict | VSAT NSX-MGR-NTP |
| `NSX-MGR-AUTH-LOCKOUT` | API authentication lockout after 5 or fewer failures | nsx-manager | medium | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide nsx.auth-policy *(unverified)* |
| `NSX-MGR-AUTH-LOCKOUT-PERIOD` | API lockout period is at least 15 minutes | nsx-manager | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide nsx.auth-policy *(unverified)* |
| `NSX-MGR-PASSWORD` | Local password minimum length is sufficient | nsx-manager | medium | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide nsx.auth-policy *(unverified)* |
| `NSX-MGR-CERT-EXPIRY` | NSX certificates are not expired or near expiry | nsx-manager | medium | automated | standard, strict | VSAT NSX-MGR-CERT-EXPIRY |
| `NSX-TN-STATE` | All transport nodes are realized successfully | nsx-manager | high | automated | standard, strict | VSAT NSX-TN-STATE |
| `NSX-DFW-ENABLED` | Distributed firewall is enabled | nsx-manager | critical | automated | standard, strict | VSAT NSX-DFW-ENABLED |
| `NSX-DFW-DEFAULT` | Default layer-3 DFW rule drops or rejects | nsx-manager | high | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide nsx.dfw-default-rule *(unverified)* |
| `NSX-DFW-DEFAULT-LOG` | Default layer-3 DFW rule logs traffic | nsx-manager | low | automated | standard, strict | VSAT NSX-DFW-DEFAULT-LOG |
| `NSX-DFW-EXCLUDE` | DFW exclusion list contains no user workloads | nsx-manager | high | automated | standard, strict | VSAT NSX-DFW-EXCLUDE |
| `NSX-DFW-ANYANY` | No enabled any-any-any ALLOW rules | nsx-rule | high | automated | standard, strict | VSAT NSX-DFW-ANYANY |
| `NSX-DFW-ANYSERVICE` | Broad ALLOW rules restrict services | nsx-rule | medium | automated | standard, strict | VSAT NSX-DFW-ANYSERVICE |
| `NSX-DFW-APPLIEDTO` | ALLOW rules scope Applied-To | nsx-rule | low | automated | standard, strict | VSAT NSX-DFW-APPLIEDTO |
| `NSX-DFW-EMPTY-GROUP` | Rules reference groups with effective members | nsx-rule | medium | automated | standard, strict | VSAT NSX-DFW-EMPTY-GROUP |
| `NSX-DFW-SHADOW` | Rules are not shadowed by earlier rules | nsx-rule | low | automated | standard, strict | VSAT NSX-DFW-SHADOW |
| `NSX-DFW-DISABLED` | No stale disabled rules | nsx-rule | info | automated | standard, strict | VSAT NSX-DFW-DISABLED |
| `NSX-DFW-DENY-LOG` | Deny rules log matched traffic | nsx-rule | low | automated | standard, strict | VSAT NSX-DFW-DENY-LOG |
| `NSX-EFF-UNPROTECTED` | Workload is covered by distributed firewall policy | vm | medium | automated | standard, strict | VSAT NSX-EFF-UNPROTECTED |
| `NSX-GFW-DEFAULT` | Gateway firewall default rules deny | nsx-manager | medium | automated | standard, strict | VSAT NSX-GFW-DEFAULT |
| `NSX-NAT-BYPASS` | NAT rules do not bypass the gateway firewall | nsx-t1 | medium | automated | standard, strict | VSAT NSX-NAT-BYPASS |
| `NSX-IDS` | Distributed IDS/IPS is enabled where licensed | nsx-manager | info | automated | standard, strict | VSAT NSX-IDS |
| `NSX-FEDERATION` | Federation / multi-tenancy context reviewed | nsx-manager | info | manual | standard, strict | VSAT NSX-FEDERATION |

## vcenter

| Rule | Title | Asset | Severity | Type | Profiles | Framework references |
|---|---|---|---|---|---|---|
| `VC-PATCH-ADV` | vCenter build is not exposed to known security advisories | vcenter | critical | automated | standard, strict | VSAT VC-PATCH-ADV |
| `VC-LIFECYCLE` | vCenter release is within vendor general support | vcenter | high | automated | standard, strict | VSAT VC-LIFECYCLE |
| `VC-ADMIN-USERS` | Administrator role is granted to groups, not individual users | vcenter | medium | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide vcenter.permissions *(unverified)* |
| `VC-PERMISSIONS-REVIEW` | vCenter permissions and roles are reviewed | vcenter | low | manual | standard, strict | VSAT VC-PERMISSIONS-REVIEW |
| `VC-PASSWORD-EXPIRY` | vpxuser password rotation is 30 days or less | vcenter | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide VirtualCenter.VimPasswordExpirationInDays *(unverified)* |
| `VC-EVENT-RETENTION` | Event and task retention meets investigation needs | vcenter | low | automated | standard, strict | VSAT VC-EVENT-RETENTION |
| `VC-SSO-POLICY` | SSO password, lockout and token policies are reviewed | vcenter | low | manual | standard, strict | VSAT VC-SSO-POLICY |
| `VC-APPLIANCE` | Appliance OS, SSH, backup and database controls are evidenced | vcenter | low | manual | standard, strict | VSAT VC-APPLIANCE |
| `VC-KEY-PROVIDER` | Key provider dependency is documented and redundant | vcenter | low | manual | standard, strict | VSAT VC-KEY-PROVIDER |

## cluster

| Rule | Title | Asset | Severity | Type | Profiles | Framework references |
|---|---|---|---|---|---|---|
| `CL-HA` | vSphere HA is enabled | cluster | medium | automated | standard, strict | VSAT CL-HA |
| `CL-HA-ADMISSION` | HA admission control is enabled | cluster | low | automated | standard, strict | VSAT CL-HA-ADMISSION |
| `CL-MULTIHOST` | Cluster has at least two hosts | cluster | low | automated | standard, strict | VSAT CL-MULTIHOST |
| `CL-DRS` | DRS is enabled | cluster | info | automated | standard, strict | VSAT CL-DRS |

## vm

| Rule | Title | Asset | Severity | Type | Profiles | Framework references |
|---|---|---|---|---|---|---|
| `VM-COPY-DISABLE` | Console copy operations are disabled | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.4.21 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide isolation.tools.copy.disable *(unverified)* |
| `VM-PASTE-DISABLE` | Console paste operations are disabled | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.4.24 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide isolation.tools.paste.disable *(unverified)* |
| `VM-DND-DISABLE` | Console drag-and-drop is disabled | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.4.22 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide isolation.tools.dnd.disable *(unverified)* |
| `VM-GUIOPTIONS` | Console GUI options are disabled | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.4.23 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide isolation.tools.setGUIOptions.enable *(unverified)* |
| `VM-DISKSHRINK` | Virtual disk shrinking is disabled | vm | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide isolation.tools.diskShrink.disable *(unverified)* |
| `VM-DISKWIPER` | Virtual disk wiping is disabled | vm | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide isolation.tools.diskWiper.disable *(unverified)* |
| `VM-CONSOLE-CONNECTIONS` | Only one remote console connection is permitted | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.1.2 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide RemoteDisplay.maxConnections *(unverified)* |
| `VM-SETINFO-LIMIT` | VMX informational message size is limited | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.1.1 *(unverified)*<br>Broadcom vSphere/NSX Security Configuration Guide tools.setInfo.sizeLimit *(unverified)* |
| `VM-HOSTINFO` | Host information is not sent to guests | vm | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide tools.guestlib.enableHostInfo *(unverified)* |
| `VM-LOG-KEEPOLD` | Number of retained VM log files is limited | vm | info | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide log.keepOld *(unverified)* |
| `VM-LOG-ROTATE` | VM log file size is limited | vm | info | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide log.rotateSize *(unverified)* |
| `VM-DEVICE-CONNECTABLE` | Guest cannot connect or disconnect devices | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.2.6 *(unverified)* |
| `VM-3D` | Hardware 3D acceleration is disabled | vm | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide mks.enable3d *(unverified)* |
| `VM-FLOPPY` | No floppy devices are present | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.2.1 *(unverified)* |
| `VM-CDROM` | No CD/DVD devices are connected | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.2.2 *(unverified)* |
| `VM-SERIAL` | No serial ports are present | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.2.4 *(unverified)* |
| `VM-PARALLEL` | No parallel ports are present | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.2.3 *(unverified)* |
| `VM-USB` | No USB controllers or devices are present | vm | low | automated | standard, strict | CIS VMware ESXi Benchmark 8.2.5 *(unverified)* |
| `VM-PASSTHROUGH` | No PCI/PCIe passthrough devices | vm | medium | automated | standard, strict | CIS VMware ESXi Benchmark 8.2.8 *(unverified)* |
| `VM-NONPERSISTENT` | Independent non-persistent disks are not used | vm | low | automated | standard, strict | Broadcom vSphere/NSX Security Configuration Guide vm.disk-persistent-mode *(unverified)* |
| `VM-TOOLS` | VMware Tools is current or supported | vm | low | automated | standard, strict | VSAT VM-TOOLS |
| `VM-SECUREBOOT` | VM uses UEFI firmware with Secure Boot | vm | low | automated | strict | Broadcom vSphere/NSX Security Configuration Guide vm.secure-boot *(unverified)* |
| `VM-ENCRYPTION` | VM is encrypted | vm | low | automated | strict | VSAT VM-ENCRYPTION |
| `VM-DVFILTER` | dvfilter network API access is authorized | vm | low | manual | standard, strict | CIS VMware ESXi Benchmark 8.4.1 *(unverified)* |

