# Using VSAT

Review every result before acting on it. See [limitations.md](limitations.md) for what is and is not covered.

## Getting vsat.ps1

Download `vsat.ps1` and verify it against the published `SHA256SUMS.txt` before running it; never pipe a download straight into the shell. See the README's [One-command start](../README.md#one-command-start) for copy-paste one-liners (Windows and Linux/macOS) that download, verify and run the built-in demo, plus a pinned-version variant for reproducible installs. On Windows, `Unblock-File` clears Mark-of-the-Web from the download so it is not silently blocked.

## Requirements

- Windows x64 (the first target). Linux and macOS are not supported or validated.
- PowerShell 7.4 or later.
- VMware PowerCLI (`VCF.PowerCLI` or `VMware.PowerCLI`; the core module is `VMware.VimAutomation.Core`). The offline package loads it from `./modules`. When you run `vsat.ps1` on its own, VSAT uses modules that are already available to the session and does not install anything.
- A read-only account on vCenter (or ESXi) and NSX. See [privileges.md](privileges.md).
- Network access from the runner to the endpoints on HTTPS (443).

Run `.\vsat.ps1 -Doctor` first. It checks the runtime, modules, output folder, reachability and TLS trust, and reports problems in plain language without starting an audit.

## Supported VMware versions

Point VSAT at vCenter. One vCenter connection covers the vCenter itself, its clusters, distributed switches, datastores, VMs and every ESX/ESXi host it manages.

| Product | Versions | Connect via | Notes |
|---|---|---|---|
| vCenter Server (recommended) | 7.0 U3, 8.0 (up to 8.0 U3), 9.0, 9.1 | `-Server vc01.example.local` | Host checks run on every host the vCenter manages, including hosts in maintenance mode. A disconnected or not-responding host stays in the inventory. Its checks, and the checks of VMs running on it, report UNKNOWN; none pass. A FAIL based on the build vCenter cached is kept, as are not-applicable and manual results. Tested in CI (vcsim) with the simulator's default API version and with vSphere API 8.0.3.0 and 9.0.0.0. |
| ESXi / ESX host, direct | 7.0 U3, 8.0 (up to 8.0 U3), 9.0, 9.1 | `-Server esx01.example.local` | Host and VM checks only. vCenter and distributed-switch checks are skipped. ESX 9.0 removed CIM, SFCB and OpenSLP, so the CIM and SLP checks are not applicable on 9.x. |
| NSX | NSX-T 3.2, NSX 4.0 to 4.2, NSX 9.0 and 9.1 (with VCF 9) | `-NsxServer nsx01.example.local` | GET calls to the Policy and Manager APIs only. Every endpoint VSAT reads is listed in the NSX 9.0 and 9.1 API guides. Tested in CI against a mock NSX Manager. |
| PowerCLI | `VCF.PowerCLI` 9.x (pinned: 9.1.1.25718932, which contains `VMware.VimAutomation.Core` 13.5.1) or `VMware.PowerCLI` 13.x | `Install-Module VCF.PowerCLI -Scope CurrentUser` | VSAT loads only `VMware.VimAutomation.Core`, which both install forms provide. `-Doctor` names the form it finds. Broadcom recommends removing `VMware.PowerCLI` before installing `VCF.PowerCLI`. The Broadcom Product Interoperability Matrix lists which PowerCLI release supports which vCenter and ESXi release. |
| Advisory and lifecycle data | 7.0, 8.0, 9.0, 9.1 (NSX 3.2, 4.x) | none | Advisory branches are keyed by the first two version parts (`9.0`, `9.1`). 7.0 reached end of general support on 2025-10-02, so it is reported as a lifecycle FAIL. No exact end-of-general-support day is confirmed on an official page for 8.0 or 9.x, so those lifecycle checks are MANUAL. |

## Starting an assessment

### Guided browser UI (default)

```powershell
.\VSAT.cmd          # offline package launcher
.\vsat.ps1          # same, with an existing runtime
```

VSAT starts a local listener on `127.0.0.1` and opens your default browser. Use `-Port` to choose the port and `-NoBrowser` to print the URL without opening it. The URL contains a per-run token in its fragment (`#…`). Do not share it.

1. **Launch.** A readiness summary.
2. **Authenticate.** Add one or more vCenter or ESXi endpoints. VSAT prompts for credentials in the terminal where practical.
3. **NSX (mandatory).** Enter your NSX Manager(s), or confirm NSX is not deployed. VSAT shows what it discovered, such as a registered NSX extension in vCenter.
4. **Review scope.** Check the discovered systems and exclusions. The profile defaults to `standard`.
5. **Run.** Watch phase progress, object counts and plain-language errors. You can cancel.
6. **Results.** Browse Overview, Findings, Topology, NSX, Changes, Remediation and Exports.

### Endpoints on the command line

```powershell
.\vsat.ps1 -Server vc01.example.local -NsxServer nsx01.example.local
```

VSAT prompts for credentials. To script a run, pass `PSCredential` objects:

```powershell
$vc  = Get-Credential -Message 'vCenter read-only account'
$nsx = Get-Credential -Message 'NSX Auditor account'
.\vsat.ps1 -Cli -Server vc01.example.local -Credential $vc -NsxServer nsx01.example.local -NsxCredential $nsx
```

Passwords are never accepted as plain command-line strings.

### Terminal only

```powershell
.\vsat.ps1 -Cli
```

Terminal mode has the same mandatory domains, statuses and findings, and does not need a browser.

### Demo and replay

```powershell
.\vsat.ps1 -Demo                              # built-in synthetic lab, no connectivity
.\vsat.ps1 -Replay .\assessment.vsat.zip      # reopen and re-evaluate saved evidence
```

Replay needs no credentials or connectivity. It re-evaluates rules only where the required facts exist in the package. A rule that needs evidence the package does not contain returns `UNKNOWN`, never `PASS`.

### When the customer runs VSAT

Often the customer runs VSAT with their own rights and the auditor sees the output later. VSAT does not try to stop the customer from fixing gaps first, running it privately or editing files. It makes those things visible:

1. **Kickoff.** Agree the engagement start date. Write it in the engagement notes.
2. **Collect on a call.** While the auditor is on the call, the customer runs:

   ```powershell
   .\vsat.ps1 -CollectOnly -EngagementStart 2026-09-01
   ```

   Collect-only writes exactly three files: `assessment.vsat.zip`, `collection.log` and `manifest.json`. It shows no findings and no report, so there is nothing to read, fix and re-run.
3. **Read the receipt aloud.** The last line (and, in the browser, the final step in large type) is a code like `VSAT-7Q2M-XK4D-9HNB-3TRE`. The customer reads it to the auditor.
4. **Write it down.** The auditor records the receipt in the engagement notes.
5. **Transfer the package.** The customer sends only `assessment.vsat.zip`.
6. **Verify and evaluate.** The auditor runs:

   ```powershell
   .\vsat.ps1 -Replay .\assessment.vsat.zip -Receipt VSAT-7Q2M-XK4D-9HNB-3TRE
   ```

   A match produces the full report with a **Receipt verified** banner. A mismatch stops with exit code `3` and no report: this is not the package from that session, or it was changed.

The report's Changes page then shows the **Engagement timeline**: what the platforms themselves recorded as changed since the engagement start, who changed it and when.

- A check that passes now but whose setting changed in the window is marked **Changed during engagement**. The result stays as collected (a `PASS` stays a `PASS`); the badge tells you to ask about it. The overview shows "N checks pass now but changed during the engagement".
- **Earlier sessions by the VSAT account** (vCenter sign-in events, KVM login records) show private dry runs.
- If a platform's history starts after the engagement start (short retention, rotated or cleared logs), the `change-history` coverage domain is `PARTIAL` and names both dates. Denied reads make it `UNKNOWN`. It is never silently empty, and it is not mandatory, so it never changes the exit code.

Sources, all read-only: vCenter and ESXi events (`Get-VIEvent`, window start, at most 50,000 records), NSX objects' own `_last_modified_time` / `_last_modified_user` (no extra API call), the Hyper-V host's System, Security, Windows Firewall and Hyper-V VMMS event logs (`Get-WinEvent`; the Security log needs the Event Log Readers group), and on KVM the modification time of key configuration files, the package history log and `last` login records. The offline collectors take the start date too: `vsat-hyperv-collect.ps1 -Since 2026-09-01` and `sh vsat-kvm-collect.sh 2026-09-01`.

## Parameters

| Parameter | Description |
|---|---|
| `-Server <string[]>` | vCenter or ESXi endpoint(s) |
| `-Credential <PSCredential>` | Credential for `-Server` |
| `-NsxServer <string[]>` | NSX Manager endpoint(s) |
| `-NsxCredential <PSCredential>` | Credential for `-NsxServer` |
| `-NsxDeclaredAbsent` | Operator declaration that NSX is not deployed in scope. It is recorded with discovery evidence. NSX coverage becomes `NOT_APPLICABLE` only when the evidence supports it, and `REVIEW` otherwise. |
| `-ScopeFile <path>` | Credential-free JSON scope (see below) |
| `-Profile standard\|strict` | Evaluation profile. Default: `standard` |
| `-OutputPath <path>` | Output folder. Default: a new timestamped folder |
| `-Baseline <path>` | A previous `.vsat.zip` to compare against (drift) |
| `-Redact` | Also write a redacted sharing copy with consistent pseudonyms |
| `-TrustedThumbprint "host=SHA256"` | Pin an endpoint certificate. Repeatable. It applies only to that endpoint. |
| `-Cli` | Terminal-only workflow |
| `-Doctor` | Readiness check only |
| `-Replay <path>` | Reopen an evidence package offline |
| `-Demo` | Use the built-in synthetic lab |
| `-Port <int>` | Local UI port. If the port is busy, VSAT reports it and picks a free loopback port. |
| `-NoBrowser` | Do not open a browser automatically |
| `-Version` | Print tool, rule pack, advisory snapshot and schema versions |
| `-EngagementStart <yyyy-MM-dd>` | Start of the change window for the engagement timeline. Default: 30 days before the run. At most 180 days back. Stored in the evidence, so a replay shows the same window. |
| `-CollectOnly` | Write only `assessment.vsat.zip`, `collection.log` and `manifest.json`, then show the receipt code. No findings, no report. Exit `0` on success, `3` when nothing could be collected. |
| `-Receipt <code>` | With `-Replay`: verify the package against the receipt code read out when it was collected. Match: report banner "Receipt verified". Mismatch: message and exit `3`. |
| `-HyperVServer`, `-HyperVCredential`, `-HyperVEvidence` | Hyper-V hosts over PowerShell remoting, or import of offline collector output |
| `-KvmServer`, `-KvmUser`, `-KvmEvidence` | KVM/libvirt hosts over SSH, or import of offline collector output |
| `-ExportCollector hyperv\|kvm` | Write the read-only offline collector script and exit |

## Scope file

The scope file is JSON and must never contain credentials. All fields are optional:

```json
{
  "endpoints": [
    { "type": "vcenter", "address": "vc01.example.local" },
    { "type": "nsx",     "address": "nsx01.example.local" }
  ],
  "exclusions":   [ { "pattern": "vm:lab-*", "reason": "Disposable test VMs" } ],
  "nativeVlans":  [ { "switch": "*", "vlan": 1 } ],
  "authorizedNetflowCollectors": [ "192.0.2.10" ],
  "authorizedSyslogTargets":     [ "udp://192.0.2.20:514" ],
  "criticalAssets": [ { "match": "name:vc01*", "criticality": "high" } ],
  "zones":          [ { "name": "DMZ", "match": "tag:zone=dmz" },
                      { "name": "Plant-L2", "match": "tag:zone=plant-l2", "purdueLevel": 2 } ],
  "entryPoints":      [ { "zone": "DMZ" }, { "principal": "EXAMPLE\\helpdesk" } ],
  "identityDomains":  [ { "dns": "example.local", "netbios": "EXAMPLE" } ],
  "identityGroups":   [ { "group": "EXAMPLE\\vi-admins", "members": [ "EXAMPLE\\jdoe" ] } ],
  "credentialStores": [ { "match": "name:backup01", "grants": "name:vc01*", "note": "backup service account" } ],
  "exceptions": [
    { "ruleId": "ESXI-SVC-SSH", "asset": "esx03.example.local", "owner": "infra-team",
      "rationale": "Vendor support session", "expires": "2026-12-31" }
  ]
}
```

VSAT records exclusions and reports their effect on completeness. Excepted findings stay `FAIL` and are shown with the owner and expiry. Once an exception expires, the finding goes back onto the active worklist.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Complete. No failing automated controls. Manual controls may still need review. |
| `1` | Complete. Findings present. |
| `2` | Incomplete. At least one mandatory domain is incomplete or unknown (for example `INCOMPLETE: NSX NOT ASSESSED`). |
| `3` | Fatal startup or collection failure |
| `4` | Canceled |

An incomplete or fatal status takes precedence over a clean finding count. A "complete" run means every applicable planned check reached a known result. It is not a certification.

## Outputs

| File | Contents |
|---|---|
| `report.html` | Standalone interactive report (works from `file://`, no server, no internet) |
| `results.json` | Findings, coverage, analysis ([data model](architecture/data-model.md)) |
| `evidence.json` | Normalized evidence with per-fact collection status |
| `findings.csv` | One row per finding, with formula neutralization |
| `worklist.csv` | Remediation worklist grouped by work package |
| `changes.csv` | Engagement timeline: one row per platform change in the window (time, asset, user, category, change, source, checks it touches), with formula neutralization |
| `attack-layer.json` | MITRE ATT&CK Navigator layer (format 4.5, enterprise-attack): each technique scored by open Blast Radius paths that use it plus failing controls that mitigate it. Open it in the ATT&CK Navigator (Open Existing Layer, Upload from local) |
| `collection.log` | Collection log, secrets redacted |
| `manifest.json` | Versions, timestamps and SHA-256 of every output, plus the package hash and receipt code |
| `assessment.vsat.zip` | Evidence package for `-Replay` and `-Baseline` |
| `assessment.redacted.vsat.zip`, `report.redacted.html` | With `-Redact`: sharing copies with consistent pseudonyms |

**These outputs describe your infrastructure in detail. Handle them as sensitive.** Share the redacted copies, not the originals.

**Receipt code.** Every run ends with `VSAT-XXXX-XXXX-XXXX-XXXX`: the first 80 bits of the SHA-256 of `assessment.vsat.zip`, in Crockford base32 (no I, L, O or U; `O` read as `0` and `I`/`L` as `1` are accepted). It is computed after the zip is written, so it is recorded in the `manifest.json` and `collection.log` next to the zip, not inside it. Check it with `-Replay assessment.vsat.zip -Receipt <code>`.

## Blast radius

Every run answers one question: **if this account or VM is compromised, what can an attacker reach?** The report's Blast radius page lets you pick an entry point and shows the crown jewels it reaches, the path to each one, and a ranked list of fixes. Tick a fix to see which paths it breaks.

- **Crown jewels** are your `criticalAssets` rated `high`, plus vCenter, NSX Manager and Hyper-V clusters automatically.
- **Entry points** default to one representative VM per platform and network, plus every account that administers something. Set `entryPoints` to choose your own (`match`, `zone`, `assetId` or `principal`).
- **Paths** are built only from collected evidence: admin rights, VM placement, NSX firewall decisions, shared virtual switches and management networks. Hops VSAT cannot verify are listed separately as "collect this to confirm" and are never ranked.
- `identityDomains` joins `EXAMPLE\user` and `user@example.local` across platforms. `identityGroups` and `credentialStores` add group nesting and stored credentials that VSAT cannot read itself; they are marked operator-declared.
- Each hop carries a MITRE ATT&CK technique, and `attack-layer.json` opens in the ATT&CK Navigator.

Paths are inferred from configuration. They do not account for guest firewalls or upstream ACLs VSAT did not collect.

## OT segmentation lens

For OT and ICS sites, VSAT checks whether the virtualization layer keeps OT workloads apart from IT. Turn it on by giving zones a Purdue level in the scope file: `0`–`3` are OT, `"dmz"` is the IT/OT DMZ, `4`–`5` are IT.

| Rule | Fails when |
|---|---|
| `OT-SHARED-HOST` | One hypervisor host runs both OT and IT workloads |
| `OT-SHARED-VSWITCH` | OT and IT VMs share a virtual switch or libvirt network |
| `OT-SHARED-MGMT` | One management plane manages both OT and IT hosts |
| `OT-IT-ADMIN` | An account administers both OT hosts and IT hosts |
| `OT-IT-PATH` | An OT workload is reachable from an IT entry point in the blast-radius graph |
| `OT-DMZ-BYPASS` | An IT VM reaches a level 0–2 OT VM directly, without passing the DMZ |

Without Purdue levels the `ot-segmentation` domain is `NOT_APPLICABLE`. VSAT audits the hypervisors, virtual networks, management planes and admin rights under OT workloads. It does not scan OT networks, speak industrial protocols or assess PLCs and other field devices.

## Result and coverage states

| Result | Meaning |
|---|---|
| `PASS` | Evidence collected and meets the profile expectation |
| `FAIL` | Evidence collected and violates the expectation |
| `MANUAL` | Cannot be decided automatically; a person must review it |
| `NOT_APPLICABLE` | Evidence shows the control does not apply |
| `UNKNOWN` | Evidence missing: denied, unsupported, or required operator input absent |
| `ERROR` | Collector or evaluator failure |

Domain coverage: `ASSESSED`, `PARTIAL`, `INCOMPLETE`, `UNKNOWN`, `NOT_APPLICABLE`, `REVIEW`. `UNKNOWN` results never improve coverage.
