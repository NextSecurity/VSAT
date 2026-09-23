# Using VSAT

> **Alpha (`2.0.0-alpha.1`).** VSAT has not been validated against a live lab. Review every result before acting on it. See [limitations.md](limitations.md).

## Requirements

- Windows x64 (the first target). Linux and macOS are not supported or validated.
- PowerShell 7.4 or later.
- VMware PowerCLI (`VCF.PowerCLI` or `VMware.PowerCLI`; the core module is `VMware.VimAutomation.Core`). The offline package loads it from `./modules`. When you run `vsat.ps1` on its own, VSAT uses modules that are already available to the session and does not install anything.
- A read-only account on vCenter (or ESXi) and NSX. See [privileges.md](privileges.md).
- Network access from the runner to the endpoints on HTTPS (443).

Run `.\vsat.ps1 -Doctor` first. It checks the runtime, modules, output folder, reachability and TLS trust, and reports problems in plain language without starting an audit.

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
  "zones":          [ { "name": "DMZ", "match": "tag:zone=dmz" } ],
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
| `collection.log` | Collection log, secrets redacted |
| `manifest.json` | Versions, timestamps and SHA-256 of every output |
| `assessment.vsat.zip` | Evidence package for `-Replay` and `-Baseline` |
| `assessment.redacted.vsat.zip`, `report.redacted.html` | With `-Redact`: sharing copies with consistent pseudonyms |

**These outputs describe your infrastructure in detail. Handle them as sensitive.** Share the redacted copies, not the originals.

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
