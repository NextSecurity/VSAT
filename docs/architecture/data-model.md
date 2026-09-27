# VSAT data model (schema 2.3, additive over 2.0)

VSAT separates **evidence** (what was collected) from **results** (what the rule
engine concluded). Both are JSON, UTF-8, camelCase. All identifiers are stable
and namespaced by endpoint; names and IP addresses are never used as identity.

## 1. Evidence (`evidence.json`)

```jsonc
{
  "schemaVersion": "2.0",
  "tool":  { "name": "VSAT", "version": "2.0.0" },
  "run": {
    "id": "8c1e…",                    // GUID
    "startedUtc": "2026-09-23T10:00:00Z",
    "endedUtc":   "2026-09-23T10:04:12Z",
    "mode": "live|fixture|replay",
    "status": "complete|partial|canceled|failed"   // collection status only
  },
  "scope": {
    "endpoints": [
      { "id": "ep-vc01", "type": "vcenter|esxi|nsx", "address": "vc01.example.local",
        "status": "collected|partial|failed|not-attempted",
        "product": "vCenter Server", "version": "8.0.3", "build": "24322831",
        "instanceUuid": "…", "apiVersion": "8.0.3.0", "errors": ["…"] }
    ],
    "exclusions": [ { "pattern": "vm:lab-*", "reason": "…" } ],
    "nativeVlans": [ { "switch": "*", "vlan": 1 } ],        // operator supplied, optional
    "authorizedNetflowCollectors": ["10.0.0.5"],            // optional
    "authorizedSyslogTargets": [],                          // optional
    "criticalAssets": [ { "match": "name:vc01*", "criticality": "high" } ],
    "zones": [ { "name": "DMZ", "match": "tag:zone=dmz" } ],
    "exceptions": [ { "ruleId": "ESXI-SVC-SSH", "asset": "*", "owner": "infra",
                      "rationale": "…", "expires": "2026-12-31" } ],
    "nsxDeclaredAbsent": false,
    "backupSystems": [ { "match": "name:backup*" } ],   // 2.5, optional: backup infrastructure (crown jewels, RW-* rules)
    "aiWorkloads": [ { "match": "name:k8s-cp*", "role": "k8s-control-plane|k8s-worker|training|inference|dataset-store|model-registry", "criticality": "high" } ]   // 2.6, optional
  },
  // 2.4: run.engagementStartUtc (change window start) and run.collectOnly (true for -CollectOnly runs).
  // New facts: 'events' on vCenter/ESXi endpoint roots (Get-VIEvent) and on hyperv-host (Get-WinEvent),
  // 'changes' on kvm-host (file mtimes, package log, logins); NSX objects carry props.lastModifiedUtc/lastModifiedUser.
  "assets": [
    {
      "id": "ep-vc01:host-12",            // <endpointId>:<moref|nsx-path>
      "type": "vcenter|datacenter|cluster|host|vm|vss|vds|portgroup|dvportgroup|pnic|vmknic|datastore|nsx-manager|nsx-segment|nsx-t0|nsx-t1|nsx-edge-cluster|nsx-transport-node|nsx-group|nsx-policy|nsx-rule|physical-neighbor|site|zone",
      "name": "esx01.example.local",
      "endpoint": "ep-vc01",
      "version": "8.0.3", "build": "24585383",
      "site": "DC1", "zone": null, "tags": ["zone=prod"],
      "criticality": "high|medium|low|null", "criticalitySource": "operator|inferred|null",
      "observedUtc": "2026-09-23T10:01:00Z",
      "facts": {
        // every fact carries its own collection status
        "advanced":   { "status": "ok",     "value": { "UserVars.DcuiTimeOut": 600 } },
        "services":   { "status": "ok",     "value": [ { "key": "TSM-SSH", "running": false, "policy": "off" } ] },
        "lockdown":   { "status": "denied", "value": null, "error": "NoPermission: Host.Config.Settings" }
      }
      // 2.6 accelerator / AI-storage facts (additive):
      //   host:        pciPassthru [ { id, vendorId, deviceId, vendorName, deviceName, classId, passthruCapable, passthruEnabled, passthruActive, sriovEnabled, numVirtualFunction } ],
      //                graphics { defaultType, sharedPassthruAssignmentPolicy, devices[] }, iommu { enabled, source: "inferred-from-active-passthrough" } (else unsupported)
      //   vm:          accel { count, devices: [ { kind: passthrough|dynamic-passthrough|vgpu|sriov-nic, id, vgpuProfile, pfId } ] }
      //   datastore:   nas gains nfsVersion
      //   pnic:        props.pci (PCI address)
      //   hyperv-host: gpuPartition [ { name, partitionCount, validPartitionCounts, totalVRAM } ], assignable [ { locationPath, instanceId, dismounted } ],
      //                sriov [ { switch, iovEnabled, iovSupport, iovSupportReasons, allowManagementOS } ], smbShares [ { name, path, scope, encryptData, folderEnumerationMode, access: [ { account, right, type } ] } ]
      //   hyperv-vm:   accel { count, devices: [ { kind: dda|gpu-p|sriov-nic, locationPath, lowMMIO, highMMIO } ] }
      //   kvm-host:    cmdline { raw, iommu: on|pt|off|null, acsOverride, intremapOff }, iommu { enabled, groups: [ { id, devices } ], interruptRemapping, source },
      //                acs [ { bdf, acsCtl } ] (unsupported when lspci hides it), mdev [ { uuid, type, parent } ], gpuMig [ { index, name, migMode, migDevices } ] (absent without nvidia-smi),
      //                exports [ { path, clients: [ { host, options } ] } ] (absent when none), mounts [ { source, target, fstype, options } ]
      //   kvm-vm:      accel { count, devices: [ { kind: hostdev-pci|mdev|sriov-vf, bdf, managed, mdevUuid, mdevType } ] }, domain.value.ips
      // Annotated at analysis time: aiRole, aiRoleSource (operator|tag).
    }
  ],
  "relationships": [
    { "source": "ep-vc01:domain-c8", "target": "ep-vc01:host-12",
      "type": "contains|runs-on|connects|uplink|neighbor|member-of|enforces|applies-to|routes|depends|manages|stores",
      "provenance": "vsphere.inventory", "confidence": "observed|inferred", "props": {} }
  ],
  "collection": {
    "collectors": [
      { "name": "vsphere.hosts", "endpoint": "ep-vc01", "status": "ok|partial|denied|error|skipped|unsupported",
        "startedUtc": "…", "endedUtc": "…", "objectCount": 12, "error": null,
        "affects": ["ESXI-*"] }
    ],
    "log": [ { "t": "…", "level": "info|warn|error", "source": "nsx", "message": "…" } ]
  },
  "nsx": {
    "discovery": {
      "status": "detected|not-detected|unknown",
      "evidence": [ "vCenter extension com.vmware.nsx.management.nsxt registered (url https://nsx01…)" ],
      "managersDiscovered": [ "nsx01.example.local" ]
    }
  }
}
```

Fact `status` values: `ok`, `absent` (collected, object/setting does not exist),
`denied` (permission), `error` (collection failed), `unsupported` (API/version
does not expose it). Only `ok` and `absent` can yield `PASS`/`FAIL`.

## 2. Results (`results.json`) — consumed by the report and the local UI

```jsonc
{
  "schemaVersion": "2.0",
  "tool": { "name": "VSAT", "version": "2.0.0" },
  "run":  { /* copied from evidence.run */ },
  "generatedUtc": "…",
  "rulePack":  { "version": "2026.09.0", "profile": "standard|strict", "ruleCount": 140 },
  "advisory":  { "snapshotDate": "2026-09-23", "ageDays": 0 },
  "status": {
    "overall":  "complete|incomplete|failed|canceled",
    "label":    "INCOMPLETE: NSX NOT ASSESSED",
    "exitCode": 0,                       // 0 clean,1 findings,2 incomplete,3 fatal,4 canceled
    "reasons":  [ "NSX detected but no NSX Manager credentials were supplied" ]
  },
  "coverage": {
    "domains": [
      { "id": "vcenter|esxi|cluster|vm|network|nsx|storage",
        "name": "NSX", "mandatory": true,
        "state": "ASSESSED|PARTIAL|INCOMPLETE|UNKNOWN|NOT_APPLICABLE|REVIEW",
        "label": "INCOMPLETE: NSX NOT ASSESSED",
        "detail": "…", "evidence": ["…"], "missing": ["NSX Manager credentials"],
        "checks": { "total": 0, "PASS": 0, "FAIL": 0, "MANUAL": 0, "UNKNOWN": 0, "ERROR": 0, "NOT_APPLICABLE": 0 } }
    ],
    "automated": { "known": 812, "total": 900 }   // known = PASS+FAIL+NOT_APPLICABLE
  },
  "summary": {
    "results":    { "PASS": 0, "FAIL": 0, "MANUAL": 0, "UNKNOWN": 0, "ERROR": 0, "NOT_APPLICABLE": 0 },
    "severity":   { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },   // FAIL only
    "confidence": { "observed": 0, "inferred": 0 },
    "assets":     { "host": 0, "vm": 0, "…": 0 }
  },
  "findings": [
    {
      "id": "F-000123",
      "key": "ESXI-SVC-SSH|ep-vc01:host-12",          // stable across runs
      "ruleId": "ESXI-SVC-SSH", "ruleVersion": 1,
      "title": "SSH service is stopped and set to manual start",
      "domain": "esxi",
      "assetId": "ep-vc01:host-12", "assetName": "esx01", "assetType": "host",
      "result": "PASS|FAIL|MANUAL|NOT_APPLICABLE|UNKNOWN|ERROR",
      "severity": "critical|high|medium|low|info",
      "priority": { "score": 72, "reasons": ["high severity", "asset criticality high (operator)"] },
      "rationale": "…",
      "observed": "running=true, policy=on",
      "expected": "running=false, policy=off",
      "evidence": [ { "fact": "services", "status": "ok", "endpoint": "ep-vc01", "observedUtc": "…" } ],
      "frameworks": [ { "framework": "CIS VMware ESXi 8.0 Benchmark", "edition": "v1.4.0",
                        "control": "…", "mappingStatus": "verified|unverified" } ],
      "mitigation": { "summary": "…", "steps": ["…"], "validation": "…", "rollback": "…",
                      "workPackage": "WP-ESXI-SERVICES", "impact": "…", "maintenanceWindow": false },
      "limitations": "…",
      "confidence": "observed|inferred",
      "exception": null,  // or { owner, rationale, expires, active: true|false }
      "affectedWorkloads": [ "<assetId>" ]   // 2.6, ai-infra findings only: AI workload VMs the finding puts at risk
    }
  ],
  "assets": [ /* evidence assets WITHOUT raw facts, plus: "findingCounts": { "FAIL": 3 }, "worstSeverity": "high" */ ],
  "relationships": [ /* as evidence */ ],
  "analysis": {
    "attackPaths": [
      { "id": "AP-001", "source": "<assetId>", "sourceZone": "DMZ", "target": "<assetId>",
        "decision": "allow|deny|unknown", "confidence": "configuration-inferred",
        "hops": [ { "asset": "<assetId>", "via": "connects" } ],
        "rules": [ { "ruleAssetId": "<nsx-rule asset id>", "name": "…", "action": "ALLOW", "reason": "first match; source ANY" } ],
        "explanation": "…", "prerequisites": ["…"], "uncertainty": ["guest firewall not assessed"] }
    ],
    "privilegePaths": [ { "principal": "EXAMPLE\\ops", "role": "Admin", "object": "<assetId>", "propagate": true } ],
    "chokepoints": [ { "ruleAssetId": "…", "name": "…", "pathsInterrupted": 7 } ],
    "impact": [
      { "component": "<assetId>", "componentType": "host|datastore|pnic|vds|nsx-edge-cluster|nsx-t0",
        "affected": [ { "asset": "<vm id>", "effect": "outage|restart-expected|degraded|unknown", "reason": "…" } ],
        "redundancy": "none|redundant|unknown", "notes": ["physical redundancy unknown"] }
    ],
    "workPackages": [
      { "id": "WP-ESXI-SERVICES", "title": "…", "team": "Virtualization", "findingIds": ["F-…"],
        "assetIds": ["…"], "outcome": "…", "prerequisites": ["…"], "impact": "…",
        "maintenanceWindow": true, "rollback": "…", "validation": "…", "steps": ["…"], "maxSeverity": "high" }
    ],
    "aiWorkloads": [ { "assetId": "…", "name": "train01", "type": "kvm-vm", "role": "training|null", "roleSource": "operator|tag|null", "platform": "vmware|hyperv|kvm",
                       "accelerators": 1, "acceleratorKinds": ["hostdev-pci"], "findings": ["F-…"], "blastPaths": ["BR-…"] } ],   // 2.6: declared AI workloads and VMs with accelerators
    "workPackageCatalog": [ { "id": "WP-MGMT-ISOLATION", "title": "…", "team": "…" } ],  // every work package in the rule pack (2.3)
    "blastRadius": {   // 2.3: cross-platform security graph search, part of every run
      "bounds":   { "maxDepth": 8, "maxPaths": 500, "maxSources": 60, "maxNodes": 250000, "budgetMs": 20000, "truncated": false, "elapsedMs": 812,
                    "pathsFound": 70, "crownsReachable": 9 },           // counted across all completed searches, before the maxPaths selection
      "entries":  [ "<nodeId>" ],                                         // principals first, then representative VMs
      "nodes":    [ { "id": "ep-hv01:vm/5f..", "kind": "asset|principal|scope", "type": "hyperv-vm", "name": "vcsa01",
                      "platform": "vmware|nsx|hyperv|kvm|identity", "crown": true, "crownReason": "management plane (vcenter)" } ],
      "edges":    [ { "id": "E-3f9a1c2b…", "source": "…", "target": "…",
                      "kind": "admin-of|controls|embodies|network-allow|mgmt-reach|credential-exposure|member-of",
                      "confidence": "observed|configuration-inferred|correlated|operator-declared",
                      "cost": 1, "fixId": "revoke:ad:example\\vi-admins@ep-vc01:group-d1",
                      "evidence": [ { "assetId": "…", "fact": "permissions", "status": "ok" } ],
                      "findingKeys": [ "VC-ADMIN-USERS|ep-vc01:vc" ], "explanation": "EXAMPLE\\vi-admins holds Admin (propagating) on Datacenters",
                      "ports": [ 22, 16509 ],                             // mgmt-reach only: management listeners the hop relies on ([] = L2 adjacency, no port observed)
                      "attack": { "technique": "T1078.002", "name": "Valid Accounts: Domain Accounts", "mappingStatus": "proposed|verified" } } ],
                                                                          // attack is null for embodies; every edge reachable from any entry
      "paths":    [ { "id": "BR-001", "entry": "<nodeId>", "crown": "<nodeId>", "cost": 4, "hops": 4, "edgeIds": ["E-…"],
                      "platforms": ["identity","hyperv","vmware"], "confidence": "correlated", "criticality": "high",
                      "narrative": "EXAMPLE\\Domain Admins → admin of hv01 → controls vcsa01 → is (matched by IP) vc01" } ],
      "needsEvidence": [ { "id": "NE-001", "entry": "…", "crown": "…|null", "crowns": [], "cost": 1, "edgeIds": [], "gapAt": 2, "platforms": [],
                      "gap": { "kind", "source", "target", "missingFact", "assetId", "status": "denied|error|unsupported|missing|unknown" },
                      "narrative": "…", "explanation": "Collect <fact> on <asset> …" } ],   // never ranked; gap status unknown = NSX policy undecidable
      "fixPlan":  [ { "rank": 1, "fixId": "relocate:ep-hv01:vm/5f..", "title": "Move vCenter appliance vcsa01 off Hyper-V host hv01 …", "kind": "embodies",
                      "pathsBroken": 37, "cumulativeBroken": 37, "pathsTotal": 52, "weightBroken": 111, "pathIds": ["BR-…"],
                      "findingKeys": [], "workPackage": "WP-MGMT-ISOLATION", "note": null } ],
      "notes":    [ "AD group nesting not collected; principals are joined by exact normalized name only" ]
    },
    "changes": {       // 2.4: change timeline from the platforms' own logs (pure function of evidence; replay reproduces it)
      "windowStartUtc": "2026-09-09T00:00:00Z", "windowEndUtc": "…", "windowSource": "parameter|default",   // -EngagementStart, default 30 days back
      "entries": [ { "id": "C-4003315a", "utc": "…", "endpointId": "ep-vc01", "assetId": "ep-vc01:host-10", "assetName": "esx01",
                     "user": "EXAMPLE\\ops1", "category": "access|service|firewall|settings|vm|patch|login",
                     "action": "Task: Stop service (SSH)", "source": "vcenter-event|nsx-object|windows-event|file-mtime|package-log|wtmp" } ],
      "historyStartUtcByEndpoint": { "ep-vc01": "…" },    // oldest record each endpoint returned
      "gaps": [ { "endpointId", "reason" } ],             // history shorter than the window, log full or cleared, reads denied
      "sources": [ … ],                                   // per endpoint: which logs were read and their status
      "accountSessions": [ { "endpointId", "user", "count", "firstUtc", "lastUtc", "entryIds": [] } ],   // earlier sign-ins by the account VSAT used
      "summary": { "entries": 9, "changedChecks": 30, "changedPassing": 25 }
    },
    "ransomware": {   // 2.5: ransomware readiness, part of every run
      "declared": true, "backups": [ { "id": "…", "name": "backup01", "type": "vm" } ],
      "oneAccountReach": [ { "principal": "EXAMPLE\\vi-admins", "id": "ad:example\\vi-admins", "type": "group|user",
                             "hypervisors": 5, "total": 5, "platforms": ["vmware"], "hosts": ["esx01.example.local"] } ],   // worst first, max 50
      "hostTotal": 5, "unknownAdminHosts": 0,
      "taggedRules": { "ruleIds": ["ESXI-PATCH-ADV"], "counts": { "PASS": 0, "FAIL": 0, "MANUAL": 0, "UNKNOWN": 0, "ERROR": 0, "NOT_APPLICABLE": 0 } },
      "backupPaths": [ { "pathId": "BR-004", "backupId": "…", "backup": "backup01", "entryId": "…", "entry": "EXAMPLE\\j.doe",
                         "cost": 3, "hops": 3, "platforms": ["identity","vmware"], "narrative": "…" } ],   // blastRadius paths ending at a backup system
      "notes": []
    },
    "drift": null  // or { "baselineRunId", "baselineUtc", "counts": { "new":0,"resolved":0,"changed":0,"unassessed":0,"unchanged":0 },
                   //       "items": [ { "key", "ruleId", "assetId", "assetName", "change": "new|resolved|changed|unassessed", "before", "after" } ],
                   //       "assets": { "added": [], "removed": [] }, "nsxRules": { "added":0, "removed":0, "modified":0 } }
  },
  "rules": [ { "id", "title", "domain", "severity", "frameworks", "automated": true,   // rule files may also carry "ransomware": true (2.5 tag)
               "attack": { "mitigates": ["T1021.004"], "mitigation": "M1042", "status": "proposed|verified",
                           "none": "reason, when mitigates is empty" } } ],   // 2.3: IDs from data/attack/attack-catalog.json (pinned MITRE release)
  "collection": { /* copied from evidence.collection */ },
  "nsx": { /* copied from evidence.nsx */ }
}
```

Findings may carry `changedInWindow: ["C-…"]` (2.4): the change entries inside the engagement window that touched the
checked setting or service (or, when the entry does not name one, the rule's `changeCategory` on that asset). The result
itself is never changed by it. `manifest.json` next to the package carries `package { name, sha256, bytes }` and the
`receipt` code (`VSAT-XXXX-XXXX-XXXX-XXXX`, the first 80 bits of the package SHA-256 in Crockford base32); a replay
with `-Receipt` records `receiptVerification { expected, actual, match }` in the results.

`results.compliance` (2.7) holds the control matrix built from the crosswalk in `data/frameworks`
(`catalogs.json`: framework, edition, license, control IDs with VSAT paraphrases; `crosswalk.json`: `{ ruleId, framework,
control, relation: equivalent|subset|supports, status: verified|proposed|derived, basis, sourceRef, reviewer?, reviewedUtc? }`):

```jsonc
"compliance": {
  "states": ["not-satisfied","not-assessed","manual-open","excepted","partial","manual-signed-off","satisfied"],
  "note": "…",
  "frameworks": [ { "id": "nist-800-53r5", "name": "NIST SP 800-53 Rev. 5", "edition": "Revision 5", "publisher", "license", "note",
                    "importRequired": false, "verifiedMappings": 0, "unverifiedMappings": 349,
                    "mappingStatuses": { "verified": 0, "proposed": 349, "derived": 0 }, "rulesMapped": 201,
                    "source": { "package", "sha256" },                       // pinned source (DISA STIG only)
                    "states": { "verified": { "<state>": 0 }, "unverified": { "<state>": 33 } },
                    "controls": [ { "control": "AC-2", "paraphrase": "…", "rules": ["VC-ADMIN-USERS"], "assets": 27, "state": "not-satisfied",
                                    "mappingStatus": "verified|unverified", "mappingStatuses": ["proposed"],
                                    "counts": { "PASS":0,"FAIL":0,"MANUAL":0,"UNKNOWN":0,"ERROR":0,"NOT_APPLICABLE":0,
                                                "EXCEPTED":0,"SIGNED_OFF":0,"SIGNED_NOT_SATISFIED":0 } } ] } ],
  "signoffs":   [ { "findingKey", "ruleId", "asset", "assetName", "result", "reviewer", "decision", "evidenceRef", "dateUtc", "expires",
                    "state": "valid|expired|incomplete|orphan|conflict", "flags": [] } ],
  "exceptions": [ { "ruleId", "asset", "owner", "approver", "rationale", "compensatingControl", "ticket", "expires", "active",
                    "findings": 1, "failing": 1, "flags": ["unapproved|expired|no-expiry|orphan"] } ]
}
```

`rule.frameworks` / `finding.frameworks` entries now carry `frameworkId`, `relation` and `sourceRef`, and the crosswalk
rows; `mappingStatus` is `verified`, `proposed`, `derived` or `legacy-unverified` (1.x CIS and SCG ids). `finding.exception`
also carries `approver`, `compensatingControl` and `ticket`. Scope files may add `signoffs` and the extended exception
fields. Results from earlier versions have no `compliance`; replaying their evidence adds it.

## 3. Result semantics

| Result | Meaning |
|---|---|
| PASS | Required facts collected (`ok`/`absent`) and meet the profile expectation |
| FAIL | Required facts collected and violate the expectation (exceptions stay FAIL) |
| MANUAL | Control cannot be decided from automated evidence; operator review needed |
| NOT_APPLICABLE | Applicability conditions false with evidence (e.g. no iSCSI adapter) |
| UNKNOWN | Evidence missing: denied, unsupported, or required operator input absent |
| ERROR | Collector or evaluator failed |

Coverage state is computed per domain and never improved by UNKNOWN results.
An overall `complete` status requires every mandatory domain to be `ASSESSED`
or evidence-backed `NOT_APPLICABLE`.
