# VSAT 2.0 data model (schema 2.0)

VSAT separates **evidence** (what was collected) from **results** (what the rule
engine concluded). Both are JSON, UTF-8, camelCase. All identifiers are stable
and namespaced by endpoint; names and IP addresses are never used as identity.

## 1. Evidence (`evidence.json`)

```jsonc
{
  "schemaVersion": "2.0",
  "tool":  { "name": "VSAT", "version": "2.0.0-alpha.1" },
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
    "nsxDeclaredAbsent": false
  },
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
  "tool": { "name": "VSAT", "version": "2.0.0-alpha.1" },
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
      "exception": null   // or { owner, rationale, expires, active: true|false }
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
    "drift": null  // or { "baselineRunId", "baselineUtc", "counts": { "new":0,"resolved":0,"changed":0,"unassessed":0,"unchanged":0 },
                   //       "items": [ { "key", "ruleId", "assetId", "assetName", "change": "new|resolved|changed|unassessed", "before", "after" } ],
                   //       "assets": { "added": [], "removed": [] }, "nsxRules": { "added":0, "removed":0, "modified":0 } }
  },
  "rules": [ { "id", "title", "domain", "severity", "frameworks", "automated": true } ],
  "collection": { /* copied from evidence.collection */ },
  "nsx": { /* copied from evidence.nsx */ }
}
```

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
