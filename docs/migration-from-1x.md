# Migrating from VSAT 1.x

VSAT 2.0 is a rewrite. The 1.x script is preserved unchanged at [`legacy/vsat-1.x.ps1`](../legacy/vsat-1.x.ps1), and its patch list is at [`legacy/patches-1.x.json`](../legacy/patches-1.x.json). Results from 1.x and 2.0 are **not directly comparable**. Expect different counts, and expect some checks that 1.x reported as passes to show as `UNKNOWN` in 2.0.

## What changes for operators

| Topic | 1.x | 2.0 |
|---|---|---|
| Runtime | PowerShell with PowerCLI installed via `Install-Module` | PowerShell 7.4+. The offline package loads PowerCLI process-locally from `./modules`. |
| Start | `.\vsat.ps1`, console prompts | `.\VSAT.cmd` or `.\vsat.ps1` (guided browser UI), or `-Cli` |
| Scope | Single connection | Multiple vCenter/ESXi endpoints, **mandatory NSX step**, credential-free scope file |
| Output | Colored console text and `vsat.log` next to the script | `report.html`, JSON, CSV, `collection.log`, `manifest.json`, evidence package |
| Exit code | Not meaningful | `0`/`1`/`2`/`3`/`4` (see [usage.md](usage.md#exit-codes)) |
| Certificate handling | Ran `Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction warn`, **persistently changing your PowerCLI settings** | Never changes PowerCLI configuration. Pin per endpoint with `-TrustedThumbprint`. |
| Patches | Static ESXi 7.0.3 VIB list in `vmware/patches.json` | Dated advisory snapshot with build ranges |

> **Cleanup tip:** 1.x left `InvalidCertificateAction` set to `Warn` at user scope. Inspect it with `Get-PowerCLIConfiguration -Scope User`. If you did not intend that setting, restore your preferred value with `Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction <Fail|Prompt|Unset> -Confirm:$false`. VSAT 2.0 will not change it for you.

## Result semantics

1.x counted each check as passed, failed or unknown and printed a console summary. 2.0 uses six result states and records a collection status for every fact (`ok`, `absent`, `denied`, `error`, `unsupported`). Only `ok` and `absent` evidence can produce `PASS` or `FAIL`.

| Situation | 1.x behavior | 2.0 result |
|---|---|---|
| Check has nothing to iterate (no hosts, no port groups) | Often a pass, because the loop ran zero times | `NOT_APPLICABLE` if evidence shows the object type is absent; `UNKNOWN` if access was denied or the result is otherwise unexplained; `ERROR` on collector failure |
| Access denied to a property | Error text or silent pass | `UNKNOWN`, naming the missing privilege, and the domain's coverage drops to `PARTIAL` or `INCOMPLETE` |
| ESXi patch level | `FAIL` unless installed VIBs exactly matched the 7.0.3 list | Build compared with advisory ranges. `UNKNOWN` if the build is not in the snapshot. |
| Lockdown mode | Compared the boolean `adminDisabled` with the strings `Normal`/`Strict`. It could not tell the modes apart, and PowerShell type coercion made the comparison misleading. | Reads `HostConfigInfo.lockdownMode`. `standard` expects `lockdownNormal` or `lockdownStrict`; `strict` may require `lockdownStrict`. |
| VDS security policy | Passed when the switch or policy object existed | Effective policy evaluated for **each port group**, including overrides |
| Native VLAN | Assumed VLAN 1 | `UNKNOWN` unless you supply `nativeVlans` in the scope file |
| Manual controls | 18 placeholder functions that printed text | `MANUAL`, counted explicitly, never merged into passes |
| Framework mapping | CIS number in the check name | Separate `frameworks[]` with edition and `mappingStatus` (`unverified` in this alpha) |
| Exceptions | None | Scoped exceptions (owner, rationale, expiry). The finding stays `FAIL`. |
| NSX | Not assessed | Mandatory domain. If NSX is detected but not assessed, the run is `INCOMPLETE: NSX NOT ASSESSED` (exit `2`). |

## Mapping 1.x checks to 2.0 rules

Most 1.x `Ensure-*` functions correspond to one 2.0 rule ID. The generated coverage matrix (`docs/coverage.md`, produced at build time) lists every rule, its automation status and its framework references. Where one technical check mapped to several CIS items in 1.x, 2.0 runs it once and lists all mappings.

## Automation and CI consumers

- Parse `results.json` (schema `2.0`) instead of console text. See [architecture/data-model.md](architecture/data-model.md).
- Use `findings[].key` (`ruleId|assetId`), which is stable across runs, to track findings over time. Or use `-Baseline` for built-in drift.
- Treat exit code `2` as "do not trust as complete".
