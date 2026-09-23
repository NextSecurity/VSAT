# Release process

## Versioning

VSAT versions four things separately. All four are recorded in `manifest.json`, `results.json` and `-Version` output.

| Item | Scheme | Example | Changes when |
|---|---|---|---|
| Tool | SemVer with prerelease tags | `2.0.0-alpha.1` | Any code change |
| Rule pack | `YYYY.MM.patch` | `2026.09.0` | Rules added or changed. Each rule also has its own `ruleVersion`. |
| Advisory snapshot | Snapshot date | `2026-09-23` | Advisory data refreshed. The age is shown in every report. |
| Evidence schema | `major.minor` | `2.0` | Evidence or results structure changes. Replay checks compatibility. |

Planned progression: `2.0.0-alpha.N` → `2.0.0-beta.N` → `2.0.0-rc.N` → `2.0.0`. A prerelease is published whenever a gate from the plan cannot be met yet, and it states which gates are open.

Data-only updates (rules or advisories) can never execute PowerShell. Code-bearing changes always require a new tool release. Old evidence stays replayable with the schema it was written with.

## Reproducible build

```powershell
pwsh -File build/Build-Vsat.ps1           # writes ./vsat.ps1 and docs/coverage.md
Invoke-Pester -Path tests                 # tests against source and generated script
```

The build is deterministic. It uses a fixed module order, normalized line endings and UTF-8 without BOM, and embeds no timestamps. Running it twice from the same commit must produce the same SHA-256. CI rebuilds and compares.

## Release checklist

Based on plan §14.

- [ ] Tag created from a clean, reviewed commit (`vX.Y.Z[-pre]`). Artifacts are built only from the immutable tag.
- [ ] `build/Build-Vsat.ps1` output is reproducible (two builds give identical hashes)
- [ ] Pester suite passes against source **and** the generated `vsat.ps1`
- [ ] Single script `vsat.ps1` attached
- [ ] Offline package: either attached (only once redistribution rights are confirmed) **or** `build/New-OfflinePackage.ps1` with pinned versions and hashes, tested to produce a fully populated ZIP
- [ ] `CHANGELOG.md` updated (Added, Changed, Fixed, Security, Deprecated/Removed, Breaking)
- [ ] Migration notes updated ([migration-from-1x.md](migration-from-1x.md)) for any change in result semantics
- [ ] Compatibility matrix updated. "Tested" lists **only** builds verified in a live lab.
- [ ] Benchmark coverage matrix (`docs/coverage.md`) regenerated; mapping status is accurate (`verified` only after the licensed document has been reviewed)
- [ ] Known limitations, minimum privileges and connectivity requirements reviewed
- [ ] `SHA256SUMS.txt` generated for all artifacts
- [ ] Source tag and commit recorded in the release notes
- [ ] Dependency lock (pinned runtime and module versions and hashes) published
- [ ] SBOM generated (CycloneDX or SPDX) for the script's embedded assets and the offline package components
- [ ] `THIRD-PARTY-NOTICES.txt` complete
- [ ] Package manifest and provenance attached
- [ ] Signatures: **only if a trusted signing identity exists**. Checksums and signatures are described separately in the notes. No signing certificate exists as of `2.0.0-alpha.1`.
- [ ] Sample sanitized report and evidence package from the synthetic demo lab (`example.local`, RFC 5737/1918 only)
- [ ] GitHub Pages demo regenerated from the same build
- [ ] Release marked **prerelease** for alpha, beta and rc

## Checksums

```powershell
Get-FileHash .\vsat.ps1, .\*.zip -Algorithm SHA256 |
  ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) } |
  Set-Content -Encoding utf8NoBOM SHA256SUMS.txt
```

Users verify with `Get-FileHash` (see [offline-package.md](offline-package.md)). A checksum proves only that you got the file listed in `SHA256SUMS.txt`. Get the sums from the GitHub release page over HTTPS.

## Signing policy

VSAT does not claim signed artifacts until a trusted code-signing identity exists and has been used in the release pipeline. When one is added, release notes will name the identity, and this document will describe how to verify it. Until then, releases are **unsigned**, and execution-policy environments must allow-list them by hash through your organization's process.

## Release credentials

Release automation uses minimally scoped tokens, and only on tag builds. Users never need CI access to run an assessment.
