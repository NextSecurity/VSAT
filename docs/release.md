# Release process

## Versioning

VSAT versions four things separately. All four are recorded in `manifest.json`, `results.json` and `-Version` output.

| Item | Scheme | Example | Changes when |
|---|---|---|---|
| Tool | Plain SemVer (`X.Y.0` feature minors, `X.Y.Z` patches) | `2.3.0` | Any code change |
| Rule pack | `YYYY.MM.patch` | `2026.09.0` | Rules added or changed. Each rule also has its own `ruleVersion`. |
| Advisory snapshot | Snapshot date | `2026-09-23` | Advisory data refreshed. The age is shown in every report. |
| Evidence schema | `major.minor` | `2.0` | Evidence or results structure changes. Replay checks compatibility. |

Every release is a plain, final SemVer version: feature work lands in a new `X.Y.0` minor, fixes land in a `X.Y.Z` patch.

Data-only updates (rules or advisories) can never execute PowerShell. Code-bearing changes always require a new tool release. Old evidence stays replayable with the schema it was written with.

## Reproducible build

```powershell
pwsh -File build/Build-Vsat.ps1           # writes ./vsat.ps1 and docs/coverage.md
Invoke-Pester -Path tests                 # tests against source and generated script
```

The build is deterministic. It uses a fixed module order, normalized line endings and UTF-8 without BOM, and embeds no timestamps. Running it twice from the same commit must produce the same SHA-256. CI rebuilds and compares.

## Release checklist

Based on plan §14.

- [ ] Tag created from a clean, reviewed commit (`vX.Y.Z`). Artifacts are built only from the immutable tag.
- [ ] `build/Build-Vsat.ps1` output is reproducible (two builds give identical hashes)
- [ ] Pester suite passes against source **and** the generated `vsat.ps1`
- [ ] Single script `vsat.ps1` attached
- [ ] Offline builder: `build/New-OfflinePackage.ps1` with pinned versions and hashes, tested to produce a fully populated ZIP
- [ ] `CHANGELOG.md` updated (Added, Changed, Fixed, Security, Deprecated/Removed, Breaking)
- [ ] Migration notes updated ([migration-from-1x.md](migration-from-1x.md)) for any change in result semantics
- [ ] Supported versions table updated
- [ ] Benchmark coverage matrix (`docs/coverage.md`) regenerated; mapping status is accurate (`verified` only after the licensed document has been reviewed)
- [ ] Known limitations, minimum privileges and connectivity requirements reviewed
- [ ] `SHA256SUMS.txt` generated for all artifacts
- [ ] Source tag and commit recorded in the release notes
- [ ] Dependency lock (pinned runtime and module versions and hashes) published
- [ ] Release has exactly three files: `vsat.ps1`, `SHA256SUMS.txt`, `VSAT-<version>-offline-builder.zip` (SPDX SBOM and dependency lock inside the ZIP)
- [ ] `THIRD-PARTY-NOTICES.txt` complete
- [ ] Package manifest and provenance attached
- [ ] GitHub Pages demo regenerated from the same build

## Checksums

```powershell
Get-FileHash .\vsat.ps1, .\*.zip -Algorithm SHA256 |
  ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) } |
  Set-Content -Encoding utf8NoBOM SHA256SUMS.txt
```

Users verify with `Get-FileHash` (see [offline-package.md](offline-package.md)). A checksum proves only that you got the file listed in `SHA256SUMS.txt`. Get the sums from the GitHub release page over HTTPS.

## Signing policy

Releases are verified by SHA-256 checksums. If a code-signing identity is added to the release pipeline, the release notes name it and this document describes how to verify it.

## Release credentials

Release automation uses minimally scoped tokens, and only on tag builds. Users never need CI access to run an assessment.
