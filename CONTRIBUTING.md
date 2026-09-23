# Contributing to VSAT

Thanks for helping. VSAT is in **alpha**, and the most valuable contributions right now are the ones that turn assumptions into verified facts.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). **Report security issues privately** as described in [SECURITY.md](SECURITY.md), never in public issues.

## Ways to contribute

- **Lab validation reports.** Run VSAT against a lab and report what worked, what was `UNKNOWN` and which privileges were missing (see below).
- **Rule requests and fixes.** Use the *Rule request* issue form. Include the vendor documentation reference. Do **not** paste proprietary benchmark text.
- **Bug reports.** Use the *Bug report* form, and attach a **redacted** evidence package (`-Redact`) where possible.
- **Code, tests and docs.** See the workflow below.

## Ground rules

1. **Never commit real infrastructure data.** Fixtures, screenshots and examples must use synthetic names (`example.local`, `example.com`) and documentation addresses (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, or RFC 1918 private ranges). No real hostnames, UUIDs, thumbprints, usernames or customer topology.
2. **Missing evidence is never a pass.** Every rule must produce `UNKNOWN` when its required facts are `denied`, `error` or `unsupported`. Reviewers reject rules that don't.
3. **Read-only.** Collectors must not call mutating cmdlets or APIs. New NSX endpoints must be added to the REST allowlist with a justification.
4. **No external runtime resources.** No CDNs, web fonts, telemetry or runtime downloads. UI and report assets are embedded.
5. **No proprietary benchmark text.** Reference control IDs and editions. Write rationale and mitigation in your own words. New CIS mappings start as `mappingStatus: "unverified"`.
6. **Honest claims.** Don't add "tested", "certified" or "compliant" language to docs without evidence.

## Development workflow

Requirements: PowerShell 7.4+ and Pester 5. PowerCLI is only needed for live collector work.

```powershell
git clone https://github.com/NextSecurity/VSAT.git
cd VSAT
pwsh -File build/Build-Vsat.ps1        # generates ./vsat.ps1 and docs/coverage.md
Invoke-Pester -Path tests               # all tests
.\vsat.ps1 -Demo                        # try it against the synthetic lab
```

- Edit sources under `src/`, `rules/`, `data/` and `assets/`. **Do not edit the generated root `vsat.ps1` by hand.** Rebuild it.
- The build must stay deterministic. Run it twice and compare hashes if you touch the build.
- Add or update Pester tests and fixtures for every behavior change. Rules need at least a PASS, FAIL and UNKNOWN (denied) fixture, and NOT_APPLICABLE where applicable.
- Hostile-content fixtures (script tags, formula prefixes, control characters in names) must keep passing.
- Update `CHANGELOG.md` under `[Unreleased]`.

### Rule files

Each rule in `rules/*.json` declares: `id`, `version`, `title`, `domain`, `severity`, the facts it requires, applicability, expected values per profile (`standard`, `strict`), `frameworks[]` (with `edition`, `control` and `mappingStatus`), mitigation (summary, steps, validation, rollback, work package) and limitations. See [docs/architecture/data-model.md](docs/architecture/data-model.md).

## Lab validation reports

Please include:

- vCenter, ESXi and NSX product versions and builds
- the role or privileges of the accounts used
- the `-Version` output and `-Doctor` output
- the coverage table from the report and any `UNKNOWN` or `ERROR` results that look wrong
- a **redacted** evidence package (`assessment.redacted.vsat.zip`), after you have reviewed it yourself

## Pull requests

- Keep PRs focused and fill in the PR template.
- CI must pass: tests, the build and the determinism check.
- For security-sensitive changes (local listener, import, REST allowlist, redaction, rendering), request a second reviewer.
- By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).

## Labels

Issues are labeled by `domain:*`, `severity:*`, `phase:WP1`–`phase:WP8` (the plan's work packages) and `type:*`. See [.github/labels.yml](.github/labels.yml).
