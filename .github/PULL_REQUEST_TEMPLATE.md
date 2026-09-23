## Summary

<!-- What does this change and why? Link issues: Fixes #123 -->

## Type

- [ ] Bug fix
- [ ] New/changed rule
- [ ] Collector
- [ ] Analysis / report / UI
- [ ] Packaging / build
- [ ] Documentation / site
- [ ] Security hardening

## Checklist

- [ ] Sources edited under `src/`, `rules/`, `data/` or `assets/`, not the generated root `vsat.ps1`
- [ ] `pwsh -File build/Build-Vsat.ps1` runs, and the output is deterministic
- [ ] `Invoke-Pester -Path tests` passes
- [ ] New or changed rules have PASS, FAIL and UNKNOWN (denied) fixtures, plus NOT_APPLICABLE where relevant
- [ ] Missing, denied or unsupported evidence cannot produce `PASS`
- [ ] No mutating cmdlet or API call added; any new NSX path is added to the allowlist with a justification
- [ ] No external runtime resources (CDN, fonts, telemetry)
- [ ] Only synthetic data in fixtures, docs and screenshots (`example.local`, RFC 5737/1918)
- [ ] No proprietary benchmark text; new CIS mappings are `unverified`
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Docs updated (usage, limitations, privileges) if behavior changed

## Security impact

<!-- Does this touch the local listener, import, redaction, rendering, REST allowlist, TLS handling or secrets? Describe how it was tested. -->

## Validation

<!-- Fixtures only, or tested against a lab? If a lab: product versions/builds (no real names). -->
