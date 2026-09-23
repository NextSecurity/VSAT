# Security policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through **GitHub Security Advisories**: go to the repository's **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/NextSecurity/VSAT/security/advisories/new)).

Please include:

- the affected version (`.\vsat.ps1 -Version`) or commit,
- a description of the issue and its impact,
- reproduction steps or a proof of concept using **synthetic data only**,
- any suggested fix.

Do not send real credentials, evidence packages or reports from production environments. If an evidence file is needed, create it from the `-Demo` lab or use a `-Redact` copy you have reviewed.

## What to expect

This is a small, volunteer-maintained project, so we cannot guarantee response times. We aim to:

- acknowledge the report within 7 days,
- agree on a severity assessment and a fix or disclosure timeline with you,
- credit you in the advisory and changelog unless you prefer otherwise.

We follow coordinated disclosure. Please give us reasonable time to release a fix before you publish details.

## Scope

**In scope:**

- `vsat.ps1` (the generated application) and its sources under `src/`, `rules/`, `data/` and `assets/`
- the local UI listener (loopback binding, token, Host/Origin/CSRF checks)
- report and UI rendering (XSS, CSP bypass), CSV/terminal injection
- evidence import (`-Replay`, `-Baseline`): ZIP traversal, decompression bombs, schema bypass
- secret handling: credentials or tokens appearing in logs, outputs or the browser
- any path where VSAT **modifies** target infrastructure, bypasses the NSX REST allowlist or weakens TLS validation
- `build/Build-Vsat.ps1` and `build/New-OfflinePackage.ps1` (for example hash-pinning bypass)
- the GitHub Pages site under `site/`

**Out of scope:**

- vulnerabilities in VMware/Broadcom products, PowerShell or PowerCLI themselves (report those to the vendor)
- findings VSAT reports about *your* environment
- the documented residual risks in [docs/threat-model.md](docs/threat-model.md#residual-risks), such as PowerShell memory zeroization limits, unless you show a practical bypass beyond what is documented
- social engineering, and attacks that require an already compromised runner account

## No public scan service

VSAT is a local tool. There is **no hosted scanning service, upload endpoint or telemetry**. The GitHub Pages site is static documentation with a synthetic demo. Never upload assessment data anywhere on our behalf. Nobody from this project will ask you for your reports or credentials.

## Supported versions

| Version | Security fixes |
|---|---|
| 2.0.x prereleases (latest only) | Yes |
| 1.x (`legacy/vsat-1.x.ps1`) | No. It is preserved for reference only and has known defects (see [CHANGELOG.md](CHANGELOG.md)). |

## Verifying releases

Releases are **not code-signed** yet. Verify artifacts against `SHA256SUMS.txt` from the GitHub release page (see [docs/offline-package.md](docs/offline-package.md)).
