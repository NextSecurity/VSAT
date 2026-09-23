# Threat model

This document covers VSAT `2.0.0`. It maps each threat from the product plan (§11) to the control implemented in this release and to the test that checks it. **It is a design self-review.** No independent penetration test or security certification has been performed. Controls are verified with Pester fixtures, not in a live environment. The "Implemented control" column describes the security contract the engine implements. Where this document and the code under `src/` disagree, the code governs, and the discrepancy is a bug worth reporting.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| vCenter, ESXi and NSX credentials | Grant read access to the entire virtual infrastructure |
| Collected evidence and reports | A detailed map of infrastructure, weaknesses and topology |
| The runner process and local UI | Can use active sessions to vCenter and NSX |
| Release artifacts | A tampered `vsat.ps1` would run with those credentials |

**Untrusted inputs:** everything an endpoint returns, including asset names, tags, annotations, NSX object names and descriptions, certificate fields and error messages. Also imported evidence packages, scope files, browser requests to the local listener, and any other web page open in the operator's browser.

**Attacker profiles:** someone who can rename a VM or tag an object; a compromised or spoofed endpoint; a malicious website visited while VSAT runs; a person who obtains a report or evidence package; a supply-chain attacker who modifies a release or dependency.

## Threats and controls

| # | Threat | Implemented control | Verification (Pester fixtures) |
|---|---|---|---|
| T1 | A malicious asset name runs script in the report or UI | Data goes into the page as JSON in a non-executable `<script type="application/json">` block with `<` escaped. Rendering uses `textContent` and DOM APIs, never `innerHTML` with data. The report has a strict **Content Security Policy with SHA-256 hashes** for inline script and style (`default-src 'none'`, no `unsafe-inline`, no `unsafe-eval`). | Stored-XSS payloads in names and tags across HTML, JSON and CSV outputs |
| T2 | A website drives localhost actions (CSRF, DNS rebinding) | Listener binds to **127.0.0.1 only**. **Random per-run token** carried in the URL **fragment**, so it is never sent in request lines or logged. The **Host header must be the loopback address and port**. The **Origin must match**. State-changing requests must carry a **custom header**, which cross-origin forms cannot send without a preflight. **No CORS headers**, so preflights fail. | Cross-origin, missing token, wrong Host (rebinding) and missing header cases |
| T3 | The local API exposes credentials | Credentials stay as `PSCredential` in server-side memory. They are never returned to the browser, stored in browser storage or embedded in reports. **Log and output redaction** masks passwords, session tokens and `Authorization` headers. | Secret canary strings are checked in every output file and in the log |
| T4 | Arbitrary commands through the UI or imports | Fixed route table with typed request schemas. No `Invoke-Expression` or script blocks built from data. No filesystem-browsing routes. Output paths are validated. | Injection and path-traversal requests |
| T5 | An imported ZIP escapes its folder or exhausts the disk | **ZIP import limits:** maximum entry count, per-entry and total uncompressed size, and compression ratio. **Path validation** rejects absolute paths, `..`, drive letters and links. Only expected file names are read. JSON is parsed against the schema. | Traversal, zip-bomb and oversized-entry fixtures |
| T6 | An endpoint redirect steals credentials | **No redirects are followed when credentials are attached.** A redirect is an error. The endpoint identity is fixed to the scoped address. | Malicious redirect fixture |
| T7 | The audit changes the target configuration | vSphere is read through read cmdlets and views only. **NSX REST goes through a method and path allowlist:** GET on approved read paths, plus POST only for session create (`/api/session/create`) and destroy (`/api/session/destroy`). Anything else is refused before it reaches the network. No Traceflow or other active tests in this release. | Recorded-operation tests reject non-allowlisted calls |
| T8 | TLS interception or weakened validation | Normal certificate validation by default. An untrusted certificate can be accepted only through **per-endpoint pinning** (`-TrustedThumbprint "host=SHA256"`). **VSAT never changes the global or user PowerCLI certificate policy** (this 1.x defect has been removed). | Mismatched thumbprint fixture; check that PowerCLI config is unchanged |
| T9 | Collector errors produce false reassurance | Every fact carries a status (`ok`, `absent`, `denied`, `error`, `unsupported`). Only `ok` and `absent` can give PASS or FAIL. Mandatory domain coverage cannot be improved by `UNKNOWN`. Exit code `2` for incomplete runs. | Denied, empty, partial and failed API fixtures; NSX-detected-without-credentials fixture |
| T10 | A report or evidence leaks | Outputs get **restrictive permissions**: an owner-only ACL on Windows where supported. Sensitivity notice in outputs. `-Redact` creates a separate copy with consistent pseudonyms. No upload feature and no telemetry. | Redaction fixtures check that no original names or addresses remain |
| T11 | Spreadsheet or terminal injection | **CSV formula neutralization:** cells that begin with `=`, `+`, `-`, `@`, tab or CR get a leading `'`. Control characters are stripped from terminal output. | Hostile-name export fixtures |
| T12 | Excessive collection disrupts management | Conservative concurrency, timeouts, pagination and cancellation | Fixture-level only. **No throttling or large-inventory measurements yet.** |
| T13 | A fake release or dependency | SHA-256 checksums for releases. The offline builder verifies pinned hashes of downloaded dependencies. | Tampered-dependency fixture in the builder. **No code signing yet.** |

## Residual risks

These risks remain and are accepted or open in this alpha:

- **PowerShell cannot guarantee memory zeroization.** `SecureString` and `PSCredential` reduce exposure, but strings are copied during authentication, so secrets can remain in process memory until garbage collection. A memory dump of the runner could expose them. VSAT disconnects sessions on completion or cancellation to limit their lifetime.
- **Loopback is not an authentication boundary.** Other processes running as the same user on the runner can reach `127.0.0.1`. The per-run token reduces this risk but does not remove it. Run VSAT on a trusted, single-user runner.
- **The token is visible to the local browser.** Browser extensions or history-syncing features could observe the URL fragment.
- **Evidence integrity is not proof of truth.** `manifest.json` hashes detect accidental or later modification of outputs. They do not prove that the source systems reported truthfully, and they are not signatures.
- **No code signing.** Users must verify SHA-256 checksums obtained over a trusted channel.
- **Dependency trust.** The offline package relies on vendor downloads made on the connected side. Pinned hashes protect against changes after pinning, not against a compromised upstream at pinning time.
- **Performance impact is unmeasured.** Collection load on large vCenter or NSX deployments has not been measured.
- **Not validated live.** Every control above has been verified only against fixtures. Real endpoint behavior, such as unusual redirect patterns, API edge cases or permission shapes, may differ.
- **Output permissions** depend on the filesystem. Restrictive ACLs may not apply on network shares or non-NTFS volumes.

## Reporting

Report suspected vulnerabilities privately. See [SECURITY.md](../SECURITY.md).
