# Offline package

VSAT is designed for isolated (air-gapped) environments. The Windows offline package contains everything needed to run an assessment with **no internet access and nothing installed on the runner**.

## Why you build it yourself

We have **not confirmed redistribution rights** for the PowerShell runtime and the VMware PowerCLI modules inside a VSAT release. Until we have, releases do **not** include those binaries. Instead, `build/New-OfflinePackage.ps1` runs on a **connected** machine, downloads the dependencies from their official vendor sources, and produces the same fully populated ZIP that a release would contain. You then move the ZIP into the isolated environment.

A partially populated ZIP that would need downloads inside the isolated environment is treated as a build failure.

## Connected-side build flow

```mermaid
flowchart LR
  A[Connected machine] --> B[Download vsat.ps1 + SHA256SUMS.txt<br/>from GitHub Releases]
  B --> C[Verify vsat.ps1 SHA-256]
  C --> D[Run build/New-OfflinePackage.ps1]
  D --> E[Fetch pinned PowerShell 7.6.6 LTS x64 zip<br/>from the official GitHub release (SHA-256 verified)]
  D --> F[Save-Module pinned PowerCLI Core + Storage<br/>(13.5.1, from VCF.PowerCLI 9.1.1)]
  E --> G[Verify pinned hashes]
  F --> G
  G --> H[Assemble VSAT-2.0.0-win-x64-offline.zip<br/>+ package-manifest.json]
  H --> I[Transfer by approved media]
  I --> J[Isolated runner: verify hash, extract, .\VSAT.cmd]
```

1. On a connected machine with PowerShell 7.4+, download `VSAT-<version>-offline-builder.zip` and `SHA256SUMS.txt` from the release, verify the hash, extract, and run `pwsh ./build/New-OfflinePackage.ps1 -OutDir ./dist` (it verifies the pinned runtime hash and fails if PowerCLI modules are missing).
2. Verify `vsat.ps1`:
   ```powershell
   (Get-FileHash .\vsat.ps1 -Algorithm SHA256).Hash
   # compare with the line for vsat.ps1 in SHA256SUMS.txt
   ```
3. Build the package:
   ```powershell
   .\build\New-OfflinePackage.ps1 -OutputPath .\out
   ```
   The builder uses pinned versions and hashes recorded in the repository. If a downloaded file does not match its pinned hash, the builder stops. It does not continue with an unverified file.
4. Record the SHA-256 of the resulting ZIP (the builder prints it and writes it to `package-manifest.json`).
5. Move the ZIP into the isolated environment according to your media-transfer procedure. Verify the hash again on the other side.
6. Extract and launch with `.\VSAT.cmd`.

## What's inside

```text
VSAT-2.0.0-win-x64-offline/
├── VSAT.cmd                 # launcher: starts the bundled pwsh with vsat.ps1
├── vsat.ps1                 # the single application file (same as the release asset)
├── runtime/pwsh/            # portable PowerShell 7.x (x64)
├── modules/                 # pinned PowerCLI modules (Save-Module layout)
├── package-manifest.json    # component versions, sources, SHA-256 of every file
├── THIRD-PARTY-NOTICES.txt  # licenses/notices of bundled components
├── LICENSE
└── docs/                    # offline copy of the documentation
```

## How the package runs

- `VSAT.cmd` starts `runtime\pwsh\pwsh.exe` with `vsat.ps1`. It does **not** load user or machine profile scripts.
- VSAT prepends the package's `./modules` folder to `PSModulePath` **for its own process only** and imports modules explicitly. VSAT performs no `Install-Module` and no global or user-scope installation, and it makes no registry or profile changes.
- **Execution policy and application control are respected.** VSAT does not use `-ExecutionPolicy Bypass` to get around organizational policy. If your policy blocks unsigned scripts, VSAT reports this during the readiness check. Follow your organization's approval process, for example allow-listing by hash. Release artifacts are **not code-signed** in this alpha.
- VSAT never changes PowerCLI's persisted configuration, including `InvalidCertificateAction`. Pin untrusted endpoint certificates per endpoint with `-TrustedThumbprint "host=SHA256"`.
- Outputs are written under the package folder by default, or to `-OutputPath`, with restrictive permissions where supported.
- VSAT contacts nothing except the endpoints you specify: no telemetry, no update checks and no external web resources.

## Advisory data age

`data/advisories.json` is built into `vsat.ps1` as a dated snapshot. Every report shows the snapshot date and age. An isolated installation cannot know about advisories published after that date. To refresh, get a newer VSAT release (or, later, an integrity-verified data bundle) on the connected side. The isolated assessment never tries to update itself online.

## Checklist

- [ ] `vsat.ps1` hash matches `SHA256SUMS.txt`
- [ ] Builder completed without hash mismatches
- [ ] ZIP hash recorded before transfer and verified after transfer
- [ ] `.\VSAT.cmd -Doctor` reports the runtime and modules as ready on the isolated runner
