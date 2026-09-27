# Reviewing vsat.ps1 before it enters your network

This page is for the security team that approves VSAT for an isolated network. VSAT is **one file, `vsat.ps1`**: plain PowerShell, readable top to bottom, with no binaries and no encoded content.

## What to download

| File | Needed? | What it is |
|---|---|---|
| `vsat.ps1` | **Yes** | The whole tool: engine, rules, report and UI assets, all as readable text |
| `SHA256SUMS.txt` | **Yes** | SHA-256 of every release file. Check `vsat.ps1` against it before review and again after transfer |
| `VSAT-<version>-offline-builder.zip` | Only if the network has no PowerShell 7 / PowerCLI | Source, build script, pinned dependency list and SBOM. Its builder downloads PowerShell and PowerCLI from their vendors on a connected machine and produces a portable package |

For Hyper-V and KVM targets, `vsat.ps1` plus PowerShell 7.4+ is all you need. VMware targets also need PowerCLI.

## Verify the file

```powershell
(Get-FileHash .\vsat.ps1 -Algorithm SHA256).Hash   # compare with the vsat.ps1 line in SHA256SUMS.txt
```

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

## How the file is laid out

- **Header:** parameters and help (`Get-Help .\vsat.ps1 -Full`).
- **Code:** one section per source file, each marked `# ---- src/<name>.ps1 ----`, in the same order as the `src/` folder on GitHub.
- **Embedded resources:** the region `#region Embedded resources` holds the rules (`rules/*.json`), data files (`data/*.json`) and the report and UI (`assets/`) as plain-text here-strings. They are data. The code never executes them.

The file is generated from the repository by `build/Build-Vsat.ps1`, and the build is byte-reproducible: check out the release tag, run `pwsh ./build/Build-Vsat.ps1`, and the `vsat.ps1` it writes has the same SHA-256 as the released file. The offline builder ZIP contains the same sources if you review offline.

## What it does

- **Reads only.** vSphere through PowerCLI read cmdlets; NSX through REST `GET` calls on an allowlist (plus creating and closing the API session); Hyper-V through `Get-*` and CIM reads over PowerShell remoting; KVM through a read-only shell script over SSH (`virsh --readonly`). The allowlists are enforced by tests in `tests/ReadOnly.Tests.ps1`.
- **Connects only to the systems you name**, over HTTPS (vCenter, ESXi, NSX), WinRM (Hyper-V) or SSH (KVM). There is no internet access, telemetry, update check or download.
- **Opens a local web UI** on `127.0.0.1` on a random free port, protected by a per-run token. On Windows it opens the default browser with `Start-Process`. `-Cli` runs without the UI.
- **Compiles one small C# class** with `Add-Type` for per-endpoint TLS certificate pinning. Its source is in the `src/30-Transport.ps1` section. If application control blocks `Add-Type`, VSAT logs it and continues with normal operating-system certificate validation, without pinning.
- **Writes only to its output folder** (default `vsat-output/<timestamp>` under the current directory). It changes no registry keys, execution policy, PowerCLI configuration or profile, and installs nothing.
- **Handles credentials in memory only.** They are prompted, never accepted on the command line, and redacted from logs and outputs.

## What it does not contain

`Invoke-Expression`, `DownloadString`, `-EncodedCommand` and base64 blobs do not appear in `vsat.ps1`. A test (`tests/Quickstart.Tests.ps1`, "Reviewable single script") fails the build if they do. The single `FromBase64String` call decodes TLS certificates returned by NSX.

The full threat model is in [threat-model.md](threat-model.md), and the rights VSAT needs are in [privileges.md](privileges.md).
