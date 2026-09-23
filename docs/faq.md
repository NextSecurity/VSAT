# FAQ

### Is VSAT production-ready?

No. `2.0.0-alpha.1` is a limited prerelease that has not been validated against a live vCenter, ESXi or NSX lab. Use it to evaluate the workflow, try the demo and help validate it. Review every result. See [limitations.md](limitations.md).

### Does VSAT change anything in my environment?

No. It reads only. vSphere access uses read cmdlets. NSX calls go through an enforced allowlist: GET requests only, apart from creating and destroying the API session. VSAT writes mitigation guidance but never applies it. It also does not change your PowerCLI configuration, unlike 1.x.

### Will a clean VSAT run make me CIS compliant?

No. VSAT is not certified by or affiliated with CIS, VMware or Broadcom. CIS mappings are `unverified` in this alpha, some controls are `MANUAL`, and a clean run is not evidence of compliance.

### Why is NSX mandatory? We don't use NSX.

Because an assessment that silently skips the network security layer can look clean when it isn't. If you don't run NSX, pass `-NsxDeclaredAbsent` or confirm it in the NSX step. VSAT records your declaration together with the discovery evidence, for example that no NSX extension is registered in vCenter. NSX shows as `NOT_APPLICABLE: NSX NOT DEPLOYED` when the evidence supports it, and as `REVIEW` otherwise. Neither is an NSX pass.

### Why does my run exit with code 2?

A mandatory domain is `INCOMPLETE` or `UNKNOWN`. The most common reason is `INCOMPLETE: NSX NOT ASSESSED`: NSX was detected, but no NSX credentials were supplied or they lacked rights. The report's coverage panel lists exactly what is missing.

### Why do I see so many UNKNOWN results?

`UNKNOWN` means VSAT could not get the evidence. The permission may be missing, the API may not expose the setting on that version, or operator input (such as the native VLAN) was not supplied. 1.x often reported these cases as passes. See [privileges.md](privileges.md) and the scope file section in [usage.md](usage.md#scope-file).

### Can I run it without internet access?

Yes, that's the main design goal. Build the offline package on a connected machine ([offline-package.md](offline-package.md)), transfer it and run `VSAT.cmd`. VSAT needs no internet during the audit, while viewing reports or during replay.

### Why isn't the offline ZIP just attached to the release?

We haven't confirmed that we may redistribute PowerShell and PowerCLI inside our package. The connected-side builder downloads them from official sources and produces the same ZIP.

### Is it signed?

Not yet. There is no code-signing certificate. Verify the SHA-256 checksums. We will not claim signing until a trusted identity exists.

### Does it work on Linux or macOS?

It is not supported or validated there. The first target is Windows x64 with PowerShell 7.4+.

### Which vSphere and NSX versions are supported?

Targets: vSphere 8.x and 9.x (modern) and 7.x (legacy), and modern NSX. **Tested against real products: none yet** (protocol-level integration tests run against the vcsim simulator and a mock NSX API). The compatibility table will list exact builds once live validation happens.

### Can I share a report with a vendor or consultant?

Use `-Redact`. It writes `report.redacted.html` and `assessment.redacted.vsat.zip` with consistent pseudonyms, so relationships stay intact while names and addresses are hidden. Review the redacted copy before sharing. The originals are unchanged.

### Does the GitHub Pages site scan anything or collect data?

No. The site is static documentation with a synthetic demo report. VSAT has no upload feature, public scan service or telemetry.

### How do I compare with last month?

```powershell
.\vsat.ps1 -Baseline .\2026-08\assessment.vsat.zip
```

### Is VSAT only for VMware?

No. VSAT is the *Virtualization Security Audit Tool*. 2.0 covers VMware vSphere and NSX. **Microsoft Hyper-V (2.1)** and **KVM/libvirt (2.2)** are planned next, and they will use the same evidence model and report. They are not available yet. See the Roadmap in the [README](../README.md#roadmap).

### What about Xen, Nutanix, Proxmox or Citrix?

They are not on the current roadmap. The 1.x roadmap listed them, but none were implemented.
