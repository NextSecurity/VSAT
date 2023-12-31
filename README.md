# 🕵🏻‍🔐✅ VSAT - Virtualization Security Audit Tool


> Virtualization Security Audit Tool assess the compliance of a VMware vSphere virtualization environment against CIS Benchmark.

## Requirements
* [VMware PowerCLI](https://developer.vmware.com/web/tool/vmware-powercli) 12.0.0 or higher
* VMware vSphere 6.5, 6.7, 7.0, 8.0
* Read access to the vCenter or ESXi host

## Usage

1. Clone the repo and navigate to the folder: 
```bash
git clone https://github.com/NextSecurity/VSAT.git
cd VSAT
```
2. Install [VMware PowerCLI](https://developer.vmware.com/web/tool/vmware-powercli):
```powershell
Install-Module -Name VMware.PowerCLI -Scope CurrentUser -Force
```
3. Run the script :
```powershell
.\vsat.ps1
```

## Roadmap

* Automatically update `patches.json` file with the latest patches for your environment
* Add support for all major virtualization solutions:
  * Microsoft Hyper-V
  * Citrix Hypervisor
  * KVM (Kernel-based Virtual Machine)
  * Proxmox Virtual Environment
  * Red Hat Virtualization
  * Nutanix AHV
  * Xen Project

## License

[MIT](https://choosealicense.com/licenses/mit/)
