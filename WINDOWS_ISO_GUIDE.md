# Windows ISO Clarification

## What Your Dad Installed

Your dad said he selected "Windows 10" but it installed "Windows 11 OEM". Here's what likely happened:

### The Problem
- The old filenames were ambiguous (e.g., "Windows 10 Pro 22H2 (Stock OEM)")
- Both Windows 10 and Windows 11 download as "Win10_*.iso" or "Win11_*.iso" from Fido
- In Ventoy's boot menu, they might have looked similar

### The Fix
All Windows ISOs now have clear numbered names:

**01 - OS - Windows 11 Pro 24H2 (Stock - Requires TPM)**
- What it is: Official Windows 11 Professional (Stock OEM)
- Downloads: ONE ISO (stock only)
- Requirements: TPM 2.0, SecureBoot, 4GB+ RAM
- Use this for: Modern PCs that meet Win11 requirements
- This is what your dad should have seen separately!

**02 - OS - Windows 11 Pro 24H2 (Modded - No TPM Required)**
- What it is: Official Windows 11 Pro + modified version with bypasses
- Downloads: TWO ISOs (stock + modded)
- Modded version: Bypasses TPM 2.0, SecureBoot, RAM requirements
- Use this for: Old PCs that don't meet Win11 requirements

**03 - OS - Windows 10 Pro 22H2 (Official)**
- What it is: Official Windows 10 Professional Edition
- Edition: Pro (NOT Home, NOT Enterprise)
- Requirements: No TPM needed (Win10 doesn't require it)
- Use this for: Clean Windows 10 installs on any PC

**04 - OS - Windows 11 Enterprise LTSC 2024**
- What it is: Official Windows 11 Enterprise LTSC (Long Term Servicing Channel)
- Edition: Enterprise LTSC (NOT Pro, NOT Home)
- Requirements: Relaxed (LTSC has less strict requirements than regular Win11)
- Use this for: Business/enterprise deployments, minimal updates

**05 - OS - Tiny11 (Lightweight Win11)**
- What it is: Stripped-down Windows 11 (community mod)
- Requirements: Much lower than stock Win11 (works on old PCs)
- Use this for: Very old hardware or minimal installations

### What Fido Downloads

The script uses Fido.ps1 to download Windows ISOs directly from Microsoft:

- Windows 10: `fido.ps1 -Win 10 -Ed Pro -Lang English -Arch x64`
- Windows 11: `fido.ps1 -Win 11 -Ed Pro -Lang English -Arch x64`

Both download the **Professional (Pro)** edition, not Home or Enterprise.

### File Naming in Ventoy

After download, files are named:
- `01_OS_Windows_11_Pro_24H2_Modded.iso`
- `01_OS_Windows_11_Pro_24H2_Stock.iso`
- `02_OS_Windows_10_Pro_22H2_Official.iso`
- `03_OS_Windows_11_Enterprise_LTSC_2024.iso`

The numbers ensure they appear in order in Ventoy's boot menu.

### All ISO Categories

### Windows (01-05)
01. Windows 11 Pro Stock (requires TPM) - For modern PCs
02. Windows 11 Pro Modded (no TPM) - For old PCs without TPM
03. Windows 10 Pro Official - Standard Win10
04. Windows 11 Enterprise LTSC - Long-term support version
05. Tiny11 - Lightweight Win11 (low requirements)

### Linux (06-09)
06. Kali Linux - Penetration testing tools
07. Linux Mint - Beginner-friendly Linux
08. Fedora Workstation - Cutting-edge Linux
09. Tails - Privacy/anonymous browsing

### Tools (10-14)
10. GParted - Partition management
11. Hiren's BootCD PE - Recovery toolkit
12. Clonezilla - Disk cloning/imaging
13. Rescuezilla - Easy backup/restore
14. Memtest86+ - RAM testing

