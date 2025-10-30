# brando's toolkit

a clean no‑nonsense flash drive installer packed with installers, tools, utilities, and scripts in a nice all‑in‑one automated package.

## quick start

### option 1: one-line command (powershell as admin)
```powershell
iex (irm 'https://brando.tools/run')
```

### option 2: download and run
1. download `RUN_ME.bat` from here [this repo](https://github.com/brand-o/tools/raw/refs/heads/main/RUN_ME.bat) (right click > save link as RUN_ME.bat)
2. run it (will prompt for admin privileges)
3. if needed to allow scripts use:   Set-ExecutionPolicy Bypass -Scope Process -Force

## what it does
the powershell script automates everything:

1. **auto-detects** all connected flash drives
2. **select** your target drive from the list
3. **formats & partitions** the drive automatically (with confirmation)
4. **downloads** 68+ tools, isos, drivers, and scripts from original or reliable sources
5. **verifies hashes** (sha-256) where available for security
6. **organizes** everything into a clean three-partition structure
7. **makes bootable via ventoy** — ready to use as your ultimate tech toolkit

## requirements
- **Windows** (requires PowerShell + administrator privileges)
- **fast 64gb+ USB flash drive** (256-512gb+ recommended)
- **internet connection** for downloads
- **~30-90 minutes** depending on drive speed and internet connection

## partition layout

the script creates three partitions on your drive:

### 1. ventoy (uefi secure boot compatible)
- **size:** 55gb (small drives) or 70gb (large drives ≥100gb)
- **contents:** all bootable ISOs for multi-boot capability

### 2. utils (tools & installers)
- **size:** 3gb (small drives) or 20gb (large drives ≥100gb)
- **contents:** portable apps, installers, drivers, scripts

### 3. backup (remaining space)
- **size:** all remaining drive space
- **contents:** your personal files, backups, documents

### resume capability
if the script is interrupted, it will detect partial installs and offer to:
- resume from where it left off
- or reformat and start over

## included software

### operating system isos (14 total)

**windows**
- Windows 11 Pro 24H2 (OEM)
- Windows 11 Pro 24H2 (OEM + modded)
    - TPM 2.0 bypass
    - Secure Boot bypass
    - RAM requirement bypass
    - Product key skip
    - English (World) locale (to avoid bloatware install)
    - Telemetry disabled
    - BitLocker auto-encryption disabled
    - Privacy questions skipped
    - Local account allowed (no Microsoft Account required)
- Windows 10 Pro 22H2 (OEM)
- Windows 11 Enterprise LTSC 2024 (OEM)
- Windows 10 Enterprise LTSC 2021 (OEM)
- Tiny11 (lightweight Windows 11)
- Live11 (live Windows 11 environment)

**linux distributions**
- Linux Mint 22.2 Cinnamon
- Fedora Workstation 42
- Kali Linux 2025.3
- Tails 7.1

**recovery & diagnostic tools**
- Hiren's Boot PE
- GParted Live 1.7.0-8
- Rescuezilla
- Clonezilla 3.3.0-33
- MemTest86+ 7.20
- Macrium Reflect Free v8

### portable applications (42 total)

**system utilities**
- 7-Zip 25.01
- Rufus
- Balena Etcher
- CPU-Z 2.17
- HWiNFO
- CrystalDiskInfo 9.5
- CrystalDiskMark 8.0.5
- NirSoft Suite (100+ utilities)
- Sysinternals Suite
- DDU v18.1.3.7
- CRU 1.5.2
- Everything 1.4.1
- TreeSize Free
- WinDirStat 1.1.2
- ImDisk Toolkit
- Process Hacker 2.39
- Speccy

**productivity & office**
- Notepad++ (latest)
- PDFsam Basic
- VLC Media Player 3.0.21

**network & security tools**
- PuTTY
- FileZilla
- WinSCP 6.4.2
- Nmap 7.98
- Angry IP Scanner
- Advanced Port Scanner 2.5
- WinMTR 0.92
- Wireshark 4.6.0
- KeePassXC

**download & torrent**
- qBittorrent 5.1.1

**password cracking & recovery** (require consent)
- John the Ripper 1.9.0
- Hashcat

**data recovery**
- TestDisk & PhotoRec 7.1
- Recuva

**development & editors**
- HxD (hex editor)

### installer applications (32 total)

**essential software**
- 7-Zip 25.01
- Git for Windows
- Bulk Crap Uninstaller
- Revo Uninstaller Free
- Rufus

**productivity & office suites**
- LibreOffice 25.8.2
- ONLYOFFICE Desktop Editors
- Microsoft Office Deployment Tool

**internet & communication**
- Mozilla Firefox
- Brave Browser
- Discord
- ProtonVPN 4.3.5

**media & entertainment**
- VLC Media Player 3.0.21
- qBittorrent 5.1.2
- Steam

**development tools**
- VS Code
- Node.js LTS 22.21.0
- Python 3.13.1

**system tools**
- HWiNFO64
- Android Platform Tools (ADB & Fastboot)
- VirtualBox 7.1.4
- Wireshark 4.6.0
- FileZilla

**remote access**
- TeamViewer
- AnyDesk

**gpu software** (manual download required)
- NVIDIA App
- AMD Software Adrenalin Edition

### drivers (12 total)

**storage drivers**
- Intel RST (Rapid Storage Technology)
- AMD NVMe Driver (manual)

**networking drivers**
- Intel Wi-Fi 6E/7 Driver 23.160.0
- Realtek Wi-Fi Driver (manual)
- Intel 2.5GbE Ethernet Driver 30.5
- Realtek 2.5GbE Driver (manual)

**bluetooth drivers**
- Intel Bluetooth Driver 23.160.0
- Realtek Bluetooth Driver (manual)

**chipset drivers**
- AMD Chipset Software (manual)

**driver installers**
- Snappy Driver Installer Origin
- Basic Driver Pack (torrent)

### browser extensions
- uBlock Origin (Firefox)

### helper scripts
- ChrisTitusTech Windows Utility
- Activate.cmd (Massgravel Microsoft Activation Scripts)
- Fido.ps1 (Windows ISO downloader)
- Get-Win11.cmd (integrated TPM bypass automation)

## special features

### windows 11 modded iso (automatic creation)
the script automatically creates a modified Windows 11 ISO with:
- TPM 2.0 bypass
- Secure Boot bypass
- RAM requirement bypass
- product key skip
- English (World) locale
- telemetry disabled
- BitLocker auto-encryption disabled
- privacy questions skipped
- local account allowed (no Microsoft Account required)

### hash verification
SHA-256 integrity checking (soft mode - warns but continues on mismatch)

### resume support
detects existing files and skips re-downloading

### portable focus
most applications are portable, requiring no installation

## license
this project is foss (free and open source software) — licensed under the GPL v3 License

## credits
we love foss. this project builds upon the incredible work of:
- [7-Zip](https://www.7-zip.org/)
- [Angry IP Scanner](https://angryip.org/)
- [Balena Etcher](https://github.com/balena-io/etcher)
- [ChrisTitusTech](https://github.com/ChrisTitusTech)
- [Clonezilla](https://clonezilla.org/)
- [Fedora](https://fedoraproject.org/)
- [FileZilla](https://filezilla-project.org/)
- [Git for Windows](https://gitforwindows.org/)
- [GParted](https://gparted.org/)
- [ImDisk Toolkit](https://sourceforge.net/projects/imdisk-toolkit/)
- [Kali Linux](https://www.kali.org/)
- [KeePassXC](https://keepassxc.org/)
- [LibreOffice](https://www.libreoffice.org/)
- [Linux Mint](https://linuxmint.com/)
- [Massgravel (MAS)](https://github.com/massgravel/Microsoft-Activation-Scripts)
- [MemTest86+](https://www.memtest.org/)
- [Mozilla Firefox](https://www.mozilla.org/firefox/)
- [Nmap](https://nmap.org/)
- [Notepad++](https://notepad-plus-plus.org/)
- [NTDEV (Tiny11)](https://github.com/ntdevlabs/tiny11builder)
- [ONLYOFFICE](https://www.onlyoffice.com/)
- [pbatard (Rufus / Fido)](https://github.com/pbatard)
- [PDFsam Basic](https://pdfsam.org/)
- [Process Hacker](https://processhacker.sourceforge.io/)
- [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/)
- [qBittorrent](https://www.qbittorrent.org/)
- [Rescuezilla](https://rescuezilla.com/)
- [Tails](https://tails.net/)
- [TestDisk / PhotoRec](https://www.cgsecurity.org/)
- [uBlock Origin](https://github.com/gorhill/uBlock)
- [Ventoy](https://github.com/ventoy/Ventoy)
- [VirtualBox](https://www.virtualbox.org/)
- [VLC Media Player](https://www.videolan.org/)
- [Win-11 Download Prep Tool](https://github.com/illsk1lls/Win-11-Download-Prep-Tool)
- [WinDirStat](https://windirstat.net/)
- [WinMTR](https://github.com/White-Tiger/WinMTR)
- [WinSCP](https://winscp.net/)
- [Wireshark](https://www.wireshark.org/)

please support these developers and help keep foss alive.

---

**web:** [brando.tools](https://brando.tools) | **repo:** [github.com/brand-o/tools](https://github.com/brand-o/tools)

