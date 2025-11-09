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

##    

#### if having issues with permissions running scripts use:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```




## what it does
the powershell script automates everything:

1. **auto-detects** all connected flash drives
2. **select** your target drive from the list
3. **formats & partitions** the drive automatically (with confirmation)
4. **downloads** 80 tools, isos, drivers, and scripts from official or reliable sources
5. **organizes** everything into a clean three-partition structure
6. **makes bootable via ventoy** — ready to use as your ultimate tech toolkit

## requirements
- **Windows** (requires PowerShell + administrator privileges)
- **fast 128GB+ USB flash drive** (256-512GB+ recommended)
- **internet connection** for downloads
- **~30-90 minutes** depending on drive speed and internet connection

## partition layout

the script creates three partitions on your drive:

### 1. ventoy (uefi secure boot compatible)
- **size:** 55GB (all ISOs + 20% buffer for modding temp space)
- **contents:** all bootable ISOs for multi-boot capability

### 2. utils (tools & installers)
- **size:** 8GB (all tools/drivers + 20% buffer)
- **contents:** portable apps, installers, drivers, scripts

### 3. files (remaining space)
- **size:** all remaining drive space (typically 50-60GB on 128GB drives)
- **contents:** your personal files, backups, documents

### resume capability
if the script is interrupted, it will detect partial installs and offer to:
- resume from where it left off
- or reformat and start over

## included software

### operating system isos (15 total)

**windows**
- Windows 11 Pro 24H2 (Stock + Modded version with TPM/SecureBoot/RAM bypasses)
- Windows 10 Pro 22H2 (Stock OEM)
- Windows 11 Enterprise LTSC 2024
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

### portable applications (31 total)

- 7-Zip
- Advanced Port Scanner
- Angry IP Scanner
- Balena Etcher
- CPU-Z
- CRU (Custom Resolution Utility)
- CrystalDiskInfo
- CrystalDiskMark
- DDU (Display Driver Uninstaller)
- Everything (Search)
- Hashcat
- HWiNFO
- HxD Hex Editor
- ImDisk Toolkit
- John the Ripper
- KeePassXC Portable
- NirSoft Suite
- Notepad++
- PDFsam Basic Portable
- Process Hacker
- PuTTY
- qBittorrent Portable
- Rufus
- Sysinternals Suite
- TestDisk & PhotoRec
- TreeSize Free
- VLC Media Player Portable
- WinDirStat
- WinMTR
- WinSCP Portable
- Wireshark Portable

### installer applications (27 total)

- 7-Zip Installer
- Android Platform Tools
- AnyDesk
- Brave Browser
- BulkCrapUninstaller
- Discord
- Git for Windows
- HWiNFO64 Installer
- LibreOffice
- Microsoft Office Deployment Tool
- Mozilla Firefox
- Nmap
- Node.js LTS
- ONLYOFFICE Desktop Editors
- Proton VPN
- Python
- qBittorrent Installer
- Recuva
- Revo Uninstaller Free
- Rufus Installer
- Speccy
- Steam
- TeamViewer
- VirtualBox
- VLC Media Player Installer
- VS Code
- Wireshark Installer

### drivers (6 total)

- Intel RST (Rapid Storage Technology)
- Intel Wi-Fi 6E/7 Driver
- Intel Bluetooth Driver
- Realtek USB Ethernet Driver
- NVIDIA App (Graphics Driver & Control Panel)
- AMD Adrenalin Software (Graphics Driver & Control Panel)

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
- [P. Batard (Fido & Rufus)](https://github.com/pbatard/Fido)
- [wimlib-imagex](https://wimlib.net/)
- [aria2c](https://github.com/aria2/aria2)
- [Chris Wu (New-IsoFile)](https://github.com/wikijm/PowerShell-AdminScripts/blob/master/Miscellaneous/New-IsoFile.ps1)
- [Helge Klein (SetACL)](https://helgeklein.com/setacl/)
- [AveYo (MediaCreationTool.bat bypass)](https://github.com/AveYo/MediaCreationTool.bat)
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
- [illsk1lls (Win-11 Download Prep Tool)](https://github.com/illsk1lls/Win-11-Download-Prep-Tool)
- [WinDirStat](https://windirstat.net/)
- [WinMTR](https://github.com/White-Tiger/WinMTR)
- [Wireshark](https://www.wireshark.org/)

please support these developers and help keep foss alive.

---

**web:** [brando.tools](https://brando.tools) | **repo:** [github.com/brand-o/tools](https://github.com/brand-o/tools)

