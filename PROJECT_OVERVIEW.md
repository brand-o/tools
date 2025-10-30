# brando's toolkit - Project Overview

## Project Purpose

A fully automated USB flash drive toolkit that creates a bootable, multi-partition drive with:
- **VENTOY partition**: 15 bootable ISOs (Windows, Linux, rescue tools)
- **UTILS partition**: 31 portable apps, 27 installers, 6 drivers, 1 extension
- **FILES partition**: User storage space

**Goal**: One-command deployment of a complete IT professional/power user toolkit on 128GB+ USB drives.

---

## Architecture

### Core Components
- **make.ps1** (2607 lines): Main PowerShell script handling:
  - Drive selection and partitioning (GPT)
  - Ventoy installation via official binaries
  - Partition creation (VENTOY NTFS, UTILS exFAT, FILES exFAT)
  - Download management (BITS, WebClient fallback)
  - File provisioning to correct partitions
  - ISO modding for Windows 11 TPM bypass
  - Folder structure and helper scripts

- **bundle.json** (1607 lines, 78 items): Configuration manifest:
  - All download URLs and metadata
  - Destination paths (VENTOY:/... or UTILS:/...)
  - Post-processing instructions (unzip, extract7z, etc.)
  - Resolve strategies (direct, github_latest, fido, etc.)

- **run.ps1** (39 lines): Remote execution wrapper:
  - Downloads and executes make.ps1 from GitHub
  - Pauses on completion/error to keep window open

- **RUN_ME.bat** (18 lines): User-friendly launcher:
  - Elevates PowerShell with UAC prompt
  - Executes `iex (irm brando.tools/run)`
  - Keeps window open with -NoExit flag

### Website (separate repo: brand-o/brando.tools)
- **index.html**: Landing page with one-liner command
- **Cloudflare Pages**: Static hosting with custom domain
- **_redirects**: `/run` → GitHub raw URL for run.ps1

### Partition Scheme (128GB minimum)
```
Disk 0 (128GB = 111GB usable)
├─ Partition 1: EFI System (256MB)
├─ Partition 2: VENTOY (55GB NTFS) - ISOs
├─ Partition 3: UTILS (8GB exFAT) - Tools/drivers
└─ Partition 4: FILES (56GB exFAT) - User storage
```

### Download Resolution Strategies
1. **direct**: Static URL, download as-is
2. **github_latest**: Fetch latest release from GitHub API
3. **fido**: Use Fido.ps1 for Windows ISOs from Microsoft
4. **custom resolvers**: Per-tool logic for dynamic URLs

---

## What's Been Accomplished

### Phase 1: Core Functionality (Oct 2024)
- ✅ Drive detection and selection UI
- ✅ GPT partitioning with diskpart
- ✅ Ventoy installation automation
- ✅ Multi-partition creation (VENTOY, UTILS, FILES)
- ✅ Download engine with BITS and fallback
- ✅ File provisioning to correct destinations
- ✅ Bundle.json configuration system

### Phase 2: ISO Handling (Oct 2024)
- ✅ Windows ISO downloads via Fido.ps1
- ✅ ISO modding for Windows 11 TPM/SecureBoot bypass
- ✅ IMAPI2 8GB size limit fix (was 2GB default)
- ✅ Standardized ISO naming
- ✅ Ventoy menu generation

### Phase 3: Capacity Planning (Oct 2024)
- ✅ Eliminated 64GB support (insufficient space)
- ✅ Implemented 128GB minimum requirement
- ✅ Fixed partition sizing: 55GB Ventoy + 8GB Utils
- ✅ Validated content fits: 45.7GB ISOs + 6GB tools
- ✅ Large drive support (1TB+, removed 2TB limit)

### Phase 4: Documentation (Oct 2024)
- ✅ README.md accuracy fixes (counts matched bundle.json)
- ✅ Removed phantom entries (Win10 LTSC 2021, manual drivers)
- ✅ Website updated to 128GB requirement
- ✅ Repository cleanup (removed internal docs)

### Phase 5: Bug Fixes (Oct 2024-2025)
- ✅ RUN_ME.bat rebuilt for reliability (-NoExit pattern)
- ✅ PowerShell window closing issues fixed
- ✅ Partition path validation added
- ✅ Better error messages for missing drive letters
- ✅ Reduced Ventoy overhead (10GB → 2GB)

### Phase 6: Driver Improvements (Oct 2025)
- ✅ Removed Snappy Driver Installer Origin (unreliable)
- ✅ Removed Basic Driver Pack (torrent dependency)
- ✅ Added NVIDIA App (replaces GeForce Experience)
- ✅ Added AMD Adrenalin Software
- ✅ Total: 6 drivers (Intel RST, WiFi, Bluetooth, Realtek LAN, NVIDIA, AMD)

---

## Current State (Oct 30, 2025)

### Bundle Contents
- **15 ISOs** (45.7GB):
  - Windows: 11 24H2 Stock/Modded, 10 22H2, Server 2025
  - Linux: Mint, Fedora, Tails
  - Tools: Clonezilla, Rescuezilla, MemTest86+
  
- **31 Portable Apps** (~3GB):
  - System: CrystalDiskInfo, DDU, Everything, TreeSize, WinDirStat, Process Hacker
  - Office: LibreOffice, ONLYOFFICE, PDFsam, Notepad++
  - Network: PuTTY, FileZilla, WinSCP, Nmap, Wireshark, WinMTR
  - Security: KeePassXC, Recuva, TestDisk
  - Media: VLC
  - Dev: HxD, Hashcat, John the Ripper
  
- **27 Installers** (~3GB):
  - Browsers: Firefox, Google Chrome
  - Tools: 7-Zip, Balena Etcher, ImDisk, qBittorrent
  - VM: VirtualBox
  - Office: Same as portable

- **6 Drivers**:
  - Intel RST (Storage)
  - Intel WiFi 6/6E/7
  - Intel Bluetooth
  - Realtek USB Ethernet
  - NVIDIA App
  - AMD Adrenalin Software

- **1 Extension**:
  - uBlock Origin for Firefox

### Repository Status
- **Repo**: brand-o/tools (tools-clean workspace)
- **Branch**: main
- **Latest commit**: ee2ab67 (path validation)
- **Working tree**: Modified (pending commit)
- **Changes**: bundle.json (removed 2 drivers, added 2 drivers)

### Known Issues & Limitations

#### Path Errors
- **Status**: ⚠️ Under investigation
- **Symptoms**: "Cannot bind argument to parameter 'Path' because it is an empty string"
- **Cause**: Partition root paths (VentoyRoot/UtilsRoot) not set correctly
- **Fix**: Added validation in ee2ab67, awaiting test results
- **Next**: Review full console output from clean install

#### Minor Issues
- Some portable apps need manual extraction verification
- Large ISOs (>4GB) require slow fallback method
- Ventoy menu could be more organized
- No automatic update mechanism for bundle.json

---

## Future Ideas & Enhancements

### Short-Term (Next Release)
1. **Path Debugging**: Fix partition detection on all drive types
2. **Error Recovery**: Better handling of partial failures
3. **Progress UI**: Show overall completion percentage

### Medium-Term
1. **[1] Full / [2] Minimal Install**: Let users skip large items
   - Minimal: Skip LibreOffice (349MB), VirtualBox (106MB), etc.
   - Save space on smaller 128GB drives
2. **Recommendation Form**: GitHub Issues integration (Cloudflare Worker)
3. **Auto-update**: Check for bundle.json updates on each run
4. **Portable App Organization**: Automatic shortcut creation
5. **Resume Support**: Continue from last successful download

### Long-Term
1. **GUI Option**: Windows Forms or WPF interface
2. **Multi-language**: Support other languages
3. **Custom Profiles**: IT/Developer/Gamer presets
4. **Cloud Sync**: Keep tools updated automatically
5. **Dual-boot Helper**: Partition existing systems safely
6. **Network Deployment**: PXE boot option for enterprise

### Ideas Bin
- BitLocker encryption option for FILES partition
- Integrated backup/restore utilities
- System diagnostic scripts
- Network toolkit (packet capture, port scanning)
- Forensics tools section
- Password recovery tools
- Game modding tools
- Video editing portable apps

---

## To-Do List (Production Ready)

### Before Launch Today
- [x] Remove Snappy Driver Installer Origin
- [x] Remove Basic Driver Pack
- [x] Add NVIDIA App
- [x] Add AMD Adrenalin Software
- [ ] Update README.md counts (78 → 78 items, but 6 drivers now)
- [ ] Commit and push all changes
- [ ] Clean install test on physical drive
- [ ] Review full console output for errors
- [ ] Document any remaining issues

### Post-Launch
- [ ] Test on various drive brands/sizes
- [ ] Test on Windows 10 vs 11
- [ ] Test Ventoy boot on UEFI vs Legacy
- [ ] Verify all portable apps work correctly
- [ ] Test modded Windows 11 ISO on TPM-less machines

### Ongoing Maintenance
- [ ] Monitor GitHub issues for bug reports
- [ ] Update bundle.json when tools release new versions
- [ ] Test quarterly on fresh drives
- [ ] Update documentation as features added
- [ ] Collect user feedback and feature requests

---

## Technical Debt

1. **Hardcoded URLs**: Many URLs will break when versions update
2. **Limited error handling**: Some failures don't recover gracefully
3. **No logging rotation**: Log files grow indefinitely
4. **Magic numbers**: Partition sizes hardcoded (55GB, 8GB)
5. **Minimal testing**: No unit tests, manual testing only
6. **Windows-only**: No Linux/macOS support for creation
7. **No CI/CD**: Manual testing and deployment

---

## Success Metrics

### Current Stats (Oct 30, 2025)
- Total bundle size: ~55GB (ISOs + tools)
- Download time: ~30-60 min (depends on connection)
- Total items: 78 (15 ISOs, 31 portable, 27 installers, 6 drivers, 1 extension)
- Minimum drive size: 128GB (111GB usable)
- Partitions: 3 data + 1 EFI
- PowerShell version: 5.1+ (Windows 10/11)
- Administrator: Required (disk operations)

### Target Metrics
- Success rate: >95% completion on standard drives
- Download failures: <5% requiring retry
- Boot success: 100% on UEFI systems
- User satisfaction: Positive feedback from early testers
- Update frequency: Monthly bundle.json updates

---

## Contributing

This is a personal project by brando, but open to:
- Bug reports via GitHub Issues
- Tool recommendations via website form (when implemented)
- Pull requests for bug fixes (must test thoroughly)
- Documentation improvements

**Not accepting**:
- Pirated software links
- Untrusted/malicious tools
- Breaking changes without discussion

---

## License

MIT License - See LICENSE file

---

**Last Updated**: October 30, 2025  
**Version**: 1.0 (Pre-production)  
**Maintainer**: brando (brand-o on GitHub)
