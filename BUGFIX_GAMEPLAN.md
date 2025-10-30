# Download Failures - Gameplan & Fixes

## Summary
- **Total Failed**: 40/80
- **Total Succeeded**: 38/80
- **Total Skipped**: 2/80 (John the Ripper, Hashcat - require consent)

---

## ✅ FIXED: Category 1 - Installer Path Mismatch (28 items)

**Root Cause**: `bundle.json` uses `UTILS:/Installers/` but folder structure created `UTILS:/Programs/`

**Items Fixed**:
- Macrium Reflect Free, Rufus (portable), DDU, Angry IP Scanner, Advanced Port Scanner, WinDirStat
- 7-Zip Installer, Git for Windows, Rufus Installer, HWiNFO64 Installer, Proton VPN
- LibreOffice, ONLYOFFICE, Discord, Steam, Node.js, qBittorrent Installer
- VLC Installer, Python, VirtualBox, TeamViewer, AnyDesk, Revo Uninstaller
- Wireshark Installer, Firefox, Brave, VS Code, uBlock Origin, Basic Driver Pack

**Fix Applied**: Changed folder structure from `Programs` to `Installers` in `make.ps1` line 1870

**Status**: ✅ COMMITTED - Ready for testing

---

## 🔧 FOUND CORRECT URLS - Ready to Update

### WinSCP Portable ✅
**Old URL**: `https://winscp.net/download/WinSCP-6.4.2-Portable.zip`
**New URL**: `https://winscp.net/download/WinSCP-6.5.4-Portable.zip`
**Status**: Direct download available (no redirect issue)

### WinMTR ✅
**Old URL**: `https://github.com/White-Tiger/WinMTR/releases/download/v0.92/WinMTR_x64.zip`
**New URL**: `https://github.com/White-Tiger/WinMTR/releases/download/v1.0/WinMTR_x64.zip`
**Note**: Version changed from v0.92 to v1.0

### Nmap ⚠️
**Current**: `https://nmap.org/dist/nmap-7.98-win32.zip`
**Issue**: No Windows ZIP available - only installer EXE
**Options**:
1. Change to installer: `https://nmap.org/dist/nmap-7.98-setup.exe` and remove `unzip` post-processing
2. Remove from bundle (use installer version separately)

### KeePassXC 🔄
**Pattern**: `KeePassXC-.*-Win64-Portable\.zip$`
**Issue**: GitHub page shows 29 assets but pattern might be wrong
**Action**: Need to check actual asset names via GitHub API to verify pattern

### Recuva & Speccy ⚠️
**Issue**: CCleaner only provides installers, NO portable ZIP versions
**Current URLs**: Point to installer EXEs not ZIPs
**Options**:
1. Remove from portable category
2. Change to installer category and remove `unzip` post-processing
3. Find alternative portable versions

---

## 🔧 TODO: Category 2 - URL/Server Issues (6 items)

### 1. NirSoft Suite ⚠️ NEEDS FALLBACK
**Error**: `The server did not return the file size. The Content-Length header is not available`
**URL**: `https://www.nirsoft.net/packages/nirsoft_package_1.30.66.zip`
**Fix**: Add WebClient fallback for downloads that fail with BITS

```powershell
# Add to Invoke-FileDownload function:
catch {
    if ($_.Exception.Message -like "*Content-Length*") {
        Write-Log "  BITS failed, trying WebClient..." -Level WARN
        (New-Object System.Net.WebClient).DownloadFile($Url, $Destination)
    }
}
```

### 2. Nmap ⚠️ NEEDS URL UPDATE
**Error**: `HTTP status 404`
**Current URL**: `https://nmap.org/dist/nmap-7.98-win32.zip`
**Fix**: Update to latest version
- Visit: https://nmap.org/download.html
- Find latest Windows zip download
- Update bundle.json with new URL

### 3. WinMTR ⚠️ NEEDS URL UPDATE  
**Error**: `HTTP status 404`
**Current URL**: `https://github.com/White-Tiger/WinMTR/releases/download/v0.92/WinMTR_x64.zip`
**Fix**: Check GitHub releases page
- Visit: https://github.com/White-Tiger/WinMTR/releases
- Asset might be named differently (e.g., `WinMTR-x64-0.92.zip`)
- Update bundle.json with correct asset name

### 4. WinSCP ⚠️ NEEDS REDIRECT HANDLING
**Error**: `HTTP status 302: redirect`
**Current URL**: `https://winscp.net/download/WinSCP-6.4.2-Portable.zip`
**Fix**: Add redirect handling to BITS or use WebClient fallback
- Option 1: Use direct CDN link if available
- Option 2: Add WebClient fallback for 302 errors

### 5. KeePassXC ⚠️ NEEDS REGEX FIX
**Error**: `No matching asset found for pattern: KeePassXC-.*-Win64-Portable\.zip$`
**Fix**: Check GitHub releases for actual asset name
- Visit: https://github.com/keepassxreboot/keepassxc/releases
- Asset might be: `KeePassXC-*-Win64-Portable.zip` (no version in middle)
- Update regex pattern in bundle.json

### 6. Snappy Driver Installer ⚠️ REPO MOVED/DELETED
**Error**: `(404) Not Found` on GitHub API
**Repo**: `Glenn-1990/SDI`
**Fix**: Find alternative source or updated repo
- Check if repo was renamed/moved
- Alternative: https://sdi-tool.org/ (official site)
- May need to use direct download link instead of GitHub API

---

## 🔧 TODO: Category 3 - Archive Format Issues (3 items)

### 1. TreeSize Free ⚠️ WRONG FILE TYPE
**Error**: `.exe is not a supported archive file format`
**Issue**: URL downloads ZIP but destination filename is `.exe`
**Current**: 
- URL: `https://downloads.jam-software.de/treesize_free/TreeSizeFree-Portable.zip`
- Dest filename: `TreeSizeFree.exe` 
**Fix**: Change destination filename to `TreeSizeFree-Portable.zip` in bundle.json

### 2. Recuva Portable ⚠️ WRONG URL
**Error**: `End of Central Directory record could not be found`  
**Issue**: URL points to installer EXE, not portable ZIP
**Current URL**: `https://download.ccleaner.com/rcsetup153.exe`
**Fix**: Find actual portable ZIP URL or change type to `installer` and remove `unzip` post-processing

### 3. Speccy Portable ⚠️ WRONG URL
**Error**: `End of Central Directory record could not be found`
**Issue**: URL points to installer EXE, not portable ZIP  
**Current URL**: `https://download.ccleaner.com/spsetup132.exe`
**Fix**: Find actual portable ZIP URL or change type to `installer` and remove `unzip` post-processing

---

## ℹ️ WARNINGS (Not Errors - Just Info)

### Shortcut Creation Warnings
**Items**: PDFsam, Process Hacker, ImDisk Toolkit
**Warning**: `No executable found for [app name]`
**Impact**: No desktop shortcut created, but files are downloaded correctly
**Fix**: Add executable detection patterns for these specific apps

### Flat Extraction Warnings  
**Items**: CPU-Z, HWiNFO, CRU, PuTTY, Everything, Sysinternals, HxD
**Warning**: `No folders found after extraction`
**Impact**: None - these apps extract as flat files (no subfolders)
**Fix**: Not needed - informational only

---

## 📋 TESTING CHECKLIST

After applying fixes:

1. ✅ **Test installer path fix** (already committed)
   - Run script and verify all 28 installer items succeed
   
2. ⚠️ **Apply URL fixes** (need bundle.json updates)
   - Nmap: Update to latest version
   - WinMTR: Fix asset name
   - KeePassXC: Fix regex pattern
   - Snappy Driver Installer: Find new source
   
3. ⚠️ **Apply download method fixes** (need code changes)
   - NirSoft: Add WebClient fallback
   - WinSCP: Add redirect handling
   
4. ⚠️ **Apply archive format fixes** (need bundle.json updates)
   - TreeSize: Fix destination filename
   - Recuva/Speccy: Fix URLs or change to installer type

---

## 🎯 PRIORITY ORDER

1. **HIGH**: Already fixed - test installer path (28 items) ✅
2. **MEDIUM**: Fix simple URL updates (Nmap, WinMTR, KeePassXC) - ~5 min
3. **MEDIUM**: Fix archive issues (TreeSize, Recuva, Speccy) - ~10 min  
4. **LOW**: Add WebClient fallback for BITS failures - ~15 min
5. **LOW**: Find Snappy Driver Installer alternative - ~10 min

**Estimated total fix time**: 30-40 minutes
**Expected success rate after fixes**: 75-78/80 (95-98%)
