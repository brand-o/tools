<#
================================================================================
Brando's Toolkit - USB Drive Provisioning Tool
Copyright (C) 2025  Brando

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
================================================================================

.SYNOPSIS
    make.ps1 - Provision brando's toolkit: Complete Ventoy-based all-in-one tech thumbdrive

.DESCRIPTION
    This script automates the creation of a multi-partition USB drive with:
    - Ventoy bootloader (GPT, Secure Boot enabled)
    - VENTOY partition (NTFS) for ISO files
    - UTILS partition (exFAT) for portable tools and installers
    - FILES partition (exFAT) for large FILESs

    It downloads official tools, ISOs, and utilities with SHA-256 verification,
    creates organized folder structures, and generates a Ventoy menu configuration.

.PARAMETER ConfigPath
    Path to bundle.json configuration file (default: .\bundle.json)

.PARAMETER BundleUrl
    URL to fetch bundle.json from remote server (e.g., https://brando.tools/bundle.json)
    Falls back to ConfigPath if download fails

.PARAMETER SkipDownloads
    Skip downloading files (useful for testing partitioning only)

.PARAMETER TestMode
    Test mode - validates all URLs and checks file availability without full downloads
    Downloads only first 1KB of each file to verify accessibility

.PARAMETER Force
    Skip confirmation prompts (use with extreme caution)

.PARAMETER Skip
    Skip specific categories (e.g., "iso", "portable", "installer", "driver")
    Can specify multiple categories: -Skip iso,driver

.EXAMPLE
    .\make.ps1

.EXAMPLE
    .\make.ps1 -ConfigPath .\custom-bundle.json

.EXAMPLE
    .\make.ps1 -BundleUrl "https://brando.tools/bundle.json"

.EXAMPLE
    .\make.ps1 -Skip iso
    Skip all ISO downloads (faster testing)

.EXAMPLE
    .\make.ps1 -Skip iso,driver
    Skip both ISOs and drivers

.NOTES
    Author: Brando (Generated with Claude Code)
    Requires: Administrator privileges, Internet connection
    License: MIT
#>

& {

# When executed via 'irm | iex', parameters are not supported
# For parameter support, download and run the script locally: .\make.ps1 -ConfigPath <path>

param(
    [string]$ConfigPath = "",
    [string]$BundleUrl = "",
    [switch]$SkipDownloads,
    [switch]$TestMode,
    [switch]$Force,
    [string[]]$Skip = @()
)

# ============================================================================
# AUTO-ELEVATION - Re-launch as admin if not already elevated
# ============================================================================

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as Administrator. Relaunching with elevation..." -ForegroundColor Yellow

    # Choose PowerShell executable (prefer pwsh if available)
    $powershellCmd = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

    # Check if script is running from a file or was invoked directly
    if ($MyInvocation.MyCommand.Path) {
        # Running from a file - relaunch the file
        Start-Process $powershellCmd -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    } else {
        # Running from command line (iex) - relaunch with script content
        $scriptContent = $MyInvocation.MyCommand.ScriptContents
        Start-Process $powershellCmd -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"$scriptContent`"" -Verb RunAs
    }

    # Exit this non-elevated instance
    exit
}

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ============================================================================
# CONSTANTS & GLOBALS
# ============================================================================

$script:LogFile = Join-Path $PSScriptRoot "make.log"
$script:StagingDir = Join-Path $PSScriptRoot "_staging"
$script:VentoyDir = Join-Path $script:StagingDir "ventoy"
$script:DownloadRetries = 3
$script:DownloadTimeout = 600
$script:Manifest = @()
$script:lastGitHubDownload = $null  # Track last GitHub API call for rate limiting
$script:TestMode = $TestMode  # Propagate test mode flag

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Color output
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }

    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path $script:LogFile -Value $logMessage -Encoding UTF8
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FriendlySize {
    param([int64]$Bytes)

    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Invoke-GitHubAPI {
    param(
        [string]$Endpoint,
        [int]$MaxRetries = 3
    )

    $baseUrl = "https://api.github.com"
    $url = "$baseUrl$Endpoint"

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $headers = @{
                "User-Agent" = "BrandoToolkit-Builder/1.0"
                "Accept" = "application/vnd.github+json"
            }

            # GitHub API rate limiting handled by 5-second delays between calls
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 30
            return $response
        }
        catch {
            if ($i -eq $MaxRetries) {
                Write-Log "GitHub API call failed after $MaxRetries attempts: $url" -Level ERROR
                throw
            }
            Write-Log "GitHub API retry $i/$MaxRetries for $url" -Level WARN
            Start-Sleep -Seconds (2 * $i)
        }
    }
}

function Resolve-DownloadUrl {
    param(
        [Parameter(Mandatory)]
        $Item
    )

    $resolve = $Item.resolve

    switch ($resolve.strategy) {
        "github_latest" {
            Write-Log "Resolving GitHub latest release: $($resolve.repo)"
            $release = Invoke-GitHubAPI -Endpoint "/repos/$($resolve.repo)/releases/latest"

            $asset = $release.assets | Where-Object {
                $_.name -match $resolve.asset_regex
            } | Select-Object -First 1

            if (-not $asset) {
                throw "No matching asset found for pattern: $($resolve.asset_regex)"
            }

            Write-Log "Found asset: $($asset.name) ($($asset.size) bytes)"

            return @{
                url = $asset.browser_download_url
                filename = $asset.name
                size = $asset.size
                version = $release.tag_name
            }
        }

        "github_release_tag" {
            Write-Log "Resolving GitHub release tag: $($resolve.repo) @ $($resolve.tag)"
            $release = Invoke-GitHubAPI -Endpoint "/repos/$($resolve.repo)/releases/tags/$($resolve.tag)"

            $asset = $release.assets | Where-Object {
                $_.name -match $resolve.asset_regex
            } | Select-Object -First 1

            if (-not $asset) {
                throw "No matching asset found for pattern: $($resolve.asset_regex)"
            }

            return @{
                url = $asset.browser_download_url
                filename = $asset.name
                size = $asset.size
                version = $release.tag_name
            }
        }

        "direct" {
            # Use explicit filename if provided, otherwise extract from URL
            $filename = if ($resolve.filename) {
                $resolve.filename
            } else {
                # Strip query parameters and extract filename
                $cleanUrl = $Item.source_url.Split('?')[0]
                $extracted = [System.IO.Path]::GetFileName($cleanUrl)

                # Fallback if extraction failed
                if ([string]::IsNullOrEmpty($extracted)) {
                    "$($Item.name -replace '[^a-zA-Z0-9]', '_').$($Item.type)"
                } else {
                    $extracted
                }
            }

            return @{
                url = $Item.source_url
                filename = $filename
                size = 0
                version = "unknown"
            }
        }

        "api_redirect" {
            Write-Log "  Strategy: API redirect (following redirect to get final URL)" -Level INFO
            try {
                # Follow the redirect to get the actual download URL
                $response = Invoke-WebRequest -Uri $Item.source_url -Method Head -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop
                $finalUrl = $response.BaseResponse.ResponseUri.AbsoluteUri
                $filename = [System.IO.Path]::GetFileName($finalUrl.Split('?')[0])

                if ([string]::IsNullOrEmpty($filename)) {
                    $filename = "$($Item.name -replace '[^a-zA-Z0-9]', '_').$($Item.type)"
                }

                Write-Log "  Resolved to: $finalUrl" -Level INFO
                Write-Log "  Filename: $filename" -Level INFO

                return @{
                    url = $finalUrl
                    filename = $filename
                    size = 0
                    version = "unknown"
                }
            }
            catch {
                throw "Failed to resolve API redirect: $($_.Exception.Message)"
            }
        }

        "fido_automated_modded" {
            Write-Log "  Strategy: Windows ISO download via integrated Fido.ps1" -Level INFO

            # Return a placeholder that indicates this needs special Fido processing
            return @{
                url = "FIDO_DOWNLOAD"  # Special marker for Fido integration
                filename = "$($resolve.edition)_Stock.iso"
                size = 0
                version = $resolve.edition
                requires_fido = $true
                edition = $resolve.edition
                language = if ($resolve.language) { $resolve.language } else { "English" }
            }
        }

        "fido_automated" {
            Write-Log "  Strategy: Windows ISO download via integrated Fido.ps1" -Level INFO

            # Return a placeholder that indicates this needs special Fido processing
            return @{
                url = "FIDO_DOWNLOAD"  # Special marker for Fido integration
                filename = "$($resolve.edition)_Stock.iso"
                size = 0
                version = $resolve.edition
                requires_fido = $true
                edition = $resolve.edition
                language = if ($resolve.language) { $resolve.language } else { "English" }
            }
        }

        "fido_with_mods" {
            Write-Log "  Strategy: Windows ISO download + modding via Get-Win11.cmd" -Level INFO

            # Return a placeholder that indicates this needs Fido + modding
            return @{
                url = "FIDO_DOWNLOAD"  # Special marker for Fido integration
                filename = "$($resolve.edition)_Modded.iso"
                size = 0
                version = $resolve.edition
                requires_fido = $true
                requires_modding = $true
                edition = $resolve.edition
                language = if ($resolve.language) { $resolve.language } else { "English" }
            }
        }

        "direct_rename_iso" {
            Write-Log "  Strategy: Direct download with .iso rename" -Level INFO

            # Download file and rename extension to .iso
            # Used for Microsoft OEM links that require extension renaming
            $filename = if ($resolve.filename) {
                $resolve.filename
            } else {
                # Extract filename from URL or use a default based on edition
                $urlFilename = [System.IO.Path]::GetFileName($Item.source_url.Split('?')[0])
                if ([string]::IsNullOrEmpty($urlFilename)) {
                    "$($resolve.edition).iso"
                } else {
                    $urlFilename -replace '\.[^.]+$', '.iso'  # Replace extension with .iso
                }
            }

            return @{
                url = $Item.source_url
                filename = $filename
                size = 0
                version = if ($resolve.edition) { $resolve.edition } else { "Unknown" }
                requires_rename = $true  # Flag to rename after download
            }
        }

        "direct_download" {
            Write-Log "  Strategy: Direct download (Windows LTSC)" -Level INFO
            $filename = [System.IO.Path]::GetFileName($Item.source_url.Split('?')[0])
            if ([string]::IsNullOrEmpty($filename) -or $filename -notmatch '\.(iso|exe|msi)$') {
                $filename = "$($Item.name -replace '[^a-zA-Z0-9]', '_').iso"
            }
            return @{
                url = $Item.source_url
                filename = $filename
                size = 0
                version = $resolve.edition
            }
        }

        default {
            throw "Unknown resolve strategy: $($resolve.strategy)"
        }
    }
}

function Get-RemoteFileSize {
    param([string]$Url)

    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "HEAD"
        $req.Timeout = 10000
        $resp = $req.GetResponse()
        $size = $resp.ContentLength
        $resp.Close()
        return $size
    }
    catch {
        return 0
    }
}

function Invoke-FileDownload {
    param(
        [string]$Url,
        [string]$Destination,
        [string]$DisplayName,
        [int64]$ExpectedSize = 0
    )

    Write-Log "Downloading: $DisplayName"
    Write-Log "  URL: $Url"
    Write-Log "  Destination: $Destination"

    $destinationDir = Split-Path -Parent $Destination
    if (-not (Test-Path $destinationDir)) {
        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    $tempFile = "$Destination.partial"

    # TEST MODE: Just validate URL accessibility without full download
    if ($script:TestMode) {
        Write-Log "  [TEST MODE] Validating URL accessibility..." -Level INFO
        try {
            $headers = @{ Range = 'bytes=0-1023' }  # Request only first 1KB
            $response = Invoke-WebRequest -Uri $Url -Method Head -MaximumRedirection 5 -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

            $statusCode = $response.StatusCode
            $contentLength = $response.Headers.'Content-Length'

            if ($statusCode -eq 200 -or $statusCode -eq 206) {
                $sizeStr = if ($contentLength) {
                    $friendlySize = Get-FriendlySize $contentLength
                    "Size: $friendlySize"
                } else { "Size: Unknown" }
                Write-Log "  [TEST MODE] OK - URL accessible ($statusCode) - $sizeStr" -Level SUCCESS

                # Create a tiny dummy file to simulate successful download
                "TEST_MODE_PLACEHOLDER" | Out-File -FilePath $Destination -Encoding ASCII
                return $Destination
            } else {
                Write-Log "  [TEST MODE] FAIL - Unexpected status code: $statusCode" -Level ERROR
                return $null
            }
        }
        catch {
            Write-Log "  [TEST MODE] FAIL - URL validation failed: $($_.Exception.Message)" -Level ERROR
            return $null
        }
    }

    # Detect Microsoft redirect URLs (BITS doesn't handle these well)
    $useBits = $true
    $finalUrl = $Url

    if ($Url -match 'go\.microsoft\.com|aka\.ms' -or $Url -match 'fwlink') {
        $useBits = $false
        Write-Log "  Detected redirect URL - resolving actual download URL..." -Level INFO

        try {
            # Follow redirects to get the actual download URL
            $response = Invoke-WebRequest -Uri $Url -Method Head -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop
            $finalUrl = $response.BaseResponse.ResponseUri.AbsoluteUri
            Write-Log "  Resolved to: $finalUrl" -Level INFO
        }
        catch {
            Write-Log "  Could not resolve redirect, will try direct download: $($_.Exception.Message)" -Level WARN
        }
    }

    for ($attempt = 1; $attempt -le $script:DownloadRetries; $attempt++) {
        try {
            # Use appropriate download method
            if ($useBits -and (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue)) {
                Write-Log "  Using BITS transfer (attempt $attempt/$($script:DownloadRetries))"
                Start-BitsTransfer -Source $finalUrl -Destination $tempFile -Description $DisplayName -ErrorAction Stop
            }
            elseif (-not $useBits) {
                Write-Log "  Using Invoke-WebRequest with progress (attempt $attempt/$($script:DownloadRetries))"

                # Get file size for progress calculation
                $fileSize = Get-RemoteFileSize -Url $finalUrl

                # Use WebClient for progress tracking
                $webClient = New-Object System.Net.WebClient
                $script:downloadComplete = $false
                $script:lastProgress = 0
                $script:startTime = Get-Date

                # Progress event handler
                $progressHandler = {
                    param($sender, $e)
                    $percent = $e.ProgressPercentage
                    $bytesReceived = $e.BytesReceived
                    $totalBytes = $e.TotalBytesToReceive

                    # Calculate speed
                    $elapsed = (Get-Date) - $script:startTime
                    if ($elapsed.TotalSeconds -gt 0) {
                        $speedBps = $bytesReceived / $elapsed.TotalSeconds
                        $speedMBps = $speedBps / 1MB

                        # Only update every 5% to avoid console spam
                        if ($percent - $script:lastProgress -ge 5) {
                            $script:lastProgress = $percent
                            $speedRounded = [math]::Round($speedMBps, 2)
                            $downloadedSize = Get-FriendlySize $bytesReceived
                            $totalSize = Get-FriendlySize $totalBytes
                            Write-Host ('    Progress: {0}% | Speed: {1} megabytes/sec | Downloaded: {2} of {3}' -f $percent, $speedRounded, $downloadedSize, $totalSize) -ForegroundColor Yellow
                        }
                    }
                }

                # Completion handler
                $completedHandler = {
                    $script:downloadComplete = $true
                }

                Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -Action $progressHandler | Out-Null
                Register-ObjectEvent -InputObject $webClient -EventName DownloadFileCompleted -Action $completedHandler | Out-Null

                try {
                    $webClient.DownloadFileAsync($finalUrl, $tempFile)

                    # Wait for download to complete
                    while (-not $script:downloadComplete) {
                        Start-Sleep -Milliseconds 100
                    }
                }
                finally {
                    $webClient.Dispose()
                    Get-EventSubscriber | Where-Object { $_.SourceObject -eq $webClient } | Unregister-Event
                }
            }
            else {
                Write-Log "  Using WebClient (attempt $attempt/$($script:DownloadRetries))"
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($finalUrl, $tempFile)
                $webClient.Dispose()
            }

            # Verify download completed
            if (Test-Path $tempFile) {
                $actualSize = (Get-Item $tempFile).Length

                if ($ExpectedSize -gt 0 -and $actualSize -ne $ExpectedSize) {
                    Write-Log "  Size mismatch: expected $ExpectedSize, got $actualSize" -Level WARN
                    if ($attempt -lt $script:DownloadRetries) {
                        Remove-Item $tempFile -Force
                        continue
                    }
                }

                Move-Item -Path $tempFile -Destination $Destination -Force
                $friendlySize = Get-FriendlySize $actualSize
                Write-Log "  Download complete: $friendlySize" -Level SUCCESS
                return $true
            }
        }
        catch {
            Write-Log "  Download attempt $attempt failed: $($_.Exception.Message)" -Level WARN
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force
            }

            if ($attempt -lt $script:DownloadRetries) {
                Start-Sleep -Seconds (3 * $attempt)
            }
            else {
                throw
            }
        }
    }

    return $false
}

function Get-FidoScript {
    <#
    .SYNOPSIS
        Downloads Fido.ps1 for Windows ISO downloads
    #>
    param()

    $fidoUrl = "https://raw.githubusercontent.com/pbatard/Fido/master/Fido.ps1"
    $fidoPath = Join-Path $script:StagingDir "Fido.ps1"

    if (Test-Path $fidoPath) {
        Write-Log "  Fido.ps1 already exists in staging" -Level INFO
        return $fidoPath
    }

    Write-Log "  Downloading Fido.ps1 from GitHub..." -Level INFO

    try {
        Invoke-WebRequest -Uri $fidoUrl -OutFile $fidoPath -UseBasicParsing -ErrorAction Stop
        Write-Log "  Fido.ps1 downloaded successfully" -Level SUCCESS
        return $fidoPath
    }
    catch {
        Write-Log "  Failed to download Fido.ps1: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Get-WimlibImagex {
    <#
    .SYNOPSIS
        Downloads wimlib-imagex for WIM file manipulation
    #>
    param()

    $wimlibUrl = "https://wimlib.net/downloads/wimlib-1.14.4-windows-x86_64-bin.zip"
    $wimlibZip = Join-Path $script:StagingDir "wimlib.zip"
    $wimlibDir = Join-Path $script:StagingDir "wimlib"
    $wimlibExe = Join-Path $wimlibDir "wimlib-imagex.exe"

    if (Test-Path $wimlibExe) {
        Write-Log "  wimlib-imagex already exists" -Level INFO
        return $wimlibExe
    }

    Write-Log "  Downloading wimlib-imagex..." -Level INFO

    try {
        # Download
        Invoke-WebRequest -Uri $wimlibUrl -OutFile $wimlibZip -UseBasicParsing -ErrorAction Stop

        # Extract
        Expand-Archive -Path $wimlibZip -DestinationPath $wimlibDir -Force

        # Find the exe in extracted files
        $extractedExe = Get-ChildItem -Path $wimlibDir -Filter "wimlib-imagex.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($extractedExe) {
            # Move to root of wimlib dir if it's in a subfolder
            if ($extractedExe.DirectoryName -ne $wimlibDir) {
                Copy-Item -Path $extractedExe.FullName -Destination $wimlibExe -Force
            }
        }

        # Cleanup zip
        Remove-Item $wimlibZip -Force -ErrorAction SilentlyContinue

        if (Test-Path $wimlibExe) {
            Write-Log "  wimlib-imagex ready" -Level SUCCESS
            return $wimlibExe
        } else {
            throw "wimlib-imagex.exe not found after extraction"
        }
    }
    catch {
        Write-Log "  Failed to get wimlib-imagex: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Invoke-ISOModding {
    <#
    .SYNOPSIS
        Creates modded Windows 11 ISO with TPM/SecureBoot/RAM bypasses - pure PowerShell
    .DESCRIPTION
        Mounts ISO, modifies install.wim registry to add hardware check bypasses, saves as new ISO
    #>
    param(
        [string]$SourceISO,
        [string]$Destination
    )

    Write-Log "  Creating modded ISO with TPM/SecureBoot bypasses..." -Level INFO
    Write-Log "  This may take 10-20 minutes..." -Level WARN

    $wimlibExe = Get-WimlibImagex
    $workDir = Join-Path $script:StagingDir "iso_mod_$(Get-Random)"
    $isoExtract = Join-Path $workDir "iso"
    $finalISO = Join-Path $Destination "Win11_Mod.iso"

    try {
        New-Item -ItemType Directory -Path $isoExtract -Force | Out-Null

        # Mount and copy ISO contents
        Write-Log "  Mounting ISO..." -Level INFO
        $mount = Mount-DiskImage -ImagePath $SourceISO -PassThru -ErrorAction Stop
        $volume = $mount | Get-Volume
        $driveLetter = $volume.DriveLetter

        if (-not $driveLetter) {
            throw "Could not get drive letter after mounting ISO"
        }

        $isoDrive = "${driveLetter}:"
        Write-Log "  ISO mounted at $isoDrive" -Level INFO

        Write-Log "  Copying ISO contents..." -Level INFO
        Copy-Item -Path "$isoDrive\*" -Destination $isoExtract -Recurse -Force
        Dismount-DiskImage -ImagePath $SourceISO | Out-Null

        # Find install.wim
        $installWim = Join-Path $isoExtract "sources\install.wim"
        if (-not (Test-Path $installWim)) {
            throw "install.wim not found in ISO"
        }

        Write-Log "  Modifying install.wim to bypass hardware checks..." -Level INFO

        # Make writable
        Set-ItemProperty -Path $installWim -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue

        # Get image count
        $wimInfoRaw = & $wimlibExe info "$installWim"
        $imageCount = ($wimInfoRaw | Select-String "Index\s+:\s+(\d+)" -AllMatches).Matches.Count

        # Create autounattend.xml with all Rufus-style bypasses and privacy tweaks
        $autoUnattendContent = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>en-001</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-001</UserLocale>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <UserData>
                <AcceptEula>true</AcceptEula>
                <ProductKey>
                    <WillShowUI>Never</WillShowUI>
                </ProductKey>
            </UserData>
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>4</Order>
                    <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassStorageCheck /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>5</Order>
                    <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassCPUCheck /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>en-001</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-001</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
                <SkipMachineOOBE>true</SkipMachineOOBE>
                <SkipUserOOBE>true</SkipUserOOBE>
            </OOBE>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ComputerName>*</ComputerName>
        </component>
        <component name="Microsoft-Windows-Security-SPP-UX" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SkipAutoActivation>true</SkipAutoActivation>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Description>Disable BitLocker auto-encryption</Description>
                    <Path>reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Description>Disable privacy questions</Description>
                    <Path>reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <Description>Disable telemetry</Description>
                    <Path>reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>4</Order>
                    <Description>Disable Windows Consumer Features</Description>
                    <Path>reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>5</Order>
                    <Description>Remove Microsoft Account requirement</Description>
                    <Path>reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
</unattend>
'@

        # Inject autounattend into ISO root
        $autoUnattendPath = Join-Path $isoExtract "autounattend.xml"
        Set-Content -Path $autoUnattendPath -Value $autoUnattendContent -Encoding UTF8

        Write-Log "  Applied all tweaks via autounattend.xml:" -Level SUCCESS
        Write-Log "    - Bypass TPM/SecureBoot/RAM/Storage/CPU checks" -Level INFO
        Write-Log "    - Skip product key prompt (activate later)" -Level INFO
        Write-Log "    - Remove Microsoft Account requirement (local account allowed)" -Level INFO
        Write-Log "    - Set region to English (World) - en-001" -Level INFO
        Write-Log "    - Disable telemetry and data collection" -Level INFO
        Write-Log "    - Disable BitLocker automatic encryption" -Level INFO
        Write-Log "    - Skip privacy questions and OOBE screens" -Level INFO

        # Recreate ISO (simple method - copy back)
        Write-Log "  Rebuilding ISO..." -Level INFO

        # Use IMAPI2 COM object to create ISO
        $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
        $fsi.VolumeName = "WIN11_MOD"
        $fsi.FileSystemsToCreate = 4  # UDF
        
        # Increase ISO size limit to 8GB (Windows 11 ISOs are ~6.5GB)
        # Default is 2GB which is too small for Windows 11
        $fsi.FreeMediaBlocks = 4194304  # 8GB in 2KB blocks (8*1024*1024*1024/2048)

        # Add all files
        $fsi.Root.AddTree($isoExtract, $false)

        # Create result
        $result = $fsi.CreateResultImage()
        $stream = $result.ImageStream

        # Write to file
        $fileStream = [System.IO.File]::Create($finalISO)
        
        # BinaryReader requires a stream and encoding/leaveOpen parameter
        # Using IStream COM interface requires special handling
        $reader = New-Object System.IO.BinaryReader($stream, [System.Text.Encoding]::Default, $false)
        $buffer = New-Object byte[] 2048

        do {
            $read = $reader.Read($buffer, 0, $buffer.Length)
            $fileStream.Write($buffer, 0, $read)
        } while ($read -gt 0)

        $fileStream.Close()
        $reader.Close()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($fsi) | Out-Null

        if (Test-Path $finalISO) {
            Write-Log "  Modded ISO created!" -Level SUCCESS
            return $finalISO
        }

        throw "ISO creation failed"
    }
    catch {
        Write-Log "  ISO modding failed: $($_.Exception.Message)" -Level ERROR

        # Close any open file handles
        try {
            if ($fileStream) { $fileStream.Close(); $fileStream.Dispose() }
            if ($reader) { $reader.Close(); $reader.Dispose() }
        } catch {}

        # Fallback to stock ISO
        if (Test-Path $SourceISO) {
            Write-Log "  Falling back to stock ISO" -Level WARN
            $fallback = Join-Path $Destination "Win11_OEM.iso"
            
            # Remove failed modded ISO if it exists
            if (Test-Path $finalISO) {
                Start-Sleep -Seconds 1
                Remove-Item $finalISO -Force -ErrorAction SilentlyContinue
            }
            
            Copy-Item -Path $SourceISO -Destination $fallback -Force
            return $fallback
        }

        return $null
    }
    finally {
        # Cleanup - ensure all handles are released
        try {
            if ($fileStream) { $fileStream.Close(); $fileStream.Dispose() }
            if ($reader) { $reader.Close(); $reader.Dispose() }
            if ($fsi) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($fsi) | Out-Null }
        } catch {}

        # Dismount ISO
        Dismount-DiskImage -ImagePath $SourceISO -ErrorAction SilentlyContinue | Out-Null
        
        # Wait for filesystem to release locks
        Start-Sleep -Seconds 2
        
        # Cleanup work directory
        if (Test-Path $workDir) {
            Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-DynamicPartitionSizes {
    <#
    .SYNOPSIS
        Calculates partition sizes based on drive size
    #>
    param(
        [Parameter(Mandatory=$true)]
        [long]$DriveSizeBytes,
        [Parameter(Mandatory=$true)]
        [hashtable]$PartitionRules
    )

    $driveSizeGB = [math]::Round($DriveSizeBytes / 1GB, 2)
    
    # Fixed partitioning scheme for all drives (128GB+ required)
    # VENTOY: 55GB (45.7GB ISOs + 20% buffer for modding temp space)
    # UTILS: 8GB (6GB tools/drivers + 20% buffer)
    # FILES: All remaining space (personal files, backups, etc.)
    
    if ($driveSizeGB -lt 111) {
        throw "Drive too small. Minimum 128GB drive required (111GB usable), found $driveSizeGB GB"
    }

    $ventoyGB = 55
    $utilsGB = 8

    Write-Log ('  Drive size: {0} GB' -f $driveSizeGB) -Level INFO
    Write-Log ('  Partition scheme: Ventoy {0} GB, Utils {1} GB, FILES (all remaining)' -f $ventoyGB, $utilsGB) -Level INFO

    return @{
        ventoy_gb = $ventoyGB
        utils_gb = $utilsGB
    }
}

function Get-StandardizedFilename {
    <#
    .SYNOPSIS
        Standardizes ISO/file names
    #>
    param(
        [string]$OriginalName,
        [string]$ItemName
    )

    # Windows ISOs
    if ($ItemName -match "Windows 11.*Pro.*Modded") { return "Win11_Mod.iso" }
    if ($ItemName -match "Windows 11.*Pro.*Stock") { return "Win11_OEM.iso" }
    if ($ItemName -match "Windows 10.*Pro") { return "Win10_OEM.iso" }
    if ($ItemName -match "Windows 11.*LTSC") { return "Win11_LTSC.iso" }
    if ($ItemName -match "Windows 10.*LTSC") { return "Win10_LTSC.iso" }

    # Other ISOs
    if ($ItemName -match "Tiny11") { return "Tiny11.iso" }
    if ($ItemName -match "Live11") { return "Live11.iso" }
    if ($ItemName -match "Hiren") { return "HirensBootPE.iso" }
    if ($ItemName -match "GParted") { return "GParted.iso" }
    if ($ItemName -match "Tails") { return "Tails.img" }
    if ($ItemName -match "Kali") { return "Kali.iso" }
    if ($ItemName -match "Linux Mint") { return "LinuxMint.iso" }
    if ($ItemName -match "Fedora") { return "Fedora.iso" }
    if ($ItemName -match "Rescuezilla") { return "Rescuezilla.iso" }
    if ($ItemName -match "Memtest") { return "Memtest86.iso" }
    if ($ItemName -match "Clonezilla") { return "Clonezilla.iso" }

    return $OriginalName
}

function New-Shortcut {
    <#
    .SYNOPSIS
        Creates a Windows shortcut (.lnk file)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetPath,
        [Parameter(Mandatory=$true)]
        [string]$ShortcutPath,
        [string]$WorkingDirectory = "",
        [string]$Description = ""
    )

    try {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $TargetPath

        if ($WorkingDirectory) {
            $Shortcut.WorkingDirectory = $WorkingDirectory
        } else {
            $Shortcut.WorkingDirectory = Split-Path $TargetPath -Parent
        }

        if ($Description) {
            $Shortcut.Description = $Description
        }

        $Shortcut.Save()
        Write-Log "  Created shortcut: $(Split-Path $ShortcutPath -Leaf)" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "  Failed to create shortcut: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Get-MainExecutable {
    <#
    .SYNOPSIS
        Finds the main executable in a portable app folder
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FolderPath,
        [Parameter(Mandatory=$true)]
        [string]$AppName
    )

    # Known main executables for specific apps
    $knownExes = @{
        "putty" = "putty.exe"
        "notepadpp" = "notepad++.exe"
        "notepad" = "notepad++.exe"
        "everything" = "Everything.exe"
        "7zip" = "7zFM.exe"
        "cpuz" = "cpuz_x64.exe"
        "hwinfo" = "HWiNFO64.exe"
        "crystaldiskinfo" = "DiskInfo64.exe"
        "crystaldiskmark" = "DiskMark64.exe"
        "sysinternals" = "procexp64.exe"
        "rufus" = "rufus.exe"
        "balena" = "balenaEtcher.exe"
        "etcher" = "balenaEtcher.exe"
        "qbittorrent" = "qbittorrent.exe"
        "vlc" = "vlc.exe"
        "windirstat" = "windirstat.exe"
        "keepassxc" = "KeePassXC.exe"
        "keepass" = "KeePassXC.exe"
        "wireshark" = "Wireshark.exe"
        "pdfsam" = "pdfsam.exe"
        "nmap" = "nmap.exe"
        "angryipscanner" = "ipscan.exe"
        "angry" = "ipscan.exe"
        "advancedportscanner" = "advanced_port_scanner.exe"
        "treesize" = "TreeSizeFree.exe"
        "winmtr" = "WinMTR.exe"
        "recuva" = "recuva64.exe"
        "speccy" = "Speccy64.exe"
        "hxd" = "HxD.exe"
        "hex" = "HxD.exe"
        "winscp" = "WinSCP.exe"
        "processhacker" = "ProcessHacker.exe"
        "imdisk" = "imdisk.exe"
    }

    # Check for known executable
    $appKey = $AppName.ToLower() -replace '[^a-z0-9]', ''
    if ($knownExes.ContainsKey($appKey)) {
        $knownExePath = Join-Path $FolderPath $knownExes[$appKey]
        if (Test-Path $knownExePath) {
            return $knownExePath
        }
    }

    # Find largest .exe file (usually the main app)
    $exeFiles = Get-ChildItem -Path $FolderPath -Filter "*.exe" -File -ErrorAction SilentlyContinue
    if ($exeFiles) {
        $mainExe = $exeFiles | Sort-Object Length -Descending | Select-Object -First 1
        return $mainExe.FullName
    }

    return $null
}

function Reorganize-PortableApp {
    <#
    .SYNOPSIS
        Reorganizes portable app into Files subfolder and creates shortcut
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppPath,
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        [Parameter(Mandatory=$true)]
        [string]$PortableRoot
    )

    try {
        # Validate input parameters
        if ([string]::IsNullOrWhiteSpace($AppPath)) {
            throw "AppPath parameter is empty for app: $AppName"
        }
        if ([string]::IsNullOrWhiteSpace($PortableRoot)) {
            throw "PortableRoot parameter is empty for app: $AppName"
        }

        $appBaseName = Split-Path $AppPath -Leaf
        $filesSubfolder = Join-Path $PortableRoot "Files"
        $newAppPath = Join-Path $filesSubfolder $appBaseName

        # Create Files subfolder if it doesn't exist
        if (-not (Test-Path $filesSubfolder)) {
            New-Item -ItemType Directory -Path $filesSubfolder -Force | Out-Null
        }

        # Move app to Files subfolder if not already there
        if ($AppPath -ne $newAppPath -and (Test-Path $AppPath)) {
            if (Test-Path $newAppPath) {
                Remove-Item $newAppPath -Recurse -Force
            }
            Move-Item -Path $AppPath -Destination $newAppPath -Force
            Write-Log "  Moved to Files subfolder: $appBaseName" -Level INFO
        }

        # Find main executable
        $mainExe = Get-MainExecutable -FolderPath $newAppPath -AppName $AppName

        if ($mainExe) {
            # Create shortcut in portable root
            $shortcutName = "$AppName.lnk"
            $shortcutPath = Join-Path $PortableRoot $shortcutName
            New-Shortcut -TargetPath $mainExe -ShortcutPath $shortcutPath -Description $AppName
            return $true
        } else {
            Write-Log "  No executable found for $AppName" -Level WARN
            return $false
        }
    }
    catch {
        Write-Log "  Failed to reorganize $AppName : $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Invoke-FidoDownload {
    <#
    .SYNOPSIS
        Downloads Windows ISO using Fido.ps1
    #>
    param(
        [string]$Edition,      # Win10Pro, Win11Pro, Win10LTSC, Win11LTSC
        [string]$Destination,
        [string]$Language = "English"  # Language variant
    )

    Write-Log "  Starting Fido download for $Edition..." -Level INFO

    # Check if ISO already exists in destination (manual download or previous run)
    # Match specific edition to avoid Win10 finding Win11 or vice versa
    $searchPattern = switch ($Edition) {
        "Win10Pro" { "Win10_*.iso" }
        "Win11Pro" { "Win11_OEM*.iso" }  # Match only stock Win11 (OEM), not modded
        default { "Win*.iso" }
    }

    $existingISOs = Get-ChildItem -Path $Destination -Filter $searchPattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

    if ($existingISOs) {
        Write-Log "  Found existing Windows ISO: $($existingISOs[0].Name)" -Level SUCCESS
        Write-Log "  Skipping download, using existing file" -Level INFO
        return $existingISOs[0].FullName
    }

    # Get or download Fido.ps1
    $fidoPath = Get-FidoScript

    # Configure download based on edition
    $fidoArgs = @()
    $expectedFileName = ""

    switch ($Edition) {
        "Win10Pro" {
            $fidoArgs = @("-Win", "10", "-Ed", "Pro", "-Lang", $Language, "-Arch", "x64", "-NoConfirm")
            $expectedFileName = "Win10_*.iso"
        }
        "Win11Pro" {
            $fidoArgs = @("-Win", "11", "-Ed", "Pro", "-Lang", $Language, "-Arch", "x64", "-NoConfirm")
            $expectedFileName = "Win11_*.iso"
        }
        "Win10LTSC" {
            # LTSC handled separately via direct download
            Write-Log "  Win10LTSC uses direct download, not Fido" -Level WARN
            return $null
        }
        "Win11LTSC" {
            # LTSC handled separately via direct download
            Write-Log "  Win11LTSC uses direct download, not Fido" -Level WARN
            return $null
        }
        default {
            Write-Log "  Unknown edition: $Edition" -Level ERROR
            return $null
        }
    }

    Write-Log "  Fido command: Fido.ps1 $($fidoArgs -join ' ')" -Level INFO
    Write-Log "  Download destination: $Destination" -Level INFO

    try {
        # Run Fido in the destination directory (VENTOY partition) directly
        # This avoids unnecessary copying from staging to final destination
        if (-not (Test-Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }

        $fidoProcess = Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-ExecutionPolicy Bypass -File `"$fidoPath`" $($fidoArgs -join ' ')" `
            -WorkingDirectory $Destination `
            -NoNewWindow -Wait -PassThru

        if ($fidoProcess.ExitCode -ne 0) {
            Write-Log "  Fido exited with code: $($fidoProcess.ExitCode)" -Level ERROR

            if ($fidoProcess.ExitCode -eq 3) {
                Write-Log "  Microsoft is blocking the download. This could be due to:" -Level WARN
                Write-Log "    - VPN/Proxy usage (disable VPN and try again)" -Level WARN
                Write-Log "    - Rate limiting (wait 10-15 minutes)" -Level WARN
                Write-Log "    - Geographic restrictions" -Level WARN
                Write-Log "  " -Level INFO
                Write-Log "  WORKAROUND: Manually download the ISO and place it in the destination folder" -Level INFO
                Write-Log "  The script will detect and use existing ISOs automatically" -Level INFO
            }

            return $null
        }

        # Find the downloaded ISO in the destination directory
        $isoFiles = Get-ChildItem -Path $Destination -Filter "*.iso" | Sort-Object LastWriteTime -Descending

        if ($isoFiles.Count -eq 0) {
            Write-Log "  No ISO file found after Fido download" -Level ERROR
            return $null
        }

        $downloadedIso = $isoFiles[0].FullName
        $sizeGB = [math]::Round($isoFiles[0].Length / 1GB, 2)
        Write-Log ('  Downloaded: {0} ({1} gigabytes)' -f $isoFiles[0].Name, $sizeGB) -Level SUCCESS

        return $downloadedIso
    }
    catch {
        Write-Log "  Fido download failed: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Expand-Archive7z {
    param(
        [string]$ArchivePath,
        [string]$DestinationPath
    )

    # Find 7z executable (either just downloaded or system-installed)
    $7zExe = $null

    # Check staging directory first
    $stagingPaths = @(
        (Join-Path $script:StagingDir "7zip\7z.exe"),
        (Join-Path $script:StagingDir "7zip\x64\7z.exe")
    )

    foreach ($path in $stagingPaths) {
        if (Test-Path $path) {
            $7zExe = $path
            break
        }
    }

    # Check system installation
    if (-not $7zExe) {
        $systemPaths = @(
            "${env:ProgramFiles}\7-Zip\7z.exe",
            "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
        )

        foreach ($path in $systemPaths) {
            if (Test-Path $path) {
                $7zExe = $path
                break
            }
        }
    }

    if (-not $7zExe) {
        throw "7-Zip not found. Cannot extract .7z archive: $ArchivePath"
    }

    Write-Log "Extracting with 7-Zip: $ArchivePath"

    $extractDir = Split-Path -Parent $DestinationPath
    if (-not (Test-Path $extractDir)) {
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
    }

    $arguments = "x `"$ArchivePath`" -o`"$extractDir`" -y"
    $process = Start-Process -FilePath $7zExe -ArgumentList $arguments -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -ne 0) {
        throw "7-Zip extraction failed with exit code: $($process.ExitCode)"
    }

    Write-Log "  Extraction complete" -Level SUCCESS
}

# ============================================================================
# DISK SELECTION & PARTITIONING
# ============================================================================

function Get-CandidateDisks {
    Write-Log "Scanning for candidate USB drives..."

    $disks = Get-Disk | Where-Object {
        # Filter: USB bus type OR removable AND minimum 128GB drive size
        # No upper size limit - support all large drives (1TB, 2TB, etc.)
        ($_.BusType -eq 'USB' -or $_.BusType -eq 'SCSI') -and
        $_.Size -gt 111GB -and
        -not $_.IsBoot -and
        -not $_.IsSystem
    }

    $candidates = @()

    foreach ($disk in $disks) {
        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue

        $candidates += [PSCustomObject]@{
            DiskNumber = $disk.Number
            Size = Get-FriendlySize $disk.Size
            SizeBytes = $disk.Size
            BusType = $disk.BusType
            FriendlyName = $disk.FriendlyName
            PartitionCount = ($partitions | Measure-Object).Count
            IsBoot = $disk.IsBoot
            IsSystem = $disk.IsSystem
            PartitionStyle = $disk.PartitionStyle
            PhysicalPath = "\\.\PhysicalDrive$($disk.Number)"
        }
    }

    Write-Log "Found $($candidates.Count) candidate disk(s)"
    return $candidates
}

function Show-DiskSelectionGUI {
    param([array]$Candidates)

    if ($Candidates.Count -eq 0) {
        throw "No candidate USB drives found. Please connect a USB drive (100+ gigabytes, under 2 terabytes) and try again."
    }

    # Try Out-GridView first (best UX)
    if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
        Write-Log "Showing GUI disk selector..."

        $selected = $Candidates | Out-GridView -Title "Select USB Drive to FORMAT (ALL DATA WILL BE LOST)" -PassThru

        if (-not $selected) {
            throw "No disk selected. Operation cancelled."
        }

        return $selected
    }
    else {
        # Fallback to console TUI
        Write-Log "Out-GridView not available, using console menu" -Level WARN

        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Yellow
        Write-Host "  CANDIDATE USB DRIVES - SELECT ONE TO FORMAT (ALL DATA WILL BE LOST)" -ForegroundColor Yellow
        Write-Host "============================================================================" -ForegroundColor Yellow
        Write-Host ""

        for ($i = 0; $i -lt $Candidates.Count; $i++) {
            $disk = $Candidates[$i]
            Write-Host "[$i] " -NoNewline -ForegroundColor Cyan
            Write-Host "Disk $($disk.DiskNumber) - " -NoNewline
            Write-Host "$($disk.Size) " -NoNewline -ForegroundColor Green
            Write-Host "- $($disk.FriendlyName) " -NoNewline
            Write-Host "($($disk.BusType), $($disk.PartitionCount) partitions)"
        }

        Write-Host ""
        Write-Host "[Q] Cancel and exit" -ForegroundColor Red
        Write-Host ""

        do {
            $choice = Read-Host "Enter disk number (0-$($Candidates.Count - 1)) or Q to cancel"

            if ($choice -eq 'Q' -or $choice -eq 'q') {
                throw "Operation cancelled by user."
            }

            $index = $null
            if ([int]::TryParse($choice, [ref]$index)) {
                if ($index -ge 0 -and $index -lt $Candidates.Count) {
                    return $Candidates[$index]
                }
            }

            Write-Host "Invalid selection. Try again." -ForegroundColor Red
        } while ($true)
    }
}

function Confirm-DiskWipe {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Disk,

        [switch]$Force
    )

    if ($Force) {
        Write-Log "Force mode enabled, skipping confirmation" -Level WARN
        return $true
    }

    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host "  WARNING: ALL DATA WILL BE ERASED" -ForegroundColor Red
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Selected disk:" -ForegroundColor Yellow
    Write-Host "  Disk:      $($Disk.PhysicalPath)" -ForegroundColor Cyan
    Write-Host "  Name:      $($Disk.FriendlyName)" -ForegroundColor Cyan
    Write-Host "  Size:      $($Disk.Size)" -ForegroundColor Cyan
    Write-Host ""

    # Try to use GUI message box, fall back to console
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Proceed with formatting $($Disk.PhysicalPath)?`n`nName: $($Disk.FriendlyName)`nSize: $($Disk.Size)`n`nALL DATA WILL BE ERASED!",
            "Confirm Format",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )

        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Write-Log "User confirmed disk wipe (GUI)" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "Operation cancelled by user (GUI)" -Level WARN
            return $false
        }
    }
    catch {
        # Fallback to console
        Write-Log "GUI not available, using console prompt" -Level WARN
        $response = Read-Host "Proceed with format? (yes/no)"

        if ($response -eq "yes" -or $response -eq "y") {
            Write-Log "User confirmed disk wipe" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "Operation cancelled by user" -Level WARN
            return $false
        }
    }
}

function Test-ExistingBrandoToolkit {
    param(
        [Parameter(Mandatory)]
        [int]$DiskNumber
    )

    Write-Log "Checking for existing Brandos Toolkit installation..."

    $partitions = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue
    $volumes = @()

    foreach ($part in $partitions) {
        if ($part.DriveLetter) {
            $vol = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
            if ($vol) {
                $volumes += $vol
            }
        }
    }

    # Look for characteristic brando's toolkit volumes (VENTOY, UTILS, FILES)
    $hasVentoy = $volumes | Where-Object { $_.FileSystemLabel -eq "VENTOY" }
    $hasUtils = $volumes | Where-Object { $_.FileSystemLabel -eq "UTILS" }
    $hasFILES = $volumes | Where-Object { $_.FileSystemLabel -eq "FILES" }

    if ($hasVentoy -or $hasUtils -or $hasFILES) {
        Write-Log "  Found existing brando's toolkit partitions:" -Level WARN
        if ($hasVentoy) { Write-Log "    - VENTOY: $($hasVentoy.DriveLetter):\" -Level WARN }
        if ($hasUtils) { Write-Log "    - UTILS: $($hasUtils.DriveLetter):\" -Level WARN }
        if ($hasFILES) { Write-Log "    - FILES: $($hasFILES.DriveLetter):\" -Level WARN }

        return @{
            Exists = $true
            Ventoy = $hasVentoy
            Utils = $hasUtils
            FILES = $hasFILES
        }
    }

    return @{ Exists = $false }
}

function Initialize-BrandoToolkit {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$SelectedDisk,

        [Parameter(Mandatory)]
        [hashtable]$Settings
    )

    $diskNumber = $SelectedDisk.DiskNumber
    Write-Log "Initializing brando's toolkit on Disk $diskNumber..."

    # Step 1: Clean the disk
    Write-Log "Step 1/5: Cleaning disk..."
    try {
        Clear-Disk -Number $diskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
        Write-Log "  Disk cleaned" -Level SUCCESS
    }
    catch {
        Write-Log "  Clean-Disk failed: $($_.Exception.Message)" -Level ERROR
        throw
    }

    Start-Sleep -Seconds 2

    # Step 2: Initialize as GPT (force conversion if needed)
    Write-Log "Step 2/5: Initializing disk as GPT..."
    try {
        $disk = Get-Disk -Number $diskNumber

        if ($disk.PartitionStyle -eq 'RAW') {
            # Disk is RAW, initialize as GPT
            Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop
            Write-Log "  Disk initialized as GPT" -Level SUCCESS
        }
        elseif ($disk.PartitionStyle -eq 'MBR') {
            # Disk is MBR, use diskpart to convert to GPT
            Write-Log "  Disk is MBR, converting to GPT via diskpart..." -Level WARN

            # Use diskpart to convert MBR to GPT
            $diskpartScript = @"
select disk $diskNumber
clean
convert gpt
"@
            $tempFile = Join-Path $env:TEMP "diskpart_convert.txt"
            Set-Content -Path $tempFile -Value $diskpartScript -Encoding ASCII

            $diskpartProcess = Start-Process -FilePath "diskpart.exe" -ArgumentList "/s `"$tempFile`"" -Wait -PassThru -NoNewWindow
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

            if ($diskpartProcess.ExitCode -eq 0) {
                Write-Log "  Disk converted to GPT" -Level SUCCESS
                Start-Sleep -Seconds 2
            }
            else {
                throw "Diskpart conversion failed with exit code: $($diskpartProcess.ExitCode)"
            }
        }
        elseif ($disk.PartitionStyle -eq 'GPT') {
            Write-Log "  Disk already initialized as GPT" -Level SUCCESS
        }
        else {
            throw "Unknown partition style: $($disk.PartitionStyle)"
        }
    }
    catch {
        Write-Log "  Disk initialization failed: $($_.Exception.Message)" -Level ERROR
        throw
    }

    Start-Sleep -Seconds 2

    # Step 3: Download and install Ventoy
    Write-Log "Step 3/5: Installing Ventoy..."
    $ventoyInfo = Install-Ventoy -DiskNumber $diskNumber -Settings $Settings

    # Step 4: Create UTILS partition
    Write-Log "Step 4/5: Creating UTILS partition..."
    $utilsSizeBytes = [int64]($Settings.utils_gb * 1GB)

    try {
        # Create partition WITHOUT drive letter to prevent Explorer popup
        $utilsPartition = New-Partition -DiskNumber $diskNumber -Size $utilsSizeBytes -ErrorAction Stop
        Start-Sleep -Seconds 1

        # Format the partition while it has no drive letter (prevents "needs formatting" popup)
        $utilsVolume = Format-Volume -Partition $utilsPartition -FileSystem exFAT -NewFileSystemLabel "UTILS" -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 1

        # Now assign drive letter after formatting
        $utilsPartition | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop
        Start-Sleep -Seconds 1

        # Refresh partition info to get the assigned drive letter
        $utilsPartition = Get-Partition -DiskNumber $diskNumber -PartitionNumber $utilsPartition.PartitionNumber
        $utilsLetter = $utilsPartition.DriveLetter

        $friendlySize = Get-FriendlySize $utilsSizeBytes
        Write-Log "  UTILS partition created: ${utilsLetter}:\ ($friendlySize)" -Level SUCCESS
    }
    catch {
        Write-Log "  Failed to create UTILS partition: $($_.Exception.Message)" -Level ERROR
        throw
    }

    # Step 5: Create FILES partition (use remaining space)
    Write-Log "Step 5/5: Creating FILES partition..."

    try {
        # Create partition WITHOUT drive letter to prevent Explorer popup
        $FILESPartition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -ErrorAction Stop
        Start-Sleep -Seconds 1

        # Format the partition while it has no drive letter (prevents "needs formatting" popup)
        $FILESVolume = Format-Volume -Partition $FILESPartition -FileSystem exFAT -NewFileSystemLabel "FILES" -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 1

        # Now assign drive letter after formatting
        $FILESPartition | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop
        Start-Sleep -Seconds 1

        # Refresh partition info to get the assigned drive letter
        $FILESPartition = Get-Partition -DiskNumber $diskNumber -PartitionNumber $FILESPartition.PartitionNumber
        $FILESLetter = $FILESPartition.DriveLetter

        $friendlySize = Get-FriendlySize $FILESPartition.Size
        Write-Log "  FILES partition created: ${FILESLetter}:\ ($friendlySize)" -Level SUCCESS
    }
    catch {
        Write-Log "  Failed to create FILES partition: $($_.Exception.Message)" -Level ERROR
        throw
    }

    Write-Log "Partitioning complete!" -Level SUCCESS

    return @{
        DiskNumber = $diskNumber
        VentoyLetter = $ventoyInfo.Letter
        UtilsLetter = $utilsLetter
        FILESLetter = $FILESLetter
        VentoySize = $ventoyInfo.Size
        UtilsSize = $utilsSizeBytes
        FILESSize = $FILESPartition.Size
    }
}

function Install-Ventoy {
    param(
        [int]$DiskNumber,
        [hashtable]$Settings
    )

    # Download Ventoy if not already present
    $ventoyExe = Join-Path $script:VentoyDir "Ventoy2Disk.exe"

    if (-not (Test-Path $ventoyExe)) {
        Write-Log "Downloading Ventoy..."

        try {
            $release = Invoke-GitHubAPI -Endpoint "/repos/ventoy/Ventoy/releases/latest"
            $asset = $release.assets | Where-Object { $_.name -match 'ventoy-.*-windows\.zip$' } | Select-Object -First 1

            if (-not $asset) {
                throw "Ventoy Windows release not found"
            }

            $ventoyZip = Join-Path $script:StagingDir "ventoy.zip"

            Invoke-FileDownload -Url $asset.browser_download_url -Destination $ventoyZip -DisplayName "Ventoy" -ExpectedSize $asset.size

            Write-Log "Extracting Ventoy..."
            Expand-Archive -Path $ventoyZip -DestinationPath $script:VentoyDir -Force

            # Find Ventoy2Disk.exe in extracted structure
            $ventoyExe = Get-ChildItem -Path $script:VentoyDir -Filter "Ventoy2Disk.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName

            if (-not $ventoyExe) {
                throw "Ventoy2Disk.exe not found in extracted archive"
            }

            # Update ventoyDir to actual location
            $script:VentoyDir = Split-Path -Parent $ventoyExe

            Write-Log "  Ventoy extracted to: $script:VentoyDir" -Level SUCCESS
        }
        catch {
            Write-Log "Failed to download/extract Ventoy: $($_.Exception.Message)" -Level ERROR
            throw
        }
    }

    # Calculate reserve space (UTILS + FILES combined, in MB)
    # Reserve = Total Drive Size - Ventoy Size - Overhead
    # This ensures FILES gets ALL remaining space after Ventoy and Utils
    $disk = Get-Disk -Number $DiskNumber
    $totalDriveSizeGB = [math]::Round($disk.Size / 1GB, 2)
    $ventoyGB = $Settings.ventoy_gb
    # GPT overhead: ~34MB for partition table + 1GB safety margin for alignment
    $ventoyOverheadGB = 2
    
    # Reserve = everything except Ventoy partition
    $reserveGB = $totalDriveSizeGB - $ventoyGB - $ventoyOverheadGB
    $reserveMB = [int]($reserveGB * 1024)

    # Install Ventoy
    Write-Log "Installing Ventoy to \\.\PhysicalDrive${DiskNumber}..."
    Write-Log ('  Flags: GPT, Secure Boot enabled, Reserve {0} MB ({1} GB)' -f $reserveMB, [math]::Round($reserveMB/1024, 2))

    try {
        # Use Ventoy CLI mode (documented at https://www.ventoy.net/en/doc_windows_cli.html)
        # Format: Ventoy2Disk.exe VTOYCLI /I /PhyDrive:X [options]
        $cliArgs = @(
            "VTOYCLI",
            "/I",
            "/PhyDrive:$DiskNumber",
            "/GPT",           # Use GPT partition style
            "/R:$reserveMB"   # Reserve space in MB
        )

        # Don't add /NOSB - we WANT Secure Boot support (enabled by default)

        $argsString = $cliArgs -join " "
        Write-Log "  Running: Ventoy2Disk.exe $argsString"

        # Run Ventoy in CLI mode
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $ventoyExe
        $processInfo.Arguments = $argsString
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $false  # Show window for progress
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.WorkingDirectory = $script:VentoyDir

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        $process.Start() | Out-Null

        # Read output in real-time
        $stdout = ""
        $stderr = ""

        while (-not $process.HasExited) {
            $stdout += $process.StandardOutput.ReadToEnd()
            $stderr += $process.StandardError.ReadToEnd()
            Start-Sleep -Milliseconds 100
        }

        # Read any remaining output
        $stdout += $process.StandardOutput.ReadToEnd()
        $stderr += $process.StandardError.ReadToEnd()

        if ($stdout) {
            Write-Log "  Ventoy output: $stdout"
        }

        if ($stderr -and $stderr.Trim() -ne "") {
            Write-Log "  Ventoy stderr: $stderr" -Level WARN
        }

        if ($process.ExitCode -ne 0) {
            throw "Ventoy CLI installation failed with exit code: $($process.ExitCode)"
        }

        Write-Log "  Ventoy installed successfully via CLI" -Level SUCCESS

        # Verify installation
        Start-Sleep -Seconds 3

        # Wait for partition to appear and get drive letter
        Start-Sleep -Seconds 5

        # Find the Ventoy data partition (largest partition)
        $ventoyPartition = Get-Partition -DiskNumber $DiskNumber | Where-Object { $_.Type -eq 'Basic' } | Sort-Object -Property Size -Descending | Select-Object -First 1

        if ($ventoyPartition) {
            if (-not $ventoyPartition.DriveLetter) {
                Write-Log "  Assigning drive letter to Ventoy partition..."
                $ventoyPartition = Add-PartitionAccessPath -DiskNumber $DiskNumber -PartitionNumber $ventoyPartition.PartitionNumber -AssignDriveLetter -PassThru
                Start-Sleep -Seconds 2
            }

            $ventoyLetter = $ventoyPartition.DriveLetter
            $friendlySize = Get-FriendlySize $ventoyPartition.Size
            Write-Log "  Ventoy partition: ${ventoyLetter}:\ ($friendlySize)" -Level SUCCESS

            return @{
                Letter = $ventoyLetter
                Size = $ventoyPartition.Size
            }
        }
        else {
            throw "Could not find Ventoy data partition after installation"
        }
    }
    catch {
        Write-Log "  Ventoy installation error: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# ============================================================================
# FOLDER STRUCTURE
# ============================================================================

function Initialize-FolderStructure {
    param(
        [hashtable]$DriveInfo
    )

    Write-Log "Creating folder structure..."

    $ventoyRoot = "$($DriveInfo.VentoyLetter):\"
    $utilsRoot = "$($DriveInfo.UtilsLetter):\"

    # VENTOY structure
    $ventoyFolders = @(
        "ISO\Windows",
        "ISO\Linux",
        "ISO\Tools",
        "ISO\_Meta"
    )

    foreach ($folder in $ventoyFolders) {
        $path = Join-Path $ventoyRoot $folder
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Log "  Created: $path"
    }

    # UTILS structure
    $utilsFolders = @(
        "Portable",
        "Installers",
        "Drivers\Storage",
        "Drivers\Networking",
        "Drivers\Bluetooth",
        "Scripts",
        "Extensions",
        "Docs\Logs",
        "_Meta"
    )

    foreach ($folder in $utilsFolders) {
        $path = Join-Path $utilsRoot $folder
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Log "  Created: $path"
    }

    Write-Log "Folder structure created" -Level SUCCESS

    return @{
        VentoyRoot = $ventoyRoot
        UtilsRoot = $utilsRoot
        FILESRoot = "$($DriveInfo.FILESLetter):\"
    }
}

function New-HelperScripts {
    <#
    .SYNOPSIS
    Creates helper batch scripts in the Scripts folder.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ScriptsPath
    )

    Write-Log "Creating helper scripts..."

    # ChrisTitusTech.cmd - Windows utility script
    $cttContent = @'
@echo off
rem Run PowerShell elevated and execute the remote script
powershell -NoProfile -Command "Start-Process PowerShell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','irm https://christitus.com/win | iex'"
'@

    $cttPath = Join-Path $ScriptsPath "ChrisTitusTech.cmd"
    try {
        Set-Content -Path $cttPath -Value $cttContent -Encoding ASCII -ErrorAction Stop
        Write-Log "  Created: ChrisTitusTech.cmd" -Level SUCCESS
    }
    catch {
        Write-Log "  Failed to create ChrisTitusTech.cmd: $_" -Level ERROR
    }

    # Activate.cmd - Windows activation script
    $activateContent = @'
@echo off
rem Run PowerShell elevated and execute the remote script
powershell -NoProfile -Command "Start-Process PowerShell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','irm https://get.activated.win | iex'"
'@

    $activatePath = Join-Path $ScriptsPath "Activate.cmd"
    try {
        Set-Content -Path $activatePath -Value $activateContent -Encoding ASCII -ErrorAction Stop
        Write-Log "  Created: Activate.cmd" -Level SUCCESS
    }
    catch {
        Write-Log "  Failed to create Activate.cmd: $_" -Level ERROR
    }
}

# ============================================================================
# DOWNLOAD & PROVISIONING
# ============================================================================

function Start-Provisioning {
    param(
        [hashtable]$Config,
        [hashtable]$Folders
    )

    Write-Log "Starting provisioning phase..."

    if ($Skip.Count -gt 0) {
        Write-Log "Skipping categories: $($Skip -join ', ')" -Level WARN
    }

    $items = $Config.items
    $totalItems = ($items | Where-Object { -not $_.flags.manual }).Count
    $processed = 0
    $succeeded = 0
    $failed = 0
    $skipped = 0

    foreach ($item in $items) {
        $processed++

        # Calculate overall progress percentage
        $overallPercent = [math]::Round(($processed / $totalItems) * 100, 1)

        Write-Host ""
        Write-Host "[$processed/$totalItems - $overallPercent%] $($item.name)" -ForegroundColor Cyan
        Write-Host ("=" * 80) -ForegroundColor DarkGray

        # Check if manual
        if ($item.flags.manual) {
            Write-Log "  Manual item, skipping download (see README)" -Level WARN
            $skipped++
            continue
        }

        # Check if requires consent
        if ($item.flags.require_consent -and -not $env:TECHDRIVE_CONSENT_DUALUSE) {
            Write-Log "  Requires consent (dual-use tool). Set `$env:TECHDRIVE_CONSENT_DUALUSE=1 to enable." -Level WARN
            $skipped++
            continue
        }

        # Check if category should be skipped
        if ($Skip -contains $item.category) {
            Write-Log "  Skipping (category: $($item.category))" -Level WARN
            $skipped++
            continue
        }

        try {
            # GitHub rate limiting: Add delay between GitHub API calls
            if ($item.resolve.strategy -like "github*") {
                if ($script:lastGitHubDownload) {
                    $timeSinceLastGitHub = (Get-Date) - $script:lastGitHubDownload
                    if ($timeSinceLastGitHub.TotalSeconds -lt 5) {
                        $waitTime = 5 - [math]::Floor($timeSinceLastGitHub.TotalSeconds)
                        Write-Log "  Rate limiting: Waiting $waitTime seconds before GitHub API call..." -Level INFO
                        Start-Sleep -Seconds $waitTime
                    }
                }
                $script:lastGitHubDownload = Get-Date
            }

            # Resolve download URL
            $resolved = Resolve-DownloadUrl -Item $item

            # Special handling for Fido downloads (Windows modded ISOs)
            if ($resolved.requires_fido -eq $true) {
                Write-Log "  This requires Fido.ps1 for Windows ISO download..." -Level INFO

                try {
                    # Determine destination
                    $destBase = if ($item.dest.StartsWith("VENTOY:")) {
                        $item.dest -replace "^VENTOY:", $Folders.VentoyRoot
                    } else {
                        $item.dest -replace "^UTILS:", $Folders.UtilsRoot
                    }

                    # Ensure destination exists
                    if (-not (Test-Path $destBase)) {
                        New-Item -ItemType Directory -Path $destBase -Force | Out-Null
                    }

                    # Download using Fido
                    $lang = if ($resolved.language) { $resolved.language } else { "English" }
                    $downloadedIso = Invoke-FidoDownload -Edition $resolved.edition -Destination $destBase -Language $lang

                    if ($downloadedIso -and (Test-Path $downloadedIso)) {
                        Write-Log "  Windows ISO downloaded successfully!" -Level SUCCESS

                        # Apply standardized filename
                        $standardizedName = Get-StandardizedFilename -OriginalName $resolved.filename -ItemName $item.name
                        $finalPath = Join-Path $destBase $standardizedName

                        if ($downloadedIso -ne $finalPath) {
                            if (Test-Path $finalPath) {
                                Remove-Item $finalPath -Force
                            }
                            Move-Item -Path $downloadedIso -Destination $finalPath -Force
                        }

                        Write-Log "  Saved as: $standardizedName" -Level SUCCESS

                        # If this needs modding, create modded version too
                        if ($resolved.requires_modding -eq $true) {
                            Write-Host ""
                            Write-Log "  Creating modded version with TPM/SecureBoot bypasses..." -Level INFO

                            $moddedISO = Invoke-ISOModding -SourceISO $finalPath -Destination $destBase

                            if ($moddedISO -and (Test-Path $moddedISO)) {
                                # Rename modded ISO with standardized name
                                $moddedStandardName = Get-StandardizedFilename -OriginalName "Win11_Mod.iso" -ItemName ($item.name -replace "Stock.*", "Modded")
                                $moddedFinalPath = Join-Path $destBase $moddedStandardName
                                if ($moddedISO -ne $moddedFinalPath) {
                                    Move-Item -Path $moddedISO -Destination $moddedFinalPath -Force
                                }

                                Write-Log "  Modded ISO created successfully!" -Level SUCCESS
                                Write-Log "  Stock: $(Split-Path $finalPath -Leaf)" -Level INFO
                                Write-Log "  Modded: $(Split-Path $moddedFinalPath -Leaf)" -Level INFO
                            } else {
                                Write-Log "  Modded ISO creation failed, but stock ISO is available" -Level WARN
                            }
                        }

                        $succeeded++
                    } else {
                        Write-Log "  Fido download failed!" -Level ERROR
                        $failed++
                    }
                } catch {
                    Write-Log "  Failed to download Windows ISO: $($_.Exception.Message)" -Level ERROR
                    $failed++
                }
                continue
            }

            # Determine destination path
            $destBase = if ($item.dest.StartsWith("VENTOY:")) {
                if ([string]::IsNullOrWhiteSpace($Folders.VentoyRoot)) {
                    throw "VentoyRoot is not set - partitions may not be mounted properly"
                }
                $item.dest -replace "^VENTOY:", $Folders.VentoyRoot
            }
            elseif ($item.dest.StartsWith("UTILS:")) {
                if ([string]::IsNullOrWhiteSpace($Folders.UtilsRoot)) {
                    throw "UtilsRoot is not set - partitions may not be mounted properly"
                }
                $item.dest -replace "^UTILS:", $Folders.UtilsRoot
            }
            else {
                throw "Invalid destination prefix: $($item.dest)"
            }

            # Validate destBase is not empty or just a slash
            if ([string]::IsNullOrWhiteSpace($destBase) -or $destBase -match '^[/\\]+$') {
                throw "Invalid destination path generated: destBase='$destBase', item.dest='$($item.dest)', VentoyRoot='$($Folders.VentoyRoot)', UtilsRoot='$($Folders.UtilsRoot)'"
            }

            # Apply filename standardization for ISOs
            $finalFilename = if ($item.category -eq "iso") {
                Get-StandardizedFilename -OriginalName $resolved.filename -ItemName $item.name
            } else {
                $resolved.filename
            }

            $destFile = Join-Path $destBase $finalFilename

            # Check if already exists
            if (Test-Path $destFile) {
                Write-Log "  File already exists, skipping" -Level SUCCESS
                $succeeded++

                # Add to manifest
                $script:Manifest += @{
                    name = $item.name
                    version = $resolved.version
                    source_url = $resolved.url
                    size = (Get-Item $destFile).Length
                    placed_path = $destFile
                    downloaded_at = (Get-Item $destFile).LastWriteTime.ToString("o")
                    status = "existing"
                }

                continue
            }

            # Download to staging
            # Validate filename is not empty
            if ([string]::IsNullOrWhiteSpace($resolved.filename)) {
                throw "Resolved filename is empty! Item: $($item.name), Strategy: $($item.resolve.strategy)"
            }

            $stagingFile = Join-Path $script:StagingDir "downloads\$($resolved.filename)"

            $downloadSuccess = Invoke-FileDownload -Url $resolved.url -Destination $stagingFile -DisplayName $item.name -ExpectedSize $resolved.size

            if (-not $downloadSuccess) {
                throw "Download failed"
            }

            # Handle .iso renaming if needed (for Microsoft OEM links)
            if ($resolved.requires_rename -eq $true) {
                Write-Log "  Renaming downloaded file to .iso extension..." -Level INFO
                # Ensure destination has .iso extension
                if ($destFile -notmatch '\.iso$') {
                    $destFile = [System.IO.Path]::ChangeExtension($destFile, '.iso')
                }
            }

            # Post-processing (extract if needed)
            $finalDest = $destFile

            if ($item.post -contains "unzip") {
                Write-Log "  Extracting ZIP archive..."
                $extractDir = Split-Path -Parent $destFile
                Expand-Archive -Path $stagingFile -DestinationPath $extractDir -Force
                $finalDest = $extractDir
            }
            elseif ($item.post -contains "extract7z") {
                Write-Log "  Extracting 7z archive..."
                $extractDir = Split-Path -Parent $destFile
                Expand-Archive7z -ArchivePath $stagingFile -DestinationPath $extractDir
                $finalDest = $extractDir
            }
            elseif ($item.post -contains "extract_rst") {
                Write-Log "  Extracting Intel RST drivers..."
                $extractDir = Join-Path (Split-Path -Parent $destFile) "RST_Extracted"

                # Copy the EXE to destination first
                $destDir = Split-Path -Parent $destFile
                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                Copy-Item -Path $stagingFile -Destination $destFile -Force

                # Extract drivers using Intel RST's built-in extraction
                try {
                    $extractArgs = "-extractdrivers `"$extractDir`""
                    Write-Log "  Running: SetupRST.exe $extractArgs" -Level INFO
                    $process = Start-Process -FilePath $destFile -ArgumentList $extractArgs -Wait -PassThru -NoNewWindow

                    if ($process.ExitCode -eq 0 -and (Test-Path $extractDir)) {
                        Write-Log "  Drivers extracted to: $extractDir" -Level SUCCESS
                    } else {
                        Write-Log "  Driver extraction may have failed (exit code: $($process.ExitCode))" -Level WARN
                    }
                } catch {
                    Write-Log "  Could not extract drivers: $($_.Exception.Message)" -Level WARN
                }
            }
            else {
                # Copy to final destination
                # Validate destFile before processing
                if ([string]::IsNullOrWhiteSpace($destFile)) {
                    throw "destFile is empty! Item: $($item.name), destBase: '$destBase', finalFilename: '$finalFilename'"
                }

                $destDir = Split-Path -Parent $destFile

                # Validate destDir after split
                if ([string]::IsNullOrWhiteSpace($destDir)) {
                    throw "destDir is empty after Split-Path! Item: $($item.name), destFile: '$destFile'"
                }

                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }

                # Validate staging file exists
                if ([string]::IsNullOrWhiteSpace($stagingFile)) {
                    throw "stagingFile is empty! Item: $($item.name)"
                }
                if (-not (Test-Path $stagingFile)) {
                    throw "Staging file not found: '$stagingFile'"
                }

                Write-Log "  Copying from staging to destination..." -Level INFO
                Copy-Item -Path $stagingFile -Destination $destFile -Force
            }

            Write-Log "  Placed: $finalDest" -Level SUCCESS

            # Reorganize portable apps and create shortcuts
            if ($item.category -eq "portable") {
                Write-Log "  Organizing portable app..." -Level INFO
                $portableRoot = Join-Path $Folders.UtilsRoot "Portable"

                # Determine what to reorganize based on extraction
                if ($item.post -contains "unzip" -or $item.post -contains "extract7z") {
                    # Archive was extracted - find the extracted folder(s)
                    # $finalDest is the extraction directory, need to find actual app folder inside
                    $extractedItems = Get-ChildItem -Path $finalDest -Directory -ErrorAction SilentlyContinue

                    if ($extractedItems.Count -eq 1) {
                        # Single folder extracted - that's the app
                        Reorganize-PortableApp -AppPath $extractedItems[0].FullName -AppName $item.name -PortableRoot $portableRoot | Out-Null
                    } elseif ($extractedItems.Count -gt 1) {
                        # Multiple folders/files extracted - extraction dir itself is the app
                        Write-Log "  Multiple items extracted, treating extraction directory as app root" -Level INFO
                        # Don't reorganize if already in Portable root - would try to move parent into child
                        if ($finalDest -ne $portableRoot) {
                            Reorganize-PortableApp -AppPath $finalDest -AppName $item.name -PortableRoot $portableRoot | Out-Null
                        } else {
                            Write-Log "  Already in portable root, skipping reorganization" -Level WARN
                        }
                    } else {
                        Write-Log "  No folders found after extraction" -Level WARN
                    }
                } else {
                    # Single-file portable (exe/msi without extraction)
                    # Already placed in correct location, no reorganization needed
                    Write-Log "  Portable executable placed: $(Split-Path $finalDest -Leaf)" -Level SUCCESS
                }
            }

            # Add to manifest
            $script:Manifest += @{
                name = $item.name
                version = $resolved.version
                source_url = $resolved.url
                size = (Get-Item $stagingFile).Length
                placed_path = $finalDest
                downloaded_at = (Get-Date).ToString("o")
                status = "downloaded"
            }

            $succeeded++
        }
        catch {
            Write-Log "  Failed: $($_.Exception.Message)" -Level ERROR
            $failed++
        }
    }

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "Provisioning Summary:" -ForegroundColor Green
    Write-Host "  Total items:  $totalItems" -ForegroundColor Cyan
    Write-Host "  Succeeded:    $succeeded" -ForegroundColor Green
    Write-Host "  Failed:       $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Gray" })
    Write-Host "  Skipped:      $skipped" -ForegroundColor Yellow
    Write-Host ("=" * 80) -ForegroundColor Green
}

# ============================================================================
# VENTOY MENU CONFIGURATION
# ============================================================================

function New-VentoyMenu {
    param(
        [string]$VentoyRoot
    )

    Write-Log "Generating Ventoy menu configuration..."

    $menuConfig = @{
        theme = @{
            display_mode = "GUI"
            serial_param = "--unit=0 --speed=9600"
            ventoy_left = "5%"
            ventoy_top = "95%"
            ventoy_color = "#0000ff"
        }
        menu_alias = @(
            @{
                parent = "/ISO/Windows"
                title = "Windows ISOs"
                class = "group"
            }
            @{
                parent = "/ISO/Linux"
                title = "Linux ISOs"
                class = "group"
            }
            @{
                parent = "/ISO/Tools"
                title = "Rescue & Utility ISOs"
                class = "group"
            }
        )
        menu_tip = @{
            left = "50%"
            top = "90%"
            color = "#ffffff"
            tips = @(
                @{ image = "/ISO/Windows/*"; tip = "Boot Windows installer" }
                @{ image = "/ISO/Linux/*"; tip = "Boot Linux live environment" }
                @{ image = "/ISO/Tools/*"; tip = "Boot rescue or utility tool" }
            )
        }
    } | ConvertTo-Json -Depth 10

    $menuPath = Join-Path $VentoyRoot "ISO\_Meta\ventoy.json"
    Set-Content -Path $menuPath -Value $menuConfig -Encoding UTF8

    Write-Log "  Ventoy menu saved: $menuPath" -Level SUCCESS
}

# ============================================================================
# MANIFEST GENERATION
# ============================================================================

function Export-Manifest {
    param(
        [string]$UtilsRoot
    )

    Write-Log "Exporting manifest..."

    $manifestPath = Join-Path $UtilsRoot "_Meta\manifest.json"

    $manifestData = @{
        generated_at = (Get-Date).ToString("o")
        generator = "make.ps1"
        version = "1.0"
        items = $script:Manifest
    } | ConvertTo-Json -Depth 10

    Set-Content -Path $manifestPath -Value $manifestData -Encoding UTF8

    Write-Log "  Manifest saved: $manifestPath" -Level SUCCESS
    Write-Log "  Total items: $($script:Manifest.Count)" -Level SUCCESS
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  brando's toolkit Builder v1.0" -ForegroundColor Cyan
    Write-Host "  Complete Ventoy-based all-in-one USB provisioning tool" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""

    # Check administrator
    if (-not (Test-Administrator)) {
        Write-Log "This script requires Administrator privileges" -Level ERROR
        throw "Run PowerShell as Administrator and try again"
    }

    # Set default BundleUrl if not provided
    if ([string]::IsNullOrEmpty($BundleUrl)) {
        $BundleUrl = "https://raw.githubusercontent.com/brand-o/tools/main/bundle.json"
    }

    # Set default ConfigPath for fallback
    if ([string]::IsNullOrEmpty($ConfigPath)) {
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $ConfigPath = Join-Path $scriptDir "bundle.json"
    }

    # Load configuration (always try remote first, fall back to local)
    $configJson = $null

    Write-Log "Fetching latest bundle.json from brando.tools..."
    Write-Log "  URL: $BundleUrl"
    try {
        $configJson = Invoke-WebRequest -Uri $BundleUrl -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content
        Write-Log "  Successfully fetched remote bundle.json" -Level SUCCESS
    }
    catch {
        Write-Log "  Failed to fetch remote bundle: $($_.Exception.Message)" -Level WARN
        Write-Log "  Falling back to local ConfigPath: $ConfigPath" -Level WARN
    }

    # Fall back to local file if remote fetch failed
    if ($null -eq $configJson) {
        if (-not (Test-Path $ConfigPath)) {
            Write-Log "Configuration file not found: $ConfigPath" -Level ERROR
            throw "Please ensure bundle.json exists locally or check your internet connection"
        }
        Write-Log "Loading local configuration: $ConfigPath"
        $configJson = Get-Content -Path $ConfigPath -Raw
    }

    $config = $configJson | ConvertFrom-Json

    # Convert to hashtable manually (PS 5.1 compatibility)
    $settings = @{
        ventoy_iso_gb = $config.settings.ventoy_iso_gb
        utils_gb = $config.settings.utils_gb
        partition_rules = @{
            small_drive_threshold_gb = $config.settings.partition_rules.small_drive_threshold_gb
            small_drive = @{
                ventoy_gb = $config.settings.partition_rules.small_drive.ventoy_gb
                utils_gb = $config.settings.partition_rules.small_drive.utils_gb
            }
            large_drive = @{
                ventoy_gb = $config.settings.partition_rules.large_drive.ventoy_gb
                utils_gb = $config.settings.partition_rules.large_drive.utils_gb
            }
        }
    }

    Write-Log "  Partition sizing: Auto (dynamic based on drive size)"

    # Create staging directory
    if (-not (Test-Path $script:StagingDir)) {
        New-Item -ItemType Directory -Path $script:StagingDir -Force | Out-Null
    }

    # TEST MODE: Skip disk operations, use dummy paths
    if ($TestMode) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "TEST MODE ENABLED - Validating URLs Only" -ForegroundColor Cyan
        Write-Host "  No disk operations will be performed" -ForegroundColor Yellow
        Write-Host "  Downloads will validate accessibility only (no full downloads)" -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""

        # Create dummy folder structure for testing
        $testRoot = Join-Path $script:StagingDir "test_mode"
        $Folders = @{
            VentoyRoot = Join-Path $testRoot "VENTOY"
            UtilsRoot = Join-Path $testRoot "UTILS"
            FILESRoot = Join-Path $testRoot "FILES"
        }

        foreach ($folder in $Folders.Values) {
            if (-not (Test-Path $folder)) {
                New-Item -ItemType Directory -Path $folder -Force | Out-Null
            }
        }

        # Skip to download validation
        $Items = $config.items
    }
    else {
        # Normal mode: Disk selection and partitioning
        $candidates = Get-CandidateDisks
        $selectedDisk = Show-DiskSelectionGUI -Candidates $candidates

        # Calculate dynamic partition sizes based on selected drive
        $driveSizeBytes = $selectedDisk.SizeBytes
        $dynamicSizes = Get-DynamicPartitionSizes -DriveSizeBytes $driveSizeBytes -PartitionRules $settings.partition_rules
        $settings.ventoy_iso_gb = $dynamicSizes.ventoy_gb
        $settings.ventoy_gb = $dynamicSizes.ventoy_gb  # Also set ventoy_gb for Install-Ventoy function
        $settings.utils_gb = $dynamicSizes.utils_gb

        # Check for existing brando's toolkit installation
        $existingDrive = Test-ExistingBrandoToolkit -DiskNumber $selectedDisk.DiskNumber

    if ($existingDrive.Exists) {
        Write-Host ""
        Write-Host "EXISTING TECHDRIVE DETECTED!" -ForegroundColor Yellow
        Write-Host "This disk appears to already have brando's toolkit partitions." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Do you want to:" -ForegroundColor Cyan
        Write-Host "  [R] REFORMAT - Wipe and rebuild everything (fresh start)" -ForegroundColor White
        Write-Host "  [K] KEEP - Skip formatting and only update downloads" -ForegroundColor White
        Write-Host ""

        $response = Read-Host "Enter choice (R/K)"

        if ($response -eq 'K' -or $response -eq 'k') {
            Write-Log "User chose to KEEP existing partitions" -Level SUCCESS
            Write-Log "Skipping disk initialization, using existing drive layout..."

            # Build drive info from existing partitions
            $driveInfo = @{
                VentoyLetter = if ($existingDrive.Ventoy) { $existingDrive.Ventoy.DriveLetter } else { $null }
                UtilsLetter = if ($existingDrive.Utils) { $existingDrive.Utils.DriveLetter } else { $null }
                FILESLetter = if ($existingDrive.FILES) { $existingDrive.FILES.DriveLetter } else { $null }
            }

            if (-not $driveInfo.VentoyLetter -or -not $driveInfo.UtilsLetter) {
                throw "Cannot resume - missing required partitions (VENTOY or UTILS)"
            }

            # Staging directory stays in temp - used only for temporary processing
            Write-Log "Staging directory (temp processing): $script:StagingDir" -Level INFO
        }
        elseif ($response -eq 'R' -or $response -eq 'r') {
            Write-Log "User chose to REFORMAT" -Level WARN

            # Confirmation for reformatting
            if (-not (Confirm-DiskWipe -Disk $selectedDisk -Force:$Force)) {
                throw "Operation cancelled - confirmation failed"
            }

            # Partitioning & Ventoy installation
            $driveInfo = Initialize-BrandoToolkit -SelectedDisk $selectedDisk -Settings $settings

            # Update staging directory after reformatting
            # (folders will be created below in the common path)
        }
        else {
            throw "Invalid choice - operation cancelled"
        }

        # For REFORMAT path, create folders
        if ($response -eq 'R' -or $response -eq 'r') {
            $folders = Initialize-FolderStructure -DriveInfo $driveInfo
            Write-Log "Staging directory (temp processing): $script:StagingDir" -Level INFO

            # Create helper scripts
            $scriptsPath = Join-Path $folders.UtilsRoot "Scripts"
            New-HelperScripts -ScriptsPath $scriptsPath

            # Generate Ventoy menu
            New-VentoyMenu -VentoyRoot $folders.VentoyRoot
        }
    }
    else {
        # No existing drive, proceed normally
        if (-not (Confirm-DiskWipe -Disk $selectedDisk -Force:$Force)) {
            throw "Operation cancelled - confirmation failed"
        }

        # Partitioning & Ventoy installation
        $driveInfo = Initialize-BrandoToolkit -SelectedDisk $selectedDisk -Settings $settings

        # Create folder structure
        $folders = Initialize-FolderStructure -DriveInfo $driveInfo

        # Keep staging directory in temp for temporary processing only
        # Downloads go directly to their destinations (VENTOY/UTILS partitions)
        Write-Log "Staging directory (temp processing): $script:StagingDir" -Level INFO

        # Create helper scripts in Scripts folder
        $scriptsPath = Join-Path $folders.UtilsRoot "Scripts"
        New-HelperScripts -ScriptsPath $scriptsPath

        # Generate Ventoy menu
        New-VentoyMenu -VentoyRoot $folders.VentoyRoot
    }  # End of normal mode (else block)
    }  # End of existing drive check

    # Download & provision (unless skipped)
    if (-not $SkipDownloads) {
        # Wrap config in hashtable for PS 5.1 compatibility
        $configHash = @{
            items = $config.items
        }

        Start-Provisioning -Config $configHash -Folders $folders

        # Export manifest
        Export-Manifest -UtilsRoot $folders.UtilsRoot
    }
    else {
        Write-Log "Skipping downloads (SkipDownloads flag set)" -Level WARN
    }

    # Final summary
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "  brando's toolkit Build Complete!" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Drive Layout:" -ForegroundColor Cyan
    $ventoySize = Get-FriendlySize $driveInfo.VentoySize
    $utilsSize = Get-FriendlySize $driveInfo.UtilsSize
    $FILESSize = Get-FriendlySize $driveInfo.FILESSize
    Write-Host "  VENTOY:  $($folders.VentoyRoot)  ($ventoySize)" -ForegroundColor White
    Write-Host "  UTILS:   $($folders.UtilsRoot)  ($utilsSize)" -ForegroundColor White
    Write-Host "  FILES:  $($folders.FILESRoot)  ($FILESSize)" -ForegroundColor White
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Review the manifest: $($folders.UtilsRoot)_Meta\manifest.json" -ForegroundColor Gray
    Write-Host "  2. Check download logs: $script:LogFile" -ForegroundColor Gray
    Write-Host "  3. Place any manual ISOs in: $($folders.VentoyRoot)ISO\" -ForegroundColor Gray
    Write-Host "  4. Safely eject and test boot!" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Enjoy your all-in-one brando's toolkit!" -ForegroundColor Green
    Write-Host ""
}

# Run Main function
try {
    Main
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
} @args
