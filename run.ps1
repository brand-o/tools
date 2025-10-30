# Brando's Toolkit - Quick Launcher
# This wrapper downloads and executes make.ps1 in a way compatible with iex

$scriptUrl = 'https://raw.githubusercontent.com/brand-o/tools/main/make.ps1'

Write-Host "Downloading brando's toolkit..." -ForegroundColor Cyan

try {
    # Download the script as a file instead of executing directly
    $tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "brando-toolkit-$(New-Guid).ps1")
    
    Invoke-WebRequest -Uri $scriptUrl -OutFile $tempFile -UseBasicParsing
    
    Write-Host "Executing installer..." -ForegroundColor Green
    
    # Execute the file directly (this handles param blocks correctly)
    & $tempFile
    
    # Clean up
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path $tempFile) {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Pause at the end when run from RUN_ME.bat
Write-Host ""
Write-Host "Script completed. Press any key to exit..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
