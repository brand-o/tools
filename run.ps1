# Brando's Toolkit - Quick Launcher
# This wrapper ensures the script executes correctly regardless of context

$ErrorActionPreference = 'Stop'

try {
    Write-Host "Downloading brando's toolkit installer..." -ForegroundColor Cyan
    
    # Download the script content
    $scriptContent = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/brand-o/tools/main/make.ps1' -UseBasicParsing
    
    if ([string]::IsNullOrWhiteSpace($scriptContent)) {
        throw "Failed to download script - received empty response"
    }
    
    Write-Host "Script downloaded successfully ($($scriptContent.Length) bytes)" -ForegroundColor Green
    Write-Host "Executing..." -ForegroundColor Cyan
    Write-Host ""
    
    # Execute the script
    Invoke-Expression $scriptContent
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}
