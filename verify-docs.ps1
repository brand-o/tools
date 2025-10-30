#!/usr/bin/env pwsh
# Verify README.md and website match bundle.json

$bundle = Get-Content 'bundle.json' -Raw | ConvertFrom-Json
$readme = Get-Content 'README.md' -Raw

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  DOCUMENTATION VERIFICATION REPORT" -ForegroundColor White
Write-Host "============================================`n" -ForegroundColor Cyan

# Get actual counts
$cats = $bundle.items | Group-Object category
$actualISOs = ($cats | Where-Object Name -eq 'iso').Count
$actualPortable = ($cats | Where-Object Name -eq 'portable').Count
$actualInstallers = ($cats | Where-Object Name -eq 'installer').Count
$actualDrivers = ($cats | Where-Object Name -eq 'driver').Count
$actualExtensions = ($cats | Where-Object Name -eq 'extension').Count

# Extract README counts
$readmeISOs = if ($readme -match 'operating system isos \((\d+) total\)') { [int]$matches[1] } else { 0 }
$readmePortable = if ($readme -match 'portable applications \((\d+) total\)') { [int]$matches[1] } else { 0 }
$readmeInstallers = if ($readme -match 'installer applications \((\d+) total\)') { [int]$matches[1] } else { 0 }
$readmeDrivers = if ($readme -match '### drivers \((\d+) total\)') { [int]$matches[1] } else { 0 }

Write-Host "COUNT COMPARISON:" -ForegroundColor Yellow
Write-Host ("{0,-15} README: {1,2}  |  Actual: {2,2}  {3}" -f "ISOs:", $readmeISOs, $actualISOs, $(if($readmeISOs -eq $actualISOs){'✓'}else{'✗ MISMATCH'})) -ForegroundColor $(if($readmeISOs -eq $actualISOs){'Green'}else{'Red'})
Write-Host ("{0,-15} README: {1,2}  |  Actual: {2,2}  {3}" -f "Portable:", $readmePortable, $actualPortable, $(if($readmePortable -eq $actualPortable){'✓'}else{'✗ MISMATCH'})) -ForegroundColor $(if($readmePortable -eq $actualPortable){'Green'}else{'Red'})
Write-Host ("{0,-15} README: {1,2}  |  Actual: {2,2}  {3}" -f "Installers:", $readmeInstallers, $actualInstallers, $(if($readmeInstallers -eq $actualInstallers){'✓'}else{'✗ MISMATCH'})) -ForegroundColor $(if($readmeInstallers -eq $actualInstallers){'Green'}else{'Red'})
Write-Host ("{0,-15} README: {1,2}  |  Actual: {2,2}  {3}" -f "Drivers:", $readmeDrivers, $actualDrivers, $(if($readmeDrivers -eq $actualDrivers){'✓'}else{'✗ MISMATCH'})) -ForegroundColor $(if($readmeDrivers -eq $actualDrivers){'Green'}else{'Red'})
Write-Host ("{0,-15} README: {1,2}  |  Actual: {2,2}  {3}" -f "Extensions:", 1, $actualExtensions, $(if(1 -eq $actualExtensions){'✓'}else{'✗ MISMATCH'})) -ForegroundColor $(if(1 -eq $actualExtensions){'Green'}else{'Red'})

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "ITEM-BY-ITEM VERIFICATION" -ForegroundColor White
Write-Host "============================================`n" -ForegroundColor Cyan

# Check ISOs
Write-Host "ISOs in bundle.json:" -ForegroundColor Yellow
$bundle.items | Where-Object {$_.category -eq 'iso'} | ForEach-Object {
    $inReadme = $readme -match [regex]::Escape($_.name)
    $status = if ($inReadme) { "✓" } else { "✗ MISSING FROM README" }
    $color = if ($inReadme) { "Green" } else { "Red" }
    Write-Host ("  {0,-50} {1}" -f $_.name, $status) -ForegroundColor $color
}

Write-Host "`nPortable tools in bundle.json:" -ForegroundColor Yellow
$bundle.items | Where-Object {$_.category -eq 'portable'} | ForEach-Object {
    $inReadme = $readme -match [regex]::Escape($_.name)
    $status = if ($inReadme) { "✓" } else { "✗ MISSING FROM README" }
    $color = if ($inReadme) { "Green" } else { "Red" }
    Write-Host ("  {0,-50} {1}" -f $_.name, $status) -ForegroundColor $color
}

Write-Host "`nInstallers in bundle.json:" -ForegroundColor Yellow
$bundle.items | Where-Object {$_.category -eq 'installer'} | ForEach-Object {
    $inReadme = $readme -match [regex]::Escape($_.name)
    $status = if ($inReadme) { "✓" } else { "✗ MISSING FROM README" }
    $color = if ($inReadme) { "Green" } else { "Red" }
    Write-Host ("  {0,-50} {1}" -f $_.name, $status) -ForegroundColor $color
}

Write-Host "`nDrivers in bundle.json:" -ForegroundColor Yellow
$bundle.items | Where-Object {$_.category -eq 'driver'} | ForEach-Object {
    $inReadme = $readme -match [regex]::Escape($_.name)
    $status = if ($inReadme) { "✓" } else { "✗ MISSING FROM README" }
    $color = if ($inReadme) { "Green" } else { "Red" }
    Write-Host ("  {0,-50} {1}" -f $_.name, $status) -ForegroundColor $color
}

Write-Host "`n============================================`n" -ForegroundColor Cyan
