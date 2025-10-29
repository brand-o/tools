@echo off
:: ============================================================================
:: Brando's Toolkit - Easy Launcher
:: Copyright (C) 2025  Brando
::
:: This program is free software: you can redistribute it and/or modify
:: it under the terms of the GNU General Public License as published by
:: the Free Software Foundation, either version 3 of the License, or
:: (at your option) any later version.
::
:: This program is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
:: GNU General Public License for more details.
::
:: You should have received a copy of the GNU General Public License
:: along with this program.  If not, see https://www.gnu.org/licenses/.
:: ============================================================================
:: This batch file downloads and runs make.ps1 from brando.tools
:: with admin privileges automatically. Just double-click to start!
:: ============================================================================

setlocal

:: Set colors and title
title Brando's Toolkit - Launcher
color 0A

:: Display banner
echo.
echo ================================================================================
echo   BRANDO'S TOOLKIT - USB Drive Provisioning Tool
echo ================================================================================
echo.
echo   This will create a complete all-in-one tech USB drive with:
echo     - Ventoy bootloader with multiple OS ISOs
echo     - Portable tools and utilities
echo     - Installers and drivers
echo     - Organized folder structure with shortcuts
echo.
echo   Requirements:
echo     - Administrator privileges (will request automatically)
echo     - USB drive 64GB or larger
echo     - Internet connection for downloads
echo.
echo   Downloading latest version from brando.tools...
echo.
echo ================================================================================
echo.

:: Check if already running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Already running as Administrator
    echo.
    goto :RunScript
)

:: Request admin privileges
echo [INFO] Requesting Administrator privileges...
echo.

:: Use PowerShell to elevate and run the online script
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -Command \"iex (iwr ''https://brando.tools/make.ps1'' -UseBasicParsing).Content\"' -Verb RunAs"

:: Exit this window since we spawned an elevated one
exit /b

:RunScript
:: If we're already admin, run the script directly
powershell -NoProfile -ExecutionPolicy Bypass -NoExit -Command "iex (iwr 'https://brando.tools/make.ps1' -UseBasicParsing).Content"
exit /b
