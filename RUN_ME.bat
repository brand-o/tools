@echo off
:: ============================================================================
:: Brando's Toolkit - Easy Launcher
:: Copyright (C) 2025  Brando
:: ============================================================================
:: This batch file runs the online installer with admin privileges
:: Just double-click to start!
:: ============================================================================

echo.
echo ================================================================================
echo   BRANDO'S TOOLKIT - USB Drive Provisioning Tool
echo ================================================================================
echo.
echo   This will download and run the latest version from brando.tools
echo   A new PowerShell window will open - please accept the UAC prompt
echo.
echo ================================================================================
echo.
pause

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process PowerShell -Verb RunAs -ArgumentList '-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-Command','iex (irm https://brando.tools/run)'"
