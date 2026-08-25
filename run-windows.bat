@echo off
title DiskLens
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo Python was not found.
    echo Install it from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b
)

python disklens.py %*
pause
