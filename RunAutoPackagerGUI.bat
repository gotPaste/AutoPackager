@echo off

echo Removing Mark-of-the-Web via PowerShell...

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Recurse -File | Unblock-File"

echo Done.

echo Launching AutoPackager GUI
cd %~dp0
powershell.exe -executionpolicy bypass -windowstyle hidden -file ".\AutoPackager.GUI.ps1"