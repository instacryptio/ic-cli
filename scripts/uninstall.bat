@echo off
rem Instacrypt CLI (icc) uninstaller for Windows.
rem
rem   Download and run:  uninstall.bat
rem
rem Removes the icc binary from the per-user and system-wide install locations
rem and strips the PATH entry the installer added.
setlocal enableextensions enabledelayedexpansion
chcp 65001 >nul

set "REPO=instacryptio/ic-cli"
set "USERDIR=%LOCALAPPDATA%\Programs\icc"
set "SYSDIR=%ProgramFiles%\icc"

call :banner

echo 🔍 Looking for icc...
set "REMOVED=0"

rem --- per-user install ------------------------------------------------------
if exist "%USERDIR%\icc.exe" (
  del /f /q "%USERDIR%\icc.exe"
  rd "%USERDIR%" 2>nul
  call :depath "%USERDIR%" User
  echo    🗑  Removed %USERDIR%\icc.exe
  set "REMOVED=1"
)

rem --- system-wide install (needs elevation) --------------------------------
if exist "%SYSDIR%\icc.exe" (
  net session >nul 2>&1
  if errorlevel 1 (
    echo    ⚠  %SYSDIR%\icc.exe needs an elevated prompt to remove — re-run as Administrator.
  ) else (
    del /f /q "%SYSDIR%\icc.exe"
    rd "%SYSDIR%" 2>nul
    call :depath "%SYSDIR%" Machine
    echo    🗑  Removed %SYSDIR%\icc.exe
    set "REMOVED=1"
  )
)

if "!REMOVED!"=="0" echo    No icc binary found in the usual locations.

echo.
echo ** Uninstall Completed **
echo.
exit /b 0

rem --- depath DIR SCOPE : remove DIR from the SCOPE (User/Machine) PATH ------
:depath
powershell -NoProfile -Command "$d='%~1'; $s='%2'; $p=[Environment]::GetEnvironmentVariable('Path',$s); if($p -like \"*$d*\"){ $n=(($p -split ';').Where({ $_ -ne $d -and $_ -ne '' })) -join ';'; [Environment]::SetEnvironmentVariable('Path',$n,$s); Write-Host '   Removed PATH entry '$d }"
exit /b 0

:banner
echo.
echo ░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░
echo.
echo   Uninstaller
echo.
exit /b 0
