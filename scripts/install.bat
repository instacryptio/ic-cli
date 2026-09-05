@echo off
rem Instacrypt CLI (icc) installer for Windows.
rem
rem   Download and run:  install.bat
rem
rem Downloads the latest icc release binary for your CPU architecture and
rem installs it either per-user (%LOCALAPPDATA%\Programs\icc) or system-wide
rem (%ProgramFiles%\icc, requires an elevated prompt).
setlocal enableextensions enabledelayedexpansion
chcp 65001 >nul

set "REPO=instacryptio/ic-cli"
set "ISSUES_URL=https://github.com/%REPO%/issues"
set "LATEST_BASE=https://github.com/%REPO%/releases/latest/download"

call :banner

rem --- 1. detect CPU architecture -------------------------------------------
echo 🔍 Detecting your platform...
set "ARCH="
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "ARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
if /i "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "ARCH=arm64"
if not defined ARCH (
  echo This CPU architecture ^(%PROCESSOR_ARCHITECTURE%^) is not currently supported. Submit an issue at %ISSUES_URL% to report this if you think this is an error.
  exit /b 1
)
set "ASSET=icc-windows-%ARCH%"
echo    Platform: windows/%ARCH%
echo.

rem --- 2. choose install scope ----------------------------------------------
echo How would you like to install icc?
echo   1^) Per-user     ^(%%LOCALAPPDATA%%\Programs\icc - no admin required^)
echo   2^) System-wide  ^(%%ProgramFiles%%\icc - requires administrator^)
set "CHOICE=1"
set /p "CHOICE=Choose [1/2] (default 1): "
echo.

if "%CHOICE%"=="2" goto :scope_system
goto :scope_user

:scope_system
set "TARGET=%ProgramFiles%\icc"
set "SCOPE=Machine"
net session >nul 2>&1
if errorlevel 1 goto :need_admin
echo 📁 Installing system-wide to !TARGET!
goto :have_target

:scope_user
set "TARGET=%LOCALAPPDATA%\Programs\icc"
set "SCOPE=User"
echo 📁 Installing per-user to !TARGET!
goto :have_target

:need_admin
echo ⚠  System-wide install requires an elevated ^(Administrator^) prompt.
echo    Right-click Command Prompt or PowerShell, choose "Run as administrator", then re-run this script.
exit /b 1

:have_target
if not exist "!TARGET!" mkdir "!TARGET!"
set "DEST=!TARGET!\icc.exe"
set "URL=%LATEST_BASE%/%ASSET%"
echo.

rem --- 3. download the binary (saved as icc.exe) ----------------------------
echo ⬇️  Downloading %ASSET%...
echo    !URL!
where curl >nul 2>&1
if errorlevel 1 goto :dl_powershell
curl -fSL --progress-bar -o "!DEST!" "!URL!"
goto :dl_done

:dl_powershell
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri '!URL!' -OutFile '!DEST!' -UseBasicParsing } catch { exit 1 }"

:dl_done
if not exist "!DEST!" (
  echo Download failed. Please try again, or report at %ISSUES_URL%.
  exit /b 1
)

rem --- 4. add the install dir to PATH (scope-appropriate) -------------------
echo 🔗 Ensuring !TARGET! is on your PATH...
powershell -NoProfile -Command "$d='!TARGET!'; $s='!SCOPE!'; $p=[Environment]::GetEnvironmentVariable('Path',$s); if($p -notlike \"*$d*\"){ [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';') + ';' + $d), $s); Write-Host '   Added to '$s' PATH' } else { Write-Host '   Already on PATH' }"

rem --- 5. done --------------------------------------------------------------
echo.
echo ** Installation Completed **
echo    icc installed to !DEST!
echo.
echo ⚠️  You may need to close and reopen your existing terminal windows for icc to work as expected...
echo.
exit /b 0

:banner
echo.
echo ░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
echo ░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░
echo.
echo   Installer
echo.
exit /b 0
