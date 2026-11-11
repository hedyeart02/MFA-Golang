@echo off
setlocal enabledelayedexpansion

:: Always run from the project root directory
cd /d "%~dp0"
title SAMLGuard - Enterprise MFA Gateway

echo ========================================================
echo   SAMLGuard - EcoStruxure IT Advisor MFA Gateway
echo ========================================================
echo.

:: Ensure required directories exist
if not exist "data" mkdir "data"
if not exist "bin" mkdir "bin"

:: Locate Go compiler
set "GO_CMD="
where go >nul 2>nul
if %errorlevel%==0 (
    set "GO_CMD=go"
) else if exist "C:\Program Files\Go\bin\go.exe" (
    set "GO_CMD=C:\Program Files\Go\bin\go.exe"
)

if defined GO_CMD (
    echo [1/2] Building SAMLGuard from source...
    "%GO_CMD%" build -o "bin\samlguard.exe" ./cmd/samlguard
    if errorlevel 1 (
        echo.
        echo [ERROR] Build failed! Please check the errors above.
        pause
        exit /b 1
    )
    echo       Build succeeded: bin\samlguard.exe
) else if exist "bin\samlguard.exe" (
    echo [1/2] Go compiler not found in PATH; using existing bin\samlguard.exe
) else (
    echo [ERROR] Neither Go compiler nor bin\samlguard.exe was found.
    pause
    exit /b 1
)

echo.
echo [2/2] Starting SAMLGuard Server...
echo   - Admin Console : https://localhost:18080/admin/login
echo   - SAML Login    : https://localhost:18080/login
echo   - Health Check  : https://localhost:18080/health
echo   - Config File   : configs\config.yaml
echo.
echo   Press Ctrl+C to stop the server.
echo ========================================================
echo.

"bin\samlguard.exe" -config "configs\config.yaml"

if errorlevel 1 (
    echo.
    echo [ERROR] SAMLGuard exited with error code %errorlevel%.
    pause
)

endlocal

