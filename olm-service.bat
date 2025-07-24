@echo off
setlocal

REM Olm Windows Service Management Script
REM This script helps manage the Olm WireGuard service on Windows

if "%1"=="" goto :help
if "%1"=="help" goto :help
if "%1"=="/?" goto :help
if "%1"=="-h" goto :help
if "%1"=="--help" goto :help

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: This script must be run as Administrator for service management.
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Execute the service command
olm.exe %*
if %errorLevel% neq 0 (
    echo Command failed with error code %errorLevel%
    pause
    exit /b %errorLevel%
)

echo.
echo Operation completed successfully.
pause
exit /b 0

:help
echo Olm WireGuard Service Management
echo.
echo Usage: %~nx0 [command]
echo.
echo Commands:
echo   install     Install the Olm service
echo   remove      Remove the Olm service  
echo   start       Start the Olm service
echo   stop        Stop the Olm service
echo   status      Show service status
echo   debug       Run in debug mode
echo   help        Show this help
echo.
echo Note: This script must be run as Administrator for service management.
echo Make sure olm.exe is in your PATH or in the same directory.
echo.
pause
