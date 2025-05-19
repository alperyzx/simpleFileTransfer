@echo off
setlocal enabledelayedexpansion

echo Simple File Transfer Server - Starting...
goto :check_python

REM Function to download and install Python
:install_python
echo Preparing to download Python installer...
set PYTHON_URL=https://www.python.org/ftp/python/3.11.4/python-3.11.4-amd64.exe
set INSTALLER_PATH=%TEMP%\python_installer.exe

echo Downloading Python installer from %PYTHON_URL%...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%INSTALLER_PATH%'}"

if %ERRORLEVEL% NEQ 0 (
    echo Failed to download Python installer.
    echo Please download and install Python manually from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installing Python...
echo IMPORTANT: Please ensure you check "Add Python to PATH" during installation!
%INSTALLER_PATH% /quiet PrependPath=1

if %ERRORLEVEL% NEQ 0 (
    echo Python installation may have failed or been cancelled.
    echo Please install Python manually from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Python installed successfully! Refreshing environment variables...
call :refresh_env
goto :check_python

:refresh_env
echo Refreshing environment variables...
for /f "tokens=*" %%a in ('powershell -Command "[System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')"') do set "PATH=%%a"
exit /b 0

REM Check if .venv exists and use it
:check_python
if exist .venv\Scripts\python.exe (
    echo Using virtual environment
    set PYTHON=.venv\Scripts\python.exe
    goto :found_python
)

REM Find highest Python version from common locations
set HIGHEST_VER=0.0
set PYTHON=

REM Check Python Launcher (py) first
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found Python Launcher, using highest available version
    set PYTHON=py
    goto :found_python
)

REM Check Registry for Python installations
for /f "tokens=1,2*" %%a in ('reg query HKEY_LOCAL_MACHINE\Software\Python\PythonCore /f "" /k 2^>nul ^| findstr "Python"') do (
    set VERSION=%%~nxa
    if "!VERSION!" GTR "!HIGHEST_VER!" (
        set HIGHEST_VER=!VERSION!
        set PYTHON_PATH=
        for /f "tokens=1,2*" %%x in ('reg query "HKEY_LOCAL_MACHINE\Software\Python\PythonCore\!VERSION!\InstallPath" /ve 2^>nul ^| findstr "REG_SZ"') do (
            set PYTHON_PATH=%%z\python.exe
        )
        if exist "!PYTHON_PATH!" set PYTHON=!PYTHON_PATH!
    )
)

REM Check common installation paths if registry search failed
if "!PYTHON!"=="" (
    for %%v in (3.12 3.11 3.10 3.9 3.8 3.7 3.6) do (
        if exist "C:\Python%%v\python.exe" (
            set PYTHON=C:\Python%%v\python.exe
            goto :found_python
        )
        if exist "C:\Program Files\Python%%v\python.exe" (
            set PYTHON=C:\Program Files\Python%%v\python.exe
            goto :found_python
        )
    )

    REM Last resort: try the PATH
    where python.exe >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set PYTHON=python
        goto :found_python
    )
)

if "!PYTHON!"=="" (
    echo Python not found. Would you like to install Python? (Y/N)
    set /p INSTALL_CHOICE=
    if /i "!INSTALL_CHOICE!"=="Y" (
        goto :install_python
    ) else (
        echo Python installation cancelled. Python 3.6 or higher is required to run this application.
        pause
        exit /b 1
    )
)

:found_python
echo Using Python: %PYTHON%
%PYTHON% httpServer.py
if %ERRORLEVEL% NEQ 0 pause
exit /b 0
