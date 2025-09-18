@echo off
REM Windows Batch Script to Start MCX Traffic Capture
REM Save as start_mcx_capture.bat

echo ==========================================
echo MCX Traffic Capture Setup
echo ==========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python and add it to PATH
    pause
    exit /b 1
)

REM Check if mitmproxy is installed
mitmdump --version >nul 2>&1
if %errorlevel% neq 0 (
    echo mitmproxy not found. Installing...
    pip install mitmproxy
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install mitmproxy
        pause
        exit /b 1
    )
)

REM Create today's folder structure
for /f "tokens=1-3 delims=/" %%a in ('date /t') do (
    set day=%%a
    set month=%%b  
    set year=%%c
)

echo Current folder: %CD%
echo Saving MCX traffic to: %year%\%month%\%day%
echo Proxy listening on: 0.0.0.0:8080
echo.
echo Configure Firefox proxy settings:
echo - HTTP Proxy: 10.116 (this VM's IP)
echo - Port: 8080
echo.
echo Press Ctrl+C to stop capturing
echo.

REM Start mitmdump with the addon
mitmdump -s mcx_capture.py --listen-host 0.0.0.0 --listen-port 8080

pause