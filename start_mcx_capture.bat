@echo off
REM Windows Batch Script to Start MCX Traffic Capture
REM Save as start_mcx_capture.bat

echo ==========================================
echo MCX Traffic Capture Setup
echo ==========================================
echo.

mitmdump -s stateful_mcx_proxy.py --listen-host 0.0.0.0 --listen-port 8080
pause