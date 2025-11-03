@echo off
echo ================================================================
echo  CYBER ATTACK DETECTION - LIVE DASHBOARD
echo ================================================================
echo.
echo Installing dependencies...
python -m pip install flask flask-cors

echo.
echo Starting dashboard server...
echo.
echo Open your browser and visit: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo ================================================================
echo.

cd /d "%~dp0"
python dashboard_server.py

