@echo off
echo ====================================================
echo Cyber Attack Detection - Model Training
echo ====================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python first:
    echo.
    echo Option 1: Install from Microsoft Store
    echo   - Open Microsoft Store
    echo   - Search for "Python 3.11"
    echo   - Click Install
    echo.
    echo Option 2: Install from python.org
    echo   - Go to https://www.python.org/downloads/
    echo   - Download and install Python
    echo   - IMPORTANT: Check "Add Python to PATH" during installation
    echo.
    echo After installing Python, please:
    echo 1. Close and reopen this window
    echo 2. Run this script again
    echo.
    echo For more help, see: INSTALL_PYTHON.md
    pause
    exit /b 1
)

echo [OK] Python is installed!
python --version
echo.

REM Navigate to script directory
cd /d "%~dp0"
echo Current directory: %CD%
echo.

REM Install dependencies
echo ====================================================
echo Installing dependencies...
echo ====================================================
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ====================================================
echo Starting model training...
echo This will take 5-10 minutes...
echo ====================================================
echo.

python train_models.py

if errorlevel 1 (
    echo [ERROR] Training failed
    pause
    exit /b 1
)

echo.
echo ====================================================
echo Training completed successfully!
echo ====================================================
echo.
echo Next steps:
echo   1. Test the models: python demo_prediction.py
echo   2. Use in your code: from prediction_api import predict_single_row
echo.
echo Check the trained_models/ folder for saved models.
echo.
pause

