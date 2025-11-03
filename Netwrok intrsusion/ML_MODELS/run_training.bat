@echo off
echo ============================================
echo Cyber Attack Detection - Model Training
echo ============================================
echo.

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python not found!
    echo Please install Python from https://www.python.org/
    pause
    exit /b 1
)

echo.
echo Installing/updating dependencies...
pip install -r requirements.txt

echo.
echo Starting model training...
echo This may take several minutes...
echo.

python train_models.py

echo.
echo ============================================
echo Training completed!
echo ============================================
echo.
echo Models saved in: trained_models/
echo You can now use prediction_api.py to make predictions.
echo.
pause

