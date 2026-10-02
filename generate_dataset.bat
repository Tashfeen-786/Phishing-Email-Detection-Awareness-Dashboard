@echo off
REM  Creates data\phishing_email_dataset.csv (600 synthetic emails).
REM  Deterministic: the same seed always produces the same file.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: run setup_windows.bat first.
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
echo Generating the synthetic dataset...
echo.
python data\generate_dataset.py
if errorlevel 1 (
    echo.
    echo Dataset generation FAILED. Read the message above.
    pause
    exit /b 1
)
echo.
echo Done. Next: train_model.bat
pause
