@echo off
REM  Fills the dashboard with 24 analysed sample emails so the
REM  charts have something to show. Safe to run again.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: run setup_windows.bat first.
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
echo Seeding demo analyses...
echo.
python scripts\seed_demo.py --reset
echo.
echo Done. Open http://localhost:5173 to see the populated dashboard.
pause
