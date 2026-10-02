@echo off
REM  Runs the full pytest suite (all 25 required scenarios).
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: run setup_windows.bat first.
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
echo Running the test suite...
echo.
python -m pytest tests\ -v
echo.
echo ==============================================================
echo   A line reading "N passed" above means everything works.
echo ==============================================================
pause
