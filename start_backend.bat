@echo off
REM  Starts the FastAPI backend on http://127.0.0.1:8000
REM  LEAVE THIS WINDOW OPEN while you use the dashboard.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: run setup_windows.bat first.
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
echo ==============================================================
echo   BACKEND API
echo ==============================================================
echo   API      : http://127.0.0.1:8000
echo   Swagger  : http://127.0.0.1:8000/docs
echo.
echo   Keep this window open. Press CTRL+C to stop.
echo ==============================================================
echo.
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
pause
