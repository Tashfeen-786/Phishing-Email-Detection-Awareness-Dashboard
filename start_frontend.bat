@echo off
REM  Starts the React dashboard on http://localhost:5173
REM  Start the backend FIRST with start_backend.bat.
setlocal
cd /d "%~dp0"
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed.
    echo Install the LTS version from https://nodejs.org/ then run setup_windows.bat again.
    pause
    exit /b 1
)
cd frontend
if not exist "node_modules" (
    echo Installing frontend packages (first run only)...
    call npm install
)
echo.
echo ==============================================================
echo   DASHBOARD
echo ==============================================================
echo   Open http://localhost:5173 in your browser.
echo.
echo   Keep this window open. Press CTRL+C to stop.
echo ==============================================================
echo.
call npm run dev
pause
