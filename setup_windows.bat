@echo off
REM ===================================================================
REM  setup_windows.bat
REM  One-time setup. Creates the Python virtual environment, installs
REM  every Python package, and installs the frontend packages.
REM
REM  Just double-click this file. It is safe to run more than once.
REM ===================================================================
setlocal
cd /d "%~dp0"

echo ==============================================================
echo   Phishing Email Detection ^& Awareness Dashboard - SETUP
echo ==============================================================
echo.

echo [1/5] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: Python was not found.
    echo   Install Python 3.10 or newer from https://www.python.org/downloads/
    echo   IMPORTANT: tick "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)
python --version

echo.
echo [2/5] Creating the virtual environment in .venv ...
if exist ".venv\Scripts\python.exe" (
    echo   .venv already exists - reusing it.
) else (
    python -m venv .venv
    if errorlevel 1 (
        echo   ERROR: could not create the virtual environment.
        pause
        exit /b 1
    )
)

echo.
echo [3/5] Installing Python packages (this can take a few minutes)...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo   ERROR: package installation failed. Check your internet connection.
    pause
    exit /b 1
)

echo.
echo [4/5] Checking Node.js for the frontend...
node --version >nul 2>&1
if errorlevel 1 (
    echo   WARNING: Node.js was not found.
    echo   The backend will still work, but the dashboard needs Node.js.
    echo   Install the LTS version from https://nodejs.org/
    echo   Then run this file again.
) else (
    node --version
    echo   Installing frontend packages...
    cd frontend
    call npm install
    cd ..
)

echo.
echo [5/5] Creating your .env file...
if exist ".env" (
    echo   .env already exists - left untouched.
) else (
    copy .env.example .env >nul
    echo   Created .env from .env.example
)

echo.
echo ==============================================================
echo   SETUP COMPLETE
echo ==============================================================
echo.
echo   Next steps, in this order:
echo     1. generate_dataset.bat    creates the synthetic dataset
echo     2. train_model.bat         trains the machine-learning models
echo     3. start_backend.bat       starts the API  (leave it running)
echo     4. start_frontend.bat      starts the dashboard (new window)
echo.
echo   Then open http://localhost:5173 in your browser.
echo.
pause
