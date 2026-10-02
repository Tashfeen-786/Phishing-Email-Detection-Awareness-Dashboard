@echo off
REM  Trains Logistic Regression, Naive Bayes and Random Forest,
REM  then saves the best model plus real metrics and charts.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: run setup_windows.bat first.
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
if not exist "data\phishing_email_dataset.csv" (
    echo Dataset not found - generating it first...
    python data\generate_dataset.py
)
echo.
echo Training the models...
echo.
python ml\train_model.py
if errorlevel 1 (
    echo.
    echo Training FAILED. Read the message above.
    pause
    exit /b 1
)
echo.
echo Comparing rule-based vs ML vs hybrid on the same test split...
echo.
python ml\evaluation.py
echo.
echo Done. Metrics are in reports\  and charts in screenshots\
pause
