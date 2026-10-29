@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Creating isolated Python environment...
  py -3 -m venv .venv
  if errorlevel 1 python -m venv .venv
)
call .venv\Scripts\activate.bat
if errorlevel 1 goto fail
if not exist .env copy .env.example .env >nul
echo Installing project dependencies. Internet is required the first time...
python -m pip install --upgrade pip
if errorlevel 1 goto fail
python -m pip install -r requirements.txt
if errorlevel 1 goto fail
echo Creating a private administrator if one does not already exist...
python -m app.create_admin
if errorlevel 1 goto fail
echo.
echo CloudAuth is starting. Keep this window open.
echo Open http://127.0.0.1:8000 in your browser.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
if errorlevel 1 goto fail
goto end
:fail
echo.
echo Setup or startup failed. Copy the complete error from this window for troubleshooting.
pause
:end
endlocal
