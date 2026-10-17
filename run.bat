@echo off
REM Windows launcher: creates a virtual environment, installs packages, starts CryptoLens.
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
)
call .venv\Scripts\activate.bat
pip install -q -r requirements.txt
python app.py
pause
