@echo off
REM Gulpsuite + Integrated Chromium Setup Launcher (Windows)
setlocal
cd /d "%~dp0"
python "%~dp0install.py" %*
