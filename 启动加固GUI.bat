@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在启动 加固套件 GUI ...
python harden_gui.py
if errorlevel 1 (
  echo.
  echo [!] 启动失败。请确认已装 Python 3 且 pip install pefile pycryptodome
  pause
)
