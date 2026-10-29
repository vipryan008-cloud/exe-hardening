@echo off
rem EXE 加固工具 — 一键 L1 整体壳。用法: 拖 exe 到本 bat 上, 或
rem   启动加固.bat 目标.exe [输出.exe]
setlocal
if "%~1"=="" (
  echo 用法: 启动加固.bat ^<目标.exe^> [输出.exe]
  echo   给合法授权软件做 L1 整体壳加密; 之后请用客户证书 signtool 重签。
  pause & exit /b 1
)
set IN=%~1
set OUT=%~2
if "%OUT%"=="" set OUT=%~dpn1_packed.exe
python "%~dp0harden.py" "%IN%" -o "%OUT%"
echo.
echo 加固完成: %OUT%
echo 记得用客户 Authenticode 证书重签 (signtool)。
pause
