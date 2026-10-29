@echo off
rem 统一入口: 载入 MSVC BuildTools 2022 x64 环境, 然后执行传入的命令行。
rem 用法: vcvars.bat <command> [args...]
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
%*
