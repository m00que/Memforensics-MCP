@echo off
set PYTHONHOME=%~dp0
set PYTHONPATH=%PYTHONHOME%\Lib;%PYTHONHOME%\DLLs;%PYTHONHOME%\Lib\lib-tk
%PYTHONHOME%\python.exe -m pip %*

pause