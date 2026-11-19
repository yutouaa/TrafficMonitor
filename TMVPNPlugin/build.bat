@echo off
setlocal
set "OUTPUT=%~dp0."
if not "%~1"=="" set "OUTPUT=%~f1"
set "FIXTURE="
if /i "%~2"=="fixture" set "FIXTURE=/DTMVPNPLUGIN_FIXTURE"
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 goto fail
cd /d "%~dp0"
if not exist "%OUTPUT%" mkdir "%OUTPUT%"
if errorlevel 1 goto fail
rc /nologo /c65001 /fo "%OUTPUT%\options.res" options.rc
if errorlevel 1 goto fail
cl /nologo /std:c++17 /LD /O2 /MD /EHsc /utf-8 /DUNICODE /D_UNICODE %FIXTURE% /I..\include vpn_plugin.cpp "%OUTPUT%\options.res" /Fo:"%OUTPUT%\vpn_plugin.obj" /Fe:"%OUTPUT%\TMVPNPlugin.dll" /link /MACHINE:X64 /IMPLIB:"%OUTPUT%\TMVPNPlugin.lib"
if errorlevel 1 goto fail
cl /nologo /O2 /MD /EHsc /utf-8 /DUNICODE /D_UNICODE /I..\include test_host.cpp /Fo:"%OUTPUT%\test_host.obj" /Fe:"%OUTPUT%\test_host.exe" /link /MACHINE:X64
if errorlevel 1 goto fail
echo BUILD_OK
exit /b 0
:fail
echo BUILD_FAIL
exit /b 1
