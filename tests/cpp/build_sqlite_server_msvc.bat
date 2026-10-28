@echo off
rem Builds the SQLite test server with MSVC instead of g++.
rem
rem Why: the g++ build makes a 34 MB exe that antivirus deletes a few seconds
rem after the link ("Permission denied", then the file is simply gone).  It is
rem a false positive.  MSVC produces a 1.7 MB exe that survives.
rem
rem Run it from the directory build_sqlite_server.sh made - it needs the
rem patched main\ and sqlite3.o that script leaves there:
rem
rem   bash tests/cpp/build_sqlite_server.sh
rem   cd build/cpp_sqlite_test
rem   cmd //c ../../tests/cpp/build_sqlite_server_msvc.bat
rem   POST=8099 ./srv_msvc.exe
rem
rem Pass the cpp source tree as %1 if it is not the usual checkout.

setlocal
set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
    echo vswhere not found - is Visual Studio installed?
    exit /b 1
)
for /f "usebackq tokens=*" %%i in (
    `"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`
) do set VSPATH=%%i
if "%VSPATH%"=="" (
    echo No MSVC toolset found.
    exit /b 1
)
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

if "%~1"=="" (set CPP=%~dp0..\..\src\server_sample\cpp) else (set CPP=%~1)
if not exist "main\lambda_server.cpp" (
    echo Run this from the build_sqlite_server.sh output directory.
    exit /b 1
)

rem The sources are UTF-8, so /utf-8 keeps the Japanese string literals intact.
cl /nologo /std:c++20 /EHsc /O1 /MD /utf-8 /bigobj ^
   /I main /I "%CPP%\gen" /I "%CPP%\date" /I "%CPP%\models" /I "%CPP%\sqlpp11" ^
   /I "%CPP%\sqlite" /I "%CPP%\include" /I "%CPP%\openssl" ^
   /Fe:srv_msvc.exe main\lambda_server.cpp "%CPP%\sqlite\sqlite3.c" ^
   /link ws2_32.lib bcrypt.lib || exit /b 1

echo.
echo done: srv_msvc.exe
echo start: POST=8099 ./srv_msvc.exe
