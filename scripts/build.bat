call scripts\var.bat

mkdir build

cd build

if "%platform%"=="Win32" call "%VS140COMNTOOLS%\..\..\vc\vcvarsall.bat" x86

if "%platform%"=="x64" call "%VS140COMNTOOLS%\..\..\vc\vcvarsall.bat" x86_amd64   

if "%platform%"=="Win32" set CMAKE_GENERATOR_NAME=Visual Studio 14 2015

if "%platform%"=="x64"   set CMAKE_GENERATOR_NAME=Visual Studio 14 2015 Win64

cmake -G "%CMAKE_GENERATOR_NAME%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% ..

msbuild erpiko.sln /p:Configuration=%CONFIGURATION%

cd C:\erpiko