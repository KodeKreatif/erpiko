@echo off
call scripts\var.bat

REM Check whether package is already installed
choco list -lo -e wget | find /i "1 packages"
if %errorlevel% == 1 (choco install -y wget)

choco list -lo -e unzip | find /i "1 packages"
if %errorlevel% == 1 (choco install -y unzip)

choco list -lo -e cmake | find /i "1 packages"
if %errorlevel% == 1 (choco install -y cmake)


mkdir deps

cd deps

wget -O tip.zip https://github.com/mdamt/libressl-portable/archive/tip.zip

unzip tip.zip

cd libressl-portable-tip

bash -lc "cd %workingdirnix%/deps/libressl-portable-tip/ && ./autogen.sh"

bash -lc "cd %workingdirnix%/deps/libressl-portable-tip/ && patch -p0 < ../../patch/cmp.patch"

bash -lc "cd %workingdirnix%/deps/libressl-portable-tip/ && patch -p1 < ../../patch/CMakefiles.patch"

cd ..

xcopy libressl-portable-tip libressl /e/i

cd libressl

mkdir build

cd build

if "%platform%"=="Win32" call "%VS140COMNTOOLS%\..\..\vc\vcvarsall.bat" x86

if "%platform%"=="x64" call "%VS140COMNTOOLS%\..\..\vc\vcvarsall.bat" x86_amd64

if "%platform%"=="Win32" set CMAKE_GENERATOR_NAME=Visual Studio 14 2015

if "%platform%"=="x64"   set CMAKE_GENERATOR_NAME=Visual Studio 14 2015 Win64


cmake -G "%CMAKE_GENERATOR_NAME%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% ..

msbuild LibreSSL.sln /p:Configuration=%CONFIGURATION%

copy /y ssl\%CONFIGURATION%\ssl.lib ..\ssl\ 
if %configuration%==Debug copy /y ssl\%configuration%\*.pdb ..\ssl\

copy /y tls\%CONFIGURATION%\tls.lib ..\tls\
if %configuration%==Debug copy /y tls\%configuration%\*.pdb ..\tls\

copy /y crypto\%CONFIGURATION%\crypto.lib ..\crypto\
if %configuration%==Debug copy /y crypto\%CONFIGURATION%\*.pdb ..\crypto\

mkdir ..\ssl\Debug

mkdir ..\tls\Debug

mkdir ..\crypto\Debug

copy /y ssl\%CONFIGURATION%\ssl.lib ..\ssl\Debug\
if %configuration%==Debug copy /y ssl\%CONFIGURATION%\*.pdb ..\ssl\Debug\

copy /y tls\%CONFIGURATION%\tls.lib ..\tls\Debug\
if %configuration%==Debug copy /y tls\%CONFIGURATION%\*.pdb ..\tls\Debug\

copy /y crypto\%CONFIGURATION%\crypto.lib ..\crypto\Debug\
if %configuration%==Debug copy /y crypto\%CONFIGURATION%\*.pdb ..\crypto\Debug\
		
cd ..\..

mkdir catch

cd catch

wget -O catch.hpp https://raw.githubusercontent.com/philsquared/Catch/master/single_include/catch.hpp

cd %workingdir%