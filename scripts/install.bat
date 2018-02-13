call var.bat

choco install -y wget
choco install -y unzip
choco install -y cmake

mkdir deps

cd deps

wget -O tip.zip https://github.com/mdamt/libressl-portable/archive/tip.zip

unzip tip.zip

cd libressl-portable-tip

bash -lc "cd /mnt/c/erpiko/deps/libressl-portable-tip/ && ./autogen.sh"

bash -lc "cd /mnt/c/erpiko/deps/libressl-portable-tip/ && patch -p0 < ../../patch/cmp.patch"

bash -lc "cd /mnt/c/erpiko/deps/libressl-portable-tip/ && patch -p1 < ../../patch/CMakefiles.patch"

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

copy ssl\%CONFIGURATION%\ssl.lib ..\ssl\

copy tls\%CONFIGURATION%\tls.lib ..\tls\

copy crypto\%CONFIGURATION%\crypto.lib ..\crypto\

mkdir ..\ssl\Debug

mkdir ..\tls\Debug

mkdir ..\crypto\Debug

copy ssl\%CONFIGURATION%\ssl.lib ..\ssl\Debug\

copy tls\%CONFIGURATION%\tls.lib ..\tls\Debug\

copy crypto\%CONFIGURATION%\crypto.lib ..\crypto\Debug\
		
cd ..\..

mkdir catch

cd catch

wget -O catch.hpp https://raw.githubusercontent.com/philsquared/Catch/master/single_include/catch.hpp

cd C:\erpiko