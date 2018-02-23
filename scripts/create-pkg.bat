@echo off
call scripts\var.bat
cd %workingdir%

echo Creating compilation of libs and headers to directory erpiko-%platform%-%CONFIGURATION%

rmdir /s /q erpiko-%platform%-%CONFIGURATION%

mkdir erpiko-%platform%-%CONFIGURATION%

cd erpiko-%platform%-%CONFIGURATION%

mkdir lib

copy /y ..\deps\libressl\ssl\ssl.lib lib\
if %configuration%==Debug copy /y ..\deps\libressl\ssl\*.pdb lib\

copy /y ..\deps\libressl\tls\tls.lib lib\
if %configuration%==Debug copy /y ..\deps\libressl\tls\*.pdb lib\

copy /y ..\deps\libressl\crypto\crypto.lib lib\
if %configuration%==Debug copy /y ..\deps\libressl\crypto\*.pdb lib\

copy /y ..\build\src\%CONFIGURATION%\erpiko.lib lib\
if %configuration%==Debug copy /y ..\build\src\%CONFIGURATION%\erpiko.pdb lib\

xcopy ..\include include /e /i /f /y

cd %workingdir%