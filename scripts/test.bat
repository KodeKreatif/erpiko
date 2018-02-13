call var.bat

cd build

cd tests

%CONFIGURATION%\testbase.exe

%CONFIGURATION%\testcertificate.exe

%CONFIGURATION%\testcipher.exe

%CONFIGURATION%\testcmp.exe

%CONFIGURATION%\testdata.exe

%CONFIGURATION%\testdigest.exe

%CONFIGURATION%\testkey.exe

%CONFIGURATION%\testrng.exe

%CONFIGURATION%\testsmime.exe

%CONFIGURATION%\testtsa.exe

cd C:\erpiko

mkdir erpiko-%platform%-%CONFIGURATION%

cd erpiko-%platform%-%CONFIGURATION%

mkdir lib

copy ..\deps\libressl\ssl\ssl.lib lib\

copy ..\deps\libressl\tls\tls.lib lib\

copy ..\deps\libressl\crypto\crypto.lib lib\

copy ..\build\src\%CONFIGURATION%\erpiko.lib lib\

xcopy ..\include include /e/i
