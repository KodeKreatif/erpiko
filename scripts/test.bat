@echo off
call scripts\var.bat

cd %workingdir%

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

cd %workingdir%
