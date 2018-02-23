REM platform value is x86 or x64
set platform=x64
REM configuration value is Debug or Release 
set configuration=Debug
REM set your visual studio location
set VS140COMNTOOLS=C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\
REM set windows base build dir
set workingdir=%cd%
REM set Nix base build dir
for /f "delims=" %%a in ('bash -lc "pwd"') do set workingdirnix=%%a