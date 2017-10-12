rm -rf deps
mkdir deps

# LibreSSL
cd deps
rm -rf libressl-portable-tip
wget -O tip.zip https://github.com/mdamt/libressl-portable/archive/tip.zip
unzip tip.zip
cd libressl-portable-tip
./autogen.sh
patch -p0 < ../../patch/cmp.patch
mkdir ../libressl
cd ../libressl
../libressl-portable-tip/configure --enable-static
cd ../libressl-portable-tip
patch -p1 < ../../patch/CMakefiles.patch
cd ../libressl
cmake -G "Unix Makefiles"  ../libressl-portable-tip
make -j3
cp -a ../libressl-portable-tip/include .
cd ../..


# Catch
cd deps
mkdir catch
cd catch
wget -O catch.hpp https://raw.githubusercontent.com/philsquared/Catch/master/single_include/catch.hpp
cd ../..
