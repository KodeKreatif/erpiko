NUMJOBS=5
if [ ! -d deps ];then
  echo "Run this from top directory"
  exit
fi
TOP=`pwd`

# LibreSSL
cd deps
rm -rf libressl-portable-tip
wget -O tip.zip https://github.com/mdamt/libressl-portable/archive/tip.zip
unzip tip.zip
cd libressl-portable-tip
./autogen.sh
patch -p0 < $TOP/patch/cmp.patch
mkdir ../libressl
cd ../libressl
../libressl-portable-tip/configure --enable-static
make -j$NUMJOBS
cp -a ../libressl-portable-tip/include .
cd $TOP


# Catch
cd deps
mkdir catch
cd catch
wget -O catch.hpp https://raw.githubusercontent.com/philsquared/Catch/master/single_include/catch.hpp
cd $TOP
