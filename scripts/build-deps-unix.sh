NUMJOBS=5
if [ ! -d deps ];then
  echo "Run this from top directory"
  exit
fi
TOP=`pwd`

# LibreSSL
cd deps
rm -rf portable-master
wget -O master.zip https://github.com/libressl-portable/portable/archive/master.zip
unzip master.zip
cd portable-master
./autogen.sh
mkdir ../libressl
cd ../libressl
../portable-master/configure --enable-static
make -j$NUMJOBS
cp -a ../portable-master/include .
cd $TOP

# Catch
cd deps
mkdir catch
cd catch
wget -O catch.hpp https://raw.githubusercontent.com/philsquared/Catch/master/single_include/catch.hpp
cd $TOP
