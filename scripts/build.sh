NUMJOB=${NUMJOB:-2}
rm -rf build
mkdir build
cd build
cmake -G "Unix Makefiles" ..
make -j$NUMJOB
