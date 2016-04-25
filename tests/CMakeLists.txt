include_directories(../include ../deps/catch)
add_test(testkey testkey testbigint)

add_executable(testkey rsakey.cpp)
target_link_libraries(testkey erpiko libressl)

add_executable(testbigint bigint.cpp)
target_link_libraries(testbigint erpiko libressl)
