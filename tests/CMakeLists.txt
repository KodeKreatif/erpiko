include_directories(../include ../deps/catch)
add_test(testkey testkey)

add_executable(testkey rsakey.cpp)
target_link_libraries(testkey erpiko libressl)
