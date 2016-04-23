include_directories(../include ../deps/catch)
add_test(testkey testkey)

add_executable(testkey key.cpp)
target_link_libraries(testkey erpiko libressl)
