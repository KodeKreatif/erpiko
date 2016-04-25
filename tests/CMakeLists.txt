include_directories(../include ../deps/catch)
add_test(testbase testoid testidentity testbigint)
add_test(testkey testkey)
add_test(testcertificate testcertificate)

add_executable(testkey rsakey.cpp)
target_link_libraries(testkey erpiko libressl)

add_executable(testbigint bigint.cpp)
target_link_libraries(testbigint erpiko libressl)

add_executable(testcertificate certificate.cpp)
target_link_libraries(testcertificate erpiko libressl)

add_executable(testidentity identity.cpp)
target_link_libraries(testidentity erpiko libressl)

add_executable(testoid oid.cpp)
target_link_libraries(testoid erpiko libressl)

