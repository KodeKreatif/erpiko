include_directories(../include ../deps/catch)
add_test(testbase testbase WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_test(testkey testkey)
add_test(testcertificate testcertificate WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_test(testdata testdata WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_test(testcmp testcmp WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(testkey rsakey.cpp)
target_link_libraries(testkey erpiko libresslcrypto)

add_executable(testcmp cmp.cpp)
target_link_libraries(testcmp erpiko libresslcrypto libresslssl libresslcrypto)

add_executable(testbase main.cpp bigint.cpp identity.cpp oid.cpp time.cpp data-source.cpp)
target_link_libraries(testbase erpiko libresslcrypto)

add_executable(testcertificate certificate.cpp)
target_link_libraries(testcertificate erpiko libresslcrypto)

add_executable(testdata pkcs12.cpp)
target_link_libraries(testdata erpiko libresslcrypto)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/assets" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
