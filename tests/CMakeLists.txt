include_directories(../include ../deps/catch)
add_test(testbase testbase WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_test(testkey testkey)
add_test(testcertificate testcertificate WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_test(testdata testdata WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(testkey rsakey.cpp)
target_link_libraries(testkey erpiko libressl)

add_executable(testbase main.cpp bigint.cpp identity.cpp oid.cpp time.cpp data-source.cpp)
target_link_libraries(testbase erpiko libressl)

add_executable(testcertificate certificate.cpp)
target_link_libraries(testcertificate erpiko libressl)

add_executable(testdata pkcs12.cpp)
target_link_libraries(testdata erpiko libressl)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/assets" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
