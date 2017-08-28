include_directories(../include ../deps/catch)
add_test(testbase testbase)
add_test(testkey testkey)
add_test(testcertificate testcertificate)
add_test(testdata testdata)
add_test(testcmp testcmp)
add_test(testsmime testdata)
add_test(testtsa testtsa)
add_test(testrng testrng)
add_test(testdigest testdigest)
add_test(testcipher testcipher)

add_executable(testkey rsakey.cpp)
target_link_libraries(testkey erpiko libresslcrypto)

add_executable(testcmp cmp.cpp)
target_link_libraries(testcmp erpiko libresslcrypto libresslssl libresslcrypto)

add_executable(testbase main.cpp bigint.cpp identity.cpp oid.cpp time.cpp data-source.cpp)
target_link_libraries(testbase erpiko libresslcrypto)

add_executable(testcertificate certificate.cpp)
target_link_libraries(testcertificate erpiko libresslcrypto)

add_executable(testdata pkcs12.cpp signed-data.cpp sim.cpp enveloped-data.cpp)
target_link_libraries(testdata erpiko libresslcrypto)

add_executable(testsmime smime.cpp)
target_link_libraries(testsmime erpiko libresslcrypto)

add_executable(testtsa tsa.cpp)
target_link_libraries(testtsa erpiko libresslcrypto)

add_executable(testrng rng.cpp)
target_link_libraries(testrng erpiko libresslcrypto)

add_executable(testdigest digest.cpp)
target_link_libraries(testdigest erpiko libresslcrypto)

add_executable(testcipher cipher.cpp rc.cpp cast.cpp 3des.cpp des.cpp aes.cpp)
target_link_libraries(testcipher erpiko libresslcrypto)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/assets" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
