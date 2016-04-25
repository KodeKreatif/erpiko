add_library(erpiko rsakey.cpp rsakey-public.cpp bigint.cpp certificate.cpp identity.cpp oid.cpp)
target_link_libraries(erpiko libressl)
