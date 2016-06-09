add_library(erpiko rsakey.cpp rsakey-public.cpp bigint.cpp certificate.cpp identity.cpp oid.cpp time.cpp data-source.cpp pkcs12.cpp cmp.cpp signed-data.cpp sim.cpp enveloped-data.cpp)
target_link_libraries(erpiko libresslssl libresslcrypto)
