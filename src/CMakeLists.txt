add_library(erpiko rsakey.cpp rsakey-public.cpp bigint.cpp)
target_link_libraries(erpiko libressl)
