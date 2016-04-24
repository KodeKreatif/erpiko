add_library(erpiko rsakey.cpp bigint.cpp)
target_link_libraries(erpiko libressl)
