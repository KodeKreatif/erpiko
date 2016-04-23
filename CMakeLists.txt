project("erpiko")
cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(warnings "-Wall -Wextra -Werror")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(warnings "/W4 /WX /EHsc")
endif()

if (NOT CONFIGURED_ONCE)
  set(CMAKE_CXX_FLAGS "-std=c++14 ${warnings}"
    CACHE STRING "Flags used by the compiler during all build types." FORCE)
endif()


include_directories(include)

add_library(libressl STATIC IMPORTED)
set_property(TARGET libressl PROPERTY IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/deps/libressl/crypto/.libs/libcrypto.a)

enable_testing()
add_subdirectory(src)
add_subdirectory(tests)


set(CONFIGURED_ONCE TRUE CACHE INTERNAL
  "A flag showing that CMake has configured at least once.")
