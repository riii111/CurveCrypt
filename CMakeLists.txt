cmake_minimum_required(VERSION 3.14)
project(CurveCrypt VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set default build type to Release
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Options
option(CURVECRYPT_BUILD_TESTS "Build the CurveCrypt test suite" ON)
option(CURVECRYPT_BUILD_EXAMPLES "Build the CurveCrypt example applications" ON)

# Find dependencies
find_package(OpenSSL REQUIRED)

# Library sources
set(CURVECRYPT_SOURCES
    src/error.cpp
    src/utility.cpp
    src/key_pair.cpp
    src/exchange.cpp
    src/secure_message.cpp
)

# Main library target
add_library(curvecrypt ${CURVECRYPT_SOURCES})
target_include_directories(curvecrypt PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(curvecrypt PUBLIC OpenSSL::Crypto)

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(curvecrypt PRIVATE -Wall -Wextra -Wpedantic -Werror)
elseif(MSVC)
    target_compile_options(curvecrypt PRIVATE /W4 /WX)
endif()

# Tests
if(CURVECRYPT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(CURVECRYPT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
include(GNUInstallDirs)
install(TARGETS curvecrypt
    EXPORT curvecrypt-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Export targets
install(EXPORT curvecrypt-targets
    FILE CurveCryptTargets.cmake
    NAMESPACE CurveCrypt::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CurveCrypt
)