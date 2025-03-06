cmake_minimum_required(VERSION 3.14)

# Find Catch2 or include it
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v2.13.9
)
FetchContent_MakeAvailable(Catch2)

# Add test executable
add_executable(curvecrypt_tests
    test_main.cpp
    test_utility.cpp
    test_key_pair.cpp
    test_exchange.cpp
    test_secure_message.cpp
)

# Link against the library and test framework
target_link_libraries(curvecrypt_tests PRIVATE curvecrypt Catch2::Catch2)

# Add tests to CTest
include(CTest)
add_test(NAME curvecrypt_tests COMMAND curvecrypt_tests)