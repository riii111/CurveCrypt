cmake_minimum_required(VERSION 3.14)

# Add simple example executable
add_executable(curvecrypt_example simple_example.cpp)

# Link against the library
target_link_libraries(curvecrypt_example PRIVATE curvecrypt)