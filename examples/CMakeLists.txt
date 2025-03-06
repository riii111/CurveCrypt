cmake_minimum_required(VERSION 3.14)

# Add simple example executable
add_executable(curvecrypt_example simple_example.cpp)

# Add CLI tool
add_executable(curvecrypt_cli curve_cli.cpp)

# Link against the library
target_link_libraries(curvecrypt_example PRIVATE curvecrypt)
target_link_libraries(curvecrypt_cli PRIVATE curvecrypt)

# Install targets
install(TARGETS curvecrypt_example curvecrypt_cli
        RUNTIME DESTINATION bin)