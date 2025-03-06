# CurveCrypt Project

## Commands

- Build: mkdir -p build && cd build && cmake .. && make
- Test: cd build && make test
- Run Example: cd build && ./examples/curvecrypt_example
- Clean: cd build && make clean

## Code Style Preferences

- Modern C++17 features
- RAII principles for resource management
- Error handling using Result pattern
- Prefer standard library over custom implementations
- Clear function and variable names

## Codebase Structure

- include/curvecrypt/ - Public headers
- src/ - Implementation files
- tests/ - Unit tests
- examples/ - Example applications