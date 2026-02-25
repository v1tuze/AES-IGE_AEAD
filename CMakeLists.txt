cmake_minimum_required(VERSION 3.10)
project(aes_ige_aead C)

set(CMAKE_C_STANDARD 99)

set(SOURCES
    src/sha256.c src/aes.c src/gf128.c src/aes_ige.c src/poly_mac.c src/aes_ige_aead.c
    src/chacha20.c src/poly1305.c src/chacha20_poly1305.c
)

add_library(aes_ige_aead ${SOURCES})
target_include_directories(aes_ige_aead PUBLIC include)

add_executable(test_vectors tests/test_vectors.c)
target_link_libraries(test_vectors aes_ige_aead)

add_executable(demo demo/demo.c)
target_link_libraries(demo aes_ige_aead)

enable_testing()
add_test(NAME test_vectors COMMAND test_vectors)
