cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(connection_pqke)

target_include_directories(app PRIVATE
    include
    include/mlkem512
)

file(GLOB MLKEM_SOURCES
    include/mlkem512/*.c
)

target_sources(app PRIVATE
    src/main.c
    src/ble_service.c
    src/pqke_crypto.c
    src/pqke_state.c
    src/pqke_transfer.c
    src/debug_utils.c
    ${MLKEM_SOURCES}
)