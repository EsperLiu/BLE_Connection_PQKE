cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(connection_pqke_central)


target_include_directories(app PRIVATE
    mlkem512
)

file(GLOB MLKEM_SOURCES
    src/mlkem512/*.c
)

target_sources(app PRIVATE
    src/main.c
    ${MLKEM_SOURCES}
)