cmake_minimum_required(VERSION 3.16)

project(booto
    VERSION 0.3.0
    DESCRIPTION "Debian-Based Tails-Inspired Live Linux Forensic Rootkit & Bootkit Detection Suite"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Compiler Hardening & Warning Flags
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -Wshadow
    -Wformat=2
    -Wconversion
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
    -D_POSIX_C_SOURCE=200809L
    -D_DEFAULT_SOURCE
)

add_link_options(-pie -Wl,-z,relro,-z,now)

# Extract Git commit hash if available
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT GIT_COMMIT_HASH)
    set(GIT_COMMIT_HASH "unknown")
endif()

string(TIMESTAMP BUILD_TIMESTAMP "%Y-%m-%dT%H:%M:%SZ" UTC)
set(PROJECT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(PROJECT_VERSION_PATCH ${PROJECT_VERSION_PATCH})

# Generate include/version.h
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/version.h
    @ONLY
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

# Core library sources
set(BOOT_LIB_SOURCES
    src/logger.c
    src/crypto_utils.c
    src/elf_analyzer.c
    src/kernel_inspector.c
    src/disk_mount.c
    src/tui/terminal.c
    src/tui/wm.c
    src/tui/pane.c
    src/tui/tui_app.c
)

add_library(booto_core STATIC ${BOOT_LIB_SOURCES})

# Executable binary
add_executable(booto src/main.c)
target_link_libraries(booto PRIVATE booto_core)

# Unit Testing Targets
enable_testing()

add_executable(test_version tests/test_version.c)
target_link_libraries(test_version PRIVATE booto_core)
add_test(NAME test_version COMMAND test_version)

add_executable(test_logger tests/test_logger.c)
target_link_libraries(test_logger PRIVATE booto_core)
add_test(NAME test_logger COMMAND test_logger)

add_executable(test_wm_tree tests/test_wm_tree.c)
target_link_libraries(test_wm_tree PRIVATE booto_core)
add_test(NAME test_wm_tree COMMAND test_wm_tree)

add_executable(test_disk_discovery tests/test_disk_discovery.c)
target_link_libraries(test_disk_discovery PRIVATE booto_core)
add_test(NAME test_disk_discovery COMMAND test_disk_discovery)

add_executable(test_elf_analyzer tests/test_elf_analyzer.c)
target_link_libraries(test_elf_analyzer PRIVATE booto_core)
add_test(NAME test_elf_analyzer COMMAND test_elf_analyzer)

# Custom Target for ISO generation
add_custom_target(iso
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/build_iso.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building Debian Live ISO (booto-live.iso)..."
)
