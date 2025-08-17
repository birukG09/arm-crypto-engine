cmake_minimum_required(VERSION 3.20)

project(ArmAsm-CryptoEngine VERSION 1.0.0 LANGUAGES C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build configuration options
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build example applications" ON)
option(BUILD_BENCHMARKS "Build benchmark suite" ON)
option(HOST_TESTS "Build for host testing" OFF)
option(STM32F4_TARGET "Build for STM32F4 target" ON)
option(RPI_TARGET "Build for Raspberry Pi target" OFF)

# Platform-specific settings
if(STM32F4_TARGET AND NOT HOST_TESTS)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain-arm-none-eabi.cmake)
    add_definitions(-DSTM32F4 -DARM_MATH_CM4)
    set(PLATFORM_DIR platform/stm32f4)
    set(ASM_SOURCES src/asm/aes_cortex_m4.s src/asm/sha256_cortex_m4.s)
elseif(RPI_TARGET AND NOT HOST_TESTS)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain-aarch64.cmake)
    add_definitions(-DARM_NEON)
    set(PLATFORM_DIR platform/rpi)
    set(ASM_SOURCES src/asm/aes_cortex_a53.s src/asm/sha256_cortex_a53.s)
else()
    # Host build for testing
    set(PLATFORM_DIR platform/host)
    set(ASM_SOURCES "")  # Use C reference implementations for host
endif()

# Include directories
include_directories(include)
include_directories(${PLATFORM_DIR})

# Core library sources
set(CORE_SOURCES
    src/c/aes.c
    src/c/sha256.c
    src/c/ct_utils.c
    ${PLATFORM_DIR}/platform.c
    ${ASM_SOURCES}
)

# Create the main library
add_library(armcrypto STATIC ${CORE_SOURCES})

# Compiler flags for security and performance
if(NOT HOST_TESTS)
    target_compile_options(armcrypto PRIVATE
        -Wall -Wextra -Werror
        -ffunction-sections -fdata-sections
        -fstack-protector-strong
        -Os  # Optimize for size on embedded
    )
    
    if(STM32F4_TARGET)
        target_compile_options(armcrypto PRIVATE
            -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
        )
        target_link_options(armcrypto PRIVATE
            -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
            -Wl,--gc-sections
            -T${CMAKE_CURRENT_SOURCE_DIR}/${PLATFORM_DIR}/linker/stm32f4.ld
        )
    endif()
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(BUILD_EXAMPLES AND NOT HOST_TESTS)
    add_subdirectory(examples)
endif()

# Benchmarks
if(BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

# Installation
install(TARGETS armcrypto DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
