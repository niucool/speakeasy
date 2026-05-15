cmake_minimum_required(VERSION 3.16)
project(speakeasy
    VERSION 1.6.1
    DESCRIPTION "Speakeasy malware emulation framework (C++ port)"
    LANGUAGES CXX
)

# ── C++ Standard ──────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── vcpkg Integration ─────────────────────────────────────────
# Build with:
#   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
#
# Required vcpkg packages (install with: vcpkg install <name>):
#   nlohmann-json   – JSON parsing / serialization
#   plog            – Logging framework
#   unicorn         – CPU emulation engine
#   pe-parse        – PE file parser

# ── Dependencies ──────────────────────────────────────────────
find_package(nlohmann_json CONFIG REQUIRED)
find_package(plog CONFIG REQUIRED)
find_package(unicorn CONFIG REQUIRED)
find_package(pe-parse CONFIG REQUIRED)

# Optional: Capstone for disassembly (used in binemu)
find_package(capstone QUIET)

# ── Platform Detection ────────────────────────────────────────
if(WIN32)
    add_definitions(-DPLATFORM_WINDOWS)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
elseif(UNIX)
    add_definitions(-DPLATFORM_LINUX)
endif()

# ── Source Files ──────────────────────────────────────────────
file(GLOB_RECURSE SPEAKEASY_SOURCES
    "secpp/*.cpp"
)

# Filter out test/driver files if any
list(FILTER SPEAKEASY_SOURCES EXCLUDE REGEX ".*/test/.*")
list(FILTER SPEAKEASY_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")

# ── Library Target ────────────────────────────────────────────
add_library(speakeasy STATIC ${SPEAKEASY_SOURCES})

target_include_directories(speakeasy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/secpp
)

target_link_libraries(speakeasy PUBLIC
    nlohmann_json::nlohmann_json
    plog::plog
    unicorn::unicorn
    pe-parse::pe-parse
)

if(capstone_FOUND)
    target_link_libraries(speakeasy PRIVATE capstone::capstone)
    target_compile_definitions(speakeasy PRIVATE HAS_CAPSTONE)
endif()

# ── Compiler Flags ────────────────────────────────────────────
if(MSVC)
    target_compile_options(speakeasy PRIVATE /W4 /utf-8)
    target_compile_definitions(speakeasy PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(speakeasy PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
    )
endif()

# ── CLI Executable ────────────────────────────────────────────
# Uncomment and create secpp/main.cpp when CLI port is ready
# add_executable(speakeasy-cli secpp/main.cpp)
# target_link_libraries(speakeasy-cli PRIVATE speakeasy)

# ── Tests ─────────────────────────────────────────────────────
option(BUILD_TESTS "Build test targets" ON)
if(BUILD_TESTS)
    enable_testing()

    # Smoke test – verifies library linkage
    add_executable(smoke_test tests/smoke_test.cpp)
    target_link_libraries(smoke_test PRIVATE
        nlohmann_json::nlohmann_json
        plog::plog
        unicorn::unicorn
        pe-parse::pe-parse
    )
    if(capstone_FOUND)
        target_link_libraries(smoke_test PRIVATE capstone::capstone)
    endif()
    add_test(NAME SmokeTest COMMAND smoke_test)

    # Future: add_subdirectory(tests) for full test suite
endif()

# ── Install Rules ─────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS speakeasy
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY secpp/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/speakeasy
    FILES_MATCHING PATTERN "*.h"
    PATTERN "*.cpp" EXCLUDE
)

install(DIRECTORY secpp/configs/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/speakeasy/configs
)

install(DIRECTORY secpp/resources/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/speakeasy/resources
)
