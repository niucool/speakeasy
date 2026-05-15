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
find_package(pe-parse CONFIG REQUIRED)

# unicorn does not ship a CMake config; use pkg-config or manual lookup
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_UNICORN unicorn IMPORTED_TARGET)
endif()

if(PC_UNICORN_FOUND)
    # pkg-config found it; create an alias for uniform target name
    if(NOT TARGET unicorn::unicorn)
        add_library(unicorn::unicorn ALIAS PkgConfig::PC_UNICORN)
    endif()
else()
    # Manual fallback
    find_path(UNICORN_INCLUDE_DIRS unicorn/unicorn.h
        HINTS ${VCPKG_INSTALLED_DIR}/include
        PATH_SUFFIXES unicorn)
    find_library(UNICORN_LIBRARIES unicorn
        HINTS ${VCPKG_INSTALLED_DIR}/lib)
    if(UNICORN_INCLUDE_DIRS AND UNICORN_LIBRARIES)
        add_library(unicorn::unicorn STATIC IMPORTED)
        set_target_properties(unicorn::unicorn PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${UNICORN_INCLUDE_DIRS}"
            IMPORTED_LOCATION "${UNICORN_LIBRARIES}")
    else()
        message(FATAL_ERROR "unicorn not found. Install via vcpkg: vcpkg install unicorn")
    endif()
endif()

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

# Filter out test/driver files and incomplete modules
list(FILTER SPEAKEASY_SOURCES EXCLUDE REGEX ".*/test/.*")
list(FILTER SPEAKEASY_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")
# win32.cpp now compiles with completed winemu.h

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

    find_package(GTest CONFIG REQUIRED)
    include(GoogleTest)

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

    # Unit tests (Google Test)
    file(GLOB_RECURSE UNIT_TEST_SOURCES "tests/test_*.cpp")
    if(UNIT_TEST_SOURCES)
        add_executable(speakeasy_tests ${UNIT_TEST_SOURCES})
        target_link_libraries(speakeasy_tests PRIVATE
            speakeasy
            GTest::gtest
            GTest::gtest_main
        )
        target_include_directories(speakeasy_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/secpp
        )
        gtest_discover_tests(speakeasy_tests)
    endif()

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
