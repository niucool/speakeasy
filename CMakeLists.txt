cmake_minimum_required(VERSION 3.16)

# Resolve compatibility errors for dependency CMake files requiring < 3.5
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# Force static CRT linking on MSVC
if(WIN32)
    set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "" FORCE)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

project(speakeasy
    VERSION 1.6.1
    DESCRIPTION "Speakeasy malware emulation framework (C++ port)"
    LANGUAGES CXX
)

#  C++ Standard 
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#  vcpkg Integration 
# Build with:
#   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake (Linux/Mac)
#   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake (Windows)
#
# Required vcpkg packages (install with: vcpkg install <name>):
#   nlohmann-json    JSON parsing / serialization
#   plog             Logging framework
#   unicorn          CPU emulation engine
#   pe-parse         PE file parser

#  Local Dependencies via FetchContent 
include(FetchContent)
set(BUILD_COMMAND_LINE_TOOLS OFF CACHE BOOL "Build Command Line Tools" FORCE)
set(PEPARSE_ENABLE_EXAMPLES OFF CACHE BOOL "Enable building examples" FORCE)
set(PEPARSE_ENABLE_TESTING OFF CACHE BOOL "Enable building tests" FORCE)

FetchContent_Declare(
    pe-parse
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/pe-parse"
)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries" FORCE)

set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "Build static library" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Build shared library" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Build cstool" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Build tests" FORCE)
set(CAPSTONE_ARCHITECTURE_ALL ON CACHE BOOL "Build all architectures" FORCE)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0.1
)

# miniz static compilation
FetchContent_Declare(
    miniz
    GIT_REPOSITORY https://github.com/richgel999/miniz.git
    GIT_TAG        3.0.2
)

# utfcpp  header-only UTF-8/16/32 conversion (replaces manual UTF-16LE handling)
FetchContent_Declare(
    utf8cpp
    GIT_REPOSITORY https://github.com/nemtrif/utfcpp.git
    GIT_TAG        v4.0.6
)

# unicorn static compilation
set(UNICORN_BUILD_SHARED OFF CACHE BOOL "Build shared library" FORCE)
set(UNICORN_BUILD_STATIC ON CACHE BOOL "Build static library" FORCE)
set(UNICORN_ARCH "x86" CACHE STRING "Architectures to build" FORCE)

FetchContent_Declare(
    unicorn
    GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
    GIT_TAG        2.1.4
)

# Make pe-parse, capstone, and miniz available with CMAKE_MSVC_RUNTIME_LIBRARY fully set
FetchContent_MakeAvailable(pe-parse capstone miniz utf8cpp)

# Workaround for Unicorn's custom MSVC runtime flag enforcement
if(MSVC)
    # Save the original value
    set(OLD_MSVC_RUNTIME ${CMAKE_MSVC_RUNTIME_LIBRARY})
    unset(CMAKE_MSVC_RUNTIME_LIBRARY CACHE)
    unset(CMAKE_MSVC_RUNTIME_LIBRARY)
    
    # Append static runtime flag to compiler flags to satisfy Unicorn's check
    if(OLD_MSVC_RUNTIME MATCHES "Debug")
        string(APPEND CMAKE_C_FLAGS " /MTd")
        string(APPEND CMAKE_CXX_FLAGS " /MTd")
    else()
        string(APPEND CMAKE_C_FLAGS " /MT")
        string(APPEND CMAKE_CXX_FLAGS " /MT")
    endif()
endif()

# Make unicorn available under the custom compiler flag workaround
FetchContent_MakeAvailable(unicorn)

if(MSVC)
    # Restore the standard variable for subsequent projects
    set(CMAKE_MSVC_RUNTIME_LIBRARY ${OLD_MSVC_RUNTIME} CACHE STRING "MSVC runtime library" FORCE)
endif()

# Create compatibility aliases for core library target linking
if(NOT TARGET unicorn::unicorn)
    add_library(unicorn::unicorn ALIAS unicorn)
endif()

if(NOT TARGET miniz::miniz)
    add_library(miniz::miniz ALIAS miniz)
endif()

#  Dependencies 
find_package(nlohmann_json CONFIG REQUIRED)
find_package(plog CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(qjs CONFIG REQUIRED)

# distorm — plain C library, no CMake config; create imported target manually
find_library(DISTORM_LIBRARY distorm REQUIRED)
find_path(DISTORM_INCLUDE_DIR distorm.h REQUIRED)
add_library(distorm STATIC IMPORTED)
set_target_properties(distorm PROPERTIES
    IMPORTED_LOCATION "${DISTORM_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${DISTORM_INCLUDE_DIR}"
)



#  Platform Detection 
if(WIN32)
    add_definitions(-DPLATFORM_WINDOWS)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
elseif(UNIX)
    add_definitions(-DPLATFORM_LINUX)
endif()

#  Source Files (re-evaluating for ApiHandler2) 
file(GLOB_RECURSE SPEAKEASY_SOURCES
    "secpp/*.h"
    "secpp/*.cpp"
)

# Filter out test/driver files and incomplete modules
list(FILTER SPEAKEASY_SOURCES EXCLUDE REGEX ".*/test/.*")
list(FILTER SPEAKEASY_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")
# list(FILTER SPEAKEASY_SOURCES EXCLUDE REGEX ".*/scylla_wrapper/.*")
# win32.cpp now compiles with completed winemu.h

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/secpp" FILES ${SPEAKEASY_SOURCES})

#  Library Target 
add_library(speakeasy STATIC ${SPEAKEASY_SOURCES})

target_include_directories(speakeasy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/secpp
)

# (compression stub  miniz not bundled; artifacts.cpp uses "none")

target_link_libraries(speakeasy PUBLIC
    nlohmann_json::nlohmann_json
    plog::plog
    unicorn::unicorn
    pe-parse::pe-parse
    miniz::miniz
    utf8cpp
    qjs
    distorm
)

if(TARGET capstone::capstone)
    target_link_libraries(speakeasy PUBLIC capstone::capstone)
else()
    target_link_libraries(speakeasy PUBLIC capstone)
endif()
target_compile_definitions(speakeasy PRIVATE HAS_CAPSTONE)

#  Compiler Flags 
if(MSVC)
    target_compile_options(speakeasy PRIVATE /W4 /utf-8 /FS)
    target_compile_definitions(speakeasy PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(speakeasy PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
    )
endif()

#  CLI Executable 
add_executable(speakeasy-cli secpp/main.cpp secpp/cli.cpp secpp/cli_config.cpp)
target_link_libraries(speakeasy-cli PRIVATE speakeasy cxxopts::cxxopts)
target_include_directories(speakeasy-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/secpp)

#  Tests 
option(BUILD_TESTS "Build test targets" ON)
if(BUILD_TESTS)
    enable_testing()

    include(FetchContent)
    set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)
    include(GoogleTest)

    # Unit tests (Google Test)  includes smoke_test + all test_*.cpp
    file(GLOB_RECURSE UNIT_TEST_SOURCES "tests/test_*.cpp" "tests/smoke_test.cpp")
    if(UNIT_TEST_SOURCES)
        add_executable(speakeasy_tests ${UNIT_TEST_SOURCES})
        target_include_directories(speakeasy_tests BEFORE PRIVATE
            ${googletest_SOURCE_DIR}/googletest/include
            ${googletest_SOURCE_DIR}/googlemock/include
        )
        target_link_libraries(speakeasy_tests PRIVATE
            speakeasy
            gtest
            gtest_main
        )
        target_include_directories(speakeasy_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/secpp
        )
        gtest_discover_tests(speakeasy_tests)
    endif()

    # Future: add_subdirectory(tests) for full test suite
endif()

#  Install Rules 
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
