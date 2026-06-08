/**
 * test_gdb.cpp — Port of test_gdb.py
 * Tests GDB server integration (RSP protocol client).
 *
 * NOTE: The Python test_gdb.py requires:
 * - SPEAKEASY_ENABLE_GDB_TESTS=1 environment variable
 * - udbserver Python package
 * - Subprocess-based GDB server lifecycle
 * - Socket-level GDB RSP protocol interaction
 *
 * This is a heavy integration test that would require:
 * 1. A GDB RSP client library in C++
 * 2. The ability to spawn Speakeasy with GDB port in a subprocess/thread
 * 3. The udbserver Rust FFI layer
 *
 * For now, these are documented as integration tests to be implemented
 * when the C++ GDB server is ready.
 */

#include <gtest/gtest.h>
#include <cstdlib>
#include <string>

namespace {

bool gdb_tests_enabled() {
    const char* env = std::getenv("SPEAKEASY_ENABLE_GDB_TESTS");
    return env && std::string(env) == "1";
}

} // namespace

TEST(GdbTest, ConnectAndReadRegisters) {
    if (!gdb_tests_enabled()) {
        GTEST_SKIP() << "Set SPEAKEASY_ENABLE_GDB_TESTS=1 to run GDB integration tests";
    }

    // Python: Starts Speakeasy with GDB port in a subprocess,
    // connects via GdbRspClient, sends "g" to read registers,
    // verifies EIP register is non-zero.
    //
    // C++ implementation would:
    // 1. Start Speakeasy with gdb_port in background thread
    // 2. Connect TCP socket to 127.0.0.1:{port}
    // 3. Send RSP "?" (halt reason), "g" (read registers)
    // 4. Parse hex register data, extract EIP
    // 5. Verify EIP is non-zero
    // 6. Send "c" (continue), disconnect

    GTEST_SKIP() << "GDB RSP client not yet implemented in C++";
}

TEST(GdbTest, ReadMemory) {
    if (!gdb_tests_enabled()) {
        GTEST_SKIP() << "Set SPEAKEASY_ENABLE_GDB_TESTS=1 to run GDB integration tests";
    }

    GTEST_SKIP() << "GDB RSP client not yet implemented in C++";
}

TEST(GdbTest, SingleStep) {
    if (!gdb_tests_enabled()) {
        GTEST_SKIP() << "Set SPEAKEASY_ENABLE_GDB_TESTS=1 to run GDB integration tests";
    }

    GTEST_SKIP() << "GDB RSP client not yet implemented in C++";
}
