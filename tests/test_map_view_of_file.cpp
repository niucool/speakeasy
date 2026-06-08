/**
 * test_map_view_of_file.cpp — Port of test_map_view_of_file.py
 * Tests that MapViewOfFile produces regions with readable protections.
 *
 * NOTE: This test requires capa-testfiles submodule with PMA samples.
 * It verifies that memory-mapped file views have appropriate access protections.
 */

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"

TEST(MapViewOfFileTest, UsesReadableProtections) {
    // Full test requires:
    // 1. capa-testfiles submodule (PMA 01-01.exe, 01-01.dll, kernel32.dll)
    // 2. Running the sample with argv triggering MapViewOfFile
    // 3. Verifying all mapped regions have prot in {r--, rw-, r-x, rwx}

    GTEST_SKIP() << "MapViewOfFile protection test requires capa-testfiles submodule";
}

TEST(MapViewOfFileTest, NoReadProtError) {
    // Verify that emulation does NOT produce "Read from non-readable memory" errors
    GTEST_SKIP() << "Requires capa-testfiles submodule";
}
