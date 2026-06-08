/**
 * test_cli_runtime_flags.cpp — Port of test_cli_runtime_flags.py
 * Tests that removed/legacy CLI flags are properly rejected.
 */

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "cli.h"

TEST(CliRuntimeFlagsTest, DumpDefaultConfigReturnsSuccess) {
    // --dump-default-config should succeed
    const char* argv[] = {"speakeasy-cli", "--dump-default-config"};
    int rc = speakeasy::run_cli(2, argv);
    EXPECT_EQ(rc, 0);
}

TEST(CliRuntimeFlagsTest, UnrecognizedArgumentReturnsError) {
    // Unknown flags should cause non-zero exit
    const char* argv[] = {"speakeasy-cli", "--no-such-flag-xyzzy"};
    int rc = speakeasy::run_cli(2, argv);
    EXPECT_NE(rc, 0);
}

TEST(CliRuntimeFlagsTest, LegacyCaptureMemoryDumpsRejected) {
    // --capture-memory-dumps was removed (renamed to snapshot_memory_regions)
    const char* argv[] = {"speakeasy-cli", "--capture-memory-dumps"};
    int rc = speakeasy::run_cli(2, argv);
    EXPECT_NE(rc, 0);
}

TEST(CliRuntimeFlagsTest, ShortFlagP_Rejected) {
    // -p was removed from CLI options
    const char* argv[] = {"speakeasy-cli", "-p", "foo"};
    int rc = speakeasy::run_cli(3, argv);
    EXPECT_NE(rc, 0);
}
