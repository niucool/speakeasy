/**
 * test_cli_runtime_flags.cpp  Port of test_cli_runtime_flags.py
 * Tests that removed/legacy CLI flags are properly rejected.
 */

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "cli.h"

TEST(CliRuntimeFlagsTest, NoArgumentsShowsHelp) {
    // Running with no arguments should return error
    const char* argv[] = {"speakeasy-cli"};
    int rc = speakeasy::run_cli(1, argv);
    // No args = show usage, non-zero exit
    EXPECT_NE(rc, 0);
}

TEST(CliRuntimeFlagsTest, UnrecognizedArgumentReturnsError) {
    const char* argv[] = {"speakeasy-cli", "--no-such-flag-xyzzy"};
    int rc = speakeasy::run_cli(2, argv);
    EXPECT_NE(rc, 0);
}

TEST(CliRuntimeFlagsTest, LegacyCaptureMemoryDumpsRejected) {
    const char* argv[] = {"speakeasy-cli", "--capture-memory-dumps"};
    int rc = speakeasy::run_cli(2, argv);
    EXPECT_NE(rc, 0);
}

TEST(CliRuntimeFlagsTest, ShortFlagP_Rejected) {
    const char* argv[] = {"speakeasy-cli", "-p", "foo"};
    int rc = speakeasy::run_cli(3, argv);
    EXPECT_NE(rc, 0);
}
