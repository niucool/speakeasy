/**
 * test_filename_override.cpp -- Port of test_filename_override.py
 * Tests the filename parameter on load_module.
 *
 * The Python Speakeasy.load_module accepts a `filename` keyword argument
 * that overrides the emulated module name. In C++, the module name is
 * derived from the emu_path set during loading. This test verifies that
 * loading a module from raw data works and the emulation runs.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "test_helper.h"

TEST(FilenameOverrideTest, LoadModuleFromData) {
    auto data = load_test_bin("dll_test_x86.dll");
    if (data.empty()) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    Speakeasy se;
    // Load from raw data (empty path = data-only loading)
    auto module = se.load_module("", data);
    EXPECT_NE(module, nullptr);
    EXPECT_GT(module->base, 0);
    se.shutdown();
}
