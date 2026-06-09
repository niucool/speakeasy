/**
 * test_coverage.cpp -- Port of test_coverage.py
 * Tests that code coverage data is collected when coverage analysis is enabled.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>

#include "speakeasy.h"
#include "config.h"
#include "report.h"
#include "test_helper.h"

TEST(CoverageTest, CoverageEnabled) {
    auto data = load_test_bin("dll_test_x86.dll");
    if (data.empty()) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    cfg.analysis.coverage = true;

    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();
        auto& eps = report.entry_points;
        ASSERT_FALSE(eps.empty());

        int eps_with_coverage = 0;
        for (auto& ep : eps) {
            if (ep.coverage.has_value() && !ep.coverage->empty()) {
                eps_with_coverage++;
                for (auto addr : *ep.coverage) {
                    EXPECT_GT(addr, 0);
                }
            }
        }
        EXPECT_GT(eps_with_coverage, 0) << "No entry points have coverage data";
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}
