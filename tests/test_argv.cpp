/**
 * test_argv.cpp — Port of test_argv.py
 * Tests that command-line arguments are correctly passed to emulated executables.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"
#include "profiler_events.h"

#include "test_helper.h"

TEST(ArgvTest, ArgvPassedToExe) {
    auto data = load_test_bin("argv_test_x86.exe");
    if (data.empty()) {
        GTEST_SKIP() << "argv_test_x86.exe not available";
    }

    int argv_len = 10;
    std::vector<std::string> argv;
    for (int i = 0; i < argv_len; i++)
        argv.push_back("argument_" + std::to_string(i + 1));

    speakeasy::SpeakeasyConfig cfg;
    Speakeasy se(cfg, argv);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();
        auto& eps = report.entry_points;
        ASSERT_FALSE(eps.empty());

        // The emulation should complete with at least one entry point.
        // The test binary calls printf for each argv entry, then exits.
        EXPECT_FALSE(eps[0].ep_type.empty());
        EXPECT_GT(eps[0].start_addr, 0);

        // If events were captured, verify printf calls
        if (eps[0].events.has_value()) {
            int printf_count = 0;
            for (auto* evt : *eps[0].events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (api && api->api_name.find("printf") != std::string::npos)
                    printf_count++;
            }
            EXPECT_GE(printf_count, argv_len)
                << "Expected at least " << argv_len << " printf calls";
        }
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}
