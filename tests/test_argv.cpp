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

        // Collect printf calls from events
        std::vector<std::string> printf_args;
        if (eps[0].events.has_value()) {
            for (auto* evt : *eps[0].events) {
                if (!evt) continue;
                if (evt->event == "api") {
                    auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                    if (api && api->api_name.find("__stdio_common_vfprintf") != std::string::npos) {
                        if (api->args.size() > 2)
                            printf_args.push_back(api->args[2]);
                    }
                }
            }
        }

        // First 2 lines are header, rest are argv entries
        ASSERT_GE(printf_args.size(), 2);
        int actual_argc = static_cast<int>(printf_args.size()) - 2;
        EXPECT_EQ(actual_argc, argv_len);
        for (int i = 0; i < actual_argc; i++) {
            std::string expected = "argv[" + std::to_string(i + 1) +
                                   "] = argument_" + std::to_string(i + 1) + "\n";
            EXPECT_EQ(printf_args[i + 2], expected);
        }
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}
