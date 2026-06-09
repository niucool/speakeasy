/**
 * test_seh.cpp -- Port of test_seh.py
 * Tests SEH (Structured Exception Handling) dispatch during emulation.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"
#include "profiler_events.h"
#include "test_helper.h"

namespace {

const std::vector<std::string> DISPATCH_SCRIPT = {
    "Hello emulator\n",
    "First access violation\r\n",
    "First nested access violation\r\n",
    "Second nested access violation\r\n",
    "After access violations\r\n",
    "In finally\r\n",
    "Returning...\n",
};

} // namespace

TEST(SehTest, SehDispatchEnabled) {
    auto data = load_test_bin("seh_test_x86.exe");
    if (data.empty()) {
        GTEST_SKIP() << "seh_test_x86.exe not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    cfg.exceptions.dispatch_handlers = true;

    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();
        auto& eps = report.entry_points;
        ASSERT_FALSE(eps.empty());

        std::vector<std::string> fmt_strings;
        if (eps[0].events.has_value()) {
            for (auto* evt : *eps[0].events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (api && api->api_name.find("__stdio_common_vfprintf") != std::string::npos) {
                    if (api->args.size() > 2)
                        fmt_strings.push_back(api->args[2]);
                }
            }
        }

        EXPECT_EQ(fmt_strings.size(), DISPATCH_SCRIPT.size());
        for (size_t i = 0; i < std::min(fmt_strings.size(), DISPATCH_SCRIPT.size()); i++) {
            EXPECT_EQ(fmt_strings[i], DISPATCH_SCRIPT[i]) << "Mismatch at index " << i;
        }
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

TEST(SehTest, SehDispatchDisabled) {
    auto data = load_test_bin("seh_test_x86.exe");
    if (data.empty()) {
        GTEST_SKIP() << "seh_test_x86.exe not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    cfg.exceptions.dispatch_handlers = false;

    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();
        auto& eps = report.entry_points;
        ASSERT_FALSE(eps.empty());

        // Should only get 1 printf before error
        int printf_count = 0;
        if (eps[0].events.has_value()) {
            for (auto* evt : *eps[0].events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (api && api->api_name.find("__stdio_common_vfprintf") != std::string::npos) {
                    printf_count++;
                    break;
                }
            }
        }
        EXPECT_EQ(printf_count, 1);

        // Check error type
        if (eps[0].error.has_value()) {
            EXPECT_EQ(eps[0].error->type, "invalid_write");
            if (eps[0].error->instr.has_value()) {
                EXPECT_EQ(*eps[0].error->instr, "mov dword ptr [0], 0x14");
            }
        }
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}
