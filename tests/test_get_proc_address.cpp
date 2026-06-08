/**
 * test_get_proc_address.cpp — Port of test_get_proc_address.py
 * Tests GetProcAddress behavior for existing and missing functions.
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


TEST(GetProcAddressTest, MissingFunctionReturnsZero) {
    auto data = load_test_bin("GetProcAddress.exe");
    if (data.empty()) {
        GTEST_SKIP() << "GetProcAddress.exe not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();
        auto& eps = report.entry_points;
        ASSERT_FALSE(eps.empty());

        // Find all GetProcAddress API calls
        std::vector<const speakeasy::events::ApiEvent*> gpa_calls;
        if (eps[0].events.has_value()) {
            for (auto* evt : *eps[0].events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (api && api->api_name == "kernel32.GetProcAddress")
                    gpa_calls.push_back(api);
            }
        }

        ASSERT_GE(gpa_calls.size(), 4);

        // 3rd call (index 2): AreFileApisANSI — should succeed
        ASSERT_GE(gpa_calls[2]->args.size(), 2);
        EXPECT_EQ(gpa_calls[2]->args[1], "AreFileApisANSI");
        EXPECT_NE(gpa_calls[2]->ret_val, "0x0");

        // 4th call (index 3): ThisFunctionIsNotExportedByKernel32 — should fail
        ASSERT_GE(gpa_calls[3]->args.size(), 2);
        EXPECT_EQ(gpa_calls[3]->args[1], "ThisFunctionIsNotExportedByKernel32");
        EXPECT_EQ(gpa_calls[3]->ret_val, "0x0");
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}
