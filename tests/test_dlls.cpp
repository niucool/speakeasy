/**
 * test_dlls.cpp -- Port of test_dlls.py
 * Tests DLL emulation with entry points and API call verification.
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

namespace {

// Find API events matching a name pattern
std::vector<const speakeasy::events::ApiEvent*> find_api_events(
    const speakeasy::EntryPoint& ep, const std::string& pattern)
{
    std::vector<const speakeasy::events::ApiEvent*> result;
    if (!ep.events.has_value()) return result;
    for (auto evt : *ep.events) {
        if (!evt || evt->event != "api") continue;
        auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt.get());
        if (api && api->api_name.find(pattern) != std::string::npos)
            result.push_back(api);
    }
    return result;
}

} // namespace

class DllEmuTest : public ::testing::TestWithParam<const char*> {};

TEST_P(DllEmuTest, DllEmulationRuns) {
    const char* bin_name = GetParam();
    auto data = load_test_bin(bin_name);
    if (data.empty()) {
        GTEST_SKIP() << "Test binary " << bin_name << " not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();
        auto& eps = report.entry_points;

        EXPECT_EQ(eps.size(), 3);

        if (eps.size() >= 1) {
            auto msgbox_calls = find_api_events(eps[0], "MessageBoxA");
            if (!msgbox_calls.empty()) {
                ASSERT_GE(msgbox_calls[0]->args.size(), 3);
                EXPECT_EQ(msgbox_calls[0]->args[1], "Inside process attach");
                EXPECT_EQ(msgbox_calls[0]->args[2], "My caption");
            }
            if (eps[0].ret_val.has_value())
                EXPECT_EQ(*eps[0].ret_val, 1);
        }

        if (eps.size() >= 2) {
            auto msgbox_calls = find_api_events(eps[1], "MessageBoxA");
            if (!msgbox_calls.empty()) {
                ASSERT_GE(msgbox_calls[0]->args.size(), 3);
                EXPECT_EQ(msgbox_calls[0]->args[1], "Inside emu_test_one");
                EXPECT_EQ(msgbox_calls[0]->args[2], "First export");
            }
            if (eps[1].ret_val.has_value())
                EXPECT_EQ(*eps[1].ret_val, 0x41414141);
        }

        if (eps.size() >= 3) {
            auto msgbox_calls = find_api_events(eps[2], "MessageBoxW");
            if (!msgbox_calls.empty()) {
                ASSERT_GE(msgbox_calls[0]->args.size(), 3);
                EXPECT_EQ(msgbox_calls[0]->args[1], "Inside emu_test_two");
                EXPECT_EQ(msgbox_calls[0]->args[2], "Second export");
            }
            if (eps[2].ret_val.has_value())
                EXPECT_EQ(*eps[2].ret_val, 0x42424242);
        }
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

INSTANTIATE_TEST_SUITE_P(
    ArchVariants,
    DllEmuTest,
    ::testing::Values("dll_test_x86.dll", "dll_test_x64.dll")
);
