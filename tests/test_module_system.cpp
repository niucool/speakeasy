/**
 * test_module_system.cpp — Port of test_module_system.py
 * Tests the module system: static imports, GetProcAddress, module lookup,
 * PEB module list, and loader provenance.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"
#include "profiler_events.h"

namespace {

std::vector<uint8_t> load_test_bin(const std::string& name) {
    std::string cmd = "xz -d -c tests/bins/" + name + ".xz 2>/dev/null";
    auto* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::vector<uint8_t> data;
    char buf[4096];
    while (size_t n = std::fread(buf, 1, sizeof(buf), pipe))
        data.insert(data.end(), buf, buf + n);
    pclose(pipe);
    return data;
}

} // namespace

TEST(ModuleSystemTest, StaticImportDispatchesApiHandler) {
    auto data = load_test_bin("dll_test_x86.dll");
    if (data.empty()) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();

        auto& ep = report.entry_points[0];
        bool found_msgbox = false;
        if (ep.events.has_value()) {
            for (auto* evt : *ep.events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (api && api->api_name.find("MessageBox") != std::string::npos) {
                    found_msgbox = true;
                    break;
                }
            }
        }
        EXPECT_TRUE(found_msgbox) << "MessageBox API not dispatched via static import";
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

TEST(ModuleSystemTest, GetProcAddressDynamicResolution) {
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

        auto& ep = report.entry_points[0];
        bool found_gpa = false, found_success = false;
        if (ep.events.has_value()) {
            for (auto* evt : *ep.events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (api && api->api_name == "kernel32.GetProcAddress") {
                    found_gpa = true;
                    if (!api->ret_val.empty() && api->ret_val != "0x0")
                        found_success = true;
                }
            }
        }
        EXPECT_TRUE(found_gpa) << "GetProcAddress not called";
        EXPECT_TRUE(found_success) << "No successful GetProcAddress resolution";
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

TEST(ModuleSystemTest, PEBModulesPopulated) {
    auto data = load_test_bin("dll_test_x86.dll");
    if (data.empty()) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);

        auto user_modules = se.get_user_modules();
        EXPECT_FALSE(user_modules.empty()) << "PEB modules should be populated";
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}
