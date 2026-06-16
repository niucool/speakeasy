/**
 * test_file_access.cpp -- Port of test_file_access.py
 * Tests file access emulation: NtCreateFile, NtReadFile, and printf output.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"
#include "profiler_events.h"
#include "test_helper.h"

class FileAccessTest : public ::testing::TestWithParam<const char*> {};

TEST_P(FileAccessTest, FileAccessEmulation) {
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
        ASSERT_FALSE(eps.empty());

        bool found_create = false, found_read = false, found_printf = false;
        std::string file_content;

        if (eps[0].events.has_value()) {
            for (auto* evt : *eps[0].events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (!api) continue;

                if (api->api_name == "ntdll.NtCreateFile") {
                    found_create = true;
                    ASSERT_GE(api->args.size(), 4);
                    EXPECT_EQ(api->args[3], "\\\\??\\\\c:\\\\myfile.txt");
                }
                if (api->api_name == "ntdll.NtReadFile") {
                    found_read = true;
                }
                if (api->api_name.find("__stdio_common_vfprintf") != std::string::npos) {
                    found_printf = true;
                    if (api->args.size() > 2)
                        file_content = api->args[2];
                }
            }
        }

        EXPECT_TRUE(found_create) << "NtCreateFile not called";
        EXPECT_TRUE(found_read) << "NtReadFile not called";
        EXPECT_TRUE(found_printf) << "printf not called";
        EXPECT_NE(file_content.find("File contained:"), std::string::npos);
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

INSTANTIATE_TEST_SUITE_P(
    ArchVariants,
    FileAccessTest,
    ::testing::Values("file_access_test_x86.exe", "file_access_test_x64.exe")
);
