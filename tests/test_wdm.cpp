/**
 * test_wdm.cpp -- Port of test_wdm.py
 * Tests WDM driver emulation: device creation, symbolic links, IRP handlers.
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

const std::string DEV_NAME = "\\Device\\wdm_test";
const std::string SYM_LINK = "\\DosDevices\\wdm_test";

} // namespace

class WdmTest : public ::testing::TestWithParam<const char*> {};

TEST_P(WdmTest, DISABLED_DriverLoadUnload) {
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

        auto& driver_entry = eps[0];
        bool found_create_dev = false, found_create_sym = false;

        if (driver_entry.events.has_value()) {
            for (auto evt : *driver_entry.events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt.get());
                if (!api) continue;

                if (api->api_name == "ntoskrnl.IoCreateDeviceSecure") {
                    found_create_dev = true;
                    ASSERT_GE(api->args.size(), 3);
                    EXPECT_EQ(api->args[2], DEV_NAME);
                }
                if (api->api_name == "ntoskrnl.IoCreateSymbolicLink") {
                    found_create_sym = true;
                    ASSERT_GE(api->args.size(), 2);
                    EXPECT_EQ(api->args[0], SYM_LINK);
                    EXPECT_EQ(api->args[1], DEV_NAME);
                }
            }
        }

        EXPECT_TRUE(found_create_dev) << "IoCreateDeviceSecure not called";
        EXPECT_TRUE(found_create_sym) << "IoCreateSymbolicLink not called";
        if (driver_entry.ret_val.has_value())
            EXPECT_EQ(*driver_entry.ret_val, 0);

        // Last entry point is driver unload
        auto& unload_entry = eps.back();
        bool found_delete_sym = false, found_delete_dev = false;

        if (unload_entry.events.has_value()) {
            for (auto evt : *unload_entry.events) {
                if (!evt || evt->event != "api") continue;
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt.get());
                if (!api) continue;

                if (api->api_name == "ntoskrnl.IoDeleteSymbolicLink") {
                    found_delete_sym = true;
                    ASSERT_GE(api->args.size(), 1);
                    EXPECT_EQ(api->args[0], SYM_LINK);
                }
                if (api->api_name == "ntoskrnl.IoDeleteDevice") {
                    found_delete_dev = true;
                    ASSERT_GE(api->args.size(), 1);
                    EXPECT_NE(api->args[0], "0x0");
                }
            }
        }

        EXPECT_TRUE(found_delete_sym) << "IoDeleteSymbolicLink not called";
        EXPECT_TRUE(found_delete_dev) << "IoDeleteDevice not called";
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

TEST_P(WdmTest, DISABLED_IrpHandlers) {
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

        int irp_count = 0;
        for (auto& ep : eps) {
            if (ep.ep_type.find("irp_") == 0) {
                irp_count++;
                bool found_dbgprint = false;
                if (ep.events.has_value()) {
                    for (auto evt : *ep.events) {
                        if (!evt || evt->event != "api") continue;
                        auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt.get());
                        if (api && api->api_name == "ntoskrnl.DbgPrint") {
                            found_dbgprint = true;
                            ASSERT_GE(api->args.size(), 1);
                            if (ep.ep_type == "irp_mj_create") {
                                EXPECT_EQ(api->args[0], "Inside IRP_MJ_CREATE handler");
                                if (ep.ret_val.has_value()) EXPECT_EQ(*ep.ret_val, 0);
                            } else if (ep.ep_type == "irp_mj_device_control") {
                                EXPECT_EQ(api->args[0], "Inside IRP_MJ_DEVICE_CONTROL handler");
                                if (ep.ret_val.has_value()) EXPECT_EQ(*ep.ret_val, 0);
                            } else if (ep.ep_type == "irp_mj_close") {
                                EXPECT_EQ(api->args[0], "Inside IRP_MJ_CLOSE handler");
                                if (ep.ret_val.has_value()) EXPECT_EQ(*ep.ret_val, 0);
                            } else {
                                EXPECT_EQ(api->args[0], "Inside default handler");
                                if (ep.ret_val.has_value()) EXPECT_EQ(*ep.ret_val, 0xC00000BB);
                            }
                            break;
                        }
                    }
                }
                EXPECT_TRUE(found_dbgprint) << "DbgPrint not found in " << ep.ep_type;
            }
        }
        EXPECT_EQ(irp_count, 6);
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

INSTANTIATE_TEST_SUITE_P(
    ArchVariants,
    WdmTest,
    ::testing::Values("wdm_test_x86.sys", "wdm_test_x64.sys")
);
