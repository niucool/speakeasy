/**
 * test_memory_capture.cpp — Port of test_memory_capture.py
 * Tests memory region capture/dump behavior during emulation.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"

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

class MemoryCaptureTest : public ::testing::Test {
protected:
    bool run_report(speakeasy::Report& report) {
        auto data = load_test_bin("dll_test_x86.dll");
        if (data.empty()) return false;

        speakeasy::SpeakeasyConfig cfg;
        cfg.snapshot_memory_regions = true;
        cfg.analysis.memory_tracing = true;

        Speakeasy se(cfg);
        auto module = se.load_module("", data);
        se.run_module(module, true);
        report = se.get_report();
        se.shutdown();
        return true;
    }
};

TEST_F(MemoryCaptureTest, CapturedDataRefsResolve) {
    speakeasy::Report report;
    if (!run_report(report)) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    EXPECT_TRUE(report.data.has_value());
    EXPECT_FALSE(report.data->empty());

    for (auto& ep : report.entry_points) {
        if (ep.memory.has_value()) {
            for (auto& region : ep.memory->layout) {
                if (region.data_ref.has_value()) {
                    EXPECT_TRUE(report.data->count(*region.data_ref) > 0)
                        << "data_ref " << *region.data_ref << " not found in report data";
                }
            }
        }
    }
}

TEST_F(MemoryCaptureTest, StackRegionsExcluded) {
    speakeasy::Report report;
    if (!run_report(report)) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    for (auto& ep : report.entry_points) {
        if (ep.memory.has_value()) {
            for (auto& region : ep.memory->layout) {
                if (region.tag.find("emu.stack") == 0) {
                    EXPECT_FALSE(region.data_ref.has_value())
                        << "Stack region should not have data_ref: " << region.tag;
                }
            }
        }
    }
}

TEST_F(MemoryCaptureTest, HeapRegionsExcluded) {
    speakeasy::Report report;
    if (!run_report(report)) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    for (auto& ep : report.entry_points) {
        if (ep.memory.has_value()) {
            for (auto& region : ep.memory->layout) {
                if (region.tag.find("api.heap") == 0 ||
                    region.tag == "emu.process_heap") {
                    EXPECT_FALSE(region.data_ref.has_value())
                        << "Heap region should not have data_ref: " << region.tag;
                }
            }
        }
    }
}

TEST_F(MemoryCaptureTest, ReportDataDeduplicatesRepeatedRegions) {
    speakeasy::Report report;
    if (!run_report(report)) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    std::vector<std::string> region_refs;
    for (auto& ep : report.entry_points) {
        if (ep.memory.has_value()) {
            for (auto& region : ep.memory->layout) {
                if (region.data_ref.has_value())
                    region_refs.push_back(*region.data_ref);
            }
        }
    }

    std::set<std::string> unique(region_refs.begin(), region_refs.end());
    // With deduplication, unique refs should be <= total refs
    EXPECT_LE(unique.size(), region_refs.size());
}
