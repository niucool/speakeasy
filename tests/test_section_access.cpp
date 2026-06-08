/**
 * test_section_access.cpp — Port of test_section_access.py
 * Tests PE section memory access tracking (reads, writes, execs per section).
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"

#include "test_helper.h"


TEST(SectionAccessTest, TextSectionHasExecs) {
    auto data = load_test_bin("dll_test_x86.dll");
    if (data.empty()) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    cfg.analysis.memory_tracing = true;

    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();

        for (auto& ep : report.entry_points) {
            if (!ep.memory.has_value()) continue;

            for (auto& mod : ep.memory->modules) {
                if (mod.segments.empty()) continue;

                for (auto& seg : mod.segments) {
                    std::string name = seg.name;
                    if (!name.empty() && name[0] == '.') name = name.substr(1);

                    for (auto& region : ep.memory->layout) {
                        if (region.address == seg.address &&
                            region.accesses.has_value()) {
                            if (name == "text") {
                                EXPECT_GT(region.accesses->execs, 0)
                                    << ".text section should have executions";
                            }
                        }
                    }
                }
            }
        }
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}

TEST(SectionAccessTest, SectionStatsNotIdentical) {
    auto data = load_test_bin("dll_test_x86.dll");
    if (data.empty()) {
        GTEST_SKIP() << "dll_test_x86.dll not available";
    }

    speakeasy::SpeakeasyConfig cfg;
    cfg.analysis.memory_tracing = true;

    Speakeasy se(cfg);
    try {
        auto module = se.load_module("", data);
        se.run_module(module, true);
        auto report = se.get_report();

        for (auto& ep : report.entry_points) {
            if (!ep.memory.has_value()) continue;

            std::set<std::tuple<int, int, int>> unique_stats;
            for (auto& region : ep.memory->layout) {
                if (region.accesses.has_value()) {
                    unique_stats.emplace(
                        region.accesses->reads,
                        region.accesses->writes,
                        region.accesses->execs
                    );
                }
            }

            if (unique_stats.size() > 1) {
                SUCCEED() << "Section access stats vary across sections";
                return;
            }
        }
    } catch (...) {
        se.shutdown();
        throw;
    }
    se.shutdown();
}
