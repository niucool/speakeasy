/**
 * test_porting_profiler.cpp  ProfilerEventTest (record_file_access_event, log_registry)
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

#include "profiler.h"
#include "profiler_events.h"

using namespace speakeasy;

TEST(ProfilerEventTest, LogFileAccess) {
    Profiler prof;
    auto run = std::make_shared<::Run>();
    prof.add_run(run);
    EXPECT_NO_THROW(
        prof.record_file_access_event(run, "C:\\test\\write.exe", "write",
                             std::vector<uint8_t>{'a','b','c'})
    );
}

TEST(ProfilerEventTest, LogRegistryAccess) {
    Profiler prof;
    auto run = std::make_shared<::Run>();
    prof.add_run(run);
    EXPECT_NO_THROW(
        prof.record_registry_access_event(run, "HKLM\\SOFTWARE\\Test", "write",
                                 "TestValue", std::vector<uint8_t>{1,2,3,4})
    );
}

TEST(ProfilerEventTest, ProfilerGetReport) {
    Profiler prof;
    prof.set_start_time();
    auto report = prof.get_report();
    EXPECT_TRUE(report.report_version.size() > 0);  // Report is always valid, has version
}

TEST(ProfilerEventTest, MultipleFileAccesses) {
    Profiler prof;
    auto run = std::make_shared<::Run>();
    prof.add_run(run);
    for (int i = 0; i < 5; i++)
        EXPECT_NO_THROW(prof.record_file_access_event(run, "C:\\multi\\file" +
            std::to_string(i) + ".bin", "write"));
}
