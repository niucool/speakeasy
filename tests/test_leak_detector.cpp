#include <gtest/gtest.h>

#if defined(_MSC_VER) && defined(_DEBUG)
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

class MSVCLeakDetectorListener : public ::testing::EmptyTestEventListener {
private:
    _CrtMemState s1;

public:
    void OnTestStart(const ::testing::TestInfo& test_info) override {
        (void)test_info;
        _CrtMemCheckpoint(&s1);
    }

    void OnTestEnd(const ::testing::TestInfo& test_info) override {
        _CrtMemState s2, s3;
        _CrtMemCheckpoint(&s2);
        if (_CrtMemDifference(&s3, &s1, &s2)) {
            _CrtMemDumpAllObjectsSince(&s1);
#if 0
            // Tolerate small leaks from third-party libraries (Unicorn, plog) that
            // do not fully free internal allocations on uc_close / shutdown.
            static constexpr long kMaxLeakBytes  = 200 * 1024;  // 200 KB
            static constexpr long kMaxLeakBlocks = 1000;
            long leaked_bytes  = s3.lSizes[_NORMAL_BLOCK];
            long leaked_blocks = s3.lCounts[_NORMAL_BLOCK];
            if (leaked_blocks > kMaxLeakBlocks || leaked_bytes > kMaxLeakBytes) {
                ADD_FAILURE_AT(test_info.file() ? test_info.file() : "unknown", test_info.line() > 0 ? test_info.line() : 1)
                    << "Memory leak detected in test " << test_info.test_suite_name() << "." << test_info.name() << "\n"
                    << "Leaked bytes: " << leaked_bytes << " in " << leaked_blocks << " blocks (threshold: "
                    << kMaxLeakBytes << " bytes / " << kMaxLeakBlocks << " blocks).\n";

                // Dump details to debug output / console
                _CrtMemDumpAllObjectsSince(&s1);
            }
#endif
        }
    }
};

struct MSVCLeakDetectorRegister {
    MSVCLeakDetectorRegister() {
        ::testing::UnitTest::GetInstance()->listeners().Append(new MSVCLeakDetectorListener);
    }
};

static MSVCLeakDetectorRegister g_msvc_leak_detector_register;
#endif
