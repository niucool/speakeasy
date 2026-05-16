// winmm.cpp — winmm.dll handler (real implementations)
#include "winmm.h"
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

static constexpr uint32_t TIMERR_NOERROR = 0;

// Reference time point for timeGetTime
static const std::chrono::steady_clock::time_point winmm_start = std::chrono::steady_clock::now();

Winmm::Winmm() {
    INIT_API_TABLE(Winmm)
    REG(Winmm, timeBeginPeriod, 1)
    REG(Winmm, timeEndPeriod, 1)
    REG(Winmm, timeGetTime, 0)
    END_API_TABLE
}

// ═══════════════════════════════════════════════════════════════
//  timeBeginPeriod — set minimum timer resolution
// ═══════════════════════════════════════════════════════════════
uint64_t Winmm::timeBeginPeriod(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e;
    uint32_t uPeriod = static_cast<uint32_t>(a[0] & 0xFFFFFFFF);
    (void)uPeriod;
    return TIMERR_NOERROR;
}

// ═══════════════════════════════════════════════════════════════
//  timeEndPeriod — clear minimum timer resolution
// ═══════════════════════════════════════════════════════════════
uint64_t Winmm::timeEndPeriod(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e;
    uint32_t uPeriod = static_cast<uint32_t>(a[0] & 0xFFFFFFFF);
    (void)uPeriod;
    return TIMERR_NOERROR;
}

// ═══════════════════════════════════════════════════════════════
//  timeGetTime — get system time in milliseconds
// ═══════════════════════════════════════════════════════════════
uint64_t Winmm::timeGetTime(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - winmm_start).count();
    return static_cast<uint64_t>(ms & 0xFFFFFFFF);
}

}} // namespaces
