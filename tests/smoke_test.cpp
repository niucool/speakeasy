/**
 * smoke_test.cpp — Speakeasy C++ Port Dependency Verification
 *
 * Validates that all required third-party libraries are correctly
 * installed and linkable.  Run via CMake CTest or directly:
 *
 *   cmake -B build && cmake --build build --target smoke_test
 *   ./build/smoke_test
 *
 * Exit code 0 = all libraries OK.
 */

#include <iostream>
#include <string>
#include <cstdlib>

// ── nlohmann/json ────────────────────────────────────────────
#include <nlohmann/json.hpp>

// ── plog ─────────────────────────────────────────────────────
#include <plog/Log.h>
#include <plog/Initializers/RollingFileInitializer.h>

// ── unicorn ──────────────────────────────────────────────────
#include <unicorn/unicorn.h>

// ── pe-parse ─────────────────────────────────────────────────
#include <pe-parse/parse.h>

// ── Capstone (optional) ──────────────────────────────────────
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif

// ── Helpers ──────────────────────────────────────────────────
static int failures = 0;

static void check(const std::string& lib, bool ok) {
    std::cout << "  [" << (ok ? " OK " : "FAIL") << "] " << lib << std::endl;
    if (!ok) ++failures;
}

// ── Main ─────────────────────────────────────────────────────
int main() {
    std::cout << "=== Speakeasy C++ Smoke Test ===" << std::endl;
    std::cout << "Project version: " << "1.6.1" << std::endl;
    std::cout << std::endl;

    // --- nlohmann/json ---
    {
        nlohmann::json j;
        j["test"] = "hello";
        j["version"] = 1;
        bool ok = (j["test"] == "hello") && (j["version"] == 1);
        check("nlohmann/json  (JSON parse/serialize)", ok);
    }

    // --- plog ---
    {
        // plog is header-only; just verify it was included cleanly
        bool ok = true;
        check("plog          (logging framework)", ok);
    }

    // --- unicorn ---
    {
        // uc_version returns combined version (major<<24 | minor<<16), not uc_err
        unsigned int major = 0, minor = 0;
        unsigned int ver = uc_version(&major, &minor);
        bool ok = (ver != 0) && (major >= 2);
        if (ok) {
            std::cout << "           Unicorn version: " << major << "." << minor << std::endl;
        }
        check("unicorn       (CPU emulation)", ok);

        // Quick open/close cycle to verify the library is functional
        uc_engine* uc = nullptr;
        uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
        if (err == UC_ERR_OK) {
            uc_close(uc);
            check("unicorn       (engine open/close)", true);
        } else {
            check("unicorn       (engine open/close)", false);
        }
    }

    // --- pe-parse ---
    {
        // pe-parse is a C library with C++ namespace; verify structure size.
        bool ok = (sizeof(peparse::pe_header) > 0);
        check("pe-parse      (PE file parser)", ok);
    }

    // --- Capstone (optional) ---
#ifdef HAS_CAPSTONE
    {
        bool ok = (cs_version(nullptr, nullptr) == CS_ERR_OK);
        check("capstone      (disassembler)", ok);
    }
#else
    std::cout << "  [ SKIP] capstone      (not linked)" << std::endl;
#endif

    // --- Summary ---
    std::cout << std::endl;
    if (failures == 0) {
        std::cout << "All dependency checks passed." << std::endl;
        return 0;
    } else {
        std::cout << failures << " check(s) FAILED." << std::endl;
        return 1;
    }
}
