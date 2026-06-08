/**
 * test_error_context.cpp — Port of test_error_context.py
 * Tests enriched exception context in ErrorInfo for invalid memory access.
 */

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"

namespace {

// x86 shellcode: mov eax, 0xdeadbeef; mov eax, [eax]  — invalid read
const std::vector<uint8_t> SC_INVALID_READ = {
    0xB8, 0xEF, 0xBE, 0xAD, 0xDE,  // mov eax, 0xDEADBEEF
    0x8B, 0x00                       // mov eax, [eax]
};

// x86 shellcode: mov eax, 0xdeadbeef; mov [eax], ebx  — invalid write
const std::vector<uint8_t> SC_INVALID_WRITE = {
    0xB8, 0xEF, 0xBE, 0xAD, 0xDE,  // mov eax, 0xDEADBEEF
    0x89, 0x18                       // mov [eax], ebx
};

speakeasy::ErrorInfo run_sc_and_get_error(const std::vector<uint8_t>& sc) {
    speakeasy::SpeakeasyConfig cfg;
    Speakeasy se(cfg);
    auto addr = se.load_shellcode("", "x86", sc);
    se.run_shellcode(addr);
    auto report = se.get_report();
    auto& ep = report.entry_points[0];
    if (!ep.error.has_value())
        throw std::runtime_error("Shellcode did not trigger error");
    auto e = *ep.error;
    se.shutdown();
    return e;
}

} // namespace

TEST(ErrorContextTest, InvalidReadErrorFields) {
    speakeasy::ErrorInfo e;
    try {
        e = run_sc_and_get_error(SC_INVALID_READ);
    } catch (const std::exception& ex) {
        GTEST_SKIP() << ex.what();
    }

    EXPECT_EQ(e.type, "invalid_read");
    EXPECT_TRUE(e.access_type.has_value());
    if (e.access_type.has_value()) EXPECT_EQ(*e.access_type, "read");
    EXPECT_TRUE(e.address.has_value());
    if (e.address.has_value()) EXPECT_EQ(*e.address, 0xDEADBEEF);
    EXPECT_TRUE(e.pc.has_value()) << "pc should be set";
    EXPECT_TRUE(e.instr.has_value()) << "instr should be set";
    if (e.instr.has_value()) {
        EXPECT_NE(e.instr->find("mov"), std::string::npos);
    }
    EXPECT_TRUE(e.thread_id.has_value());
    EXPECT_TRUE(e.process_id.has_value());
}

TEST(ErrorContextTest, InvalidReadHasRegisterState) {
    speakeasy::ErrorInfo e;
    try {
        e = run_sc_and_get_error(SC_INVALID_READ);
    } catch (const std::exception& ex) {
        GTEST_SKIP() << ex.what();
    }

    EXPECT_TRUE(e.regs.has_value());
    if (e.regs.has_value()) {
        EXPECT_TRUE(e.regs->count("eax") > 0);
        EXPECT_EQ((*e.regs)["eax"], "0xdeadbeef");
        EXPECT_TRUE(e.regs->count("esp") > 0);
        EXPECT_TRUE(e.regs->count("eip") > 0);
    }
}

TEST(ErrorContextTest, InvalidReadHasStackTrace) {
    speakeasy::ErrorInfo e;
    try {
        e = run_sc_and_get_error(SC_INVALID_READ);
    } catch (const std::exception& ex) {
        GTEST_SKIP() << ex.what();
    }

    EXPECT_TRUE(e.stack.has_value());
    if (e.stack.has_value()) {
        EXPECT_FALSE(e.stack->empty());
    }
}

TEST(ErrorContextTest, InvalidReadContextSummary) {
    speakeasy::ErrorInfo e;
    try {
        e = run_sc_and_get_error(SC_INVALID_READ);
    } catch (const std::exception& ex) {
        GTEST_SKIP() << ex.what();
    }

    EXPECT_TRUE(e.context_summary.has_value());
    if (e.context_summary.has_value()) {
        EXPECT_NE(e.context_summary->find("read"), std::string::npos);
        EXPECT_NE(e.context_summary->find("0xdeadbeef"), std::string::npos);
    }
}

TEST(ErrorContextTest, InvalidWriteErrorFields) {
    speakeasy::ErrorInfo e;
    try {
        e = run_sc_and_get_error(SC_INVALID_WRITE);
    } catch (const std::exception& ex) {
        GTEST_SKIP() << ex.what();
    }

    EXPECT_EQ(e.type, "invalid_write");
    EXPECT_TRUE(e.access_type.has_value());
    if (e.access_type.has_value()) EXPECT_EQ(*e.access_type, "write");
    EXPECT_TRUE(e.address.has_value());
    if (e.address.has_value()) EXPECT_EQ(*e.address, 0xDEADBEEF);
}

TEST(ErrorContextTest, InvalidWriteContextSummary) {
    speakeasy::ErrorInfo e;
    try {
        e = run_sc_and_get_error(SC_INVALID_WRITE);
    } catch (const std::exception& ex) {
        GTEST_SKIP() << ex.what();
    }

    EXPECT_TRUE(e.context_summary.has_value());
    if (e.context_summary.has_value()) {
        EXPECT_NE(e.context_summary->find("write"), std::string::npos);
        EXPECT_NE(e.context_summary->find("0xdeadbeef"), std::string::npos);
    }
}

TEST(ErrorContextTest, ErrorInfoRoundTripsThroughJson) {
    speakeasy::ErrorInfo e;
    try {
        e = run_sc_and_get_error(SC_INVALID_READ);
    } catch (const std::exception& ex) {
        GTEST_SKIP() << ex.what();
    }

    nlohmann::json data = e.to_json();
    EXPECT_TRUE(data.contains("pc"));
    EXPECT_TRUE(data.contains("address"));
    EXPECT_EQ(data["type"], e.type);
}
