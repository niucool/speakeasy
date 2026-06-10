// crypt32.h
#ifndef SPEAKEASY_CRYPT32_H
#define SPEAKEASY_CRYPT32_H
#include <string>
#include <vector>
#include "../api.h"
namespace speakeasy { namespace api {
class Crypt32 : public ApiHandler {
public: Crypt32(void* emu); std::string get_name() const override {return "crypt32";}
const std::vector<ApiEntry>& get_apis() const override {return apis_;}
private: std::vector<ApiEntry> apis_;
static uint64_t CryptStringToBinaryA(void*, ArgList&, void* ctx);
static uint64_t CryptStringToBinaryW(void*, ArgList&, void* ctx);
static uint64_t CryptBinaryToStringA(void*, ArgList&, void* ctx);
static uint64_t CryptBinaryToStringW(void*, ArgList&, void* ctx);
static uint64_t CertOpenStore(void*, ArgList&, void* ctx);
static uint64_t CryptDecodeObject(void*, ArgList&, void* ctx);
static uint64_t stub(void*, ArgList&, void* ctx);
};
}}
#endif
