// crypt32.h
#ifndef SPEAKEASY_CRYPT32_H
#define SPEAKEASY_CRYPT32_H
#include <string>
#include <vector>
#include "api_handler_base.h"
namespace speakeasy { namespace api {
class Crypt32 : public ApiHandler {
public: Crypt32(); std::string get_name() const override {return "crypt32";}
const std::vector<ApiEntry>& get_apis() const override {return apis_;}
private: std::vector<ApiEntry> apis_;
static uint64_t CryptStringToBinaryA(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t CryptBinaryToStringA(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t CertOpenStore(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t CryptDecodeObject(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t stub(void*,const std::string&,int,const std::vector<uint64_t>&);
};
}}
#endif
