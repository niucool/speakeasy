// crypt32.cpp
#include "crypt32.h"
namespace speakeasy { namespace api {
#define STUB(n) uint64_t Crypt32::n(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
Crypt32::Crypt32(){apis_={
    {"CryptStringToBinaryA",6,CryptStringToBinaryA},{"CryptBinaryToStringA",6,CryptBinaryToStringA},
    {"CertOpenStore",3,CertOpenStore},{"CryptDecodeObject",5,CryptDecodeObject},
};}
STUB(CryptStringToBinaryA) STUB(CryptBinaryToStringA) STUB(CertOpenStore) STUB(CryptDecodeObject)
uint64_t Crypt32::stub(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
}}
