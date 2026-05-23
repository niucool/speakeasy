// mscoree.h — mscoree.dll API handler
#ifndef SPEAKEASY_MSCOREE_H
#define SPEAKEASY_MSCOREE_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Mscoree : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(CorExitProcess, 1)
    API_LIST_END

public:
    Mscoree(void* emu);
    std::string get_name() const override { return "mscoree"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
