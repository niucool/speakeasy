// bcryptprimitives.h — bcryptprimitives.dll API handler
#ifndef SPEAKEASY_BCRYPTPRIMITIVES_H
#define SPEAKEASY_BCRYPTPRIMITIVES_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Bcryptprimitives : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(ProcessPrng, 2)
    API_LIST_END

public:
    Bcryptprimitives(void* emu);
    std::string get_name() const override { return "bcryptprimitives"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
