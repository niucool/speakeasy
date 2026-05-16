// dnsapi.cpp — dnsapi.dll handler (v2 — all STUB, return 1)
#include "dnsapi.h"

namespace speakeasy { namespace api {

DnsApi::DnsApi() {
    INIT_API_TABLE(DnsApi)
    REG(DnsApi, DnsQuery_, 6)
    END_API_TABLE
}

// ── All stubs ────────────────────────────────────────────────

#define DNS_STUB(n) STUB(DnsApi, n)

DNS_STUB(DnsQuery_)

}} // namespaces
