// iphlpapi.h — iphlpapi.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_IPHLPAPI_H
#define SPEAKEASY_IPHLPAPI_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Iphlpapi : public ApiHandler {
    API_LIST_BEGIN
    // Network adapter / configuration
    API_ENTRY(GetAdaptersInfo, 2)
    API_ENTRY(GetAdaptersAddresses, 5)
    API_ENTRY(GetIfEntry, 2)
    API_ENTRY(GetIfTable, 3)
    API_ENTRY(GetExtendedTcpTable, 6)
    API_ENTRY(GetExtendedUdpTable, 6)
    API_ENTRY(GetNetworkParams, 2)
    API_ENTRY(GetBestInterface, 2)
    API_ENTRY(GetBestRoute, 3)
    API_ENTRY(GetRTTAndHopCount, 4)
    API_ENTRY(GetFriendlyIfIndex, 1)
    API_ENTRY(NotifyAddrChange, 2)
    API_ENTRY(NotifyRouteChange, 2)
    API_ENTRY(CancelIPChangeNotify, 1)
    API_ENTRY(FlushIpNetTable, 2)
    API_ENTRY(FlushIpPathTable, 1)
    API_ENTRY(GetIpAddrTable, 3)
    API_ENTRY(GetIpForwardTable, 3)
    API_ENTRY(GetIpNetTable, 3)
    API_ENTRY(GetIpStatistics, 1)
    API_ENTRY(GetIpStatisticsEx, 2)
    API_ENTRY(GetTcpStatistics, 1)
    API_ENTRY(GetTcpStatisticsEx, 2)
    API_ENTRY(GetUdpStatistics, 1)
    API_ENTRY(GetUdpStatisticsEx, 2)
    API_ENTRY(SetIpStatistics, 1)
    API_ENTRY(SetIpTTL, 1)
    API_ENTRY(AllocateAndGetIpAddrTableFromStack, 4)
    API_ENTRY(AllocateAndGetIpNetTableFromStack, 4)
    API_ENTRY(AllocateAndGetTcpTableFromStack, 4)
    API_ENTRY(AllocateAndGetUdpTableFromStack, 4)
    API_ENTRY(GetInterfaceInfo, 2)
    API_ENTRY(GetNumberOfInterfaces, 1)
    API_ENTRY(DhcpRequestParams, 7)
    API_ENTRY(EnableRouter, 3)
    API_ENTRY(UnenableRouter, 2)
    API_ENTRY(IpReleaseAddress, 2)
    API_ENTRY(IpRenewAddress, 2)
    API_ENTRY(SendARP, 4)
    API_ENTRY(Ping, 6)
    API_ENTRY(PingEx, 7)
    API_ENTRY(CancelIPInfoChange, 1)
    API_ENTRY(SetAdapterIpAddress, 3)
    API_ENTRY(AddIPAddress, 5)
    API_ENTRY(DeleteIPAddress, 2)
    API_LIST_END

public:
    Iphlpapi();
    std::string get_name() const override { return "iphlpapi"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
