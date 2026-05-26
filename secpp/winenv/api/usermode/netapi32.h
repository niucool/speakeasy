// netapi32.h  netapi32.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_NETAPI32_H
#define SPEAKEASY_NETAPI32_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class NetApi32 : public ApiHandler {
    API_LIST_BEGIN
    // Domain / workstation
    API_ENTRY(NetGetJoinInformation, 3)
    API_ENTRY(NetWkstaGetInfo, 3)
    API_ENTRY(NetWkstaUserEnum, 4)
    API_ENTRY(NetServerEnum, 8)
    API_ENTRY(NetServerEnumEx, 8)
    API_ENTRY(NetServerGetInfo, 3)
    API_ENTRY(NetServerSetInfo, 4)
    API_ENTRY(NetUserAdd, 4)
    API_ENTRY(NetUserDel, 3)
    API_ENTRY(NetUserEnum, 8)
    API_ENTRY(NetUserGetGroups, 4)
    API_ENTRY(NetUserGetInfo, 4)
    API_ENTRY(NetUserSetInfo, 5)
    API_ENTRY(NetUserGetLocalGroups, 7)
    API_ENTRY(NetUserModalsGet, 3)
    API_ENTRY(NetUserModalsSet, 4)
    API_ENTRY(NetGroupEnum, 8)
    API_ENTRY(NetGroupGetInfo, 4)
    API_ENTRY(NetGroupSetInfo, 5)
    API_ENTRY(NetGroupAddUser, 3)
    API_ENTRY(NetGroupDelUser, 3)
    API_ENTRY(NetLocalGroupEnum, 7)
    API_ENTRY(NetLocalGroupGetInfo, 4)
    API_ENTRY(NetLocalGroupSetInfo, 5)
    API_ENTRY(NetLocalGroupAdd, 4)
    API_ENTRY(NetLocalGroupAddMembers, 6)
    API_ENTRY(NetLocalGroupDelMembers, 6)
    API_ENTRY(NetLocalGroupGetMembers, 7)
    API_ENTRY(NetApiBufferAllocate, 2)
    API_ENTRY(NetApiBufferFree, 1)
    API_ENTRY(NetApiBufferReallocate, 3)
    API_ENTRY(NetApiBufferSize, 2)
    API_ENTRY(NetGetDCName, 3)
    API_ENTRY(NetGetAnyDCName, 3)
    API_ENTRY(NetGetDisplayInformationIndex, 5)
    API_ENTRY(NetQueryDisplayInformation, 8)
    API_ENTRY(NetShareAdd, 4)
    API_ENTRY(NetShareCheck, 3)
    API_ENTRY(NetShareDel, 3)
    API_ENTRY(NetShareEnum, 8)
    API_ENTRY(NetShareGetInfo, 4)
    API_ENTRY(NetShareSetInfo, 5)
    API_ENTRY(NetConnectionEnum, 8)
    API_ENTRY(NetFileEnum, 8)
    API_ENTRY(NetFileGetInfo, 4)
    API_ENTRY(NetFileClose, 2)
    API_ENTRY(NetSessionEnum, 8)
    API_ENTRY(NetSessionGetInfo, 4)
    API_ENTRY(NetSessionDel, 3)
    API_ENTRY(NetUseAdd, 4)
    API_ENTRY(NetUseDel, 3)
    API_ENTRY(NetUseEnum, 8)
    API_ENTRY(NetUseGetInfo, 4)
    API_ENTRY(NetScheduleJobAdd, 3)
    API_ENTRY(NetScheduleJobDel, 3)
    API_ENTRY(NetScheduleJobEnum, 5)
    API_ENTRY(NetScheduleJobGetInfo, 4)
    API_ENTRY(NetRemoteComputerSupports, 2)
    API_ENTRY(NetRemoteTOD, 2)
    API_ENTRY(NetWkstaSetInfo, 4)
    API_ENTRY(NetWkstaTransportEnum, 5)
    API_ENTRY(NetWkstaTransportAdd, 4)
    API_ENTRY(NetWkstaTransportDel, 3)
    API_ENTRY(NetAccessAdd, 4)
    API_ENTRY(NetAccessDel, 3)
    API_ENTRY(NetAccessEnum, 8)
    API_ENTRY(NetAccessGetInfo, 4)
    API_ENTRY(NetAccessSetInfo, 5)
    API_ENTRY(NetAuditClear, 2)
    API_ENTRY(NetAuditRead, 10)
    API_ENTRY(NetAuditWrite, 4)
    API_ENTRY(NetConfigGet, 4)
    API_ENTRY(NetConfigGetAll, 3)
    API_ENTRY(NetConfigSet, 5)
    API_ENTRY(NetErrorLogClear, 2)
    API_ENTRY(NetErrorLogRead, 10)
    API_ENTRY(NetErrorLogWrite, 8)
    API_ENTRY(SetServiceBits, 3)
    API_LIST_END

public:
    NetApi32(void* emu);
    std::string get_name() const override { return "netapi32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
