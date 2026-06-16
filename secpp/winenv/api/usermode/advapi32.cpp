// advapi32.cpp  advapi32.dll handler  real implementations
#include "advapi32.h"
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;
namespace speakeasy { namespace api {


//  In-memory registry store 
struct RegVal { std::string name; int type; std::vector<uint8_t> data; };
struct RegNode {
    std::string path;
    std::map<std::string, RegVal> values;
    std::map<std::string, std::shared_ptr<RegNode>> children;
};

static std::map<std::string, std::shared_ptr<RegNode>>& reg_tree() {
    static auto tree = []() {
        auto t = std::map<std::string, std::shared_ptr<RegNode>>();
        auto mk = [&](const char* n) { auto node = std::make_shared<RegNode>(); node->path = n; t[n] = node; };
        mk("HKEY_CLASSES_ROOT"); mk("HKEY_CURRENT_USER"); mk("HKEY_LOCAL_MACHINE");
        mk("HKEY_USERS"); mk("HKEY_CURRENT_CONFIG"); return t;
    }(); return tree;
}

static std::map<uint32_t, std::string>& reg_handles() { static std::map<uint32_t, std::string> h; return h; }
static uint32_t next_rh() { static uint32_t h = 0x100; return ++h; }

static const char* get_hkey_name(uint64_t hKey) {
    switch (hKey) {
        case 0x80000000ULL: return "HKEY_CLASSES_ROOT";
        case 0x80000001ULL: return "HKEY_CURRENT_USER";
        case 0x80000002ULL: return "HKEY_LOCAL_MACHINE";
        case 0x80000003ULL: return "HKEY_USERS";
        case 0x80000004ULL: return "HKEY_PERFORMANCE_DATA";
        case 0x80000005ULL: return "HKEY_CURRENT_CONFIG";
        case 0x80000006ULL: return "HKEY_DYN_DATA";
        default: return nullptr;
    }
}

static std::shared_ptr<RegNode> find_node(const std::string& path) {
    auto& tree = reg_tree();
    for (auto& [rn, root] : tree) {
        if (path == rn) return root;
        if (path.find(rn + "\\") == 0 || path.find(rn + "/") == 0) {
            std::string rem = path.substr(rn.length() + 1);
            auto node = root; size_t pos = 0;
            while (pos < rem.length()) {
                size_t nxt = rem.find('\\', pos);
                if (nxt == std::string::npos) nxt = rem.length();
                auto it = node->children.find(rem.substr(pos, nxt - pos));
                if (it == node->children.end()) return nullptr;
                node = it->second; pos = nxt + 1;
            } return node;
        }
    } return nullptr;
}

static std::shared_ptr<RegNode> ensure_node(const std::string& path) {
    auto ex = find_node(path); if (ex) return ex;
    auto& tree = reg_tree();
    for (auto& [rn, root] : tree) {
        if (path == rn) return root;
        if (path.find(rn + "\\") == 0 || path.find(rn + "/") == 0) {
            std::string rem = path.substr(rn.length() + 1);
            auto node = root; size_t pos = 0;
            while (pos < rem.length()) {
                size_t nxt = rem.find('\\', pos);
                if (nxt == std::string::npos) nxt = rem.length();
                std::string comp = rem.substr(pos, nxt - pos);
                auto it = node->children.find(comp);
                if (it == node->children.end()) {
                    auto child = std::make_shared<RegNode>();
                    child->path = node->path + "\\" + comp;
                    node->children[comp] = child; node = child;
                } else { node = it->second; }
                pos = nxt + 1;
            } return node;
        }
    } return nullptr;
}

static std::string resolve_hk(uint64_t hKey) {
    const char* name = get_hkey_name(hKey); if (name) return name;
    auto& handles = reg_handles();
    auto it = handles.find(static_cast<uint32_t>(hKey));
    return (it != handles.end()) ? it->second : "";
}

static uint32_t open_rk(const std::string& path, bool create) {
    auto node = create ? ensure_node(path) : find_node(path);
    if (!node) return 0;
    uint32_t hnd = next_rh(); reg_handles()[hnd] = node->path; return hnd;
}

// 
// API implementations
// 

//  RegOpenKeyExA 
uint64_t Advapi32::RegOpenKeyExA(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return 0xFFFFFFFF;
    uint64_t hKey = a[0], lpSubKey = a[1], phkResult = a[4];
    std::string pp = resolve_hk(hKey);
    if (pp.empty()) return 2;
    uint32_t hnd = 0;
    if (lpSubKey) {
        std::string sk = be(e)->read_mem_string(lpSubKey, 1);
        hnd = sk.empty() ? open_rk(pp, false) : open_rk(pp + "\\" + sk, false);
    } else { hnd = open_rk(pp, false); }
    if (hnd == 0) return 2;
    if (phkResult) { std::vector<uint8_t> buf(4,0); write_le(buf,0,hnd,4); we(e)->mem_write(phkResult,buf); }
    return 0;
}

//  RegQueryValueExA 
uint64_t Advapi32::RegQueryValueExA(void* e, ArgList& a, void* ctx) {
    if (a.size() < 6) return 0xFFFFFFFF;
    uint64_t hKey=a[0], lpValueName=a[1], lpType=a[3], lpData=a[4], lpcbData=a[5];
    std::string kp = resolve_hk(hKey);
    if (kp.empty()) return 6;
    auto node = find_node(kp);
    if (!node) return 6;
    std::string vn;
    if (lpValueName) vn = be(e)->read_mem_string(lpValueName, 1);
    uint32_t buf_sz = 0;
    if (lpcbData) { auto r = we(e)->mem_read(lpcbData,4); if(r.size()>=4) buf_sz=(uint32_t)read_le(r,0,4); }
    auto vit = node->values.find(vn);
    if (vit != node->values.end()) {
        auto& val = vit->second;
        if (lpType) { std::vector<uint8_t> tb(4,0); write_le(tb,0,(uint32_t)val.type,4); we(e)->mem_write(lpType,tb); }
        std::vector<uint8_t> out = val.data;
        if ((val.type==1||val.type==2)&&(out.empty()||out.back()!=0)) out.push_back(0);
        if (lpcbData) { std::vector<uint8_t> sb(4,0); write_le(sb,0,(uint32_t)out.size(),4); we(e)->mem_write(lpcbData,sb); }
        if (lpData && !out.empty()) {
            if (buf_sz>=out.size()) we(e)->mem_write(lpData,out);
            else return 0x7A;
        }
        return 0;
    }
    if (lpcbData) { std::vector<uint8_t> sb(4,0); write_le(sb,0,0,4); we(e)->mem_write(lpcbData,sb); }
    return 0;
}

//  RegCloseKey 
uint64_t Advapi32::RegCloseKey(void* e, ArgList& a, void* ctx) {
    (void)e; if (a.size()<1) return 0xFFFFFFFF;
    return resolve_hk(a[0]).empty() ? 6 : 0;
}

//  RegCreateKeyExA 
uint64_t Advapi32::RegCreateKeyExA(void* e, ArgList& a, void* ctx) {
    if (a.size()<9) return 0xFFFFFFFF;
    uint64_t hKey=a[0], lpSubKey=a[1], phkResult=a[7], lpdwDisposition=a[8];
    std::string pp = resolve_hk(hKey);
    if (pp.empty()) return 6;
    std::string fp = pp;
    if (lpSubKey) { std::string sk = be(e)->read_mem_string(lpSubKey,1); if(!sk.empty()) fp+="\\"+sk; }
    bool existed = (find_node(fp)!=nullptr);
    uint32_t hnd = open_rk(fp, true);
    if (hnd==0) return 3;
    if (phkResult) { std::vector<uint8_t> buf(4,0); write_le(buf,0,hnd,4); we(e)->mem_write(phkResult,buf); }
    if (lpdwDisposition) { std::vector<uint8_t> db(4,0); write_le(db,0,existed?2:1,4); we(e)->mem_write(lpdwDisposition,db); }
    return 0;
}

//  RegSetValueExA 
uint64_t Advapi32::RegSetValueExA(void* e, ArgList& a, void* ctx) {
    if (a.size()<6) return 0xFFFFFFFF;
    uint64_t hKey=a[0], lpValueName=a[1], dwType=a[3], lpData=a[4], cbData=a[5];
    std::string kp = resolve_hk(hKey);
    if (kp.empty()) return 6;
    auto node = find_node(kp);
    if (!node) return 6;
    std::string vn; if (lpValueName) vn = be(e)->read_mem_string(lpValueName, 1);
    RegVal val; val.name=vn; val.type=(int)dwType;
    if (lpData&&cbData) val.data = we(e)->mem_read(lpData, (size_t)cbData);
    node->values[vn]=val;
    return 0;
}

//  RegDeleteKeyA 
uint64_t Advapi32::RegDeleteKeyA(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 0;
}

//  OpenProcessToken 
uint64_t Advapi32::OpenProcessToken(void* e, ArgList& a, void* ctx) {
    if (a.size()<3||!a[2]) return 0;
    static uint64_t nt=0x2800; nt+=4;
    int ps=we(e)->get_ptr_size(); std::vector<uint8_t> buf((size_t)ps,0);
    write_le(buf,0,nt,ps); we(e)->mem_write(a[2],buf); return 1;
}

//  LookupPrivilegeValueA 
uint64_t Advapi32::LookupPrivilegeValueA(void* e, ArgList& a, void* ctx) {
    if (a.size()<3||!a[2]) return 0;
    std::vector<uint8_t> buf(8,0); write_le(buf,0,0x20,4); write_le(buf,4,0,4);
    we(e)->mem_write(a[2],buf); return 1;
}

//  AdjustTokenPrivileges 
uint64_t Advapi32::AdjustTokenPrivileges(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  CryptAcquireContextA 
uint64_t Advapi32::CryptAcquireContextA(void* e, ArgList& a, void* ctx) {
    if (a.size()<5||!a[0]) return 0;
    static uint64_t nc=0x2900; nc+=4;
    int ps=we(e)->get_ptr_size(); std::vector<uint8_t> buf((size_t)ps,0);
    write_le(buf,0,nc,ps); we(e)->mem_write(a[0],buf); return 1;
}

//  CryptGenRandom 
uint64_t Advapi32::CryptGenRandom(void* e, ArgList& a, void* ctx) {
    if (a.size()<3||!a[2]||!a[1]) return 0;
    uint64_t len=a[1]; std::vector<uint8_t> buf((size_t)len);
    for(size_t i=0;i<(size_t)len;i++) buf[i]=(uint8_t)(rand()&0xFF);
    we(e)->mem_write(a[2],buf); return 1;
}

uint64_t Advapi32::RegOpenKeyExW(void* e, ArgList& a, void* ctx) {
    if (a.size()<5) return 0xFFFFFFFF;
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], 2); }
    return RegOpenKeyExA(e, a, ctx);
}
uint64_t Advapi32::RegQueryValueExW(void* e, ArgList& a, void* ctx) {
    if (a.size()<6) return 0xFFFFFFFF;
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], 2); }
    return RegQueryValueExA(e, a, ctx);
}
uint64_t Advapi32::RegCreateKeyExW(void* e, ArgList& a, void* ctx) {
    if (a.size()<9) return 0xFFFFFFFF;
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], 2); }
    return RegCreateKeyExA(e, a, ctx);
}
uint64_t Advapi32::RegSetValueExW(void* e, ArgList& a, void* ctx) {
    if (a.size()<6) return 0xFFFFFFFF;
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], 2); }
    return RegSetValueExA(e, a, ctx);
}
uint64_t Advapi32::RegDeleteValueA(void* e, ArgList& a, void* ctx) {
    if (a.size()<2) return 2;
    std::string kp=resolve_hk(a[0]); if(kp.empty()) return 2;
    auto node=find_node(kp); if(!node) return 2;
    std::string vn; if(a[1]) vn=be(e)->read_mem_string(a[1],1);
    node->values.erase(vn); return 0;
}

// ── Token / SID ────────────────────────────────────────────────────
uint64_t Advapi32::OpenThreadToken(void* e, ArgList& a, void* ctx) {
    if (a.size()<4||!a[3]) return 0;
    uint64_t h = we(e)->mem_map(8, 0, 4, "advapi32.token");
    return h;
}
uint64_t Advapi32::LookupPrivilegeValueW(void* e, ArgList& a, void* ctx) {
    if (a[2]) { a[0] = be(e)->read_mem_string(a[0], 2); }
    return LookupPrivilegeValueA(e, a, ctx);
}
uint64_t Advapi32::DuplicateTokenEx(void* e, ArgList& a, void* ctx) {
    if (a.size()<6||!a[5]) return 0;
    uint64_t h = we(e)->mem_map(8, 0, 4, "advapi32.duptoken");
    int ps=we(e)->get_ptr_size(); std::vector<uint8_t>buf((size_t)ps,0);
    write_le(buf,0,h,ps); we(e)->mem_write(a[5],buf); return 1;
}
uint64_t Advapi32::SetTokenInformation(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::AllocateAndInitializeSid(void* e, ArgList& a, void* ctx) {
    if (a.size()<11||!a[10]) return 0;
    uint64_t h = we(e)->mem_map(68, 0, 4, "advapi32.sid");
    int ps=we(e)->get_ptr_size(); std::vector<uint8_t>buf((size_t)ps,0);
    write_le(buf,0,h,ps); we(e)->mem_write(a[10],buf); return 1;
}
uint64_t Advapi32::CheckTokenMembership(void* e, ArgList& a, void* ctx) {
    if (a.size()<3||!a[2]) return 0;
    std::vector<uint8_t>buf(4,255); we(e)->mem_write(a[2],buf); return 1;
}
uint64_t Advapi32::FreeSid(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 0;
}

// ── Crypto ──────────────────────────────────────────────────────────
uint64_t Advapi32::CryptAcquireContextW(void* e, ArgList& a, void* ctx) {
    return CryptAcquireContextA(e, a, ctx);
}
uint64_t Advapi32::CryptReleaseContext(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::SystemFunction036(void* e, ArgList& a, void* ctx) {
    // RtlGenRandom — Python: fills buffer with range bytes
    if (a.size()<2||!a[0]||!a[1]) return 0;
    uint32_t len=static_cast<uint32_t>(a[1]);
    std::vector<uint8_t>buf(len);
    for(uint32_t i=0;i<len;i++) buf[i]=(uint8_t)i;
    we(e)->mem_write(a[0],buf); return 1;
}

// ── Service Manager ─────────────────────────────────────────────────
uint64_t Advapi32::OpenSCManagerA(void* e, ArgList& a, void* ctx) {
    // Python: hScm = self.mem_alloc(size=8)
    (void)a;
    uint64_t hScm = we(e)->mem_map(8, 0, 4, "advapi32.scmanager");
    
    return hScm;
}
uint64_t Advapi32::OpenSCManagerW(void* e, ArgList& a, void* ctx) {
    if (a[0]) { a[0] = be(e)->read_mem_string(a[0], 2); }
    return OpenSCManagerA(e, a, ctx);
}

uint64_t Advapi32::CreateServiceA(void* e, ArgList& a, void* ctx) {
    // Python: reads svc_name, disp_name, bin_path and updates argv.
    // Returns hSvc = self.mem_alloc(size=8)
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], 1); }
    if (a[2]) { a[2] = be(e)->read_mem_string(a[2], 1); }
    if (a[7]) { a[7] = be(e)->read_mem_string(a[7], 1); }
    uint64_t hSvc = we(e)->mem_map(8, 0, 4, "advapi32.service");
    
    return hSvc;
}
uint64_t Advapi32::CreateServiceW(void* e, ArgList& a, void* ctx) {
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], 2); }
    if (a[2]) { a[2] = be(e)->read_mem_string(a[2], 2); }
    if (a[7]) { a[7] = be(e)->read_mem_string(a[7], 2); }
    uint64_t hSvc = we(e)->mem_map(8, 0, 4, "advapi32.service");
    
    return hSvc;
}

uint64_t Advapi32::StartServiceA(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::StartServiceW(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

uint64_t Advapi32::ControlService(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

uint64_t Advapi32::DeleteService(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

uint64_t Advapi32::QueryServiceStatus(void* e, ArgList& a, void* ctx) {
    (void)e;
    if (a.size()>=2 && a[1]) {
        std::vector<uint8_t>buf(28,0); write_le(buf,0,0x30,4);
        we(e)->mem_write(a[1],buf);
    }
    return 1;
}

uint64_t Advapi32::CloseServiceHandle(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

// ── ChangeServiceConfig / ChangeServiceConfig2 ─────────────────────
uint64_t Advapi32::ChangeServiceConfigA(void* e, ArgList& a, void* ctx) {
    // Python: reads name strings and updates argv for logging
    if (a[4]) { a[4] = be(e)->read_mem_string(a[4], 1); }
    if (a[5]) { a[5] = be(e)->read_mem_string(a[5], 1); }
    if (a[7]) { a[7] = be(e)->read_mem_string(a[7], 1); }
    if (a[8]) { a[8] = be(e)->read_mem_string(a[8], 1); }
    if (a[9]) { a[9] = be(e)->read_mem_string(a[9], 1); }
    if (a[10]){ a[10]= be(e)->read_mem_string(a[10],1); }
    return 1;
}
uint64_t Advapi32::ChangeServiceConfigW(void* e, ArgList& a, void* ctx) {
    if (a[4]) { a[4] = be(e)->read_mem_string(a[4], 2); }
    if (a[5]) { a[5] = be(e)->read_mem_string(a[5], 2); }
    if (a[7]) { a[7] = be(e)->read_mem_string(a[7], 2); }
    if (a[8]) { a[8] = be(e)->read_mem_string(a[8], 2); }
    if (a[9]) { a[9] = be(e)->read_mem_string(a[9], 2); }
    if (a[10]){ a[10]= be(e)->read_mem_string(a[10],2); }
    return 1;
}
uint64_t Advapi32::ChangeServiceConfig2A(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::ChangeServiceConfig2W(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

// ── Misc ────────────────────────────────────────────────────────────
uint64_t Advapi32::RevertToSelf(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::ImpersonateLoggedOnUser(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

uint64_t Advapi32::stub(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

Advapi32::Advapi32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Advapi32)
    REG(Advapi32, RegOpenKeyExA, 5)     REG(Advapi32, RegOpenKeyExW, 5)
    REG(Advapi32, RegQueryValueExA, 6)  REG(Advapi32, RegQueryValueExW, 6)
    REG(Advapi32, RegCloseKey, 1)
    REG(Advapi32, RegCreateKeyExA, 9)   REG(Advapi32, RegCreateKeyExW, 9)
    REG(Advapi32, RegSetValueExA, 6)    REG(Advapi32, RegSetValueExW, 6)
    REG(Advapi32, RegDeleteKeyA, 1)     REG(Advapi32, RegDeleteValueA, 2)
    REG(Advapi32, OpenProcessToken, 3)  REG(Advapi32, OpenThreadToken, 4)
    REG(Advapi32, LookupPrivilegeValueA, 3) REG(Advapi32, LookupPrivilegeValueW, 3)
    REG(Advapi32, AdjustTokenPrivileges, 6)
    REG(Advapi32, DuplicateTokenEx, 6)  REG(Advapi32, SetTokenInformation, 4)
    REG(Advapi32, CryptAcquireContextA, 5) REG(Advapi32, CryptAcquireContextW, 5)
    REG(Advapi32, CryptGenRandom, 3)    REG(Advapi32, CryptReleaseContext, 2)
    REG(Advapi32, SystemFunction036, 2) // RtlGenRandom
    REG(Advapi32, CreateServiceA, 13)   REG(Advapi32, CreateServiceW, 13)
    REG(Advapi32, StartServiceA, 3)     REG(Advapi32, StartServiceW, 3)
    REG(Advapi32, ControlService, 3)    REG(Advapi32, DeleteService, 1)
    REG(Advapi32, QueryServiceStatus, 2) REG(Advapi32, CloseServiceHandle, 1)
    REG(Advapi32, ChangeServiceConfigA, 11) REG(Advapi32, ChangeServiceConfigW, 11)
    REG(Advapi32, ChangeServiceConfig2A, 3) REG(Advapi32, ChangeServiceConfig2W, 3)
    REG(Advapi32, OpenSCManagerA, 3)    REG(Advapi32, OpenSCManagerW, 3)
    REG(Advapi32, RevertToSelf, 0)      REG(Advapi32, ImpersonateLoggedOnUser, 1)
    REG(Advapi32, AllocateAndInitializeSid, 11)
    REG(Advapi32, CheckTokenMembership, 3) REG(Advapi32, FreeSid, 1)
    END_API_TABLE
}

}} // namespaces
