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
#include "../../deffs/windows/advapi32.h"
#include "../../deffs/windows/kernel32.h"

using namespace speakeasy;
using namespace speakeasy::deffs::windows;
namespace speakeasy { namespace api {
#ifdef RegOpenKey
#undef RegOpenKey
#endif
#ifdef RegOpenKeyEx
#undef RegOpenKeyEx
#endif
#ifdef RegEnumKey
#undef RegEnumKey
#endif
#ifdef RegEnumKeyEx
#undef RegEnumKeyEx
#endif
#ifdef RegGetValue
#undef RegGetValue
#endif
#ifdef RegQueryInfoKey
#undef RegQueryInfoKey
#endif
#ifdef RegQueryValueEx
#undef RegQueryValueEx
#endif
#ifdef RegCreateKey
#undef RegCreateKey
#endif
#ifdef RegCreateKeyEx
#undef RegCreateKeyEx
#endif
#ifdef RegSetValueEx
#undef RegSetValueEx
#endif
#ifdef RegDeleteKey
#undef RegDeleteKey
#endif
#ifdef RegDeleteValue
#undef RegDeleteValue
#endif
#ifdef LookupPrivilegeValue
#undef LookupPrivilegeValue
#endif
#ifdef CryptAcquireContext
#undef CryptAcquireContext
#endif
#ifdef CreateService
#undef CreateService
#endif
#ifdef StartService
#undef StartService
#endif
#ifdef ChangeServiceConfig
#undef ChangeServiceConfig
#endif
#ifdef ChangeServiceConfig2
#undef ChangeServiceConfig2
#endif
#ifdef OpenSCManager
#undef OpenSCManager
#endif
#ifdef StartServiceCtrlDispatcher
#undef StartServiceCtrlDispatcher
#endif
#ifdef RegisterServiceCtrlHandler
#undef RegisterServiceCtrlHandler
#endif
#ifdef RegisterServiceCtrlHandlerEx
#undef RegisterServiceCtrlHandlerEx
#endif
#ifdef OpenService
#undef OpenService
#endif
#ifdef GetUserName
#undef GetUserName
#endif
#ifdef LookupAccountName
#undef LookupAccountName
#endif
#ifdef LookupAccountSid
#undef LookupAccountSid
#endif
#ifdef GetCurrentHwProfile
#undef GetCurrentHwProfile
#endif
#ifdef CreateProcessAsUser
#undef CreateProcessAsUser
#endif
#ifdef EnumServicesStatus
#undef EnumServicesStatus
#endif
#ifdef QueryServiceConfig
#undef QueryServiceConfig
#endif
static uint64_t g_service_status_handle = 0x1000;


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

//  RegOpenKey (Python: reads hkey/name with cw, delegates to reg_open_key)
uint64_t Advapi32::RegOpenKey(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return 2;
    uint64_t hKey = a[0], lpSubKey = a[1], phkResult = a[2];
    std::string hkey_name = resolve_hk(hKey);
    if (hkey_name.empty()) return 2;
    a[0] = hkey_name;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (lpSubKey) {
        std::string sk = be(e)->read_mem_string(lpSubKey, cw);
        a[1] = sk;
        if (sk[0] != '\\') sk = "\\" + sk;
        sk = hkey_name + sk;
        uint32_t hnd = open_rk(sk, false);
        if (!hnd) return 2;
        if (phkResult) { std::vector<uint8_t> buf(4,0); write_le(buf,0,hnd,4); we(e)->mem_write(phkResult,buf); }
    } else if (phkResult) {
        int ps = we(e)->get_ptr_size();
        std::vector<uint8_t> buf((size_t)ps,0);
        write_le(buf,0,hKey,ps); we(e)->mem_write(phkResult,buf);
    }
    return 0;
}

//  RegOpenKeyExA
uint64_t Advapi32::RegOpenKeyEx(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return 0xFFFFFFFF;
    uint64_t hKey = a[0], lpSubKey = a[1], phkResult = a[4];
    std::string pp = resolve_hk(hKey);
    a[0] = pp; // Python: argv[0] = hkey_name
    if (pp.empty()) return 2;
    uint32_t hnd = 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (lpSubKey) {
        std::string sk = be(e)->read_mem_string(lpSubKey, cw);
        a[1] = sk;
        hnd = sk.empty() ? open_rk(pp, false) : open_rk(pp + "\\" + sk, false);
    } else { hnd = open_rk(pp, false); }
    if (hnd == 0) return 2;
    if (phkResult) { std::vector<uint8_t> buf(4,0); write_le(buf,0,hnd,4); we(e)->mem_write(phkResult,buf); }
    return 0;
}

//  RegQueryValueExA 
uint64_t Advapi32::RegQueryValueEx(void* e, ArgList& a, void* ctx) {
    if (a.size() < 6) return 0xFFFFFFFF;
    uint64_t hKey=a[0], lpValueName=a[1], lpType=a[3], lpData=a[4], lpcbData=a[5];
    std::string kp = resolve_hk(hKey);
    if (kp.empty()) return 6;
    auto node = find_node(kp);
    if (!node) return 6;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    std::string vn;
    if (lpValueName) { vn = be(e)->read_mem_string(lpValueName, cw); a[1] = vn; }
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

//  RegCreateKeyA — Python advapi32.py: follows the ApiContext pattern (like wininet InternetOpen)
uint64_t Advapi32::RegCreateKey(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return 2;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    uint64_t hkey_arg = a[0], lpSubKey = a[1], phkResult = a[2];
    std::string key_path = resolve_hk(hkey_arg);
    if (key_path.empty()) return 2; // ERROR_FILE_NOT_FOUND
    a[0] = key_path;
    if (lpSubKey) {
        std::string sk = be(e)->read_mem_string(lpSubKey, cw);
        a[1] = sk;
        std::string full = key_path + "\\" + sk;
        we(e)->reg_create_key(full);
        // Record registry event
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->record_registry_access_event(run, full, "create_key", "", {}, 0, {}, {}, 0, -1);
        }
        if (phkResult) {
            uint32_t hnd = open_rk(full, true);
            int ps = we(e)->get_ptr_size();
            std::vector<uint8_t> buf((size_t)ps, 0);
            write_le(buf, 0, hnd, ps);
            we(e)->mem_write(phkResult, buf);
        }
    } else {
        if (phkResult) {
            int ps = we(e)->get_ptr_size();
            std::vector<uint8_t> buf((size_t)ps, 0);
            write_le(buf, 0, static_cast<uint64_t>(hkey_arg), ps);
            we(e)->mem_write(phkResult, buf);
        }
    }
    return 0; // ERROR_SUCCESS
}

//  RegCreateKeyExA
uint64_t Advapi32::RegCreateKeyEx(void* e, ArgList& a, void* ctx) {
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
uint64_t Advapi32::RegSetValueEx(void* e, ArgList& a, void* ctx) {
    if (a.size()<6) return 0xFFFFFFFF;
    uint64_t hKey=a[0], lpValueName=a[1], dwType=a[3], lpData=a[4], cbData=a[5];
    std::string kp = resolve_hk(hKey);
    if (kp.empty()) return 6;
    auto node = find_node(kp);
    if (!node) return 6;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    std::string vn; if (lpValueName) { vn = be(e)->read_mem_string(lpValueName, cw); a[1] = vn; }
    RegVal val; val.name=vn; val.type=(int)dwType;
    if (lpData&&cbData) val.data = we(e)->mem_read(lpData, (size_t)cbData);
    node->values[vn]=val;
    return 0;
}

//  RegDeleteKeyA 
uint64_t Advapi32::RegDeleteKey(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 0;
}

//  OpenProcessToken 
uint64_t Advapi32::OpenProcessToken(void* e, ArgList& a, void* ctx) {
    if (a.size()<3||!a[2]) return 0;
    static uint64_t nt=0x2800; nt+=4;
    int ps=we(e)->get_ptr_size(); std::vector<uint8_t> buf((size_t)ps,0);
    write_le(buf,0,nt,ps); we(e)->mem_write(a[2],buf); return 1;
}

//  AdjustTokenPrivileges
uint64_t Advapi32::AdjustTokenPrivileges(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  CryptAcquireContextA 
uint64_t Advapi32::CryptAcquireContext(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: CryptAcquireContext  read container/provider strings with cw
    if (a.size()<5||!a[0]) return 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    std::string cont_str, prov_str;
    if (a[1]) { cont_str = be(e)->read_mem_string(a[1], cw); a[1] = cont_str; }
    if (a[2]) { prov_str = be(e)->read_mem_string(a[2], cw); a[2] = prov_str; }
    auto cm = we(e)->get_crypt_manager();
    uint64_t hnd = 0;
    if (cm) hnd = cm->crypt_open(cont_str, prov_str, static_cast<uint32_t>(a[3]), static_cast<uint32_t>(a[4]));
    if (!hnd) hnd = 0x2900; // fallback handle
    int ps = we(e)->get_ptr_size();
    std::vector<uint8_t> buf((size_t)ps, 0);
    write_le(buf, 0, hnd, ps);
    we(e)->mem_write(a[0], buf);
    return 1;
}

//  CryptGenRandom 
uint64_t Advapi32::CryptGenRandom(void* e, ArgList& a, void* ctx) {
    if (a.size()<3||!a[2]||!a[1]) return 0;
    uint64_t len=a[1]; std::vector<uint8_t> buf((size_t)len);
    for(size_t i=0;i<(size_t)len;i++) buf[i]=(uint8_t)(rand()&0xFF);
    we(e)->mem_write(a[2],buf); return 1;
}


uint64_t Advapi32::RegDeleteValue(void* e, ArgList& a, void* ctx) {
    if (a.size()<2) return 2;
    std::string kp=resolve_hk(a[0]); if(kp.empty()) return 2;
    auto node=find_node(kp); if(!node) return 2;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    std::string vn; if(a[1]) { vn=be(e)->read_mem_string(a[1], cw); a[1]=vn; }
    if (vn.empty() || node->values.find(vn)==node->values.end()) return 2; // ERROR_FILE_NOT_FOUND
    node->values.erase(vn); return 0;
}

//  RegQueryInfoKey (Python stub: resolves hkey name, validates handle)
uint64_t Advapi32::RegQueryInfoKey(void* e, ArgList& a, void* ctx) {
    if (a.size()<12) return 2;
    std::string hkey_name = resolve_hk(a[0]);
    if (!hkey_name.empty()) a[0] = hkey_name;
    auto node = find_node(resolve_hk(a[0]));
    return node ? 0 : 6; // ERROR_INVALID_HANDLE
}

//  RegEnumKey (Python: delegates to RegEnumKeyEx with 4 extra zero args)
uint64_t Advapi32::RegEnumKey(void* e, ArgList& a, void* ctx) {
    ArgList ext = {a[0], a[1], a[2], a[3], uint64_t(0), uint64_t(0), uint64_t(0), uint64_t(0)};
    uint64_t rv = Advapi32::RegEnumKeyEx(e, ext, ctx);
    a[0] = ext[0]; a[1] = ext[1]; a[2] = ext[2]; a[3] = ext[3];
    return rv;
}

//  RegEnumKeyEx (Python: enumerate subkeys, write name with cw)
uint64_t Advapi32::RegEnumKeyEx(void* e, ArgList& a, void* ctx) {
    if (a.size()<8) return 6; // ERROR_INVALID_HANDLE
    uint64_t hKey = a[0];
    uint32_t dwIndex = static_cast<uint32_t>(a[1]);
    uint64_t lpName = a[2];
    uint64_t cchName = a[3];
    (void)a[4]; (void)a[5]; (void)a[6]; (void)a[7]; // reserved/class/lastwrite
    std::string kp = resolve_hk(hKey);
    if (kp.empty()) return 6;
    a[0] = kp;
    auto node = find_node(kp);
    if (!node) return 6;
    // Collect subkeys
    std::vector<std::string> subkeys;
    for (auto& [name, child] : node->children) subkeys.push_back(name);
    if (dwIndex >= subkeys.size()) return 259; // ERROR_NO_MORE_ITEMS
    if (lpName && cchName) {
        int cw = get_char_width(static_cast<ApiContext*>(ctx));
        std::string sk = subkeys[dwIndex];
        if (cw == 2) {
            for (size_t i = 0; i < sk.size() && i < static_cast<size_t>(cchName); i++) {
                std::vector<uint8_t> w(2,0); write_le(w, 0, static_cast<uint16_t>(sk[i]), 2);
                we(e)->mem_write(lpName + i*2, w);
            }
        } else {
            size_t n = std::min(sk.size(), static_cast<size_t>(cchName));
            we(e)->mem_write(lpName, std::vector<uint8_t>(sk.begin(), sk.begin()+n));
        }
        a[2] = sk;
    }
    return 0;
}

//  RegGetValue (Python: read subkey/value strings with cw, retrieve value data)
uint64_t Advapi32::RegGetValue(void* e, ArgList& a, void* ctx) {
    if (a.size()<7) return 2;
    uint64_t hKey=a[0], lpSubKey=a[1], lpValue=a[2], lpType=a[4], lpData=a[5], lpcbData=a[6];
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (lpSubKey) { a[1] = be(e)->read_mem_string(lpSubKey, cw); }
    if (lpValue)  { a[2] = be(e)->read_mem_string(lpValue, cw); }
    std::string kp = resolve_hk(hKey);
    if (kp.empty()) return 2;
    auto node = find_node(kp);
    if (!node) return 2;
    std::string vn = lpValue ? std::get<std::string>(a[2].data) : "";
    auto vit = node->values.find(vn);
    if (vit != node->values.end()) {
        auto& val = vit->second;
        if (lpType) { std::vector<uint8_t> tb(4,0); write_le(tb,0,(uint32_t)val.type,4); we(e)->mem_write(lpType,tb); }
        if (lpcbData) { std::vector<uint8_t> sb(4,0); write_le(sb,0,(uint32_t)val.data.size(),4); we(e)->mem_write(lpcbData,sb); }
        if (lpData && !val.data.empty()) we(e)->mem_write(lpData, val.data);
        return 0;
    }
    if (lpcbData) { std::vector<uint8_t> sb(4,0); write_le(sb,0,0,4); we(e)->mem_write(lpcbData,sb); }
    return 2;
}

//  Token / SID
uint64_t Advapi32::OpenThreadToken(void* e, ArgList& a, void* ctx) {
    if (a.size()<4||!a[3]) return 0;
    uint64_t h = we(e)->mem_map(8, 0, 4, "advapi32.token");
    return h;
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

//  Crypto 
uint64_t Advapi32::CryptReleaseContext(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::SystemFunction036(void* e, ArgList& a, void* ctx) {
    // RtlGenRandom  Python: fills buffer with range bytes
    if (a.size()<2||!a[0]||!a[1]) return 0;
    uint32_t len=static_cast<uint32_t>(a[1]);
    std::vector<uint8_t>buf(len);
    for(uint32_t i=0;i<len;i++) buf[i]=(uint8_t)i;
    we(e)->mem_write(a[0],buf); return 1;
}

//  Service Manager 
uint64_t Advapi32::OpenSCManager(void* e, ArgList& a, void* ctx) {
    // Python: hScm = self.mem_alloc(size=8)
    (void)a;
    uint64_t hScm = we(e)->mem_map(8, 0, 4, "advapi32.scmanager");
    
    return hScm;
}
uint64_t Advapi32::StartServiceCtrlDispatcher(void* e, ArgList& a, void* ctx) {
    if (a.size()<1||!a[0]) return 0;
    int ps=we(e)->get_ptr_size();
    // Read SERVICE_TABLE_ENTRY
    auto raw=we(e)->mem_read(a[0], (size_t)(ps*2));
    if (raw.size()<(size_t)(ps*2)) return 0;
    uint64_t svcName=0, svcProc=0;
    if (ps==8){
        svcName=read_le(raw,0,8); svcProc=read_le(raw,8,8);
    } else {
        svcName=read_le(raw,0,4); svcProc=read_le(raw,4,4);
    }
    // Update argv for logging: build service table description
    std::string desc="lpServiceStartTable=[";
    uint64_t off=0;
    while (svcName!=0||svcProc!=0){
        uint64_t entryAddr=a[0]+off;
        auto eraw=we(e)->mem_read(entryAddr,(size_t)(ps*2));
        if(eraw.size()<(size_t)(ps*2)) break;
        uint64_t en=0,ep=0;
        if(ps==8){en=read_le(eraw,0,8);ep=read_le(eraw,8,8);}
        else{en=read_le(eraw,0,4);ep=read_le(eraw,4,4);}
        desc+=" {lpServiceName=";
        if(en) desc+="\""+be(e)->read_mem_string(en,1)+"\"";
        else desc+="NULL";
        desc+=", lpServiceProc=";
        if(ep){char buf[32];snprintf(buf,sizeof(buf),"0x%llx",(unsigned long long)ep);desc+=buf;}
        else desc+="NULL";
        desc+="} ";
        off+=ps*2;
        if (off>=0x1000) break; // safety limit
        // Read next entry
        auto nraw=we(e)->mem_read(a[0]+off,(size_t)(ps*2));
        if(nraw.size()<(size_t)(ps*2)) break;
        if(ps==8){svcName=read_le(nraw,0,8);svcProc=read_le(nraw,8,8);}
        else{svcName=read_le(nraw,0,4);svcProc=read_le(nraw,4,4);}
    }
    desc+="]"; a[0]=desc; return 1;
}

//  RegisterServiceCtrlHandler A/W/Ex 
uint64_t Advapi32::RegisterServiceCtrlHandler(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; g_service_status_handle++; return g_service_status_handle;
}
uint64_t Advapi32::RegisterServiceCtrlHandlerEx(void* e, ArgList& a, void* ctx) {
    (void)e; g_service_status_handle++; return g_service_status_handle;
}
uint64_t Advapi32::SetServiceStatus(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  OpenService 
uint64_t Advapi32::OpenService(void* e, ArgList& a, void* ctx) {
    if (a.size()<3) return 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (a[1]) { a[1]=be(e)->read_mem_string(a[1], cw); }
    static uint64_t ns=0x3100; ns+=4; return ns;
}

//  CreateServiceA (Python: reads strings, mem_alloc, returns handle) 
uint64_t Advapi32::CreateService(void* e, ArgList& a, void* ctx) {
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (a.size()>=2&&a[1]) { a[1]=be(e)->read_mem_string(a[1], cw); }
    if (a.size()>=3&&a[2]) { a[2]=be(e)->read_mem_string(a[2], cw); }
    if (a.size()>=8&&a[7]) { a[7]=be(e)->read_mem_string(a[7], cw); }
    return we(e)->mem_map(8,0,4,"advapi32.service");
}

//  StartServiceA (Python: reads strings, set_last_error, returns 1) 
uint64_t Advapi32::StartService(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  ChangeServiceConfigA (Python: reads 6 strings, updates argv) 
uint64_t Advapi32::ChangeServiceConfig(void* e, ArgList& a, void* ctx) {
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (a.size()>=5&&a[4])  { a[4] =be(e)->read_mem_string(a[4], cw); }
    if (a.size()>=6&&a[5])  { a[5] =be(e)->read_mem_string(a[5], cw); }
    if (a.size()>=8&&a[7])  { a[7] =be(e)->read_mem_string(a[7], cw); }
    if (a.size()>=9&&a[8])  { a[8] =be(e)->read_mem_string(a[8], cw); }
    if (a.size()>=10&&a[9]) { a[9] =be(e)->read_mem_string(a[9], cw); }
    if (a.size()>=11&&a[10]){ a[10]=be(e)->read_mem_string(a[10],1); }
    return 1;
}

//  GetUserName 
uint64_t Advapi32::GetUserName(void* e, ArgList& a, void* ctx) {
    if (a.size()<2||!a[0]||!a[1]) return 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    auto user=be(e)->get_user();
    std::string name=user.count("name")?user.at("name"):"user";
    uint32_t sz = 0;
    we(e)->mem_read(a[1], &sz, sizeof(sz));

    uint32_t need=static_cast<uint32_t>(name.size()+1);
    if (sz<need) return 0; // ERROR_INSUFFICIENT_BUFFER
    be(e)->write_mem_string(name,a[0],cw);
    be(e)->mem_write(a[1], &need, 4); // write size
    a[0] = name; // Python: argv[0] = user_name
    return 1;
}

//  LookupAccountNameA 
uint64_t Advapi32::LookupAccountName(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: LookupAccountName  read sysname/acctname with cw, write SID/domain/peUse
    if (a.size()<7 || !a[1]) return 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (a[0]) { a[0] = be(e)->read_mem_string(a[0], cw); }
    std::string acctname = be(e)->read_mem_string(a[1], cw);
    a[1] = acctname;
    auto usermap = be(e)->get_user();
    std::string user = usermap.count("name") ? usermap.at("name") : "user";
    if (user != acctname) return 0;
    std::string str_sid = usermap.count("sid") ? usermap.at("sid") : "S-1-5-21-0-0-0-1000";
    a[2] = str_sid;
    // Read cbSid
    uint32_t cbsid = 0, cbcch = 0;
    if (a[3]) { auto r = we(e)->mem_read(a[3],4); if(r.size()>=4) cbsid=(uint32_t)read_le(r,0,4); }
    a[3] = cbsid;
    if (a[5]) { auto r = we(e)->mem_read(a[5],4); if(r.size()>=4) cbcch=(uint32_t)read_le(r,0,4); }
    a[5] = cbcch;
    // Write SID struct (simplified: 16 bytes placeholder)
    if (a[2] && cbsid >= 16) {
        std::vector<uint8_t> sid_buf(16,0);
        sid_buf[0]=1; sid_buf[1]=4; // revision=1, subauth=4
        write_le(sid_buf, 8, 0x15, 4); // NT_AUTHORITY
        we(e)->mem_write(a[2], sid_buf);
    }
    // Write domain name
    std::string domain = be(e)->get_domain();
    a[4] = domain;
    be(e)->write_mem_string(domain, a[4], cw);
    // Write peUse = 1 (SidTypeUser)
    if (a[6]) { std::vector<uint8_t> pe(4,0); write_le(pe,0,1,4); we(e)->mem_write(a[6],pe); a[6]=uint64_t(1); }
    return 1;
}

//  Crypto stubs 
uint64_t Advapi32::CryptCreateHash(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: CryptCreateHash  update argv[1] with alg_name
    static uint64_t nh=0x3200;
    if(a.size()>=2&&a[1]) {
        uint32_t alg = static_cast<uint32_t>(a[1]);
        switch (alg) {
            case 0x8004: a[1] = std::string("CALG_SHA1"); break;
            case 0x800C: a[1] = std::string("CALG_SHA_256"); break;
            case 0x800D: a[1] = std::string("CALG_SHA_384"); break;
            case 0x800E: a[1] = std::string("CALG_SHA_512"); break;
            case 0x8003: a[1] = std::string("CALG_MD5"); break;
            default: a[1] = std::string("CALG_UNKNOWN"); break;
        }
        nh+=4; return nh;
    }
    return 0;
}
uint64_t Advapi32::CryptDestroyHash(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::CryptGetHashParam(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: CryptGetHashParam  update argv[1] with param name
    if (a.size()>=2) {
        uint32_t p = static_cast<uint32_t>(a[1]);
        switch (p) {
            case 1: a[1] = std::string("HP_ALGID"); break;
            case 2: a[1] = std::string("HP_HASHVAL"); break;
            case 4: a[1] = std::string("HP_HASHSIZE"); break;
            case 5: a[1] = std::string("HP_HMAC_INFO"); break;
            default: break;
        }
    }
    (void)e; return 1;
}
uint64_t Advapi32::CryptHashData(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::CryptDecrypt(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::CryptDeriveKey(void* e, ArgList& a, void* ctx) {
    static uint64_t nk=0x3300; nk+=4; return nk;
}

//  More registry / token / misc 
uint64_t Advapi32::GetTokenInformation(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::LookupAccountSid(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: LookupAccountSid  write name/domain with cw
    if (a.size()<7 || !a[2] || !a[4]) return 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (a[0]) { a[0] = be(e)->read_mem_string(a[0], cw); }
    // Write user name and domain name with cw encoding
    std::string user = "myuser";
    std::string domain = "mydomain";
    if (a[2]) { be(e)->write_mem_string(user, a[2], cw); a[2] = user; }
    if (a[4]) { be(e)->write_mem_string(domain, a[4], cw); a[4] = domain; }
    return 1;
}
uint64_t Advapi32::LookupPrivilegeValue(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: LookupPrivilegeValue  read sysname/name with cw, write LUID
    if (a.size()<3||!a[2]) return 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (a[0]) { a[0] = be(e)->read_mem_string(a[0], cw); }
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], cw); }
    std::vector<uint8_t>buf(8,0); write_le(buf,0,0x20,4); write_le(buf,4,0,4);
    we(e)->mem_write(a[2],buf); return 1;
}
uint64_t Advapi32::EqualSid(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return 1;
}
uint64_t Advapi32::GetSidSubAuthority(void* e, ArgList& a, void* ctx) {
    if (a.size()>=2&&a[1]) { std::vector<uint8_t>buf(4,0); write_le(buf,0,0x20,4); we(e)->mem_write(a[1],buf); }
    return 1;
}
uint64_t Advapi32::GetSidSubAuthorityCount(void* e, ArgList& a, void* ctx) {
    if (a.size()>=1&&a[0]) { std::vector<uint8_t>buf(1,1); we(e)->mem_write(a[0],buf); }
    return 1;
}
uint64_t Advapi32::GetSidIdentifierAuthority(void* e, ArgList& a, void* ctx) {
    if (a.size()>=1&&a[0]) { std::vector<uint8_t>buf(6,0); buf[5]=5; we(e)->mem_write(a[0],buf); }
    return 1;
}
uint64_t Advapi32::GetCurrentHwProfile(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: GetCurrentHwProfile  write HW_PROFILE_INFO with cw encoding
    if (a.size()>=1&&a[0]) {
        int cw = get_char_width(static_cast<ApiContext*>(ctx));
        uint64_t dst = a[0];
        std::string guid = "{00000000-0000-0000-0000-000000000000}";
        std::string name = "Speakeasy Hardware Profile";
        // dwSize(4) + GUID string + profile name string
        size_t guid_bytes = guid.size() + 1; // +null
        size_t name_bytes = name.size() + 1;
        size_t sz = 4 + (cw == 2 ? guid_bytes * 2 : guid_bytes) + (cw == 2 ? name_bytes * 2 : name_bytes);
        std::vector<uint8_t> buf(sz, 0);
        write_le(buf, 0, static_cast<uint32_t>(sz), 4);
        uint64_t off = 4;
        if (cw == 2) {
            for (size_t i = 0; i < guid.size(); i++) { write_le(buf, off + i*2, static_cast<uint16_t>(guid[i]), 2); }
            off += guid_bytes * 2;
            for (size_t i = 0; i < name.size(); i++) { write_le(buf, off + i*2, static_cast<uint16_t>(name[i]), 2); }
        } else {
            for (size_t i = 0; i < guid.size(); i++) buf[off + i] = static_cast<uint8_t>(guid[i]);
            off += guid_bytes;
            for (size_t i = 0; i < name.size(); i++) buf[off + i] = static_cast<uint8_t>(name[i]);
        }
        we(e)->mem_write(dst, buf);
    }
    return 1;
}
// Python advapi32.py: CreateProcessAsUser  reads app/cmdline strings,
// creates a process via emu.create_process(), writes PROCESS_INFORMATION output.
uint64_t Advapi32::CreateProcessAsUser(void* e, ArgList& a, void* ctx) {
    if (a.size()<11) return 0;
    uint64_t app=a[1], cmd=a[2], env=a[7], cd=a[8], si=a[9], ppi=a[10];
    std::string appstr, cmdstr;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    if (app) { appstr=be(e)->read_mem_string(app, cw); a[1]=appstr; }
    if (cmd) { cmdstr=be(e)->read_mem_string(cmd, cw); a[2]=cmdstr; }
    if (appstr.empty() && !cmdstr.empty()) appstr=cmdstr.substr(0,cmdstr.find(' '));
    auto proc = we(e)->create_process(appstr, cmdstr, nullptr, false);
    if (!proc) return 0;
    auto proc_hnd = we(e)->get_object_handle(proc);
    uint64_t tid=0, th_hnd=0;
    if (!proc->threads.empty()) {
        auto t=proc->threads[0]; tid=t->get_tid();
        th_hnd=we(e)->get_object_handle(t);
    }
    int ps=we(e)->get_ptr_size();
    if (ppi) {
        if (ps==8) {
            PROCESS_INFORMATION_POD<8> pi;
            pi.hProcess=static_cast<uint64_t>(proc_hnd);
            pi.hThread=static_cast<uint64_t>(th_hnd);
            pi.dwProcessId=static_cast<uint32_t>(proc->get_pid());
            pi.dwThreadId=static_cast<uint32_t>(tid);
            std::vector<uint8_t> buf(sizeof(pi));
            cast_to_bytes(buf, 0, pi);
            we(e)->mem_write(ppi, buf);
        } else {
            PROCESS_INFORMATION_POD<4> pi;
            pi.hProcess=static_cast<uint32_t>(proc_hnd);
            pi.hThread=static_cast<uint32_t>(th_hnd);
            pi.dwProcessId=static_cast<uint32_t>(proc->get_pid());
            pi.dwThreadId=static_cast<uint32_t>(tid);
            std::vector<uint8_t> buf(sizeof(pi));
            cast_to_bytes(buf, 0, pi);
            we(e)->mem_write(ppi, buf);
        }
    }
    (void)env; (void)cd; (void)si;
    return 1;
}
uint64_t Advapi32::EnumServicesStatus(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: EnumServicesStatus  resolve enum types, update argv
    if (a.size()<8) return 0;
    uint32_t svcType = static_cast<uint32_t>(a[1]);
    uint32_t svcState = static_cast<uint32_t>(a[2]);
    // Resolve enum names for logging
    if (svcType == 0x10) a[1] = std::string("SERVICE_WIN32_OWN_PROCESS");
    else if (svcType == 0x20) a[1] = std::string("SERVICE_WIN32_SHARE_PROCESS");
    else a[1] = std::string("SERVICE_UNKNOWN");
    if (svcState == 1) a[2] = std::string("SERVICE_STOPPED");
    else if (svcState == 4) a[2] = std::string("SERVICE_RUNNING");
    else a[2] = std::string("SERVICE_STATE_UNKNOWN");
    // Write bytes needed = 0 (no services to enumerate in emulation)
    if (a[5]) { std::vector<uint8_t> buf(4,0); we(e)->mem_write(a[5], buf); }
    (void)e;
    return 0; // ERROR_NO_MORE_ITEMS
}

uint64_t Advapi32::QueryServiceConfig(void* e, ArgList& a, void* ctx) {
    // Python advapi32.py: QueryServiceConfig  write QUERY_SERVICE_CONFIG structure
    if (a.size()<4 || !a[1]) return 0;
    uint32_t bufSize = static_cast<uint32_t>(a[3]);
    int ps = we(e)->get_ptr_size();
    // QUERY_SERVICE_CONFIG: ServiceType(4)+StartType(4)+ErrorControl(4)+BinaryPathName(ps)+LoadOrderGroup(ps)+TagId(4)+Dependencies(ps)+ServiceStartName(ps)+DisplayName(ps)
    uint32_t structSize = 4+4+4 + static_cast<uint32_t>(ps)*5 + 4;
    if (a[3]) { std::vector<uint8_t> sz(4,0); write_le(sz,0,structSize,4); we(e)->mem_write(a[3], sz); }
    if (bufSize >= structSize && a[1]) {
        std::vector<uint8_t> buf(structSize, 0);
        write_le(buf, 0, 0x10, 4);  // SERVICE_WIN32_OWN_PROCESS
        write_le(buf, 4, 2, 4);     // SERVICE_AUTO_START
        write_le(buf, 8, 1, 4);     // SERVICE_ERROR_NORMAL
        we(e)->mem_write(a[1], buf);
    }
    (void)e; return 1;
}

uint64_t Advapi32::ControlService(void* e, ArgList& a, void* ctx) { (void)e;(void)a;return 1; }
uint64_t Advapi32::DeleteService(void* e, ArgList& a, void* ctx) { (void)e;(void)a;return 1; }
uint64_t Advapi32::QueryServiceStatus(void* e, ArgList& a, void* ctx) {
    (void)e; if(a.size()>=2&&a[1]){std::vector<uint8_t>buf(28,0);write_le(buf,0,0x30,4);we(e)->mem_write(a[1],buf);}
    return 1;
}
uint64_t Advapi32::CloseServiceHandle(void* e, ArgList& a, void* ctx) { (void)e;(void)a;return 1; }
uint64_t Advapi32::ChangeServiceConfig2(void* e, ArgList& a, void* ctx) { (void)e;(void)a;return 1; }
uint64_t Advapi32::RevertToSelf(void* e, ArgList& a, void* ctx) { (void)e;(void)a;return 1; }
uint64_t Advapi32::ImpersonateLoggedOnUser(void* e, ArgList& a, void* ctx) { (void)e;(void)a;return 1; }
uint64_t Advapi32::stub(void* e, ArgList& a, void* ctx) { (void)e; (void)a; return 1; }

Advapi32::Advapi32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Advapi32)
    REG(Advapi32, RegOpenKey, 3)            REG(Advapi32, RegOpenKeyEx, 5)
    REG(Advapi32, RegQueryValueEx, 6)
    REG(Advapi32, RegCloseKey, 1)
    REG(Advapi32, RegCreateKey, 3)
    REG(Advapi32, RegCreateKeyEx, 9)
    REG(Advapi32, RegSetValueEx, 6)
    REG(Advapi32, RegDeleteKey, 1)     REG(Advapi32, RegDeleteValue, 2)
    REG(Advapi32, RegEnumKey, 4)        REG(Advapi32, RegEnumKeyEx, 8)
    REG(Advapi32, RegGetValue, 7)       REG(Advapi32, RegQueryInfoKey, 12)
    REG(Advapi32, OpenProcessToken, 3)  REG(Advapi32, OpenThreadToken, 4)
    REG(Advapi32, LookupPrivilegeValue, 3)
    REG(Advapi32, AdjustTokenPrivileges, 6)
    REG(Advapi32, DuplicateTokenEx, 6)  REG(Advapi32, SetTokenInformation, 4)
    REG(Advapi32, CryptAcquireContext, 5)
    REG(Advapi32, CryptGenRandom, 3)    REG(Advapi32, CryptReleaseContext, 2)
    REG(Advapi32, SystemFunction036, 2) // RtlGenRandom
    REG(Advapi32, CreateService, 13)
    REG(Advapi32, StartService, 3)
    REG(Advapi32, ControlService, 3)    REG(Advapi32, DeleteService, 1)
    REG(Advapi32, QueryServiceStatus, 2) REG(Advapi32, CloseServiceHandle, 1)
    REG(Advapi32, ChangeServiceConfig, 11)
    REG(Advapi32, ChangeServiceConfig2, 3)
    REG(Advapi32, OpenSCManager, 3)
    REG(Advapi32, RevertToSelf, 0)      REG(Advapi32, ImpersonateLoggedOnUser, 1)
    REG(Advapi32, AllocateAndInitializeSid, 11)
    REG(Advapi32, CheckTokenMembership, 3) REG(Advapi32, FreeSid, 1)
    REG(Advapi32, StartServiceCtrlDispatcher, 1)
    REG(Advapi32, RegisterServiceCtrlHandler, 2)
    REG(Advapi32, RegisterServiceCtrlHandlerEx, 3)
    REG(Advapi32, SetServiceStatus, 2)
    REG(Advapi32, OpenService, 3)
    REG(Advapi32, GetUserName, 2)
    REG(Advapi32, LookupAccountName, 7)
    REG(Advapi32, LookupAccountSid, 7)
    REG(Advapi32, CryptCreateHash, 5)       REG(Advapi32, CryptDestroyHash, 1)
    REG(Advapi32, CryptGetHashParam, 5)     REG(Advapi32, CryptHashData, 4)
    REG(Advapi32, CryptDecrypt, 6)          REG(Advapi32, CryptDeriveKey, 5)
    REG(Advapi32, GetTokenInformation, 5)
    REG(Advapi32, GetCurrentHwProfile, 1)
    REG(Advapi32, CreateProcessAsUser, 11)
    REG(Advapi32, EnumServicesStatus, 8)
    REG(Advapi32, QueryServiceConfig, 4)
    REG(Advapi32, EqualSid, 2)              REG(Advapi32, GetSidSubAuthority, 2)
    REG(Advapi32, GetSidSubAuthorityCount, 1) REG(Advapi32, GetSidIdentifierAuthority, 1)
    END_API_TABLE
}

}} // namespaces
