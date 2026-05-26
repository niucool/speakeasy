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

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

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
uint64_t Advapi32::RegOpenKeyExA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
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
uint64_t Advapi32::RegQueryValueExA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
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
uint64_t Advapi32::RegCloseKey(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; if (a.size()<1) return 0xFFFFFFFF;
    return resolve_hk(a[0]).empty() ? 6 : 0;
}

//  RegCreateKeyExA 
uint64_t Advapi32::RegCreateKeyExA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
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
uint64_t Advapi32::RegSetValueExA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
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
uint64_t Advapi32::RegDeleteKeyA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

//  OpenProcessToken 
uint64_t Advapi32::OpenProcessToken(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<3||!a[2]) return 0;
    static uint64_t nt=0x2800; nt+=4;
    int ps=we(e)->get_ptr_size(); std::vector<uint8_t> buf((size_t)ps,0);
    write_le(buf,0,nt,ps); we(e)->mem_write(a[2],buf); return 1;
}

//  LookupPrivilegeValueA 
uint64_t Advapi32::LookupPrivilegeValueA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<3||!a[2]) return 0;
    std::vector<uint8_t> buf(8,0); write_le(buf,0,0x20,4); write_le(buf,4,0,4);
    we(e)->mem_write(a[2],buf); return 1;
}

//  AdjustTokenPrivileges 
uint64_t Advapi32::AdjustTokenPrivileges(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

//  CryptAcquireContextA 
uint64_t Advapi32::CryptAcquireContextA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<5||!a[0]) return 0;
    static uint64_t nc=0x2900; nc+=4;
    int ps=we(e)->get_ptr_size(); std::vector<uint8_t> buf((size_t)ps,0);
    write_le(buf,0,nc,ps); we(e)->mem_write(a[0],buf); return 1;
}

//  CryptGenRandom 
uint64_t Advapi32::CryptGenRandom(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<3||!a[2]||!a[1]) return 0;
    uint64_t len=a[1]; std::vector<uint8_t> buf((size_t)len);
    for(size_t i=0;i<(size_t)len;i++) buf[i]=(uint8_t)(rand()&0xFF);
    we(e)->mem_write(a[2],buf); return 1;
}

//  CreateServiceA 
uint64_t Advapi32::CreateServiceA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; static uint64_t ns=0x3000; ns+=4; return ns;
}

//  StartServiceA 
uint64_t Advapi32::StartServiceA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

uint64_t Advapi32::stub(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

Advapi32::Advapi32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Advapi32)
    REG(Advapi32, RegOpenKeyExA, 5)
    REG(Advapi32, RegQueryValueExA, 6)
    REG(Advapi32, RegCloseKey, 1)
    REG(Advapi32, RegCreateKeyExA, 9)
    REG(Advapi32, RegSetValueExA, 6)
    REG(Advapi32, RegDeleteKeyA, 1)
    REG(Advapi32, OpenProcessToken, 3)
    REG(Advapi32, LookupPrivilegeValueA, 3)
    REG(Advapi32, AdjustTokenPrivileges, 6)
    REG(Advapi32, CryptAcquireContextA, 5)
    REG(Advapi32, CryptGenRandom, 3)
    REG(Advapi32, CreateServiceA, 13)
    REG(Advapi32, StartServiceA, 3)
    END_API_TABLE
}

}} // namespaces
