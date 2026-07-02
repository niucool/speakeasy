/*
 * platform_linux.h — Drop-in <windows.h> replacement.
 *
 * On MSVC: the Windows SDK always exists; we just include it and add stubs.
 * On Linux: provide every type, PE struct, constant, helper, and API stub.
 */
#pragma once

#define PLATFORM_LINUX_ACTIVE

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cerrno>
#include <string>
#include <vector>

// =========================================================================
// Shared string helpers — only the ones that don't conflict with MSVC CRT
// =========================================================================

inline int scylla_stricmp(const char* a,const char* b){
    while(*a&&*b){char ca=(*a>='A'&&*a<='Z')?*a+32:*a,cb=(*b>='A'&&*b<='Z')?*b+32:*b;if(ca!=cb)return ca-cb;++a;++b;}
    return *a-*b;
}
#ifndef _stricmp
#define _stricmp scylla_stricmp
#endif

inline int scylla_wcsicmp(const wchar_t* a,const wchar_t* b){
    while(*a&&*b){wchar_t ca=(*a>=L'A'&&*a<=L'Z')?*a+32:*a,cb=(*b>=L'A'&&*b<=L'Z')?*b+32:*b;if(ca!=cb)return(int)(ca-cb);++a;++b;}
    return(int)(*a-*b);
}
#ifndef _wcsicmp
#define _wcsicmp scylla_wcsicmp
#endif

// =========================================================================
// Platform-specific
// =========================================================================

#ifdef _MSC_VER
// ---- MSVC: the Windows SDK is always available. Just include it. ----
#pragma message("platform_linux.h: MSVC detected — including real Windows SDK")

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <imagehlp.h>

// Only stubs that the SDK doesn't provide:
inline BOOL UnmapViewOfFile_stub(LPCVOID){return TRUE;}
#define UnmapViewOfFile UnmapViewOfFile_stub

inline PIMAGE_NT_HEADERS CheckSumMappedFile_stub(void* Base,DWORD len,DWORD* hs,DWORD* cs){
    auto* dos=(PIMAGE_DOS_HEADER)Base;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return nullptr;
    auto* hdr=(PIMAGE_NT_HEADERS)((uint8_t*)Base+dos->e_lfanew);
    if(hdr->Signature!=IMAGE_NT_SIGNATURE)return nullptr;
    hdr->OptionalHeader.CheckSum=0;*cs=0;*hs=0;return hdr;
}
#define CheckSumMappedFile CheckSumMappedFile_stub

#else // =====  REAL LINUX / GCC / CLANG  =====

// ---- 1. Calling conventions ----
#define WINAPI
#define CALLBACK
#define __stdcall
#define __cdecl
#define __in
#define __out
#define __inout
#define __reserved

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

// ---- 2. Basic types ----
using BOOL       = int32_t;
using CHAR       = char;
using BYTE       = uint8_t;
using WORD       = uint16_t;
using DWORD      = uint32_t;
using ULONG      = uint32_t;
using UINT       = uint32_t;
using INT        = int32_t;
using LONG       = int32_t;
using HRESULT    = LONG;
using HANDLE     = void*;
using HMODULE    = void*;
using HINSTANCE  = void*;
using HWND       = void*;
using LPVOID     = void*;
using LPCVOID    = const void*;
using PVOID      = void*;
using LPCSTR     = const char*;
using LPCWSTR    = const wchar_t*;
using LPSTR      = char*;
using LPWSTR     = wchar_t*;
using PWSTR      = wchar_t*;
using PCWSTR     = const wchar_t*;
using FARPROC    = void*;
using WCHAR      = wchar_t;
using DWORD_PTR  = uint64_t;
using ULONG_PTR  = uint64_t;
using LONGLONG   = int64_t;
using SIZE_T     = uint64_t;
using SHORT      = int16_t;
using USHORT     = uint16_t;
using UINT_PTR   = uint64_t;
using LONG_PTR   = int64_t;
using LPARAM     = LONG_PTR;
using WPARAM     = UINT_PTR;
using LRESULT    = LONG_PTR;
using DWORDLONG  = uint64_t;
using NTSTATUS   = LONG;
using ACCESS_MASK= DWORD;
using KPRIORITY  = LONG;
using PSID       = void*;
using errno_t    = int;
constexpr int MAX_PATH = 260;

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define INVALID_SET_FILE_POINTER ((DWORD)-1)
#define NT_SUCCESS(s) (((NTSTATUS)(s))>=0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

// ---- 3. Macros ----
inline void ZeroMemory(void* p, size_t n) { std::memset(p, 0, n); }
#define _countof(a) (sizeof(a)/sizeof((a)[0]))
#define LOWORD(l)   ((WORD)((DWORD_PTR)(l)&0xffff))
#define HIWORD(l)   ((WORD)((DWORD_PTR)(l)>>16))
#define LOBYTE(w)   ((BYTE)((DWORD_PTR)(w)&0xff))
#define HIBYTE(w)   ((BYTE)((DWORD_PTR)(w)>>8))
#define MAKELONG(a,b) ((LONG)(((WORD)((DWORD_PTR)(a)&0xffff))|((DWORD)((WORD)((DWORD_PTR)(b)&0xffff)))<<16))
#define MAKELPARAM(l,h) ((LPARAM)MAKELONG(l,h))
#define MAKEINTRESOURCEA(i) ((LPCSTR)((ULONG_PTR)((WORD)(i))))
#define MAKEINTRESOURCEW(i) ((LPCWSTR)((ULONG_PTR)((WORD)(i))))
inline void __cpuidex_stub(int d[4],int,int){d[0]=d[1]=d[2]=d[3]=0;}
#define __cpuidex __cpuidex_stub

// ---- 4. PE structures ----
struct IMAGE_DOS_HEADER {
    WORD e_magic,e_cblp,e_cp,e_crlc,e_cparhdr,e_minalloc,e_maxalloc,e_ss,e_sp;
    WORD e_csum,e_ip,e_cs,e_lfarlc,e_ovno,e_res[4],e_oemid,e_oeminfo,e_res2[10];
    LONG e_lfanew;
};
using PIMAGE_DOS_HEADER=IMAGE_DOS_HEADER*;
constexpr WORD IMAGE_DOS_SIGNATURE=0x5A4D;
struct IMAGE_FILE_HEADER{WORD Machine,NumberOfSections;DWORD TimeDateStamp,PointerToSymbolTable,NumberOfSymbols;WORD SizeOfOptionalHeader,Characteristics;};
using PIMAGE_FILE_HEADER=IMAGE_FILE_HEADER*;
struct IMAGE_DATA_DIRECTORY{DWORD VirtualAddress,Size;};
constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES=16;
struct IMAGE_OPTIONAL_HEADER{
    WORD Magic;BYTE MajorLinkerVersion,MinorLinkerVersion;
    DWORD SizeOfCode,SizeOfInitializedData,SizeOfUninitializedData,AddressOfEntryPoint,BaseOfCode;
    DWORD_PTR ImageBase;DWORD SectionAlignment,FileAlignment;
    WORD MajorOperatingSystemVersion,MinorOperatingSystemVersion,MajorImageVersion,MinorImageVersion,MajorSubsystemVersion,MinorSubsystemVersion;
    DWORD Win32VersionValue,SizeOfImage,SizeOfHeaders,CheckSum;WORD Subsystem,DllCharacteristics;
    DWORD_PTR SizeOfStackReserve,SizeOfStackCommit,SizeOfHeapReserve,SizeOfHeapCommit;
    DWORD LoaderFlags,NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
constexpr WORD IMAGE_NT_OPTIONAL_HDR32_MAGIC=0x10b,IMAGE_NT_OPTIONAL_HDR64_MAGIC=0x20b;
struct IMAGE_NT_HEADERS{DWORD Signature;IMAGE_FILE_HEADER FileHeader;IMAGE_OPTIONAL_HEADER OptionalHeader;};
using IMAGE_NT_HEADERS32=IMAGE_NT_HEADERS,IMAGE_NT_HEADERS64=IMAGE_NT_HEADERS;
using PIMAGE_NT_HEADERS=IMAGE_NT_HEADERS*,PIMAGE_NT_HEADERS32=IMAGE_NT_HEADERS*,PIMAGE_NT_HEADERS64=IMAGE_NT_HEADERS*;
constexpr DWORD IMAGE_NT_SIGNATURE=0x00004550;
constexpr int IMAGE_SIZEOF_SHORT_NAME=8;
struct IMAGE_SECTION_HEADER{
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];union { DWORD PhysicalAddress;DWORD VirtualSize;}Misc;
    DWORD VirtualAddress,SizeOfRawData,PointerToRawData,PointerToRelocations,PointerToLinenumbers;
    WORD NumberOfRelocations,NumberOfLinenumbers;DWORD Characteristics;
};
using PIMAGE_SECTION_HEADER=IMAGE_SECTION_HEADER*;
struct IMAGE_EXPORT_DIRECTORY{DWORD Characteristics,TimeDateStamp;WORD MajorVersion,MinorVersion;DWORD Name,Base,NumberOfFunctions,NumberOfNames,AddressOfFunctions,AddressOfNames,AddressOfNameOrdinals;};
using PIMAGE_EXPORT_DIRECTORY=IMAGE_EXPORT_DIRECTORY*;
struct IMAGE_IMPORT_DESCRIPTOR{union { DWORD Characteristics;DWORD OriginalFirstThunk;};DWORD TimeDateStamp,ForwarderChain,Name,FirstThunk;};
using PIMAGE_IMPORT_DESCRIPTOR=IMAGE_IMPORT_DESCRIPTOR*;
union IMAGE_THUNK_DATA{DWORD_PTR ForwarderString,Function,Ordinal,AddressOfData;};
using PIMAGE_THUNK_DATA=IMAGE_THUNK_DATA*,IIMAGE_THUNK_DATA=IMAGE_THUNK_DATA;
constexpr DWORD_PTR IMAGE_ORDINAL_FLAG=(sizeof(DWORD_PTR)==8)?0x8000000000000000ULL:0x80000000U;
inline DWORD IMAGE_ORDINAL(DWORD_PTR o){return(DWORD)(o&0xFFFF);}
inline bool IMAGE_SNAP_BY_ORDINAL(DWORD_PTR o){return(o&IMAGE_ORDINAL_FLAG)!=0;}
struct IMAGE_IMPORT_BY_NAME{WORD Hint;char Name[1];};
using PIMAGE_IMPORT_BY_NAME=IMAGE_IMPORT_BY_NAME*;
struct IMAGE_RESOURCE_DATA_ENTRY{DWORD OffsetToData,Size,CodePage,Reserved;};
inline PIMAGE_SECTION_HEADER IMAGE_FIRST_SECTION(const IMAGE_NT_HEADERS* nthdr){return(PIMAGE_SECTION_HEADER)((const uint8_t*)nthdr+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nthdr->FileHeader.SizeOfOptionalHeader);}
constexpr int IMAGE_DIRECTORY_ENTRY_EXPORT=0,IMAGE_DIRECTORY_ENTRY_IMPORT=1,IMAGE_DIRECTORY_ENTRY_RESOURCE=2,IMAGE_DIRECTORY_ENTRY_TLS=9,IMAGE_DIRECTORY_ENTRY_IAT=12;

// ---- 5. NT structures ----
struct UNICODE_STRING{USHORT Length,MaximumLength;PWSTR Buffer;};
using PUNICODE_STRING=UNICODE_STRING*;
struct CLIENT_ID{HANDLE UniqueProcess,UniqueThread;};using PCLIENT_ID=CLIENT_ID*;
struct OBJECT_ATTRIBUTES{ULONG Length;HANDLE RootDirectory;PUNICODE_STRING ObjectName;ULONG Attributes;PVOID SecurityDescriptor,SecurityQualityOfService;};
using POBJECT_ATTRIBUTES=OBJECT_ATTRIBUTES*;
inline void InitializeObjectAttributes(OBJECT_ATTRIBUTES* p,UNICODE_STRING* n,ULONG a,HANDLE r,PVOID s){p->Length=sizeof(OBJECT_ATTRIBUTES);p->RootDirectory=r;p->Attributes=a;p->ObjectName=n;p->SecurityDescriptor=s;p->SecurityQualityOfService=nullptr;}
struct LIST_ENTRY{LIST_ENTRY*Flink;LIST_ENTRY*Blink;};
union LARGE_INTEGER{struct {DWORD LowPart;LONG HighPart;}u;LONGLONG QuadPart;};
using PLARGE_INTEGER=LARGE_INTEGER*;
struct FILETIME{DWORD dwLowDateTime,dwHighDateTime;};
struct SECURITY_ATTRIBUTES{DWORD nLength;LPVOID lpSecurityDescriptor;BOOL bInheritHandle;};
struct OVERLAPPED{ULONG_PTR Internal,InternalHigh;union {struct {DWORD Offset,OffsetHigh;};PVOID Pointer;};HANDLE hEvent;};

// ---- 6. MEMORY_BASIC_INFORMATION ----
struct MEMORY_BASIC_INFORMATION{void*BaseAddress,*AllocationBase;DWORD AllocationProtect;SIZE_T RegionSize;DWORD State,Protect,Type;};
using PMEMORY_BASIC_INFORMATION=MEMORY_BASIC_INFORMATION*;
constexpr DWORD MEM_COMMIT=0x1000,MEM_RESERVE=0x2000,MEM_FREE=0x10000,MEM_IMAGE=0x1000000,MEM_MAPPED=0x40000;
constexpr DWORD PAGE_NOACCESS=1,PAGE_READONLY=2,PAGE_READWRITE=4,PAGE_WRITECOPY=8;
constexpr DWORD PAGE_EXECUTE=0x10,PAGE_EXECUTE_READ=0x20,PAGE_EXECUTE_READWRITE=0x40,PAGE_EXECUTE_WRITECOPY=0x80;
constexpr DWORD PAGE_GUARD=0x100,PAGE_NOCACHE=0x200,PAGE_WRITECOMBINE=0x400;

// ---- 7. Process structures ----
struct PROCESSENTRY32W{DWORD dwSize,cntUsage,th32ProcessID;ULONG_PTR th32DefaultHeapID;DWORD th32ModuleID,cntThreads,th32ParentProcessID;LONG pcPriClassBase;DWORD dwFlags;WCHAR szExeFile[MAX_PATH];};
using PROCESSENTRY32=PROCESSENTRY32W;using LPPROCESSENTRY32W=PROCESSENTRY32W*;
struct SYSTEM_INFO{union {DWORD dwOemId;struct {WORD wProcessorArchitecture,wReserved;};};DWORD dwPageSize;void*lpMinimumApplicationAddress,*lpMaximumApplicationAddress;DWORD_PTR dwActiveProcessorMask;DWORD dwNumberOfProcessors,dwProcessorType,dwAllocationGranularity;WORD wProcessorLevel,wProcessorRevision;};
using LPSYSTEM_INFO=SYSTEM_INFO*;
struct RTL_OSVERSIONINFOW{DWORD dwOSVersionInfoSize,dwMajorVersion,dwMinorVersion,dwBuildNumber,dwPlatformId;WCHAR szCSDVersion[128];};
using PRTL_OSVERSIONINFOW=RTL_OSVERSIONINFOW*;

// ---- 8. Constants ----
constexpr DWORD FILE_BEGIN=0,FILE_END=2,GENERIC_READ=0x80000000,GENERIC_WRITE=0x40000000,GENERIC_ALL=0x10000000;
constexpr DWORD FILE_SHARE_READ=1,OPEN_EXISTING=3,CREATE_ALWAYS=2;
constexpr DWORD PAGE_READONLY_FM=0x02,PAGE_EXECUTE_READWRITE_FM=0x40,SEC_IMAGE=0x1000000;
constexpr DWORD FILE_MAP_READ=4,FILE_MAP_ALL_ACCESS=0x000F001F;
constexpr DWORD PROCESS_VM_READ=0x10,PROCESS_VM_WRITE=0x20,PROCESS_VM_OPERATION=0x08,PROCESS_QUERY_INFORMATION=0x0400;
constexpr DWORD PROCESS_CREATE_THREAD=0x02,PROCESS_SUSPEND_RESUME=0x0800,PROCESS_TERMINATE=0x01;
constexpr DWORD TH32CS_SNAPPROCESS=2,TH32CS_SNAPTHREAD=4,TH32CS_SNAPMODULE=8,CP_ACP=0,CP_UTF8=65001;

// ---- 9. Safe-string helpers (MSVC CRT provides these) ----
inline void scylla_wcscpy_s(wchar_t* d,size_t ds,const wchar_t* s){size_t n=0;while(s[n])++n;if(n>=ds)n=ds-1;for(size_t i=0;i<n;++i)d[i]=s[i];d[n]=0;}
template<size_t N> inline void scylla_wcscpy_s(wchar_t(&d)[N],const wchar_t* s){scylla_wcscpy_s(d,N,s);}
#define wcscpy_s scylla_wcscpy_s
inline void scylla_wcscat_s(wchar_t* d,size_t ds,const wchar_t* s){size_t dl=0;while(d[dl])++dl;scylla_wcscpy_s(d+dl,ds-dl,s);}
template<size_t N> inline void scylla_wcscat_s(wchar_t(&d)[N],const wchar_t* s){scylla_wcscat_s(d,N,s);}
#define wcscat_s scylla_wcscat_s
inline int scylla_strcpy_s(char* d,size_t ds,const char* s){size_t n=0;while(s[n])++n;if(n>=ds)n=ds-1;for(size_t i=0;i<n;++i)d[i]=s[i];d[n]=0;return 0;}
template<size_t N> inline int scylla_strcpy_s(char(&d)[N],const char* s){return scylla_strcpy_s(d,N,s);}
#define strcpy_s scylla_strcpy_s

// ---- 10. String conversion stubs ----
inline int MultiByteToWideChar_stub(DWORD cp,DWORD fl,const char* s,int sl,wchar_t* d,int dl){(void)cp;(void)fl;if(!d||!s)return 0;int n=(sl==-1)?(int)std::strlen(s):sl;if(dl==0)return n;int w=(n<dl-1)?n:dl-1;for(int i=0;i<w;++i)d[i]=(wchar_t)(unsigned char)s[i];d[w]=0;return w;}
#define MultiByteToWideChar MultiByteToWideChar_stub
inline int WideCharToMultiByte_stub(DWORD cp,DWORD fl,const wchar_t* s,int sl,char* d,int dl,const char*,BOOL*){(void)cp;(void)fl;if(!d||!s)return 0;int n=(sl==-1)?(int)std::wcslen(s):sl;if(dl==0)return n;int w=(n<dl-1)?n:dl-1;for(int i=0;i<w;++i)d[i]=(char)(s[i]&0xFF);d[w]=0;return w;}
#define WideCharToMultiByte WideCharToMultiByte_stub
inline errno_t wcstombs_s_stub(size_t* r,char* d,size_t ds,const wchar_t* s,size_t c){if(!d||!s){if(r)*r=(size_t)-1;return 1;}size_t i=0;while(i<c&&i<ds-1&&s[i]){d[i]=(char)(s[i]&0x7F);++i;}d[i]=0;if(r)*r=i;return 0;}
#ifndef wcstombs_s
#define wcstombs_s wcstombs_s_stub
#endif
inline errno_t mbstowcs_s_stub(size_t* r,wchar_t* d,size_t ds,const char* s,size_t c){if(!d||!s){if(r)*r=(size_t)-1;return 1;}size_t i=0;while(i<c&&i<ds-1&&s[i]){d[i]=(wchar_t)(unsigned char)s[i];++i;}d[i]=0;if(r)*r=i;return 0;}
#ifndef mbstowcs_s
#define mbstowcs_s mbstowcs_s_stub
#endif

// ---- 10. API stubs ----
inline BOOL UnmapViewOfFile_stub(LPCVOID){return TRUE;}
#define UnmapViewOfFile UnmapViewOfFile_stub
inline PIMAGE_NT_HEADERS CheckSumMappedFile_stub(void* B,DWORD len,DWORD*hs,DWORD*cs){auto*dos=(PIMAGE_DOS_HEADER)B;if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return nullptr;auto*hdr=(PIMAGE_NT_HEADERS)((uint8_t*)B+dos->e_lfanew);if(hdr->Signature!=IMAGE_NT_SIGNATURE)return nullptr;hdr->OptionalHeader.CheckSum=0;*cs=0;*hs=0;return hdr;}
#define CheckSumMappedFile CheckSumMappedFile_stub
inline BOOL CloseHandle_stub(HANDLE){return TRUE;}
#define CloseHandle CloseHandle_stub
inline DWORD GetLastError_stub(){return 0;}
#define GetLastError GetLastError_stub
inline HANDLE GetCurrentProcess_stub(){return(HANDLE)(uintptr_t)0xFFFFFFFF;}
#define GetCurrentProcess GetCurrentProcess_stub
inline void GetSystemTimeAsFileTime_stub(void*){}
#define GetSystemTimeAsFileTime GetSystemTimeAsFileTime_stub
inline HANDLE OpenProcess_stub(DWORD,BOOL,DWORD){return nullptr;}
#define OpenProcess OpenProcess_stub
inline BOOL ReadProcessMemory_stub(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*){return FALSE;}
#define ReadProcessMemory ReadProcessMemory_stub
inline BOOL WriteProcessMemory_stub(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*){return FALSE;}
#define WriteProcessMemory WriteProcessMemory_stub
inline SIZE_T VirtualQueryEx_stub(HANDLE,LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T){return 0;}
#define VirtualQueryEx VirtualQueryEx_stub
inline BOOL VirtualProtectEx_stub(HANDLE,LPVOID,SIZE_T,DWORD,DWORD*){return FALSE;}
#define VirtualProtectEx VirtualProtectEx_stub
inline BOOL EnumProcessModules_stub(HANDLE,HMODULE*,DWORD,DWORD*){return FALSE;}
#define EnumProcessModules EnumProcessModules_stub
inline DWORD GetModuleFileNameExW_stub(HANDLE,HMODULE,WCHAR*,DWORD){return 0;}
#define GetModuleFileNameExW GetModuleFileNameExW_stub
inline DWORD GetMappedFileNameW_stub(HANDLE,LPVOID,WCHAR*,DWORD){return 0;}
#define GetMappedFileNameW GetMappedFileNameW_stub
inline HANDLE CreateToolhelp32Snapshot_stub(DWORD,DWORD){return nullptr;}
#define CreateToolhelp32Snapshot CreateToolhelp32Snapshot_stub
inline BOOL Process32FirstW_stub(HANDLE,LPPROCESSENTRY32W){return FALSE;}
#define Process32FirstW Process32FirstW_stub
inline BOOL Process32NextW_stub(HANDLE,LPPROCESSENTRY32W){return FALSE;}
#define Process32NextW Process32NextW_stub
inline BOOL IsWow64Process_stub(HANDLE,BOOL*){return FALSE;}
#define IsWow64Process IsWow64Process_stub
inline FARPROC GetProcAddress_stub(HMODULE,LPCSTR){return nullptr;}
#define GetProcAddress GetProcAddress_stub
inline HMODULE GetModuleHandleA_stub(LPCSTR){return nullptr;}
#define GetModuleHandleA GetModuleHandleA_stub
inline HMODULE GetModuleHandleW_stub(LPCWSTR){return nullptr;}
#define GetModuleHandleW GetModuleHandleW_stub
inline HANDLE CreateFileW_stub(LPCWSTR,DWORD,DWORD,void*,DWORD,DWORD,HANDLE){return nullptr;}
#define CreateFileW CreateFileW_stub
inline BOOL ReadFile_stub(HANDLE,LPVOID,DWORD,DWORD*,void*){return FALSE;}
#define ReadFile ReadFile_stub
inline BOOL WriteFile_stub(HANDLE,LPCVOID,DWORD,DWORD*,void*){return FALSE;}
#define WriteFile WriteFile_stub
inline DWORD SetFilePointer_stub(HANDLE,LONG,LONG*,DWORD){return INVALID_SET_FILE_POINTER;}
#define SetFilePointer SetFilePointer_stub
inline BOOL GetFileSizeEx_stub(HANDLE,PLARGE_INTEGER){return FALSE;}
#define GetFileSizeEx GetFileSizeEx_stub
inline BOOL SetEndOfFile_stub(HANDLE){return FALSE;}
#define SetEndOfFile SetEndOfFile_stub
inline BOOL CopyFileW_stub(LPCWSTR,LPCWSTR,BOOL){return FALSE;}
#define CopyFileW CopyFileW_stub
inline HANDLE CreateFileMappingW_stub(HANDLE,void*,DWORD,DWORD,DWORD,LPCWSTR){return nullptr;}
#define CreateFileMappingW CreateFileMappingW_stub
inline LPVOID MapViewOfFile_stub(HANDLE,DWORD,DWORD,DWORD,SIZE_T){return nullptr;}
#define MapViewOfFile MapViewOfFile_stub
inline void GetSystemInfo_stub(LPSYSTEM_INFO si){std::memset(si,0,sizeof(*si));si->dwPageSize=4096;si->dwNumberOfProcessors=1;si->wProcessorArchitecture=9;}
#define GetSystemInfo GetSystemInfo_stub
#define GetNativeSystemInfo GetSystemInfo_stub
inline DWORD QueryDosDeviceW_stub(LPCWSTR,LPWSTR,DWORD){return 0;}
#define QueryDosDeviceW QueryDosDeviceW_stub
inline NTSTATUS RtlGetVersion_stub(PRTL_OSVERSIONINFOW v){std::memset(v,0,sizeof(*v));v->dwOSVersionInfoSize=sizeof(*v);v->dwMajorVersion=6;v->dwMinorVersion=1;v->dwBuildNumber=7601;return 0;}
#define RtlGetVersion RtlGetVersion_stub
inline BOOL OpenProcessToken_stub(HANDLE,DWORD,HANDLE*){return FALSE;}
#define OpenProcessToken OpenProcessToken_stub
inline BOOL LookupPrivilegeValueW_stub(LPCWSTR,LPCWSTR,LPVOID){return FALSE;}
#define LookupPrivilegeValueW LookupPrivilegeValueW_stub
inline BOOL AdjustTokenPrivileges_stub(HANDLE,BOOL,void*,DWORD,void*,DWORD*){return FALSE;}
#define AdjustTokenPrivileges AdjustTokenPrivileges_stub
inline BOOL GetProcessImageFileNameW_stub(HANDLE,WCHAR*,DWORD){return FALSE;}
#define GetProcessImageFileNameW GetProcessImageFileNameW_stub
inline BOOL DuplicateHandle_stub(HANDLE,HANDLE,HANDLE,HANDLE*,DWORD,BOOL,DWORD){return FALSE;}
#define DuplicateHandle DuplicateHandle_stub

#endif // _MSC_VER
