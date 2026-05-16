// com.h — COM interface type definitions
//
// Maps to: speakeasy/winenv/defs/windows/com.py
//
// COM interface vtables and GUID constants for WMI and other
// COM-based emulation.

#ifndef SPEAKEASY_DEFS_WINDOWS_COM_H
#define SPEAKEASY_DEFS_WINDOWS_COM_H

#include <cstdint>
#include <vector>
#include "windef.h"
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── HRESULT constants ─────────────────────────────────────────

constexpr int32_t S_OK                      = 0;
constexpr int32_t S_FALSE                   = 1;
constexpr int32_t E_NOTIMPL                 = 0x80004001;
constexpr int32_t E_NOINTERFACE             = 0x80004002;
constexpr int32_t E_POINTER                 = 0x80004003;
constexpr int32_t E_FAIL                    = 0x80004005;
constexpr int32_t E_OUTOFMEMORY             = 0x8007000E;
constexpr int32_t E_INVALIDARG              = 0x80070057;

// ── RPC authentication level constants ────────────────────────

constexpr uint32_t RPC_C_AUTHN_LEVEL_DEFAULT         = 0;
constexpr uint32_t RPC_C_AUTHN_LEVEL_NONE            = 1;
constexpr uint32_t RPC_C_AUTHN_LEVEL_CONNECT         = 2;
constexpr uint32_t RPC_C_AUTHN_LEVEL_CALL            = 3;
constexpr uint32_t RPC_C_AUTHN_LEVEL_PKT             = 4;
constexpr uint32_t RPC_C_AUTHN_LEVEL_PKT_INTEGRITY   = 5;
constexpr uint32_t RPC_C_AUTHN_LEVEL_PKT_PRIVACY     = 6;

// ── RPC impersonation level constants ─────────────────────────

constexpr uint32_t RPC_C_IMP_LEVEL_DEFAULT     = 0;
constexpr uint32_t RPC_C_IMP_LEVEL_ANONYMOUS   = 1;
constexpr uint32_t RPC_C_IMP_LEVEL_IDENTIFY    = 2;
constexpr uint32_t RPC_C_IMP_LEVEL_IMPERSONATE = 3;
constexpr uint32_t RPC_C_IMP_LEVEL_DELEGATE    = 4;

// ── CLSID / IID constants ─────────────────────────────────────

// CLSID_WbemLocator = "{4590F811-1D3A-11D0-891F-00AA004B2E24}"
constexpr GUID CLSID_WbemLocator = {
    0x4590F811, 0x1D3A, 0x11D0,
    {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

// CLSID_IWbemContext = "{674B6698-EE92-11D0-AD71-00C04FD8FDFF}"
constexpr GUID CLSID_IWbemContext = {
    0x674B6698, 0xEE92, 0x11D0,
    {0xAD, 0x71, 0x00, 0xC0, 0x4F, 0xD8, 0xFD, 0xFF}
};

// IID_IWbemLocator = "{DC12A687-737F-11CF-884D-00AA004B2E24}"
constexpr GUID IID_IWbemLocator = {
    0xDC12A687, 0x737F, 0x11CF,
    {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

// IID_IWbemContext = "{44ACA674-E8FC-11D0-A07C-00C04FB68820}"
constexpr GUID IID_IWbemContext = {
    0x44ACA674, 0xE8FC, 0x11D0,
    {0xA0, 0x7C, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20}
};

// ── COM interface vtable structures ───────────────────────────

// All COM interface vtables are arrays of function pointers (uint64_t on x64,
// uint32_t on x86).  We model them as structures whose fields are pointer-sized.

struct IUnknownVtbl : speakeasy::EmuStruct {
    uint64_t QueryInterface = 0;  // HRESULT (IID*, void**)
    uint64_t AddRef         = 0;  // ULONG ()
    uint64_t Release        = 0;  // ULONG ()

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 24 : 12;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        speakeasy::write_le(b, 0,  QueryInterface, p);
        speakeasy::write_le(b, p,  AddRef, p);
        speakeasy::write_le(b, p*2, Release, p);
        return b;
    }
};

struct IMallocVtbl : speakeasy::EmuStruct {
    IUnknownVtbl IUnknown;
    uint64_t Alloc        = 0;  // void* (size_t)
    uint64_t Realloc      = 0;  // void* (void*, size_t)
    uint64_t Free         = 0;  // void (void*)
    uint64_t GetSize      = 0;  // size_t (void*)
    uint64_t DidAlloc     = 0;  // int (void*)
    uint64_t HeapMinimize = 0;  // void ()

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 72 : 36;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        auto iunk = IUnknown.get_bytes();
        std::copy(iunk.begin(), iunk.end(), b.begin());
        speakeasy::write_le(b, p*3, Alloc, p);
        speakeasy::write_le(b, p*4, Realloc, p);
        speakeasy::write_le(b, p*5, Free, p);
        speakeasy::write_le(b, p*6, GetSize, p);
        speakeasy::write_le(b, p*7, DidAlloc, p);
        speakeasy::write_le(b, p*8, HeapMinimize, p);
        return b;
    }
};

struct IWbemLocatorVtbl : speakeasy::EmuStruct {
    IUnknownVtbl IUnknown;
    uint64_t ConnectServer = 0;

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 32 : 16;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        auto iunk = IUnknown.get_bytes();
        std::copy(iunk.begin(), iunk.end(), b.begin());
        speakeasy::write_le(b, p*3, ConnectServer, p);
        return b;
    }
};

struct IWbemServicesVtbl : speakeasy::EmuStruct {
    IUnknownVtbl IUnknown;
    uint64_t OpenNamespace             = 0;
    uint64_t CancelAsyncCall           = 0;
    uint64_t QueryObjectSink           = 0;
    uint64_t GetObject                 = 0;
    uint64_t GetObjectAsync            = 0;
    uint64_t PutClass                  = 0;
    uint64_t PutClassAsync             = 0;
    uint64_t DeleteClass               = 0;
    uint64_t DeleteClassAsync          = 0;
    uint64_t CreateClassEnum           = 0;
    uint64_t CreateClassEnumAsync      = 0;
    uint64_t PutInstance               = 0;
    uint64_t PutInstanceAsync          = 0;
    uint64_t DeleteInstance            = 0;
    uint64_t DeleteInstanceAsync       = 0;
    uint64_t CreateInstanceEnum        = 0;
    uint64_t CreateInstanceEnumAsync   = 0;
    uint64_t ExecQuery                 = 0;
    uint64_t ExecQueryAsync            = 0;
    uint64_t ExecNotificationQuery     = 0;
    uint64_t ExecNotificationQueryAsync = 0;
    uint64_t ExecMethod                = 0;
    uint64_t ExecMethodAsync           = 0;

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 200 : 100;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        auto iunk = IUnknown.get_bytes();
        std::copy(iunk.begin(), iunk.end(), b.begin());
        for (size_t i = 0; i < 22; ++i) {
            uint64_t vtable_entry = 0;
            switch (i) {
                case 0:  vtable_entry = OpenNamespace; break;
                case 1:  vtable_entry = CancelAsyncCall; break;
                case 2:  vtable_entry = QueryObjectSink; break;
                case 3:  vtable_entry = GetObject; break;
                case 4:  vtable_entry = GetObjectAsync; break;
                case 5:  vtable_entry = PutClass; break;
                case 6:  vtable_entry = PutClassAsync; break;
                case 7:  vtable_entry = DeleteClass; break;
                case 8:  vtable_entry = DeleteClassAsync; break;
                case 9:  vtable_entry = CreateClassEnum; break;
                case 10: vtable_entry = CreateClassEnumAsync; break;
                case 11: vtable_entry = PutInstance; break;
                case 12: vtable_entry = PutInstanceAsync; break;
                case 13: vtable_entry = DeleteInstance; break;
                case 14: vtable_entry = DeleteInstanceAsync; break;
                case 15: vtable_entry = CreateInstanceEnum; break;
                case 16: vtable_entry = CreateInstanceEnumAsync; break;
                case 17: vtable_entry = ExecQuery; break;
                case 18: vtable_entry = ExecQueryAsync; break;
                case 19: vtable_entry = ExecNotificationQuery; break;
                case 20: vtable_entry = ExecNotificationQueryAsync; break;
                case 21: vtable_entry = ExecMethod; break;
                case 22: vtable_entry = ExecMethodAsync; break;
            }
            speakeasy::write_le(b, p * (3 + i), vtable_entry, p);
        }
        return b;
    }
};

struct IWbemContextVtbl : speakeasy::EmuStruct {
    IUnknownVtbl IUnknown;
    uint64_t Clone              = 0;
    uint64_t GetNames           = 0;
    uint64_t BeginEnumeration   = 0;
    uint64_t Next               = 0;
    uint64_t EndEnumeration     = 0;
    uint64_t SetValue           = 0;
    uint64_t GetValue           = 0;
    uint64_t DeleteValue        = 0;
    uint64_t DeleteAll          = 0;

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 104 : 52;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        auto iunk = IUnknown.get_bytes();
        std::copy(iunk.begin(), iunk.end(), b.begin());
        speakeasy::write_le(b, p*3,  Clone, p);
        speakeasy::write_le(b, p*4,  GetNames, p);
        speakeasy::write_le(b, p*5,  BeginEnumeration, p);
        speakeasy::write_le(b, p*6,  Next, p);
        speakeasy::write_le(b, p*7,  EndEnumeration, p);
        speakeasy::write_le(b, p*8,  SetValue, p);
        speakeasy::write_le(b, p*9,  GetValue, p);
        speakeasy::write_le(b, p*10, DeleteValue, p);
        speakeasy::write_le(b, p*11, DeleteAll, p);
        return b;
    }
};

// ── COM interface wrapper ─────────────────────────────────────

struct ComInterface : speakeasy::EmuStruct {
    uint64_t vtable = 0;  // Ptr to vtable in emulated memory

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 8 : 4;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, vtable, sz);
        return b;
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_WINDOWS_COM_H
