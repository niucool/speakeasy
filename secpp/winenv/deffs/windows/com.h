// com.h  Windows COM interface type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/com.py
//
// COM interfaces are vtable-based — each entry is a Ptr (function pointer).
// These are NOT plain data structs but describe a COM vtable layout.
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::defs::new_structs to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_COM_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_COM_H

#include <cstdint>
#include <string>
#include <cstring>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

#pragma pack(push, 1)

// ==========================================================================================================
// IUnknown vtable: 3 function pointers
// ==========================================================================================================
template <int PtrSize>
struct IUnknown_POD;

template <>
struct IUnknown_POD<4> {
    uint32_t QueryInterface = 0; // offset 0
    uint32_t AddRef         = 0; // offset 4
    uint32_t Release        = 0; // offset 8
    // total = 12
};

template <>
struct IUnknown_POD<8> {
    uint64_t QueryInterface = 0; // offset  0
    uint64_t AddRef         = 0; // offset  8
    uint64_t Release        = 0; // offset 16
    // total = 24
};

template <int PtrSize>
struct IUnknown : public EmuStructHelper<IUnknown<PtrSize>>, public IUnknown_POD<PtrSize> {
    std::string get_mem_tag() const override { return "iunknown"; }
};

// ==========================================================================================================
// IMalloc vtable: IUnknown + 6 function pointers = 9 total
// ==========================================================================================================
template <int PtrSize>
struct IMalloc_POD;

template <>
struct IMalloc_POD<4> {
    uint32_t QueryInterface = 0; // offset  0
    uint32_t AddRef         = 0; // offset  4
    uint32_t Release        = 0; // offset  8
    uint32_t Alloc          = 0; // offset 12
    uint32_t Realloc        = 0; // offset 16
    uint32_t Free           = 0; // offset 20
    uint32_t GetSize        = 0; // offset 24
    uint32_t DidAlloc       = 0; // offset 28
    uint32_t HeapMinimize   = 0; // offset 32
    // total = 36
};

template <>
struct IMalloc_POD<8> {
    uint64_t QueryInterface = 0; // offset  0
    uint64_t AddRef         = 0; // offset  8
    uint64_t Release        = 0; // offset 16
    uint64_t Alloc          = 0; // offset 24
    uint64_t Realloc        = 0; // offset 32
    uint64_t Free           = 0; // offset 40
    uint64_t GetSize        = 0; // offset 48
    uint64_t DidAlloc       = 0; // offset 56
    uint64_t HeapMinimize   = 0; // offset 64
    // total = 72
};

template <int PtrSize>
struct IMalloc : public EmuStructHelper<IMalloc<PtrSize>>, public IMalloc_POD<PtrSize> {
    std::string get_mem_tag() const override { return "imalloc"; }
};

// ==========================================================================================================
// IWbemLocator vtable: IUnknown + 1 function pointer = 4 total
// ==========================================================================================================
template <int PtrSize>
struct IWbemLocator_POD;

template <>
struct IWbemLocator_POD<4> {
    uint32_t QueryInterface = 0; // offset  0
    uint32_t AddRef         = 0; // offset  4
    uint32_t Release        = 0; // offset  8
    uint32_t ConnectServer  = 0; // offset 12
    // total = 16
};

template <>
struct IWbemLocator_POD<8> {
    uint64_t QueryInterface = 0; // offset  0
    uint64_t AddRef         = 0; // offset  8
    uint64_t Release        = 0; // offset 16
    uint64_t ConnectServer  = 0; // offset 24
    // total = 32
};

template <int PtrSize>
struct IWbemLocator : public EmuStructHelper<IWbemLocator<PtrSize>>, public IWbemLocator_POD<PtrSize> {
    std::string get_mem_tag() const override { return "iwbemlocator"; }
};

// ==========================================================================================================
// IWbemServices vtable: IUnknown + 20 function pointers = 23 total
// ==========================================================================================================
template <int PtrSize>
struct IWbemServices_POD;

template <>
struct IWbemServices_POD<4> {
    uint32_t QueryInterface            = 0; // offset  0
    uint32_t AddRef                    = 0; // offset  4
    uint32_t Release                   = 0; // offset  8
    uint32_t OpenNamespace             = 0; // offset 12
    uint32_t CancelAsyncCall           = 0; // offset 16
    uint32_t QueryObjectSink           = 0; // offset 20
    uint32_t GetObject                 = 0; // offset 24
    uint32_t GetObjectAsync            = 0; // offset 28
    uint32_t PutClass                  = 0; // offset 32
    uint32_t PutClassAsync             = 0; // offset 36
    uint32_t DeleteClass               = 0; // offset 40
    uint32_t DeleteClassAsync          = 0; // offset 44
    uint32_t CreateClassEnum           = 0; // offset 48
    uint32_t CreateClassEnumAsync      = 0; // offset 52
    uint32_t PutInstance               = 0; // offset 56
    uint32_t PutInstanceAsync          = 0; // offset 60
    uint32_t DeleteInstance            = 0; // offset 64
    uint32_t DeleteInstanceAsync       = 0; // offset 68
    uint32_t CreateInstanceEnum        = 0; // offset 72
    uint32_t CreateInstanceEnumAsync   = 0; // offset 76
    uint32_t ExecQuery                 = 0; // offset 80
    uint32_t ExecQueryAsync            = 0; // offset 84
    uint32_t ExecNotificationQuery     = 0; // offset 88
    uint32_t ExecNotificationQueryAsync = 0; // offset 92
    uint32_t ExecMethod                = 0; // offset 96
    uint32_t ExecMethodAsync           = 0; // offset 100
    // total = 104
};

template <>
struct IWbemServices_POD<8> {
    uint64_t QueryInterface             = 0; // offset   0
    uint64_t AddRef                     = 0; // offset   8
    uint64_t Release                    = 0; // offset  16
    uint64_t OpenNamespace              = 0; // offset  24
    uint64_t CancelAsyncCall            = 0; // offset  32
    uint64_t QueryObjectSink            = 0; // offset  40
    uint64_t GetObject                  = 0; // offset  48
    uint64_t GetObjectAsync             = 0; // offset  56
    uint64_t PutClass                   = 0; // offset  64
    uint64_t PutClassAsync              = 0; // offset  72
    uint64_t DeleteClass                = 0; // offset  80
    uint64_t DeleteClassAsync           = 0; // offset  88
    uint64_t CreateClassEnum            = 0; // offset  96
    uint64_t CreateClassEnumAsync       = 0; // offset 104
    uint64_t PutInstance                = 0; // offset 112
    uint64_t PutInstanceAsync           = 0; // offset 120
    uint64_t DeleteInstance             = 0; // offset 128
    uint64_t DeleteInstanceAsync        = 0; // offset 136
    uint64_t CreateInstanceEnum         = 0; // offset 144
    uint64_t CreateInstanceEnumAsync    = 0; // offset 152
    uint64_t ExecQuery                  = 0; // offset 160
    uint64_t ExecQueryAsync             = 0; // offset 168
    uint64_t ExecNotificationQuery      = 0; // offset 176
    uint64_t ExecNotificationQueryAsync = 0; // offset 184
    uint64_t ExecMethod                 = 0; // offset 192
    uint64_t ExecMethodAsync            = 0; // offset 200
    // total = 208
};

template <int PtrSize>
struct IWbemServices : public EmuStructHelper<IWbemServices<PtrSize>>, public IWbemServices_POD<PtrSize> {
    std::string get_mem_tag() const override { return "iwbemservices"; }
};

// ==========================================================================================================
// IWbemContext vtable: IUnknown + 9 function pointers = 12 total
// ==========================================================================================================
template <int PtrSize>
struct IWbemContext_POD;

template <>
struct IWbemContext_POD<4> {
    uint32_t QueryInterface    = 0; // offset  0
    uint32_t AddRef            = 0; // offset  4
    uint32_t Release           = 0; // offset  8
    uint32_t Clone             = 0; // offset 12
    uint32_t GetNames          = 0; // offset 16
    uint32_t BeginEnumeration  = 0; // offset 20
    uint32_t Next              = 0; // offset 24
    uint32_t EndEnumeration    = 0; // offset 28
    uint32_t SetValue          = 0; // offset 32
    uint32_t GetValue          = 0; // offset 36
    uint32_t DeleteValue       = 0; // offset 40
    uint32_t DeleteAll         = 0; // offset 44
    // total = 48
};

template <>
struct IWbemContext_POD<8> {
    uint64_t QueryInterface    = 0; // offset  0
    uint64_t AddRef            = 0; // offset  8
    uint64_t Release           = 0; // offset 16
    uint64_t Clone             = 0; // offset 24
    uint64_t GetNames          = 0; // offset 32
    uint64_t BeginEnumeration  = 0; // offset 40
    uint64_t Next              = 0; // offset 48
    uint64_t EndEnumeration    = 0; // offset 56
    uint64_t SetValue          = 0; // offset 64
    uint64_t GetValue          = 0; // offset 72
    uint64_t DeleteValue       = 0; // offset 80
    uint64_t DeleteAll         = 0; // offset 88
    // total = 96
};

template <int PtrSize>
struct IWbemContext : public EmuStructHelper<IWbemContext<PtrSize>>, public IWbemContext_POD<PtrSize> {
    std::string get_mem_tag() const override { return "iwbemcontext"; }
};

// ==========================================================================================================
// ComInterface: simple COM interface wrapper (just a vtable pointer)
// ==========================================================================================================
template <int PtrSize>
struct ComInterface_POD;

template <>
struct ComInterface_POD<4> {
    uint32_t vtable = 0;  // offset 0
    // total = 4
};

template <>
struct ComInterface_POD<8> {
    uint64_t vtable = 0;  // offset 0
    // total = 8
};

template <int PtrSize>
struct ComInterface : public EmuStructHelper<ComInterface<PtrSize>>, public ComInterface_POD<PtrSize> {
    std::string get_mem_tag() const override { return "com_interface"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_COM_H
