// windows.h  Windows core type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/windows.py
//
// Includes: GUID, SID, M128A, EXCEPTION_REGISTRATION, EXCEPTION_POINTERS,
// EH4_SCOPETABLE, EH4_SCOPETABLE_RECORD, EXCEPTION_RECORD, FLOATING_SAVE_AREA,
// CONTEXT, CONTEXT64.
//
// NOTE: KSYSTEM_TIME and UNICODE_STRING are defined in nt/ntoskrnl.h.
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::deffs::windows to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_WINDOWS_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_WINDOWS_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace windows {

#pragma pack(push, 1)

// ==========================================================================================================
// GUID: 16 bytes (u32 + u16 + u16 + u8[8])
// ==========================================================================================================
struct GUID_POD {
    uint32_t Data1     = 0;    // offset 0
    uint16_t Data2     = 0;    // offset 4
    uint16_t Data3     = 0;    // offset 6
    uint8_t  Data4[8]  = {};   // offset 8
    // total = 16
};
struct GUID : public EmuStructHelper<GUID>, public GUID_POD {
    std::string get_mem_tag() const override { return "guid"; }
};

// ==========================================================================================================
// SID: variable-length (fixed header + variable SubAuthority)
// Fixed header: Revision(1)+SubAuthorityCount(1)+IdentifierAuthority(6) = 8 bytes
// Then SubAuthority[count] of uint32.
// ==========================================================================================================
struct SID_POD {
    uint8_t  Revision             = 0;   // offset 0
    uint8_t  SubAuthorityCount    = 0;   // offset 1
    uint8_t  IdentifierAuthority[6] = {};// offset 2
    uint32_t SubAuthority         = 0;   // offset 8 → minimum 1 DWORD
    // Followed by more SubAuthority[SubAuthorityCount-1] of uint32 (variable)
    // Fixed header total = 12 (minimum SID size with 1 SubAuthority)
};
struct SID : public EmuStructHelper<SID>, public SID_POD {
    std::string get_mem_tag() const override { return "sid"; }
};

// ==========================================================================================================
// M128A: 16 bytes (uint64 Low, uint64 High)
// ==========================================================================================================
struct M128A_POD {
    uint64_t Low  = 0;    // offset 0
    uint64_t High = 0;    // offset 8
    // total = 16
};
struct M128A : public EmuStructHelper<M128A>, public M128A_POD {
    std::string get_mem_tag() const override { return "m128a"; }
};

// ==========================================================================================================
// EXCEPTION_REGISTRATION: ptr-size polymorphic (4*Ptr)
// x86: 4*u32 = 16
// x64: 4*u64 = 32
// ==========================================================================================================
template <int PtrSize>
struct EXCEPTION_REGISTRATION_POD;

template <>
struct EXCEPTION_REGISTRATION_POD<4> {
    uint32_t Next       = 0;    // offset 0
    uint32_t Handler    = 0;    // offset 4
    uint32_t ScopeTable = 0;    // offset 8
    uint32_t TryLevel   = 0;    // offset 12
    // total = 16
};

template <>
struct EXCEPTION_REGISTRATION_POD<8> {
    uint64_t Next       = 0;    // offset 0
    uint64_t Handler    = 0;    // offset 8
    uint64_t ScopeTable = 0;    // offset 16
    uint64_t TryLevel   = 0;    // offset 24
    // total = 32
};

template <int PtrSize>
struct EXCEPTION_REGISTRATION : public EmuStructHelper<EXCEPTION_REGISTRATION<PtrSize>>, public EXCEPTION_REGISTRATION_POD<PtrSize> {
    std::string get_mem_tag() const override { return "exception_registration"; }
};

// ==========================================================================================================
// EXCEPTION_POINTERS: ptr-size polymorphic (2*Ptr)
// x86: 2*u32 = 8
// x64: 2*u64 = 16
// ==========================================================================================================
template <int PtrSize>
struct EXCEPTION_POINTERS_POD;

template <>
struct EXCEPTION_POINTERS_POD<4> {
    uint32_t ExceptionRecord = 0;    // offset 0
    uint32_t ContextRecord   = 0;    // offset 4
    // total = 8
};

template <>
struct EXCEPTION_POINTERS_POD<8> {
    uint64_t ExceptionRecord = 0;    // offset 0
    uint64_t ContextRecord   = 0;    // offset 8
    // total = 16
};

template <int PtrSize>
struct EXCEPTION_POINTERS : public EmuStructHelper<EXCEPTION_POINTERS<PtrSize>>, public EXCEPTION_POINTERS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "exception_pointers"; }
};

// ==========================================================================================================
// EH4_SCOPETABLE: fixed-size, 16 bytes (4*uint32)
// ==========================================================================================================
struct EH4_SCOPETABLE_POD {
    uint32_t GSCookieOffset    = 0;    // offset 0
    uint32_t GSCookieXOROffset = 0;    // offset 4
    uint32_t EHCookieOffset    = 0;    // offset 8
    uint32_t EHCookieXOROffset = 0;    // offset 12
    // total = 16
};
struct EH4_SCOPETABLE : public EmuStructHelper<EH4_SCOPETABLE>, public EH4_SCOPETABLE_POD {
    std::string get_mem_tag() const override { return "eh4_scopetable"; }
};

// ==========================================================================================================
// EH4_SCOPETABLE_RECORD: ptr-size polymorphic
// x86: EnclosingLevel(4)+FilterFunc(4)+HandlerAddress(4) = 12
// x64: EnclosingLevel(4)+pad(4)+FilterFunc(8)+HandlerAddress(8) = 24
// ==========================================================================================================
template <int PtrSize>
struct EH4_SCOPETABLE_RECORD_POD;

template <>
struct EH4_SCOPETABLE_RECORD_POD<4> {
    uint32_t EnclosingLevel  = 0;    // offset 0
    uint32_t FilterFunc      = 0;    // offset 4
    uint32_t HandlerAddress  = 0;    // offset 8
    // total = 12
};

template <>
struct EH4_SCOPETABLE_RECORD_POD<8> {
    uint32_t EnclosingLevel  = 0;    // offset 0
    uint32_t pad1            = 0;    // offset 4 → align FilterFunc
    uint64_t FilterFunc      = 0;    // offset 8
    uint64_t HandlerAddress  = 0;    // offset 16
    // total = 24
};

template <int PtrSize>
struct EH4_SCOPETABLE_RECORD : public EmuStructHelper<EH4_SCOPETABLE_RECORD<PtrSize>>, public EH4_SCOPETABLE_RECORD_POD<PtrSize> {
    std::string get_mem_tag() const override { return "eh4_scopetable_record"; }
};

// ==========================================================================================================
// EXCEPTION_RECORD: ptr-size polymorphic
// x86: ExceptionCode(4)+ExceptionFlags(4)+ExceptionRecord(4)+ExceptionAddress(4)
//      +NumberParameters(4)+ExceptionInformation(15*u32=60) = 80
// x64: ExceptionCode(4)+ExceptionFlags(4)+ExceptionRecord(8)+ExceptionAddress(8)
//      +NumberParameters(4)+pad(4)+ExceptionInformation(15*u64=120) = 152
// ==========================================================================================================
template <int PtrSize>
struct EXCEPTION_RECORD_POD;

template <>
struct EXCEPTION_RECORD_POD<4> {
    uint32_t ExceptionCode          = 0;   // offset  0
    uint32_t ExceptionFlags         = 0;   // offset  4
    uint32_t ExceptionRecord        = 0;   // offset  8
    uint32_t ExceptionAddress       = 0;   // offset 12
    uint32_t NumberParameters       = 0;   // offset 16
    uint32_t ExceptionInformation[15] = {};// offset 20 (60 bytes)
    // total = 80
};

template <>
struct EXCEPTION_RECORD_POD<8> {
    uint32_t ExceptionCode          = 0;   // offset  0
    uint32_t ExceptionFlags         = 0;   // offset  4
    uint64_t ExceptionRecord        = 0;   // offset  8 (8-aligned ✓)
    uint64_t ExceptionAddress       = 0;   // offset 16
    uint32_t NumberParameters       = 0;   // offset 24
    uint32_t pad1                   = 0;   // offset 28 → align ExceptionInformation to 8
    uint64_t ExceptionInformation[15] = {};// offset 32 (120 bytes)
    // total = 152
};

template <int PtrSize>
struct EXCEPTION_RECORD : public EmuStructHelper<EXCEPTION_RECORD<PtrSize>>, public EXCEPTION_RECORD_POD<PtrSize> {
    std::string get_mem_tag() const override { return "exception_record"; }
};

// ==========================================================================================================
// FLOATING_SAVE_AREA: fixed-size, 112 bytes
// 7*uint32(28) + u8[80] + uint32(4) = 112
// ==========================================================================================================
struct FLOATING_SAVE_AREA_POD {
    uint32_t ControlWord    = 0;    // offset   0
    uint32_t StatusWord     = 0;    // offset   4
    uint32_t TagWord        = 0;    // offset   8
    uint32_t ErrorOffset    = 0;    // offset  12
    uint32_t ErrorSelector  = 0;    // offset  16
    uint32_t DataOffset     = 0;    // offset  20
    uint32_t DataSelector   = 0;    // offset  24
    uint8_t  RegisterArea[80] = {}; // offset  28
    uint32_t Spare0         = 0;    // offset 108
    // total = 112
};
struct FLOATING_SAVE_AREA : public EmuStructHelper<FLOATING_SAVE_AREA>, public FLOATING_SAVE_AREA_POD {
    std::string get_mem_tag() const override { return "floating_save_area"; }
};

// ==========================================================================================================
// CONTEXT (x86): 204 bytes
// ContextFlags(4)+Dr0(4)+Dr1(4)+Dr2(4)+Dr3(4)+Dr6(4)+Dr7(4) = 28
// + FloatSave(FLOATING_SAVE_AREA=112) = 140
// + SegGs(4)+SegFs(4)+SegEs(4)+SegDs(4) = 156
// + Edi(4)+Esi(4)+Ebx(4)+Edx(4)+Ecx(4)+Eax(4)+Ebp(4)+Eip(4) = 188
// + SegCs(4)+EFlags(4)+Esp(4)+SegSs(4) = 204
// ==========================================================================================================
struct CONTEXT_POD {
    uint32_t ContextFlags    = 0;    // offset   0
    uint32_t Dr0             = 0;    // offset   4
    uint32_t Dr1             = 0;    // offset   8
    uint32_t Dr2             = 0;    // offset  12
    uint32_t Dr3             = 0;    // offset  16
    uint32_t Dr6             = 0;    // offset  20
    uint32_t Dr7             = 0;    // offset  24
    FLOATING_SAVE_AREA_POD FloatSave;    // offset  28 (nested, size=112)
    uint32_t SegGs             = 0;    // offset 140
    uint32_t SegFs             = 0;    // offset 144
    uint32_t SegEs             = 0;    // offset 148
    uint32_t SegDs             = 0;    // offset 152
    uint32_t Edi               = 0;    // offset 156
    uint32_t Esi               = 0;    // offset 160
    uint32_t Ebx               = 0;    // offset 164
    uint32_t Edx               = 0;    // offset 168
    uint32_t Ecx               = 0;    // offset 172
    uint32_t Eax               = 0;    // offset 176
    uint32_t Ebp               = 0;    // offset 180
    uint32_t Eip               = 0;    // offset 184
    uint32_t SegCs             = 0;    // offset 188
    uint32_t EFlags            = 0;    // offset 192
    uint32_t Esp               = 0;    // offset 196
    uint32_t SegSs             = 0;    // offset 200
    // total = 204
};
struct CONTEXT : public EmuStructHelper<CONTEXT>, public CONTEXT_POD {
    std::string get_mem_tag() const override { return "context"; }
};

// ==========================================================================================================
// CONTEXT64 (x64): 1160 bytes
// P1Home-P6Home: 6*u64(48) + ContextFlags(u32=4) + MxCsr(u32=4) + SegCs-SegSs(6*u16=12)
// + pad(4) + EFlags(u64=8) + Dr0-Dr7(8*u64=64) + Rax-R15+Rip(17*u64=136)
// + Header(M128A[2]=32) + Legacy(M128A[8]=128) + Xmm0-Xmm15(M128A[16]=256)
// + VectorRegister(M128A[26]=416) + VectorControl(u64=8) + DebugControl(u64=8)
// + LastBranchToRip(u64=8) + LastBranchFromRip(u64=8)
// + LastExceptionToRip(u64=8) + LastExceptionFromRip(u64=8)
// ==========================================================================================================
struct CONTEXT64_POD {
    // P1Home-P6Home: 6*u64
    // P1Home-P6Home: 6*u64
    uint64_t P1Home = 0;     // offset   0
    uint64_t P2Home = 0;     // offset   8
    uint64_t P3Home = 0;     // offset  16
    uint64_t P4Home = 0;     // offset  24
    uint64_t P5Home = 0;     // offset  32
    uint64_t P6Home = 0;     // offset  40
    uint32_t ContextFlags = 0; // offset  48
    uint32_t MxCsr        = 0; // offset  52
    uint16_t SegCs = 0;    // offset  56
    uint16_t SegDs = 0;    // offset  58
    uint16_t SegEs = 0;    // offset  60
    uint16_t SegFs = 0;    // offset  62
    uint16_t SegGs = 0;    // offset  64
    uint16_t SegSs = 0;    // offset  66
    uint8_t  _pad_eflags[4] = {}; // offset  68 → align EFlags to 72
    uint64_t EFlags = 0;   // offset  72
    uint64_t Dr0    = 0;   // offset  80
    uint64_t Dr1    = 0;   // offset  88
    uint64_t Dr2    = 0;   // offset  96
    uint64_t Dr3    = 0;   // offset 104
    uint64_t Dr6    = 0;   // offset 112
    uint64_t Dr7    = 0;   // offset 120
    uint64_t Rax = 0;      // offset 128
    uint64_t Rcx = 0;      // offset 136
    uint64_t Rdx = 0;      // offset 144
    uint64_t Rbx = 0;      // offset 152
    uint64_t Rsp = 0;      // offset 160
    uint64_t Rbp = 0;      // offset 168
    uint64_t Rsi = 0;      // offset 176
    uint64_t Rdi = 0;      // offset 184
    uint64_t R8  = 0;      // offset 192
    uint64_t R9  = 0;      // offset 200
    uint64_t R10 = 0;      // offset 208
    uint64_t R11 = 0;      // offset 216
    uint64_t R12 = 0;      // offset 224
    uint64_t R13 = 0;      // offset 232
    uint64_t R14 = 0;      // offset 240
    uint64_t R15 = 0;      // offset 248
    uint64_t Rip = 0;      // offset 256
    // Header: M128A[2] = 32 bytes → offset 264
    M128A_POD Header[2];   // offset 264
    // Legacy: M128A[8] = 128 bytes → offset 296
    M128A_POD Legacy[8];   // offset 296
    // Xmm0-Xmm15: M128A[16] = 256 bytes → offset 424
    M128A_POD Xmm0;        // offset 424
    M128A_POD Xmm1;        // offset 440
    M128A_POD Xmm2;        // offset 456
    M128A_POD Xmm3;        // offset 472
    M128A_POD Xmm4;        // offset 488
    M128A_POD Xmm5;        // offset 504
    M128A_POD Xmm6;        // offset 520
    M128A_POD Xmm7;        // offset 536
    M128A_POD Xmm8;        // offset 552
    M128A_POD Xmm9;        // offset 568
    M128A_POD Xmm10;       // offset 584
    M128A_POD Xmm11;       // offset 600
    M128A_POD Xmm12;       // offset 616
    M128A_POD Xmm13;       // offset 632
    M128A_POD Xmm14;       // offset 648
    M128A_POD Xmm15;       // offset 664
    // VectorRegister: M128A[26] = 416 bytes → offset 680
    M128A_POD VectorRegister[26]; // offset 680
    // Remaining u64 fields
    uint64_t VectorControl        = 0; // offset 1096
    uint64_t DebugControl         = 0; // offset 1104
    uint64_t LastBranchToRip      = 0; // offset 1112
    uint64_t LastBranchFromRip    = 0; // offset 1120
    uint64_t LastExceptionToRip   = 0; // offset 1128
    uint64_t LastExceptionFromRip = 0; // offset 1136
    // total = 1144
    // Hmm, let me verify:
    // 0-48: P1-P6 = 48 bytes ✓
    // 48-52: ContextFlags(4) ✓
    // 52-56: MxCsr(4) ✓
    // 56-68: SegCs-SegSs(6*u16=12) = 56→68 ✓
    // 68-72: pad(4) ✓
    // 72-80: EFlags(8) ✓
    // 80-128: Dr0-Dr7(6*u64=48) ✓
    // 128-264: Rax-Rip(17*u64=136) ✓
    // 264-296: Header[2](32) ✓
    // 296-424: Legacy[8](128) ✓
    // 424-680: Xmm0-Xmm15(16*16=256) ✓
    // 680-1096: VectorRegister[26](26*16=416) ✓
    // 1096-1144: 6*u64(48) ✓
    // total = 1144
};

struct CONTEXT64 : public EmuStructHelper<CONTEXT64>, public CONTEXT64_POD {
    std::string get_mem_tag() const override { return "context64"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::windows

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_WINDOWS_H
