// arch.h
#ifndef SPEAKEASY_ARCH_H
#define SPEAKEASY_ARCH_H

#include <cstdint>
#include <string>
#include <unordered_map>

// Architecture types
const int ARCH_X86 = 32;
const int ARCH_AMD64 = 64;

// Memory constants
const uint32_t PAGE_SIZE = 0x1000;
const int BITS_32 = 32;
const int BITS_64 = 64;

// Model Specific Registers
const uint32_t LSTAR = 0xC0000082;

// x86 Registers
const int X86_REG_CS = 1001;
const int X86_REG_DS = 1002;
const int X86_REG_EAX = 1003;
const int X86_REG_EBP = 1004;
const int X86_REG_EBX = 1005;
const int X86_REG_ECX = 1006;
const int X86_REG_EDI = 1007;
const int X86_REG_EDX = 1008;
const int X86_REG_EFLAGS = 1009;
const int X86_REG_EIP = 1010;
const int X86_REG_EIZ = 1011;
const int X86_REG_ESI = 1012;
const int X86_REG_ESP = 1013;

// Segment registers
const int X86_REG_FS = 1014;
const int X86_REG_GS = 1015;
const int X86_REG_ES = 1016;
const int X86_REG_SS = 1017;
// Note: Duplicate values in original Python, keeping them for compatibility
const int X86_REG_CS_ALT = 1018;
const int X86_REG_DS_ALT = 1019;

const int X86_REG_MSR = 1020;

// AMD64 Registers
const int AMD64_REG_RAX = 1021;
const int AMD64_REG_RBP = 1022;
const int AMD64_REG_RBX = 1023;
const int AMD64_REG_RCX = 1024;
const int AMD64_REG_RDI = 1025;
const int AMD64_REG_RDX = 1026;
const int AMD64_REG_RIP = 1027;
const int AMD64_REG_RIZ = 1028;
const int AMD64_REG_RSI = 1029;
const int AMD64_REG_RSP = 1030;
const int AMD64_REG_SIL = 1031;
const int AMD64_REG_DIL = 1032;
const int AMD64_REG_BPL = 1033;
const int AMD64_REG_SPL = 1034;
const int AMD64_REG_R8 = 1035;
const int AMD64_REG_R9 = 1036;
const int AMD64_REG_R10 = 1037;
const int AMD64_REG_R11 = 1038;
const int AMD64_REG_R12 = 1039;
const int AMD64_REG_R13 = 1040;
const int AMD64_REG_R14 = 1041;
const int AMD64_REG_R15 = 1042;

// Control Registers
const int X86_REG_CR0 = 1043;
const int X86_REG_CR1 = 1044;
const int X86_REG_CR2 = 1045;
const int X86_REG_CR3 = 1046;
const int X86_REG_CR4 = 1047;
const int X86_REG_CR5 = 1048;
const int X86_REG_CR6 = 1049;
const int X86_REG_CR7 = 1050;
const int X86_REG_CR8 = 1051;

// Debug registers
const int X86_REG_DR0 = 1052;
const int X86_REG_DR1 = 1053;
const int X86_REG_DR2 = 1054;
const int X86_REG_DR3 = 1055;
const int X86_REG_DR4 = 1056;
const int X86_REG_DR5 = 1057;
const int X86_REG_DR6 = 1058;
const int X86_REG_DR7 = 1059;
const int X86_REG_DR8 = 1060;

// Descriptor Table Registers
const int X86_REG_IDTR = 1061;
const int X86_REG_GDTR = 1062;

// XMM Registers
const int X86_REG_XMM0 = 1063;
const int X86_REG_XMM1 = 1064;
const int X86_REG_XMM2 = 1065;
const int X86_REG_XMM3 = 1066;
const int X86_REG_XMM4 = 1067;

// Calling conventions
const int CALL_CONV_CDECL = 0;
const int CALL_CONV_STDCALL = 1;
const int CALL_CONV_FASTCALL = 2;
const int CALL_CONV_FLOAT = 3;
const int VAR_ARGS = -1;

/**
 * Register lookup map that maps register name strings to their corresponding constants
 */
const std::unordered_map<std::string, int> REG_LOOKUP = {
    // x86 registers
    {"eax", X86_REG_EAX}, {"ebx", X86_REG_EBX}, {"ecx", X86_REG_ECX}, {"edx", X86_REG_EDX},
    {"edi", X86_REG_EDI}, {"esi", X86_REG_ESI}, {"ebp", X86_REG_EBP}, {"esp", X86_REG_ESP},
    {"eip", X86_REG_EIP}, {"eflags", X86_REG_EFLAGS},
    
    // amd64 registers
    {"rax", AMD64_REG_RAX}, {"rbx", AMD64_REG_RBX}, {"rcx", AMD64_REG_RCX}, {"rdx", AMD64_REG_RDX},
    {"rdi", AMD64_REG_RDI}, {"rsi", AMD64_REG_RSI}, {"rsp", AMD64_REG_RSP}, {"rbp", AMD64_REG_RBP},
    {"r8", AMD64_REG_R8}, {"r9", AMD64_REG_R9}, {"r10", AMD64_REG_R10}, {"r11", AMD64_REG_R11},
    {"r12", AMD64_REG_R12}, {"r13", AMD64_REG_R13}, {"r14", AMD64_REG_R14}, {"r15", AMD64_REG_R15},
    {"rip", AMD64_REG_RIP}
};

#endif // SPEAKEASY_ARCH_H