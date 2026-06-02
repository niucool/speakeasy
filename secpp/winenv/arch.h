// arch.h
#ifndef SPEAKEASY_ARCH_H
#define SPEAKEASY_ARCH_H

#include <cstdint>
#include <string>
#include <unordered_map>

namespace speakeasy { namespace arch {

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
//const int REG_CS = 1001;
//const int REG_DS = 1002;
const int REG_EAX = 1003;
const int REG_EBP = 1004;
const int REG_EBX = 1005;
const int REG_ECX = 1006;
const int REG_EDI = 1007;
const int REG_EDX = 1008;
const int REG_EFLAGS = 1009;
const int REG_EIP = 1010;
const int REG_EIZ = 1011;
const int REG_ESI = 1012;
const int REG_ESP = 1013;
const int REG_FS = 1014;
const int REG_GS = 1015;
const int REG_ES = 1016;
const int REG_SS = 1017;
const int REG_CS = 1018;
const int REG_DS = 1019;
const int REG_MSR = 1020;

// AMD64 Registers
const int REG_RAX = 1021;
const int REG_RBP = 1022;
const int REG_RBX = 1023;
const int REG_RCX = 1024;
const int REG_RDI = 1025;
const int REG_RDX = 1026;
const int REG_RIP = 1027;
const int REG_RIZ = 1028;
const int REG_RSI = 1029;
const int REG_RSP = 1030;
const int REG_SIL = 1031;
const int REG_DIL = 1032;
const int REG_BPL = 1033;
const int REG_SPL = 1034;
const int REG_R8 = 1035;
const int REG_R9 = 1036;
const int REG_R10 = 1037;
const int REG_R11 = 1038;
const int REG_R12 = 1039;
const int REG_R13 = 1040;
const int REG_R14 = 1041;
const int REG_R15 = 1042;

// Control Registers
const int REG_CR0 = 1043;
const int REG_CR1 = 1044;
const int REG_CR2 = 1045;
const int REG_CR3 = 1046;
const int REG_CR4 = 1047;
const int REG_CR5 = 1048;
const int REG_CR6 = 1049;
const int REG_CR7 = 1050;
const int REG_CR8 = 1051;

// Debug registers
const int REG_DR0 = 1052;
const int REG_DR1 = 1053;
const int REG_DR2 = 1054;
const int REG_DR3 = 1055;
const int REG_DR4 = 1056;
const int REG_DR5 = 1057;
const int REG_DR6 = 1058;
const int REG_DR7 = 1059;
const int REG_DR8 = 1060;

const int REG_IDTR = 1061;
const int REG_GDTR = 1062;
const int REG_XMM0 = 1063;
const int REG_XMM1 = 1064;
const int REG_XMM2 = 1065;
const int REG_XMM3 = 1066;
const int REG_XMM4 = 1067;

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
    {"eax", REG_EAX}, {"ebx", REG_EBX}, {"ecx", REG_ECX}, {"edx", REG_EDX},
    {"edi", REG_EDI}, {"esi", REG_ESI}, {"ebp", REG_EBP}, {"esp", REG_ESP},
    {"eip", REG_EIP}, {"eflags", REG_EFLAGS},
    {"rax", REG_RAX}, {"rbx", REG_RBX}, {"rcx", REG_RCX}, {"rdx", REG_RDX},
    {"rdi", REG_RDI}, {"rsi", REG_RSI}, {"rsp", REG_RSP}, {"rbp", REG_RBP},
    {"r8", REG_R8}, {"r9", REG_R9}, {"r10", REG_R10}, {"r11", REG_R11},
    {"r12", REG_R12}, {"r13", REG_R13}, {"r14", REG_R14}, {"r15", REG_R15},
    {"rip", REG_RIP}
};

}} // namespace speakeasy::arch

#endif
