// ddk.h  Windows Driver Development Kit constants
//
// Maps to: speakeasy/winenv/defs/nt/ddk.py
//
// NT status codes, IRP major function codes, IRQL levels, and
// device flags used throughout the kernel emulation.

#ifndef SPEAKEASY_DEFS_NT_DDK_H
#define SPEAKEASY_DEFS_NT_DDK_H

#include <cstdint>

//  IRQL Levels 

constexpr uint32_t PASSIVE_LEVEL  = 0;
constexpr uint32_t LOW_LEVEL      = 0;
constexpr uint32_t APC_LEVEL      = 1;
constexpr uint32_t DISPATCH_LEVEL = 2;
constexpr uint32_t CMCI_LEVEL     = 5;
constexpr uint32_t PROFILE_LEVEL  = 27;
constexpr uint32_t CLOCK1_LEVEL   = 28;
constexpr uint32_t CLOCK2_LEVEL   = 28;
constexpr uint32_t IPI_LEVEL      = 29;
constexpr uint32_t POWER_LEVEL    = 30;
constexpr uint32_t HIGH_LEVEL     = 31;

//  NT Status Codes 

constexpr uint32_t STATUS_SUCCESS                   = 0x00000000;
constexpr uint32_t STATUS_BREAKPOINT                = 0x80000003;
constexpr uint32_t STATUS_SINGLE_STEP               = 0x80000004;
constexpr uint32_t STATUS_UNSUCCESSFUL              = 0xC0000001;
constexpr uint32_t STATUS_INFO_LENGTH_MISMATCH      = 0xC0000004;
constexpr uint32_t STATUS_ACCESS_VIOLATION          = 0xC0000005;
constexpr uint32_t STATUS_INVALID_HANDLE            = 0xC0000008;
constexpr uint32_t STATUS_INVALID_CID               = 0xC000000B;
constexpr uint32_t STATUS_INVALID_PARAMETER         = 0xC000000D;
constexpr uint32_t STATUS_INTEGER_DIVIDE_BY_ZERO    = 0xC0000094;
constexpr uint32_t STATUS_ILLEGAL_INSTRUCTION        = 0xC000001D;
constexpr uint32_t STATUS_BUFFER_TOO_SMALL          = 0xC0000023;
constexpr uint32_t STATUS_OBJECT_TYPE_MISMATCH      = 0xC0000024;
constexpr uint32_t STATUS_OBJECT_NAME_NOT_FOUND     = 0xC0000034;
constexpr uint32_t STATUS_PROCEDURE_NOT_FOUND       = 0xC000007A;
constexpr uint32_t STATUS_RESOURCE_DATA_NOT_FOUND   = 0xC0000089;
constexpr uint32_t STATUS_NOT_SUPPORTED             = 0xC00000BB;
constexpr uint32_t STATUS_INVALID_DEVICE_REQUEST    = 0xC0000010;
constexpr uint32_t STATUS_PRIVILEGED_INSTRUCTION     = 0xC0000096;
constexpr uint32_t STATUS_DEBUGGER_INACTIVE         = 0xC0000354;
constexpr uint32_t STATUS_BAD_COMPRESSION_BUFFER    = 0xC0000242;
constexpr uint32_t STATUS_UNSUPPORTED_COMPRESSION   = 0xC000025F;
constexpr uint32_t STATUS_NOINTERFACE               = 0xC00002B9;
constexpr uint32_t STATUS_PORT_NOT_SET              = 0xC0000353;

//  Device Flags 

constexpr uint32_t DO_DIRECT_IO           = 0x00000010;
constexpr uint32_t DO_BUFFERED_IO         = 0x00000004;
constexpr uint32_t DO_EXCLUSIVE           = 0x00000008;
constexpr uint32_t DO_DEVICE_INITIALIZING  = 0x00000080;

//  IRP Major Function Codes 

constexpr uint32_t IRP_MJ_CREATE                   = 0x00;
constexpr uint32_t IRP_MJ_CREATE_NAMED_PIPE        = 0x01;
constexpr uint32_t IRP_MJ_CLOSE                    = 0x02;
constexpr uint32_t IRP_MJ_READ                     = 0x03;
constexpr uint32_t IRP_MJ_WRITE                    = 0x04;
constexpr uint32_t IRP_MJ_QUERY_INFORMATION        = 0x05;
constexpr uint32_t IRP_MJ_SET_INFORMATION          = 0x06;
constexpr uint32_t IRP_MJ_QUERY_EA                 = 0x07;
constexpr uint32_t IRP_MJ_SET_EA                   = 0x08;
constexpr uint32_t IRP_MJ_FLUSH_BUFFERS            = 0x09;
constexpr uint32_t IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0A;
constexpr uint32_t IRP_MJ_SET_VOLUME_INFORMATION   = 0x0B;
constexpr uint32_t IRP_MJ_DIRECTORY_CONTROL        = 0x0C;
constexpr uint32_t IRP_MJ_FILE_SYSTEM_CONTROL      = 0x0D;
constexpr uint32_t IRP_MJ_DEVICE_CONTROL           = 0x0E;
constexpr uint32_t IRP_MJ_INTERNAL_DEVICE_CONTROL  = 0x0F;
constexpr uint32_t IRP_MJ_SHUTDOWN                 = 0x10;
constexpr uint32_t IRP_MJ_LOCK_CONTROL             = 0x11;
constexpr uint32_t IRP_MJ_CLEANUP                  = 0x12;
constexpr uint32_t IRP_MJ_CREATE_MAILSLOT          = 0x13;
constexpr uint32_t IRP_MJ_QUERY_SECURITY           = 0x14;
constexpr uint32_t IRP_MJ_SET_SECURITY             = 0x15;
constexpr uint32_t IRP_MJ_POWER                    = 0x16;
constexpr uint32_t IRP_MJ_SYSTEM_CONTROL           = 0x17;
constexpr uint32_t IRP_MJ_DEVICE_CHANGE            = 0x18;
constexpr uint32_t IRP_MJ_QUERY_QUOTA              = 0x19;
constexpr uint32_t IRP_MJ_SET_QUOTA                = 0x1A;
constexpr uint32_t IRP_MJ_PNP                      = 0x1B;
constexpr uint32_t IRP_MJ_PNP_POWER                = IRP_MJ_PNP;
constexpr uint32_t IRP_MJ_MAXIMUM_FUNCTION         = 0x1B;

//  POOL_TYPE 

struct POOL_TYPE {
    static constexpr int NonPagedPool    = 0;
    static constexpr int PagedPool       = 1;
    static constexpr int NonPagedPoolNx  = 2;
};

#endif // SPEAKEASY_DEFS_NT_DDK_H
