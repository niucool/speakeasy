// ddk.h  Windows Driver Development Kit constants (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/nt/ddk.py
//
// Namespace speakeasy::deffs::nt to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_NT_DDK_H
#define SPEAKEASY_DEFS_NEW_NT_DDK_H

#include <cstdint>

namespace speakeasy { namespace deffs { namespace nt {

// ------ IRQL Levels ---------------------------------------------------------------------
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

// ------ NT Status Codes -------------------------------------------------------------------
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

// ------ Device Flags --------------------------------------------------------------------
constexpr uint32_t DO_DIRECT_IO           = 0x00000010;
constexpr uint32_t DO_BUFFERED_IO         = 0x00000004;
constexpr uint32_t DO_EXCLUSIVE           = 0x00000008;
constexpr uint32_t DO_DEVICE_INITIALIZING  = 0x00000080;

// ------ IRP Major Function Codes ---------------------------------------------------------
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
constexpr uint32_t IRP_MJ_QUERY_VOLUME_INFORMATION  = 0x0A;
constexpr uint32_t IRP_MJ_SET_VOLUME_INFORMATION    = 0x0B;
constexpr uint32_t IRP_MJ_DIRECTORY_CONTROL         = 0x0C;
constexpr uint32_t IRP_MJ_FILE_SYSTEM_CONTROL       = 0x0D;
constexpr uint32_t IRP_MJ_DEVICE_CONTROL            = 0x0E;
constexpr uint32_t IRP_MJ_INTERNAL_DEVICE_CONTROL   = 0x0F;
constexpr uint32_t IRP_MJ_SHUTDOWN                  = 0x10;
constexpr uint32_t IRP_MJ_LOCK_CONTROL              = 0x11;
constexpr uint32_t IRP_MJ_CLEANUP                   = 0x12;
constexpr uint32_t IRP_MJ_CREATE_MAILSLOT           = 0x13;
constexpr uint32_t IRP_MJ_QUERY_SECURITY            = 0x14;
constexpr uint32_t IRP_MJ_SET_SECURITY              = 0x15;
constexpr uint32_t IRP_MJ_POWER                     = 0x16;
constexpr uint32_t IRP_MJ_SYSTEM_CONTROL            = 0x17;
constexpr uint32_t IRP_MJ_DEVICE_CHANGE             = 0x18;
constexpr uint32_t IRP_MJ_QUERY_QUOTA              = 0x19;
constexpr uint32_t IRP_MJ_SET_QUOTA                = 0x1A;
constexpr uint32_t IRP_MJ_PNP                      = 0x1B;
constexpr uint32_t IRP_MJ_PNP_POWER                = IRP_MJ_PNP;
constexpr uint32_t IRP_MJ_MAXIMUM_FUNCTION         = 0x1B;

// ------ Compression Formats ---------------------------------------------------------------
constexpr uint32_t COMPRESSION_FORMAT_LZNT1   = 0x2;
constexpr uint32_t COMPRESSION_FORMAT_XPRESS  = 0x3;

// ------ Access Masks ----------------------------------------------------------------------
constexpr uint32_t DELETE           = 0x00010000;
constexpr uint32_t READ_CONTROL     = 0x00020000;
constexpr uint32_t WRITE_DAC        = 0x00040000;
constexpr uint32_t WRITE_OWNER      = 0x00080000;
constexpr uint32_t SYNCHRONIZE      = 0x00100000;
constexpr uint32_t GENERIC_READ     = 0x80000000;
constexpr uint32_t GENERIC_WRITE    = 0x40000000;
constexpr uint32_t GENERIC_EXECUTE  = 0x20000000;
constexpr uint32_t GENERIC_ALL      = 0x10000000;

// ------ File Attributes ---------------------------------------------------------------------
constexpr uint32_t FILE_ATTRIBUTE_READONLY    = 0x00000001;
constexpr uint32_t FILE_ATTRIBUTE_HIDDEN      = 0x00000002;
constexpr uint32_t FILE_ATTRIBUTE_SYSTEM      = 0x00000004;
constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY   = 0x00000010;
constexpr uint32_t FILE_ATTRIBUTE_ARCHIVE     = 0x00000020;
constexpr uint32_t FILE_ATTRIBUTE_NORMAL      = 0x00000080;

// ------ Memory Allocation Types -----------------------------------------------------------
constexpr uint32_t NonPagedPool       = 0;
constexpr uint32_t PagedPool          = 1;
constexpr uint32_t NonPagedPoolNx     = 2;

// ------ Process Information Class --------------------------------------------------------
constexpr uint32_t ProcessBasicInformation    = 0;
constexpr uint32_t ProcessDebugPort           = 7;

// ------ SYSTEM_INFORMATION_CLASS ---------------------------------------------------------
constexpr uint32_t SystemBasicInformation           = 0;
constexpr uint32_t SystemModuleInformation          = 11;
constexpr uint32_t SystemProcessInformation          = 5;
constexpr uint32_t SystemPerformanceInformation      = 2;
constexpr uint32_t SystemTimeOfDayInformation        = 3;
constexpr uint32_t SystemFlagsInformation             = 21;

// ------ FILE_INFORMATION_CLASS -----------------------------------------------------------
constexpr uint32_t FileStandardInformation   = 5;
constexpr uint32_t FilePositionInformation   = 14;
constexpr uint32_t FileAlignmentInformation  = 17;
constexpr uint32_t FileNameInformation       = 9;

// ------ KEY_VALUE_INFORMATION_CLASS ------------------------------------------------------
constexpr uint32_t KeyValueBasicInformation      = 0;
constexpr uint32_t KeyValueFullInformation       = 1;
constexpr uint32_t KeyValuePartialInformation    = 2;

// ------ Processor Modes ----------------------------------------------------------------
constexpr uint32_t KernelMode = 0;
constexpr uint32_t UserMode   = 1;

// ------ PE Constants -------------------------------------------------------------------
#pragma push_macro("IMAGE_DOS_SIGNATURE")
#pragma push_macro("IMAGE_NT_SIGNATURE")
#pragma push_macro("IMAGE_NT_OPTIONAL_HDR32_MAGIC")
#pragma push_macro("IMAGE_NT_OPTIONAL_HDR64_MAGIC")
#pragma push_macro("IMAGE_SIZEOF_SHORT_NAME")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_EXPORT")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_IMPORT")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_RESOURCE")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_EXCEPTION")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_SECURITY")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_BASERELOC")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_DEBUG")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_TLS")
#pragma push_macro("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG")
#pragma push_macro("IMAGE_SCN_MEM_EXECUTE")
#pragma push_macro("IMAGE_SCN_MEM_READ")
#pragma push_macro("IMAGE_SCN_MEM_WRITE")
#pragma push_macro("IMAGE_FILE_RELOCS_STRIPPED")
#pragma push_macro("IMAGE_FILE_EXECUTABLE_IMAGE")
#pragma push_macro("IMAGE_FILE_DLL")
#pragma push_macro("IMAGE_FILE_SYSTEM")
#pragma push_macro("IMAGE_SUBSYSTEM_NATIVE")
#pragma push_macro("IMAGE_SUBSYSTEM_WINDOWS_GUI")
#undef IMAGE_DOS_SIGNATURE
#undef IMAGE_NT_SIGNATURE
#undef IMAGE_NT_OPTIONAL_HDR32_MAGIC
#undef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#undef IMAGE_SIZEOF_SHORT_NAME
#undef IMAGE_DIRECTORY_ENTRY_EXPORT
#undef IMAGE_DIRECTORY_ENTRY_IMPORT
#undef IMAGE_DIRECTORY_ENTRY_RESOURCE
#undef IMAGE_DIRECTORY_ENTRY_EXCEPTION
#undef IMAGE_DIRECTORY_ENTRY_SECURITY
#undef IMAGE_DIRECTORY_ENTRY_BASERELOC
#undef IMAGE_DIRECTORY_ENTRY_DEBUG
#undef IMAGE_DIRECTORY_ENTRY_TLS
#undef IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
#undef IMAGE_SCN_MEM_EXECUTE
#undef IMAGE_SCN_MEM_READ
#undef IMAGE_SCN_MEM_WRITE
#undef IMAGE_FILE_RELOCS_STRIPPED
#undef IMAGE_FILE_EXECUTABLE_IMAGE
#undef IMAGE_FILE_DLL
#undef IMAGE_FILE_SYSTEM
#undef IMAGE_SUBSYSTEM_NATIVE
#undef IMAGE_SUBSYSTEM_WINDOWS_GUI
constexpr uint32_t IMAGE_DOS_SIGNATURE     = 0x5A4D;
constexpr uint32_t IMAGE_NT_SIGNATURE      = 0x00004550;
constexpr uint32_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
constexpr uint32_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;
constexpr uint32_t IMAGE_SIZEOF_SHORT_NAME = 8;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_EXPORT     = 0;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_IMPORT     = 1;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_RESOURCE   = 2;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_EXCEPTION  = 3;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_SECURITY   = 4;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_BASERELOC  = 5;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_DEBUG      = 6;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_TLS        = 9;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE  = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ     = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE    = 0x80000000;
constexpr uint32_t IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
constexpr uint32_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
constexpr uint32_t IMAGE_FILE_DLL           = 0x2000;
constexpr uint32_t IMAGE_FILE_SYSTEM        = 0x1000;
constexpr uint32_t IMAGE_SUBSYSTEM_NATIVE   = 1;
constexpr uint32_t IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
#pragma pop_macro("IMAGE_SUBSYSTEM_WINDOWS_GUI")
#pragma pop_macro("IMAGE_SUBSYSTEM_NATIVE")
#pragma pop_macro("IMAGE_FILE_SYSTEM")
#pragma pop_macro("IMAGE_FILE_DLL")
#pragma pop_macro("IMAGE_FILE_EXECUTABLE_IMAGE")
#pragma pop_macro("IMAGE_FILE_RELOCS_STRIPPED")
#pragma pop_macro("IMAGE_SCN_MEM_WRITE")
#pragma pop_macro("IMAGE_SCN_MEM_READ")
#pragma pop_macro("IMAGE_SCN_MEM_EXECUTE")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_TLS")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_DEBUG")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_BASERELOC")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_SECURITY")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_EXCEPTION")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_RESOURCE")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_IMPORT")
#pragma pop_macro("IMAGE_DIRECTORY_ENTRY_EXPORT")
#pragma pop_macro("IMAGE_SIZEOF_SHORT_NAME")
#pragma pop_macro("IMAGE_NT_OPTIONAL_HDR64_MAGIC")
#pragma pop_macro("IMAGE_NT_OPTIONAL_HDR32_MAGIC")
#pragma pop_macro("IMAGE_NT_SIGNATURE")
#pragma pop_macro("IMAGE_DOS_SIGNATURE")

}}} // namespace speakeasy::deffs::nt

#endif // SPEAKEASY_DEFS_NEW_NT_DDK_H
