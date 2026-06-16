// wdfldr.cpp  Windows Driver Framework Loader handler (implemented)
#include "wdfldr.h"

#include <cstdint>
#include <vector>
#include <string>
#include <map>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api { namespace kernelmode {

//  Typed cast helpers 
static inline int ptr_sz(void* e) { return we(e)->get_ptr_size(); }

// WDF handle management
static uint32_t wdf_next_handle = 4;
static inline uint32_t wdf_new_handle() {
    uint32_t h = wdf_next_handle;
    wdf_next_handle += 4;
    return h;
}

Wdfldr::Wdfldr(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Wdfldr)
    REG(Wdfldr, WdfVersionBind, 4)
    REG(Wdfldr, WdfDriverCreate, 6)
    REG(Wdfldr, WdfDeviceInitSetPnpPowerEventCallbacks, 3)
    REG(Wdfldr, WdfDeviceInitSetRequestAttributes, 3)
    REG(Wdfldr, WdfDeviceInitSetFileObjectConfig, 4)
    REG(Wdfldr, WdfDeviceInitSetIoType, 3)
    REG(Wdfldr, WdfDeviceCreate, 4)
    REG(Wdfldr, WdfObjectGetTypedContextWorker, 3)
    REG(Wdfldr, WdfDriverOpenParametersRegistryKey, 5)
    REG(Wdfldr, WdfRegistryQueryULong, 4)
    REG(Wdfldr, WdfRegistryClose, 2)
    REG(Wdfldr, WdfDeviceSetPnpCapabilities, 3)
    REG(Wdfldr, WdfIoQueueReadyNotify, 4)
    REG(Wdfldr, WdfDeviceCreateDeviceInterface, 4)
    REG(Wdfldr, WdfIoQueueCreate, 5)
    REG(Wdfldr, WdfDeviceWdmGetAttachedDevice, 2)
    REG(Wdfldr, WdfDeviceWdmGetDeviceObject, 2)
    REG(Wdfldr, WdfUsbTargetDeviceCreateWithParameters, 5)
    REG(Wdfldr, WdfUsbTargetDeviceGetDeviceDescriptor, 3)
    REG(Wdfldr, WdfMemoryCreate, 7)
    REG(Wdfldr, WdfUsbTargetDeviceSelectConfig, 4)
    REG(Wdfldr, WdfUsbTargetDeviceRetrieveConfigDescriptor, 4)
    REG(Wdfldr, WdfUsbInterfaceSelectSetting, 4)
    REG(Wdfldr, WdfUsbTargetDeviceGetNumInterfaces, 2)
    REG(Wdfldr, WdfUsbInterfaceGetNumConfiguredPipes, 2)
    REG(Wdfldr, WdfUsbInterfaceGetNumSettings, 2)
    REG(Wdfldr, WdfUsbTargetDeviceRetrieveInformation, 3)
    REG(Wdfldr, WdfUsbInterfaceGetConfiguredPipe, 4)
    REG(Wdfldr, WdfUsbTargetPipeGetInformation, 3)
    REG(Wdfldr, WdfUsbInterfaceGetInterfaceNumber, 2)
    END_API_TABLE
}

//  Implementations 

uint64_t Wdfldr::WdfVersionBind(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfVersionBind(DriverObject, RegistryPath, BindInfo, ComponentGlobals)
    uint64_t bind_info = a[2];
    uint64_t comp_globals = a[3];
    
    if (bind_info) {
        // Read WDF_BIND_INFO: at offset 0 is FunctionTable pointer, then Version
        size_t psz = static_cast<size_t>(ptr_sz(e));
        size_t func_tbl_size = psz * 64; // enough for WDFFUNCTIONS table
        uint64_t func_tbl = mm(e)->mem_map(func_tbl_size, std::nullopt, common::PERM_MEM_RWX,
                                           "api.struct.WDFFUNCTIONS");
        
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, func_tbl, psz);
        mm(e)->mem_write(bind_info, data);
    }
    
    if (comp_globals) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        uint64_t globals = mm(e)->mem_map(psz * 8, std::nullopt, common::PERM_MEM_RWX,
                                          "api.struct.WDF_COMPONENT_GLOBALS");
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, globals, psz);
        mm(e)->mem_write(comp_globals, data);
    }
    
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfDriverCreate(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfDriverCreate(DriverGlobals, DriverObject, RegistryPath, DriverAttributes, DriverConfig, Driver)
    (void)e; (void)a;
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfDeviceInitSetPnpPowerEventCallbacks(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfDeviceInitSetRequestAttributes(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfDeviceInitSetFileObjectConfig(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfDeviceInitSetIoType(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfDeviceCreate(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfDeviceCreate(DeviceInit, DeviceAttributes, Device)
    uint64_t device_out = a[2];
    if (device_out) {
        uint32_t handle = wdf_new_handle();
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, static_cast<uint64_t>(handle), psz);
        mm(e)->mem_write(device_out, data);
        
        // Allocate a DEVICE_OBJECT structure
        mm(e)->mem_map(psz * 16, std::nullopt, common::PERM_MEM_RWX, "api.struct.DEVICE_OBJECT");
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfObjectGetTypedContextWorker(void* e, ArgList& a, void* ctx) {
    // PVOID WdfObjectGetTypedContextWorker(Handle, TypeInfo)
    size_t psz = static_cast<size_t>(ptr_sz(e));
    (void)psz;
    uint64_t mapped_ctx = mm(e)->mem_map(psz * 8, std::nullopt, common::PERM_MEM_RWX,
                                  "api.struct.WDF_TYPED_CONTEXT_WORKER");
    return mapped_ctx;
}

uint64_t Wdfldr::WdfDriverOpenParametersRegistryKey(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfDriverOpenParametersRegistryKey(Driver, DesiredAccess, KeyAttributes, Key)
    uint64_t p_key = a[3];
    if (p_key) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz, 0);
        mm(e)->mem_write(p_key, data);
    }
    return 0; // STATUS_SUCCESS (simplified)
}

uint64_t Wdfldr::WdfRegistryQueryULong(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfRegistryQueryULong(Key, ValueName, Value)
    uint64_t p_value = a[2];
    if (p_value) {
        auto data = std::vector<uint8_t>(4, 0);
        mm(e)->mem_write(p_value, data);
    }
    return 0; // STATUS_SUCCESS (simplified, returns 0)
}

uint64_t Wdfldr::WdfRegistryClose(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfDeviceSetPnpCapabilities(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfIoQueueReadyNotify(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfDeviceCreateDeviceInterface(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfIoQueueCreate(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfDeviceWdmGetAttachedDevice(void* e, ArgList& a, void* ctx) {
    // Return a dummy device object
    size_t psz = static_cast<size_t>(ptr_sz(e));
    (void)psz;
    return mm(e)->mem_map(psz * 16, std::nullopt, common::PERM_MEM_RWX, "api.struct.DEVICE_OBJECT");
}

uint64_t Wdfldr::WdfDeviceWdmGetDeviceObject(void* e, ArgList& a, void* ctx) {
    // Return a dummy device object
    size_t psz = static_cast<size_t>(ptr_sz(e));
    (void)psz;
    return mm(e)->mem_map(psz * 16, std::nullopt, common::PERM_MEM_RWX, "api.struct.DEVICE_OBJECT");
}

uint64_t Wdfldr::WdfUsbTargetDeviceCreateWithParameters(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbTargetDeviceCreateWithParameters(Device, Config, Attributes, USBDevice)
    uint64_t usb_dev = a[3];
    if (usb_dev) {
        uint32_t handle = wdf_new_handle();
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, static_cast<uint64_t>(handle), psz);
        mm(e)->mem_write(usb_dev, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbTargetDeviceGetDeviceDescriptor(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbTargetDeviceGetDeviceDescriptor(Handle, Descriptor)
    uint64_t desc = a[1];
    if (desc) {
        // Write a USB_DEVICE_DESCRIPTOR (18 bytes)
        auto data = std::vector<uint8_t>(18, 0);
        data[0] = 18;     // bLength
        data[1] = 1;      // bDescriptorType = DEVICE
        data[2] = 0x10;   // bcdUSB low
        data[3] = 0x01;   // bcdUSB high = USB 1.1
        data[4] = 0;      // bDeviceClass
        data[5] = 0;      // bDeviceSubClass
        data[6] = 0;      // bDeviceProtocol
        data[7] = 64;     // bMaxPacketSize0
        mm(e)->mem_write(desc, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfMemoryCreate(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfMemoryCreate(Attributes, PoolType, PoolTag, BufferSize, Memory, Buffer)
    uint64_t mem_out = a[3]; // Memory handle
    uint64_t buf_out = a[4]; // Buffer pointer
    uint64_t buf_size = a[2]; // BufferSize
    
    if (buf_size == 0) buf_size = 1;
    
    uint64_t buf = mm(e)->mem_map(buf_size, std::nullopt, common::PERM_MEM_RWX, "wdf.memory.buffer");
    
    if (mem_out) {
        uint32_t handle = wdf_new_handle();
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, static_cast<uint64_t>(handle), psz);
        mm(e)->mem_write(mem_out, data);
    }
    
    if (buf_out) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, buf, psz);
        mm(e)->mem_write(buf_out, data);
    }
    
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbTargetDeviceSelectConfig(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbTargetDeviceSelectConfig(Handle, Options, Params)
    (void)e; (void)a;
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbTargetDeviceRetrieveConfigDescriptor(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbTargetDeviceRetrieveConfigDescriptor(Handle, ConfigDescriptor, Size)
    uint64_t config_desc = a[1];
    uint64_t size_ptr = a[2];
    
    // Simulate a USB configuration descriptor
    if (config_desc && size_ptr) {
        auto raw = mm(e)->mem_read(size_ptr, 2);
        uint16_t buf_size = static_cast<uint16_t>(read_le(raw, 0, 2));
        
        if (buf_size >= 9) {
            auto data = std::vector<uint8_t>(9);
            data[0] = 9;      // bLength
            data[1] = 2;      // bDescriptorType = CONFIGURATION
            data[2] = 9;      // wTotalLength low
            data[3] = 0;      // wTotalLength high
            data[4] = 1;      // bNumInterfaces
            data[5] = 1;      // bConfigurationValue
            data[6] = 0;      // iConfiguration
            data[7] = 0x80;   // bmAttributes (bus-powered)
            data[8] = 50;     // bMaxPower (100 mA)
            mm(e)->mem_write(config_desc, data);
            
            // Update size
            auto size_data = std::vector<uint8_t>(2);
            write_le(size_data, 0, static_cast<uint64_t>(9), 2);
            mm(e)->mem_write(size_ptr, size_data);
        }
    } else if (size_ptr) {
        // Just return the required size
        auto size_data = std::vector<uint8_t>(2);
        write_le(size_data, 0, static_cast<uint64_t>(9), 2);
        mm(e)->mem_write(size_ptr, size_data);
    }
    
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbInterfaceSelectSetting(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfUsbTargetDeviceGetNumInterfaces(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbTargetDeviceGetNumInterfaces(Handle, NumInterfaces)
    uint64_t num_if = a[1];
    if (num_if) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(1), 4); // 1 interface
        mm(e)->mem_write(num_if, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbInterfaceGetNumConfiguredPipes(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbInterfaceGetNumConfiguredPipes(Handle, NumPipes)
    uint64_t num_pipes = a[1];
    if (num_pipes) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(1), 4); // 1 pipe
        mm(e)->mem_write(num_pipes, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbInterfaceGetNumSettings(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbInterfaceGetNumSettings(Handle, NumSettings)
    uint64_t num_settings = a[1];
    if (num_settings) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(1), 4); // 1 setting
        mm(e)->mem_write(num_settings, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbTargetDeviceRetrieveInformation(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Wdfldr::WdfUsbInterfaceGetConfiguredPipe(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbInterfaceGetConfiguredPipe(Handle, Index, Pipe)
    uint64_t pipe_out = a[2];
    if (pipe_out) {
        uint32_t handle = wdf_new_handle();
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, static_cast<uint64_t>(handle), psz);
        mm(e)->mem_write(pipe_out, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbTargetPipeGetInformation(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbTargetPipeGetInformation(Handle, PipeInfo)
    uint64_t pipe_info = a[1];
    if (pipe_info) {
        // Write a basic pipe info: type = 0 (UsbdPipeTypeControl), maxPacketSize = 64
        auto data = std::vector<uint8_t>(ptr_sz(e) * 4, 0);
        mm(e)->mem_write(pipe_info, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Wdfldr::WdfUsbInterfaceGetInterfaceNumber(void* e, ArgList& a, void* ctx) {
    // NTSTATUS WdfUsbInterfaceGetInterfaceNumber(Handle, InterfaceNumber)
    uint64_t if_num = a[1];
    if (if_num) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(0), 4); // interface 0
        mm(e)->mem_write(if_num, data);
    }
    return 0; // STATUS_SUCCESS
}

}}} // namespaces
