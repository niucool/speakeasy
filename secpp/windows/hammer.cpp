// hammer.cpp
#include "hammer.h"
#include <algorithm>
#include <cctype>
#include <iostream>

// Default list of APIs to always allow despite triggering API hammering detection
const std::vector<std::string> _default_api_hammer_allowlist = {
    "kernel32.WriteProcessMemory",
    "kernel32.WriteFile",
    "kernel32.ReadFile",
};

// Helper function to create a set with lowercase strings
std::set<std::string> _lowercase_set(const std::vector<std::string>& tt) {
    std::set<std::string> result;
    for (const std::string& bb : tt) {
        std::string lower_bb = bb;
        std::transform(lower_bb.begin(), lower_bb.end(), lower_bb.begin(), ::tolower);
        result.insert(lower_bb);
    }
    return result;
}

// ApiHammer implementation
ApiHammer::ApiHammer(void* emu) 
    : emu(emu), hammer_memregion(0), hammer_offset(0) {
    
    // TODO: Implementation depends on emulator config access
    /*
    super(ApiHammer, this).__init__()
    this.emu = emu
    this.api_stats = collections.defaultdict(int)
    this.hammer_memregion = None
    this.hammer_offset = 0

    this.config = this.emu.config.get('api_hammering', {})
    this.api_threshold = this.config.get('threshold', 1000)
    this.enabled = this.config.get('enabled', False)
    this.allow_list = _lowercase_set(this.config.get('allow_list',
                                                     _default_api_hammer_allowlist))
    */
}

bool ApiHammer::is_allowed_api(const std::string& apiname) {
    /*
    Returns true if the given apiname is one we don't want to use api hammering
    mitigation for
    */
    std::string lower_apiname = apiname;
    std::transform(lower_apiname.begin(), lower_apiname.end(), lower_apiname.begin(), ::tolower);
    return allow_list.find(lower_apiname) != allow_list.end();
}

void ApiHammer::handle_import_func(const std::string& imp_api, int conv, int argc) {
    /*
    Identifies possible API hammering and attempts to patch in mitigations.
    */
    // TODO: Implementation depends on enabled flag
    /*
    if not this.enabled:
        // api hammering mitigation not enabled, so exit
        return
    */
    
    if (is_allowed_api(imp_api)) {
        // this is an api that we always want to allow, don't bother trying to
        // prevent api hammering
        return;
    }
    
    // TODO: Implementation depends on emulator access
    /*
    hammer_key = imp_api + '%x' % this.emu.get_ret_address()
    this.api_stats[hammer_key] += 1
    if this.api_stats[hammer_key] < this.api_threshold:
        return
    */
    
    // TODO: better parameterize the checking & dispatch of the types of calls/jmps to imports
    // so we can more easily loop through them & clean up the the logic below
    // TODO: track patches in the hammer_memregion & reuse when possible
    
    // TODO: Implementation depends on architecture access
    /*
    if this.emu.get_arch() == e_arch.ARCH_X86:
        eip = this.emu.get_ret_address() - 6
        mnem, op, instr = this.emu.get_disasm(eip, DISASM_SIZE)
        this.emu.log_info('api hammering at: %s 0x%x %r %r %r' % (imp_api, this.emu.get_pc(),
                                                                  mnem, op, instr))
        if (mnem == 'call') and 'dword ptr' in instr:
            if conv == e_arch.CALL_CONV_CDECL:
                // If cdecl, the emu engine will clean the stack
                // just xor eax,eax & 4 bytes of nop
                patch = b'\x31\xc0\x90\x90\x90\x90\x90'
                this.emu.mem_write(eip, patch)
                this.emu.log_info('API HAMMERING DETECTED - patching 1 cdecl at %x' % (eip, ))
            elif conv == e_arch.CALL_CONV_STDCALL:
                // If stdcall, we need to clean the stack
                // patch is xor eax, eax; add esp, <count>
                patch = b'\x31\xc0\x83\xc4' + (4*argc).to_bytes(1, 'little') + b'\x90'
                this.emu.mem_write(eip, patch)
                this.emu.log_info('API HAMMERING DETECTED - patching 1 stdcall at %x' % (eip,))
        else:
            eip = this.emu.get_ret_address() - 2
            mnem, op, instr = this.emu.get_disasm(eip, DISASM_SIZE)
            this.emu.log_info('api hammering at: 0x%x %r %r %r' % (this.emu.get_pc(), mnem,
                                                                   op, instr))
            if (mnem == 'call') and op in e_arch.REG_LOOKUP.keys():
                // not enough space to clean up stack inline, so write stack cleanup code to a
                // hammerpatch region & change the register to point to this cleanup code
                // instead the hope is that we're in a tight loop, so this will prevent exiting
                // the emulator the majority of the time.
                if this.hammer_memregion is None:
                    this.hammer_memregion = this.emu.mem_map(0x1024*4,
                                                             tag='speakeasy.hammerpatch')
                if conv == e_arch.CALL_CONV_CDECL:
                    // If cdecl, the emu engine will clean the stack
                    // just xor eax,eax; retn
                    patch = b'\x31\xc0\xc3'
                    this.emu.mem_write(eip, patch)
                    this.emu.log_info('API HAMMERING DETECTED - patching 2 cdecl at %x' % (eip,)) # noqa
                elif conv == e_arch.CALL_CONV_STDCALL:
                    // patch is xor eax, eax; retn <count>
                    patch = b'\x31\xc0\xc2' + (4*argc).to_bytes(2, 'little') + b'\x90'
                    loc = this.hammer_memregion + this.hammer_offset
                    if (this.hammer_offset + len(patch)) < 0x1024*4:
                        this.emu.mem_write(loc, patch)
                        this.hammer_offset += len(patch)
                        // now change the the register
                        reg = e_arch.REG_LOOKUP[op]
                        this.emu.reg_write(reg, loc)
                        this.emu.log_info('API HAMMERING DETECTED - patching 2 stdcall at %x' % (eip,)) # noqa
            else:
                this.emu.log_info('API HAMMERING DETECTED - unable to patch %x' % (eip, ))

    if this.emu.get_arch() == e_arch.ARCH_AMD64:
        // TODO
        pass
    */
}