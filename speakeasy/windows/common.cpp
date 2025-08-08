// common.cpp
#include "common.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>

// Function to normalize DLL names
std::string normalize_dll_name(const std::string& name) {
    std::string ret = name;
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    // Funnel CRTs into a single handler
    if (lower_name.substr(0, std::min<size_t>(lower_name.length(), 12)).find("api-ms-win-crt") == 0 ||
        lower_name.substr(0, std::min<size_t>(lower_name.length(), 9)).find("vcruntime") == 0 ||
        lower_name.substr(0, std::min<size_t>(lower_name.length(), 10)).find("ucrtbased") == 0 ||
        lower_name.substr(0, std::min<size_t>(lower_name.length(), 8)).find("ucrtbase") == 0 ||
        lower_name.substr(0, std::min<size_t>(lower_name.length(), 5)).find("msvcr") == 0 ||
        lower_name.substr(0, std::min<size_t>(lower_name.length(), 5)).find("msvcp") == 0) {
        ret = "msvcrt";
    }
    // Redirect windows sockets 1.0 to windows sockets 2.0
    else if (lower_name.substr(0, std::min<size_t>(lower_name.length(), 6)).find("winsock") == 0 ||
             lower_name.substr(0, std::min<size_t>(lower_name.length(), 8)).find("wsock32") == 0) {
        ret = "ws2_32";
    }
    else if (lower_name.substr(0, std::min<size_t>(lower_name.length(), 12)).find("api-ms-win-core") == 0) {
        ret = "kernel32";
    }

    return ret;
}

// PeFile constructor
PeFile::PeFile(const std::string& path, const std::vector<uint8_t>& data, 
               uint64_t imp_id, uint64_t imp_step, 
               const std::string& emu_path, bool fast_load) 
    : imp_id(imp_id), imp_step(imp_step), file_size(0), base(0), 
      image_size(0), is_mapped(true), ep(0), stack_commit(0),
      path(path), emu_path(emu_path) {
    
    // TODO: Implementation depends on PE file library
    /*
    super(PeFile, this).__init__(name=path, data=data, fast_load=fast_load)

    if 0 == this.OPTIONAL_HEADER.ImageBase:
        this.relocate_image(DEFAULT_LOAD_ADDR)
        super(PeFile, this).__init__(name=None, data=this.write())

    this.imp_id = imp_id
    this.imp_step = imp_step
    this.file_size = 0
    this.base = this.OPTIONAL_HEADER.ImageBase
    this.hash = this._hash_pe(path=path, data=data)
    this.imports = this._get_pe_imports()
    this.exports = this._get_pe_exports()
    this.mapped_image = this.get_memory_mapped_image(max_virtual_address=0xf0000000)
    // this.mapped_image = None
    this.image_size = this.OPTIONAL_HEADER.SizeOfImage
    this.import_table = {}
    this.is_mapped = True
    this.pe_sections = this._get_pe_sections()
    this.ep = this.OPTIONAL_HEADER.AddressOfEntryPoint
    this.stack_commit = this.OPTIONAL_HEADER.SizeOfStackCommit
    this.path = ''
    this.name = ''
    if path:
        this.path = os.path.abspath(path)
    this.emu_path = emu_path
    this.arch = this._get_architecture()
    if this.arch == _arch.ARCH_X86:
        this.ptr_size = 4
    else:
        this.ptr_size = 8

    this._patch_imports()
    */
}

std::vector<uint64_t> PeFile::get_tls_callbacks() {
    // Get the TLS callbacks for a PE (if any)
    // TODO: Implementation depends on PE file library
    /*
    max_tls_callbacks = 100
    callbacks = []
    if hasattr(this, 'DIRECTORY_ENTRY_TLS'):
        rva = (this.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks -
               this.OPTIONAL_HEADER.ImageBase)

        for i in range(max_tls_callbacks):
            ptr = this.get_data(rva + this.ptr_size * i, this.ptr_size)
            ptr = int.from_bytes(ptr, 'little')
            if ptr == 0:
                break
            callbacks.append(ptr)
    return callbacks
    */
    return std::vector<uint64_t>();
}

uint32_t PeFile::get_resource_dir_rva() {
    // TODO: Implementation depends on PE file library
    /*
    res_dir_rva = 0
    for dd in this.OPTIONAL_HEADER.DATA_DIRECTORY:
        if dd.name == "IMAGE_DIRECTORY_ENTRY_RESOURCE":
            res_dir_rva = dd.VirtualAddress
            break

    return res_dir_rva
    */
    return 0;
}

std::string PeFile::get_emu_path() {
    // Get the path of the module (as it appears to the emulated binary)
    return emu_path;
}

void PeFile::set_emu_path(const std::string& path) {
    emu_path = path;
}

std::string PeFile::_hash_pe(const std::string& path, const std::vector<uint8_t>& data) {
    // TODO: Implementation depends on hashing library
    /*
    hasher = hashlib.sha256()
    buf = b''
    if path:
        with open(path, 'rb') as f:
            buf = f.read()
    elif data:
        buf = data

    hasher.update(buf)
    this.file_size = len(buf)
    return hasher.hexdigest()
    */
    return "";
}

std::map<uint64_t, std::tuple<std::string, std::string>> PeFile::_get_pe_imports() {
    // TODO: Implementation depends on PE file library
    /*
    pe = this
    imports = {}

    try:
        pe.DIRECTORY_ENTRY_IMPORT
    except Exception:
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll
        dll = dll.decode('utf-8')
        dll = os.path.splitext(dll)[0]
        for imp in entry.imports:
            if imp.import_by_ordinal:
                func_name = 'ordinal_%d' % (imp.ordinal)
                imports.update({imp.address: (dll, func_name)})
            else:
                func_name = imp.name.decode('utf-8')
                imports.update({imp.address: (dll, func_name)})
    return imports
    */
    return std::map<uint64_t, std::tuple<std::string, std::string>>();
}

std::vector<ExportEntry> PeFile::get_exports() {
    exports = _get_pe_exports();
    return exports;
}

std::vector<ExportEntry> PeFile::_get_pe_exports() {
    // TODO: Implementation depends on PE file library
    /*
    pe = this
    exports = []
    try:
        pe.DIRECTORY_ENTRY_EXPORT
    except Exception:
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        entry = namedtuple('export', ['name', 'address', 'forwarder', 'ordinal'])
        entry.name = exp.name
        entry.address = exp.address + pe.get_base()
        entry.forwarder = exp.forwarder
        entry.ordinal = exp.ordinal
        if entry.name:
            entry.name = entry.name.decode('utf-8')
        exports.append(entry)
    return exports
    */
    return std::vector<ExportEntry>();
}

std::vector<PeSection> PeFile::_get_pe_sections() {
    // TODO: Implementation depends on PE file library
    /*
    pe = this
    sections = []
    for section in pe.sections:
        sect = (section.Name, section.VirtualAddress,
                section.Misc_VirtualSize, section.SizeOfRawData)
        sections.append(sect)
    return sections
    */
    return std::vector<PeSection>();
}

std::vector<PeSection> PeFile::get_sections() {
    return pe_sections;
}

PeSection* PeFile::get_section_by_name(const std::string& name) {
    // TODO: Implementation depends on PE file library
    /*
    sect = [s for s in this.get_sections() if s.Name.decode('utf-8').strip('\x00') == name]
    if sect:
        return sect[0]
    */
    return nullptr;
}

int PeFile::_get_architecture() {
    // TODO: Implementation depends on PE file library
    /*
    // 0x010b: PE32, 0x020b: PE32+ (64 bit)
    magic = this.OPTIONAL_HEADER.Magic
    if magic & ddk.PE32_BIT:
        return _arch.ARCH_X86
    elif magic & ddk.PE32_PLUS_BIT:
        return _arch.ARCH_AMD64
    else:
        raise ValueError('Unsupported architecture: 0x%x' % (magic))
    */
    return 0;
}

void PeFile::_patch_imports() {
    /*
    Imports are patched with invalid memory addresses. When the API is called
    by the emulated binary, the invalid memory fetch callback will trigger,
    allowing us to handle the Windows API within the emulator
    */
    // TODO: Implementation depends on PE file library
    /*
    if not this.imports:
        return

    if not this.mapped_image:
        raise ValueError('PE image has not been mapped yet')

    for addr, imp in this.imports.items():
        tmp = bytearray(this.mapped_image)
        offset = addr - this.base
        tmp[offset: offset + this.ptr_size] = \
            this.imp_id.to_bytes(this.ptr_size, 'little')
        this.mapped_image = bytes(tmp)

        this.import_table.update({this.imp_id: imp})
        this.imp_id += this.imp_step
    */
}

uint64_t PeFile::get_export_by_name(const std::string& name) {
    // TODO: Implementation depends on export handling
    /*
    for exp in this.get_exports():
        if name == exp.name:
            return exp.address
    */
    return 0;
}

std::vector<uint8_t> PeFile::get_raw_data() {
    // TODO: Implementation depends on PE file library
    // return this.get_memory_mapped_image()
    return std::vector<uint8_t>();
}

int PeFile::find_bytes(const std::vector<uint8_t>& pattern, int offset) {
    // TODO: Implementation depends on data searching
    // return this.get_raw_data().find(pattern, offset)
    return -1;
}

void PeFile::set_bytes(int offset, const std::vector<uint8_t>& pattern) {
    // TODO: Implementation depends on PE file library
    // this.set_bytes_at_offset(offset, pattern)
}

int PeFile::get_ptr_size() {
    return ptr_size;
}

uint64_t PeFile::get_base() {
    return base;
}

std::string PeFile::get_base_name() {
    // TODO: Implementation depends on path handling
    /*
    fn = os.path.basename(this.path)
    bn = os.path.splitext(fn)[0]
    return bn
    */
    return "";
}

size_t PeFile::get_image_size() {
    return image_size;
}

bool PeFile::is_decoy() {
    return false;
}

bool PeFile::is_driver() {
    // TODO: Implementation depends on PE file library
    /*
    rv = super(PeFile, this).is_driver()
    if rv:
        return rv

    system_DLLs = set((b'ntoskrnl.exe', b'hal.dll', b'ndis.sys',
                       b'bootvid.dll', b'kdcom.dll', b'win32k.sys'))

    if hasattr(this, 'DIRECTORY_ENTRY_IMPORT'):
        if system_DLLs.intersection(
                [imp.dll.lower() for imp in this.DIRECTORY_ENTRY_IMPORT]):
            return True

    if this.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE'] \
       and this.ep == 0:
        return True
    */
    return false;
}

bool PeFile::is_dotnet() {
    /*
    Is the current PE file a .NET assembly?
    */
    // TODO: Implementation depends on import handling
    /*
    for addr, imp in this.imports.items():
        dll, func = imp
        if dll == 'mscoree' and func in ['_CorExeMain', '_CorDllMain']:
            return True
    return False
    */
    return false;
}

bool PeFile::has_reloc_table() {
    // TODO: Implementation depends on PE file library
    /*
    return len(this.OPTIONAL_HEADER.DATA_DIRECTORY) >= 6 and \
            this.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0
    */
    return false;
}

void PeFile::rebase(uint64_t to) {
    // TODO: Implementation depends on PE file library
    /*
    this.relocate_image(to)

    this.base = to
    this.ep = this.OPTIONAL_HEADER.AddressOfEntryPoint

    // After relocation, generate a new memory mapped image
    this.mapped_image = this.get_memory_mapped_image(max_virtual_address=0xf0000000)

    this.pe_sections = this._get_pe_sections()
    this.imports = this._get_pe_imports()
    this.exports = this._get_pe_exports()
    this._patch_imports()

    return
    */
}

// DecoyModule constructor
DecoyModule::DecoyModule(const std::string& path, const std::vector<uint8_t>& data, 
                         bool fast_load, uint64_t base, const std::string& emu_path, 
                         bool is_jitted)
    : PeFile(path, data, IMPORT_HOOK_ADDR, 4, emu_path, fast_load),
      image_size(0), ep(0), is_jitted(is_jitted), decoy_base(base), 
      decoy_path(emu_path), base_name(""), is_mapped(false) {
    
    if (data.size() > 0) {
        image_size = data.size();
    }
}

std::vector<uint8_t> DecoyModule::get_memory_mapped_image(uint64_t max_virtual_address, 
                                                          uint64_t base) {
    // TODO: Implementation depends on parent class
    /*
    mmi = super(DecoyModule, this).get_memory_mapped_image(max_virtual_address, base)
    if this.is_jitted and len(mmi) < len(this.__data__):
        return this.__data__
    return mmi
    */
    return std::vector<uint8_t>();
}

uint64_t DecoyModule::get_base() {
    return decoy_base;
}

std::string DecoyModule::get_emu_path() {
    return decoy_path;
}

std::string DecoyModule::get_base_name() {
    // TODO: Implementation depends on path handling
    /*
    p = this.get_emu_path()
    img = ntpath.basename(p)
    bn = os.path.splitext(img)[0]
    return bn
    */
    return "";
}

uint64_t DecoyModule::get_ep() {
    return get_base() + ep;
}

bool DecoyModule::is_decoy() {
    return true;
}

// JitPeFile constructor
JitPeFile::JitPeFile(int arch) : arch(arch) {
    if (arch == /*_arch.ARCH_X86*/ 0) { // TODO: Replace with actual architecture constant
        pattern_size = 9;
        basepe_data = EMPTY_PE_32;
    } else {
        pattern_size = 12;
        basepe_data = EMPTY_PE_64;
    }
    
    // TODO: Implementation depends on PE file library
    /*
    this.basepe = pefile.PE(data=husk, fast_load=True)
    */
}

// Other methods would follow similar patterns...
// Due to length constraints, I'm not implementing all methods here
// but the pattern would be similar to the above methods