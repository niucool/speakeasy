// fileman.cpp
#include "fileman.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h> // TODO: For SHA256 hashing

// Helper function to normalize response path
std::string normalize_response_path(const std::string& path) {
    // TODO: Implementation depends on path handling
    /*
    def _get_speakeasy_root():
        return os.path.join(os.path.dirname(__file__), os.pardir)

    root_var = '$ROOT$'
    if root_var in path:
        root = _get_speakeasy_root()
        return path.replace(root_var, root)
    return path
    */
    return path;
}

// MapView implementation
MapView::MapView(uint64_t base, uint64_t offset, size_t size, int protect, void* process)
    : base(base), offset(offset), size(size), protect(protect), process(process) {
    // Constructor
}

// FileMap implementation
uint32_t FileMap::curr_handle = 0x280;

FileMap::FileMap(const std::string& name, size_t size, int prot, void* backed_file)
    : name(name), backed_file(backed_file), size(size), prot(prot) {
    // Constructor
}

uint32_t FileMap::get_handle() {
    uint32_t hmap = FileMap::curr_handle;
    FileMap::curr_handle += 4;
    return hmap;
}

std::string FileMap::get_name() {
    return name;
}

int FileMap::get_prot() {
    return prot;
}

void* FileMap::get_backed_file() {
    return backed_file;
}

void FileMap::add_view(uint64_t base, uint64_t offset, size_t size, int protect) {
    std::shared_ptr<MapView> view = std::make_shared<MapView>(base, offset, size, protect);
    views[base] = view;
}

// File implementation
uint32_t File::curr_handle = 0x80;

// TODO: Replace with nlohmann::json parameter
// File::File(const std::string& path, const nlohmann::json& config, const std::vector<uint8_t>& data)
File::File(const std::string& path, const std::map<std::string, std::string>& config, 
           const std::vector<uint8_t>& data)
    : path(path), bytes_written(0), curr_offset(0), is_dir(false), config(config) {
    
    if (!data.empty()) {
        data = std::make_shared<std::stringstream>(std::string(data.begin(), data.end()));
    }
}

std::shared_ptr<File> File::duplicate() {
    std::vector<uint8_t> file_data;
    if (data) {
        std::string data_str = data->str();
        file_data = std::vector<uint8_t>(data_str.begin(), data_str.end());
    }
    
    std::shared_ptr<File> new_file = std::make_shared<File>(path, config, file_data);
    new_file->is_dir = is_dir;
    return new_file;
}

uint32_t File::get_handle() {
    uint32_t hfile = File::curr_handle;
    File::curr_handle += 4;
    return hfile;
}

std::string File::get_path() {
    return path;
}

std::string File::get_hash() {
    // TODO: Implementation depends on SHA256 hashing
    /*
    h = hashlib.sha256()
    data = this.get_data(reset_pointer=True)
    h.update(data)
    return h.hexdigest()
    */
    return "";
}

size_t File::get_size() {
    if (!data && !config.empty()) {
        data = handle_file_data();
    }
    if (!data) {
        return 0;
    }
    
    std::streampos off = data->tellg();
    data->seekg(0, std::ios::beg);
    size_t size = data->str().length();
    data->seekg(off, std::ios::beg);
    return size;
}

std::vector<uint8_t> File::get_data(int size, bool reset_pointer) {
    if (!data && !config.empty()) {
        data = handle_file_data();
    }

    if (!data) {
        return std::vector<uint8_t>();
    }

    std::streampos off = data->tellg();
    if (off == static_cast<std::streampos>(get_size())) {
        if (reset_pointer) {
            // Reset the file pointer
            data->seekg(0);
        } else {
            return std::vector<uint8_t>();
        }
    }

    std::string data_str = data->str();
    if (size == -1) {
        // Read all data
        std::string remaining_data = data_str.substr(off);
        return std::vector<uint8_t>(remaining_data.begin(), remaining_data.end());
    } else {
        // Read specified size
        std::string chunk = data_str.substr(off, size);
        return std::vector<uint8_t>(chunk.begin(), chunk.end());
    }
}

void File::seek(uint64_t offset, int whence) {
    // TODO: Implementation depends on stream positioning
    /*
    if whence not in [io.SEEK_CUR, io.SEEK_SET, io.SEEK_END]:
        return
    if this.data:
        this.data.seek(offset, whence)
    */
}

uint64_t File::tell() {
    if (data) {
        return data->tellg();
    }
    return 0; // TODO: Should return None equivalent
}

void File::add_data(const std::vector<uint8_t>& data_to_add) {
    if (!data) {
        data = std::make_shared<std::stringstream>();
    }
    
    std::streampos off = data->tellg();
    data->seekg(0, std::ios::end);
    
    std::string data_str(data_to_add.begin(), data_to_add.end());
    *data << data_str;
    
    data->seekg(off, std::ios::beg);
    bytes_written += data_to_add.size();
}

void File::remove_data() {
    data = std::make_shared<std::stringstream>("");
}

bool File::is_directory() {
    return is_dir;
}

std::shared_ptr<std::stringstream> File::handle_file_data() {
    /*
    Based on the emulation config, determine what data
    to return from the read request
    */
    // TODO: Implementation depends on config structure
    /*
    path = this.config.get('path')
    if path:
        path = normalize_response_path(path)
        with open(path, 'rb') as f:
            return io.BytesIO(f.read())
    bf = this.config.get('byte_fill')
    if bf:
        byte = bf.get('byte')
        if byte.startswith('0x'):
            byte = 0xFF & int(byte, 0)
        else:
            byte = 0xFF & int(byte, 16)
        size = bf.get('size')
        b = (byte).to_bytes(1, 'little')
        return b * size
    return io.BytesIO(b'')
    */
    return std::make_shared<std::stringstream>("");
}

// Pipe implementation
uint32_t Pipe::curr_handle = 0x400;

// TODO: Replace with nlohmann::json parameter
// Pipe::Pipe(const std::string& name, const std::string& mode, int num_instances, 
//            size_t out_size, size_t in_size, const nlohmann::json& config)
Pipe::Pipe(const std::string& name, const std::string& mode, int num_instances, 
           size_t out_size, size_t in_size, const std::map<std::string, std::string>& config)
    : File(name, config), name(name), mode(mode), num_instances(num_instances), 
      out_size(out_size), in_size(in_size) {
    
    // super(Pipe, this).__init__(path=name, config=config)
}

uint32_t Pipe::get_handle() {
    uint32_t hpipe = Pipe::curr_handle;
    Pipe::curr_handle += 4;
    return hpipe;
}

// FileManager implementation
// TODO: Replace with nlohmann::json parameter
// FileManager::FileManager(const nlohmann::json& config, void* emu) : config(config), emu(emu) {
FileManager::FileManager(const std::map<std::string, std::string>& config, void* emu) 
    : config(config), emu(emu) {
    
    // super(FileManager, this).__init__()
    
    // TODO: Implementation depends on config structure
    /*
    // "files" key of config
    this.file_config = this.config.get('filesystem', {})
    
    cmdline = this.config.get('command_line')

    if cmdline is None:
        cmdline = ""

    this.emulated_binname = shlex.split(cmdline)[0]

    // First file in this list seems to always be the module itself
    this.files = []
    */
}

uint32_t FileManager::file_create_mapping(uint32_t hfile, const std::string& name, size_t size, int prot) {
    // TODO: Implementation depends on windefs constants
    /*
    if hfile not in (windefs.INVALID_HANDLE_VALUE, 0):
        f = this.get_file_from_handle(hfile)
        fm = FileMap(name, size, prot, f)
        hnd = fm.get_handle()
        this.file_maps.update({hnd: fm})
        return hnd
    else:
        fm = FileMap(name, size, prot, None)
        hnd = fm.get_handle()
        this.file_maps.update({hnd: fm})
        return hnd
    */
    return 0;
}

// TODO: Replace with appropriate iterator for JSON
// nlohmann::json::iterator FileManager::walk_files() {
std::vector<std::map<std::string, std::string>>::iterator FileManager::walk_files() {
    // TODO: Implementation depends on file_config structure
    /*
    for f in this.file_config.get('files', []):
        path = f.get('emu_path')
        if not path:
            continue
        yield path
    */
    // Return begin iterator as placeholder
    static std::vector<std::map<std::string, std::string>> dummy_files;
    return dummy_files.begin();
}

std::vector<std::shared_ptr<File>> FileManager::get_dropped_files() {
    // TODO: Implementation depends on file tracking
    /*
    return [f for f in this.files if f.bytes_written == f.get_size()]
    */
    return std::vector<std::shared_ptr<File>>();
}

std::shared_ptr<FileMap> FileManager::get_mapping_from_handle(uint32_t handle) {
    auto it = file_maps.find(handle);
    if (it != file_maps.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<FileMap> FileManager::get_mapping_from_addr(uint64_t addr) {
    for (auto& pair : file_maps) {
        auto& fmap = pair.second;
        for (auto& view_pair : fmap->views) {
            auto& base = view_pair.first;
            if (base == addr) {
                return fmap;
            }
        }
    }
    return nullptr;
}

std::shared_ptr<File> FileManager::get_file_from_handle(uint32_t handle) {
    auto it = file_handles.find(handle);
    if (it != file_handles.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<Pipe> FileManager::get_pipe_from_handle(uint32_t handle) {
    auto it = pipe_handles.find(handle);
    if (it != pipe_handles.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<File> FileManager::get_file_from_path(const std::string& path) {
    // TODO: Implementation depends on emulated_binname
    /*
    // The emulated sample is requesting itself. The module path
    // for it is(?) always the first entry in this.files
    if this.emulated_binname in path:
        return this.files[0]

    for f in this.files:
        if f.get_path().lower() == path.lower():
            return f
    return None
    */
    return nullptr;
}

std::vector<std::shared_ptr<File>> FileManager::get_all_files() {
    return files;
}

// TODO: Replace with nlohmann::json parameter
// std::vector<uint8_t> FileManager::handle_file_data(const nlohmann::json& fconf) {
std::vector<uint8_t> FileManager::handle_file_data(const std::map<std::string, std::string>& fconf) {
    // TODO: Implementation depends on file configuration
    /*
    path = fconf.get('path')
    if path:
        path = normalize_response_path(path)
        with open(path, 'rb') as f:
            return f.read()
    bf = fconf.get('byte_fill')
    if bf:
        byte = bf.get('byte')
        if byte.startswith('0x'):
            byte = 0xFF & int(byte, 0)
        else:
            byte = 0xFF & int(byte, 16)
        size = bf.get('size')
        b = (byte).to_bytes(1, 'little')
        return b * size
    */
    return std::vector<uint8_t>();
}

std::shared_ptr<File> FileManager::add_existing_file(const std::string& path, 
                                                     const std::vector<uint8_t>& data) {
    /*
    Register an existing file already included in the emulation space
    (with data)
    */
    std::shared_ptr<File> f = std::make_shared<File>(path, std::map<std::string, std::string>(), data);
    files.push_back(f);
    return f;
}

std::shared_ptr<File> FileManager::create_file(const std::string& path) {
    // TODO: Implementation depends on file management
    /*
    f = this.get_file_from_path(path)
    if f:
        this.files.remove(f)
    f = File(path)
    this.files.append(f)
    return f
    */
    std::shared_ptr<File> f = std::make_shared<File>(path);
    files.push_back(f);
    return f;
}

bool FileManager::delete_file(const std::string& path) {
    // TODO: Implementation depends on file management
    /*
    f = this.get_file_from_path(path)
    if f:
        this.files.remove(f)
        return True
    return False
    */
    return false;
}

// TODO: Replace with nlohmann::json return type
// nlohmann::json* FileManager::get_emu_file(const std::string& path) {
std::map<std::string, std::string>* FileManager::get_emu_file(const std::string& path) {
    // TODO: Implementation depends on file configuration and pattern matching
    /*
    // Does this file exist in our emulation environment
    // See if we have a handler for this exact file
    for f in this.file_config.get('files', []):
        mode = f.get('mode')
        if mode == 'full_path':
            if fnmatch.fnmatch(path.lower(), f.get('emu_path').lower()):
                return f

    all_modules = this.config.get('modules')

    if this.emu.arch == _arch.ARCH_X86:
        decoy_dir = all_modules.get('module_directory_x86', [])
    else:
        decoy_dir = all_modules.get('module_directory_x64', [])

    ext = os.path.splitext(path)[1]

    // Check if we can load the contents of a decoy DLL
    for f in all_modules.get('user_modules', []):
        if f.get('path') == path:
            newconf = dict()
            newconf['path'] = os.path.join(decoy_dir, f.get('name') + ext)
            return newconf

    for f in all_modules.get('system_modules', []):
        if f.get('path') == path:
            newconf = dict()
            newconf['path'] = os.path.join(decoy_dir, f.get('name') + ext)
            return newconf

    // If no full path handler exists, do we have an extension handler?
    for f in this.file_config.get('files', []):
        path_ext = ntpath.splitext(path)[-1:][0].strip('.')
        if path_ext:
            mode = f.get('mode')
            if mode == 'by_ext':
                if path_ext.lower() == f.get('ext'):
                    return f

    // Finally, do we have a catch-all default handler?
    for f in this.file_config.get('files', []):

        mode = f.get('mode')
        if mode == 'default':
            return f
    return None
    */
    return nullptr;
}

uint32_t FileManager::pipe_open(const std::string& path, const std::string& mode, 
                                int num_instances, size_t out_size, size_t in_size) {
    uint32_t hnd = 0;
    // TODO: Replace with nlohmann::json return type
    // nlohmann::json* fconf = get_emu_file(path);
    std::map<std::string, std::string>* fconf = get_emu_file(path);
    
    if (!fconf) {
        return hnd;
    }
    
    // TODO: Implementation depends on config structure
    /*
    p = Pipe(path, mode, num_instances, out_size, in_size, config=fconf)
    hnd = p.get_handle()
    this.pipe_handles.update({hnd: p})
    return hnd
    */
    return hnd;
}

bool FileManager::does_file_exist(const std::string& path) {
    if (get_file_from_path(path)) {
        return true;
    }

    if (get_emu_file(path)) {
        return true;
    }
    return false;
}

void* FileManager::get_object_from_handle(uint32_t handle) {
    auto obj_it = file_maps.find(handle);
    if (obj_it != file_maps.end()) {
        return obj_it->second.get();
    }
    
    auto pipe_it = pipe_handles.find(handle);
    if (pipe_it != pipe_handles.end()) {
        return pipe_it->second.get();
    }
    
    auto file_it = file_handles.find(handle);
    if (file_it != file_handles.end()) {
        return file_it->second.get();
    }
    
    return nullptr;
}

uint32_t FileManager::file_open(const std::string& path, bool create, bool truncate, bool is_dir) {
    uint32_t hnd = 0;

    if (create) {
        // TODO: Implementation depends on file management
        /*
        f = this.create_file(path)
        hnd = f.get_handle()
        this.file_handles.update({hnd: f})
        */
    } else {
        // TODO: Implementation depends on file management
        /*
        f = this.get_file_from_path(path)

        if f:
            // Deep-copy this file so we can have separate file
            // offset pointers
            dup = f.duplicate()
            hnd = dup.get_handle()
            this.file_handles.update({hnd: dup})
            return hnd

        fconf = this.get_emu_file(path)
        if not fconf:
            return hnd

        real_path = fconf.get('path', '')
        real_path = normalize_response_path(real_path)
        if not truncate:
            if real_path and not os.path.exists(real_path):
                raise FileSystemEmuError('File path not found: %s' % (real_path))
            f = File(path, config=fconf)
            this.files.append(f)
        else:
            if real_path and not os.path.exists(real_path):
                raise FileSystemEmuError('File path not found: %s' % (real_path))
            f = File(path, config=fconf)
            this.files.append(f)
        hnd = f.get_handle()
        this.file_handles.update({hnd: f})
        */
    }

    return hnd;
}