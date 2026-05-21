// fileman.cpp
#include "fileman.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <picosha2.h>

// Helper function to normalize response path
std::string normalize_response_path(const std::string& path) {
    const std::string root_var = "$ROOT$";
    auto pos = path.find(root_var);
    if (pos != std::string::npos) {
        std::string result = path;
        result.replace(pos, root_var.length(), ".");
        return result;
    }
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

File::File(const std::string& path, const std::map<std::string, std::string>& config, 
           const std::vector<uint8_t>& data)
    : path(path), bytes_written(0), curr_offset(0), is_dir(false), config(config) {
    
    if (!data.empty()) {
        this->data = std::make_shared<std::stringstream>(std::string(data.begin(), data.end()));
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
    auto d = get_data(-1, true);
    return picosha2::hash256_hex_string(d.begin(), d.end());
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
    if (!data) return;
    std::ios::seekdir dir = std::ios::beg;
    if (whence == 1) dir = std::ios::cur;
    else if (whence == 2) dir = std::ios::end;
    data->seekg((int32_t)offset, dir);
}

uint64_t File::tell() {
    if (data) {
        return data->tellg();
    }
    return 0;
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
    auto pit = config.find("path");
    if (pit != config.end() && !pit->second.empty()) {
        std::string rpath = normalize_response_path(pit->second);
        std::ifstream f(rpath, std::ios::binary);
        if (f.is_open()) {
            auto* ss = new std::stringstream();
            *ss << f.rdbuf();
            return std::shared_ptr<std::stringstream>(ss);
        }
    }
    return std::make_shared<std::stringstream>("");
}

// Pipe implementation
uint32_t Pipe::curr_handle = 0x400;

Pipe::Pipe(const std::string& name, const std::string& mode, int num_instances, 
           size_t out_size, size_t in_size, const std::map<std::string, std::string>& config)
    : File(name, config), name(name), mode(mode), num_instances(num_instances), 
      out_size(out_size), in_size(in_size) {
    
}

uint32_t Pipe::get_handle() {
    uint32_t hpipe = Pipe::curr_handle;
    Pipe::curr_handle += 4;
    return hpipe;
}

// FileManager implementation
FileManager::FileManager(const speakeasy::SpeakeasyConfig& lconfig, void* emu)
    : config(lconfig), emu(emu) {
    std::string cmd = config.command_line;
    auto space = cmd.find(' ');
    emulated_binname = (space != std::string::npos) ? cmd.substr(0, space) : cmd;
}

uint32_t FileManager::file_create_mapping(uint32_t hfile, const std::string& name, size_t size, int prot) {
    if (hfile != 0 && hfile != (uint32_t)-1) {
        auto f = get_file_from_handle(hfile);
        auto fm = std::make_shared<FileMap>(name, size, prot, f.get());
        uint32_t hnd = fm->get_handle();
        file_maps[hnd] = fm;
        return hnd;
    } else {
        auto fm = std::make_shared<FileMap>(name, size, prot, nullptr);
        uint32_t hnd = fm->get_handle();
        file_maps[hnd] = fm;
        return hnd;
    }
}

std::vector<std::map<std::string, std::string>>::iterator FileManager::walk_files() {
    // walk_files requires JSON file_config
    static std::vector<std::map<std::string, std::string>> dummy;
    return dummy.begin();
}

std::vector<std::shared_ptr<File>> FileManager::get_dropped_files() {
    std::vector<std::shared_ptr<File>> dropped;
    for (auto& f : files) {
        if (f->get_size() > 0) dropped.push_back(f);
    }
    return dropped;
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
        for (auto& view_pair : fmap->get_views()) {
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
    if (!files.empty() && !emulated_binname.empty() &&
        path.find(emulated_binname) != std::string::npos)
        return files[0];
    std::string path_lower = path;
    std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(), ::tolower);
    for (auto& f : files) {
        std::string fpath = f->get_path();
        std::transform(fpath.begin(), fpath.end(), fpath.begin(), ::tolower);
        if (fpath == path_lower) return f;
    }
    return nullptr;
}

std::vector<std::shared_ptr<File>> FileManager::get_all_files() {
    return files;
}

std::vector<uint8_t> FileManager::handle_file_data(const std::map<std::string, std::string>& fconf) {
    auto pit = fconf.find("path");
    if (pit != fconf.end() && !pit->second.empty()) {
        std::string rpath = normalize_response_path(pit->second);
        std::ifstream f(rpath, std::ios::binary | std::ios::ate);
        if (f.is_open()) {
            size_t sz = f.tellg(); f.seekg(0);
            std::vector<uint8_t> buf(sz);
            f.read((char*)buf.data(), sz);
            return buf;
        }
    }
    return {};
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
    auto existing = get_file_from_path(path);
    if (existing) {
        files.erase(std::remove(files.begin(), files.end(), existing), files.end());
    }
    auto f = std::make_shared<File>(path);
    files.push_back(f);
    return f;
}

bool FileManager::delete_file(const std::string& path) {
    auto f = get_file_from_path(path);
    if (f) {
        files.erase(std::remove(files.begin(), files.end(), f), files.end());
        return true;
    }
    return false;
}

std::map<std::string, std::string>* FileManager::get_emu_file(const std::string& path) {
    (void)path;
    return nullptr;
}

uint32_t FileManager::pipe_open(const std::string& path, const std::string& mode, 
                                int num_instances, size_t out_size, size_t in_size) {
    auto fconf = get_emu_file(path);
    std::map<std::string, std::string> cfg;
    if (fconf) cfg = *fconf;
    auto p = std::make_shared<Pipe>(path, mode, num_instances, out_size, in_size, cfg);
    uint32_t hnd = p->get_handle();
    pipe_handles[hnd] = p;
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
    (void)truncate; (void)is_dir;
    if (create) {
        auto f = create_file(path);
        hnd = f->get_handle();
        file_handles[hnd] = f;
    } else {
        auto f = get_file_from_path(path);
        if (f) {
            auto dup = f->duplicate();
            hnd = dup->get_handle();
            file_handles[hnd] = dup;
            return hnd;
        }
        auto fconf = get_emu_file(path);
        if (!fconf) return hnd;
        auto newf = std::make_shared<File>(path, *fconf);
        files.push_back(newf);
        hnd = newf->get_handle();
        file_handles[hnd] = newf;
    }
    return hnd;
}