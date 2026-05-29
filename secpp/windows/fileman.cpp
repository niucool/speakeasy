// fileman.cpp
#include "fileman.h"
#include "../binemu.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "picosha2.h"

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

// Path resolution helpers
static bool is_absolute(const std::string& path) {
    if (path.length() >= 2 && path[1] == ':') {
        return true;
    }
    if (path.length() >= 1 && (path[0] == '\\' || path[0] == '/')) {
        return true;
    }
    return false;
}

static std::string clean_path(const std::string& p) {
    std::string clean;
    for (char c : p) {
        clean.push_back((c == '/') ? '\\' : c);
    }
    std::string res;
    bool is_unc = (clean.rfind("\\\\", 0) == 0);
    size_t i = 0;
    if (is_unc) {
        res = "\\\\";
        i = 2;
    }
    for (; i < clean.length(); ++i) {
        if (clean[i] == '\\' && !res.empty() && res.back() == '\\') {
            continue;
        }
        res.push_back(clean[i]);
    }
    return res;
}

static bool wildcard_match(const std::string& pat, const std::string& str) {
    size_t n = pat.length(), m = str.length();
    size_t i = 0, j = 0, asterisk = -1, match = 0;
    while (j < m) {
        if (i < n && (pat[i] == '?' || tolower(pat[i]) == tolower(str[j]))) {
            i++;
            j++;
        } else if (i < n && pat[i] == '*') {
            asterisk = i++;
            match = j;
        } else if (asterisk != -1) {
            i = asterisk + 1;
            j = ++match;
        } else {
            return false;
        }
    }
    while (i < n && pat[i] == '*') {
        i++;
    }
    return i == n;
}

// MapView implementation
MapView::MapView(uint64_t base, uint64_t offset, size_t size, int protect, void* process)
    : base(base), offset(offset), size(size), protect(protect), process(process) {
    // Constructor
}

// FileMap implementation
//int FileMap::curr_handle = 0x280;

FileMap::FileMap(void* emu, const std::string& name, size_t size, int prot, void* backed_file)
    : KernelObject(emu), name_(name), backed_file_(backed_file), size_(size), prot_(prot) {
    // Constructor
}

std::string FileMap::get_name() {
    return name_;
}

int FileMap::get_prot() {
    return prot_;
}

void* FileMap::get_backed_file() {
    return backed_file_;
}

void FileMap::add_view(uint64_t base, uint64_t offset, size_t size, int protect) {
    std::shared_ptr<MapView> view = std::make_shared<MapView>(base, offset, size, protect);
    views_[base] = view;
}

// File implementation
//int File::curr_handle = 0x80;

File::File(void* emu, const std::string& path, const std::map<std::string, std::string>& config, 
           const std::vector<uint8_t>& data)
    : KernelObject(emu), path_(path), bytes_written_(0), curr_offset_(0), is_dir_(false), config_(config) {
    
    if (!data.empty()) {
        this->data_ = std::make_shared<std::stringstream>(std::string(data.begin(), data.end()));
    }
}

std::shared_ptr<File> File::duplicate() {
    std::vector<uint8_t> file_data;
    if (data_) {
        std::string data_str = data_->str();
        file_data = std::vector<uint8_t>(data_str.begin(), data_str.end());
    }
    
    std::shared_ptr<File> new_file = std::make_shared<File>(emu_, path_, config_, file_data);
    new_file->is_dir_ = is_dir_;
    return new_file;
}

std::string File::get_path() {
    return path_;
}

std::string File::get_hash() {
    auto d = get_data(-1, true);
    return picosha2::hash256_hex_string(d.begin(), d.end());
}

size_t File::get_size() {
    if (!data_ && !config_.empty()) {
        data_ = handle_file_data();
    }
    if (!data_) {
        return 0;
    }
    
    std::streampos off = data_->tellg();
    data_->seekg(0, std::ios::beg);
    size_t size = data_->str().length();
    data_->seekg(off, std::ios::beg);
    return size;
}

std::vector<uint8_t> File::get_data(int size, bool reset_pointer) {
    if (!data_ && !config_.empty()) {
        data_ = handle_file_data();
    }

    if (!data_) {
        return std::vector<uint8_t>();
    }

    std::streampos off = data_->tellg();
    if (off == static_cast<std::streampos>(get_size())) {
        if (reset_pointer) {
            // Reset the file pointer
            data_->seekg(0);
        } else {
            return std::vector<uint8_t>();
        }
    }

    std::string data_str = data_->str();
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
    if (!data_) return;
    std::ios::seekdir dir = std::ios::beg;
    if (whence == 1) dir = std::ios::cur;
    else if (whence == 2) dir = std::ios::end;
    data_->seekg((int32_t)offset, dir);
}

uint64_t File::tell() {
    if (data_) {
        return data_->tellg();
    }
    return 0;
}

void File::add_data(const std::vector<uint8_t>& data_to_add) {
    if (!data_) {
        data_ = std::make_shared<std::stringstream>();
    }
    
    std::streampos off = data_->tellg();
    data_->seekg(0, std::ios::end);
    
    std::string data_str(data_to_add.begin(), data_to_add.end());
    *data_ << data_str;
    
    data_->seekg(off, std::ios::beg);
    bytes_written_ += data_to_add.size();
}

void File::remove_data() {
    data_ = std::make_shared<std::stringstream>("");
}

bool File::is_directory() {
    return is_dir_;
}

std::shared_ptr<std::stringstream> File::handle_file_data() {
    auto pit = config_.find("path");
    if (pit != config_.end() && !pit->second.empty()) {
        std::string rpath = normalize_response_path(pit->second);
        std::ifstream f(rpath, std::ios::binary);
        if (f.is_open()) {
            auto* ss = new std::stringstream();
            *ss << f.rdbuf();
            return std::shared_ptr<std::stringstream>(ss);
        }
    }
    
    // Support byte_fill!
    auto bit = config_.find("byte_val");
    auto sit = config_.find("byte_fill_size");
    if (bit != config_.end() && sit != config_.end()) {
        std::string bval = bit->second;
        int sz = std::stoi(sit->second);
        if (sz > 0) {
            uint8_t byte = 0;
            if (bval.rfind("0x", 0) == 0) {
                byte = static_cast<uint8_t>(std::stoul(bval, nullptr, 16) & 0xFF);
            } else {
                byte = static_cast<uint8_t>(std::stoul(bval, nullptr, 10) & 0xFF);
            }
            std::string data_str(sz, static_cast<char>(byte));
            return std::make_shared<std::stringstream>(data_str);
        }
    }
    return std::make_shared<std::stringstream>("");
}

// Pipe implementation
//uint32_t Pipe::curr_handle_ = 0x400;

Pipe::Pipe(void* emu, const std::string& name, const std::string& mode, int num_instances, 
           size_t out_size, size_t in_size, const std::map<std::string, std::string>& config)
    : File(emu, name, config), name_(name), mode_(mode), num_instances_(num_instances), 
      out_size_(out_size), in_size_(in_size) {
    
}

// FileManager implementation
FileManager::FileManager(const speakeasy::SpeakeasyConfig& lconfig, void* emu)
    : config_(lconfig), emu_(emu) {
    std::string cmd = config_.command_line;
    auto space = cmd.find(' ');
    emulated_binname_ = (space != std::string::npos) ? cmd.substr(0, space) : cmd;
}

uint32_t FileManager::file_create_mapping(uint32_t hfile, const std::string& name, size_t size, int prot) {
    if (hfile != 0 && hfile != (uint32_t)-1) {
        auto f = get_file_from_handle(hfile);
        auto fm = std::make_shared<FileMap>(emu_, name, size, prot, f ? f.get() : nullptr);
        uint32_t hnd = fm->get_handle();
        file_maps_[hnd] = fm;
        return hnd;
    } else {
        auto fm = std::make_shared<FileMap>(emu_, name, size, prot, nullptr);
        uint32_t hnd = fm->get_handle();
        file_maps_[hnd] = fm;
        return hnd;
    }
}

std::vector<std::string> FileManager::walk_files() {
    std::vector<std::string> paths;
    for (const auto& f : config_.filesystem.files) {
        if (!f.emu_path.empty()) {
            paths.push_back(f.emu_path);
        }
    }
    return paths;
}

std::vector<std::shared_ptr<File>> FileManager::get_dropped_files() {
    std::vector<std::shared_ptr<File>> dropped;
    for (auto& f : files_) {
        if (f->get_size() > 0) dropped.push_back(f);
    }
    return dropped;
}

std::shared_ptr<FileMap> FileManager::get_mapping_from_handle(uint32_t handle) {
    auto it = file_maps_.find(handle);
    if (it != file_maps_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<FileMap> FileManager::get_mapping_from_addr(uint64_t addr) {
    for (auto& pair : file_maps_) {
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
    auto it = file_handles_.find(handle);
    if (it != file_handles_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<Pipe> FileManager::get_pipe_from_handle(uint32_t handle) {
    auto it = pipe_handles_.find(handle);
    if (it != pipe_handles_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<File> FileManager::get_file_from_path(const std::string& path) {
    if (!files_.empty() && !emulated_binname_.empty() &&
        path.find(emulated_binname_) != std::string::npos)
        return files_[0];

    std::string norm_path = path;
    if (!is_absolute(norm_path)) {
        std::string cwd = config_.current_dir;
        if (!cwd.empty() && cwd.back() != '\\' && cwd.back() != '/') {
            cwd += "\\";
        }
        norm_path = cwd + norm_path;
    }
    norm_path = clean_path(norm_path);
    std::string norm_path_lower = norm_path;
    std::transform(norm_path_lower.begin(), norm_path_lower.end(), norm_path_lower.begin(), ::tolower);

    for (auto& f : files_) {
        std::string fpath = f->get_path();
        fpath = clean_path(fpath);
        std::transform(fpath.begin(), fpath.end(), fpath.begin(), ::tolower);
        if (fpath == norm_path_lower) return f;
    }
    return nullptr;
}

std::vector<std::shared_ptr<File>> FileManager::get_all_files() {
    return files_;
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

    // Support byte_fill!
    auto bit = fconf.find("byte_val");
    auto sit = fconf.find("byte_fill_size");
    if (bit != fconf.end() && sit != fconf.end()) {
        std::string bval = bit->second;
        int sz = std::stoi(sit->second);
        if (sz > 0) {
            uint8_t byte = 0;
            if (bval.rfind("0x", 0) == 0) {
                byte = static_cast<uint8_t>(std::stoul(bval, nullptr, 16) & 0xFF);
            } else {
                byte = static_cast<uint8_t>(std::stoul(bval, nullptr, 10) & 0xFF);
            }
            return std::vector<uint8_t>(sz, byte);
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
    std::shared_ptr<File> f = std::make_shared<File>(emu_, path, std::map<std::string, std::string>(), data);
    files_.push_back(f);
    return f;
}

std::shared_ptr<File> FileManager::create_file(const std::string& path) {
    auto existing = get_file_from_path(path);
    if (existing) {
        files_.erase(std::remove(files_.begin(), files_.end(), existing), files_.end());
    }
    auto f = std::make_shared<File>(emu_, path);
    files_.push_back(f);
    return f;
}

bool FileManager::delete_file(const std::string& path) {
    auto f = get_file_from_path(path);
    if (f) {
        files_.erase(std::remove(files_.begin(), files_.end(), f), files_.end());
        return true;
    }
    return false;
}

std::map<std::string, std::string>* FileManager::get_emu_file(const std::string& path) {
    // Resolve relative paths against the current directory
    std::string norm_path = path;
    if (!is_absolute(norm_path)) {
        std::string cwd = config_.current_dir;
        if (!cwd.empty() && cwd.back() != '\\' && cwd.back() != '/') {
            cwd += "\\";
        }
        norm_path = cwd + norm_path;
    }
    // Clean canonical windows path
    norm_path = clean_path(norm_path);

    // See if we have a handler for this exact file in config
    for (const auto& f : config_.filesystem.files) {
        if (f.mode == "full_path") {
            if (wildcard_match(f.emu_path, norm_path)) {
                // Populate/create a map entry in our cache and return a pointer
                std::map<std::string, std::string> entry;
                entry["path"] = f.path;
                entry["byte_val"] = f.byte_fill.byte_val;
                entry["byte_fill_size"] = std::to_string(f.byte_fill.size);
                entry["mode"] = f.mode;
                entry["emu_path"] = f.emu_path;
                emu_file_configs_[norm_path] = entry;
                return &emu_file_configs_[norm_path];
            }
        }
    }

    // Check if we can load the contents of a decoy DLL
    std::string decoy_dir;
    int arch = static_cast<BinaryEmulator*>(emu_)->get_arch();
    if (arch == speakeasy::arch::ARCH_X86) {
        decoy_dir = config_.modules.module_directory_x86;
    } else {
        decoy_dir = config_.modules.module_directory_x64;
    }

    // Get extension of norm_path
    std::string ext;
    size_t dot = norm_path.rfind('.');
    if (dot != std::string::npos) {
        ext = norm_path.substr(dot);
    }

    // User modules
    for (const auto& m : config_.modules.user_modules) {
        if (wildcard_match(m->path, norm_path)) {
            std::map<std::string, std::string> entry;
            std::string ddir = decoy_dir;
            if (!ddir.empty() && ddir.back() != '\\' && ddir.back() != '/') {
                ddir += "\\";
            }
            entry["path"] = ddir + m->name + ext;
            emu_file_configs_[norm_path] = entry;
            return &emu_file_configs_[norm_path];
        }
    }

    // System modules
    for (const auto& m : config_.modules.system_modules) {
        if (wildcard_match(m->path, norm_path)) {
            std::map<std::string, std::string> entry;
            std::string ddir = decoy_dir;
            if (!ddir.empty() && ddir.back() != '\\' && ddir.back() != '/') {
                ddir += "\\";
            }
            entry["path"] = ddir + m->name + ext;
            emu_file_configs_[norm_path] = entry;
            return &emu_file_configs_[norm_path];
        }
    }

    // If no full path handler exists, do we have an extension handler?
    std::string ext_name = (ext.length() > 1) ? ext.substr(1) : "";
    while (!ext_name.empty() && ext_name.back() == '.') ext_name.pop_back();

    for (const auto& f : config_.filesystem.files) {
        if (f.mode == "by_ext") {
            std::string ext_lower = ext_name;
            std::transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(), ::tolower);
            std::string f_ext_lower = f.ext;
            std::transform(f_ext_lower.begin(), f_ext_lower.end(), f_ext_lower.begin(), ::tolower);
            if (ext_lower == f_ext_lower) {
                std::map<std::string, std::string> entry;
                entry["path"] = f.path;
                entry["byte_val"] = f.byte_fill.byte_val;
                entry["byte_fill_size"] = std::to_string(f.byte_fill.size);
                entry["mode"] = f.mode;
                entry["emu_path"] = f.emu_path;
                emu_file_configs_[norm_path] = entry;
                return &emu_file_configs_[norm_path];
            }
        }
    }

    // Finally, do we have a catch-all default handler?
    for (const auto& f : config_.filesystem.files) {
        if (f.mode == "default") {
            std::map<std::string, std::string> entry;
            entry["path"] = f.path;
            entry["byte_val"] = f.byte_fill.byte_val;
            entry["byte_fill_size"] = std::to_string(f.byte_fill.size);
            entry["mode"] = f.mode;
            entry["emu_path"] = f.emu_path;
            emu_file_configs_[norm_path] = entry;
            return &emu_file_configs_[norm_path];
        }
    }

    return nullptr;
}

uint32_t FileManager::pipe_open(const std::string& path, const std::string& mode, 
                                int num_instances, size_t out_size, size_t in_size) {
    auto fconf = get_emu_file(path);
    std::map<std::string, std::string> cfg;
    if (fconf) cfg = *fconf;
    auto p = std::make_shared<Pipe>(emu_, path, mode, num_instances, out_size, in_size, cfg);
    uint32_t hnd = p->get_handle();
    pipe_handles_[hnd] = p;
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

std::shared_ptr<KernelObject> FileManager::get_object_from_handle(uint32_t handle) {
    auto obj_it = file_maps_.find(handle);
    if (obj_it != file_maps_.end()) {
        return obj_it->second;
    }
    
    auto pipe_it = pipe_handles_.find(handle);
    if (pipe_it != pipe_handles_.end()) {
        return pipe_it->second;
    }
    
    auto file_it = file_handles_.find(handle);
    if (file_it != file_handles_.end()) {
        return file_it->second;
    }
    
    return nullptr;
}

uint32_t FileManager::file_open(const std::string& path, bool create, bool truncate, bool is_dir) {
    uint32_t hnd = 0;
    (void)truncate; (void)is_dir;
    if (create) {
        auto f = create_file(path);
        hnd = f->get_handle();
        file_handles_[hnd] = f;
    } else {
        auto f = get_file_from_path(path);
        if (f) {
            auto dup = f->duplicate();
            hnd = dup->get_handle();
            file_handles_[hnd] = dup;
            return hnd;
        }
        auto fconf = get_emu_file(path);
        if (!fconf) return hnd;
        auto newf = std::make_shared<File>(emu_, path, *fconf);
        files_.push_back(newf);
        hnd = newf->get_handle();
        file_handles_[hnd] = newf;
    }
    return hnd;
}