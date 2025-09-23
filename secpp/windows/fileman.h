// fileman.h
#ifndef FILEMAN_H
#define FILEMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <sstream>

// TODO: Need C++ equivalents for these Python imports
// #include <nlohmann/json.hpp>
// #include <speakeasy/winenv/defs/windows/windows.h>
// #include <speakeasy/winenv/arch.h>
// #include <speakeasy/errors.h>

// Forward declarations
class MapView;
class FileMap;
class File;
class Pipe;
class FileManager;

// Helper function to normalize response path
std::string normalize_response_path(const std::string& path);

// Represents a shared memory view
class MapView {
public:
    uint64_t base;
    uint64_t offset;
    size_t size;
    int protect;
    void* process; // TODO: Should be Process* or appropriate process type

    // Constructor
    MapView(uint64_t base, uint64_t offset, size_t size, int protect, void* process = nullptr);
};

// Represents a memory mapped file
class FileMap {
private:
    static uint32_t curr_handle;
    std::string name;
    void* backed_file; // TODO: Should be File* or appropriate file type
    std::map<uint64_t, std::shared_ptr<MapView>> views;
    size_t size;
    int prot;

public:
    // Constructor
    FileMap(const std::string& name, size_t size, int prot, void* backed_file = nullptr);
    
    // Methods
    uint32_t get_handle();
    std::string get_name();
    int get_prot();
    void* get_backed_file();
    void add_view(uint64_t base, uint64_t offset, size_t size, int protect);
};

// Base class for an emulated file
class File {
protected:
    static uint32_t curr_handle;
    std::string path;
    std::shared_ptr<std::stringstream> data;
    size_t bytes_written;
    uint64_t curr_offset;
    bool is_dir;
    // TODO: Replace with nlohmann::json or appropriate JSON type
    // nlohmann::json config;
    std::map<std::string, std::string> config;

public:
    // Constructor
    // TODO: Replace with nlohmann::json parameter
    // File(const std::string& path, const nlohmann::json& config = nlohmann::json(), 
    //      const std::vector<uint8_t>& data = {});
    File(const std::string& path, const std::map<std::string, std::string>& config = {}, 
         const std::vector<uint8_t>& data = {});
    
    // Methods
    std::shared_ptr<File> duplicate();
    uint32_t get_handle();
    std::string get_path();
    std::string get_hash();
    size_t get_size();
    std::vector<uint8_t> get_data(int size = -1, bool reset_pointer = false);
    void seek(uint64_t offset, int whence);
    uint64_t tell();
    void add_data(const std::vector<uint8_t>& data);
    void remove_data();
    bool is_directory();
    std::shared_ptr<std::stringstream> handle_file_data();
};

// Emulated named pipe objects
class Pipe : public File {
private:
    static uint32_t curr_handle;
    std::string name;
    std::string mode;
    int num_instances;
    size_t out_size;
    size_t in_size;

public:
    // Constructor
    // TODO: Replace with nlohmann::json parameter
    // Pipe(const std::string& name, const std::string& mode, int num_instances, 
    //      size_t out_size, size_t in_size, const nlohmann::json& config = nlohmann::json());
    Pipe(const std::string& name, const std::string& mode, int num_instances, 
         size_t out_size, size_t in_size, const std::map<std::string, std::string>& config = {});
    
    // Methods
    uint32_t get_handle() override;
};

// Manages file system activity during emulation
class FileManager {
private:
    std::map<uint32_t, std::shared_ptr<File>> file_handles;
    std::map<uint32_t, std::shared_ptr<Pipe>> pipe_handles;
    std::map<uint32_t, std::shared_ptr<FileMap>> file_maps;

    // TODO: Replace with nlohmann::json or appropriate JSON type
    // nlohmann::json config;
    // nlohmann::json file_config;
    std::map<std::string, std::string> config;
    std::map<std::string, std::string> file_config;
    void* emu; // TODO: Should be WindowsEmulator* or appropriate emulator type
    std::string emulated_binname;
    std::vector<std::shared_ptr<File>> files;

public:
    // Constructor
    // TODO: Replace with nlohmann::json parameter
    // FileManager(const nlohmann::json& config, void* emu);
    FileManager(const std::map<std::string, std::string>& config, void* emu);
    
    // Methods
    uint32_t file_create_mapping(uint32_t hfile, const std::string& name, size_t size, int prot);
    
    // TODO: Replace with appropriate iterator for JSON
    // nlohmann::json::iterator walk_files();
    std::vector<std::map<std::string, std::string>>::iterator walk_files();
    
    std::vector<std::shared_ptr<File>> get_dropped_files();
    std::shared_ptr<FileMap> get_mapping_from_handle(uint32_t handle);
    std::shared_ptr<FileMap> get_mapping_from_addr(uint64_t addr);
    std::shared_ptr<File> get_file_from_handle(uint32_t handle);
    std::shared_ptr<Pipe> get_pipe_from_handle(uint32_t handle);
    std::shared_ptr<File> get_file_from_path(const std::string& path);
    std::vector<std::shared_ptr<File>> get_all_files();
    
    // TODO: Replace with nlohmann::json parameter
    // std::vector<uint8_t> handle_file_data(const nlohmann::json& fconf);
    std::vector<uint8_t> handle_file_data(const std::map<std::string, std::string>& fconf);
    
    std::shared_ptr<File> add_existing_file(const std::string& path, const std::vector<uint8_t>& data);
    std::shared_ptr<File> create_file(const std::string& path);
    bool delete_file(const std::string& path);
    
    // TODO: Replace with nlohmann::json return type
    // nlohmann::json* get_emu_file(const std::string& path);
    std::map<std::string, std::string>* get_emu_file(const std::string& path);
    
    uint32_t pipe_open(const std::string& path, const std::string& mode, int num_instances, 
                       size_t out_size, size_t in_size);
    bool does_file_exist(const std::string& path);
    void* get_object_from_handle(uint32_t handle);
    uint32_t file_open(const std::string& path, bool create = false, bool truncate = false, 
                       bool is_dir = false);
};

#endif // FILEMAN_H