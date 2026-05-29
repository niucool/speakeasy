// fileman.h
#ifndef FILEMAN_H
#define FILEMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <sstream>

#include "../config.h"
#include "objman.h"

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
    void* process;

    // Constructor
    MapView(uint64_t base, uint64_t offset, size_t size, int protect, void* process = nullptr);
};

// Represents a memory mapped file
class FileMap : public KernelObject {
private:
    std::string name_;
    void* backed_file_;
    std::map<uint64_t, std::shared_ptr<MapView>> views_;
    size_t size_;
    int prot_;

public:
    // Constructor
    FileMap(void* emu, const std::string& name, size_t size, int prot, void* backed_file = nullptr);
    
    // Methods
    std::string get_name();
    int get_prot();
    void* get_backed_file();
    void add_view(uint64_t base, uint64_t offset, size_t size, int protect);
    std::map<uint64_t, std::shared_ptr<MapView>>& get_views() { return views_; }
};

// Base class for an emulated file
class File : public KernelObject {
protected:
    std::string path_;
    std::shared_ptr<std::stringstream> data_;
    size_t bytes_written_;
    uint64_t curr_offset_;
    bool is_dir_;
    std::map<std::string, std::string> config_;

public:
    // Constructor
    File(void* emu, const std::string& path, const std::map<std::string, std::string>& config = {}, 
         const std::vector<uint8_t>& data = {});
    
    // Methods
    std::shared_ptr<File> duplicate();
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
    static uint32_t curr_handle_;
    std::string name_;
    std::string mode_;
    int num_instances_;
    size_t out_size_;
    size_t in_size_;

public:
    // Constructor
    Pipe(void* emu, const std::string& name, const std::string& mode, int num_instances, 
         size_t out_size, size_t in_size, const std::map<std::string, std::string>& config = {});
    
};

// Manages file system activity during emulation
class FileManager {
private:
    std::map<uint32_t, std::shared_ptr<File>> file_handles_;
    std::map<uint32_t, std::shared_ptr<Pipe>> pipe_handles_;
    std::map<uint32_t, std::shared_ptr<FileMap>> file_maps_;

    const speakeasy::SpeakeasyConfig& config_;
    std::map<std::string, std::string> file_config_;
    void* emu_;
    std::string emulated_binname_;
    std::vector<std::shared_ptr<File>> files_;

    // Cache to store generated configurations for emulated files
    std::map<std::string, std::map<std::string, std::string>> emu_file_configs_;

public:
    // Constructor
    FileManager(const speakeasy::SpeakeasyConfig& config, void* emu);
    
    // Methods
    uint32_t file_create_mapping(uint32_t hfile, const std::string& name, size_t size, int prot);
    
    std::vector<std::string> walk_files();
    
    std::vector<std::shared_ptr<File>> get_dropped_files();
    std::shared_ptr<FileMap> get_mapping_from_handle(uint32_t handle);
    std::shared_ptr<FileMap> get_mapping_from_addr(uint64_t addr);
    std::shared_ptr<File> get_file_from_handle(uint32_t handle);
    std::shared_ptr<Pipe> get_pipe_from_handle(uint32_t handle);
    std::shared_ptr<File> get_file_from_path(const std::string& path);
    std::vector<std::shared_ptr<File>> get_all_files();
    
    std::vector<uint8_t> handle_file_data(const std::map<std::string, std::string>& fconf);
    
    std::shared_ptr<File> add_existing_file(const std::string& path, const std::vector<uint8_t>& data);
    std::shared_ptr<File> create_file(const std::string& path);
    bool delete_file(const std::string& path);
    
    std::map<std::string, std::string>* get_emu_file(const std::string& path);
    
    uint32_t pipe_open(const std::string& path, const std::string& mode, int num_instances, 
                       size_t out_size, size_t in_size);
    bool does_file_exist(const std::string& path);
    std::shared_ptr<KernelObject> get_object_from_handle(uint32_t handle);
    uint32_t file_open(const std::string& path, bool create = false, bool truncate = false, 
                       bool is_dir = false);
};

#endif // FILEMAN_H