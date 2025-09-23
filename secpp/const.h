// const.h
#ifndef SPEAKEASY_CONST_H
#define SPEAKEASY_CONST_H

#include <string>

// Process log constants
const std::string PROC_CREATE = "create";
const std::string MEM_ALLOC = "mem_alloc";
const std::string MEM_WRITE = "mem_write";
const std::string MEM_READ = "mem_read";
const std::string MEM_PROTECT = "mem_protect";
const std::string THREAD_INJECT = "thread_inject";
const std::string THREAD_CREATE = "thread_create";

// File log constants
const std::string FILE_CREATE = "create";
const std::string FILE_WRITE = "write";
const std::string FILE_OPEN = "open";
const std::string FILE_READ = "read";

// Registry log constants
const std::string REG_OPEN = "open_key";
const std::string REG_READ = "read_value";
const std::string REG_LIST = "list_subkeys";
const std::string REG_CREATE = "create_key";

#endif // SPEAKEASY_CONST_H