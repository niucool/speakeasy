// netman.h
#ifndef NETMAN_H
#define NETMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <sstream>

// TODO: Need C++ equivalents for these Python imports
// #include <nlohmann/json.hpp>
// #include <speakeasy/errors.h>

// Forward declarations
class Socket;
class WSKSocket;
class WininetComponent;
class WininetRequest;
class WininetSession;
class WininetInstance;
class NetworkManager;

// Helper functions
bool is_empty(std::shared_ptr<std::stringstream> bio);
std::string normalize_response_path(const std::string& path);

// Represents a Windows network socket
class Socket {
protected:
    int fd;
    int family;
    int type;
    int protocol;
    uint32_t flags;
    std::string connected_host;
    int connected_port;
    std::shared_ptr<std::stringstream> curr_packet;
    std::vector<std::shared_ptr<std::stringstream>> packet_queue;

public:
    // Constructor
    Socket(int fd, int family, int stype, int protocol, uint32_t flags);
    
    // Methods
    int get_fd();
    int get_type();
    void set_connection_info(const std::string& host, int port);
    std::tuple<std::string, int> get_connection_info();
    void fill_recv_queue(/* TODO: Replace with nlohmann::json parameter */ const std::vector<std::map<std::string, std::string>>& responses);
    std::vector<uint8_t> get_recv_data(size_t size, bool peek = false);
};

// Represents a WSK socket used in kernel mode applications
class WSKSocket : public Socket {
public:
    // Constructor
    WSKSocket(int fd, int family, int stype, int protocol, uint32_t flags);
};

// Base class used for WinInet connections
class WininetComponent {
protected:
    static uint32_t curr_handle;
    // TODO: Replace with nlohmann::json or appropriate JSON type
    // static nlohmann::json config;
    static std::map<std::string, std::string> config;
    uint32_t handle;

public:
    // Constructor
    WininetComponent();
    
    // Methods
    uint32_t new_handle();
    uint32_t get_handle();
};

// WinInet request object
class WininetRequest : public WininetComponent {
private:
    std::string verb;
    // TODO: Replace with appropriate URL parsing class
    // urlparse objname;
    std::string objname;
    std::string ver;
    std::string referrer;
    std::vector<std::string> accept_types;
    std::vector<std::string> flags;
    uint32_t ctx;
    std::shared_ptr<std::stringstream> response;
    std::shared_ptr<WininetSession> session;

public:
    // Constructor
    WininetRequest(std::shared_ptr<WininetSession> session, const std::string& verb, 
                   const std::string& objname, const std::string& ver, const std::string& ref, 
                   const std::vector<std::string>& accepts, const std::vector<std::string>& flags, 
                   uint32_t ctx);
    
    // Methods
    std::shared_ptr<WininetSession> get_session();
    std::string get_server();
    int get_port();
    std::shared_ptr<WininetInstance> get_instance();
    bool is_secure();
    std::string format_http_request(const std::string& headers = "");
    size_t get_response_size();
    std::shared_ptr<std::stringstream> get_response();
    std::string get_object_path();
};

// WinInet session object
class WininetSession : public WininetComponent {
private:
    std::string server;
    int port;
    std::string user;
    std::string password;
    int service;
    std::vector<std::string> flags;
    uint32_t ctx;
    std::map<uint32_t, std::shared_ptr<WininetRequest>> requests;
    std::shared_ptr<WininetInstance> instance;

public:
    // Constructor
    WininetSession(std::shared_ptr<WininetInstance> instance, const std::string& server, 
                   int port, const std::string& user, const std::string& password, 
                   int service, const std::vector<std::string>& flags, uint32_t ctx);
    
    // Methods
    std::shared_ptr<WininetInstance> get_instance();
    std::vector<std::string> get_flags();
    std::shared_ptr<WininetRequest> new_request(const std::string& verb, 
                                                const std::string& objname, 
                                                const std::string& ver, 
                                                const std::string& ref, 
                                                const std::vector<std::string>& accepts, 
                                                const std::vector<std::string>& flags, 
                                                uint32_t ctx);
    
    // Getters
    std::string get_server() const { return server; }
    int get_port() const { return port; }
};

// WinInet instance object
class WininetInstance : public WininetComponent {
private:
    std::string user_agent;
    int access;
    std::string proxy;
    std::string bypass;
    uint32_t flags;
    std::map<uint32_t, std::shared_ptr<WininetSession>> sessions;

public:
    // Constructor
    WininetInstance(const std::string& user_agent, int access, const std::string& proxy, 
                    const std::string& bypass, uint32_t flags);
    
    // Methods
    std::shared_ptr<WininetSession> get_session(uint32_t sess_handle);
    void add_session(uint32_t handle, std::shared_ptr<WininetSession> session);
    std::shared_ptr<WininetSession> new_session(const std::string& server, int port, 
                                                const std::string& user, 
                                                const std::string& password, 
                                                int service, 
                                                const std::vector<std::string>& flags, 
                                                uint32_t ctx);
    std::string get_user_agent();
};

// Class that manages network connections during emulation
class NetworkManager {
private:
    std::map<int, std::shared_ptr<Socket>> sockets;
    std::map<uint32_t, std::shared_ptr<WininetInstance>> wininets;
    int curr_fd;
    uint32_t curr_handle;
    // TODO: Replace with nlohmann::json or appropriate JSON type
    // nlohmann::json config;
    std::map<std::string, std::string> config;
    // TODO: Replace with appropriate DNS configuration structure
    // nlohmann::json dns;
    std::map<std::string, std::string> dns;

public:
    // Constructor
    // TODO: Replace with nlohmann::json parameter
    // NetworkManager(const nlohmann::json& config);
    NetworkManager(const std::map<std::string, std::string>& config);
    
    // Methods
    std::shared_ptr<Socket> new_socket(int family, int stype, int protocol, uint32_t flags);
    std::string name_lookup(const std::string& domain);
    std::vector<uint8_t> get_dns_txt(const std::string& domain);
    std::string ip_lookup(const std::string& ip);
    std::shared_ptr<WininetInstance> new_wininet_inst(const std::string& user_agent, 
                                                      int access, const std::string& proxy, 
                                                      const std::string& bypass, uint32_t flags);
    void* get_wininet_object(uint32_t handle);
    void close_wininet_object(uint32_t handle);
    std::shared_ptr<Socket> get_socket(int fd);
    void close_socket(int fd);
};

#endif // NETMAN_H