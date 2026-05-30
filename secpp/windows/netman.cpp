// netman.cpp
#include "netman.h"
#include "../helper.h"
#include "../common.h"
#include <algorithm>
#include <fstream>
#include <sstream>

// Helper functions
bool is_empty(std::shared_ptr<std::stringstream> bio) {
    if (!bio) return true;
    std::streampos current = bio->tellg();
    bio->seekg(0, std::ios::end);
    std::streampos end = bio->tellg();
    bio->seekg(current);
    return current == end;
}

//std::string normalize_response_path(const std::string& path) {
//    return normalize_package_path(path);
//}

// Static member initialization
uint32_t WininetComponent::curr_handle = 0x20;
// Static config  starts as null JSON object
speakeasy::NetworkConfig WininetComponent::config;

// Socket implementation
Socket::Socket(int fd, int family, int stype, int protocol, uint32_t flags)
    : fd(fd), family(family), type(stype), protocol(protocol), flags(flags),
      connected_port(0), curr_packet(std::make_shared<std::stringstream>()) {
    // Constructor
}

int Socket::get_fd() {
    return fd;
}

int Socket::get_type() {
    return type;
}

void Socket::set_connection_info(const std::string& host, int port) {
    connected_host = host;
    connected_port = port;
}

std::tuple<std::string, int> Socket::get_connection_info() {
    return std::make_tuple(connected_host, connected_port);
}

void Socket::fill_recv_queue(const nlohmann::json& responses) {
    if (!responses.is_array()) return;

    for (const auto& resp : responses) {
        std::string mode = speakeasy::to_lower(resp.value("mode", ""));
        if (mode == "default") {
            std::string default_resp_path = resp.value("path", "");
            if (!default_resp_path.empty()) {
                default_resp_path = normalize_response_path(default_resp_path);
                std::ifstream file(default_resp_path, std::ios::binary | std::ios::ate);
                if (file) {
                    std::streamsize size = file.tellg();
                    file.seekg(0, std::ios::beg);
                    std::vector<uint8_t> buffer(size);
                    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                        curr_packet = std::make_shared<std::stringstream>(
                            std::string(buffer.begin(), buffer.end()));
                    }
                }
            }
        }
    }
}

std::vector<uint8_t> Socket::get_recv_data(size_t size, bool peek) {
    std::vector<uint8_t> data;
    if (!curr_packet) return data;

    data.resize(size);
    curr_packet->read(reinterpret_cast<char*>(data.data()), size);
    std::streamsize bytes_read = curr_packet->gcount();
    data.resize(bytes_read);

    if (peek && bytes_read > 0) {
        curr_packet->seekg(-bytes_read, std::ios::cur);
    }

    return data;
}

// WSKSocket implementation
WSKSocket::WSKSocket(int fd, int family, int stype, int protocol, uint32_t flags)
    : Socket(fd, family, stype, protocol, flags) {
    // super(WSKSocket, this).__init__(this, fd, family, stype, protocol, flags)
}

// WininetComponent implementation
WininetComponent::WininetComponent() {
    // super(WininetComponent, this).__init__()
    handle = new_handle();
}

uint32_t WininetComponent::new_handle() {
    uint32_t tmp = WininetComponent::curr_handle;
    WininetComponent::curr_handle += 4;
    return tmp;
}

uint32_t WininetComponent::get_handle() {
    return handle;
}

// WininetRequest implementation
WininetRequest::WininetRequest(std::shared_ptr<WininetSession> session, const std::string& verb, 
                               const std::string& objname, const std::string& ver, 
                               const std::string& ref, const std::vector<std::string>& accepts, 
                               const std::vector<std::string>& flags, uint32_t ctx)
    : session(session), ver(ver), referrer(ref), accept_types(accepts), 
      flags(flags), ctx(ctx), response(nullptr) {
    
    // super(WininetRequest, this).__init__()
    
    // The WiniNet APIs default to a HTTP "GET" if no verb is specified
    if (verb.empty()) {
        this->verb = "get";
    } else {
        this->verb = speakeasy::to_lower(verb);
    }

    this->objname = objname;
    if (this->objname.empty()) {
        this->objname = "";
    }
    // Note: Python's urlparse would split objname into components here;
    // we store the raw URL string and access it directly.
}

std::shared_ptr<WininetSession> WininetRequest::get_session() {
    return session;
}

std::string WininetRequest::get_server() {
    return get_session()->get_server();
}

int WininetRequest::get_port() {
    return get_session()->get_port();
}

std::shared_ptr<WininetInstance> WininetRequest::get_instance() {
    std::shared_ptr<WininetSession> sess = get_session();
    return sess->get_instance();
}

bool WininetRequest::is_secure() {
    for (const auto& flag : flags) {
        if (flag == "INTERNET_FLAG_SECURE") {
            return true;
        }
    }
    return false;
}

std::string WininetRequest::format_http_request(const std::string& headers) {
    std::string request_string = "";
    std::string action = verb + " " + objname + " " + ver + "\n";
    
    request_string += action;
    if (!headers.empty()) {
        request_string += headers;
    }

    std::shared_ptr<WininetInstance> inst = get_instance();
    std::shared_ptr<WininetSession> sess = get_session();

    std::string host = sess->get_server();
    request_string += "Host: " + host + "\n";

    std::string ua = inst->get_user_agent();
    if (!ua.empty()) {
        request_string += "User-Agent: " + ua + "\n";
    }

    // Check for keep-alive connection flag
    bool keep_alive = false;
    bool dont_cache = false;
    for (const auto& flag : flags) {
        if (flag == "INTERNET_FLAG_KEEP_CONNECTION") {
            keep_alive = true;
        }
        if (flag == "INTERNET_FLAG_DONT_CACHE") {
            dont_cache = true;
        }
    }

    if (keep_alive) {
        request_string += "Connection: Keep-Alive\n";
    } else {
        request_string += "Connection: Close\n";
    }

    if (dont_cache) {
        request_string += "Cache-Control: no-cache\n";
    }

    return request_string;
}

size_t WininetRequest::get_response_size() {
    std::shared_ptr<std::stringstream> resp = get_response();
    if (!resp) {
        return 0;
    }
    
    // Save current position, read all, get size, restore position
    std::streampos off = resp->tellg();
    resp->seekg(0, std::ios::end);
    std::streampos size = resp->tellg();
    resp->seekg(off);
    return static_cast<size_t>(size);
}

std::shared_ptr<std::stringstream> WininetRequest::get_response() {
    /*
    Check the configuration file so see if there is a
    handler for the current WinInet request
    */
    
    if (response) {
        return response;
    }

    speakeasy::NetworkConfig& cfg = WininetComponent::get_config();

    speakeasy::HttpConfig& http = cfg.http;

    auto& resps = http.responses;
    if (resps.empty()) {
        throw NetworkEmuError("No HTTP responses supplied");
    }

    response = nullptr;
    std::string default_resp_path;

    for (const auto& res : resps) {
        std::string verb_lower = speakeasy::to_lower(res.verb);

        if (verb_lower == this->verb) {
            auto& resp_files = res.files;
            if (!resp_files.empty()) {
                for (const auto& file : resp_files) {
                    std::string mode = speakeasy::to_lower(file.mode);

                    if (mode == "by_ext") {
                        std::string ext = file.ext;
                        // Extract extension from objname
                        size_t dot_pos = objname.find_last_of('.');
                        std::string obj_ext;
                        if (dot_pos != std::string::npos) {
                            obj_ext = objname.substr(dot_pos + 1);
                        }

                        std::string ext_clean = ext;
                        std::string obj_ext_clean = obj_ext;
                        // Strip leading dots and lowercase for comparison
                        if (!ext_clean.empty() && ext_clean[0] == '.') {
                            ext_clean = ext_clean.substr(1);
                        }
                        if (!obj_ext_clean.empty() && obj_ext_clean[0] == '.') {
                            obj_ext_clean = obj_ext_clean.substr(1);
                        }
                        ext_clean = speakeasy::to_lower(ext_clean);
                        obj_ext_clean = speakeasy::to_lower(obj_ext_clean);

                        if (ext_clean == obj_ext_clean) {
                            std::string path = file.path;
                            if (!path.empty()) {
                                path = normalize_response_path(path);
                                std::ifstream f(path, std::ios::binary | std::ios::ate);
                                if (f) {
                                    std::streamsize size = f.tellg();
                                    f.seekg(0, std::ios::beg);
                                    std::vector<char> buf(size);
                                    if (f.read(buf.data(), size)) {
                                        response = std::make_shared<std::stringstream>(
                                            std::string(buf.data(), size));
                                    }
                                }
                            }
                        }
                    } else if (mode == "default") {
                        default_resp_path = file.path;
                        if (!default_resp_path.empty()) {
                            default_resp_path = normalize_response_path(default_resp_path);
                        }
                    }
                }

                // If no match found by extension, use default
                if (!response && !default_resp_path.empty()) {
                    std::ifstream f(default_resp_path, std::ios::binary | std::ios::ate);
                    if (f) {
                        std::streamsize size = f.tellg();
                        f.seekg(0, std::ios::beg);
                        std::vector<char> buf(size);
                        if (f.read(buf.data(), size)) {
                            response = std::make_shared<std::stringstream>(
                                std::string(buf.data(), size));
                        }
                    }
                }
            }
        }
    }

    return response;
}

std::string WininetRequest::get_object_path() {
    return objname;
}

// WininetSession implementation
WininetSession::WininetSession(std::shared_ptr<WininetInstance> instance, const std::string& server, 
                               int port, const std::string& user, const std::string& password, 
                               int service, const std::vector<std::string>& flags, uint32_t ctx)
    : server(server), port(port), user(user), password(password), service(service), 
      flags(flags), ctx(ctx), instance(instance) {
    // super(WininetSession, this).__init__()
}

std::shared_ptr<WininetInstance> WininetSession::get_instance() {
    return instance;
}

std::vector<std::string> WininetSession::get_flags() {
    return flags;
}

std::shared_ptr<WininetRequest> WininetSession::new_request(const std::string& verb, 
                                                            const std::string& objname, 
                                                            const std::string& ver, 
                                                            const std::string& ref, 
                                                            const std::vector<std::string>& accepts, 
                                                            const std::vector<std::string>& flags, 
                                                            uint32_t ctx) {
    std::shared_ptr<WininetRequest> req = std::make_shared<WininetRequest>(
        shared_from_this(), verb, objname, ver, ref, accepts, flags, ctx);
    uint32_t hdl = req->get_handle();
    requests[hdl] = req;
    return req;
}

// WininetInstance implementation
WininetInstance::WininetInstance(const std::string& user_agent, int access, const std::string& proxy, 
                                 const std::string& bypass, uint32_t flags)
    : user_agent(user_agent), access(access), proxy(proxy), bypass(bypass), flags(flags) {
    // super(WininetInstance, this).__init__()
}

std::shared_ptr<WininetSession> WininetInstance::get_session(uint32_t sess_handle) {
    auto it = sessions.find(sess_handle);
    if (it != sessions.end()) {
        return it->second;
    }
    return nullptr;
}

void WininetInstance::add_session(uint32_t handle, std::shared_ptr<WininetSession> session) {
    sessions[handle] = session;
}

std::shared_ptr<WininetSession> WininetInstance::new_session(const std::string& server, int port, 
                                                             const std::string& user, 
                                                             const std::string& password, 
                                                             int service, 
                                                             const std::vector<std::string>& flags, 
                                                             uint32_t ctx) {
    std::shared_ptr<WininetSession> sess = std::make_shared<WininetSession>(
        shared_from_this(), server, port, user, password, service, flags, ctx);
    uint32_t hdl = sess->get_handle();
    sessions[hdl] = sess;
    return sess;
}

std::string WininetInstance::get_user_agent() {
    return user_agent;
}

// NetworkManager implementation
NetworkManager::NetworkManager(const speakeasy::NetworkConfig& config)
    : curr_fd(4), curr_handle(0x20), config(config) {
    
    WininetComponent::set_config(config);
    
    dns = config.dns;
}

std::shared_ptr<Socket> NetworkManager::new_socket(int family, int stype, int protocol, uint32_t flags) {
    int fd = curr_fd;
    std::shared_ptr<Socket> sock = std::make_shared<Socket>(fd, family, stype, protocol, flags);
    curr_fd += 4;

    sock->fill_recv_queue(config.winsock.responses);

    sockets[fd] = sock;
    return sock;
}

std::string NetworkManager::name_lookup(const std::string& domain) {

    auto& names = dns.names;
    if (names.empty()) {
        return "";
    }

    // Convert domain to lowercase for lookup
    std::string domain_lower = speakeasy::to_lower(domain);

    // Do we have an IP for this name?
    for (auto& it : names) {
        std::string name_lower = speakeasy::to_lower(it.name);
        if (name_lower == domain_lower) {
            return it.ip;
        }
    }
    
    // Use the default IP (if any)
    return "";
}

std::vector<uint8_t> NetworkManager::get_dns_txt(const std::string& domain) {
    /*
    Return a configured DNS TXT record (if any)
    */
    //TODO:
    return {};
}

std::string NetworkManager::ip_lookup(const std::string& ip) {
    for (auto& item : dns.names) {
        if (item.ip == ip) {
            return item.name;
        }
    }
    return "";
}

std::shared_ptr<WininetInstance> NetworkManager::new_wininet_inst(const std::string& user_agent, 
                                                                  int access, const std::string& proxy, 
                                                                  const std::string& bypass, uint32_t flags) {
    std::shared_ptr<WininetInstance> wini = std::make_shared<WininetInstance>(
        user_agent, access, proxy, bypass, flags);
    wininets[wini->get_handle()] = wini;
    return wini;
}

void* NetworkManager::get_wininet_object(uint32_t handle) {
    // Search through instances, sessions, and requests
    for (auto& [hinst, inst] : wininets) {
        if (hinst == handle) {
            return static_cast<void*>(inst.get());
        }
        if (inst) {
            for (auto& [hsess, sess] : inst->sessions) {
                if (hsess == handle) {
                    return static_cast<void*>(sess.get());
                }
                if (sess) {
                    for (auto& [hreq, req] : sess->requests) {
                        if (hreq == handle) {
                            return static_cast<void*>(req.get());
                        }
                    }
                }
            }
        }
    }
    return nullptr;
}

void NetworkManager::close_wininet_object(uint32_t handle) {
    // Check instances
    auto it = wininets.find(handle);
    if (it != wininets.end()) {
        wininets.erase(it);
        return;
    }
    // Check sessions within all instances
    for (auto& [hinst, inst] : wininets) {
        if (inst) {
            auto sit = inst->sessions.find(handle);
            if (sit != inst->sessions.end()) {
                inst->sessions.erase(sit);
                return;
            }
            // Check requests within sessions
            for (auto& [hsess, sess] : inst->sessions) {
                if (sess) {
                    auto rit = sess->requests.find(handle);
                    if (rit != sess->requests.end()) {
                        sess->requests.erase(rit);
                        return;
                    }
                }
            }
        }
    }
}

std::shared_ptr<Socket> NetworkManager::get_socket(int fd) {
    auto it = sockets.find(fd);
    if (it != sockets.end()) {
        return it->second;
    }
    return nullptr;
}

void NetworkManager::close_socket(int fd) {
    sockets.erase(fd);
}