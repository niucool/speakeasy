// sessman.cpp
#include "sessman.h"

// GuiObject implementation
int GuiObject::curr_handle = 0x120;

GuiObject::GuiObject() : handle(get_handle()) {}

int GuiObject::get_handle() {
    int tmp = GuiObject::curr_handle;
    GuiObject::curr_handle += 4;
    return tmp;
}

// Session implementation
Session::Session(int sess_id) : id(sess_id) {}

Station Session::new_station(const std::string& name) {
    Station stat(name);
    stations.insert({stat.get_handle(), stat});
    return stat;
}

// Station implementation
Station::Station(const std::string& name) : name(name) {}

Desktop Station::new_desktop(const std::string& name) {
    Desktop desk(name);
    desktops.insert({desk.get_handle(), desk});
    return desk;
}

std::string Station::get_name() const {
    return name;
}

// Desktop implementation
Desktop::Desktop(const std::string& name) : name(name) {
    desktop_window = &new_window();
}

Window Desktop::new_window() {
    // create the desktop window
    Window window;
    windows.insert({window.get_handle(), window});
    return window;
}

Window* Desktop::get_desktop_window() {
    return desktop_window;
}

std::string Desktop::get_name() const {
    return name;
}

// Window implementation
Window::Window(const std::string* name, const std::string* class_name) {
    if (name) {
        this->name = *name;
    }
    if (class_name) {
        this->class_name = *class_name;
    }
}

// WindowClass implementation
WindowClass::WindowClass(void* class_obj, const std::string& name) 
    : wclass(class_obj), name(name) {}

// SessionManager implementation
SessionManager::SessionManager(const nlohmann::json& config) 
    : config(config), curr_session(nullptr), curr_station(nullptr), 
      curr_desktop(nullptr) {
    dev_ctx = GuiObject::curr_handle;

    // create a session 0
    curr_session = &sessions.emplace(0, Session(0)).first->second;

    // create WinSta0
    curr_station = &curr_session->new_station("WinSta0");

    // Create a desktop
    curr_station->new_desktop("Winlogon");
    Desktop default_desktop = curr_station->new_desktop("Default");
    curr_station->new_desktop("Disconnect");

    // For now lets default to the Default desktop
    // Note: In a real implementation, we would need to properly manage the Desktop object reference
    // This is a simplified version for demonstration
}

int SessionManager::create_window_class(void* class_obj, const std::string* class_name) {
    WindowClass wc(class_obj, class_name ? *class_name : "");
    int atom = wc.get_handle();
    window_classes.insert({atom, wc});
    if (class_name) {
        window_classes_by_name.insert({*class_name, &window_classes.at(atom)});
    }
    return atom;
}

int SessionManager::create_window(const std::string* window_name, const std::string* class_name) {
    Window wc(window_name, class_name);
    int hnd = wc.get_handle();
    windows.insert({hnd, wc});
    if (window_name) {
        windows_by_name.insert({*window_name, &windows.at(hnd)});
    }
    return hnd;
}

WindowClass* SessionManager::get_window_class(int atom) {
    auto it = window_classes.find(atom);
    if (it != window_classes.end()) {
        return &it->second;
    }
    return nullptr;
}

Window* SessionManager::get_window(int handle) {
    auto it = windows.find(handle);
    if (it != windows.end()) {
        return &it->second;
    }
    return nullptr;
}

int SessionManager::get_device_context() const {
    return dev_ctx;
}

Desktop* SessionManager::get_current_desktop() {
    return curr_desktop;
}

Station* SessionManager::get_current_station() {
    return curr_station;
}

GuiObject* SessionManager::get_gui_object(int handle) {
    // TODO: This implementation needs to be revisited as it has issues with object lifetime
    // The current approach of returning pointers to temporary objects will cause issues
    // A proper implementation would need to manage object lifetimes more carefully
    
    for (auto& sess_pair : sessions) {
        int hsess = sess_pair.first;
        Session& sess = sess_pair.second;
        
        if (hsess == handle) {
            return &sess;
        }
        
        for (auto& stat_pair : sess.get_desktops()) {
            int hstat = stat_pair.first;
            Station& stat = const_cast<Station&>(stat_pair.second);
            
            if (hstat == handle) {
                return &stat;
            }
            
            // TODO: Check desktops within the station
            // This requires a more complex implementation to properly handle object references
        }
    }
    
    return nullptr;
}