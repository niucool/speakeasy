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

std::shared_ptr<Station> Session::new_station(const std::string& name) {
    auto stat = std::make_shared<Station>(name);
    stations.insert({stat->get_handle(), stat});
    return stat;
}

// Station implementation
Station::Station(const std::string& name) : name(name) {}

std::shared_ptr<Desktop> Station::new_desktop(const std::string& name) {
    auto desk = std::make_shared<Desktop>(name);
    desktops.insert({desk->get_handle(), desk});
    return desk;
}

std::string Station::get_name() const {
    return name;
}

// Desktop implementation
Desktop::Desktop(const std::string& name) : name(name) {
    auto win = new_window();
    desktop_window = win;
}

std::shared_ptr<Window> Desktop::new_window() {
    auto window = std::make_shared<Window>();
    windows.insert({window->get_handle(), window});
    return window;
}

std::string Desktop::get_name() const {
    return name;
}

// Window implementation
Window::Window(const std::string& name, const std::string& class_name) {
    this->name = name;
    this->class_name = class_name;
}

// WindowClass implementation
WindowClass::WindowClass(void* class_obj, const std::string& name) : wclass(class_obj), name(name) {}

// SessionManager implementation
SessionManager::SessionManager(const speakeasy::SpeakeasyConfig& cfg)
    : config(cfg), curr_session(nullptr), curr_station(nullptr), curr_desktop(nullptr) {
    dev_ctx = GuiObject::curr_handle;

    // create a session 0
    auto session = std::make_shared<Session>(0);
    sessions.insert({session->get_handle(), session});
    curr_session = session;

    // create WinSta0
    auto st = curr_session->new_station("WinSta0");
    curr_station = st;

    // Create a desktop
    curr_station->new_desktop("Winlogon");
    curr_station->new_desktop("Default");
    curr_station->new_desktop("Disconnect");

    // For now default to the Default desktop
    auto& def_desktops = curr_station->get_desktops();
    for (auto& [hnd, desk] : def_desktops) {
        if (desk->get_name() == "Default") {
            curr_desktop = desk;
            break;
        }
    }
}

int SessionManager::create_window_class(void* class_obj, const std::string& class_name) {
    auto wc = std::make_shared<WindowClass>(class_obj, class_name);
    int atom = wc->get_handle();
    window_classes.insert({atom, wc});
    if (!class_name.empty()) {
        window_classes_by_name.insert({class_name, *wc});
    }
    return atom;
}

int SessionManager::create_window(const std::string& window_name, const std::string& class_name) {
    auto wc = std::make_shared<Window>(window_name, class_name);
    int hnd = wc->get_handle();
    windows.insert({hnd, wc});
    if (!window_name.empty()) {
        windows_by_name.insert({window_name, *wc});
    }
    return hnd;
}

std::shared_ptr<WindowClass> SessionManager::get_window_class(int atom) {
    auto it = window_classes.find(atom);
    if (it != window_classes.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<Window> SessionManager::get_window(int handle) {
    auto it = windows.find(handle);
    if (it != windows.end()) {
        return it->second;
    }
    return nullptr;
}

int SessionManager::get_device_context() const {
    return dev_ctx;
}

std::shared_ptr<Desktop> SessionManager::get_current_desktop() {
    return curr_desktop;
}

std::shared_ptr<Station> SessionManager::get_current_station() {
    return curr_station;
}

std::shared_ptr<GuiObject> SessionManager::get_gui_object(int handle) {
    for (auto& sess_pair : sessions) {
        if (sess_pair.first == handle) {
            return sess_pair.second;
        }

        const auto& sess = sess_pair.second;
        for (const auto& stat_pair : sess->get_stations()) {
            if (stat_pair.first == handle) {
                return stat_pair.second;
            }

            for (const auto& desk_pair : stat_pair.second->get_desktops()) {
                if (desk_pair.first == handle) {
                    return desk_pair.second;
                }
            }
        }
    }
    
    return nullptr;
}