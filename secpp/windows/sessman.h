// sessman.h
#ifndef SESSMAN_H
#define SESSMAN_H

#include <string>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>

#include "../config.h"

/**
 * Base class for all GUI objects
 */
class GuiObject {
public:
    static int curr_handle;
protected:
    int handle;

public:
    GuiObject();
    virtual ~GuiObject() = default;
    int get_handle();
};

/**
 * Represents a windows Session
 */
class Session : public GuiObject {
private:
    int id;
    std::map<int, std::shared_ptr<class Station>> stations;

public:
    Session(int sess_id);
    class std::shared_ptr<class Station> new_station(const std::string& name = "WinSta0");
    int get_id() const { return id; }
    // Access to stations
    const std::map<int, class std::shared_ptr<class Station>>& get_stations() const { return stations; }
};

/**
 * Represents a window station
 */
class Station : public GuiObject {
private:
    std::string name;
    std::map<int, class std::shared_ptr<class Desktop>> desktops;

public:
    Station(const std::string& name = "");
    class std::shared_ptr<class Desktop> new_desktop(const std::string& name = "");
    std::string get_name() const;
    const std::map<int, class std::shared_ptr<class Desktop>>& get_desktops() const { return desktops; }
};

/**
 * Represents a Desktop object
 */
class Desktop : public GuiObject {
private:
    std::map<int, class std::shared_ptr<class Window>> windows;
    class std::shared_ptr<class Window> desktop_window;
    std::string name;

public:
    Desktop(const std::string& name = "");
    class std::shared_ptr<class Window> new_window();
    std::string get_name() const;
};

/**
 * Represents a GUI window
 */
class Window : public GuiObject {
private:
    std::string name;
    std::string class_name;

public:
    Window(const std::string& name = "", const std::string& class_name = "");
    const std::string& get_name() const { return name; }
    const std::string& get_class_name() const { return class_name; }
};

/**
 * Represents a GUI window class
 */
class WindowClass : public GuiObject {
private:
    // Opaque pointer to the underlying class object (type depends on context)
    void* wclass;
    std::string name;

public:
    WindowClass(void* class_obj, const std::string& name);
    void* get_wclass() const { return wclass; }
    const std::string& get_name() const { return name; }
};

/**
 * The session manager for the emulator. This will manage things like desktops,
 * windows, and session isolation
 */
class SessionManager {
private:
    std::map<int, std::shared_ptr<Session>> sessions;
    std::map<int, std::shared_ptr<WindowClass>> window_classes;
    std::map<int, std::shared_ptr<Window>> windows;
    // For string-based lookups
    std::map<std::string, WindowClass> window_classes_by_name;
    std::map<std::string, Window> windows_by_name;
    
    std::shared_ptr<Session> curr_session;
    std::shared_ptr<Station> curr_station;
    std::shared_ptr<Desktop> curr_desktop;
    const speakeasy::SpeakeasyConfig& config;
    int dev_ctx;

public:
    SessionManager(const speakeasy::SpeakeasyConfig& cfg);
    
    int create_window_class(void* class_obj, const std::string& class_name = "");
    int create_window(const std::string& window_name = "", const std::string& class_name = "");
    std::shared_ptr<WindowClass> get_window_class(int atom);
    std::shared_ptr<Window> get_window(int handle);
    int get_device_context() const;
    std::shared_ptr<Desktop> get_current_desktop();
    std::shared_ptr<Station> get_current_station();
    std::shared_ptr<GuiObject> get_gui_object(int handle);
};

#endif // SESSMAN_H