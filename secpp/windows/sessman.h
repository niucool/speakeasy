// sessman.h
#ifndef SESSMAN_H
#define SESSMAN_H

#include <string>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>

/**
 * Base class for all GUI objects
 */
class GuiObject {
protected:
    static int curr_handle;
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
    std::map<int, class Station> stations;

public:
    Session(int sess_id);
    class Station new_station(const std::string& name = "WinSta0");
    int get_id() const { return id; }
};

/**
 * Represents a window station
 */
class Station : public GuiObject {
private:
    std::string name;
    std::map<int, class Desktop> desktops;

public:
    Station(const std::string& name = "");
    class Desktop new_desktop(const std::string& name = "");
    std::string get_name() const;
    const std::map<int, class Desktop>& get_desktops() const { return desktops; }
};

/**
 * Represents a Desktop object
 */
class Desktop : public GuiObject {
private:
    std::map<int, class Window> windows;
    class Window* desktop_window;
    std::string name;

public:
    Desktop(const std::string& name = "");
    class Window new_window();
    class Window* get_desktop_window();
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
    Window(const std::string* name = nullptr, const std::string* class_name = nullptr);
    const std::string& get_name() const { return name; }
    const std::string& get_class_name() const { return class_name; }
};

/**
 * Represents a GUI window class
 */
class WindowClass : public GuiObject {
private:
    // TODO: Define class_obj type
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
    std::map<int, Session> sessions;
    std::map<int, WindowClass> window_classes;
    std::map<int, Window> windows;
    // For string-based lookups
    std::map<std::string, WindowClass*> window_classes_by_name;
    std::map<std::string, Window*> windows_by_name;
    
    Session* curr_session;
    Station* curr_station;
    Desktop* curr_desktop;
    nlohmann::json config;
    int dev_ctx;

public:
    SessionManager(const nlohmann::json& config);
    
    int create_window_class(void* class_obj, const std::string* class_name = nullptr);
    int create_window(const std::string* window_name = nullptr, const std::string* class_name = nullptr);
    WindowClass* get_window_class(int atom);
    Window* get_window(int handle);
    int get_device_context() const;
    Desktop* get_current_desktop();
    Station* get_current_station();
    GuiObject* get_gui_object(int handle);
};

#endif // SESSMAN_H