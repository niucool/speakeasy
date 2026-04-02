// Session manager

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use crate::config::SpeakeasyConfig;

static CURR_HANDLE: AtomicU32 = AtomicU32::new(0x120);

fn get_next_handle() -> u32 {
    CURR_HANDLE.fetch_add(4, Ordering::SeqCst)
}

#[derive(Debug, Clone)]
pub struct Window {
    pub handle: u32,
    pub name: Option<String>,
    pub class_name: Option<String>,
}

impl Window {
    pub fn new(name: Option<String>, class_name: Option<String>) -> Self {
        Self {
            handle: get_next_handle(),
            name,
            class_name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WindowClass {
    pub handle: u32,
    pub wclass: u64, // Maps to 'Any' class obj pointer in Python
    pub name: String,
}

impl WindowClass {
    pub fn new(wclass: u64, name: String) -> Self {
        Self {
            handle: get_next_handle(),
            wclass,
            name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Desktop {
    pub handle: u32,
    pub name: String,
    pub windows: HashMap<u32, Window>,
    pub desktop_window: Window,
}

impl Desktop {
    pub fn new(name: String) -> Self {
        let desk_window = Window::new(None, None);
        let mut windows = HashMap::new();
        windows.insert(desk_window.handle, desk_window.clone());

        Self {
            handle: get_next_handle(),
            name,
            windows,
            desktop_window: desk_window,
        }
    }

    pub fn new_window(&mut self) -> Window {
        let window = Window::new(None, None);
        self.windows.insert(window.handle, window.clone());
        window
    }
}

#[derive(Debug, Clone)]
pub struct Station {
    pub handle: u32,
    pub name: String,
    pub desktops: HashMap<u32, Desktop>,
}

impl Station {
    pub fn new(name: String) -> Self {
        Self {
            handle: get_next_handle(),
            name,
            desktops: HashMap::new(),
        }
    }

    pub fn new_desktop(&mut self, name: &str) -> Desktop {
        let desk = Desktop::new(name.to_string());
        self.desktops.insert(desk.handle, desk.clone());
        desk
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub handle: u32,
    pub id: u32,
    pub stations: HashMap<u32, Station>,
}

impl Session {
    pub fn new(sess_id: u32) -> Self {
        Self {
            handle: get_next_handle(),
            id: sess_id,
            stations: HashMap::new(),
        }
    }

    pub fn new_station(&mut self, name: &str) -> Station {
        let stat = Station::new(name.to_string());
        self.stations.insert(stat.handle, stat.clone());
        stat
    }
}

#[derive(Debug, Clone)]
pub enum GuiObject {
    Session(Session),
    Station(Station),
    Desktop(Desktop),
    Window(Window),
    WindowClass(WindowClass),
}

pub struct SessionManager {
    pub sessions: HashMap<u32, Session>,
    pub window_classes_by_handle: HashMap<u32, WindowClass>,
    pub window_classes_by_name: HashMap<String, WindowClass>,
    pub windows_by_handle: HashMap<u32, Window>,
    pub windows_by_name: HashMap<String, Window>,
    pub curr_session: Option<Session>,
    pub curr_station: Option<Station>,
    pub curr_desktop: Option<Desktop>,
    pub dev_ctx: u32,
}

impl SessionManager {
    /// The session manager for the emulator. This will manage things like desktops,
    /// windows, and session isolation
    pub fn new(_config: &SpeakeasyConfig) -> Self {
        let mut sessions = HashMap::new();
        let dev_ctx = get_next_handle();

        // create a session 0
        let mut sess0 = Session::new(0);

        // create WinSta0
        let mut winsta0 = sess0.new_station("WinSta0");

        // Create a desktop
        winsta0.new_desktop("Winlogon");
        let default_desk = winsta0.new_desktop("Default");
        winsta0.new_desktop("Disconnect");

        // Sync updates back to maps
        sess0.stations.insert(winsta0.handle, winsta0.clone());
        sessions.insert(sess0.handle, sess0.clone());

        Self {
            sessions,
            window_classes_by_handle: HashMap::new(),
            window_classes_by_name: HashMap::new(),
            windows_by_handle: HashMap::new(),
            windows_by_name: HashMap::new(),
            curr_session: Some(sess0),
            curr_station: Some(winsta0),
            curr_desktop: Some(default_desk),
            dev_ctx,
        }
    }

    pub fn create_window_class(&mut self, class_obj: u64, class_name: Option<String>) -> u32 {
        let name = class_name.clone().unwrap_or_default();
        let wc = WindowClass::new(class_obj, name.clone());
        let handle = wc.handle;
        
        self.window_classes_by_handle.insert(handle, wc.clone());
        if !name.is_empty() {
            self.window_classes_by_name.insert(name, wc);
        }
        handle
    }

    pub fn create_window(&mut self, window_name: Option<String>, class_name: Option<String>) -> u32 {
        let wc = Window::new(window_name.clone(), class_name);
        let handle = wc.handle;
        
        self.windows_by_handle.insert(handle, wc.clone());
        if let Some(name) = window_name {
            self.windows_by_name.insert(name, wc);
        }
        handle
    }

    pub fn get_window_class_by_handle(&self, handle: u32) -> Option<&WindowClass> {
        self.window_classes_by_handle.get(&handle)
    }
    
    pub fn get_window_class_by_name(&self, name: &str) -> Option<&WindowClass> {
        self.window_classes_by_name.get(name)
    }

    pub fn get_window_by_handle(&self, handle: u32) -> Option<&Window> {
        self.windows_by_handle.get(&handle)
    }
    
    pub fn get_window_by_name(&self, name: &str) -> Option<&Window> {
        self.windows_by_name.get(name)
    }

    pub fn get_device_context(&self) -> u32 {
        self.dev_ctx
    }

    pub fn get_current_desktop(&self) -> Option<&Desktop> {
        self.curr_desktop.as_ref()
    }

    pub fn get_current_station(&self) -> Option<&Station> {
        self.curr_station.as_ref()
    }

    pub fn get_gui_object(&self, handle: u32) -> Option<GuiObject> {
        for (hsess, sess) in &self.sessions {
            if *hsess == handle {
                return Some(GuiObject::Session(sess.clone()));
            }
            for (hstat, stat) in &sess.stations {
                if *hstat == handle {
                    return Some(GuiObject::Station(stat.clone()));
                }
                for (hdesk, desk) in &stat.desktops {
                    if *hdesk == handle {
                        return Some(GuiObject::Desktop(desk.clone()));
                    }
                }
            }
        }
        None
    }
}
