use std::collections::HashMap;

use crate::config::SpeakeasyConfig;
use crate::windows::sessman::SessionManager;
use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::winenv::defs::windows::user32 as windefs;

pub struct User32Handler {
    sessman: SessionManager,
    window_hooks: HashMap<u32, (i32, u64, u64)>,
    wndprocs: HashMap<u32, u64>,
    next_handle: u32,
    synthetic_async_keys: Vec<u32>,
    synthetic_async_key_index: usize,
    next_atom: u32,
    window_messages: HashMap<u32, String>,
}

impl User32Handler {
    pub fn new() -> Self {
        Self {
            sessman: SessionManager::new(&SpeakeasyConfig::default()),
            window_hooks: HashMap::new(),
            wndprocs: HashMap::new(),
            next_handle: 4,
            synthetic_async_keys: vec![0x41, 0x42, 0x43],
            synthetic_async_key_index: 0,
            next_atom: 0xC000,
            window_messages: HashMap::new(),
        }
    }

    fn get_handle(&mut self) -> u32 {
        self.next_handle += 4;
        self.next_handle
    }

    pub fn get_desktop_window(&self) -> u32 {
        self.sessman
            .get_current_desktop()
            .map(|desktop| desktop.desktop_window.handle)
            .unwrap_or(0)
    }

    pub fn register_class_ex(&mut self, class_name: Option<String>, wndproc: u64) -> u32 {
        let atom = self.sessman.create_window_class(wndproc, class_name.clone());
        if let Some(name) = class_name {
            self.wndprocs.insert(atom, wndproc);
            self.sessman.create_window(Some(name), None);
        }
        atom
    }

    pub fn create_window_ex(&mut self, class_name: Option<String>, window_name: Option<String>) -> u32 {
        self.sessman.create_window(window_name, class_name)
    }

    pub fn message_box(&self, _text: &str, _caption: &str, _message_type: u32) -> i32 {
        2
    }

    pub fn get_async_key_state(&mut self, vkey: u32) -> u16 {
        if self.synthetic_async_key_index >= self.synthetic_async_keys.len() {
            return 0;
        }
        if vkey != self.synthetic_async_keys[self.synthetic_async_key_index] {
            return 0;
        }
        self.synthetic_async_key_index += 1;
        0x8001
    }

    pub fn get_keyboard_type(&self, type_flag: i32) -> i32 {
        match type_flag {
            0 => 4,
            1 => 0,
            2 => 12,
            _ => 0,
        }
    }

    pub fn get_system_metrics(&self, index: i32) -> i32 {
        match index {
            0 => 800,
            1 => 600,
            16 => 1,
            23 => 0,
            _ => 0,
        }
    }

    pub fn set_windows_hook_ex(&mut self, hook_type: i32, proc: u64, module: u64) -> u32 {
        let handle = self.get_handle();
        self.window_hooks.insert(handle, (hook_type, proc, module));
        handle
    }

    pub fn unhook_windows_hook_ex(&mut self, hook: u32) -> bool {
        self.window_hooks.remove(&hook).is_some()
    }

    pub fn post_message(&self, _hwnd: u32, _msg: u32, _wparam: u64, _lparam: u64) -> bool {
        true
    }

    pub fn send_message(&self, hwnd: u32, _msg: u32, _wparam: u64, _lparam: u64) -> u64 {
        self.wndprocs.get(&hwnd).copied().unwrap_or(0)
    }

    pub fn register_window_message(&mut self, _message: &str) -> u32 {
        self.next_atom += 1;
        self.next_atom
    }
}

impl Default for User32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for User32Handler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "GetDesktopWindow" => Ok(self.get_desktop_window() as u64),
            "ShowWindow" => Ok(1),
            "CreateWindowStation" => Ok(self.get_handle() as u64),
            "SetProcessWindowStation" => Ok(1),
            "GetDC" | "GetDCEx" => Ok(self.get_handle() as u64),
            "ReleaseDC" => Ok(1),
            "RegisterClassExA" | "RegisterClassExW" => Ok(self.get_handle() as u64),
            "UnregisterClassA" | "UnregisterClassW" => Ok(1),
            "SetCursorPos" => Ok(1),
            "CloseDesktop" => Ok(1),
            "CloseWindowStation" => Ok(1),
            "GetThreadDesktop" => Ok(self.get_handle() as u64),
            "OpenWindowStation" => Ok(self.get_handle() as u64),
            "ChangeWindowMessageFilter" => Ok(1),
            "UpdateWindow" => Ok(1),
            "PostQuitMessage" => Ok(0),
            "DestroyWindow" => Ok(1),
            "DefWindowProcA" | "DefWindowProcW" => Ok(0),
            "CreateWindowExA" | "CreateWindowExW" => Ok(self.get_handle() as u64),
            "SetLayeredWindowAttributes" => Ok(1),
            "MessageBoxA" | "MessageBoxW" | "MessageBoxExA" | "MessageBoxExW" => Ok(2),
            "MessageBoxIndirectA" | "MessageBoxIndirectW" => Ok(2),
            "LoadStringA" | "LoadStringW" => Ok(0),
            "GetCursorPos" => Ok(1),
            "GetAsyncKeyState" => Ok(self.get_async_key_state(args[0] as u32) as u64),
            "GetKeyboardType" => Ok(self.get_keyboard_type(args[0] as i32) as u64),
            "GetSystemMetrics" => Ok(self.get_system_metrics(args[0] as i32) as u64),
            "LoadBitmapA" | "LoadBitmapW" => Ok(0),
            "GetClientRect" => {
                let hwnd = args[0];
                let lprc = args[1];
                if lprc != 0 {
                    let rect = [0i32, 0, 800, 600];
                    emu.mem_write(lprc, &rect.iter().flat_map(|&v| v.to_le_bytes()).collect::<Vec<u8>>())?;
                }
                Ok(1)
            },
            "RegisterWindowMessageA" | "RegisterWindowMessageW" => Ok(self.register_window_message("") as u64),
            "PeekMessageA" | "PeekMessageW" => Ok(0),
            "PostMessageA" | "PostMessageW" => Ok(1),
            "SendMessageA" | "SendMessageW" => Ok(self.send_message(args[0] as u32, args[1] as u32, args[2], args[3])),
            "CallNextHookEx" => Ok(0),
            "SetWindowsHookExA" | "SetWindowsHookExW" => {
                let hook_type = args[0] as i32;
                let proc = args[1];
                let module = args[2];
                Ok(self.set_windows_hook_ex(hook_type, proc, module) as u64)
            },
            "UnhookWindowsHookEx" => Ok(self.unhook_windows_hook_ex(args[0] as u32) as u64),
            "MsgWaitForMultipleObjects" => Ok(0),
            "GetMessageA" | "GetMessageW" => Ok(0),
            "TranslateMessage" => Ok(0),
            "DispatchMessageA" | "DispatchMessageW" => Ok(0),
            "GetForegroundWindow" => Ok(self.get_handle() as u64),
            "LoadCursorA" | "LoadCursorW" => Ok(self.get_handle() as u64),
            "FindWindowA" | "FindWindowW" | "FindWindowExA" | "FindWindowExW" => Ok(0),
            "GetWindowTextA" | "GetWindowTextW" => Ok(0),
            "PaintDesktop" => Ok(1),
            "GetMenuInfo" => Ok(0),
            "GetProcessWindowStation" => Ok(self.get_handle() as u64),
            "LoadAcceleratorsA" | "LoadAcceleratorsW" => Ok(self.get_handle() as u64),
            "IsWindowVisible" => Ok(0),
            "BeginPaint" => Ok(self.get_handle() as u64),
            "EndPaint" => Ok(1),
            "GetActiveWindow" => Ok(self.get_handle() as u64),
            "GetLastActivePopup" => Ok(0),
            "GetUserObjectInformation" => Ok(1),
            "LoadIconA" | "LoadIconW" => Ok(self.get_handle() as u64),
            "GetRawInputDeviceList" => Ok(0),
            "GetNextDlgTabItem" => Ok(0),
            "GetCaretPos" => Ok(1),
            "GetMonitorInfoA" | "GetMonitorInfoW" => Ok(1),
            "GetDlgCtrlID" => Ok(0),
            "GetUpdateRect" => Ok(0),
            "GetAltTabInfoA" | "GetAltTabInfoW" => Ok(0),
            "GetUpdateRgn" => Ok(0),
            "FlashWindow" => Ok(1),
            "IsClipboardFormatAvailable" => Ok(0),
            "IsWindow" => Ok(0),
            "EnableWindow" => Ok(1),
            "CharLowerBuffA" | "CharLowerBuffW" => Ok(1),
            "CharUpperBuffA" | "CharUpperBuffW" => Ok(1),
            "CharLowerA" | "CharLowerW" => Ok(0),
            "CharUpperA" | "CharUpperW" => Ok(0),
            "SetTimer" => Ok(1),
            "KillTimer" => Ok(1),
            "OpenDesktopA" | "OpenDesktopW" => Ok(self.get_handle() as u64),
            "SetThreadDesktop" => Ok(1),
            "GetKeyboardLayoutList" => Ok(0),
            "GetKBCodePage" => Ok(1),
            "GetClipboardViewer" => Ok(0),
            "GetClipboardOwner" => Ok(0),
            "GetMenuCheckMarkDimensions" => Ok(0x14001E),
            "GetOpenClipboardWindow" => Ok(0),
            "GetFocus" => Ok(0),
            "GetCursor" => Ok(0),
            "GetClipboardSequenceNumber" => Ok(0),
            "GetCaretBlinkTime" => Ok(530),
            "GetDoubleClickTime" => Ok(500),
            "RegisterClipboardFormatA" | "RegisterClipboardFormatW" => Ok(self.register_window_message("") as u64),
            "GetClipboardData" => Ok(0),
            "SetClipboardData" => Ok(1),
            "EmptyClipboard" => Ok(1),
            "OpenClipboard" => Ok(1),
            "CloseClipboard" => Ok(1),
            "IsWindowEnabled" => Ok(1),
            "GetWindowLongA" | "GetWindowLongW" => Ok(0),
            "SetWindowLongA" | "SetWindowLongW" => Ok(0),
            "GetWindowRect" => Ok(1),
            "SetWindowRect" => Ok(1),
            "GetWindowTextLengthA" | "GetWindowTextLengthW" => Ok(0),
            "GetWindowThreadProcessId" => Ok(4),
            "GetParent" => Ok(0),
            "SetParent" => Ok(0),
            "SetWindowPos" => Ok(1),
            "MoveWindow" => Ok(1),
            "SetWindowTextA" | "SetWindowTextW" => Ok(1),
            "GetScrollBarInfo" => Ok(0),
            "GetWindowInfo" => Ok(1),
            "GetTitleBarInfo" => Ok(0),
            "GetAncestor" => Ok(0),
            "RealGetWindowClassA" | "RealGetWindowClassW" => Ok(0),
            "GetClassNameA" | "GetClassNameW" => Ok(0),
            "SetClassLongA" | "SetClassLongW" => Ok(0),
            "GetClassLongA" | "GetClassLongW" => Ok(0),
            "SetClassWord" => Ok(0),
            "GetClassWord" => Ok(0),
            "CreateMenu" => Ok(self.get_handle() as u64),
            "CreatePopupMenu" => Ok(self.get_handle() as u64),
            "DestroyMenu" => Ok(1),
            "AppendMenuA" | "AppendMenuW" => Ok(1),
            "InsertMenuA" | "InsertMenuW" => Ok(1),
            "RemoveMenu" => Ok(1),
            "GetMenu" => Ok(0),
            "GetSubMenu" => Ok(0),
            "GetMenuItemCount" => Ok(0),
            "GetMenuItemID" => Ok(0),
            "GetMenuState" => Ok(0),
            "GetMenuStringA" | "GetMenuStringW" => Ok(0),
            "SetMenu" => Ok(1),
            "DrawMenuBar" => Ok(1),
            "GetSystemMenu" => Ok(0),
            "GetMenuBarInfo" => Ok(0),
            "GetMenuInfo" => Ok(0),
            "SetMenuInfo" => Ok(1),
            "GetMenuItemRect" => Ok(0),
            "MenuItemFromPoint" => Ok(-1),
            "TrackPopupMenu" => Ok(1),
            "TrackPopupMenuEx" => Ok(1),
            "DrawIcon" => Ok(1),
            "DrawIconEx" => Ok(1),
            "LoadImageA" | "LoadImageW" => Ok(self.get_handle() as u64),
            "CopyImage" => Ok(self.get_handle() as u64),
            "LoadCursorFromFileA" | "LoadCursorFromFileW" => Ok(self.get_handle() as u64),
            "CreateIcon" => Ok(self.get_handle() as u64),
            "CreateIconFromResource" => Ok(self.get_handle() as u64),
            "CreateIconIndirect" => Ok(self.get_handle() as u64),
            "DestroyIcon" => Ok(1),
            "LookupIconIdFromDirectory" => Ok(0),
            "GetIconInfo" => Ok(1),
            "GetDialogBaseUnits" => Ok(0x40004),
            "SetForegroundWindow" => Ok(1),
            "AttachThreadInput" => Ok(1),
            "GetWindowThreadProcessId" => Ok(4),
            "GetAsyncKeyState" => Ok(self.get_async_key_state(args[0] as u32) as u64),
            "GetKeyState" => Ok(0),
            "GetKeyboardState" => Ok(1),
            "SetKeyboardState" => Ok(1),
            "GetKeyNameTextA" | "GetKeyNameTextW" => Ok(0),
            "MapVirtualKeyA" | "MapVirtualKeyW" => Ok(0),
            "MapVirtualKeyExA" | "MapVirtualKeyExW" => Ok(0),
            "ToUnicode" => Ok(-1),
            "ToUnicodeEx" => Ok(-1),
            "VkKeyScanA" | "VkKeyScanW" => Ok(-1),
            "VkKeyScanExA" | "VkKeyScanExW" => Ok(-1),
            "keybd_event" => Ok(()),
            "mouse_event" => Ok(()),
            "SendInput" => Ok(0),
            "GetInputState" => Ok(0),
            "GetQueueStatus" => Ok(0),
            "MsgWaitForMultipleObjectsEx" => Ok(0),
            "WaitForMessage" => Ok(0),
            "PeekMessageW" => Ok(0),
            "GetMessageW" => Ok(0),
            "TranslateMessage" => Ok(0),
            "DispatchMessageW" => Ok(0),
            "SetMessageQueue" => Ok(1),
            "PostThreadMessageA" | "PostThreadMessageW" => Ok(1),
            "GetThreadDesktop" => Ok(self.get_handle() as u64),
            "GetProcessWindowStation" => Ok(self.get_handle() as u64),
            "SetThreadDesktop" => Ok(1),
            "SetProcessWindowStation" => Ok(1),
            "GetUserObjectSecurity" => Ok(1),
            "SetUserObjectSecurity" => Ok(1),
            "CreateDesktopA" | "CreateDesktopW" => Ok(self.get_handle() as u64),
            "OpenDesktopA" | "OpenDesktopW" => Ok(self.get_handle() as u64),
            "EnumDesktopsA" | "EnumDesktopsW" => Ok(0),
            "CloseDesktop" => Ok(1),
            "EnumWindowStationsA" | "EnumWindowStationsW" => Ok(0),
            "SetProcessDPIAware" => Ok(1),
            "SetProcessDPIAwareness" => Ok(0),
            "GetDpiForSystem" => Ok(96),
            "GetDpiForWindow" => Ok(96),
            "MonitorFromWindow" => Ok(self.get_handle() as u64),
            "MonitorFromRect" => Ok(self.get_handle() as u64),
            "MonitorFromPoint" => Ok(self.get_handle() as u64),
            "GetWindowPlacement" => Ok(1),
            "SetWindowPlacement" => Ok(1),
            "GetWindowPlacement" => Ok(1),
            "SetWindowPlacement" => Ok(1),
            "GetWindowInfo" => Ok(1),
            "GetWindowRect" => Ok(1),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "User32"
    }
}

pub fn get_windowhook_flags(flags: i32) -> Vec<&'static str> {
    const DEFINES: &[(i32, &str)] = &[
        (windefs::WH_CALLWNDPROC, "WH_CALLWNDPROC"),
        (windefs::WH_CALLWNDPROCRET, "WH_CALLWNDPROCRET"),
        (windefs::WH_CBT, "WH_CBT"),
        (windefs::WH_DEBUG, "WH_DEBUG"),
        (windefs::WH_FOREGROUNDIDLE, "WH_FOREGROUNDIDLE"),
        (windefs::WH_GETMESSAGE, "WH_GETMESSAGE"),
        (windefs::WH_JOURNALPLAYBACK, "WH_JOURNALPLAYBACK"),
        (windefs::WH_JOURNALRECORD, "WH_JOURNALRECORD"),
        (windefs::WH_KEYBOARD, "WH_KEYBOARD"),
        (windefs::WH_KEYBOARD_LL, "WH_KEYBOARD_LL"),
        (windefs::WH_MOUSE, "WH_MOUSE"),
        (windefs::WH_MOUSE_LL, "WH_MOUSE_LL"),
        (windefs::WH_MSGFILTER, "WH_MSGFILTER"),
        (windefs::WH_SHELL, "WH_SHELL"),
        (windefs::WH_SYSMSGFILTER, "WH_SYSMSGFILTER"),
    ];
    DEFINES
        .iter()
        .filter_map(|(value, name)| if *value == flags { Some(*name) } else { None })
        .collect()
}
