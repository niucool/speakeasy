use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::winenv::defs::windows::shell32 as shell32defs;

pub struct Shell32Handler {
    next_handle: u32,
}

impl Shell32Handler {
    pub fn new() -> Self {
        Self { next_handle: 0x4000 }
    }

    fn new_handle(&mut self) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 4;
        handle
    }

    pub fn shell_execute(
        &mut self,
        _verb: Option<&str>,
        file: &str,
        _parameters: Option<&str>,
        _directory: Option<&str>,
        _show: i32,
    ) -> u32 {
        if file.is_empty() {
            return 0;
        }
        self.new_handle()
    }

    pub fn shell_execute_info(&mut self, execute_info: &shell32defs::SHELLEXECUTEINFOA) -> u32 {
        if execute_info.lpFile == 0 {
            return 0;
        }
        self.new_handle()
    }

    pub fn sh_get_folder_path(&self, csidl: u32) -> Option<String> {
        match csidl {
            0x24 => Some("C:\\Windows".to_string()),
            0x25 => Some("C:\\Windows\\System32".to_string()),
            0x1A => Some("C:\\Users\\User\\AppData\\Roaming".to_string()),
            0x1C => Some("C:\\Users\\User\\AppData\\Local".to_string()),
            0x28 => Some("C:\\Users\\User".to_string()),
            0x26 => Some("C:\\Program Files".to_string()),
            0x00..=0x45 => Some("C:\\".to_string()),
            _ => None,
        }
    }
}

impl Default for Shell32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Shell32Handler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "ShellExecuteA" | "ShellExecuteW" | "ShellExecuteExA" | "ShellExecuteExW" => {
                Ok(self.new_handle() as u64)
            },
            "SHGetFolderPathA" | "SHGetFolderPathW" | "SHGetFolderPathExA" | "SHGetFolderPathExW" => Ok(0),
            "SHGetKnownFolderPath" => Ok(0),
            "SHGetKnownFolderItem" => Ok(0),
            "SHAddToRecentDocs" => Ok(0),
            "SHChangeNotify" => Ok(0),
            "SHEmptyRecycleBinA" | "SHEmptyRecycleBinW" => Ok(0),
            "SHFileOperationA" | "SHFileOperationW" => Ok(0),
            "SHFormatCapacity" => Ok(0),
            "SHGetPathFromIDListA" | "SHGetPathFromIDListW" => Ok(0),
            "SHGetSpecialFolderLocation" => Ok(0),
            "SHGetSpecialFolderPathA" | "SHGetSpecialFolderPathW" => Ok(0),
            "SHItemExists" => Ok(0),
            "SHParseDisplayName" => Ok(0),
            "SHCreateDataObject" => Ok(0),
            "SHCreateDirectoryExA" | "SHCreateDirectoryExW" => Ok(0),
            "SHRunControlPanel" => Ok(0),
            "FindResourceShell32" => Ok(0),
            "SHAlloc" => Ok(0x200000),
            "SHFree" => Ok(0),
            "SHAllocShared" => Ok(0),
            "SHFreeShared" => Ok(0),
            "SHLockShared" => Ok(0),
            "SHUnlockShared" => Ok(0),
            "SHCopyKeyA" | "SHCopyKeyW" => Ok(0),
            "SHCreateKey" => Ok(0),
            "SHDeleteEmptyKeyA" | "SHDeleteEmptyKeyW" => Ok(0),
            "SHDeleteKeyA" | "SHDeleteKeyW" => Ok(0),
            "SHDeleteValueA" | "SHDeleteValueW" => Ok(0),
            "SHEnumKeyExA" | "SHEnumKeyExW" => Ok(0),
            "SHEnumValuesA" | "SHEnumValuesW" => Ok(0),
            "SHGetValueA" | "SHGetValueW" => Ok(0),
            "SHOpenKey" => Ok(0),
            "SHQueryInfoKeyA" | "SHQueryInfoKeyW" => Ok(0),
            "SHQueryValueExA" | "SHQueryValueExW" => Ok(0),
            "SHSetValueA" | "SHSetValueW" => Ok(0),
            "SHCopyFileA" | "SHCopyFileW" => Ok(0),
            "SHMoveFileA" | "SHMoveFileW" => Ok(0),
            "ILCreateFromPathA" | "ILCreateFromPathW" => Ok(0),
            "ILIsEqual" => Ok(0),
            "ILCombine" => Ok(0),
            "ILRemoveLastSpec" => Ok(0),
            "ILGetSize" => Ok(0),
            "SHPathPrepareForWrite" => Ok(0),
            "SHWNetGetResourceInformation" => Ok(0),
            "SHWNetGetResourceParent" => Ok(0),
            "PathIsDirectoryA" | "PathIsDirectoryW" => Ok(0),
            "PathIsFileSpecA" | "PathIsFileSpecW" => Ok(0),
            "PathIsPrefixA" | "PathIsPrefixW" => Ok(0),
            "PathIsRelativeA" | "PathIsRelativeW" => Ok(1),
            "PathIsRootA" | "PathIsRootW" => Ok(0),
            "PathIsSameRootA" | "PathIsSameRootW" => Ok(0),
            "PathIsUNCServerA" | "PathIsUNCServerW" => Ok(0),
            "PathIsUNCServerShareA" | "PathIsUNCServerShareW" => Ok(0),
            "PathIsURLA" | "PathIsURLW" => Ok(0),
            "PathCanonicalizeA" | "PathCanonicalizeW" => Ok(0),
            "PathCombineA" | "PathCombineW" => Ok(0),
            "PathAppendA" | "PathAppendW" => Ok(0),
            "PathBuildRootA" | "PathBuildRootW" => Ok(0),
            "PathCompactPathA" | "PathCompactPathW" => Ok(0),
            "PathCompactPathExA" | "PathCompactPathExW" => Ok(0),
            "PathCreateFromUrlA" | "PathCreateFromUrlW" => Ok(0),
            "PathFindExtensionA" | "PathFindExtensionW" => Ok(0),
            "PathFindFileNameA" | "PathFindFileNameW" => Ok(0),
            "PathFindNextComponentA" | "PathFindNextComponentW" => Ok(0),
            "PathFindOnPathA" | "PathFindOnPathW" => Ok(0),
            "PathFindOnPathExA" | "PathFindOnPathExW" => Ok(0),
            "PathGetArgsA" | "PathGetArgsW" => Ok(0),
            "PathGetCharTypeA" | "PathGetCharTypeW" => Ok(0),
            "PathGetExtensionA" | "PathGetExtensionW" => Ok(0),
            "PathGetFileNameA" | "PathGetFileNameW" => Ok(0),
            "PathGetFileNameSizeA" | "PathGetFileNameSizeW" => Ok(0),
            "PathGetShortPathA" | "PathGetShortPathW" => Ok(0),
            "PathGetTempA" | "PathGetTempW" => Ok(0),
            "PathIsContentTypeA" | "PathIsContentTypeW" => Ok(0),
            "PathIsDeviceA" | "PathIsDeviceW" => Ok(0),
            "PathIsNetworkPathA" | "PathIsNetworkPathW" => Ok(0),
            "PathIsTempA" | "PathIsTempW" => Ok(0),
            "PathMakePrettyNameA" | "PathMakePrettyNameW" => Ok(0),
            "PathMakeSystemFolderA" | "PathMakeSystemFolderW" => Ok(0),
            "PathMatchSpecA" | "PathMatchSpecW" => Ok(0),
            "PathParseCommandLineA" | "PathParseCommandLineW" => Ok(0),
            "PathQuoteSpacesA" | "PathQuoteSpacesW" => Ok(0),
            "PathRemoveArgsA" | "PathRemoveArgsW" => Ok(0),
            "PathRemoveBackslashA" | "PathRemoveBackslashW" => Ok(0),
            "PathRemoveExtensionA" | "PathRemoveExtensionW" => Ok(0),
            "PathRemoveFileSpecA" | "PathRemoveFileSpecW" => Ok(0),
            "PathRenameExtensionA" | "PathRenameExtensionW" => Ok(0),
            "PathSetExtensionA" | "PathSetExtensionW" => Ok(0),
            "PathSkipRootA" | "PathSkipRootW" => Ok(0),
            "PathStripToRootA" | "PathStripToRootW" => Ok(0),
            "PathStripPathA" | "PathStripPathW" => Ok(0),
            "PathUndecorateA" | "PathUndecorateW" => Ok(0),
            "PathUnExpandEnvStringsA" | "PathUnExpandEnvStringsW" => Ok(0),
            "PathMakeSystemFolderA" | "PathMakeSystemFolderW" => Ok(0),
            "PathUnmakeSystemFolderA" | "PathUnmakeSystemFolderW" => Ok(0),
            "AssocCreate" => Ok(0),
            "AssocGetKey" => Ok(0),
            "AssocQueryKeyA" | "AssocQueryKeyW" => Ok(0),
            "AssocQueryStringA" | "AssocQueryStringW" => Ok(0),
            "AssocIsFullQualify" => Ok(0),
            "SHAssocEnumHandlers" => Ok(0),
            "SHAssocEnumHandlersForProtocol" => Ok(0),
            "SHGetAttribute" => Ok(0),
            "SHGetPropertyStore" => Ok(0),
            "SHGetPropertyStoreFromIDList" => Ok(0),
            "SHGetPropertyStoreFromParsingName" => Ok(0),
            "IPropertyStoreCommit" => Ok(0),
            "IPropertyStoreGetCount" => Ok(0),
            "IPropertyStoreGetAt" => Ok(0),
            "IPropertyStoreGetValue" => Ok(0),
            "IPropertyStoreSetValue" => Ok(0),
            "SHPropStgCreate" => Ok(0),
            "SHPropStgReadMultiple" => Ok(0),
            "SHPropStgWriteMultiple" => Ok(0),
            "SHCreatePropertyStore" => Ok(0),
            "SHGetPropertyStoreForWindow" => Ok(0),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Shell32"
    }
}
