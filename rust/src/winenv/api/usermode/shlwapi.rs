use std::path::{Path, PathBuf};

use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct ShlwapiHandler;

impl ShlwapiHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn path_append(base: &str, more: &str) -> String {
        let mut path = PathBuf::from(base);
        path.push(more);
        path.to_string_lossy().to_string()
    }

    pub fn path_file_exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    pub fn path_find_file_name(path: &str) -> String {
        Path::new(path)
            .file_name()
            .map(|part| part.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string())
    }

    pub fn path_remove_file_spec(path: &str) -> String {
        Path::new(path)
            .parent()
            .map(|part| part.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    pub fn path_is_relative(path: &str) -> bool {
        Path::new(path).is_relative()
    }
}

impl Default for ShlwapiHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for ShlwapiHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "PathAppendA" | "PathAppendW" => Ok(1),
            "PathBuildRootA" | "PathBuildRootW" => Ok(0),
            "PathCanonicalizeA" | "PathCanonicalizeW" => Ok(0),
            "PathCombineA" | "PathCombineW" => Ok(0),
            "PathCommonPrefixA" | "PathCommonPrefixW" => Ok(0),
            "PathCompactPathA" | "PathCompactPathW" => Ok(0),
            "PathCompactPathExA" | "PathCompactPathExW" => Ok(0),
            "PathCreateFromUrlA" | "PathCreateFromUrlW" => Ok(0),
            "PathFileExistsA" | "PathFileExistsW" => Ok(0),
            "PathFindExtensionA" | "PathFindExtensionW" => Ok(0),
            "PathFindFileNameA" | "PathFindFileNameW" => Ok(0),
            "PathFindNextComponentA" | "PathFindNextComponentW" => Ok(0),
            "PathFindOnPathA" | "PathFindOnPathW" => Ok(0),
            "PathFindOnPathExA" | "PathFindOnPathExW" => Ok(0),
            "PathGetArgsA" | "PathGetArgsW" => Ok(0),
            "PathGetCharTypeA" | "PathGetCharTypeW" => Ok(0),
            "PathGetDirectoryA" | "PathGetDirectoryW" => Ok(0),
            "PathGetDriveNumberA" | "PathGetDriveNumberW" => Ok(-1),
            "PathGetExtensionA" | "PathGetExtensionW" => Ok(0),
            "PathGetFileNameA" | "PathGetFileNameW" => Ok(0),
            "PathGetFileNameSizeA" | "PathGetFileNameSizeW" => Ok(0),
            "PathGetFullPathNameA" | "PathGetFullPathNameW" => Ok(0),
            "PathGetLongPathNameA" | "PathGetLongPathNameW" => Ok(0),
            "PathGetShortPathNameA" | "PathGetShortPathNameW" => Ok(0),
            "PathGetTempDriveA" | "PathGetTempDriveW" => Ok(0),
            "PathGetTempPathA" | "PathGetTempPathW" => Ok(0),
            "PathIsDirectoryA" | "PathIsDirectoryW" => Ok(0),
            "PathIsFileSpecA" | "PathIsFileSpecW" => Ok(0),
            "PathIsPrefixA" | "PathIsPrefixW" => Ok(0),
            "PathIsRelativeA" | "PathIsRelativeW" => Ok(1),
            "PathIsRootA" | "PathIsRootW" => Ok(0),
            "PathIsSameRootA" | "PathIsSameRootW" => Ok(0),
            "PathIsUNCServerA" | "PathIsUNCServerW" => Ok(0),
            "PathIsUNCServerShareA" | "PathIsUNCServerShareW" => Ok(0),
            "PathIsURLA" | "PathIsURLW" => Ok(0),
            "PathMakePrettyNameA" | "PathMakePrettyNameW" => Ok(0),
            "PathMatchSpecA" | "PathMatchSpecW" => Ok(0),
            "PathParseCommandLineA" | "PathParseCommandLineW" => Ok(0),
            "PathQuoteSpacesA" | "PathQuoteSpacesW" => Ok(0),
            "PathRelativePathToA" | "PathRelativePathToW" => Ok(0),
            "PathRemoveArgsA" | "PathRemoveArgsW" => Ok(0),
            "PathRemoveBackslashA" | "PathRemoveBackslashW" => Ok(0),
            "PathRemoveExtensionA" | "PathRemoveExtensionW" => Ok(0),
            "PathRemoveFileSpecA" | "PathRemoveFileSpecW" => Ok(0),
            "PathRenameExtensionA" | "PathRenameExtensionW" => Ok(0),
            "PathSearchAndQualifyA" | "PathSearchAndQualifyW" => Ok(0),
            "PathSetExtensionA" | "PathSetExtensionW" => Ok(0),
            "PathSkipRootA" | "PathSkipRootW" => Ok(0),
            "PathStripPathA" | "PathStripPathW" => Ok(0),
            "PathStripToRootA" | "PathStripToRootW" => Ok(0),
            "PathUndecorateA" | "PathUndecorateW" => Ok(0),
            "PathUnExpandEnvStringsA" | "PathUnExpandEnvStringsW" => Ok(0),
            "PathMakeSystemFolderA" | "PathMakeSystemFolderW" => Ok(0),
            "PathUnmakeSystemFolderA" | "PathUnmakeSystemFolderW" => Ok(0),
            "UrlCanonicalizeA" | "UrlCanonicalizeW" => Ok(0),
            "UrlCombineA" | "UrlCombineW" => Ok(0),
            "UrlCompareA" | "UrlCompareW" => Ok(0),
            "UrlCreateFromPathA" | "UrlCreateFromPathW" => Ok(0),
            "UrlDestroyFile" => Ok(0),
            "UrlEscapeA" | "UrlEscapeW" => Ok(0),
            "UrlGetFileSizeA" | "UrlGetFileSizeW" => Ok(0),
            "UrlGetHostA" | "UrlGetHostW" => Ok(0),
            "UrlGetPartW" => Ok(0),
            "UrlHashA" | "UrlHashW" => Ok(0),
            "UrlIsFileUrlA" | "UrlIsFileUrlW" => Ok(0),
            "UrlIsNoHistoryA" | "UrlIsNoHistoryW" => Ok(0),
            "UrlIsOpaqueA" | "UrlIsOpaqueW" => Ok(0),
            "UrlParseUrlA" | "UrlParseUrlW" => Ok(0),
            "UrlUnescapeA" | "UrlUnescapeW" => Ok(0),
            "HashData" => Ok(0),
            "SHRegisterValidateTemplate" => Ok(0),
            "SHRunEmbeddedUI" => Ok(0),
            "GetWindowWord" => Ok(0),
            "SetWindowWord" => Ok(0),
            "GetWindowLong" => Ok(0),
            "SetWindowLong" => Ok(0),
            "CallWindowProcA" | "CallWindowProcW" => Ok(0),
            "wnsprintfA" | "wnsprintfW" => Ok(0),
            "wvsprintfA" | "wvsprintfW" => Ok(0),
            "IntToStrA" | "IntToStrW" => Ok(0),
            "IntToStrExA" | "IntToStrExW" => Ok(0),
            "StrToIntA" | "StrToIntW" => Ok(0),
            "StrToIntExA" | "StrToIntExW" => Ok(0),
            "StrToInt64ExA" | "StrToInt64ExW" => Ok(0),
            "StrFromTimeIA" | "StrFromTimeIW" => Ok(0),
            "StrFromTime64IA" | "StrFromTime64IW" => Ok(0),
            "StrToTimeA" | "StrToTimeW" => Ok(0),
            "StrToTime64A" | "StrToTime64W" => Ok(0),
            "GetDateFormatA" | "GetDateFormatW" => Ok(0),
            "GetTimeFormatA" | "GetTimeFormatW" => Ok(0),
            "LCMapStringA" | "LCMapStringW" => Ok(0),
            "FoldStringA" | "FoldStringW" => Ok(0),
            "EnumSystemLocalesA" | "EnumSystemLocalesW" => Ok(0),
            "EnumCalendarInfoA" | "EnumCalendarInfoW" => Ok(0),
            "EnumTimeFormatsA" | "EnumTimeFormatsW" => Ok(0),
            "IsValidLocale" => Ok(1),
            "GetGeoInfoA" | "GetGeoInfoW" => Ok(0),
            "GetUserDefaultLangID" => Ok(0x409),
            "GetUserDefaultLCID" => Ok(0x409),
            "GetSystemDefaultLangID" => Ok(0x409),
            "GetSystemDefaultLCID" => Ok(0x409),
            "GetThreadLocale" => Ok(0xC000),
            "SetThreadLocale" => Ok(1),
            "GetNumberFormatA" | "GetNumberFormatW" => Ok(0),
            "GetCurrencyFormatA" | "GetCurrencyFormatW" => Ok(0),
            "GetLocaleInfoA" | "GetLocaleInfoW" => Ok(0),
            "SetLocaleInfoA" | "SetLocaleInfoW" => Ok(1),
            "GetACP" => Ok(1252),
            "GetOEMCP" => Ok(437),
            "GetCPInfo" => Ok(1),
            "IsValidCodePage" => Ok(1),
            "GetCodePageInfo" => Ok(1),
            "GetStringTypeA" | "GetStringTypeW" => Ok(1),
            "GetStringTypeExA" | "GetStringTypeExW" => Ok(1),
            "CompareStringA" | "CompareStringW" => Ok(2),
            "LCMapStringA" | "LCMapStringW" => Ok(0),
            "MulDiv" => Ok(10),
            "SHRegisterValidateTemplate" => Ok(0),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Shlwapi"
    }
}
