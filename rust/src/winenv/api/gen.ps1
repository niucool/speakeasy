$apis = @("advapi32", "advpack", "bcrypt", "bcryptprimitives", "com_api", "comctl32", "crypt32", "dnsapi", "gdi32", "iphlpapi", "lz32", "mpr", "mscoree", "msi32", "msimg32", "msvcrt", "msvfw32", "ncrypt", "netapi32", "netutils", "ntdll", "ole32", "oleaut32", "psapi", "rpcrt4", "secur32", "sfc", "sfc_os", "shell32", "shlwapi", "urlmon", "winhttp", "wininet", "winmm", "wkscli", "wtsapi32")

$modContents = @"
pub mod kernel32;
pub mod user32;
pub mod ws2_32;

"@

foreach ($api in $apis) {
    $handlerName = ""
    # Make handler name PascalCase-ish
    foreach ($part in $api.Split("_")) {
        if ($part.Length -gt 0) {
            $handlerName += $part.Substring(0,1).ToUpper() + $part.Substring(1)
        }
    }
    
    $content = @"
use crate::winenv::api::ApiHandler;

pub struct $($handlerName)Handler;

impl ApiHandler for $($handlerName)Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "$handlerName"
    }
}
"@

    Out-File -FilePath "c:\Projects\github\speakeasy\rust\src\winenv\api\usermode\$api.rs" -InputObject $content -Encoding UTF8
    $modContents += "pub mod $api;`n"
}

Out-File -FilePath "c:\Projects\github\speakeasy\rust\src\winenv\api\usermode\mod.rs" -InputObject $modContents -Encoding UTF8

$k_apis = @("fwpkclnt", "hal", "ndis", "netio", "usbd", "wdfldr")

$kmodContents = @"
pub mod ntoskrnl;

"@

foreach ($api in $k_apis) {
    $handlerName = ""
    foreach ($part in $api.Split("_")) {
        if ($part.Length -gt 0) {
            $handlerName += $part.Substring(0,1).ToUpper() + $part.Substring(1)
        }
    }
    $content = @"
use crate::winenv::api::ApiHandler;

pub struct $($handlerName)Handler;

impl ApiHandler for $($handlerName)Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "$handlerName"
    }
}
"@

    Out-File -FilePath "c:\Projects\github\speakeasy\rust\src\winenv\api\kernelmode\$api.rs" -InputObject $content -Encoding UTF8
    $kmodContents += "pub mod $api;`n"
}

Out-File -FilePath "c:\Projects\github\speakeasy\rust\src\winenv\api\kernelmode\mod.rs" -InputObject $kmodContents -Encoding UTF8
