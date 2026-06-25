/**
 * hook_gpa.js — JavaScript plugin that hooks kernel32.GetProcAddress
 *
 * Captures every GetProcAddress call and logs the module, function name,
 * and return value.  Collected data is exposed on globalThis.__gpaResults
 * for test verification.
 *
 * Usage:
 *   speakeasy-cli -t tests/bins/GetProcAddress.exe -j tests/js/hook_gpa.js
 */

// Use globalThis so the test can read results after emulation
//globalThis.__gpaResults = [];

/* */
var hook = new ApiHook();
hook.OnCallBack = function(api, args) {
    // api:  string like "kernel32.GetProcAddress"
    // args: array of uint64_t values (hModule, lpProcName, ...)
    var hModule = args[0];
    var procName = args[1];

    var entry = {
        api: api,
        hModule: Number(hModule),
        procName: String(procName),
    };
    //globalThis.__gpaResults.push(entry);

    log("[hook] GetProcAddress: hModule=" + entry.hModule.toString(16) +
        " proc=" + entry.procName);
};

hook.OnExit = function(api, args, retval) {
    //var last = globalThis.__gpaResults[globalThis.__gpaResults.length - 1];
    //if (last) {
    //    last.retval = Number(retval);
        log("[hook] GetProcAddress returned: 0x" + retval.toString(16));
    //}
};

if(hook.install("kernel32", "GetProcAddress")) {
  log("[hook] GetProcAddress hook installed");
}
else {
  log("[hook] GetProcAddress hook install failed");
}
//log(Reflect.ownKeys(globalThis).sort());
try {
    const keys = Object.getOwnPropertyNames(globalThis).sort();
    log("OK:", JSON.stringify(keys));
} catch (error) {
    log("Fail:", error.message);
}
log("[hook] bye");

