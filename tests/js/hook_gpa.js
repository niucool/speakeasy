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
let hook = ApiHook.install({
    lib: "kernel32",
    api: "GetProcAddress",

    onCallBack: function(api, args) {
        // api: string like "kernel32.GetProcAddress"
        // args: array of uint64_t values (hModule, lpProcName, ...)

        var hModule = args[0];
        var procName = args[1];

		if(procName < 0xFFFF)
		    procName = "ordinal_" + String(procName);
		else
		    procName = Emu.ReadStringA(procName, 0);
		  
        var entry = {
            api: api,
            hModule: Number(hModule),
            procName: procName,
        };

        // globalThis.__gpaResults.push(entry);

        log(
            "[hook] " + api + ": hModule=" +
            entry.hModule.toString(16) +
            " proc=" +
            entry.procName
        );
    },


    onExit: function(api, args, retval) {
        // var last =
        //     globalThis.__gpaResults[
        //         globalThis.__gpaResults.length - 1
        //     ];

        // if (last) {
        //     last.retval = Number(retval);
        // }

        log(
            "[hook] GetProcAddress returned: 0x" +
            retval.toString(16)
        );
    }
});

if (hook) {
    log("installed: " + hook.id);
}

//log(Reflect.ownKeys(globalThis).sort());
try {
    const keys = Object.getOwnPropertyNames(globalThis).sort();
    log("OK:", JSON.stringify(keys));
} catch (error) {
    log("Fail:", error.message);
}
log("[hook] bye");

