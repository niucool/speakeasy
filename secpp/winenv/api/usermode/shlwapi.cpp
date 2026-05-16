// shlwapi.cpp — shlwapi.dll handler (~15 APIs, macro-driven stubs)
#include "shlwapi.h"

namespace speakeasy { namespace api {

Shlwapi::Shlwapi() {
    INIT_API_TABLE(Shlwapi)
    REG(Shlwapi, PathIsRelative, 1)      REG(Shlwapi, StrStr, 2)
    REG(Shlwapi, StrStrI, 2)             REG(Shlwapi, PathFindExtension, 1)
    REG(Shlwapi, StrCmpI, 2)             REG(Shlwapi, PathFindFileName, 1)
    REG(Shlwapi, PathRemoveExtension, 1) REG(Shlwapi, PathStripPath, 1)
    REG(Shlwapi, wvnsprintfA, 4)         REG(Shlwapi, wnsprintf, 4)
    REG(Shlwapi, PathAppend, 2)          REG(Shlwapi, PathCanonicalize, 2)
    REG(Shlwapi, PathRemoveFileSpec, 1)  REG(Shlwapi, PathAddBackslash, 1)
    REG(Shlwapi, PathRenameExtension, 2)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define SHLWAPI_STUB(n) STUB(Shlwapi, n)

SHLWAPI_STUB(PathIsRelative) SHLWAPI_STUB(StrStr) SHLWAPI_STUB(StrStrI)
SHLWAPI_STUB(PathFindExtension) SHLWAPI_STUB(StrCmpI)
SHLWAPI_STUB(PathFindFileName) SHLWAPI_STUB(PathRemoveExtension)
SHLWAPI_STUB(PathStripPath) SHLWAPI_STUB(wvnsprintfA)
SHLWAPI_STUB(wnsprintf) SHLWAPI_STUB(PathAppend)
SHLWAPI_STUB(PathCanonicalize) SHLWAPI_STUB(PathRemoveFileSpec)
SHLWAPI_STUB(PathAddBackslash) SHLWAPI_STUB(PathRenameExtension)

}} // namespaces
