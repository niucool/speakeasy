// defs_new_compat.h  Migration bridge from old defs (runtime ptr_sz) to new deffs (compile-time templates)
//
// This header provides:
//   1. Aggregated includes for all deffs headers
//   2. new_by_ptr_sz<T8,T4>(ptr_sz) factory helper: dispatch runtime ptr_sz  compile-time template
//   3. compat::static_typed<T8,T4>(ptr_sz, code) helper: dispatch static_cast + field access
//
// Usage patterns:
//   // Construction
//   object_ = new_by_ptr_sz<TEB<8>, TEB<4>>(ptr_sz);
//   object_ = new_by_ptr_sz<PEB<8>, PEB<4>>(ptr_sz);
//   object_ = new ETHREAD();  // non-template (fixed-size)
//
//   // Field access with type dispatch
//   compat::with_typed<TEB<8>, TEB<4>>(
//       ptr_sz, obj, [](auto* t) { t->NtTib_StackBase = ...; });
//
#ifndef SPEAKEASY_DEFS_NEW_COMPAT_H
#define SPEAKEASY_DEFS_NEW_COMPAT_H

// Include all deffs headers
#include "nt/ntoskrnl.h"
#include "registry/reg.h"
#include "usb.h"
#include "wdf.h"
#include "wsk.h"
#include "wininet.h"
#include "ndis/ndis.h"
#include "wfp/fwpmtypes.h"
#include "winsock/ws2_32.h"
#include "winsock/winsock.h"
#include "windows/windef.h"
#include "windows/kernel32.h"
#include "windows/user32.h"
#include "windows/shell32.h"
#include "windows/advapi32.h"
#include "windows/iphlpapi.h"
#include "windows/netapi32.h"
#include "windows/windows.h"
#include "windows/com.h"
#include "windows/mpr.h"
#include "windows/secur32.h"

namespace speakeasy { namespace deffs {

// Factory: creates a template-parameterized struct at runtime, dispatching on ptr_sz.
// Returns void* so it can be stored in KernelObject's object_ field (just like the old code).
template <typename T8, typename T4>
inline void* new_by_ptr_sz(int ptr_sz) noexcept {
    if (ptr_sz == 8)
        return new T8();
    return new T4();
}

namespace compat {

// Helper: cast void* to the right template instantiation and invoke a lambda
// The lambda gets the correctly-typed pointer.
template <typename T8, typename T4, typename Fn>
inline auto with_typed(int ptr_sz, void* obj, Fn&& fn) -> decltype(fn(static_cast<T8*>(obj))) {
    if (ptr_sz == 8)
        return fn(static_cast<T8*>(obj));
    return fn(static_cast<T4*>(obj));
}

// Helper: cast void* to the right template instantiation and invoke a lambda
// The lambda gets the correctly-typed const pointer.
template <typename T8, typename T4, typename Fn>
inline auto with_typed_const(int ptr_sz, const void* obj, Fn&& fn) -> decltype(fn(static_cast<const T8*>(obj))) {
    if (ptr_sz == 8)
        return fn(static_cast<const T8*>(obj));
    return fn(static_cast<const T4*>(obj));
}

} // namespace compat
}} // namespace speakeasy::deffs

#endif // SPEAKEASY_DEFS_NEW_COMPAT_H
