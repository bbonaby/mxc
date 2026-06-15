// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc_wfp_sys` — unsafe FFI to the Windows Filtering Platform and the
//! Win32 security primitives MXC needs.
//!
//! Every function in this crate is `unsafe` and documented with a short
//! `# Safety` clause. The safe wrapper crate (`mxc_wfp`) is the only
//! intended caller. Nothing here interprets results; raw `u32` status
//! codes and raw pointers are returned as-is.
//!
//! Rationale for the sys/safe split: keeping all `extern "system"`
//! call sites in one crate gives us a single audit surface for FFI
//! correctness. Consumers depend on `mxc_wfp` and never touch this
//! crate directly.

#![cfg(target_os = "windows")]
// Pure FFI — the entire crate is a thin shim, allow unsafe ops at
// the crate root.
#![allow(clippy::missing_safety_doc)] // every fn has its own.

use std::ffi::c_void;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{ACL, PSECURITY_DESCRIPTOR, PSID};

// Re-export every type the wrapper layer needs to *describe* a call,
// so callers don't import directly from `windows::*`. The glob
// re-export below makes the WFP type/function names available locally
// too, so the FFI bodies don't need separate `use` lines (those would
// shadow the glob and trigger `hidden_glob_reexports`).
pub use windows::core::{GUID as Guid, PCWSTR as PCWStr, PWSTR as PWStr};
pub use windows::Win32::Foundation::{
    LocalFree, ERROR_SUCCESS, FWP_E_ALREADY_EXISTS, HANDLE as Handle, HLOCAL as HLocal,
};
pub use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
pub use windows::Win32::Security::Authorization::{
    ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS,
    SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
pub use windows::Win32::Security::{
    ACL as Acl, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR as PSecurityDescriptor, PSID as PSid,
};
pub use windows::Win32::System::Rpc::{RPC_C_AUTHN_DEFAULT, RPC_C_AUTHN_WINNT};

// ─────────────────────────────────────────────────────────────────────
// Engine lifecycle
// ─────────────────────────────────────────────────────────────────────

/// Open a session against the BFE engine.
///
/// # Safety
/// - `session` (if `Some`) must point to a fully-initialised `FWPM_SESSION0`
///   whose embedded pointers (display name etc.) outlive this call.
/// - `engine_out` must be valid for writes of one `HANDLE`.
pub unsafe fn engine_open(
    auth_service: u32,
    session: Option<&FWPM_SESSION0>,
    engine_out: &mut HANDLE,
) -> u32 {
    unsafe {
        FwpmEngineOpen0(
            None,
            auth_service,
            None,
            session.map(|s| s as *const _),
            engine_out as *mut _,
        )
    }
}

/// Open a session against the BFE engine with a non-null `server_name`.
/// Mirrors `engine_open` plus the optional UNC server.
///
/// # Safety
/// Same as [`engine_open`].
pub unsafe fn engine_open_local() -> Result<HANDLE, u32> {
    let mut h = HANDLE::default();
    // RPC_C_AUTHN_WINNT (10) — anonymous (0) returns ERROR_NOT_SUPPORTED on
    // the local BFE endpoint.
    let rc = unsafe { FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &mut h) };
    if rc == 0 {
        Ok(h)
    } else {
        Err(rc)
    }
}

/// Close an engine handle obtained from `engine_open*`.
///
/// # Safety
/// `engine` must be a handle returned by `engine_open*` and not yet closed.
pub unsafe fn engine_close(engine: HANDLE) {
    unsafe {
        let _ = FwpmEngineClose0(engine);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Engine SD (BFE security descriptor)
// ─────────────────────────────────────────────────────────────────────

/// Read the engine's security info into newly-allocated buffers owned
/// by the system. Caller must `LocalFree` the security-descriptor on
/// success.
///
/// # Safety
/// - `engine` must be a live engine handle.
/// - `dacl_out` and `sd_out` must be valid for writes.
pub unsafe fn engine_get_security_info(
    engine: HANDLE,
    security_info: u32,
    dacl_out: *mut *mut ACL,
    sd_out: *mut PSECURITY_DESCRIPTOR,
) -> u32 {
    unsafe {
        FwpmEngineGetSecurityInfo0(
            engine,
            security_info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl_out,
            std::ptr::null_mut(),
            sd_out,
        )
    }
}

/// Replace the DACL on the engine's security descriptor.
///
/// # Safety
/// - `engine` must be a live engine handle.
/// - `dacl` must outlive this call.
/// - Caller must hold `WRITE_DAC` on the engine SD (LocalSystem does).
pub unsafe fn engine_set_dacl(engine: HANDLE, dacl: *const ACL) -> u32 {
    unsafe {
        FwpmEngineSetSecurityInfo0(
            engine,
            DACL_SECURITY_INFORMATION_VALUE,
            None,
            None,
            Some(dacl),
            None,
        )
    }
}

/// Constant alias — `DACL_SECURITY_INFORMATION.0`. Re-exporting the
/// raw `u32` so callers don't need to dereference the newtype.
pub const DACL_SECURITY_INFORMATION_VALUE: u32 = 0x00000004;

// ─────────────────────────────────────────────────────────────────────
// Provider / Sublayer / Filter
// ─────────────────────────────────────────────────────────────────────

/// Add a provider object to the engine.
///
/// # Safety
/// - `engine` must be live.
/// - `provider` must be fully initialised; its embedded pointers
///   (display name, etc.) must outlive this call.
pub unsafe fn provider_add(engine: HANDLE, provider: &FWPM_PROVIDER0) -> u32 {
    unsafe { FwpmProviderAdd0(engine, provider as *const _, None) }
}

/// Add a sublayer object to the engine.
///
/// # Safety
/// As for [`provider_add`].
pub unsafe fn sublayer_add(engine: HANDLE, sublayer: &FWPM_SUBLAYER0) -> u32 {
    unsafe { FwpmSubLayerAdd0(engine, sublayer as *const _, None) }
}

/// Install a filter; on success the engine assigns a 64-bit filter id.
///
/// # Safety
/// - `engine` must be live.
/// - `filter` must be fully initialised with its embedded
///   `FWPM_FILTER_CONDITION0` array (`filterCondition` / `numFilterConditions`)
///   and weight storage outliving this call.
/// - `filter_id_out` (when `Some`) must be valid for writes.
pub unsafe fn filter_add(
    engine: HANDLE,
    filter: &FWPM_FILTER0,
    filter_id_out: Option<&mut u64>,
) -> u32 {
    unsafe {
        FwpmFilterAdd0(
            engine,
            filter as *const _,
            None,
            filter_id_out.map(|p| p as *mut _),
        )
    }
}

/// Delete a filter by its engine-assigned 64-bit id.
///
/// # Safety
/// `engine` must be live. `id` may be stale — non-zero status is the
/// signal.
pub unsafe fn filter_delete_by_id(engine: HANDLE, id: u64) -> u32 {
    unsafe { FwpmFilterDeleteById0(engine, id) }
}

// ─────────────────────────────────────────────────────────────────────
// SID + ACL helpers (Win32 security)
// ─────────────────────────────────────────────────────────────────────

/// Convert an SDDL SID string to a `LocalAlloc`-backed `PSID`.
///
/// # Safety
/// - `sddl` must be a NUL-terminated UTF-16 buffer.
/// - On success the caller owns the returned `PSID` and must release
///   it with `LocalFree`.
pub unsafe fn convert_string_sid_to_sid(
    sddl: PCWSTR,
    sid_out: &mut PSID,
) -> windows_core::Result<()> {
    unsafe { ConvertStringSidToSidW(sddl, sid_out as *mut _) }
}

/// Release a `LocalAlloc`-backed pointer (SID buffer or ACL buffer).
///
/// # Safety
/// `ptr` must have been returned by an API that documents `LocalAlloc`
/// ownership (e.g. `ConvertStringSidToSidW`, `SetEntriesInAclW`).
pub unsafe fn local_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(ptr)));
        }
    }
}

/// Build a new ACL by merging an `EXPLICIT_ACCESS_W` array into a
/// (possibly null) existing ACL. The returned ACL pointer is
/// `LocalAlloc`-backed.
///
/// # Safety
/// - `entries` must reference valid `EXPLICIT_ACCESS_W` records whose
///   trustees and embedded pointers outlive this call.
/// - `old_acl` (if non-null) must be a valid ACL pointer.
/// - `new_acl_out` must be valid for writes; on success it owns a
///   `LocalAlloc`-backed buffer.
pub unsafe fn set_entries_in_acl(
    entries: &[EXPLICIT_ACCESS_W],
    old_acl: *const ACL,
    new_acl_out: *mut *mut ACL,
) -> u32 {
    let r = unsafe { SetEntriesInAclW(Some(entries), Some(old_acl), new_acl_out) };
    r.0
}

// ─────────────────────────────────────────────────────────────────────
// Owning RAII wrappers for LocalAlloc-backed buffers
// ─────────────────────────────────────────────────────────────────────

/// Owns a `LocalAlloc`-backed pointer; calls `LocalFree` on drop.
/// Safe to construct from any pointer satisfying that contract.
pub struct LocalAllocOwned(pub *mut c_void);

impl Drop for LocalAllocOwned {
    fn drop(&mut self) {
        // SAFETY: by the type's invariant the pointer (if non-null) was
        // produced by a `LocalAlloc`-returning API.
        unsafe { local_free(self.0) }
    }
}

impl LocalAllocOwned {
    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}
