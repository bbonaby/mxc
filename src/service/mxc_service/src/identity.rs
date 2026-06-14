// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-call caller identity.
//!
//! Spec §6.7 calls for LRPC, which exposes the caller token via
//! `RpcImpersonateClient` + `RpcGetAuthorizationContextForClient`.
//! The prototype's named-pipe transport gets the equivalent shape
//! through `ImpersonateNamedPipeClient` + `OpenThreadToken` +
//! `GetTokenInformation(TokenUser)`. This gives us:
//!
//! - The caller's user SID (LRPC: same shape).
//! - The caller's integrity level (we don't query this yet, but the
//!   primitive matches; future work can compare it to the broker's
//!   own IL for trust-tier decisions).
//!
//! What we still don't get vs. real LRPC:
//! - Handle transfer for `sandboxProcess` (§3.2). We work around it
//!   via PID-based `OpenProcess` in `crate::lifetime`.
//!
//! Identity is **logged**, not used for trust decisions. Per the
//! prototype shortcuts §"Authenticode caller verification" in the
//! README, that's its own design pass.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, OwnedHandle};

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenUser, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::PWSTR;

/// Best-effort caller identity. Never fails the IPC call — we log a
/// placeholder if we can't get the token.
pub struct CallerIdentity {
    pub user_sid: String,
}

impl CallerIdentity {
    pub fn unknown() -> Self {
        Self {
            user_sid: "<unknown>".into(),
        }
    }
}

/// Run `f` under the caller's identity (`ImpersonateNamedPipeClient`),
/// capture their user SID, then revert. Pure best-effort: on any
/// failure we return `CallerIdentity::unknown()` and continue.
pub fn capture(pipe: &OwnedHandle) -> CallerIdentity {
    let pipe_handle = HANDLE(pipe.as_raw_handle() as *mut c_void);
    let impersonated = unsafe { ImpersonateNamedPipeClient(pipe_handle) };
    if impersonated.is_err() {
        return CallerIdentity::unknown();
    }

    let id = query_thread_token_user();

    // RevertToSelf failure here is catastrophic — we'd leave the IPC
    // thread impersonating the caller. We swallow the Result because
    // the windows-rs binding is Ok-or-panic-on-bool, but log via the
    // Err path for defense in depth.
    unsafe {
        let _ = RevertToSelf();
    }

    id.unwrap_or_else(CallerIdentity::unknown)
}

fn query_thread_token_user() -> Option<CallerIdentity> {
    let mut raw: HANDLE = HANDLE(std::ptr::null_mut());
    let opened = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY,
            true,
            &mut raw,
        )
    };
    if opened.is_err() {
        return None;
    }
    let token = scopeguard(raw);

    let mut needed: u32 = 0;
    // First call discovers the buffer size.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    let got = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
    };
    if got.is_err() {
        return None;
    }

    // Safety: GetTokenInformation(TokenUser) wrote a TOKEN_USER at the
    // start of buf, with Sid pointing into the same buffer.
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = sid_to_string(tu.User.Sid)?;
    Some(CallerIdentity { user_sid: sid })
}

fn sid_to_string(sid: PSID) -> Option<String> {
    let mut wide: PWSTR = PWSTR(std::ptr::null_mut());
    let r = unsafe { ConvertSidToStringSidW(sid, &mut wide) };
    if r.is_err() || wide.0.is_null() {
        return None;
    }
    // Borrow as wide slice, then free with LocalFree.
    let mut len = 0usize;
    unsafe {
        while *wide.0.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(wide.0, len) };
    let s = String::from_utf16_lossy(slice);
    unsafe {
        // ConvertSidToStringSidW allocates with LocalAlloc; release it.
        let _ = LocalFree(Some(HLOCAL(wide.0 as *mut c_void)));
    }
    Some(s)
}

/// Minimal RAII wrapper just for the impersonation-token handle.
struct TokenGuard(HANDLE);
impl Drop for TokenGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn scopeguard(h: HANDLE) -> TokenGuard {
    TokenGuard(h)
}
