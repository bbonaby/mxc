// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-call caller identity (LRPC).
//!
//! Spec §6.7 transport is LRPC. Inside an RPC server callback we use
//! `RpcImpersonateClient(NULL)` to adopt the caller's token on the
//! current thread, then `OpenThreadToken` + `GetTokenInformation(TokenUser)`
//! to recover the caller's user SID, then `RpcRevertToSelf` to drop the
//! impersonation.
//!
//! Identity is **logged**, not used for trust decisions. Authenticode
//! caller verification remains its own design pass.

use std::ffi::c_void;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Rpc::{RpcImpersonateClient, RpcRevertToSelf, RPC_STATUS};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::PWSTR;

const RPC_S_OK: RPC_STATUS = RPC_STATUS(0);

pub struct CallerIdentity {
    pub user_sid: String,
}

impl CallerIdentity {
    pub fn unknown() -> Self {
        Self { user_sid: "<unknown>".into() }
    }
}

/// Capture the caller's user SID from the active LRPC call. Best-effort:
/// returns `CallerIdentity::unknown()` if impersonation or token lookup
/// fails. Must be invoked from inside an RPC server handler (otherwise
/// `RpcImpersonateClient` has no call context and fails).
pub fn capture_lrpc() -> CallerIdentity {
    let status = unsafe { RpcImpersonateClient(None) };
    if status != RPC_S_OK {
        crate::diag::emit(format!("identity: RpcImpersonateClient failed: {status:?}"));
        return CallerIdentity::unknown();
    }

    let id = query_thread_token_user();

    unsafe {
        let _ = RpcRevertToSelf();
    }

    id.unwrap_or_else(|| {
        crate::diag::emit("identity: OpenThreadToken / GetTokenInformation returned None");
        CallerIdentity::unknown()
    })
}

fn query_thread_token_user() -> Option<CallerIdentity> {
    let mut raw: HANDLE = HANDLE(std::ptr::null_mut());
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut raw) };
    if opened.is_err() {
        return None;
    }
    let _guard = TokenGuard(raw);

    let mut needed: u32 = 0;
    let _ = unsafe { GetTokenInformation(raw, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    let got = unsafe {
        GetTokenInformation(
            raw,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
    };
    if got.is_err() {
        return None;
    }

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
    let mut len = 0usize;
    unsafe {
        while *wide.0.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(wide.0, len) };
    let s = String::from_utf16_lossy(slice);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(wide.0 as *mut c_void)));
    }
    Some(s)
}

struct TokenGuard(HANDLE);
impl Drop for TokenGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
