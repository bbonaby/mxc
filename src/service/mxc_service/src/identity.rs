// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-call caller identity (LRPC).

use std::ffi::c_void;
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Rpc::{RpcImpersonateClient, RpcRevertToSelf, RPC_STATUS};
use windows::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenThreadToken, QueryFullProcessImageNameW,
    PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::PWSTR;

const RPC_S_OK: RPC_STATUS = RPC_STATUS(0);

// I_RpcBindingInqLocalClientPID — the only documented way to recover the
// caller PID for an LRPC call from inside a server handler. Stable since
// Windows XP and exported by rpcrt4.dll under this name.
#[link(name = "rpcrt4")]
unsafe extern "system" {
    fn I_RpcBindingInqLocalClientPID(binding: *mut c_void, pid: *mut u32) -> i32;
}

pub struct CallerIdentity {
    pub user_sid: String,
    pub pid: Option<u32>,
    pub image_path: Option<PathBuf>,
}

impl CallerIdentity {
    #[allow(dead_code)]
    pub fn unknown() -> Self {
        Self { user_sid: "<unknown>".into(), pid: None, image_path: None }
    }
}

/// Capture the caller's user SID + PID + image path from the active
/// LRPC call. Best-effort: missing pieces become `None`. Must be invoked
/// from inside an RPC server handler.
pub fn capture_lrpc() -> CallerIdentity {
    let mut user_sid = "<unknown>".to_string();

    let imp = unsafe { RpcImpersonateClient(None) };
    if imp == RPC_S_OK {
        if let Some(id) = query_thread_token_user() {
            user_sid = id;
        }
        unsafe {
            let _ = RpcRevertToSelf();
        }
    } else {
        crate::diag::emit(format!("identity: RpcImpersonateClient failed: {imp:?}"));
    }

    let pid = query_caller_pid();
    let image_path = pid.and_then(|p| process_image_path(p));

    CallerIdentity { user_sid, pid, image_path }
}

fn query_caller_pid() -> Option<u32> {
    let mut pid: u32 = 0;
    let status = unsafe { I_RpcBindingInqLocalClientPID(std::ptr::null_mut(), &mut pid) };
    if status == 0 && pid != 0 { Some(pid) } else { None }
}

fn process_image_path(pid: u32) -> Option<PathBuf> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    let r = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut len)
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    if r.is_err() || len == 0 {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..len as usize]);
    Some(PathBuf::from(s))
}

fn query_thread_token_user() -> Option<String> {
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
    sid_to_string(tu.User.Sid)
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
