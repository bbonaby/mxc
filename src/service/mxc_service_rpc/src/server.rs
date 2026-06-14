// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Server side: register the `IMxcService` interface on the local
//! `mxc-service` ALPC endpoint and dispatch each call through a
//! user-supplied handler closure.

use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use mxc_service_proto::{Request, Response};
use windows::core::PWSTR;
use windows::Win32::System::Rpc::{
    RpcServerListen, RpcServerRegisterAuthInfoW, RpcServerRegisterIf3, RpcServerUseProtseqEpW,
    RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, RPC_IF_AUTOLISTEN, RPC_STATUS,
};

use crate::sys::{self, MIDL_user_allocate};

const RPC_S_OK: RPC_STATUS = RPC_STATUS(0);
const RPC_S_ALREADY_LISTENING: RPC_STATUS = RPC_STATUS(1753);

type Dispatcher = Box<dyn Fn(Request) -> Response + Send + Sync + 'static>;

static DISPATCHER: OnceLock<Mutex<Option<Dispatcher>>> = OnceLock::new();

fn dispatcher_slot() -> &'static Mutex<Option<Dispatcher>> {
    DISPATCHER.get_or_init(|| Mutex::new(None))
}

/// Register the interface and start the RPC server. Idempotent: a
/// second call replaces the dispatcher but does not re-listen.
pub fn start<F>(handler: F) -> Result<()>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    {
        let mut slot = dispatcher_slot().lock().unwrap();
        *slot = Some(Box::new(handler));
    }

    static ONCE: OnceLock<()> = OnceLock::new();
    if ONCE.get().is_some() {
        return Ok(());
    }

    let protseq = to_wide("ncalrpc");
    let endpoint = to_wide(sys::ENDPOINT);

    let status = unsafe {
        RpcServerUseProtseqEpW(
            PWSTR(protseq.as_ptr() as *mut _),
            RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
            PWSTR(endpoint.as_ptr() as *mut _),
            None,
        )
    };
    if status != RPC_S_OK {
        return Err(anyhow!("RpcServerUseProtseqEpW failed: {:?}", status));
    }

    let status = unsafe {
        RpcServerRegisterIf3(
            sys::IMxcService_v1_0_s_ifspec,
            None,
            None,
            RPC_IF_AUTOLISTEN,
            RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
            0,
            None,
            None,
        )
    };
    if status != RPC_S_OK {
        return Err(anyhow!("RpcServerRegisterIf3 failed: {:?}", status));
    }

    let status = unsafe {
        RpcServerRegisterAuthInfoW(None, RPC_C_AUTHN_GSS_NEGOTIATE, None, None)
    };
    if status != RPC_S_OK {
        return Err(anyhow!("RpcServerRegisterAuthInfoW failed: {:?}", status));
    }

    let status = unsafe { RpcServerListen(1, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, 1) };
    if status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING {
        return Err(anyhow!("RpcServerListen failed: {:?}", status));
    }

    ONCE.set(()).ok();
    Ok(())
}

/// MIDL-generated server stub dispatches inbound calls here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RpcCall(
    _binding: *mut c_void,
    request_len: u32,
    request_cbor: *const u8,
    response_len: *mut u32,
    response_cbor: *mut *mut u8,
) {
    unsafe {
        *response_len = 0;
        *response_cbor = std::ptr::null_mut();
    }

    let slice = unsafe { std::slice::from_raw_parts(request_cbor, request_len as usize) };
    let request: Request = match ciborium::de::from_reader(slice) {
        Ok(r) => r,
        Err(_) => return,
    };

    let response = {
        let guard = dispatcher_slot().lock().unwrap();
        match guard.as_ref() {
            Some(d) => d(request),
            None => return,
        }
    };

    let mut bytes: Vec<u8> = Vec::new();
    if ciborium::ser::into_writer(&response, &mut bytes).is_err() {
        return;
    }

    let out_buf = unsafe { MIDL_user_allocate(bytes.len()) as *mut u8 };
    if out_buf.is_null() {
        return;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        *response_len = bytes.len() as u32;
        *response_cbor = out_buf;
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
