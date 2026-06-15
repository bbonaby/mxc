// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Client side: bind to the local `mxc-service` LRPC endpoint and
//! invoke `RpcCall`.

use std::ffi::c_void;

use anyhow::{anyhow, Context};
use mxc_service_proto::{Request, Response};
use windows::core::PWSTR;
use windows::Win32::System::Com::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY;
use windows::Win32::System::Rpc::{
    RpcBindingFree, RpcBindingFromStringBindingW, RpcBindingSetAuthInfoW,
    RpcStringBindingComposeW, RpcStringFreeW, RPC_C_AUTHN_WINNT, RPC_STATUS,
};

use crate::sys::{self, midl_free};

const RPC_S_OK: RPC_STATUS = RPC_STATUS(0);

pub struct Client {
    binding: *mut c_void,
}

unsafe impl Send for Client {}

impl Client {
    pub fn connect() -> anyhow::Result<Self> {
        let mut binding_str: PWSTR = PWSTR(std::ptr::null_mut());
        let protseq = to_wide("ncalrpc");
        let endpoint = to_wide(sys::ENDPOINT);
        let status = unsafe {
            RpcStringBindingComposeW(
                None,
                PWSTR(protseq.as_ptr() as *mut _),
                None,
                PWSTR(endpoint.as_ptr() as *mut _),
                None,
                Some(&mut binding_str),
            )
        };
        if status != RPC_S_OK {
            return Err(anyhow!("RpcStringBindingComposeW failed: {:?}", status));
        }

        let mut binding: *mut c_void = std::ptr::null_mut();
        let status = unsafe { RpcBindingFromStringBindingW(binding_str, &mut binding) };
        unsafe {
            let _ = RpcStringFreeW(&mut binding_str);
        }
        if status != RPC_S_OK {
            return Err(anyhow!("RpcBindingFromStringBindingW failed: {:?}", status));
        }

        let status = unsafe {
            RpcBindingSetAuthInfoW(
                binding,
                None,
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY.0 as u32,
                RPC_C_AUTHN_WINNT,
                None,
                0,
            )
        };
        if status != RPC_S_OK {
            unsafe {
                let _ = RpcBindingFree(&mut binding);
            }
            return Err(anyhow!("RpcBindingSetAuthInfoW failed: {:?}", status));
        }

        Ok(Self { binding })
    }

    pub fn call(&self, req: &Request) -> anyhow::Result<Response> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(req, &mut bytes)
            .map_err(|e| anyhow!("cbor encode: {e}"))?;

        let mut resp_len: u32 = 0;
        let mut resp_ptr: *mut u8 = std::ptr::null_mut();
        unsafe {
            sys::RpcCall(
                self.binding,
                bytes.len() as u32,
                bytes.as_ptr(),
                &mut resp_len,
                &mut resp_ptr,
            );
        }
        if resp_ptr.is_null() || resp_len == 0 {
            return Err(anyhow!("RpcCall returned empty response"));
        }
        let owned = unsafe {
            std::slice::from_raw_parts(resp_ptr, resp_len as usize).to_vec()
        };
        unsafe { midl_free(resp_ptr as *mut c_void) };

        ciborium::de::from_reader(owned.as_slice())
            .context("decode response cbor")
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            let _ = RpcBindingFree(&mut self.binding);
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
