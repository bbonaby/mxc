// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_void;

pub const ENDPOINT: &str = "mxc-service";

unsafe extern "C" {
    pub static IMxcService_v1_0_c_ifspec: *const c_void;
}

// Client proxy provided by MIDL-generated client stub.
unsafe extern "C" {
    pub fn RpcCall(
        binding: *mut c_void,
        request_len: u32,
        request_cbor: *const u8,
        response_len: *mut u32,
        response_cbor: *mut *mut u8,
    );
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn MIDL_user_allocate(size: usize) -> *mut c_void {
    unsafe { malloc(size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn MIDL_user_free(p: *mut c_void) {
    if !p.is_null() {
        unsafe { free(p) }
    }
}

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

pub unsafe fn midl_free(p: *mut c_void) {
    unsafe { MIDL_user_free(p) }
}
