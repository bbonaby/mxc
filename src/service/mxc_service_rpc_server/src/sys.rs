// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_void;

pub const ENDPOINT: &str = "mxc-service";

unsafe extern "C" {
    pub static IMxcService_v1_0_s_ifspec: *const c_void;
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
