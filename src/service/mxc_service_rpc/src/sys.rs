// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// FFI to the MIDL-generated stubs and to the parts of the RPC runtime
// we hand-declare (specifically, the IF spec exported by whichever
// stub the active feature pulls in).

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_void;

pub const ENDPOINT: &str = "mxc-service";

#[cfg(feature = "client")]
unsafe extern "C" {
    pub static IMxcService_v1_0_c_ifspec: *const c_void;
}

#[cfg(feature = "server")]
unsafe extern "C" {
    pub static IMxcService_v1_0_s_ifspec: *const c_void;
}

// Client proxy. Symbol provided by the MIDL-generated client stub.
#[cfg(feature = "client")]
unsafe extern "C" {
    pub fn RpcCall(
        binding: *mut c_void,
        request_len: u32,
        request_cbor: *const u8,
        response_len: *mut u32,
        response_cbor: *mut *mut u8,
    );
}

// MIDL allocator hooks — required exactly once per linkage closure.
// Compiled only when either stub is in this build.
#[cfg(any(feature = "client", feature = "server"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn MIDL_user_allocate(size: usize) -> *mut c_void {
    unsafe { malloc(size) }
}

#[cfg(any(feature = "client", feature = "server"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn MIDL_user_free(p: *mut c_void) {
    if !p.is_null() {
        unsafe { free(p) }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

// Re-export for crate-internal use of the free function.
#[cfg(any(feature = "client", feature = "server"))]
pub unsafe fn midl_free(p: *mut c_void) {
    unsafe { MIDL_user_free(p) }
}
