// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RAII handle on a BFE engine session.

use mxc_service_proto::ServiceError;
use mxc_wfp_sys::{
    engine_close, engine_open, engine_open_local, ERROR_SUCCESS, FWPM_DISPLAY_DATA0,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, Handle, PWStr,
};
use windows::core::w;

/// `true` = dynamic (auto-reaped at process exit) — used by the
/// service runtime. `false` = persistent — used by install/uninstall
/// grant.
pub enum SessionKind {
    Dynamic,
    Persistent,
}

pub struct Engine(Handle);

// SAFETY: BFE engine handles are documented thread-safe for
// add/delete operations; the handle is opaque to the borrow checker.
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    pub fn open(kind: SessionKind) -> Result<Self, ServiceError> {
        let h = match kind {
            SessionKind::Persistent => {
                // SAFETY: passes no session struct, no display data; sys
                // wrapper handles the FFI call.
                unsafe { engine_open_local() }.map_err(|rc| win32_err("FwpmEngineOpen0", rc))?
            }
            SessionKind::Dynamic => {
                let session = FWPM_SESSION0 {
                    sessionKey: mxc_wfp_sys::Guid::zeroed(),
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: PWStr(w!("mxc-service").as_ptr() as *mut _),
                        description: PWStr(
                            w!("MXC Tier 2 policy session").as_ptr() as *mut _,
                        ),
                    },
                    flags: FWPM_SESSION_FLAG_DYNAMIC,
                    txnWaitTimeoutInMSec: 0,
                    processId: 0,
                    sid: std::ptr::null_mut(),
                    username: PWStr::null(),
                    kernelMode: false.into(),
                };
                let mut h = Handle::default();
                // SAFETY: `session`'s embedded display names come from
                // `w!()` static literals that outlive the call;
                // `&mut h` is a live stack slot.
                let rc = unsafe { engine_open(10, Some(&session), &mut h) };
                if rc != ERROR_SUCCESS.0 {
                    return Err(win32_err("FwpmEngineOpen0", rc));
                }
                h
            }
        };
        Ok(Self(h))
    }

    pub fn handle(&self) -> Handle {
        self.0
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle is live by RAII invariant.
            unsafe { engine_close(self.0) }
        }
    }
}

pub(crate) fn win32_err(api: &str, rc: u32) -> ServiceError {
    ServiceError::WfpFailure {
        api: api.into(),
        hresult: rc,
        message: format!("Win32 error {rc} (0x{rc:08X})"),
    }
}
