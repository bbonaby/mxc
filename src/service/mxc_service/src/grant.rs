// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Engine SD grant for the `NT SERVICE\mxc-service` per-service SID.
//!
//! Spec §4.1: the MSI install custom action invokes this binary with
//! `--install-grant` while running as `LocalSystem`. That gives it the
//! `WRITE_DAC` it needs on the BFE engine SD. We write an inheritable
//! ACE granting the per-service SID:
//!
//! ```text
//! FWPM_ACTRL_OPEN | FWPM_ACTRL_ADD | FWPM_ACTRL_ADD_LINK
//! | DELETE | FWPM_ACTRL_ENUM | FWPM_ACTRL_READ
//! ```
//!
//! with `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE` so the grant
//! propagates to filters/sublayers/providers we create later. After
//! this completes the service can run as write-restricted
//! `LocalService` with `SERVICE_SID_TYPE_RESTRICTED` and still open
//! the engine + add filters in our provider/sublayer.
//!
//! Made outside any explicit `FwpmTransaction*` — that is the
//! documented MSDN constraint on `FwpmEngineSetSecurityInfo0`.

use std::ffi::c_void;
use std::ptr;

use anyhow::{bail, Context};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineGetSecurityInfo0, FwpmEngineOpen0,
    FwpmEngineSetSecurityInfo0, FWPM_ACTRL_ADD, FWPM_ACTRL_ADD_LINK, FWPM_ACTRL_ENUM,
    FWPM_ACTRL_OPEN, FWPM_ACTRL_READ,
};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, MULTIPLE_TRUSTEE_OPERATION,
    NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, TRUSTEE_FORM, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_TYPE, TRUSTEE_W,
};
use windows::Win32::Security::{
    LookupAccountNameW, ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    NO_INHERITANCE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SID, SID_NAME_USE,
};
use windows::Win32::Storage::FileSystem::DELETE as FILE_DELETE;

const SERVICE_ACCOUNT: &str = "NT SERVICE\\mxc-service";

const RIGHTS: u32 =
    FWPM_ACTRL_OPEN | FWPM_ACTRL_ADD | FWPM_ACTRL_ADD_LINK | FWPM_ACTRL_ENUM | FWPM_ACTRL_READ;

pub fn install_grant() -> anyhow::Result<()> {
    modify_engine_ace(GRANT_ACCESS).context("install grant")
}

pub fn uninstall_grant() -> anyhow::Result<()> {
    // Best-effort: don't block uninstall if the SID is gone.
    if let Err(e) = modify_engine_ace(REVOKE_ACCESS) {
        eprintln!("[grant] uninstall grant warning: {e:#}");
    }
    Ok(())
}

fn modify_engine_ace(mode: ACCESS_MODE) -> anyhow::Result<()> {
    let sid = SidBuf::lookup(SERVICE_ACCOUNT)?;
    let engine = open_engine()?;

    let result: anyhow::Result<()> = (|| {
        let mut current_dacl: *mut ACL = ptr::null_mut();
        let mut current_sd = PSECURITY_DESCRIPTOR(ptr::null_mut());
        let rc = unsafe {
            FwpmEngineGetSecurityInfo0(
                engine,
                DACL_SECURITY_INFORMATION.0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut current_dacl,
                ptr::null_mut(),
                &mut current_sd,
            )
        };
        if rc != 0 {
            bail!("FwpmEngineGetSecurityInfo0 failed: Win32 0x{rc:08x}");
        }
        // current_dacl is owned by current_sd allocation.
        let _sd_owner = LocalAllocOwned(current_sd.0);

        let inheritance = match mode {
            GRANT_ACCESS => ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0),
            _ => NO_INHERITANCE,
        };

        let explicit = EXPLICIT_ACCESS_W {
            grfAccessPermissions: RIGHTS | FILE_DELETE.0,
            grfAccessMode: mode,
            grfInheritance: inheritance,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: PWSTR(sid.as_psid().0 as *mut u16),
            },
        };

        let mut new_dacl: *mut ACL = ptr::null_mut();
        let rc = unsafe {
            SetEntriesInAclW(
                Some(std::slice::from_ref(&explicit)),
                Some(current_dacl as *const ACL),
                &mut new_dacl,
            )
        };
        if rc.0 != 0 {
            bail!("SetEntriesInAclW failed: Win32 {}", rc.0);
        }
        let _new_dacl_owner = LocalAllocOwned(new_dacl as *mut c_void);

        let rc = unsafe {
            FwpmEngineSetSecurityInfo0(
                engine,
                DACL_SECURITY_INFORMATION.0,
                None,
                None,
                Some(new_dacl as *const ACL),
                None,
            )
        };
        if rc != 0 {
            bail!("FwpmEngineSetSecurityInfo0 failed: Win32 0x{rc:08x}");
        }

        Ok(())
    })();

    let _ = unsafe { FwpmEngineClose0(engine) };
    result
}

fn open_engine() -> anyhow::Result<HANDLE> {
    let mut engine = HANDLE::default();
    let rc = unsafe { FwpmEngineOpen0(PCWSTR::null(), 0, None, None, &mut engine) };
    if rc != 0 {
        bail!("FwpmEngineOpen0 failed: Win32 0x{rc:08x}");
    }
    Ok(engine)
}

/// Heap-resident SID buffer suitable for `EXPLICIT_ACCESS_W.Trustee`.
struct SidBuf(Vec<u8>);

impl SidBuf {
    fn lookup(account: &str) -> anyhow::Result<Self> {
        let name = HSTRING::from(account);
        let mut sid_size: u32 = 0;
        let mut dom_size: u32 = 0;
        let mut sid_use = SID_NAME_USE::default();
        let res = unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                None,
                &mut sid_size,
                None,
                &mut dom_size,
                &mut sid_use,
            )
        };
        if res.is_ok() {
            bail!("LookupAccountNameW unexpectedly succeeded on sizing call");
        }
        let last = unsafe { GetLastError() };
        if last != ERROR_INSUFFICIENT_BUFFER {
            bail!("LookupAccountNameW sizing for {account}: {last:?}");
        }
        let mut sid_buf = vec![0u8; sid_size as usize];
        let mut dom_buf = vec![0u16; dom_size as usize];
        unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                Some(PSID(sid_buf.as_mut_ptr() as *mut c_void)),
                &mut sid_size,
                Some(PWSTR(dom_buf.as_mut_ptr())),
                &mut dom_size,
                &mut sid_use,
            )
            .with_context(|| format!("LookupAccountNameW failed for {account}"))?;
        }
        Ok(SidBuf(sid_buf))
    }

    fn as_psid(&self) -> PSID {
        PSID(self.0.as_ptr() as *mut c_void)
    }
}

struct LocalAllocOwned(*mut c_void);
impl Drop for LocalAllocOwned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

// Quiet unused-import warnings when modules elsewhere don't reach grant code.
#[allow(dead_code)]
fn _imports() {
    let _ = SID_NAME_USE::default();
    let _ = TRUSTEE_FORM::default();
    let _ = TRUSTEE_TYPE::default();
    let _: *mut SID = ptr::null_mut();
    let _: MULTIPLE_TRUSTEE_OPERATION = NO_MULTIPLE_TRUSTEE;
}
