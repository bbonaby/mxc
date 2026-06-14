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
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineGetSecurityInfo0, FwpmEngineOpen0,
    FwpmEngineSetSecurityInfo0, FWPM_ACTRL_ADD, FWPM_ACTRL_ADD_LINK, FWPM_ACTRL_ENUM,
    FWPM_ACTRL_OPEN, FWPM_ACTRL_READ,
};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE,
    REVOKE_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::DELETE as FILE_DELETE;
use windows::core::PWSTR;

const SERVICE_NAME_FOR_SID: &str = "mxc-service";

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
    let sid = SidBuf::for_service(SERVICE_NAME_FOR_SID);
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
    // RPC_C_AUTHN_WINNT = 10. Required by FwpmEngineOpen0; 0 (RPC_C_AUTHN_NONE)
    // yields ERROR_NOT_SUPPORTED (0x32) against the BFE local RPC endpoint.
    let rc = unsafe { FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &mut engine) };
    if rc != 0 {
        bail!("FwpmEngineOpen0 failed: Win32 0x{rc:08x}");
    }
    Ok(engine)
}

/// Heap-resident SID buffer suitable for `EXPLICIT_ACCESS_W.Trustee`.
struct SidBuf(Vec<u8>);

impl SidBuf {
    /// Build the per-service SID for `service_name` deterministically.
    ///
    /// Format: `S-1-5-80-{h0}-{h1}-{h2}-{h3}-{h4}` where the five 32-bit
    /// chunks are little-endian reads from SHA-1(uppercase service name
    /// encoded as UTF-16LE). This matches the algorithm Windows uses
    /// to generate per-service SIDs (see MSDN "Service Security and
    /// Access Rights" + `SERVICE_SID_TYPE_RESTRICTED` docs).
    ///
    /// Computing instead of `LookupAccountNameW` because the LSA
    /// account name `NT SERVICE\<name>` is not always resolvable
    /// immediately after `CreateService` (the MSI custom action sees
    /// `ERROR_NONE_MAPPED` before LSA has cached the freshly-created
    /// SID).
    fn for_service(service_name: &str) -> Self {
        use sha1::{Digest, Sha1};
        let upper = service_name.to_uppercase();
        let utf16_le: Vec<u8> = upper
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let hash = Sha1::digest(&utf16_le); // 20 bytes

        // SID byte layout:
        //   [Revision=1][SubAuthCount=6][IdentifierAuthority(6 BE bytes)]
        //   [SubAuthority(0..6) each 4 LE bytes]
        // SubAuthorities = [SECURITY_SERVICE_ID_BASE_RID=80, h0..h4]
        let mut buf = Vec::with_capacity(8 + 6 * 4);
        buf.push(1); // Revision
        buf.push(6); // SubAuthorityCount: 1 base RID + 5 hash chunks
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // SECURITY_NT_AUTHORITY in BE
        buf.extend_from_slice(&80u32.to_le_bytes()); // base RID
        for i in 0..5 {
            let chunk = u32::from_le_bytes([
                hash[i * 4],
                hash[i * 4 + 1],
                hash[i * 4 + 2],
                hash[i * 4 + 3],
            ]);
            buf.extend_from_slice(&chunk.to_le_bytes());
        }
        SidBuf(buf)
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
    let _ = NO_MULTIPLE_TRUSTEE;
    let _ = TRUSTEE_IS_SID;
    let _ = TRUSTEE_IS_UNKNOWN;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_sid_layout_is_plausible() {
        let sid = SidBuf::for_service("mxc-service");
        // Revision=1, SubAuthCount=6, IdAuth bytes 0,0,0,0,0,5,
        // SubAuthorities = 4 bytes * 6 = 24
        assert_eq!(sid.0.len(), 8 + 24);
        assert_eq!(sid.0[0], 1); // revision
        assert_eq!(sid.0[1], 6); // sub-auth count
        assert_eq!(&sid.0[2..8], &[0, 0, 0, 0, 0, 5]); // SECURITY_NT_AUTHORITY
        // First sub-authority is 80 (SECURITY_SERVICE_ID_BASE_RID)
        let base = u32::from_le_bytes([sid.0[8], sid.0[9], sid.0[10], sid.0[11]]);
        assert_eq!(base, 80);
    }

    #[test]
    fn service_sid_is_case_insensitive() {
        let a = SidBuf::for_service("mxc-service");
        let b = SidBuf::for_service("MXC-Service");
        let c = SidBuf::for_service("MXC-SERVICE");
        assert_eq!(a.0, b.0);
        assert_eq!(a.0, c.0);
    }
}
