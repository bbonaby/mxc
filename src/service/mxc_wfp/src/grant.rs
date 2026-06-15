// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Engine-SD ACE install/uninstall for the per-service SID.
//!
//! See `installer/mxc-service-msi/Package.wxs`: the MSI custom action
//! invokes `mxc-service.exe --install-grant` while running as
//! `LocalSystem`, which gives it the `WRITE_DAC` required on the BFE
//! engine SD. The ACE we add is **non-inheritable** and grants only
//! `FWPM_ACTRL_OPEN | FWPM_ACTRL_ADD` — the minimum the runtime
//! service needs to open the engine and register its own provider +
//! sublayer. Further access on objects we create is granted by the
//! implicit creator/owner ACE that WFP installs at create time.

use std::ffi::c_void;
use std::ptr;

use mxc_service_proto::ServiceError;
use mxc_wfp_sys::{
    engine_get_security_info, engine_set_dacl, set_entries_in_acl, Acl,
    DACL_SECURITY_INFORMATION_VALUE, EXPLICIT_ACCESS_W, FWPM_ACTRL_ADD, FWPM_ACTRL_OPEN,
    GRANT_ACCESS, LocalAllocOwned, NO_INHERITANCE, NO_MULTIPLE_TRUSTEE, PSecurityDescriptor,
    PSid, PWStr, REVOKE_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::Authorization::ACCESS_MODE;

use crate::engine::{win32_err, Engine, SessionKind};

const SERVICE_NAME_FOR_SID: &str = "mxc-service";
const RIGHTS: u32 = FWPM_ACTRL_OPEN | FWPM_ACTRL_ADD;

/// Add a non-inheritable `OPEN | ADD` ACE for the per-service SID.
pub fn install_grant() -> Result<(), ServiceError> {
    modify_engine_ace(GRANT_ACCESS)
}

/// Best-effort revoke: log and swallow errors so MSI uninstall stays
/// unblocked.
pub fn uninstall_grant() -> Result<(), ServiceError> {
    if let Err(e) = modify_engine_ace(REVOKE_ACCESS) {
        eprintln!("[mxc_wfp::grant] uninstall warning: {e:?}");
    }
    Ok(())
}

fn modify_engine_ace(mode: ACCESS_MODE) -> Result<(), ServiceError> {
    let engine = Engine::open(SessionKind::Persistent)?;
    let sid = ServiceSid::derive(SERVICE_NAME_FOR_SID);

    let mut current_dacl: *mut Acl = ptr::null_mut();
    let mut current_sd = PSecurityDescriptor(ptr::null_mut());
    // SAFETY: `engine` is live; the two out-pointers are valid stack
    // slots; on success WFP allocates the SD which we own via
    // `_sd_owner` below.
    let rc = unsafe {
        engine_get_security_info(
            engine.handle(),
            DACL_SECURITY_INFORMATION_VALUE,
            &mut current_dacl,
            &mut current_sd,
        )
    };
    if rc != 0 {
        return Err(win32_err("FwpmEngineGetSecurityInfo0", rc));
    }
    // `current_dacl` is owned by the same `LocalAlloc` chunk as
    // `current_sd`.
    let _sd_owner = LocalAllocOwned(current_sd.0);

    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: RIGHTS,
        grfAccessMode: mode,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: PWStr(sid.as_psid().0 as *mut u16),
        },
    };

    let mut new_dacl: *mut Acl = ptr::null_mut();
    // SAFETY: `explicit` borrows `sid`'s buffer which lives across
    // this call; `current_dacl` is the live engine DACL we just
    // fetched; `&mut new_dacl` is a stack slot.
    let rc = unsafe {
        set_entries_in_acl(
            std::slice::from_ref(&explicit),
            current_dacl as *const Acl,
            &mut new_dacl,
        )
    };
    if rc != 0 {
        return Err(win32_err("SetEntriesInAclW", rc));
    }
    let _new_dacl_owner = LocalAllocOwned(new_dacl as *mut c_void);

    // SAFETY: `engine` live; `new_dacl` owned by `_new_dacl_owner`
    // for the duration of this call.
    let rc = unsafe { engine_set_dacl(engine.handle(), new_dacl as *const Acl) };
    if rc != 0 {
        return Err(win32_err("FwpmEngineSetSecurityInfo0", rc));
    }
    Ok(())
}

/// Heap-resident per-service SID buffer.
///
/// Built by hashing the uppercase service name (UTF-16LE) with SHA-1
/// and packing the digest into a `S-1-5-80-{h0..h4}` SID. This matches
/// the Windows SCM algorithm and avoids `LookupAccountNameW`, which
/// races with the LSA cache right after `CreateService`.
pub(crate) struct ServiceSid(Vec<u8>);

impl ServiceSid {
    pub(crate) fn derive(service_name: &str) -> Self {
        use sha1::{Digest, Sha1};
        let upper = service_name.to_uppercase();
        let utf16_le: Vec<u8> = upper
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let hash = Sha1::digest(&utf16_le);

        let mut buf = Vec::with_capacity(8 + 6 * 4);
        buf.push(1); // revision
        buf.push(6); // sub-authority count
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT authority (BE)
        buf.extend_from_slice(&80u32.to_le_bytes()); // service base RID
        for i in 0..5 {
            let chunk = u32::from_le_bytes([
                hash[i * 4],
                hash[i * 4 + 1],
                hash[i * 4 + 2],
                hash[i * 4 + 3],
            ]);
            buf.extend_from_slice(&chunk.to_le_bytes());
        }
        Self(buf)
    }

    pub(crate) fn as_psid(&self) -> PSid {
        PSid(self.0.as_ptr() as *mut c_void)
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_sid_layout_is_plausible() {
        let sid = ServiceSid::derive("mxc-service");
        let b = sid.bytes();
        assert_eq!(b.len(), 8 + 24);
        assert_eq!(b[0], 1);
        assert_eq!(b[1], 6);
        assert_eq!(&b[2..8], &[0, 0, 0, 0, 0, 5]);
        let base = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        assert_eq!(base, 80);
    }

    #[test]
    fn service_sid_is_case_insensitive() {
        let a = ServiceSid::derive("mxc-service");
        let b = ServiceSid::derive("MXC-Service");
        let c = ServiceSid::derive("MXC-SERVICE");
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.bytes(), c.bytes());
    }
}
