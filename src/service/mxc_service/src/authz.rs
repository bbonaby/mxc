// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Caller code-integrity gate.
//!
//! In **release** builds, every privileged RPC (AddPolicy/RemovePolicy)
//! is gated on the calling EXE being Authenticode-signed AND its cert
//! chain rooting in a Microsoft trust anchor (`CERT_CHAIN_POLICY_MICROSOFT_ROOT`).
//!
//! In **debug** builds the same check runs but a failure becomes a
//! `warn!` line and the call proceeds — lets us iterate on unsigned
//! build artifacts without disabling the code path entirely.
//!
//! Two-step check, both required in release:
//!   1. `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` — signature
//!      is valid AND its primary chain validates to a system-trusted
//!      root cert. Honors revocation.
//!   2. `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT)`
//!      — that root is one of the Microsoft roots (PCA, Code Sign Root,
//!      Code Sign 2010/2011, etc.).

use std::path::Path;
use std::ptr;

use windows::core::{BOOL, PCSTR};
use windows::Win32::Foundation::{GetLastError, HANDLE, HWND, TRUE};
use windows::Win32::Security::Cryptography::{
    CertVerifyCertificateChainPolicy, CERT_CHAIN_CONTEXT, CERT_CHAIN_POLICY_FLAGS,
    CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    CRYPT_PROVIDER_DATA, CRYPT_PROVIDER_SGNR, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_UICHOICE,
    WINTRUST_DATA_UICONTEXT, WINTRUST_DATA_UNION_CHOICE, WINTRUST_FILE_INFO,
};

// CERT_CHAIN_POLICY_MICROSOFT_ROOT (== 7). The policy OID API takes a
// PCSTR but accepts MAKEINTRESOURCE-style integer "OIDs" for built-in
// policies — see the szOID_* family in wincrypt.h.
const CERT_CHAIN_POLICY_MS_ROOT: PCSTR = PCSTR(7 as *const u8);

// fdwRevocationChecks: WTD_REVOCATION_CHECK_CHAIN == 2.
const REVOCATION_CHECK_CHAIN: WINTRUST_DATA_REVOCATION_CHECKS = WINTRUST_DATA_REVOCATION_CHECKS(2);
// dwUIChoice: WTD_UI_NONE == 2.
const UI_NONE: WINTRUST_DATA_UICHOICE = WINTRUST_DATA_UICHOICE(2);
// dwUnionChoice: WTD_CHOICE_FILE == 1.
const CHOICE_FILE: WINTRUST_DATA_UNION_CHOICE = WINTRUST_DATA_UNION_CHOICE(1);
// dwStateAction: WTD_STATEACTION_VERIFY == 1, WTD_STATEACTION_CLOSE == 2.
const STATEACTION_VERIFY: u32 = 1;
const STATEACTION_CLOSE: u32 = 2;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AuthzVerdict {
    /// EXE signed AND chain rooted in a Microsoft root cert.
    Trusted,
    /// Signature valid but does not chain to a Microsoft root.
    NotMicrosoftSigned,
    /// EXE is not Authenticode-signed, or signature is invalid/revoked.
    NotSigned(u32),
    /// Couldn't determine (failed to open the binary, etc.).
    Indeterminate(String),
}

impl AuthzVerdict {
    #[allow(dead_code)]
    pub fn is_trusted(&self) -> bool {
        matches!(self, AuthzVerdict::Trusted)
    }
}

/// Run WinVerifyTrust + Microsoft-root check on `image_path`. Pure
/// inspection: no decision is made here; callers compose this with
/// build-mode policy via [`enforce`].
pub fn verify_image(image_path: &Path) -> AuthzVerdict {
    let wide: Vec<u16> = image_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR(wide.as_ptr()),
        hFile: HANDLE(ptr::null_mut()),
        pgKnownSubject: ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA::default();
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = UI_NONE;
    data.fdwRevocationChecks = REVOCATION_CHECK_CHAIN;
    data.dwUnionChoice = CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 {
        pFile: &mut file_info as *mut _,
    };
    data.dwStateAction = windows::Win32::Security::WinTrust::WINTRUST_DATA_STATE_ACTION(STATEACTION_VERIFY);
    data.dwUIContext = WINTRUST_DATA_UICONTEXT(0);

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hr = unsafe {
        WinVerifyTrust(
            HWND(ptr::null_mut()),
            &mut action as *mut _,
            &mut data as *mut _ as *mut _,
        )
    };

    let verdict = if hr != 0 {
        AuthzVerdict::NotSigned(hr as u32)
    } else {
        check_microsoft_root(&data)
    };

    data.dwStateAction = windows::Win32::Security::WinTrust::WINTRUST_DATA_STATE_ACTION(STATEACTION_CLOSE);
    unsafe {
        WinVerifyTrust(
            HWND(ptr::null_mut()),
            &mut action as *mut _,
            &mut data as *mut _ as *mut _,
        )
    };

    verdict
}

fn check_microsoft_root(data: &WINTRUST_DATA) -> AuthzVerdict {
    let prov: *mut CRYPT_PROVIDER_DATA =
        unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
    if prov.is_null() {
        return AuthzVerdict::Indeterminate("WTHelperProvDataFromStateData returned null".into());
    }
    let signer: *mut CRYPT_PROVIDER_SGNR =
        unsafe { WTHelperGetProvSignerFromChain(prov, 0, false, 0) };
    if signer.is_null() {
        return AuthzVerdict::Indeterminate("WTHelperGetProvSignerFromChain returned null".into());
    }
    let chain_ctx: *mut CERT_CHAIN_CONTEXT = unsafe { (*signer).pChainContext };
    if chain_ctx.is_null() {
        return AuthzVerdict::Indeterminate("signer has null pChainContext".into());
    }

    let mut policy_para = CERT_CHAIN_POLICY_PARA::default();
    policy_para.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32;
    policy_para.dwFlags = CERT_CHAIN_POLICY_FLAGS(0);
    let mut policy_status = CERT_CHAIN_POLICY_STATUS::default();
    policy_status.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32;

    let ok: BOOL = unsafe {
        CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_MS_ROOT,
            chain_ctx,
            &policy_para,
            &mut policy_status,
        )
    };
    if ok != TRUE {
        let gle = unsafe { GetLastError().0 };
        return AuthzVerdict::Indeterminate(format!(
            "CertVerifyCertificateChainPolicy call failed: gle=0x{gle:08x}"
        ));
    }
    if policy_status.dwError == 0 {
        AuthzVerdict::Trusted
    } else {
        AuthzVerdict::NotMicrosoftSigned
    }
}

/// Apply build-mode policy to a verification result.
///
/// - Release: `Trusted` → Ok; anything else → Err.
/// - Debug: emits a warn-style diag line on non-`Trusted`; returns Ok
///   so unsigned dev builds still function.
pub fn enforce(image_path: Option<&Path>) -> Result<(), String> {
    let image_path = match image_path {
        Some(p) => p,
        None => {
            let msg = "authz: caller image path unavailable";
            #[cfg(debug_assertions)]
            {
                crate::diag::emit(format!("{msg} (debug build: allowing)"));
                return Ok(());
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(msg.to_string());
            }
        }
    };

    let verdict = verify_image(image_path);
    match &verdict {
        AuthzVerdict::Trusted => {
            crate::diag::emit(format!("authz: {} -> Trusted (MS root)", image_path.display()));
            Ok(())
        }
        other => {
            let msg = format!("authz: {} -> {:?}", image_path.display(), other);
            #[cfg(debug_assertions)]
            {
                crate::diag::emit(format!("{msg} (debug build: allowing)"));
                Ok(())
            }
            #[cfg(not(debug_assertions))]
            {
                crate::diag::emit(msg.clone());
                Err(msg)
            }
        }
    }
}

// Make OsStr::encode_wide available on Windows.
use std::os::windows::ffi::OsStrExt;
