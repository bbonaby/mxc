// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This crate is temporary — transmute annotations are verbose for FFI casts
// where the target types are already defined as type aliases.
#![allow(clippy::missing_transmute_annotations)]

//! Safe wrappers around the WinHTTP per-AppContainer proxy policy APIs.
//!
//! These APIs (`WinHttpConnectionSetPolicyEntries`,
//! `WinHttpConnectionSetProxyInfo`, `WinHttpConnectionUpdateIfIndexTable`)
//! are not in the public SDK or windows-rs. They are loaded at runtime from
//! winhttp.dll via `GetProcAddress`.

use std::net::{IpAddr, ToSocketAddrs};
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{GetLengthSid, PSID};
use windows::Win32::System::Com::CoCreateGuid;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_core::PWSTR;

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::string_util;

use crate::bindings::*;

/// Loopback interface index used by `WinHttpConnectionUpdateIfIndexTable`.
///
/// We currently only support loopback proxies, so the route is always the
/// loopback adapter (ifIndex 1). Matches the reference implementation in
/// `SandboxNetworking.cpp::ApplyProxyConfiguration`.
const LOOPBACK_IF_INDEX: u32 = 1;

// Standard WinHTTP API function pointer types (public SDK, but loaded dynamically)
const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;

type FnWinHttpOpen = unsafe extern "system" fn(
    user_agent: *const u16,
    access_type: u32,
    proxy_name: *const u16,
    proxy_bypass: *const u16,
    flags: u32,
) -> *mut core::ffi::c_void;

type FnWinHttpCloseHandle = unsafe extern "system" fn(handle: *mut core::ffi::c_void) -> i32;

/// Holds a WinHTTP session handle and ensures it is closed on drop.
struct WinHttpSession {
    handle: *mut core::ffi::c_void,
    close_fn: FnWinHttpCloseHandle,
}

impl WinHttpSession {
    fn open(module: windows::Win32::Foundation::HMODULE) -> Result<Self, WxcError> {
        let open_fn: FnWinHttpOpen = unsafe {
            let proc =
                GetProcAddress(module, windows::core::s!("WinHttpOpen")).ok_or_else(|| {
                    WxcError::NetworkProxy("WinHttpOpen not found in winhttp.dll".to_string())
                })?;
            std::mem::transmute(proc)
        };

        let close_fn: FnWinHttpCloseHandle = unsafe {
            let proc = GetProcAddress(module, windows::core::s!("WinHttpCloseHandle")).ok_or_else(
                || {
                    WxcError::NetworkProxy(
                        "WinHttpCloseHandle not found in winhttp.dll".to_string(),
                    )
                },
            )?;
            std::mem::transmute(proc)
        };

        let user_agent = string_util::to_wide("WXC-NetworkProxy/1.0");
        let handle = unsafe {
            open_fn(
                user_agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                ptr::null(),
                ptr::null(),
                0,
            )
        };

        if handle.is_null() {
            return Err(WxcError::NetworkProxy(
                "WinHttpOpen returned null".to_string(),
            ));
        }

        Ok(Self { handle, close_fn })
    }

    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.handle
    }
}

impl Drop for WinHttpSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                (self.close_fn)(self.handle);
            }
        }
    }
}

/// Resolved function pointers for the undocumented WinHTTP APIs.
struct WinHttpProxyFunctions {
    set_policy: FnWinHttpConnectionSetPolicyEntries,
    update_if_index: FnWinHttpConnectionUpdateIfIndexTable,
    set_proxy: FnWinHttpConnectionSetProxyInfo,
    delete_proxy: FnWinHttpConnectionDeleteProxyInfo,
}

impl WinHttpProxyFunctions {
    fn load(module: windows::Win32::Foundation::HMODULE) -> Result<Self, WxcError> {
        unsafe {
            let set_policy = GetProcAddress(
                module,
                windows::core::s!("WinHttpConnectionSetPolicyEntries"),
            )
            .ok_or_else(|| {
                WxcError::NetworkProxy(
                    "WinHttpConnectionSetPolicyEntries not found in winhttp.dll".to_string(),
                )
            })?;

            let update_if_index = GetProcAddress(
                module,
                windows::core::s!("WinHttpConnectionUpdateIfIndexTable"),
            )
            .ok_or_else(|| {
                WxcError::NetworkProxy(
                    "WinHttpConnectionUpdateIfIndexTable not found in winhttp.dll".to_string(),
                )
            })?;

            let set_proxy =
                GetProcAddress(module, windows::core::s!("WinHttpConnectionSetProxyInfo"))
                    .ok_or_else(|| {
                        WxcError::NetworkProxy(
                            "WinHttpConnectionSetProxyInfo not found in winhttp.dll".to_string(),
                        )
                    })?;

            let delete_proxy = GetProcAddress(
                module,
                windows::core::s!("WinHttpConnectionDeleteProxyInfo"),
            )
            .ok_or_else(|| {
                WxcError::NetworkProxy(
                    "WinHttpConnectionDeleteProxyInfo not found in winhttp.dll".to_string(),
                )
            })?;

            Ok(Self {
                set_policy: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWinHttpConnectionSetPolicyEntries,
                >(set_policy),
                update_if_index: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWinHttpConnectionUpdateIfIndexTable,
                >(update_if_index),
                set_proxy: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWinHttpConnectionSetProxyInfo,
                >(set_proxy),
                delete_proxy: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWinHttpConnectionDeleteProxyInfo,
                >(delete_proxy),
            })
        }
    }
}

/// Generate a GUID string in the format `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
fn generate_guid_string() -> Result<String, WxcError> {
    let guid = unsafe {
        CoCreateGuid()
            .map_err(|err| WxcError::NetworkProxy(format!("CoCreateGuid failed: {}", err)))?
    };

    Ok(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    ))
}

/// Convert a SID string (e.g. "S-1-15-2-...") to raw SID bytes.
fn sid_string_to_raw(sid_string: &str) -> Result<(PSID, u32), WxcError> {
    let wide_sid = string_util::to_wide(sid_string);
    let mut psid = PSID(ptr::null_mut());

    unsafe {
        ConvertStringSidToSidW(PCWSTR(wide_sid.as_ptr()), &mut psid).map_err(|err| {
            WxcError::NetworkProxy(format!(
                "ConvertStringSidToSidW failed for '{}': {}",
                sid_string, err
            ))
        })?;

        let sid_len = GetLengthSid(psid);
        Ok((psid, sid_len))
    }
}

fn free_sid(psid: PSID) {
    unsafe {
        let _ =
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(psid.0)));
    }
}

fn set_policy_entries(
    session: &WinHttpSession,
    functions: &WinHttpProxyFunctions,
    psid: PSID,
    sid_len: u32,
    connection_guid: &str,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let host_wide = string_util::to_wide("*");
    let connection_guid_wide = string_util::to_wide(connection_guid);
    let connection_ptr: *const u16 = connection_guid_wide.as_ptr();

    let mut policy_entry = WinHttpConnectionPolicyEntry {
        pwsz_host: host_wide.as_ptr(),
        pwsz_app_id: ptr::null(),
        cb_app_sid: sid_len,
        pb_app_sid: psid.0 as *const u8,
        n_connections: 1,
        ppwsz_connections: &connection_ptr,
        dw_policy_entry_flags: 0,
    };

    let mut policy_list = WinHttpConnectionPolicyEntryList {
        p_policy_entries: &mut policy_entry,
        n_entries: 1,
    };

    let result = unsafe {
        (functions.set_policy)(
            session.as_ptr(),
            WinHttpConnectionPolicyTag::Wwwpt,
            &mut policy_list,
        )
    };

    if result != 0 {
        if result == 5 {
            return Err(WxcError::NetworkProxy(
                "WinHttpConnectionSetPolicyEntries failed: access denied. \
                 Network proxy requires administrator privileges. Run wxc-exec as administrator."
                    .to_string(),
            ));
        }
        return Err(WxcError::NetworkProxy(format!(
            "WinHttpConnectionSetPolicyEntries failed (error {})",
            result
        )));
    }

    logger.log_line("Policy entry set successfully.");
    Ok(())
}

fn update_if_index_table(
    session: &WinHttpSession,
    functions: &WinHttpProxyFunctions,
    connection_guid: &str,
    if_index: u32,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let connection_guid_wide = string_util::to_wide(connection_guid);

    let mut entry = WinHttpConnectionIfindexEntry {
        pwsz_connection_name: connection_guid_wide.as_ptr(),
        dw_if_index: if_index,
    };

    let mut list = WinHttpConnectionIfindexList {
        n_entries: 1,
        p_connection_ifindex_entries: &mut entry,
    };

    let result = unsafe { (functions.update_if_index)(session.as_ptr(), &mut list) };

    if result != 0 {
        return Err(WxcError::NetworkProxy(format!(
            "WinHttpConnectionUpdateIfIndexTable failed (error {})",
            result
        )));
    }

    logger.log_line(&format!(
        "Connection bound to interface index {} (loopback).",
        if_index
    ));
    Ok(())
}

fn set_proxy_info(
    functions: &WinHttpProxyFunctions,
    connection_guid: &str,
    proxy_url: &str,
    proxy_port: u16,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let mut proxy_url_wide = string_util::to_wide(proxy_url);
    let connection_guid_wide = string_util::to_wide(connection_guid);

    let mut proxy_info = WinHttpConnectionProxyInfo {
        version: WINHTTP_CONNECTION_PROXY_INFO_CURRENT_VERSION,
        pwsz_friendly_name: PWSTR::null(),
        flags: 0,
        switch: WinHttpConnectionProxyInfoSwitch::Config,
        config: WinHttpConnectionProxyInfoConfig {
            pwsz_server: PWSTR(proxy_url_wide.as_mut_ptr()),
            pwsz_username: PWSTR::null(),   // not used
            pwsz_password: PWSTR::null(),   // not used
            pwsz_exception: PWSTR::null(),  // not used
            pwsz_extra_info: PWSTR::null(), // not used
            port: proxy_port,
        },
    };

    logger.log_line(&format!(
        "Setting proxy info: {} (port {})",
        proxy_url, proxy_port
    ));

    let result = unsafe {
        (functions.set_proxy)(
            connection_guid_wide.as_ptr(),
            WINHTTP_CONNECTION_PROXY_TYPE_HTTP,
            &mut proxy_info,
        )
    };

    if result != 0 {
        return Err(WxcError::NetworkProxy(format!(
            "WinHttpConnectionSetProxyInfo failed (error {})",
            result
        )));
    }

    Ok(())
}

/// Active proxy policy state — tracks what was set so it can be cleaned up.
///
/// **Requires elevation.** The WinHTTP proxy policy APIs return
/// `ERROR_ACCESS_DENIED` without administrator privileges. This is a POC
/// constraint — in production the OS will manage proxy policy on behalf of
/// the AppContainer, removing the need for elevation.
pub struct ActiveProxyPolicy {
    // The session handle owns the connection-policy state we set. It must
    // outlive the policy or the DNS cache service drops the binding, so we
    // keep it stored even though we don't read it back after setup.
    #[allow(dead_code)]
    session: WinHttpSession,
    connection_guid: String,
    functions: WinHttpProxyFunctions,
}

/// Reject any proxy address that doesn't resolve to a loopback IP.
///
/// We only support loopback proxies today because:
///   * loopback bypasses the AppContainer network isolation when the
///     container is granted the `networkLoopback` capability, and
///   * we always route the connection through the loopback adapter
///     (ifIndex 1) rather than calling `GetBestInterfaceEx` for a remote
///     proxy server.
///
/// Accepts an IP literal (parsed directly) or a hostname (resolved via DNS).
fn require_loopback_proxy(proxy_address: &str) -> Result<(), WxcError> {
    if let Ok(ip) = proxy_address.parse::<IpAddr>() {
        if ip.is_loopback() {
            return Ok(());
        }
        return Err(WxcError::NetworkProxy(format!(
            "Proxy address '{}' is not an IPv4 or IPv6 loopback address. \
             Only loopback proxies are supported.",
            proxy_address
        )));
    }

    let addrs: Vec<_> = (proxy_address, 0u16)
        .to_socket_addrs()
        .map_err(|err| {
            WxcError::NetworkProxy(format!(
                "Failed to resolve proxy host '{}': {}",
                proxy_address, err
            ))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(WxcError::NetworkProxy(format!(
            "Proxy host '{}' did not resolve to any addresses",
            proxy_address
        )));
    }

    if addrs.iter().all(|a| a.ip().is_loopback()) {
        return Ok(());
    }

    Err(WxcError::NetworkProxy(format!(
        "Proxy host '{}' resolves to a non-loopback address. \
         Only IPv4/IPv6 loopback proxies are supported.",
        proxy_address
    )))
}

impl ActiveProxyPolicy {
    /// Set a per-AppContainer proxy policy.
    ///
    /// This binds the AppContainer SID to a connection GUID, then binds that
    /// GUID to the loopback interface and a proxy server address/port.
    /// Mirrors the Orchestrator/SandboxNetworking pattern from the WinHTTP
    /// reference code.
    ///
    /// Returns an error if `proxy_address` is not an IPv4 or IPv6 loopback
    /// address (or a hostname that resolves exclusively to loopback).
    pub fn set(
        principal_id: &str,
        proxy_address: &str,
        proxy_port: u16,
        logger: &mut Logger,
    ) -> Result<Self, WxcError> {
        require_loopback_proxy(proxy_address)?;

        let dll_name = string_util::to_wide("winhttp.dll");
        let module = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }.map_err(|err| {
            WxcError::NetworkProxy(format!("Failed to load winhttp.dll: {}", err))
        })?;

        let functions = WinHttpProxyFunctions::load(module)?;
        let session = WinHttpSession::open(module)?;
        let connection_guid = generate_guid_string()?;

        logger.log_line(&format!(
            "Setting per-AppContainer proxy policy (connection GUID: {})",
            connection_guid
        ));

        let (psid, sid_len) = sid_string_to_raw(principal_id)?;
        let proxy_url = format!("http://{}:{}", proxy_address, proxy_port);

        if let Err(err) = set_policy_entries(
            &session,
            &functions,
            psid,
            sid_len,
            &connection_guid,
            logger,
        ) {
            free_sid(psid);
            return Err(err);
        }

        free_sid(psid);

        // Bind the connection GUID to the loopback adapter so the DNS cache
        // service routes traffic for this AppContainer through the loopback
        // interface. Without this, the connection GUID has no interface
        // mapping and the proxy lookup may return the wrong route.
        // We deliberately do NOT call `WinHttpConnectionDeletePolicyEntries`
        // to roll this back -- that API removes all policy entries for the
        // tag (including those owned by other concurrent sandboxes) and has
        // no per-GUID variant. The accepted trade-off is that a failure here
        // leaves the policy entry behind; it will be ignored without a
        // matching proxy info entry and is cleaned up at OS boot.
        update_if_index_table(
            &session,
            &functions,
            &connection_guid,
            LOOPBACK_IF_INDEX,
            logger,
        )?;

        // Same trade-off applies here: on failure we leave the policy entry
        // (and now the ifindex mapping) behind rather than wiping the
        // tag-wide state.
        set_proxy_info(&functions, &connection_guid, &proxy_url, proxy_port, logger)?;

        logger.log_line(&format!(
            "Proxy policy active: {}:{} for SID {}",
            proxy_address, proxy_port, principal_id
        ));

        Ok(Self {
            session,
            connection_guid,
            functions,
        })
    }

    /// Remove the per-AppContainer proxy policy.
    ///
    /// Only the per-GUID proxy info is cleaned up. We intentionally do NOT
    /// call `WinHttpConnectionDeletePolicyEntries`: it removes every
    /// in-memory entry for our tag, so concurrent sandbox launches would
    /// stomp each other's connection bindings. A per-GUID delete API does
    /// not exist, so the policy entry is left behind for the OS to recycle.
    pub fn delete(self, logger: &mut Logger) {
        let connection_guid_wide = string_util::to_wide(&self.connection_guid);

        unsafe {
            let result = (self.functions.delete_proxy)(
                connection_guid_wide.as_ptr(),
                WINHTTP_CONNECTION_PROXY_TYPE_HTTP,
            );
            if result == 0 {
                logger.log_line("Proxy info deleted.");
            } else {
                logger.log_line(&format!(
                    "Warning: WinHttpConnectionDeleteProxyInfo failed (error {})",
                    result
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_ipv4_literal_is_accepted() {
        assert!(require_loopback_proxy("127.0.0.1").is_ok());
        assert!(require_loopback_proxy("127.5.0.99").is_ok());
    }

    #[test]
    fn loopback_ipv6_literal_is_accepted() {
        assert!(require_loopback_proxy("::1").is_ok());
    }

    #[test]
    fn non_loopback_literal_is_rejected() {
        assert!(require_loopback_proxy("10.0.0.1").is_err());
        assert!(require_loopback_proxy("8.8.8.8").is_err());
        assert!(require_loopback_proxy("2001:4860:4860::8888").is_err());
    }

    #[test]
    fn invalid_string_is_rejected() {
        // Bogus hostname won't resolve; must surface as an error rather than
        // silently accepted as loopback.
        assert!(require_loopback_proxy("definitely.not.a.real.host.invalid.").is_err());
    }
}
