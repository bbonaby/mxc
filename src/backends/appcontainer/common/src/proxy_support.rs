// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared proxy plumbing used by both the AppContainer and BaseContainer
//! runners so the policy-to-capability mapping and the loopback-only check
//! stay in lockstep across the two backends.

use std::net::{IpAddr, ToSocketAddrs};

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, ProxyAddress, ScriptResponse};

/// Generic error message for the loopback-only proxy restriction.
///
/// Phrased without referencing a specific runner because the constraint
/// applies to all process-container backends on Windows.
pub const PROXY_LOOPBACK_ONLY_ERROR: &str =
    "Network proxy address must be an IPv4 or IPv6 loopback address. \
     Only loopback proxy URLs are currently supported for process \
     containers on Windows.";

/// Validate the proxy section of an `ExecutionRequest` for the process-container
/// backends on Windows. Intended to be called from
/// `ScriptRunner::validate_runner` so the error surfaces before any sandbox
/// state is built up.
///
/// Skips the check when no user-supplied proxy address is set: the builtin
/// test server always binds to a loopback address, so its address (filled in
/// at execute time) trivially satisfies the constraint.
pub fn validate_proxy_for_runner(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if !request.policy.network_proxy.is_enabled() {
        return Ok(());
    }
    if let Some(addr) = request.policy.network_proxy.address.as_ref() {
        if let Err(err) = require_loopback_proxy(addr) {
            return Err(ScriptResponse::error(&err.to_string()));
        }
    }
    Ok(())
}

/// Reject any proxy whose host is not an IPv4 / IPv6 loopback address.
///
/// Accepts an IP literal (parsed directly) or a hostname (resolved via DNS;
/// every returned address must be loopback). On any failure we surface the
/// same generic error so callers don't leak runner-specific wording.
pub fn require_loopback_proxy(address: &ProxyAddress) -> Result<(), WxcError> {
    let host = address.host();

    if let Ok(ip) = host.parse::<IpAddr>() {
        return if ip.is_loopback() {
            Ok(())
        } else {
            Err(WxcError::NetworkProxy(PROXY_LOOPBACK_ONLY_ERROR.into()))
        };
    }

    let resolved: Vec<_> = (host, 0u16)
        .to_socket_addrs()
        .map_err(|_| WxcError::NetworkProxy(PROXY_LOOPBACK_ONLY_ERROR.into()))?
        .collect();

    if !resolved.is_empty() && resolved.iter().all(|a| a.ip().is_loopback()) {
        Ok(())
    } else {
        Err(WxcError::NetworkProxy(PROXY_LOOPBACK_ONLY_ERROR.into()))
    }
}

/// Apply the proxy-specific capability adjustments to a capability list.
///
/// When a proxy is active the sandbox must talk to the loopback-bound proxy
/// instead of the open internet, so we:
///   * remove `internetClient` (the sandbox should not reach the open
///     internet directly), and
///   * grant `networkLoopback` so the OS allows the loopback connection
///     without a per-container loopback exemption.
///
/// This is a no-op when `proxy_enabled` is false.
pub fn apply_proxy_capability_adjustments(
    capabilities: &mut Vec<String>,
    proxy_enabled: bool,
    logger: &mut Logger,
) {
    if !proxy_enabled {
        return;
    }

    let stripped = capabilities.iter().any(|c| c == "internetClient");
    capabilities.retain(|c| c != "internetClient");
    if stripped {
        logger.log_line(
            "Proxy active: stripped 'internetClient' capability; \
             sandbox traffic is restricted to the configured proxy.",
        );
    }

    if !capabilities.iter().any(|c| c == "networkLoopback") {
        capabilities.push("networkLoopback".to_string());
        logger.log_line(
            "Proxy active: granted 'networkLoopback' capability so the \
             sandbox can reach the loopback proxy.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::logger::Mode;

    fn buffer_logger() -> Logger {
        Logger::new(Mode::Buffer)
    }

    fn addr(host: &str) -> ProxyAddress {
        ProxyAddress::new(host.to_string(), 8080)
    }

    #[test]
    fn loopback_ipv4_literal_is_accepted() {
        require_loopback_proxy(&addr("127.0.0.1")).unwrap();
        require_loopback_proxy(&addr("127.5.0.99")).unwrap();
    }

    #[test]
    fn loopback_ipv6_literal_is_accepted() {
        require_loopback_proxy(&addr("::1")).unwrap();
    }

    #[test]
    fn non_loopback_literal_is_rejected() {
        assert!(require_loopback_proxy(&addr("10.0.0.1")).is_err());
        assert!(require_loopback_proxy(&addr("8.8.8.8")).is_err());
        assert!(require_loopback_proxy(&addr("2001:4860:4860::8888")).is_err());
    }

    #[test]
    fn invalid_host_is_rejected_with_generic_message() {
        let err = require_loopback_proxy(&addr("definitely.not.a.real.host.invalid."))
            .expect_err("should reject unresolvable host");
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn capability_adjustment_noop_when_proxy_disabled() {
        let mut caps = vec!["internetClient".to_string(), "registryRead".to_string()];
        apply_proxy_capability_adjustments(&mut caps, false, &mut buffer_logger());
        assert_eq!(caps, vec!["internetClient", "registryRead"]);
    }

    #[test]
    fn capability_adjustment_strips_internet_client_when_proxy_enabled() {
        let mut caps = vec!["internetClient".to_string(), "registryRead".to_string()];
        apply_proxy_capability_adjustments(&mut caps, true, &mut buffer_logger());
        assert!(!caps.iter().any(|c| c == "internetClient"));
        assert!(caps.iter().any(|c| c == "networkLoopback"));
        assert!(caps.iter().any(|c| c == "registryRead"));
    }

    #[test]
    fn capability_adjustment_adds_loopback_when_absent() {
        let mut caps: Vec<String> = vec![];
        apply_proxy_capability_adjustments(&mut caps, true, &mut buffer_logger());
        assert_eq!(caps, vec!["networkLoopback"]);
    }

    #[test]
    fn capability_adjustment_does_not_duplicate_loopback() {
        let mut caps = vec!["networkLoopback".to_string()];
        apply_proxy_capability_adjustments(&mut caps, true, &mut buffer_logger());
        assert_eq!(caps, vec!["networkLoopback"]);
    }

    #[test]
    fn validate_proxy_for_runner_accepts_no_proxy() {
        let req = ExecutionRequest::default();
        validate_proxy_for_runner(&req).unwrap();
    }

    #[test]
    fn validate_proxy_for_runner_accepts_loopback_address() {
        use wxc_common::models::ProxyConfig;
        let mut req = ExecutionRequest::default();
        req.policy.network_proxy = ProxyConfig {
            address: Some(addr("127.0.0.1")),
            builtin_test_server: false,
        };
        validate_proxy_for_runner(&req).unwrap();
    }

    #[test]
    fn validate_proxy_for_runner_rejects_non_loopback_address() {
        use wxc_common::models::ProxyConfig;
        let mut req = ExecutionRequest::default();
        req.policy.network_proxy = ProxyConfig {
            address: Some(addr("8.8.8.8")),
            builtin_test_server: false,
        };
        let resp = validate_proxy_for_runner(&req).expect_err("non-loopback must be rejected");
        assert!(resp.error_message.contains("loopback"));
    }

    #[test]
    fn validate_proxy_for_runner_skips_check_for_builtin_server() {
        use wxc_common::models::ProxyConfig;
        let mut req = ExecutionRequest::default();
        req.policy.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };
        validate_proxy_for_runner(&req).unwrap();
    }
}
