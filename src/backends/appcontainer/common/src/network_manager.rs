// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AppContainer network setup.
//!
//! Per-host filtering goes through the Tier 2 broker (`mxc-service`)
//! via [`BrokerSession`]. The proxy stack is handled by
//! [`ProxyCoordinator`] (orthogonal — runs as the caller, no broker).
//!
//! There is no Windows-Firewall (`INetFwPolicy2`) fallback. That path
//! required wxc-exec to run elevated, which defeats the Tier 2 goal of
//! keeping the sandbox launcher unprivileged. Any per-host enforcement
//! is the broker's job, period.

use crate::broker_network::BrokerSession;
use crate::proxy_coordinator::ProxyCoordinator;
use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::ContainerPolicy;

pub struct NetworkManager {
    proxy_coordinator: ProxyCoordinator,
    broker: BrokerSession,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::new(),
            broker: BrokerSession::new(),
        }
    }

    /// Returns the proxy address if a proxy is active.
    pub fn proxy_address(&self) -> Option<&wxc_common::models::ProxyAddress> {
        self.proxy_coordinator.address()
    }

    /// Returns `true` if the broker installed any per-host filters.
    pub fn rules_applied(&self) -> bool {
        self.broker.is_active()
    }

    /// Start the proxy (if configured). Must run BEFORE the sandbox
    /// process is created so the proxy URL is in the child's env block.
    pub fn start_proxy(
        &mut self,
        principal_id: &str,
        container_name: &str,
        policy: &ContainerPolicy,
        script_sid: windows::Win32::Security::PSID,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if policy.network_proxy.is_enabled() {
            self.proxy_coordinator.start(
                &policy.network_proxy,
                container_name,
                principal_id,
                script_sid,
                logger,
            )?;
        }
        Ok(())
    }

    /// Install per-host WFP filters via the Tier 2 broker. MUST be
    /// called AFTER `CreateProcessW(CREATE_SUSPENDED)` and BEFORE
    /// `ResumeThread`. Filters are scoped to the AppContainer SID, and
    /// the broker also wires lifetime cleanup to `sandbox_pid` so a
    /// crash between resume and explicit `stop_all` doesn't leak
    /// policy.
    pub fn start_broker(
        &mut self,
        principal_id: &str,
        sandbox_pid: u32,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if let Err(err) = self.broker.start(principal_id, sandbox_pid, policy, logger) {
            if self.proxy_coordinator.is_active() {
                self.proxy_coordinator.stop(logger);
            }
            return Err(err);
        }
        Ok(())
    }

    /// Tear down broker filters and proxy state. Idempotent.
    pub fn stop_all(&mut self, cleanup_policy: bool, logger: &mut Logger) {
        if cleanup_policy {
            self.broker.stop(logger);
        }
        if self.proxy_coordinator.is_active() {
            self.proxy_coordinator.stop(logger);
        }
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_manager_has_no_state() {
        let mgr = NetworkManager::new();
        assert!(!mgr.rules_applied());
        assert!(mgr.proxy_address().is_none());
    }
}
