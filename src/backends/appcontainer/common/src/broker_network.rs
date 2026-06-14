// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tier 2 broker client: marshals the script's per-host policy into
//! `mxc-service` AddPolicy / RemovePolicy calls.
//!
//! The broker writes WFP filters scoped to the AppContainer SID, so
//! no admin privileges are needed in this process. Filter lifetime is
//! bound to the `PolicyId` returned by `AddPolicy`; we hold it until
//! `stop()` runs and then call `RemovePolicy`.
//!
//! When the broker is unreachable (service not installed, pipe ACL
//! denied, etc.) we fall back to the legacy `NetworkManager` path so
//! existing playground configs that target the Tier 1 Windows
//! Firewall code keep working.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use mxc_service_client::Client;
use mxc_service_proto::{DefaultPolicy, PolicyId, Rule, RuleVerb, Transport};

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkPolicy};

/// Per-sandbox broker session. Lives alongside `NetworkManager`.
pub struct BrokerSession {
    policy_id: Option<PolicyId>,
}

impl BrokerSession {
    pub fn new() -> Self {
        Self { policy_id: None }
    }

    /// True iff `policy` describes per-host filtering the broker can
    /// implement on this host. Callers use this to decide whether to
    /// route through the broker vs. the legacy `NetworkManager` path.
    pub fn applies_to(policy: &ContainerPolicy) -> bool {
        !policy.allowed_hosts.is_empty()
            || !policy.blocked_hosts.is_empty()
            || policy.default_network_policy == NetworkPolicy::Block
    }

    /// Resolve hostnames, build broker rules, and install them via the
    /// service. Returns `Ok(true)` if the broker accepted the policy,
    /// `Ok(false)` if there was nothing for the broker to do, or `Err`
    /// on a hard failure (caller may fall back).
    pub fn start(
        &mut self,
        ac_sid_sddl: &str,
        sandbox_pid: u32,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, WxcError> {
        if !Self::applies_to(policy) {
            return Ok(false);
        }

        let default = match policy.default_network_policy {
            NetworkPolicy::Block => DefaultPolicy::Block,
            NetworkPolicy::Allow => DefaultPolicy::Allow,
        };

        let mut rules: Vec<Rule> = Vec::new();
        push_host_rules(&policy.blocked_hosts, RuleVerb::Block, &mut rules, logger);
        push_host_rules(&policy.allowed_hosts, RuleVerb::Allow, &mut rules, logger);

        logger.log_line(&format!(
            "broker: AddPolicy ac_sid={ac_sid_sddl} default={default:?} \
             rules={} sandbox_pid={sandbox_pid}",
            rules.len()
        ));

        let client = Client::connect_with_timeout(Duration::from_secs(2))
            .map_err(|e| WxcError::Firewall(format!("broker connect: {e}")))?;
        let (policy_id, filters_installed) = client
            .add_policy(ac_sid_sddl.to_string(), default, rules, sandbox_pid)
            .map_err(|e| WxcError::Firewall(format!("broker AddPolicy: {e}")))?;

        logger.log_line(&format!(
            "broker: policy_id={policy_id} filters_installed={filters_installed}"
        ));
        self.policy_id = Some(policy_id);
        Ok(true)
    }

    /// Best-effort cleanup. Idempotent.
    pub fn stop(&mut self, logger: &mut Logger) {
        let Some(policy_id) = self.policy_id.take() else {
            return;
        };
        match Client::connect_with_timeout(Duration::from_secs(2)) {
            Ok(client) => match client.remove_policy(policy_id) {
                Ok(removed) => logger.log_line(&format!(
                    "broker: RemovePolicy policy_id={policy_id} filters_removed={removed}"
                )),
                Err(e) => logger
                    .log_line(&format!("broker: RemovePolicy {policy_id} failed: {e}")),
            },
            Err(e) => logger.log_line(&format!(
                "broker: RemovePolicy {policy_id} skipped (connect failed: {e})"
            )),
        }
    }

    pub fn is_active(&self) -> bool {
        self.policy_id.is_some()
    }
}

impl Default for BrokerSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        if self.policy_id.is_some() {
            let mut sink = Logger::new(wxc_common::logger::Mode::Buffer);
            self.stop(&mut sink);
        }
    }
}

fn push_host_rules(hosts: &[String], verb: RuleVerb, out: &mut Vec<Rule>, logger: &mut Logger) {
    for host in hosts {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        for addr in resolve(host, logger) {
            out.push(Rule {
                verb,
                transport: Transport::Any,
                address: Some(addr.to_string()),
                prefix_length: None,
                port: None,
            });
        }
    }
}

fn resolve(host: &str, logger: &mut Logger) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    // ToSocketAddrs needs a port; any port works for resolution.
    match (host, 0u16).to_socket_addrs() {
        Ok(iter) => {
            let mut seen: Vec<IpAddr> = Vec::new();
            for sa in iter {
                let ip = sa.ip();
                if !seen.contains(&ip) {
                    seen.push(ip);
                }
            }
            if seen.is_empty() {
                logger.log_line(&format!("broker: warn — '{host}' resolved to no addresses"));
            }
            seen
        }
        Err(e) => {
            logger.log_line(&format!("broker: warn — '{host}' DNS resolution failed: {e}"));
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};

    fn empty_policy() -> ContainerPolicy {
        ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            network_enforcement_mode: NetworkEnforcementMode::Both,
            allow_local_network: false,
            allowed_hosts: vec![],
            blocked_hosts: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn applies_to_false_for_default_allow_no_lists() {
        assert!(!BrokerSession::applies_to(&empty_policy()));
    }

    #[test]
    fn applies_to_true_for_block_default() {
        let mut p = empty_policy();
        p.default_network_policy = NetworkPolicy::Block;
        assert!(BrokerSession::applies_to(&p));
    }

    #[test]
    fn applies_to_true_for_blocked_hosts() {
        let mut p = empty_policy();
        p.blocked_hosts = vec!["8.8.8.8".into()];
        assert!(BrokerSession::applies_to(&p));
    }

    #[test]
    fn resolve_passes_through_ip_literal() {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let addrs = resolve("8.8.8.8", &mut logger);
        assert_eq!(addrs, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }
}
