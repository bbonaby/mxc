// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-sandbox WFP policy manager.
//!
//! Implements spec §3.1 / §3.2 / §6.6: filters installed at
//! `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6`, scoped to one
//! AppContainer SID via `FWPM_CONDITION_ALE_PACKAGE_ID`.
//!
//! Weight tiers (deterministic):
//!
//! | Tier              | Weight        |
//! |-------------------|---------------|
//! | explicit `block`  | `0x2000_0000` |
//! | explicit `allow`  | `0x1000_0000` |
//! | default-deny      | `0x0000_0001` |
//!
//! `add_policy` performs partial-failure rollback: if filter *N*
//! fails to install, filters `0..N` are deleted before the error
//! returns so we never leave a half-installed policy.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::IpAddr;
use std::sync::Mutex;

use mxc_service_proto::{DefaultPolicy, PolicyId, Rule, RuleVerb, ServiceError, Transport};
use mxc_wfp_sys::{
    convert_string_sid_to_sid, filter_add, filter_delete_by_id, local_free, provider_add,
    sublayer_add, ERROR_SUCCESS, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_PACKAGE_ID,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER0_0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAGS,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_E_ALREADY_EXISTS, FWP_EMPTY,
    FWP_MATCH_EQUAL, FWP_SID, FWP_UINT16, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, Guid,
    PCWStr, PSid, PWStr,
};

use crate::engine::{win32_err, Engine, SessionKind};
use crate::{MXC_PROVIDER_GUID, MXC_SUBLAYER_GUID, MXC_SUBLAYER_WEIGHT};

const WEIGHT_EXPLICIT_BLOCK: u64 = 0x2000_0000;
const WEIGHT_EXPLICIT_ALLOW: u64 = 0x1000_0000;
const WEIGHT_DEFAULT_DENY: u64 = 0x0000_0001;

/// Resource cap — prototype only.
pub const MAX_ACTIVE_POLICIES: usize = 64;

/// RAII guard around a SID allocated by `ConvertStringSidToSidW`
/// (`LocalAlloc`-backed; needs `LocalFree`).
struct OwnedSid(PSid);

impl OwnedSid {
    fn from_sddl(sddl: &str) -> Result<Self, ServiceError> {
        if !sddl.starts_with("S-1-15-2-") {
            return Err(ServiceError::InvalidAcSid(sddl.into()));
        }
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = PSid::default();
        // SAFETY: `wide` is NUL-terminated for the duration of the call;
        // `sid` is a live stack slot.
        unsafe { convert_string_sid_to_sid(PCWStr(wide.as_ptr()), &mut sid) }
            .map_err(|_| ServiceError::InvalidAcSid(sddl.into()))?;
        if sid.is_invalid() {
            return Err(ServiceError::InvalidAcSid(sddl.into()));
        }
        Ok(Self(sid))
    }

    fn as_ptr(&self) -> PSid {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` was produced by `ConvertStringSidToSidW`,
            // documented `LocalAlloc` owner.
            unsafe { local_free(self.0 .0 as *mut c_void) }
        }
    }
}

/// Runtime façade over the BFE engine: tracks installed per-sandbox
/// filter ids and rolls back partial failures.
pub struct PolicyManager {
    engine: Engine,
    policies: Mutex<HashMap<PolicyId, Vec<u64>>>,
}

impl PolicyManager {
    pub fn open() -> Result<Self, ServiceError> {
        let engine = Engine::open(SessionKind::Dynamic)?;
        let mgr = Self {
            engine,
            policies: Mutex::new(HashMap::new()),
        };
        mgr.ensure_provider_and_sublayer()?;
        Ok(mgr)
    }

    fn ensure_provider_and_sublayer(&self) -> Result<(), ServiceError> {
        let mut name: Vec<u16> = "MXC Service\0".encode_utf16().collect();
        let mut desc: Vec<u16> = "MXC Tier 2 process-container provider\0"
            .encode_utf16()
            .collect();
        let provider = FWPM_PROVIDER0 {
            providerKey: MXC_PROVIDER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWStr(name.as_mut_ptr()),
                description: PWStr(desc.as_mut_ptr()),
            },
            flags: 0,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            serviceName: PWStr::null(),
        };
        // SAFETY: `provider`'s display-name buffers outlive the call.
        let rc = unsafe { provider_add(self.engine.handle(), &provider) };
        if rc != ERROR_SUCCESS.0 && rc != FWP_E_ALREADY_EXISTS.0 as u32 {
            return Err(win32_err("FwpmProviderAdd0", rc));
        }

        let mut sub_name: Vec<u16> = "MXC Service Sublayer\0".encode_utf16().collect();
        let mut sub_desc: Vec<u16> = "Per-sandbox MXC outbound policy\0".encode_utf16().collect();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: MXC_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWStr(sub_name.as_mut_ptr()),
                description: PWStr(sub_desc.as_mut_ptr()),
            },
            flags: 0,
            providerKey: &MXC_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: MXC_SUBLAYER_WEIGHT,
        };
        // SAFETY: `sublayer`'s display-name buffers and the borrowed
        // provider GUID outlive the call.
        let rc = unsafe { sublayer_add(self.engine.handle(), &sublayer) };
        if rc != ERROR_SUCCESS.0 && rc != FWP_E_ALREADY_EXISTS.0 as u32 {
            return Err(win32_err("FwpmSubLayerAdd0", rc));
        }
        Ok(())
    }

    pub fn add_policy(
        &self,
        ac_sid_sddl: &str,
        default: DefaultPolicy,
        rules: &[Rule],
    ) -> Result<(PolicyId, u32), ServiceError> {
        {
            let map = self.policies.lock().expect("policies mutex poisoned");
            if map.len() >= MAX_ACTIVE_POLICIES {
                return Err(ServiceError::ResourceExhausted(format!(
                    "active policies at cap ({MAX_ACTIVE_POLICIES})"
                )));
            }
        }

        for (i, rule) in rules.iter().enumerate() {
            validate_rule(i, rule)?;
        }

        let sid = OwnedSid::from_sddl(ac_sid_sddl)?;
        let policy_id = PolicyId::new_random();
        let mut installed: Vec<u64> = Vec::with_capacity(rules.len() * 2 + 2);

        if matches!(default, DefaultPolicy::Block) {
            for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
                self.install_one(
                    &mut installed,
                    &policy_id,
                    sid.as_ptr(),
                    layer,
                    FWP_ACTION_BLOCK,
                    WEIGHT_DEFAULT_DENY,
                    None,
                )?;
            }
        }

        for rule in rules {
            let (action, weight) = match rule.verb {
                RuleVerb::Allow => (FWP_ACTION_PERMIT, WEIGHT_EXPLICIT_ALLOW),
                RuleVerb::Block => (FWP_ACTION_BLOCK, WEIGHT_EXPLICIT_BLOCK),
            };
            for layer in pick_layers(rule) {
                self.install_one(
                    &mut installed,
                    &policy_id,
                    sid.as_ptr(),
                    layer,
                    action,
                    weight,
                    Some(rule),
                )?;
            }
        }

        let count = installed.len() as u32;
        self.policies
            .lock()
            .expect("policies mutex poisoned")
            .insert(policy_id, installed);
        Ok((policy_id, count))
    }

    pub fn remove_policy(&self, policy_id: PolicyId) -> Result<u32, ServiceError> {
        let ids = self
            .policies
            .lock()
            .expect("policies mutex poisoned")
            .remove(&policy_id)
            .ok_or(ServiceError::UnknownPolicy(policy_id))?;
        let mut removed = 0u32;
        for id in ids {
            // SAFETY: `engine` live; stale id is harmless (we ignore rc).
            let rc = unsafe { filter_delete_by_id(self.engine.handle(), id) };
            if rc == ERROR_SUCCESS.0 {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn install_one(
        &self,
        installed: &mut Vec<u64>,
        policy_id: &PolicyId,
        ac_sid: PSid,
        layer: Guid,
        action: FWP_ACTION_TYPE,
        weight: u64,
        rule: Option<&Rule>,
    ) -> Result<(), ServiceError> {
        match self.add_one_filter(policy_id, ac_sid, layer, action, weight, rule) {
            Ok(id) => {
                installed.push(id);
                Ok(())
            }
            Err(e) => {
                for id in installed.drain(..) {
                    // SAFETY: rollback path; engine live; ignore rc.
                    let _ = unsafe { filter_delete_by_id(self.engine.handle(), id) };
                }
                Err(e)
            }
        }
    }

    fn add_one_filter(
        &self,
        policy_id: &PolicyId,
        ac_sid: PSid,
        layer: Guid,
        action: FWP_ACTION_TYPE,
        weight: u64,
        rule: Option<&Rule>,
    ) -> Result<u64, ServiceError> {
        // Storage that must outlive the FwpmFilterAdd0 call.
        let mut v4_mask = FWP_V4_ADDR_AND_MASK { addr: 0, mask: 0 };
        let mut v6_mask = FWP_V6_ADDR_AND_MASK {
            addr: [0u8; 16],
            prefixLength: 0,
        };
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(4);

        // 1. Always: AppContainer package SID match.
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SID,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sid: ac_sid.0 as *mut _,
                },
            },
        });

        if let Some(r) = rule {
            // 2. Remote address (absent = "any").
            if let Some(addr_str) = r.address.as_deref() {
                let ip: IpAddr = addr_str.parse().map_err(|_| ServiceError::InvalidRule {
                    index: 0,
                    reason: format!("not a valid IP literal: {addr_str}"),
                })?;
                match ip {
                    IpAddr::V4(v4) => {
                        v4_mask.addr = u32::from_be_bytes(v4.octets());
                        v4_mask.mask = prefix_to_v4_mask(r.prefix_length.unwrap_or(32));
                        conditions.push(FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_V4_ADDR_MASK,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    v4AddrMask: &mut v4_mask,
                                },
                            },
                        });
                    }
                    IpAddr::V6(v6) => {
                        v6_mask.addr = v6.octets();
                        v6_mask.prefixLength = r.prefix_length.unwrap_or(128);
                        conditions.push(FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_V6_ADDR_MASK,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    v6AddrMask: &mut v6_mask,
                                },
                            },
                        });
                    }
                }
            }

            // 3. Remote port.
            if let Some(port) = r.port {
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                    },
                });
            }

            // 4. Transport protocol.
            if let Some(proto) = transport_to_ip_protocol(r.transport) {
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint8: proto },
                    },
                });
            }
        }

        let mut name: Vec<u16> = format!(
            "MXC Policy {} [{}]\0",
            policy_id,
            layer_short_name(&layer)
        )
        .encode_utf16()
        .collect();
        let mut desc: Vec<u16> = "MXC Tier 2 per-sandbox rule\0".encode_utf16().collect();

        let mut weight_storage: u64 = weight;
        let filter = FWPM_FILTER0 {
            filterKey: Guid::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWStr(name.as_mut_ptr()),
                description: PWStr(desc.as_mut_ptr()),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &MXC_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            layerKey: layer,
            subLayerKey: MXC_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight_storage,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: Guid::zeroed(),
                },
            },
            Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
            reserved: std::ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0 {
                r#type: FWP_EMPTY,
                Anonymous: FWP_VALUE0_0 {
                    uint64: std::ptr::null_mut(),
                },
            },
        };

        let mut filter_id: u64 = 0;
        // SAFETY: `engine` live; `filter` references stack/heap
        // (`name`, `desc`, `conditions`, `v4_mask`, `v6_mask`,
        // `weight_storage`) all live until end of function.
        let rc = unsafe { filter_add(self.engine.handle(), &filter, Some(&mut filter_id)) };
        if rc != ERROR_SUCCESS.0 {
            return Err(win32_err("FwpmFilterAdd0", rc));
        }
        Ok(filter_id)
    }
}

fn validate_rule(index: usize, rule: &Rule) -> Result<(), ServiceError> {
    if rule.address.is_none() && rule.prefix_length.is_some() {
        return Err(ServiceError::InvalidRule {
            index: index as u32,
            reason: "prefix_length without address".into(),
        });
    }
    if let Some(addr) = &rule.address {
        let ip: IpAddr = addr.parse().map_err(|_| ServiceError::InvalidRule {
            index: index as u32,
            reason: format!("not a valid IP literal: {addr}"),
        })?;
        if let Some(prefix) = rule.prefix_length {
            let max = match ip {
                IpAddr::V4(_) => 32u8,
                IpAddr::V6(_) => 128u8,
            };
            if prefix == 0 || prefix > max {
                return Err(ServiceError::InvalidRule {
                    index: index as u32,
                    reason: format!("prefix_length {prefix} out of range (1..={max})"),
                });
            }
        }
    }
    if let Some(p) = rule.port {
        if p == 0 {
            return Err(ServiceError::InvalidRule {
                index: index as u32,
                reason: "port 0 is not a valid match".into(),
            });
        }
    }
    Ok(())
}

fn pick_layers(rule: &Rule) -> Vec<Guid> {
    match rule.address.as_deref().and_then(|s| s.parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(_)) => vec![FWPM_LAYER_ALE_AUTH_CONNECT_V4],
        Some(IpAddr::V6(_)) => vec![FWPM_LAYER_ALE_AUTH_CONNECT_V6],
        None => vec![FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6],
    }
}

fn prefix_to_v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        !0u32
    } else {
        (!0u32).wrapping_shl(32 - prefix as u32)
    }
}

fn transport_to_ip_protocol(t: Transport) -> Option<u8> {
    match t {
        Transport::Tcp => Some(6),
        Transport::Udp => Some(17),
        Transport::Any => None,
    }
}

fn layer_short_name(layer: &Guid) -> &'static str {
    if *layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 {
        "v4"
    } else if *layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
        "v6"
    } else {
        "?"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_to_mask_basic() {
        assert_eq!(prefix_to_v4_mask(0), 0);
        assert_eq!(prefix_to_v4_mask(8), 0xff00_0000);
        assert_eq!(prefix_to_v4_mask(20), 0xffff_f000);
        assert_eq!(prefix_to_v4_mask(32), 0xffff_ffff);
    }

    #[test]
    fn validate_rule_rejects_prefix_without_address() {
        let r = Rule {
            verb: RuleVerb::Allow,
            transport: Transport::Tcp,
            address: None,
            prefix_length: Some(24),
            port: None,
        };
        assert!(validate_rule(0, &r).is_err());
    }

    #[test]
    fn validate_rule_rejects_bad_ip() {
        let r = Rule {
            verb: RuleVerb::Allow,
            transport: Transport::Tcp,
            address: Some("not.an.ip".into()),
            prefix_length: None,
            port: None,
        };
        assert!(validate_rule(0, &r).is_err());
    }

    #[test]
    fn validate_rule_rejects_oversize_prefix() {
        let r = Rule {
            verb: RuleVerb::Allow,
            transport: Transport::Tcp,
            address: Some("10.0.0.0".into()),
            prefix_length: Some(33),
            port: None,
        };
        assert!(validate_rule(0, &r).is_err());
    }

    #[test]
    fn validate_rule_rejects_port_zero() {
        let r = Rule {
            verb: RuleVerb::Allow,
            transport: Transport::Tcp,
            address: Some("10.0.0.1".into()),
            prefix_length: None,
            port: Some(0),
        };
        assert!(validate_rule(0, &r).is_err());
    }

    #[test]
    fn validate_rule_accepts_good_input() {
        let r = Rule {
            verb: RuleVerb::Allow,
            transport: Transport::Tcp,
            address: Some("140.82.112.0".into()),
            prefix_length: Some(20),
            port: Some(443),
        };
        assert!(validate_rule(0, &r).is_ok());
    }

    #[test]
    fn pick_layers_dual_for_wildcard() {
        let r = Rule {
            verb: RuleVerb::Block,
            transport: Transport::Any,
            address: None,
            prefix_length: None,
            port: None,
        };
        assert_eq!(pick_layers(&r).len(), 2);
    }

    #[test]
    fn owned_sid_rejects_non_appcontainer_sid() {
        assert!(OwnedSid::from_sddl("S-1-5-18").is_err());
        assert!(OwnedSid::from_sddl("nonsense").is_err());
    }
}
