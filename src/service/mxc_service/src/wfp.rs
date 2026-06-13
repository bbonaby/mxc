// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WFP (Windows Filtering Platform) wrapper for `mxc-service`.
//!
//! Implements spec §3.1 / §3.2 / §6.6: per-sandbox policies installed
//! as filters at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6`, scoped to
//! one AppContainer SID via `FWPM_CONDITION_ALE_PACKAGE_ID`.
//!
//! ## Weight tiers (deterministic; design review item #4)
//!
//! Inside the MXC sublayer we use three explicit weight tiers so
//! overlapping rules resolve deterministically:
//!
//! | Tier                        | Weight        | Notes                                  |
//! |-----------------------------|---------------|----------------------------------------|
//! | explicit `block`            | `0x2000_0000` | Always wins inside our sublayer.       |
//! | explicit `allow`            | `0x1000_0000` | Carves holes through the default-deny. |
//! | catch-all `block` (deny)    | `0x0000_0001` | Only installed when default = block.   |
//!
//! Cross-sublayer arbitration is decided by the sublayer weight
//! (`MXC_SUBLAYER_WEIGHT`) — note review item #3: this does **not**
//! prove dominance over system-origin filters; that has to be
//! verified empirically on the VM.
//!
//! ## Lifetime
//!
//! Filters are installed on a dynamic engine session. They disappear
//! when `WfpEngine` is dropped (process death) or when
//! `remove_policy` is called. Provider + sublayer are also created
//! on the dynamic session (so they too disappear with us) — see
//! review item #9; this is an intentional prototype choice. Promoting
//! provider/sublayer to durable objects is future work.
//!
//! ## AddPolicy atomicity
//!
//! `add_policy` performs partial-failure rollback (review item #8):
//! if filter *N* fails to install, filters `0..N` are deleted before
//! returning the error so we never leave a half-installed policy.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::IpAddr;
use std::sync::Mutex;

use mxc_service_proto::{DefaultPolicy, PolicyId, Rule, RuleVerb, ServiceError, Transport};
use windows::core::{w, GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    LocalFree, ERROR_SUCCESS, FWP_E_ALREADY_EXISTS, HANDLE, HLOCAL,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::PSID;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

// Stable GUIDs owned by MXC. Changing them breaks upgrade paths.
const MXC_PROVIDER_GUID: GUID = GUID::from_u128(0x7a3d1bbe_3f1e_4d7a_9c4e_5a36f51e9b21);
const MXC_SUBLAYER_GUID: GUID = GUID::from_u128(0x7a3d1bbf_3f1e_4d7a_9c4e_5a36f51e9b22);

const MXC_SUBLAYER_WEIGHT: u16 = 0x4000;

const WEIGHT_EXPLICIT_BLOCK: u64 = 0x2000_0000;
const WEIGHT_EXPLICIT_ALLOW: u64 = 0x1000_0000;
const WEIGHT_DEFAULT_DENY: u64 = 0x0000_0001;

/// Resource cap — prototype only.
pub const MAX_ACTIVE_POLICIES: usize = 64;

/// RAII guard around a SID allocated by `ConvertStringSidToSidW`
/// (uses `LocalAlloc`; needs `LocalFree`).
struct OwnedSid(PSID);

impl OwnedSid {
    fn from_sddl(sddl: &str) -> Result<Self, ServiceError> {
        // AppContainer package SIDs start with `S-1-15-2-`. Reject
        // anything else early — design review item #8.
        if !sddl.starts_with("S-1-15-2-") {
            return Err(ServiceError::InvalidAcSid(sddl.into()));
        }
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = PSID::default();
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid)
                .map_err(|_| ServiceError::InvalidAcSid(sddl.into()))?;
        }
        if sid.is_invalid() {
            return Err(ServiceError::InvalidAcSid(sddl.into()));
        }
        Ok(Self(sid))
    }

    fn as_ptr(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0 as *mut c_void)));
            }
        }
    }
}

pub struct WfpEngine {
    handle: HANDLE,
    policies: Mutex<HashMap<PolicyId, Vec<u64>>>,
}

unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl WfpEngine {
    pub fn open() -> Result<Self, ServiceError> {
        let mut handle = HANDLE::default();
        let session = FWPM_SESSION0 {
            sessionKey: GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(w!("mxc-service").as_ptr() as *mut _),
                description: PWSTR(w!("MXC Tier 2 policy session").as_ptr() as *mut _),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 0,
            processId: 0,
            sid: std::ptr::null_mut(),
            username: PWSTR::null(),
            kernelMode: false.into(),
        };
        unsafe {
            let rc = FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_WINNT as u32,
                None,
                Some(&session),
                &mut handle,
            );
            if rc != ERROR_SUCCESS.0 {
                return Err(win32_err("FwpmEngineOpen0", rc));
            }
        }
        let engine = Self {
            handle,
            policies: Mutex::new(HashMap::new()),
        };
        engine.ensure_provider_and_sublayer()?;
        Ok(engine)
    }

    fn ensure_provider_and_sublayer(&self) -> Result<(), ServiceError> {
        let mut name: Vec<u16> = "MXC Service\0".encode_utf16().collect();
        let mut desc: Vec<u16> = "MXC Tier 2 process-container provider\0"
            .encode_utf16()
            .collect();
        let provider = FWPM_PROVIDER0 {
            providerKey: MXC_PROVIDER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(desc.as_mut_ptr()),
            },
            // No PERSISTENT flag — the dynamic session reaps this on
            // close. Each service start re-registers.
            flags: 0,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            serviceName: PWSTR::null(),
        };
        unsafe {
            let rc = FwpmProviderAdd0(self.handle, &provider, None);
            if rc != ERROR_SUCCESS.0 && rc != FWP_E_ALREADY_EXISTS.0 as u32 {
                return Err(win32_err("FwpmProviderAdd0", rc));
            }
        }

        let mut sub_name: Vec<u16> = "MXC Service Sublayer\0".encode_utf16().collect();
        let mut sub_desc: Vec<u16> = "Per-sandbox MXC outbound policy\0".encode_utf16().collect();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: MXC_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sub_name.as_mut_ptr()),
                description: PWSTR(sub_desc.as_mut_ptr()),
            },
            flags: 0,
            providerKey: &MXC_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: MXC_SUBLAYER_WEIGHT,
        };
        unsafe {
            let rc = FwpmSubLayerAdd0(self.handle, &sublayer, None);
            if rc != ERROR_SUCCESS.0 && rc != FWP_E_ALREADY_EXISTS.0 as u32 {
                return Err(win32_err("FwpmSubLayerAdd0", rc));
            }
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

        // Validate every rule before touching WFP — fail fast.
        for (i, rule) in rules.iter().enumerate() {
            validate_rule(i, rule)?;
        }

        let sid = OwnedSid::from_sddl(ac_sid_sddl)?;
        let policy_id = PolicyId::new_random();
        let mut installed: Vec<u64> = Vec::with_capacity(rules.len() * 2 + 2);

        // Helper closure: install one filter, rolling back on error.
        let install_one = |engine: &Self,
                           installed: &mut Vec<u64>,
                           layer: GUID,
                           action: FWP_ACTION_TYPE,
                           weight: u64,
                           rule: Option<&Rule>|
         -> Result<(), ServiceError> {
            match engine.add_one_filter(&policy_id, sid.as_ptr(), layer, action, weight, rule) {
                Ok(id) => {
                    installed.push(id);
                    Ok(())
                }
                Err(e) => {
                    // Rollback prior filters in this transaction.
                    for id in installed.drain(..) {
                        unsafe {
                            let _ = FwpmFilterDeleteById0(engine.handle, id);
                        }
                    }
                    Err(e)
                }
            }
        };

        // Catch-all default-deny first (lowest weight) so explicit
        // allows can carve through.
        if matches!(default, DefaultPolicy::Block) {
            for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
                install_one(
                    self,
                    &mut installed,
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
                install_one(self, &mut installed, layer, action, weight, Some(rule))?;
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
            unsafe {
                if FwpmFilterDeleteById0(self.handle, id) == ERROR_SUCCESS.0 {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    fn add_one_filter(
        &self,
        policy_id: &PolicyId,
        ac_sid: PSID,
        layer: GUID,
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

        // 2. Remote address (if rule pins one). Absent = "any" per
        // design review item #7.
        if let Some(r) = rule {
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
            filterKey: GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(desc.as_mut_ptr()),
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
                    filterType: GUID::zeroed(),
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
        unsafe {
            let rc = FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id));
            if rc != ERROR_SUCCESS.0 {
                return Err(win32_err("FwpmFilterAdd0", rc));
            }
        }
        Ok(filter_id)
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }
}

fn win32_err(api: &str, rc: u32) -> ServiceError {
    ServiceError::WfpFailure {
        api: api.into(),
        hresult: rc,
        message: format!("Win32 error {rc} (0x{rc:08X})"),
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

fn pick_layers(rule: &Rule) -> Vec<GUID> {
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

fn layer_short_name(layer: &GUID) -> &'static str {
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
