// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IPC contract between the MXC SDK and the elevated `mxc-service`.
//!
//! This crate is shared by the service implementation (`mxc_service`) and
//! the client wrapper (`mxc_service_client`). All wire types live here so
//! there is exactly one source of truth for the protocol.
//!
//! ## Prototype scope
//!
//! Tier 2 / process-container-networking spec (sections 4.1–4.4 + 6.7)
//! mandates **LRPC** as the production IPC. The prototype substitutes a
//! Windows **named pipe** (`\\.\pipe\mxc-service`) — same trust boundary
//! (kernel-mediated, local-only with `PIPE_REJECT_REMOTE_CLIENTS`),
//! easier-to-author Rust binding. The wire format is decoupled from the
//! transport so a future LRPC swap touches only `mxc_service`'s
//! transport module, not this crate.
//!
//! ## Wire framing
//!
//! Each message is a 4-byte little-endian payload-length prefix followed
//! by a CBOR-encoded `Request` (client → service) or `Response` (service
//! → client). Length excludes the prefix itself. Max payload size is
//! bounded by `MAX_MESSAGE_BYTES`.
//!
//! ## Versioning
//!
//! `IPC_MAJOR` / `IPC_MINOR` follow the rules in spec 4.4.1:
//! - The service is backwards-compatible: a newer service accepts every
//!   `(major, minor)` ≤ its own.
//! - The SDK fails a call (with an actionable error) when it needs a verb
//!   the installed service doesn't carry.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PIPE_NAME: &str = r"\\.\pipe\mxc-service";

pub const IPC_MAJOR: u16 = 0;
pub const IPC_MINOR: u16 = 1;

/// Hard upper bound on a single framed message (request or response).
/// Bounded to reject malformed clients before allocating large buffers.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Service-side maximum rules per `AddPolicy` call.
/// Mirrors spec 4.3 "resource caps".
pub const MAX_RULES_PER_POLICY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleVerb {
    Allow,
    Block,
}

/// A single per-AC outbound rule.
///
/// `address` is an IPv4 or IPv6 literal in canonical text form, OR `None`
/// for "any". `prefix_length` of `Some(n)` makes it a CIDR; `None` means
/// host match. `port` of `None` means any port. `transport` of `Any`
/// means no protocol condition is emitted.
///
/// The service rejects rules that combine `address = None` with
/// `prefix_length = Some(_)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub verb: RuleVerb,
    pub transport: Transport,
    pub address: Option<String>,
    pub prefix_length: Option<u8>,
    pub port: Option<u16>,
}

/// A `PolicyId` identifies a batch of WFP filters installed by a single
/// successful `AddPolicy`. The SDK keeps it for the sandbox lifetime and
/// passes it back to `RemovePolicy` on teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid);

impl PolicyId {
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultPolicy {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPolicyRequest {
    /// AppContainer SID in SDDL string form (e.g. "S-1-15-2-...").
    pub ac_sid_sddl: String,
    /// Default posture for traffic that matches no explicit rule.
    pub default: DefaultPolicy,
    /// Explicit allow / block rules, evaluated against the default.
    pub rules: Vec<Rule>,
    /// PID of the suspended sandbox process. Used by the service for
    /// caller-supplied-handle bookkeeping; not used to scope the filter
    /// itself (the AC SID does that).
    ///
    /// In the production design (spec 3.2) the SDK marshals a duplicated
    /// HANDLE; the prototype just passes the PID for diagnostics.
    pub sandbox_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPolicyResponse {
    pub policy_id: PolicyId,
    /// Number of WFP filters the service actually installed.
    pub filters_installed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePolicyRequest {
    pub policy_id: PolicyId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePolicyResponse {
    /// Number of WFP filters removed. May be 0 if the policy was already
    /// reaped (e.g. service restart). Not an error.
    pub filters_removed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVersionResponse {
    pub service_version: String,
    pub ipc_major: u16,
    pub ipc_minor: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    GetVersion,
    AddPolicy(AddPolicyRequest),
    RemovePolicy(RemovePolicyRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Version(GetVersionResponse),
    AddPolicy(AddPolicyResponse),
    RemovePolicy(RemovePolicyResponse),
    Error(ServiceError),
}

/// Stable error surface. New variants append-only.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum ServiceError {
    #[error("invalid AppContainer SID: {0}")]
    InvalidAcSid(String),
    #[error("invalid rule (rule #{index}): {reason}")]
    InvalidRule { index: u32, reason: String },
    #[error("too many rules (max {max}, got {got})")]
    TooManyRules { max: u32, got: u32 },
    #[error("unknown policy id: {0}")]
    UnknownPolicy(PolicyId),
    #[error("WFP operation failed: {api} -> 0x{hresult:08x} ({message})")]
    WfpFailure {
        api: String,
        hresult: u32,
        message: String,
    },
    #[error("caller authentication failed: {0}")]
    Unauthorized(String),
    #[error("internal service error: {0}")]
    Internal(String),
    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("payload too large: {got} bytes (max {})", MAX_MESSAGE_BYTES)]
    TooLarge { got: usize },
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
}

/// Serialize `value` to CBOR and write the framed message
/// (4-byte LE length prefix + payload) to `w`.
pub fn write_frame<W, T>(w: &mut W, value: &T) -> Result<(), FrameError>
where
    W: std::io::Write,
    T: Serialize,
{
    let mut buf = Vec::with_capacity(256);
    ciborium::into_writer(value, &mut buf).map_err(|e| FrameError::Encode(e.to_string()))?;
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge { got: buf.len() });
    }
    let len_prefix = (buf.len() as u32).to_le_bytes();
    w.write_all(&len_prefix)?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Read a single framed message from `r` and decode it as `T`.
pub fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: std::io::Read,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge { got: len });
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    ciborium::from_reader(payload.as_slice()).map_err(|e| FrameError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_get_version() {
        let req = Request::GetVersion;
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let decoded: Request = read_frame(&mut cursor).unwrap();
        assert!(matches!(decoded, Request::GetVersion));
    }

    #[test]
    fn roundtrip_add_policy() {
        let req = Request::AddPolicy(AddPolicyRequest {
            ac_sid_sddl: "S-1-15-2-1-2-3-4-5-6-7".into(),
            default: DefaultPolicy::Block,
            rules: vec![Rule {
                verb: RuleVerb::Allow,
                transport: Transport::Tcp,
                address: Some("140.82.112.0".into()),
                prefix_length: Some(20),
                port: Some(443),
            }],
            sandbox_pid: 1234,
        });
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let decoded: Request = read_frame(&mut cursor).unwrap();
        match decoded {
            Request::AddPolicy(p) => {
                assert_eq!(p.ac_sid_sddl, "S-1-15-2-1-2-3-4-5-6-7");
                assert_eq!(p.rules.len(), 1);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn rejects_oversized_frame() {
        let huge = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let len_prefix = (huge.len() as u32).to_le_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&len_prefix);
        buf.extend_from_slice(&huge);
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_frame::<_, Request>(&mut cursor).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { .. }));
    }
}
