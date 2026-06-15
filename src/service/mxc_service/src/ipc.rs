// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LRPC request dispatcher.
//!
//! Spec §6.7 transport is LRPC. The MIDL-generated `RpcCall` stub in
//! `mxc_service_rpc_server` decodes a CBOR-framed `Request`, hands it
//! to [`dispatch_request`], and serializes the resulting `Response`
//! back to the caller. Caller identity is captured here via
//! [`identity::capture_lrpc`] (logged only, not used for trust).

use std::sync::Arc;

use mxc_service_proto::{
    AddPolicyRequest, AddPolicyResponse, GetVersionResponse, RemovePolicyRequest,
    RemovePolicyResponse, Request, Response, ServiceError, IPC_MAJOR, IPC_MINOR,
    MAX_RULES_PER_POLICY,
};

use crate::diag;
use crate::identity;
use crate::lifetime;
use crate::log;
use mxc_wfp::PolicyManager;

/// Dispatcher for an LRPC call. The MIDL stub already decoded `req`
/// from CBOR; we route it to the right `PolicyManager` operation and
/// emit caller identity + diag for the call.
pub fn dispatch_request(req: Request, engine: &Arc<PolicyManager>) -> Response {
    let caller = identity::capture_lrpc();
    diag::emit(format!("ipc: call from user_sid={}", caller.user_sid));
    match req {
        Request::GetVersion => Response::Version(GetVersionResponse {
            service_version: env!("CARGO_PKG_VERSION").into(),
            ipc_major: IPC_MAJOR,
            ipc_minor: IPC_MINOR,
        }),
        Request::AddPolicy(req) => handle_add_impl(engine, req, &caller.user_sid),
        Request::RemovePolicy(req) => handle_remove_impl(engine, req, &caller.user_sid),
    }
}

fn handle_add_impl(engine: &Arc<PolicyManager>, req: AddPolicyRequest, caller_sid: &str) -> Response {
    if req.rules.len() > MAX_RULES_PER_POLICY {
        return Response::Error(ServiceError::TooManyRules {
            max: MAX_RULES_PER_POLICY as u32,
            got: req.rules.len() as u32,
        });
    }
    log::info(&format!(
        "AddPolicy caller_sid={caller_sid} ac_sid={} default={:?} rules={} sandbox_pid={}",
        req.ac_sid_sddl,
        req.default,
        req.rules.len(),
        req.sandbox_pid,
    ));
    diag::emit(format!(
        "AddPolicy caller_sid={caller_sid} ac_sid={} default={:?} rules={} sandbox_pid={}",
        req.ac_sid_sddl,
        req.default,
        req.rules.len(),
        req.sandbox_pid,
    ));
    for (i, r) in req.rules.iter().enumerate() {
        diag::emit(format!("  rule[{i}] = {r:?}"));
    }
    match engine.add_policy(&req.ac_sid_sddl, req.default, &req.rules) {
        Ok((policy_id, filters_installed)) => {
            log::info(&format!(
                "  -> policy_id={policy_id} filters_installed={filters_installed}"
            ));
            diag::emit(format!(
                "  -> policy_id={policy_id} filters_installed={filters_installed}"
            ));
            lifetime::track(engine.clone(), policy_id, req.sandbox_pid);
            Response::AddPolicy(AddPolicyResponse {
                policy_id,
                filters_installed,
            })
        }
        Err(e) => {
            log::warn(&format!("  -> error: {e}"));
            diag::emit(format!("  -> AddPolicy error: {e}"));
            Response::Error(e)
        }
    }
}

fn handle_remove_impl(
    engine: &Arc<PolicyManager>,
    req: RemovePolicyRequest,
    caller_sid: &str,
) -> Response {
    log::info(&format!(
        "RemovePolicy caller_sid={caller_sid} policy_id={}",
        req.policy_id
    ));
    diag::emit(format!(
        "RemovePolicy caller_sid={caller_sid} policy_id={}",
        req.policy_id
    ));
    let was_tracked = lifetime::cancel(req.policy_id);
    match engine.remove_policy(req.policy_id) {
        Ok(filters_removed) => {
            log::info(&format!("  -> filters_removed={filters_removed}"));
            diag::emit(format!("  -> filters_removed={filters_removed}"));
            Response::RemovePolicy(RemovePolicyResponse { filters_removed })
        }
        Err(ServiceError::UnknownPolicy(_)) if !was_tracked => {
            diag::emit("  -> already removed (auto-cleanup raced explicit call)");
            Response::RemovePolicy(RemovePolicyResponse { filters_removed: 0 })
        }
        Err(e) => {
            log::warn(&format!("  -> error: {e}"));
            diag::emit(format!("  -> RemovePolicy error: {e}"));
            Response::Error(e)
        }
    }
}
