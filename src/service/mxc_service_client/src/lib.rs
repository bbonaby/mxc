// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Thin LRPC client for `mxc-service` (spec §6.7).
//!
//! This crate is consumed by the `mxc-net.exe` CLI (for VM-side smoke
//! testing) and by the MXC AppContainer backend
//! (`appcontainer_common::broker_network`) to install per-host WFP
//! policy via the elevated broker.

use mxc_service_proto::{
    AddPolicyRequest, DefaultPolicy, GetVersionResponse, PolicyId, RemovePolicyRequest, Request,
    Response, Rule, ServiceError,
};
use std::time::Duration;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
};

const SERVICE_NAME: &str = "mxc-service";

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(
        "mxc-service is not installed on this machine (and the LRPC \
         endpoint was unreachable: {raw}). \
         The MXC SDK requires the `mxc-service` Windows service to enforce \
         per-host network policy. Ask the application that bundles MXC \
         (or your IT admin) to install the MXC runtime MSI."
    )]
    ServiceNotInstalled { raw: String },
    #[error(
        "mxc-service is installed but not running (state={state:?}, lrpc: {raw}). \
         Start it with `sc start mxc-service` or via Services.msc."
    )]
    ServiceNotRunning { state: u32, raw: String },
    #[error("lrpc: {0}")]
    Lrpc(String),
    #[error("service returned error: {0}")]
    Service(#[from] ServiceError),
    #[error("unexpected response variant: {0}")]
    Unexpected(String),
}

/// SCM status of `mxc-service`. Used to turn a generic LRPC
/// "endpoint not found" into an actionable error for end users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceInstallStatus {
    NotInstalled,
    Stopped,
    StartPending,
    Running,
    Other(u32),
}

pub fn service_install_status() -> ServiceInstallStatus {
    unsafe {
        let scm = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) {
            Ok(h) => h,
            Err(_) => return ServiceInstallStatus::NotInstalled,
        };
        let name = HSTRING::from(SERVICE_NAME);
        let svc = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                return ServiceInstallStatus::NotInstalled;
            }
        };
        let mut status = SERVICE_STATUS::default();
        let ok = QueryServiceStatus(svc, &mut status).is_ok();
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        if !ok {
            return ServiceInstallStatus::Other(0);
        }
        match status.dwCurrentState {
            s if s == SERVICE_RUNNING => ServiceInstallStatus::Running,
            s if s == SERVICE_START_PENDING => ServiceInstallStatus::StartPending,
            s if s.0 == 1 => ServiceInstallStatus::Stopped,
            s => ServiceInstallStatus::Other(s.0),
        }
    }
}

/// Map an LRPC connect failure to an actionable error using SCM.
/// Always carries the raw LRPC error so callers can distinguish
/// install-state issues from auth/binding failures.
fn classify_connect_failure(raw: String) -> ClientError {
    match service_install_status() {
        ServiceInstallStatus::NotInstalled => ClientError::ServiceNotInstalled { raw },
        ServiceInstallStatus::Stopped => ClientError::ServiceNotRunning { state: 1, raw },
        ServiceInstallStatus::StartPending => ClientError::ServiceNotRunning { state: 2, raw },
        ServiceInstallStatus::Other(s) => ClientError::ServiceNotRunning { state: s, raw },
        ServiceInstallStatus::Running => ClientError::Lrpc(raw),
    }
}

pub struct Client {
    inner: mxc_service_rpc_client::Client,
}

impl Client {
    /// Connect to the local `mxc-service` LRPC endpoint. On failure,
    /// consult the Service Control Manager to return one of
    /// `ServiceNotInstalled` / `ServiceNotRunning` / `Lrpc(reason)`.
    pub fn connect() -> Result<Self, ClientError> {
        mxc_service_rpc_client::Client::connect()
            .map(|inner| Self { inner })
            .map_err(|e| classify_connect_failure(format!("{e:#}")))
    }

    /// Kept for API compatibility; LRPC binding is synchronous and
    /// connects immediately, so `timeout` is currently unused.
    pub fn connect_with_timeout(_timeout: Duration) -> Result<Self, ClientError> {
        Self::connect()
    }

    pub fn get_version(mut self) -> Result<GetVersionResponse, ClientError> {
        match self.request(Request::GetVersion)? {
            Response::Version(v) => Ok(v),
            Response::Error(e) => Err(e.into()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    pub fn add_policy(
        mut self,
        ac_sid_sddl: impl Into<String>,
        default: DefaultPolicy,
        rules: Vec<Rule>,
        sandbox_pid: u32,
    ) -> Result<(PolicyId, u32), ClientError> {
        let req = Request::AddPolicy(AddPolicyRequest {
            ac_sid_sddl: ac_sid_sddl.into(),
            default,
            rules,
            sandbox_pid,
        });
        match self.request(req)? {
            Response::AddPolicy(r) => Ok((r.policy_id, r.filters_installed)),
            Response::Error(e) => Err(e.into()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    pub fn remove_policy(mut self, policy_id: PolicyId) -> Result<u32, ClientError> {
        match self.request(Request::RemovePolicy(RemovePolicyRequest { policy_id }))? {
            Response::RemovePolicy(r) => Ok(r.filters_removed),
            Response::Error(e) => Err(e.into()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    fn request(&mut self, req: Request) -> Result<Response, ClientError> {
        self.inner
            .call(&req)
            .map_err(|e| ClientError::Lrpc(format!("{e:#}")))
    }
}
