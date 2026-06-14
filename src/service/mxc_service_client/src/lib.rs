// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Thin client over the `mxc-service` named-pipe transport.
//!
//! This crate is consumed both by the `mxc-net.exe` CLI (for VM-side
//! smoke testing) and — eventually — by the MXC orchestrator's
//! AppContainer backend in place of the in-process WFP rule code in
//! `appcontainer_common::network_manager`.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::time::Duration;

use mxc_service_proto::{
    read_frame, write_frame, AddPolicyRequest, DefaultPolicy, GetVersionResponse, PolicyId,
    RemovePolicyRequest, Request, Response, Rule, ServiceError, PIPE_NAME,
};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("could not open pipe {PIPE_NAME}: {0}")]
    Open(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("framing: {0}")]
    Frame(String),
    #[error("service returned error: {0}")]
    Service(#[from] ServiceError),
    #[error("unexpected response variant: {0}")]
    Unexpected(String),
}

pub struct Client {
    transport: Transport,
}

enum Transport {
    Rpc(mxc_service_rpc::client::Client),
    Pipe(OwnedHandle),
}

impl Client {
    /// Try LRPC first (production transport per spec §6.7); fall back
    /// to named pipe if LRPC isn't available (e.g., service was built
    /// without the RPC listener registered).
    pub fn connect() -> Result<Self, ClientError> {
        match mxc_service_rpc::client::Client::connect() {
            Ok(c) => Ok(Self { transport: Transport::Rpc(c) }),
            Err(_) => Self::connect_pipe(Duration::from_secs(5)),
        }
    }

    pub fn connect_with_timeout(timeout: Duration) -> Result<Self, ClientError> {
        match mxc_service_rpc::client::Client::connect() {
            Ok(c) => Ok(Self { transport: Transport::Rpc(c) }),
            Err(_) => Self::connect_pipe(timeout),
        }
    }

    /// Force the named-pipe transport (used by `mxc-net --pipe` for
    /// transport-comparison diagnostics).
    pub fn connect_pipe(timeout: Duration) -> Result<Self, ClientError> {
        let name = HSTRING::from(PIPE_NAME);
        unsafe {
            let _ = WaitNamedPipeW(PCWSTR(name.as_ptr()), timeout.as_millis() as u32);
        }
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };
        let handle = handle.map_err(|e| {
            let err = unsafe { GetLastError() };
            ClientError::Open(format!("CreateFileW: {e} ({err:?})"))
        })?;
        Ok(Self {
            transport: Transport::Pipe(unsafe { OwnedHandle::from_raw_handle(handle.0 as RawHandle) }),
        })
    }

    pub fn get_version(mut self) -> Result<GetVersionResponse, ClientError> {
        let resp = self.request(Request::GetVersion)?;
        match resp {
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
        match &mut self.transport {
            Transport::Rpc(c) => c
                .call(&req)
                .map_err(|e| ClientError::Frame(format!("lrpc: {e:#}"))),
            Transport::Pipe(pipe) => {
                let mut io = PipeIo(pipe);
                write_frame(&mut io, &req).map_err(|e| ClientError::Frame(e.to_string()))?;
                read_frame(&mut io).map_err(|e| ClientError::Frame(e.to_string()))
            }
        }
    }
}

struct PipeIo<'a>(&'a OwnedHandle);

impl<'a> std::io::Read for PipeIo<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut got: u32 = 0;
        unsafe {
            ReadFile(
                HANDLE(self.0.as_raw_handle() as *mut c_void),
                Some(buf),
                Some(&mut got),
                None,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
        }
        Ok(got as usize)
    }
}

impl<'a> std::io::Write for PipeIo<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written: u32 = 0;
        unsafe {
            WriteFile(
                HANDLE(self.0.as_raw_handle() as *mut c_void),
                Some(buf),
                Some(&mut written),
                None,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
        }
        Ok(written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
