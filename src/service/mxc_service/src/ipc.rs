// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Named-pipe IPC server.
//!
//! Spec section 6.7 specifies LRPC. The prototype substitutes a named
//! pipe at `\\.\pipe\mxc-service` (review item #1 / #5). The pipe is
//! created with `PIPE_REJECT_REMOTE_CLIENTS` so it is local-only, and
//! a default ACL that allows the local Administrators group + the
//! caller's session — sufficient for VM-side smoke testing.
//!
//! For each connection we accept exactly one request/response pair
//! and then close. This keeps the prototype trivially correct under
//! concurrency: every request is isolated from every other.
//!
//! Caller PID/exe is logged for diagnostics only (review item #5):
//! we do **not** make trust decisions on it.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use mxc_service_proto::{
    read_frame, write_frame, AddPolicyRequest, AddPolicyResponse, GetVersionResponse,
    RemovePolicyRequest, RemovePolicyResponse, Request, Response, ServiceError, IPC_MAJOR,
    IPC_MINOR, MAX_RULES_PER_POLICY, PIPE_NAME,
};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::diag;
use crate::identity;
use crate::lifetime;
use crate::log;
use crate::wfp::WfpEngine;

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

pub struct Server {
    engine: Arc<WfpEngine>,
    shutdown: Arc<AtomicBool>,
}

impl Server {
    pub fn new(engine: Arc<WfpEngine>, shutdown: Arc<AtomicBool>) -> Self {
        Self { engine, shutdown }
    }

    pub fn run(&self) -> anyhow::Result<()> {
        log::info(&format!("listening on {PIPE_NAME}"));
        while !self.shutdown.load(Ordering::SeqCst) {
            match self.accept_one() {
                Ok(()) => {}
                Err(e) => log::error(&format!("connection failed: {e:#}")),
            }
        }
        log::info("shutdown signaled, exiting");
        Ok(())
    }

    fn accept_one(&self) -> anyhow::Result<()> {
        // Always pass FIRST_PIPE_INSTANCE so a local squatter that
        // raced us to the name causes a loud failure instead of being
        // silently joined as a second instance.
        let pipe = create_pipe().context("CreateNamedPipeW")?;

        // Block until a client connects (or shutdown wakes us via a
        // self-connect from `wake_accept_loop`).
        unsafe {
            // ConnectNamedPipe returns FALSE with ERROR_PIPE_CONNECTED
            // (535) if the client connected between Create and Connect.
            let _ = ConnectNamedPipe(HANDLE(pipe.as_raw_handle() as *mut c_void), None);
            let _ = GetLastError();
        }

        if self.shutdown.load(Ordering::SeqCst) {
            // Woken by wake_accept_loop; nothing to dispatch.
            unsafe {
                let _ = DisconnectNamedPipe(HANDLE(pipe.as_raw_handle() as *mut c_void));
            }
            return Ok(());
        }

        let caller_pid = client_pid(pipe.as_raw_handle());
        let caller_id = identity::capture(&pipe);
        log::info(&format!(
            "client connected pid={caller_pid} user_sid={}",
            caller_id.user_sid
        ));
        diag::emit(format!(
            "ipc: client connected pid={caller_pid} user_sid={}",
            caller_id.user_sid
        ));

        let request: Request = read_frame(&mut PipeIo(&pipe))
            .map_err(|e| anyhow::anyhow!("read_frame: {e}"))?;

        let response = self.dispatch(request, caller_pid);

        write_frame(&mut PipeIo(&pipe), &response)
            .map_err(|e| anyhow::anyhow!("write_frame: {e}"))?;

        unsafe {
            let _ = FlushFileBuffers(HANDLE(pipe.as_raw_handle() as *mut c_void));
            let _ = DisconnectNamedPipe(HANDLE(pipe.as_raw_handle() as *mut c_void));
        }
        Ok(())
    }

    fn dispatch(&self, req: Request, caller_pid: u32) -> Response {
        dispatch_request(req, &self.engine, caller_pid)
    }
}

/// Shared dispatcher reused by both the named-pipe path and the LRPC path.
pub fn dispatch_request(req: Request, engine: &Arc<WfpEngine>, caller_pid: u32) -> Response {
    match req {
        Request::GetVersion => Response::Version(GetVersionResponse {
            service_version: env!("CARGO_PKG_VERSION").into(),
            ipc_major: IPC_MAJOR,
            ipc_minor: IPC_MINOR,
        }),
        Request::AddPolicy(req) => handle_add_impl(engine, req, caller_pid),
        Request::RemovePolicy(req) => handle_remove_impl(engine, req, caller_pid),
    }
}

fn handle_add_impl(engine: &Arc<WfpEngine>, req: AddPolicyRequest, caller_pid: u32) -> Response {
    if req.rules.len() > MAX_RULES_PER_POLICY {
        return Response::Error(ServiceError::TooManyRules {
            max: MAX_RULES_PER_POLICY as u32,
            got: req.rules.len() as u32,
        });
    }
    log::info(&format!(
        "AddPolicy caller_pid={caller_pid} ac_sid={} default={:?} rules={} sandbox_pid={}",
        req.ac_sid_sddl,
        req.default,
        req.rules.len(),
        req.sandbox_pid,
    ));
    diag::emit(format!(
        "AddPolicy caller_pid={caller_pid} ac_sid={} default={:?} rules={} sandbox_pid={}",
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

fn handle_remove_impl(engine: &Arc<WfpEngine>, req: RemovePolicyRequest, caller_pid: u32) -> Response {
    log::info(&format!(
        "RemovePolicy caller_pid={caller_pid} policy_id={}",
        req.policy_id
    ));
    diag::emit(format!(
        "RemovePolicy caller_pid={caller_pid} policy_id={}",
        req.policy_id
    ));
    lifetime::cancel(req.policy_id);
    match engine.remove_policy(req.policy_id) {
        Ok(filters_removed) => {
            log::info(&format!("  -> filters_removed={filters_removed}"));
            diag::emit(format!("  -> filters_removed={filters_removed}"));
            Response::RemovePolicy(RemovePolicyResponse { filters_removed })
        }
        Err(e) => {
            log::warn(&format!("  -> error: {e}"));
            diag::emit(format!("  -> RemovePolicy error: {e}"));
            Response::Error(e)
        }
    }
}

/// std::io adapter over a `OwnedHandle` pointing at a named-pipe instance.
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

fn create_pipe() -> anyhow::Result<OwnedHandle> {
    let name = HSTRING::from(PIPE_NAME);
    let open_mode: FILE_FLAGS_AND_ATTRIBUTES =
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            open_mode,
            pipe_mode,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            Duration::from_secs(5).as_millis() as u32,
            None,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        anyhow::bail!("CreateNamedPipeW failed: Win32 {err:?}");
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0 as RawHandle) })
}

/// Wake a blocked `ConnectNamedPipe` by opening (and immediately
/// closing) a client connection. Called from the SCM control handler
/// after flipping the shutdown flag.
pub fn wake_accept_loop() {
    use windows::Win32::Foundation::GENERIC_READ;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_MODE, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES as FFA,
    };
    let name = HSTRING::from(PIPE_NAME);
    unsafe {
        let h = CreateFileW(
            PCWSTR(name.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FFA(0),
            None,
        );
        if let Ok(h) = h {
            let _ = CloseHandle(h);
        }
    }
}

fn client_pid(pipe: RawHandle) -> u32 {
    let mut pid: u32 = 0;
    unsafe {
        let _ = GetNamedPipeClientProcessId(HANDLE(pipe as *mut c_void), &mut pid);
    }
    pid
}

// Make sure unused imports don't trip CI.
#[allow(dead_code)]
fn _link_only() {
    let _ = ptr::null_mut::<u8>();
    let _ = CloseHandle;
}
