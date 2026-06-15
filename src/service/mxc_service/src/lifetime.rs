// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bind a `PolicyId`'s lifetime to a sandbox PID.
//!
//! Per spec §3.2 the production design uses an RPC-transferred process
//! handle so the broker can `WaitForSingleObject` the sandbox directly.
//! Until that handle-transfer is wired through the LRPC interface, we
//! receive the sandbox PID over the `AddPolicy` call and try two paths
//! in order:
//!
//! 1. `OpenProcess(SYNCHRONIZE)` + `WaitForSingleObject(INFINITE)` —
//!    works when the sandbox's default DACL grants LocalService
//!    SYNCHRONIZE. Cheap, event-driven.
//! 2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` +
//!    `GetExitCodeProcess` poll at 500 ms — fallback when SYNCHRONIZE
//!    is denied (the common case for restricted LocalService against
//!    Administrator-launched sandboxes). `PROCESS_QUERY_LIMITED_INFORMATION`
//!    is granted to authenticated callers by the default process DACL.
//!
//! Either way, when the sandbox terminates we call
//! `PolicyManager::remove_policy(policy_id)` and emit a diag line. The
//! explicit `RemovePolicy` IPC also calls `cancel` so we don't double-
//! remove.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use mxc_service_proto::PolicyId;
use windows::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, WaitForSingleObject, INFINITE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use crate::diag;
use crate::log;
use mxc_wfp::PolicyManager;

struct Watcher {
    cancel: Arc<AtomicBool>,
}

static WATCHERS: OnceLock<Mutex<HashMap<PolicyId, Watcher>>> = OnceLock::new();

fn watchers() -> &'static Mutex<HashMap<PolicyId, Watcher>> {
    WATCHERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Spawn a background thread that calls `engine.remove_policy` when
/// `sandbox_pid` terminates. No-op if `sandbox_pid == 0` (caller didn't
/// supply one). Idempotent per `policy_id`.
pub fn track(engine: Arc<PolicyManager>, policy_id: PolicyId, sandbox_pid: u32) {
    if sandbox_pid == 0 {
        return;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut map = watchers().lock().unwrap();
        if map.contains_key(&policy_id) {
            return;
        }
        map.insert(
            policy_id,
            Watcher {
                cancel: cancel.clone(),
            },
        );
    }
    thread::Builder::new()
        .name(format!("policy-watch-{policy_id}"))
        .spawn(move || run_watch(engine, policy_id, sandbox_pid, cancel))
        .ok();
}

/// Stop watching a policy without removing the WFP filters. Called by
/// the IPC `RemovePolicy` handler so the watcher doesn't race with the
/// explicit cleanup. Returns true iff a tracked watcher was found and
/// cancelled — RemovePolicy uses this to distinguish "racing with our
/// own auto-cleanup" (false) from "we cancelled a live watcher" (true).
pub fn cancel(policy_id: PolicyId) -> bool {
    if let Some(w) = watchers().lock().unwrap().remove(&policy_id) {
        w.cancel.store(true, Ordering::SeqCst);
        true
    } else {
        false
    }
}

fn run_watch(engine: Arc<PolicyManager>, policy_id: PolicyId, pid: u32, cancel: Arc<AtomicBool>) {
    let exited = match wait_event_driven(pid, &cancel) {
        WaitOutcome::Exited => true,
        WaitOutcome::Cancelled => false,
        WaitOutcome::AccessDenied => wait_polling(pid, &cancel),
        WaitOutcome::OpenFailed(code) => {
            log::warn(&format!(
                "lifetime watcher: OpenProcess({pid}) failed: code={code} \
                 — policy {policy_id} will only clean up on explicit RemovePolicy"
            ));
            diag::emit(format!(
                "lifetime: OpenProcess({pid}) failed code={code} for policy {policy_id} \
                 (no auto-cleanup on sandbox crash)"
            ));
            // Don't remove ourselves: the explicit RemovePolicy path
            // is the only cleanup, but the watcher is no longer useful.
            watchers().lock().unwrap().remove(&policy_id);
            return;
        }
    };

    // Always remove the watcher entry; if we exited because of
    // cancellation we never call remove_policy (the IPC handler did).
    watchers().lock().unwrap().remove(&policy_id);

    if !exited {
        return;
    }

    diag::emit(format!(
        "lifetime: sandbox pid={pid} exited → auto-RemovePolicy {policy_id}"
    ));
    match engine.remove_policy(policy_id) {
        Ok(removed) => {
            log::info(&format!(
                "auto-cleanup: policy {policy_id} removed (filters_removed={removed})"
            ));
            diag::emit(format!(
                "lifetime: auto-RemovePolicy {policy_id} -> filters_removed={removed}"
            ));
        }
        Err(e) => {
            log::warn(&format!(
                "auto-cleanup: policy {policy_id} remove failed: {e}"
            ));
            diag::emit(format!(
                "lifetime: auto-RemovePolicy {policy_id} failed: {e}"
            ));
        }
    }
}

enum WaitOutcome {
    Exited,
    Cancelled,
    AccessDenied,
    OpenFailed(u32),
}

fn wait_event_driven(pid: u32, cancel: &Arc<AtomicBool>) -> WaitOutcome {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) };
    let h = match handle {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) => return WaitOutcome::AccessDenied,
        Err(e) => {
            let code = e.code().0 as u32;
            // 5 = ERROR_ACCESS_DENIED. windows-rs may return either the raw
            // Win32 code or HRESULT_FROM_WIN32(5) = 0x80070005.
            if code == 5 || code == 0x80070005 {
                return WaitOutcome::AccessDenied;
            }
            return WaitOutcome::OpenFailed(code);
        }
    };

    // Wait in 250 ms slices so cancellation is responsive without a separate event.
    loop {
        if cancel.load(Ordering::SeqCst) {
            unsafe { let _ = CloseHandle(h); }
            return WaitOutcome::Cancelled;
        }
        let r = unsafe { WaitForSingleObject(h, 250) };
        if r == WAIT_OBJECT_0 {
            unsafe { let _ = CloseHandle(h); }
            return WaitOutcome::Exited;
        }
        // WAIT_TIMEOUT (258) → loop. Anything else (failed) → treat as exit
        // so we don't leak the watcher; better safe than sorry.
        if r.0 != 258 {
            unsafe { let _ = CloseHandle(h); }
            return WaitOutcome::Exited;
        }
    }
}

fn wait_polling(pid: u32, cancel: &Arc<AtomicBool>) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let h = match handle {
        Ok(h) if !h.is_invalid() => h,
        _ => {
            // PID gone before we could even open it → treat as exited.
            return true;
        }
    };
    let mut code: u32 = 0;
    loop {
        if cancel.load(Ordering::SeqCst) {
            unsafe { let _ = CloseHandle(h); }
            return false;
        }
        let ok = unsafe { GetExitCodeProcess(h, &mut code).is_ok() };
        if !ok || code != STILL_ACTIVE.0 as u32 {
            unsafe { let _ = CloseHandle(h); }
            return true;
        }
        // Use a slightly longer interval since we're polling. 500 ms is
        // imperceptible for cleanup but gentle on the CPU.
        thread::sleep(Duration::from_millis(500));
    }
}

// Keep the prelude tidy.
#[allow(dead_code)]
fn _link_only() {
    let _: HANDLE = HANDLE(std::ptr::null_mut());
    let _ = INFINITE;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_is_noop_for_unknown_policy() {
        let id = PolicyId::new_random();
        cancel(id);
    }
}
