// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-service` — elevated broker that installs WFP filters for the
//! MXC SDK. See spec sections 4 + 6.6 for the architectural contract.
//!
//! Runs in two modes:
//!
//! - `--console`  — foreground, logs to stdout. For dev/VM debugging.
//! - (no args)    — SCM-controlled Windows service entry point. The
//!                  MSI registers this binary under the service name
//!                  `mxc-service`. SCM calls `service_main` via the
//!                  dispatcher set up below.

use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use clap::Parser;

mod diag;
mod grant;
mod ipc;
mod log;
mod wfp;

use crate::wfp::WfpEngine;

const SERVICE_NAME: &str = "mxc-service";

#[derive(Debug, Parser)]
#[command(name = SERVICE_NAME, about = "MXC Tier 2 elevated WFP broker")]
struct Cli {
    /// Run in the foreground instead of as a Windows service.
    /// Useful for VM-side debugging — service stdout is normally
    /// invisible.
    #[arg(long)]
    console: bool,

    /// Install-time hook (invoked by the MSI custom action while
    /// running as `LocalSystem`): write an inheritable ACE on the BFE
    /// engine SD granting the `NT SERVICE\mxc-service` per-service SID
    /// the WFP rights it needs. See `grant.rs` and spec §4.1.
    #[arg(long, hide = true, conflicts_with_all = ["console", "uninstall_grant"])]
    install_grant: bool,

    /// Uninstall-time hook: best-effort revoke the engine ACE.
    #[arg(long, hide = true, conflicts_with_all = ["console", "install_grant"])]
    uninstall_grant: bool,
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.install_grant {
        log::init_console();
        log::info("install-grant: granting engine ACE to NT SERVICE\\mxc-service");
        return grant::install_grant();
    }
    if cli.uninstall_grant {
        log::init_console();
        log::info("uninstall-grant: revoking engine ACE");
        return grant::uninstall_grant();
    }
    if cli.console {
        log::init_console();
        log::info("starting in --console mode");
        run_console()
    } else {
        // Hand off to SCM dispatcher.
        service::run()
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("mxc-service only builds on Windows");
    std::process::exit(1);
}

fn run_console() -> anyhow::Result<()> {
    diag::init();
    diag::emit(format!(
        "mxc-service starting (--console, pid={})",
        std::process::id()
    ));
    let engine = Arc::new(WfpEngine::open().context("WfpEngine::open")?);
    let shutdown = Arc::new(AtomicBool::new(false));

    let server = ipc::Server::new(Arc::clone(&engine), Arc::clone(&shutdown));
    let shutdown_for_ctrlc = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        log::info("ctrl-c received, shutting down");
        shutdown_for_ctrlc.store(true, Ordering::SeqCst);
        ipc::wake_accept_loop();
    })
    .ok();

    server.run()
}

// ---------------------------------------------------------------------------
// SCM service entry points
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    use super::{diag, ipc, log, WfpEngine, SERVICE_NAME};

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> anyhow::Result<()> {
        log::init_eventlog();
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|e| anyhow::anyhow!("service_dispatcher::start failed: {e}"))
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            log::error(&format!("service exited with error: {e:#}"));
        }
    }

    fn run_service() -> anyhow::Result<()> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_handler = Arc::clone(&shutdown);

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    shutdown_for_handler.store(true, Ordering::SeqCst);
                    ipc::wake_accept_loop();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .map_err(|e| anyhow::anyhow!("register status handler: {e}"))?;

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StartPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(5),
                process_id: None,
            })
            .ok();

        let engine = Arc::new(WfpEngine::open()?);
        let server = ipc::Server::new(Arc::clone(&engine), Arc::clone(&shutdown));

        diag::init();
        diag::emit(format!(
            "mxc-service running under SCM (pid={})",
            std::process::id()
        ));

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .ok();

        log::info("mxc-service running");
        let res = server.run();

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .ok();

        res
    }
}

// Silence unused-import warning under cross-builds.
#[allow(dead_code)]
fn _link_only(_: OsString) {}
