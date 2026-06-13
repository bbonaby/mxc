// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal structured logger for `mxc-service`.
//!
//! Two backends:
//! - `init_console()` — stderr writer (used in `--console` mode).
//! - `init_eventlog()` — stub: prefixes lines with `[mxc-service]`
//!   and writes to stderr. Real eventlog integration is future work;
//!   for the prototype, when the service is launched via `sc.exe`
//!   we redirect stderr to a file from the MSI launcher.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

static EVENTLOG_MODE: AtomicBool = AtomicBool::new(false);
static INIT: OnceLock<()> = OnceLock::new();

pub fn init_console() {
    INIT.get_or_init(|| {});
    EVENTLOG_MODE.store(false, Ordering::SeqCst);
}

pub fn init_eventlog() {
    INIT.get_or_init(|| {});
    EVENTLOG_MODE.store(true, Ordering::SeqCst);
}

fn emit(level: &str, msg: &str) {
    let prefix = if EVENTLOG_MODE.load(Ordering::SeqCst) {
        "[mxc-service]"
    } else {
        ""
    };
    let ts = chrono_like_now();
    eprintln!("{ts} {prefix}{level} {msg}");
}

pub fn info(msg: &str) {
    emit("INFO ", msg);
}

pub fn warn(msg: &str) {
    emit("WARN ", msg);
}

pub fn error(msg: &str) {
    emit("ERROR", msg);
}

/// Cheap ISO-ish timestamp without pulling in `chrono`.
fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let ms = now.subsec_millis();
    format!("{secs}.{ms:03}")
}
