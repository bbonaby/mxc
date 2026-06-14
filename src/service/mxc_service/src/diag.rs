// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Diagnostic-pipe client for mxc-service.
//!
//! Discovers any active `\\.\pipe\mxc-diagnostics-*` server (created by
//! `mxc-diagnostic-console.exe` for the interactive user) and pushes
//! `{"msg":"..."}\n` framed messages so broker activity shows up in the
//! same console as wxc-exec output.
//!
//! Connection failure is non-fatal: the broker keeps running, retries
//! discovery every second, and drops messages while disconnected.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    FindClose, FindFirstFileW, FindNextFileW, FILE_FLAG_OVERLAPPED, WIN32_FIND_DATAW,
};

#[allow(dead_code)]
const PIPE_PREFIX: &str = r"\\.\pipe\mxc-diagnostics";
const QUEUE_CAP: usize = 256;

static QUEUE: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn queue() -> &'static Mutex<VecDeque<String>> {
    QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(QUEUE_CAP)))
}

/// Start the background diag-pipe writer thread. Idempotent.
pub fn init() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let _ = queue();
        thread::Builder::new()
            .name("mxc-svc-diag".to_string())
            .spawn(writer_thread)
            .ok();
    });
}

/// Enqueue a diagnostic line. Silently drops if the queue is full or
/// no `init()` has been called yet.
pub fn emit(line: impl Into<String>) {
    let line = line.into();
    if let Ok(mut q) = queue().lock() {
        if q.len() >= QUEUE_CAP {
            q.pop_front();
        }
        q.push_back(line);
    }
}

fn writer_thread() {
    let mut backoff = Duration::from_millis(500);
    loop {
        match discover_and_connect() {
            Some(mut file) => {
                backoff = Duration::from_millis(500);
                emit_loop(&mut file);
            }
            None => {
                thread::sleep(backoff);
                if backoff < Duration::from_secs(5) {
                    backoff = backoff.saturating_mul(2);
                }
            }
        }
    }
}

fn emit_loop(file: &mut std::fs::File) {
    loop {
        let msg = {
            let mut q = match queue().lock() {
                Ok(q) => q,
                Err(_) => return,
            };
            q.pop_front()
        };
        match msg {
            Some(line) => {
                let json = format!("{}\n", json_envelope(&line));
                if file.write_all(json.as_bytes()).is_err() {
                    return; // pipe broken; reconnect
                }
                let _ = file.flush();
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn json_envelope(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    out.push_str("{\"msg\":\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push_str("\"}");
    out
}

fn discover_and_connect() -> Option<std::fs::File> {
    let names = enumerate_pipes()?;
    for name in names {
        if let Some(file) = try_open(&name) {
            return Some(file);
        }
    }
    None
}

fn enumerate_pipes() -> Option<Vec<String>> {
    // FindFirstFile on `\\.\pipe\mxc-diagnostics*` returns just the
    // leaf name (no `\\.\pipe\` prefix) -- we reattach.
    let pattern: Vec<u16> = format!(r"\\.\pipe\mxc-diagnostics*")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut data = WIN32_FIND_DATAW::default();
    let h = unsafe { FindFirstFileW(PCWSTR(pattern.as_ptr()), &mut data) };
    let h = match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        _ => return None,
    };
    let mut out = Vec::new();
    loop {
        let name = wide_to_string(&data.cFileName);
        if !name.is_empty() {
            out.push(format!(r"\\.\pipe\{}", name));
        }
        match unsafe { FindNextFileW(h, &mut data) } {
            Ok(()) => continue,
            Err(_) => {
                let last = unsafe { GetLastError() };
                if last == ERROR_NO_MORE_FILES || last == ERROR_FILE_NOT_FOUND {
                    break;
                }
                break;
            }
        }
    }
    unsafe { let _ = FindClose(h); }
    if out.is_empty() { None } else { Some(out) }
}

fn try_open(name: &str) -> Option<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .read(false)
        .custom_flags(FILE_FLAG_OVERLAPPED.0)
        .open(PathBuf::from(name))
        .ok()
        .and_then(|f| {
            // Drop overlapped flag for simple sync writes by reopening
            // -- but our writes are short, so blocking is fine.
            Some(f)
        })
        .or_else(|| OpenOptions::new().write(true).open(PathBuf::from(name)).ok())
}

fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
        .to_string_lossy()
        .into_owned()
}

// Silence unused warnings on non-Windows builds (this crate is win-only,
// but keep the imports cleanly used).
#[allow(dead_code)]
fn _unused() {
    let _ = HANDLE::default();
    let _ = CloseHandle;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_envelope_escapes_quotes_and_newlines() {
        let env = json_envelope("hello \"world\"\nline 2");
        assert_eq!(env, r#"{"msg":"hello \"world\"\nline 2"}"#);
    }

    #[test]
    fn json_envelope_escapes_control_chars() {
        let env = json_envelope("a\x01b");
        assert_eq!(env, r#"{"msg":"a\u0001b"}"#);
    }

    #[test]
    fn emit_does_not_panic_without_init() {
        // emit() before init() should silently succeed (no writer thread yet).
        emit("test message without init");
    }
}
