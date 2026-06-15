# MXC service: crate architecture

> Audience: anyone touching `src/service/*`. Read this before adding a
> new platform call or a new "thing the service does on Windows".

## TL;DR

```
┌──────────────────────────────────────────────────────────────────┐
│ mxc_service  (bin)                                               │
│   - SCM main / --console / --install-grant / --uninstall-grant   │
│   - LRPC dispatch (ipc.rs)                                       │
│   - sandbox-pid lifetime watcher (lifetime.rs)                   │
│   - caller-identity capture (identity.rs)                        │
│   - diag log (diag.rs)                                           │
│   No `unsafe` for the WFP path. Other modules still hold local   │
│   unsafe (process handles, identity); see "Future work".         │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ depends on
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ mxc_wfp  (lib)            ← "MXC-flavoured safe layer"           │
│   engine.rs   Engine           – RAII handle on a BFE session    │
│   grant.rs    install_grant    – engine-SD ACE (one-time)        │
│                uninstall_grant                                   │
│                ServiceSid       – SHA-1 per-service SID          │
│   policy.rs   PolicyManager    – per-sandbox add/remove + rollback│
│                OwnedSid         – RAII over ConvertStringSidToSidW│
│                validate_rule, pick_layers, prefix_to_v4_mask, …  │
│   Has unsafe { mxc_wfp_sys::… } call sites only — each one line, │
│   each preceded by a `// SAFETY:` comment.                       │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ depends on
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ mxc_wfp_sys  (lib)        ← "the entire unsafe surface"          │
│   lib.rs   engine_open / engine_open_local / engine_close        │
│            engine_get_security_info / engine_set_dacl            │
│            provider_add / sublayer_add                           │
│            filter_add / filter_delete_by_id                      │
│            convert_string_sid_to_sid / local_free                │
│            set_entries_in_acl                                    │
│            LocalAllocOwned (RAII)                                │
│   Every fn is `unsafe` and carries a # Safety clause. Nothing    │
│   interprets results; raw u32 status / raw pointers come out.    │
│   Re-exports the `windows::*` types its callers need so the      │
│   safe crate doesn't depend on `windows` directly for those.     │
└──────────────────────────────────────────────────────────────────┘
```

## Why three layers?

1. **All `extern "system"` calls live in one crate.** When auditing
   FFI correctness, you read one file (`mxc_wfp_sys/src/lib.rs`,
   ~270 lines). Future security reviewers don't have to chase unsafe
   blocks across the service binary.

2. **`mxc_wfp` is "MXC-flavoured safe API".** It still has `unsafe`
   blocks (one per FFI call), but each is a single line wrapping a
   `mxc_wfp_sys` fn whose safety contract we satisfy inline. The
   public API (`Engine`, `PolicyManager`, `install_grant`,
   `uninstall_grant`) is **fully safe**: a future Rust author can use
   it without `unsafe` and without reading the FFI shim.

3. **`mxc_service` is the orchestrator.** No `unsafe` for the WFP
   path; just `mxc_wfp::PolicyManager::open()` and method calls.
   This means service-binary code reviews don't need a WFP expert
   in the loop unless `mxc_wfp` itself is changing.

## What goes where

| Concern                                    | Crate          |
|--------------------------------------------|----------------|
| `FwpmEngineOpen0` and friends              | `mxc_wfp_sys`  |
| `ConvertStringSidToSidW`, `SetEntriesInAclW`, `LocalFree` | `mxc_wfp_sys` |
| `EXPLICIT_ACCESS_W` / `TRUSTEE_W` struct construction     | `mxc_wfp`    |
| `FWPM_FILTER0` + condition-array construction             | `mxc_wfp`    |
| Per-sandbox `HashMap<PolicyId, Vec<u64>>` + rollback      | `mxc_wfp`    |
| Per-service SID derivation (SHA-1 over uppercase name)    | `mxc_wfp`    |
| Engine-SD ACE install/uninstall                            | `mxc_wfp`    |
| SCM dispatch, CLI flags, ctrl-c handling                   | `mxc_service`|
| LRPC server, caller-identity logging                       | `mxc_service`|
| Sandbox-pid lifetime watcher                               | `mxc_service`|

## Constants ownership

Stable identity GUIDs live at `mxc_wfp::{MXC_PROVIDER_GUID, MXC_SUBLAYER_GUID}`.
Sublayer weight at `MXC_SUBLAYER_WEIGHT`. Changing these breaks
upgrade paths (existing filters would be orphaned).

## Error types

- `mxc_wfp_sys` returns raw `u32` Win32 status codes (no interpretation).
- `mxc_wfp` wraps failures in `mxc_service_proto::ServiceError`
  (`WfpFailure { api, hresult, message }`, `InvalidRule`,
  `InvalidAcSid`, `UnknownPolicy`, `ResourceExhausted`,
  `TooManyRules`). That's the same type the RPC surface already uses,
  so `mxc_service` doesn't have to translate.
- Install/uninstall grant code uses the same `ServiceError`; `main.rs`
  converts to `anyhow::Error` at the binary boundary.

## Tests

| Crate          | Count | What                                            |
|----------------|-------|-------------------------------------------------|
| `mxc_wfp_sys`  | 0     | Pure FFI shim — no testable logic.              |
| `mxc_wfp`      | 10    | SID derivation, rule validation, layer-pick, mask math, OwnedSid SDDL guard. |
| `mxc_service`  | 4     | Diag JSON escaping, lifetime cancel no-op.      |

Anything that calls into BFE itself (real `FwpmEngineOpen0`, real
filter install) is **integration tested on the VM**, not in unit
tests, because BFE is not mockable in-process.

## Future work

This refactor extracted **WFP**. Three other unsafe surfaces inside
`mxc_service` would benefit from the same sys/safe split if we keep
extending the prototype:

### 1. Caller-identity / token introspection (`identity.rs`)

Today: ~6 unsafe sites for `RpcImpersonateClient` + `OpenThreadToken`
+ `GetTokenInformation`. Proposed:

```
mxc_winsec_sys      ← raw rpcrt4 + advapi32 token FFI
   ↑
mxc_caller_identity ← safe wrapper: ImpersonationScope (RAII),
                      ClientIdentity { user_sid, integrity, … }
```

### 2. Process-lifetime watching (`lifetime.rs`)

Today: ~5 unsafe sites for `OpenProcess` + `WaitForSingleObject` +
`GetExitCodeProcess`. Proposed:

```
mxc_proc_watch_sys  ← raw kernel32 process FFI
   ↑
mxc_proc_watch      ← safe wrapper: ProcessWatcher, WaitOutcome
```

### 3. Diag log rotation (`diag.rs`)

Today: ~4 unsafe sites for `FindFirstFileW` / `FindNextFileW` enumeration
of `%TEMP%\mxc-diag-*.log`. Smaller surface; probably **stays in
`mxc_service`** as a private `sys` module unless we share rotation
logic with another binary.

### 4. `mxc_service_rpc` reorganisation

Already split into `sys.rs` / `client.rs` / `server.rs`. The MIDL
stub unsafe is awkward to crate-split (gen+stub code lives together).
Leave alone unless it grows.

## Crate naming convention

`*_sys` — unsafe FFI shim only. Documented `# Safety` per fn.
`<name>` (no suffix) — safe wrapper. May still have `unsafe { _sys::… }`
blocks but each one line with a `// SAFETY:` comment.

No "super-crates": `mxc_service_common` style buckets are explicitly
**not** the pattern. Each crate has one clearly described
responsibility; if two responsibilities don't naturally co-locate,
split them.
