# MXC Tier 2 Service — Prototype

A working prototype of "Tier 2" from `process-container-networking.md` —
an elevated Windows service that installs per-AppContainer WFP filters
on behalf of unprivileged SDK callers.

> **This is a prototype.** It cuts several corners that the production
> design (spec §4) does not. See **[Prototype shortcuts](#prototype-shortcuts)**
> below.

## What's in this prototype

```
src/service/
├── mxc_service_proto/      ← shared wire format (proto crate)
├── mxc_service/            ← the elevated Windows service binary
└── mxc_service_client/     ← embeddable Rust client + `mxc-net.exe` CLI
installer/mxc-service-msi/  ← WiX 5+ source for the installer MSI
scripts/build-mxc-service.ps1  ← one-command build/install/verify loop
tests/playground/           ← UI surface with a Tier 2 Broker panel
```

### Components

| Crate / artifact      | Role                                                                                          |
|-----------------------|------------------------------------------------------------------------------------------------|
| `mxc-service.exe`     | Windows service. SCM-aware (`StartServiceCtrlDispatcher`). Listens on `\\.\pipe\mxc-service`. |
| `mxc-net.exe`         | CLI client (`version` / `add` / `remove` subcommands).                                        |
| `mxc-service.msi`     | Installs both binaries under `C:\Program Files\Microsoft\MXC Service\` and registers the service. |
| Playground panel      | "Tier 2 Broker" sidebar section that drives `mxc-net.exe` via Electron IPC.                   |

### WFP shape

For each `AddPolicy`, the service installs filters on a **dynamic engine
session** at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (and `_V6` when the rule
addresses v6 or is a wildcard), all scoped to the caller's AppContainer
SID via `FWPM_CONDITION_ALE_PACKAGE_ID` (`FWP_SID`).

Three deterministic weight tiers, all in the MXC sublayer
(`MXC_SUBLAYER_WEIGHT = 0x4000`):

| Tier                       | Weight        | Purpose                                |
|----------------------------|---------------|----------------------------------------|
| Explicit `block`           | `0x2000_0000` | Always wins inside our sublayer.       |
| Explicit `allow`           | `0x1000_0000` | Carves holes through the default-deny. |
| Catch-all `block` (deny)   | `0x0000_0001` | Only added when default = `block`.     |

`AddPolicy` is atomic — partial filter-install failures roll back the
filters added so far.

## Quick start

```powershell
# 1. Install WiX 5+ once (skip if you already have it)
dotnet tool install --global wix
wix eula accept wix7

# 2. Build, install, and smoke-test (from an elevated PowerShell)
.\scripts\build-mxc-service.ps1 -Install -Verify
```

`-Install` runs `msiexec /i mxc-service.msi /qn`. Each invocation bumps
the MSI's `ProductVersion` so `MajorUpgrade` always replaces the prior
install — you can iterate as many times as you like.

### Manual verification

```powershell
# Probe the service
mxc-net version
#  -> service_version=0.7.0 ipc=v0.1

# Add a default-deny policy for an AppContainer (replace SID)
mxc-net add S-1-15-2-... --default block --rule allow:tcp:140.82.112.0:20:443
#  -> policy_id=<UUID> filters_installed=3

# Remove it
mxc-net remove <UUID>
#  -> filters_removed=3
```

Logs (`--console` mode) and SCM service logs both prefix lines with
`[mxc-service]`. There is no eventlog integration yet (future work).

## Prototype shortcuts

These are deliberate deviations from the production design in
spec §4. Each is called out in the relevant source file's
module-level doc, but here is the consolidated list so reviewers can
calibrate.

| Production design               | Prototype substitute                                  | Why                                                                                                    |
|---------------------------------|-------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **LRPC** (§6.7)                 | **Named pipe** `\\.\pipe\mxc-service` (CBOR framed)   | Same kernel-mediated local trust boundary. Pure-Rust LRPC binding is painful; named-pipe is one stdlib call. Transport is decoupled from wire format — LRPC swap touches only `mxc_service` transport. |
| `NT SERVICE\mxc-service` virtual account with restricted SID | `LocalSystem`                       | Tightest production rung needs `FwpmEngineSetSecurityInfo0` DACL work to grant a restricted SID write access. LocalSystem unblocks WFP and lets us validate everything else. |
| Authenticode caller verification | Caller PID/exe **logged only**, no trust decision | Production-grade caller verification is its own design pass; documenting the gap is more useful for a prototype than half-implementing it. |
| Engine handle duplicated into sandbox process (§3.2) — filter lifetime bound to sandbox | Filter lifetime bound to `mxc-service` process       | Sandbox-handle anchoring depends on spec §8.3 PoC. Until then, `RemovePolicy` is the cleanup path; service crash also reaps everything (dynamic session). |
| Provider + sublayer durable, recreated only on schema change | Dynamic-session provider + sublayer, recreated every service start | OK for prototype but means anything outside MXC cannot reference them by GUID across reboots.       |
| Production-grade caps           | `MAX_RULES_PER_POLICY = 256`, `MAX_ACTIVE_POLICIES = 64`, `MAX_MESSAGE_BYTES = 64 KiB` | Defensive against malformed clients. Numbers are starting points. |

## Things this prototype does **not** prove

- That the named-pipe trust boundary equals LRPC's: it doesn't validate
  RPC handle transfer for `sandboxProcess`, RPC call attributes, or per-call
  caller authentication shape.
- That MXC filters dominate system-origin filters during BFE arbitration
  (the open question from the earlier AC↔AC loopback investigation).
  Outbound `ALE_AUTH_CONNECT_V4` is the most favorable layer for our
  user-mode PERMITs, but this needs **empirical** validation on a VM
  with actual `connect()` calls and `netsh wfp capture`.
- The end-to-end Tier 2 lifecycle (SDK creates sandbox suspended →
  service applies policy → SDK resumes). The current playground panel
  drives a known SID after the fact; integrating the call into the
  AppContainer backend's `start_sandbox` path is the next milestone.

## Testing

```powershell
cd src
cargo test -p mxc_service_proto -p mxc_service
```

11 unit tests covering the wire format roundtrip, oversized-frame
rejection, rule validation (good and bad inputs across the matrix), the
prefix-to-mask helper, dual-stack layer selection, and AC SID prefix
validation. All green.

Integration testing is manual via `mxc-net.exe` from inside a VM with
the MSI installed — see **Quick start** above.
