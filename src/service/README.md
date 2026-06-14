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

## Service identity (spec §4.1)

Per spec §4.1 the service ships at the tightest empirically-viable
identity rung. The MSI installs at the top of the ladder:

| Aspect                | Value                                                        |
|-----------------------|--------------------------------------------------------------|
| Logon account         | `NT AUTHORITY\LocalService`                                   |
| Service SID type      | `SERVICE_SID_TYPE_RESTRICTED` (set via `sc sidtype` CA)        |
| Required privileges   | `SeChangeNotifyPrivilege` only (`sc privs` CA)                |
| Engine-SD ACE         | granted by `mxc-service.exe --install-grant` CA, running as LocalSystem during deferred install. ACE = `FWPM_ACTRL_OPEN \| FWPM_ACTRL_ADD \| FWPM_ACTRL_ADD_LINK \| DELETE \| FWPM_ACTRL_ENUM \| FWPM_ACTRL_READ` with `CONTAINER_INHERIT_ACE \| OBJECT_INHERIT_ACE`. Target = the `NT SERVICE\mxc-service` per-service SID. |
| MSI install sequence  | InstallServices → SetSidType → SetPrivs → GrantWfpRights → StartServices |

If an empirical check shows BFE rejects a lower rung, drop the next
identity from the ladder: write-restricted LocalService → unrestricted
LocalService → NetworkService → LocalSystem. The MSI must be rebuilt to
ship a lower rung — there is no runtime fallback (spec §4.1
"Build order, not runtime fallback").

### Ladder fallback procedure (manual)

If `FwpmFilterAdd0` returns `E_ACCESSDENIED` at the current rung,
relax in this order. Each step is a one-character change to
`installer/mxc-service-msi/Package.wxs`:

1. **Drop `SERVICE_SID_TYPE_RESTRICTED`** — remove the `SetSidType` CA
   from `InstallExecuteSequence`. The service still runs as LocalService
   but with an unrestricted token.
2. **Switch account to `NT AUTHORITY\NetworkService`** — change the
   `Account=` attribute on `<ServiceInstall>`. The engine ACE granted to
   `NT SERVICE\mxc-service` still applies (per-service SID is present
   in NetworkService's token too).
3. **Switch account to `LocalSystem`** and remove all the privilege/SID
   custom actions. This is what AppInfoSvc uses on Tier 1 for the same
   work. **This rung defeats the privilege-separation goal of the
   Tier 2 design**; only use if every higher rung is empirically
   blocked.

## Prototype shortcuts

Deliberate deviations from the production design (spec §4) that remain
in this prototype:

| Production design | Prototype substitute | Why |
|---|---|---|
| **LRPC** (§6.7) | **Named pipe** `\\.\pipe\mxc-service` (CBOR framed) | Same kernel-mediated local trust boundary. Transport is decoupled from the wire format, so an LRPC swap touches only `ipc.rs` + `mxc_service_client/lib.rs`. |
| Authenticode caller verification | Caller PID/exe **logged only**, no trust decision | Caller verification is its own design pass (signed-binary policy, signer chain, revocation). Documenting the gap is more useful than half-implementing it. |
| Engine handle duplicated into sandbox process (§3.2) — filter lifetime bound to sandbox | Filter lifetime bound to the `mxc-service` process | Sandbox-handle anchoring depends on the §8.3 PoC. Today `RemovePolicy` is the cleanup path; service exit also reaps everything (dynamic session). |
| Durable provider + sublayer, recreated only on schema change | Dynamic-session provider + sublayer, recreated every service start | OK for a prototype but means no external consumer can reference them by GUID across reboots. |
| `MAX_RULES_PER_POLICY = 256`, `MAX_ACTIVE_POLICIES = 64`, `MAX_MESSAGE_BYTES = 64 KiB` | (same — already prototype values) | Defensive against malformed clients. Numbers are starting points, not the final policy. |

What is **not** on this list — implemented as designed:

- **§4.1 service identity.** `NT AUTHORITY\LocalService`, `SERVICE_SID_TYPE_RESTRICTED`,
  `SeChangeNotifyPrivilege`-only, deterministic per-service SID, inheritable
  engine ACE. See "Service identity" above.
- **Client wiring.** `wxc-exec`'s AppContainer backend talks to the broker
  through `mxc_service_client`. No second binary is needed — `blockedHosts` /
  `allowedHosts` flow straight from the script config through the broker into
  WFP. There is **no** Windows-Firewall (`INetFwPolicy2`) fallback: that path
  required `wxc-exec` to run elevated, which defeats Tier 2's whole point.
- **Diagnostic surface.** The broker emits a line on the diagnostic-console
  named pipe for every IPC connect, AddPolicy / RemovePolicy, and rule
  installed. Run `mxc-diagnostic-console.exe` elevated alongside any test to
  watch broker activity live.

## What this prototype now proves (was previously open)

- **LRPC transport** (spec §6.7): the broker registers an LRPC
  interface on `ncalrpc:mxc-service` via MIDL-generated stubs (see
  `mxc_service_rpc/`). Clients prefer LRPC and fall back to the
  named-pipe path. Confirmed end-to-end on a VM with the broker line
  `LRPC listener registered on ncalrpc:mxc-service`.
- **Sandbox lifecycle binding** (spec §3.2): broker is now called from
  `appcontainer_runner::run_internal_impl` between
  `CreateProcessW(CREATE_SUSPENDED)` and `ResumeThread`, with the real
  `pi.dwProcessId` passed as `sandbox_pid`. Filter lifetime is bound
  to the sandbox PID via `lifetime.rs`: when the sandbox terminates,
  the broker auto-issues `RemovePolicy` (verified by the diag line
  `lifetime: sandbox pid=N exited → auto-RemovePolicy`).
- **Per-call caller identity**: best-effort `ImpersonateNamedPipeClient`
  + `OpenThreadToken` capture the caller's user SID. Logged only,
  not used for trust decisions (the production design needs
  Authenticode caller verification, which remains a separate pass).
- **WFP arbitration for AC↔AC loopback (empirical answer)**: ran
  `Test-WfpArbitrationAcToAc.ps1` with a real Rust listener
  (`ac_tcp_listener`) inside one AC and curl inside another. **MXC
  user-mode PERMITs at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` do NOT
  dominate system filter 71655**: all three scenarios (no broker,
  broker-block, broker-permit) produce identical 4-second timeouts.
  This means the broker cannot fix AC↔AC loopback at the WFP layer;
  the `networkLoopback` capability remains the only viable path for
  that case (which is exactly what the original investigation
  concluded).

## Things this prototype still does **not** prove

- That MXC user-mode PERMITs at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
  dominate the system-origin filter 71655 in BFE arbitration for
  AppContainer↔AppContainer loopback. `Test-WfpArbitration.ps1`
  exercises a single-AC → closed-loopback-port baseline (which is
  *not* gated by filter 71655 — the target isn't an AC); a faithful
  AC↔AC test requires standing up a listener inside a second AC,
  which is out of scope for the script harness.
- That the named-pipe-fallback transport is equivalent to LRPC for
  caller-token shape. Identity capture works on both, but
  `OpenThreadToken(OpenAsSelf=true)` on a Negotiate-authenticated
  LRPC call yields a richer impersonation token than the
  named-pipe path; the prototype treats them as interchangeable.

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
