# Process Container Networking — Tech Spec (GA)

## 1. Overview

MXC's `processcontainer` containment must offer, at GA, a **per-sandbox
outbound network policy** that is uniform across the Windows builds it
supports, and that is honest about what each build can actually enforce.

**Scope.** This spec covers the `processcontainer` containment type
only. MXC's other containment options on Windows (sessions, microVMs,
and any future types) will be addressed in their own specs. Nothing
below applies to those.

### 1.1 Goal

`processcontainer` containment must offer two outbound-networking
capabilities, per sandbox, on every Windows build MXC supports
— plus a third stretch goal:

**(a) Allow/block of arbitrary outbound TCP and UDP by IP, CIDR,
and port.** Surfaced in the MXC config schema as `allowedHosts`
and `blockedHosts`. This is the general-purpose containment lever:
for example, limiting a `gh-copilot` sandbox to GitHub's API IP
range on port 443. Sandboxes are default-deny outbound; both lists
layer on top of that posture. (A `protocols` allow-list — transport-
and-port filter — is a planned addition to the schema in section 6
alongside this work; today the schema only carries the host lists.)

**(b) Transparent proxy on loopback through a controlled proxy
AppContainer.** A second AppContainer sandbox (B) runs an inspecting /
logging proxy listening on the loopback interface, and sandbox A's
traffic is transparently routed over loopback to sandbox B. The
mechanism is the per-AppContainer WinHTTP proxy
configuration — the only OS surface that scopes a proxy URL to a
single AppContainer SID.

**(c) (Stretch goal) Multi-protocol proxy support beyond
HTTP/HTTPS.** Today the per-AppContainer proxy hook only exists
in WinHTTP, so (b) covers HTTP and HTTPS only. The stretch
goal is to extend the same proxy-on-loopback pattern to other
protocols (SOCKS, raw TCP, and longer-tail) so a single proxy
AppContainer can inspect arbitrary sandbox egress — not just the
web-stack subset. This depends on new OS surfaces outside MXC's
control and is not committed for GA; tracked as an open question
in section 8.

### 1.2 Where we stand today

Both capabilities from section 1.1 are broken on `processcontainer` today, in different ways.

**(a) `allowedHosts` / `blockedHosts` — fully rejected at runtime
today.** The 0.7.0-dev MXC config schema already documents these
fields, but the `processcontainer` validators in the AppContainer-
runner and BaseContainer-runner reject them with "not supported on
processcontainer" before the launch is attempted. The enforcement
mechanism itself is not missing — MXC's AppContainer-runner network
manager already calls the Windows Firewall (`INetFwRule3`) to materialize
per-AppContainer firewall rules for other code paths. The reason
`processcontainer` doesn't use it is that `INetFwRule3` writes
require admin, and the only way for medium-IL `mxc-exec.exe` to make
the call today is for `mxc-exec.exe` itself to be elevated, which
means a UAC prompt every sandbox launch. That cost is unacceptable
for an interactive developer-tool workflow, so we throw instead.

**(b) Proxy (HTTP/HTTPS via WinHTTP) — partial implementation,
incomplete.** MXC installs a proxy URL scoped to the sandbox's
AppContainer SID, and WinHTTP routes the sandbox's HTTP/HTTPS
through it. Clients that use WinHTTP directly honor this. Clients
that have their own HTTP stack and read `HTTP_PROXY` / `HTTPS_PROXY`
env vars (Node, curl, Python) are not supported. The per-AppContainer
WinHTTP proxy APIs also require admin, so MXC ships
`winhttp-proxy-shim.exe` — an elevated stub spawned via
`ShellExecuteExW("runas", …)` per proxy start whose only job is to
be a process running as admin so it can make the WinHTTP calls on
behalf of medium-IL `mxc-exec.exe`. This "works" but takes a UAC per
launch, and the proxy flow itself has further gaps that span MXC, the
Tier 1 path (`CreateProcessInSandbox`), and WinHTTP:

1. **AppContainer-to-AppContainer binding not wired up.** First-
   priority OS work. The pieces exist (`NetworkIsolationSetApp
   ContainerConfig` for loopback exemptions, the per-AppContainer
   WinHTTP proxy surface), but neither MXC nor `CreateProcessInSandbox`
   (the Tier 1 host, section 1.3) wires them in this configuration
   today. Closing the gap is OS work in `CreateProcessInSandbox` plus
   matching wiring in MXC's Tier 2 path.
2. **Per-AppContainer WinHTTP proxy cleanup is whole-AC scoped.**
   The only delete API today removes *all* proxy policies on an
   AppContainer, so MXC can't reliably tear down its own policy without
   clobbering anything else set on the AC. WinHTTP team is delivering
   a per-policy delete in an upcoming Insider Preview.
3. **Loopback-interface proxy binding (Tier 2 only) is missing.**
   `WinHttpConnectionUpdateIfIndexTable` is the API that binds proxy
   info to a specific interface (loopback, in our case). MXC does not
   call it on the Tier 2 path, so the per-AC proxy isn't pinned to
   the loopback interface. The current API is also delete-all-and-
   replace, so even using it would clobber concurrent settings;
   networking team is delivering a non-clobber replacement.

Once (a) and (b) land, MXC will have its first fully working
protocol proxy: HTTP and HTTPS, via WinHTTP.

### 1.3 How we get closer to the goal

There are exactly two enforcement paths and we collapse to those two
labels everywhere in this spec:

- **Tier 1.** The OS exposes `CreateProcessInSandbox`. The OS applies
  the per-sandbox policy in-process at sandbox-create time: WFP
  user-mode filters for allow/block (section 3.1), and AC-to-AC
  binding + per-AppContainer WinHTTP proxy wiring for the proxy path.
  No MXC-side elevated service,
  no UAC ever.
- **Tier 2.** `CreateProcessInSandbox` is absent. MXC's separately-
  installed elevated service `mxc-service` (section 4) makes the
  admin-only calls itself, using the same WFP mechanism as Tier 1
  (section 3.2). `mxc-service` is **not** bundled with the SDK; it
  ships as a signed MSI distributed via winget (section 4.4, section 8.4). If the
  service is not installed, the SDK
  errors with an install URL rather than attempting to install on
  demand. The happy path remains Tier 1, where no install is needed
  at all.

**Tier 1 is not a guarantee of every feature.** `CreateProcessInSandbox`
is a single API but its network-feature surface grows over time across
Windows builds. A machine on Tier 1 can be on an older Tier 1 build
that does not yet implement a feature MXC is asking for. Tier 1 does
**not** silently fall back to Tier 2 in that case — the SDK queries
the OS feature bitmap (section 6.5), and if the requested feature is
missing, the SDK errors with a message naming the missing feature. The
Tier 2 `mxc-service` is a single code path that supports every feature in
this spec regardless of Windows build, so it does not have the same
problem; only Tier 1 needs the feature probe.

We do **not** carry a third tier or a "best-effort" mode. The two
paths have measurably different cleanup, persistence, and trust
properties (section 3 table), and operators need a predictable answer
to "where is my policy actually being enforced."

**Operator escape hatch — out of scope at GA.** Earlier drafts
proposed letting an operator pin Tier 2 even on a Tier-1-capable
machine for diagnosability (Tier 2 rules show in `wf.msc` and
`Get-NetFirewallRule`; Tier 1 filters only via the operator-hostile
`netsh wfp show filters`), to work around a specific Tier 1 OS
issue, or to keep mixed-fleet reproducibility. Per the policy in
section 4, the SDK chooses tier automatically with no opt-out — Tier
2 is the downlevel parity bridge, not a configurable target. An
operator who wants to keep a machine off Tier 2 simply does not
install `mxc-service`.

### 1.4 Three concrete requirements drive every decision below

1. **Per-instance, concurrent policy.** Two different MXC
   clients (e.g. `gh-copilot` and `vscode`) routinely launch
   `powershell.exe` into their own AppContainer sandboxes at the same
   time. Each sandbox has its own AppContainer SID; one may be allowed
   only to GitHub's API IP range (`140.82.112.0/20:443`), the other
   only to a loopback proxy AppContainer. Per-instance scoping operates
   on IP / CIDR / port literals — DNS-name allow-listing is explicitly
   out of scope for GA (section 5). **AC SIDs are ephemeral and
   globally unique:** MXC creates a fresh AppContainer profile (and
   therefore a fresh SID) per sandbox launch via
   `CreateAppContainerProfile` with a UUID-derived name; SIDs are never
   reused across launches, `mxc-service` crashes, or reboots. Several Tier 2
   recovery decisions in section 3.2 and section 6.6 rely on this property.

2. **No UAC per launch on Tier 2.** Adding firewall rules requires
   admin (both the Windows Firewall and WFP gate on it). Today MXC raises one
   UAC per launch via the elevated WinHTTP shim. Doing that for *every*
   sandbox launch plus *every* policy change is not shippable. The
   answer is an elevated service installed once (section 4).

3. **Fail loud on version skew, never silently downgrade.** Tier 1
   `CreateProcessInSandbox` is not one build — it is a moving feature
   set. A user can be on a Windows build where the API exists but does
   not yet support the specific feature the MXC SDK is asking for (for
   example a newer MXC version asking for a network filter shape the
   inbox API hasn't picked up yet).    the wrong answer is for the SDK to silently fall back to the Tier
   2 path: the security and performance profiles are different and
   the operator wouldn't know. The right answer is to error with a
   clear message naming what is missing. The SDK only falls back to
   Tier 2 when `CreateProcessInSandbox` is *absent on the build*, not
   when it is present but missing a requested field.

   This requires two probes:

   - **MXC-side:** extend MXC's existing tier-probe CLI to report which
     network features the current machine supports end-to-end (the
     intersection of API presence and `mxc-service` availability).
   - **OS-side (new API request):** when `CreateProcessInSandbox` is
     present, MXC needs a way to ask it which network-policy fields it
     can actually honor. This is a small feature-bitmap query that
     should land alongside the Tier 1 enforcement work in the OS; the
     shape is proposed in section 6.5.

   With both probes in place, the SDK rejects a containment-launch call
   that asks for a feature the current build cannot deliver, instead of
   degrading to Tier 2 without telling anyone.

## 2. Per-tier delivery table

This is the contract. Anything not in this table is not GA.

| Tier | Per-AC outbound allow-rule | Per-AC outbound deny-rule | HTTP proxy via loopback AppContainer | L7 classification (HTTP vs SSH on :443) | DNS-name allow-list | UAC per launch | Mechanism |
|---|---|---|---|---|---|---|---|
| **Tier 1** (`CreateProcessInSandbox` present, build supports the requested feature per section 6.5 probe) | **yes** | **yes** | **yes** | no | no | none, ever | WFP filters added by the OS inside `CreateProcessInSandbox`, scoped to the sandbox AppContainer SID via `FWPM_CONDITION_ALE_PACKAGE_ID`. Lifetime is tied to the sandbox process — when the sandbox exits, the OS removes the filters; the calling host runs no cleanup code. The specific handle-ownership mechanism is internal to `CreateProcessInSandbox`. |
| **Tier 1, requested feature not in this build** | — | — | — | — | — | n/a | SDK errors before the launch happens. No silent fallback. Operator updates Windows or downgrades the schema. |
| **Tier 2** (`CreateProcessInSandbox` absent) | yes | yes | yes | no | no | none after setup | Same WFP mechanism as Tier 1, opened from `mxc-service` (section 4). Engine handle is duplicated into the sandbox process before resume so filter lifetime is bound to the sandbox, not to `mxc-service`. Falls back to `INetFwRule3` if the WFP-handle-dup feasibility in section 8.3 comes back unfavorable. |

**What an allow-rule or deny-rule can express concretely.** Both shapes
draw from the same primitive set per rule: a destination as an IPv4 or
IPv6 literal or CIDR (or omitted = any), a transport (`tcp`, `udp`,
`icmpv4`, `icmpv6`, or `any`), and a single port or inclusive range
(`1024-65535`, or omitted = any). Examples: an allow-rule with
`destination=140.82.112.0/20`, `transport=tcp`, `port=443` permits only
HTTPS to GitHub; a deny-rule with `transport=udp` and no destination or
port blocks all outbound UDP from the AppContainer. Rules are evaluated
per-AppContainer-SID; rules from one sandbox do not affect another.
What is **not** in the primitive set: DNS names (allow-list resolves
literals only, see out-of-scope below), L7 protocols (HTTP vs SSH vs
SOCKS on the same port), and process-identity match within a sandbox
(the AppContainer SID *is* the identity).

**Snapshot of which Windows builds land in which tier today.** At time
of writing, `CreateProcessInSandbox` ships in the current Windows
Insider Preview Dev channel. Everything else — retail today, all of
23H2 / 24H2 / 25H2, and 26H2 out of the box — lands on Tier 2. 26H2
will receive `CreateProcessInSandbox` via inbox update, at which point
those machines move to Tier 1. The Tier 2 API surface (`INetFwRule3`)
is present and stable across all of 23H2 → current builds, so a
single Tier 2 implementation covers the whole tail and continues to
work as a
fallback forever.

**Version skew within Tier 1.** A machine on a `CreateProcessInSandbox`-
capable build but missing a specific network feature does **not**
silently fall back to Tier 2. The SDK calls the proposed OS
feature-query API (section 6.5), compares the bitmap against what the
caller asked for, and either honors the request on Tier 1 or returns a
typed error naming the missing feature. The operator decides whether to
update the OS, downgrade the MXC schema, or run on a different build.

What is **explicitly out of scope** for GA on every build:

- Classifying HTTP vs SSH vs SOCKS on the same TCP port. Requires a kernel
  WFP Stream-layer callout driver, which is out of scope (section 3.3).
- DNS-name allow-list resolved at filter time. Requires either a callout
  or an in-host DNS interceptor, both out of scope for GA.
- Inbound (listening) sandboxes. Schema may reserve fields; enforcement
  is post-GA.
- IPv6 parity audit beyond what `INetFwRule3` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`
  give us "for free."

The reason the table is **flat** (same capabilities on every build) is the
elevated `mxc-service` from section 4. Without it, the table would collapse to "current Insider Preview only";
none of the Tier 2 builds can add per-AppContainer firewall rules from a
medium-IL caller.

## 3. Mechanism choice

Three Windows mechanisms can plausibly carry per-AppContainer,
per-instance outbound policy. We evaluate them below and pick the
same one for both tiers, differing only in execution site (in-OS
vs. `mxc-service`).

### 3.1 WFP user-mode filters (`Fwpm*` from `fwpuclnt.dll`)

Used by us on Tier 1 (the WFP calls happen inside
`CreateProcessInSandbox`, which runs in the OS's elevated AppInfo
service).

**What WFP gives us.** WFP is the in-kernel hook point inside the
Windows network stack where any outbound `connect()` can be inspected
and permitted or blocked **before** it reaches the TCP/IP layer. We
attach filters at the `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`V6` layer
scoped to the sandbox's AppContainer SID via the
`FWPM_CONDITION_ALE_PACKAGE_ID` condition. That is the only piece of
identity we reliably have at filter-add time, and Windows applies the
filters only to outbound traffic from that one sandbox process.

**Cleanup is automatic.** WFP filters added against a *session*
(dynamic) engine handle are reaped by the kernel when the handle
closes, and dangling handles owned by an exited process are auto-closed
by BFE. On Tier 1, `CreateProcessInSandbox` uses that property to tie
filter lifetime to the sandbox process. The contract MXC relies on is
"filter lifetime ≤ sandbox process lifetime, no caller cleanup." When the sandbox dies, the filters are gone.
No leaked-rule recovery code on our side.

**Why this needs admin, and how we get it.** Adding filters to WFP is
admin-only — the WFP engine's access check requires the caller to be
in the engine object's DACL, and only administrators (plus a small
set of OS services such as `AppXSvc`) are there by default. On
Tier 1 this is satisfied because the call originates from
`CreateProcessInSandbox` running inside AppInfo (`LocalSystem`); the
MXC caller never touches WFP. On Tier 2 we route the equivalent calls
through `mxc-service` (section 4) to satisfy the same check
without putting up a UAC prompt.

**Verdict:** the right choice for both tiers. On Tier 1 the OS already has
the elevation needed and ties filter lifetime to the sandbox process
for us. On Tier 2 `mxc-service` (section 4) provides the same elevation,
and the handle-anchoring trick described in (3.2) gives us the same
sandbox-bound lifetime contract.

**Why `FWPM_CONDITION_ALE_PACKAGE_ID` and not the other AppContainer-scoping
conditions.** The AppContainer SID is the value we already have at
filter-add time, and `FWPM_CONDITION_ALE_PACKAGE_ID` is a direct SID compare with no
SD access-check overhead. `ALE_USER_ID` (SDDL granting the AC SID) and
`ALE_PACKAGE_FAMILY_NAME` (PFN-derived SD) both reach the same
enforcement point with more plumbing per filter.
`FWPM_CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE` keys off an AppLocker FQBN attribute and
requires a deployed AppLocker policy tagging the sandbox image — unworkable
as a primary mechanism. The others stay in reserve if we ever need to
differentiate (e.g. AC SID **and** user SID together).

**Layer choice.** `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` fires on `connect()`
and is the standard outbound-policy point. `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4/V6`
fires earlier — on socket bind — and can prevent the sandbox from
*creating* a socket at all. Tighter, but the failure surfaces as a bind
error rather than a `connect()` error, which is less expected for
applications. We pick AUTH_CONNECT for the predictable error model and
keep RESOURCE_ASSIGNMENT in reserve for cases where bind-time blocking
matters (e.g. forbidding the sandbox from creating raw or UDP sockets
even if it never `connect()`s).

### 3.2 Same WFP mechanism, hosted in `mxc-service` (Tier 2)

Tier 2 uses the same WFP primitive as (3.1) — dynamic-session engine
handle, `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` filters with the `FWPM_CONDITION_ALE_PACKAGE_ID`
condition. Only the execution site and the handle-anchoring shape differ:

- **Execution site.** `mxc-service` (an installed service from the
  elevated setup binary, section 4) instead of AppInfo. Service identity
  and the install-time WFP DACL setup are discussed in section 4.
- **Handle anchoring.** The SDK creates the AC sandbox suspended,
  marshals the sandbox process handle to `mxc-service` over LRPC, the
  service opens the engine handle and adds the filters,
  `DuplicateHandle`s the engine handle into the sandbox with
  lifetime-anchor-only access, closes its own reference, and acks; the
  SDK then resumes the sandbox. Filter lifetime is bound to the
  sandbox process, so an `mxc-service` crash leaves every running
  sandbox's policy intact. Sandbox exit reaps the filters via the same
  BFE handle-close path (3.1) relies on.

This design depends on three WFP engine-handle properties tracked in
section 8.3: cross-process duplicability, access stripping on the duplicated
handle, and `FWPM_SESSION_FLAG_DYNAMIC` reaping bounded by the last
open handle rather than opener-process lifetime. If any come back
unfavorable, Tier 2 falls back to `INetFwRule3` from `hnetcfg.dll`,
which `mpssvc` materializes as `FWPM_CONDITION_ALE_PACKAGE_ID` WFP filters under the
hood scoped by `LocalAppPackageId` — schema and IPC contract unchanged,
only the service's post-`AddPolicy` behavior changes.

`INetFwRule3` is also the surface MXC's AppContainer-runner network
manager uses today (from the elevated `mxc-exec.exe`). It's reachable
and well-understood, but it doesn't give us anything WFP doesn't — same
enforcement point, same per-AC scoping, more knobs we don't need
(profile expansion, policy-store persistence).

### 3.3 WFP Stream-layer callout driver (kernel)

Only Windows mechanism that can inspect L7 payload (HTTP method, SSH
banner). **Out of scope.** A new kernel-mode driver carries its own
signing pipeline, update channel, and crash-blast-radius story that
needs to be designed separately. The design here does not assume one
exists.

### 3.4 What WFP itself can and can't filter on

Empirical — the conditions and actions WFP exposes at the
`FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6` layer (the layer Tier 1 and Tier 2 both
target). What the MXC schema chooses to surface from this is a
separate question (section 6.1).

| WFP can match / act on                                  | Notes                                                  |
|---------------------------------------------------------|--------------------------------------------------------|
| **Direction**: inbound and outbound                     | Per-layer; we only use outbound.                       |
| **Transport**: TCP, UDP, ICMPv4/v6, and other IP protocols (GRE, ESP, AH, ...) | Selected by IP protocol number. |
| **Remote IPv4 / IPv6**: literal, CIDR, range, set       | IPv4 and IPv6 reach parity.                            |
| **Remote port**: single, range, set                     | Multi-port handled in a single filter.                 |
| **Local IP / local port**                               | Same expressivity as remote.                           |
| **Interface index / type / tunnel type**                | Lets us scope to loopback specifically.                |
| **Process scope**: image path, AppContainer SID, token user SID | AppContainer SID is how we scope per sandbox.   |
| **Action verbs**: permit, block, defer to lower sublayer, hand to callout | Plain permit/block is all we need without a callout. |

| WFP can't help with                                     | Why                                                    |
|---------------------------------------------------------|--------------------------------------------------------|
| **Match on DNS name**                                   | Filters operate on IPs. No name-resolution hook.       |
| **Inspect L7 payload** (HTTP method, URL, TLS SNI, SSH banner) | The connect-authorization layer only sees protocol + source / destination IP + source / destination port — fine for blocking SSH on its known port, but not for *recognizing* SSH on a non-standard port. Needs a kernel callout at the stream layer (out of scope, 3.3). |
| **Filter encrypted content**                            | Even with the stream-layer callout, TLS payload is opaque without MITM. |
| **Rate-limit or shape bandwidth**                       | Not a WFP dimension — that's QoS.                      |
| **Modify packets in-flight**                            | The verdict at our layer is permit/block only. Rewrite requires a callout. |
| **Scope below the process** (per-thread, per-handle)    | Policy attaches via process attributes; threads in the same process share the verdict. |
| **Authenticate the remote peer** (cert pinning, mTLS)   | TLS lives above WFP.                                    |

## 4. The `mxc-service` elevated service — shape, deployment, IPC

This section is **Tier 2 only.** Tier 1 enforcement (section 6.4)
does not require this service at all — the OS does the WFP work
in-process inside `CreateProcessInSandbox`. Tier 2 enforcement
requires admin and admin per launch is unacceptable, so an installed
elevated component is invoked by IPC. This section chooses the shape.

**Forward-looking policy: Tier 2 is a downlevel parity bridge, not a
feature target.** Any new or experimental capability lands in
`CreateProcessInSandbox` (Tier 1) only. `mxc-service` mirrors the
Tier 1 surface as it stands at GA and does not grow new verbs after
that. Users who want post-GA capability upgrade their OS; users on
older builds get the GA baseline. This keeps the service surface
small, the security audit bounded, and the OS-release schedule the
single forcing function for new networking primitives in sandboxes.

### 4.1 Service vs. OOP COM elevation vs. per-launch shim

| Option | UAC cost | Always-on attack surface | Caller authn primitive | Verdict |
|---|---|---|---|---|
| Per-launch elevated shim (today) | one UAC per launch | none | n/a (caller is the user) | **rejected** — incompatible with interactive sandbox-launch workflows |
| COM Elevation Moniker (`Elevation:Administrator!new:{CLSID}`) | one UAC per object create | only while client alive | client must already be elevated to skip the prompt | **rejected** — doesn't solve the medium-IL caller problem; just moves the prompt |
| Long-running Windows service (`mxc-service`) installed once via MSI/winget (section 4.4) | one UAC at first install | service binary, IPC endpoint, rule-store writes | service must authenticate caller from token | **chosen** |
| Scheduled Task running as `LocalSystem` triggered by IPC | one UAC at install | similar to service | same as service | rejected — strictly worse diagnosability, same attack surface |
| Backport `CreateProcessInSandbox` to 23H2 (eliminates Tier 2 entirely) | none (in-OS) | none (kernel-mediated) | n/a (kernel does it) | rejected for this design — would eliminate the need for any installed service, but the OS-backport process is multi-year and does not help the GA timeline. Worth flagging for reviewers who prefer no runtime broker. |
| Remove the admin requirement on WFP user-mode APIs (no service needed) | none | none | n/a | rejected for this design — the WFP user-mode admin gate has been in place since Vista / Server 2008 and there is no signal that Windows networking plans to change it. Worth flagging for the same reviewers. |

**Service identity. Preferred: write-restricted virtual service account
`NT SERVICE\mxc-service` running as `LocalService`.** The elevated MSI
custom action (section 4.4) registers the service with
`SERVICE_SID_TYPE_RESTRICTED` (the service process token's
restricted-SID list is the documented four-SID set — per-service SID,
World, the service logon SID, and `S-1-5-33` — so write access
succeeds only where a DACL grants one of those; we keep our own
provider/sublayer/filter DACLs scoped to the per-service SID), strips
ambient privileges via `RequiredPrivileges` (minimum practical set:
`SeChangeNotifyPrivilege` to keep path resolution working;
`SeImpersonatePrivilege` only if the LRPC server in section 4.3
actually requests an impersonation level above `Identify`), and calls
`FwpmEngineSetSecurityInfo0` once to write an inheritable ACE
(`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`) granting the
`NT SERVICE\mxc-service` SID `FWPM_ACTRL_OPEN | FWPM_ACTRL_ADD |
FWPM_ACTRL_ADD_LINK | DELETE | FWPM_ACTRL_ENUM | FWPM_ACTRL_READ` on
the BFE engine. By the documented WFP inheritance model, that
propagates to the filters container and built-in layer objects, which
is what `FwpmFilterAdd0` checks against the
`FWPM_LAYER_ALE_AUTH_CONNECT_V4/_V6` layer plus the MXC
provider/sublayer (the callout and provider-context access rights are
not exercised because our filter has neither). The runtime service
then opens a dynamic engine session and writes per-sandbox filters
with neither `SYSTEM` rights nor the ambient `LocalService` group's
write access — only what the engine SD explicitly grants the
per-service SID. The `FwpmEngineSetSecurityInfo0` call is made
outside any explicit transaction, per the documented API constraint.

**Build order, not runtime fallback.** The PoC (open question 8.7)
walks identities from tightest to loosest: write-restricted
`LocalService` → unrestricted `LocalService` → `NetworkService` →
`LocalSystem` (what AppInfo uses for the same WFP work on Tier 1). We
**ship at the tightest rung that empirically works** and that is the
fixed installed identity for the lifetime of that release; the
service does not downgrade itself at runtime, and a later release
that finds a tighter rung viable moves the install down via package
update. Schema, IPC contract, and section 4.3 caller-auth defenses
are identical at every rung.

Either way, section 4.3 carries the caller-authentication and
input-validation defenses that make the service safe under a hostile
caller. Running at the tightest identity is a defense-in-depth posture
against bugs in the service itself, not a replacement for caller auth.

### 4.2 IPC channel choice

| Channel | Notes |
|---|---|
| Named pipe `\\.\pipe\mxc-net` | discoverable; squattable at boot; impersonation footguns |
| ALPC port (`NtAlpc*`) | not file-namespace addressable; server controls connection ACL; native primitive used by RPC/LRPC |
| LRPC (Local RPC over ALPC) | MIDL-generated stubs, automatic marshalling, authn via `RpcImpersonateClient` + `RpcServerInqCallAttributesW` (V2) |
| COM (LRPC under the hood) | same as LRPC plus typelib + lifetime management |

**Choice: LRPC** with a `ncalrpc` endpoint — the documented Windows
secure-IPC pattern for a local privileged service, the same primitive
`mpssvc` and `mxc-service`'s own callees use. Per-call, the server
uses `RpcServerInqCallAttributesW` with `RPC_CALL_ATTRIBUTES_V2_W` to
get the caller's PID (kernel-supplied, unspoofable) and local
connection address. No `I_Rpc*` internals — those are undocumented and
not redistributable contract. Endpoint is ACL'd to `BUILTIN\Users`;
section 4.3 authenticates the caller binary in case the service is stopped
and the endpoint squatted.

### 4.3 Caller authentication

The IPC client is **medium IL, unpackaged** — no AppContainer SID,
no MSIX identity, no manifest the kernel can vouch for. A medium-IL
process on the same desktop can copy the client binary, inject into
it, or spoof its image path. There is no perfect answer for "trust a
medium-IL caller"; the design posture is **defenses that make the
`mxc-service` API safe even if the caller is hostile.** Three layers:

**Layer 1 — verify the caller binary at IPC time.** The service
identifies the caller's process from the IPC runtime (kernel-supplied,
unspoofable), verifies the Authenticode signature on the caller's
on-disk image, and requires the chain to terminate at a Microsoft
production root with the MXC publisher identity on the leaf. Images
loaded from user-writable directories are rejected. Not TOCTOU-proof
on its own — mitigated by also tying the check to the running image's
section identity.

**Layer 2 — narrow the API so a hostile caller's worst outcome is
bounded.** The service exposes only three verbs: add a policy
(per-AppContainer-SID rules + a sandbox process handle for lifetime),
remove a policy, and query version. Invariants:

- **Per-AC scoping.** Every filter is scoped to the caller-named
  AppContainer SID; no filter can apply system-wide. Worst-case abuse
  is the caller adding deny filters to an AC SID nobody else is using.
- **Handle-anchored lifetime.** Engine handle is duplicated into the
  caller-supplied sandbox process with lifetime-anchor-only access
  (pending section 8.3 PoC); the sandbox cannot use it to add/remove filters.
  A hostile caller passing a sandbox handle it doesn't own is rejected
  by the IPC layer's token check before any WFP work happens.
- **Per-caller bookkeeping.** Remove rejects policies not owned by the
  calling identity; one caller cannot tear down another's policies.
- **No attacker-controlled name resolution.** Rule addresses must be
  IP literals; the service never resolves DNS for callers.
- **Resource caps.** Bounded rules per policy and policies per machine.
- **No read API.** Existing policies are not enumerable; no
  information disclosure.
- **No verbs outside WFP.** No file I/O, no registry, no process
  creation, no token manipulation. The `INetFwRule3` fallback (section 3.2)
  preserves the same scoping and bookkeeping against `mpssvc` rules.

This is the load-bearing defense. The threat model is that the IPC
caller may be hostile; the `mxc-service` API is the boundary.

**Layer 3 — anti-spoof on the wire.** LRPC is kernel-mediated, not
network — no replay risk. The relevant attacks reduce to cross-user
calls (mitigated by the endpoint ACL + Layer 1 signer check), caller
PID spoofing (impossible — kernel-supplied), and malformed SID inputs
(parsed and range-checked).

**Out of model:** local administrator subverting `mxc-service`,
kernel-level malware, an MXC-signed legitimate client misbehaving on
the caller's behalf.

### 4.4 Distribution and lifecycle

`mxc-service` ships as a **signed Microsoft MSI** distributed via
**winget**, with direct download from `aka.ms/mxc-service` for offline
/ air-gapped operators. MSI handles service registration
declaratively at the section 4.1 identity and avoids the
`packagedServices` restricted capability and Microsoft Store partner
approval that MSIX-based service hosting would require. Microsoft
Store as a Win32 app stays open as a third surface (see section 8.4).

The SDK does **not** auto-install or auto-elevate. On the first Tier 2
call that needs `mxc-service`, the SDK queries SCM; if absent, it
returns a typed error carrying the install URL. Consuming applications
(`gh-copilot`, `vscode-mcp`) decide their own UX from there —
typically a one-time onboarding card pointing at winget or the direct
download. On a Tier-1-capable machine the SDK never needs
`mxc-service` at all.

Not every Tier 2 policy needs `mxc-service`. Proxy-cooperative
policies — "proxy URL + capability strip", no `allowedHosts` /
`blockedHosts` / `protocols` — go through the SDK's no-service path
and never trip the install error above. Policies that use
`allowedHosts` / `blockedHosts` / `protocols` are the ones that
require `mxc-service` on Tier 2 and hit the error path when it isn't
installed.

#### 4.4.1 Versioning and SDK / `mxc-service` skew

`mxc-service` is **backwards compatible**: a service update never
breaks functionality on an already-installed SDK. Existing consumers
keep working after `mxc-service` is upgraded, and a newer service
serves every IPC major/minor at or below its own.

Forward skew is the only case that errors. The IPC contract carries
an RPC `(major, minor)` field, and `IMxcNetService::GetVersion`
returns `{ service_version, ipc_major, ipc_minor }`. If an SDK needs
a method or field that the installed service doesn't expose, the SDK
fails the call with an actionable error pointing at the
`mxc-service` install/update URL — it does not silently degrade for
required features. Optional features may degrade and surface a
warning.

`minimumSecureServiceVersion` embedded in the SDK is the one
exception to backwards compatibility: the SDK refuses any service at
or below that floor regardless of major/minor, so npm-side CVE
advisories propagate ("update the npm package *and* the
`mxc-service` package"). The SDK's error text includes the CVE
number.

There is exactly one installed `mxc-service` per machine. If two
projects pin SDKs that require a service version newer than the
installed one, the operator resolves it with a single service
upgrade; we do not sidecar multiple service versions.

## 5. What we cannot do at GA

This list is the GA contract; each item is the answer to a "why not?"
question from a partner integrator.

- **Block HTTP CONNECT tunneling on TCP/443 to arbitrary hosts.** The
  forward proxy AppContainer sees opaque bytes after the `200 Connection
  established`. If the user's proxy permits `CONNECT host:443`, anything
  (SSH-over-443, custom protocols) tunnels through. mitmproxy default
  permits this; squid is configurable. The proxy AppContainer is the
  user's chosen policy boundary; OS-level L7 enforcement on top of a
  user-chosen proxy belongs at the wrong layer.
- **Filter by DNS name.** The firewall scope is IPs. We can advertise
  "allowedHosts" in the schema only if MXC resolves at policy-apply time
  and pins the resolved IPs as filters; the staleness window then
  becomes a policy property the operator must understand. We propose
  IP-only at GA and revisit DNS in a follow-up.
- **Classify HTTP vs SSH on the same port.** Requires a kernel
  callout driver, out of scope (section 3.3).

## 6. Design

### 6.1 Schema

Today's stable schema (0.6.0-alpha) already accepts `network.allowedHosts`
and `network.blockedHosts` as string arrays, but the `processcontainer`
backend rejects them at runtime. We unblock both with explicit IP
semantics, tighten the item type from a free-form string to a structured
`HostRule`, and add a sibling `protocols` allow-list. Default posture
stays `network.defaultPolicy = "block"` (already deny-by-default since
SDK 0.3.0); `allowedHosts` carves in, `blockedHosts` carves out, and the
deny rules take precedence over the allows. `internetClient` continues
to live in `processContainer.capabilities` — there is no new network-level
`internetClient` knob. The additions go into the in-flight dev schema:

```jsonc
"network": {
  // existing: defaultPolicy, enforcementMode, allowLocalNetwork, proxy ...
  "allowedHosts": {
    "type": "array",
    "items": { "$ref": "#/$defs/HostRule" }   // tightened from "string"
  },
  "blockedHosts": {
    "type": "array",
    "items": { "$ref": "#/$defs/HostRule" }   // tightened from "string"
  },
  "protocols": {                              // new
    "type": "array",
    "items": { "$ref": "#/$defs/Protocol" }
  }
}
```

`HostRule` is `{ address: ipv4|ipv6|"*", prefixLength: uint8|null, port: uint16|0 }`;
when `prefixLength` is set the rule matches the CIDR range
`address/prefixLength` (1..32 for IPv4, 1..128 for IPv6). `Protocol` is
`{ transport: "tcp"|"udp", ports: uint16[] }`. Tightening the item type
is a breaking change for any caller already passing string hosts to
`processcontainer`; since the backend rejects them today, the practical
break is zero.

Tier selection is automatic and not user-configurable: the SDK uses
Tier 1 when `CreateProcessInSandbox` is present on the build and
falls back to Tier 2 otherwise. There is no opt-in to pin Tier 2 on
a Tier-1-capable machine — that would contradict the "Tier 1 is the
forward surface, Tier 2 is downlevel parity" policy in section 4. An
operator who wants to refuse Tier 2 entirely simply does not install
`mxc-service`.

Validation rejects:

- `processContainer.capabilities` containing `"internetClient"` while any
  of `network.allowedHosts`, `network.blockedHosts`, or `network.protocols`
  is set (contradiction — `internetClient` is "open the door");
- DNS names in `allowedHosts[].address` / `blockedHosts[].address`
  (GA is IP-literal only).

The loopback-proxy AppContainer SID needed by the OS is derived
internally by `mxc-exec` from the sandbox principal and threaded into
the FlatBuffer `proxy_info` (section 6.3); it is not part of the
user-facing config schema.

### 6.2 MXC plumbing

- The AppContainer-runner and BaseContainer-runner validators today
  reject `allowedHosts` / `blockedHosts` with a "not supported on
  processcontainer" message. Replace both rejects with actual
  enforcement.
- The AppContainer-runner network manager already generates per-AppContainer
  `INetFwRule3` rules from the existing rules surface. Two changes:
  (a) extend it to consume the new `allowedHosts` / `blockedHosts` /
  `protocols` fields, and (b) move the actual `INetFwRule3` calls out
  of the MXC-elevated launch path and into the `mxc-service` via LRPC,
  so the launch path itself never needs admin.
- The BaseContainer-runner stays the same shape: it builds the
  FlatBuffer `NetworkPolicy` (section 6.3) and hands it to the OS; the OS
  enforces inside `CreateProcessInSandbox`.
- The fallback detector already picks tier; no change.
- New crate `crates/mxc-service/` for the LRPC service binary.

### 6.3 FlatBuffer schema (the spec `CreateProcessInSandbox` parses)

Today the relevant `SandboxSpec` carries a `NetworkPolicy` wrapping a
bare `proxy_info { url }`. We extend `proxy_info` with the
AppContainer SID the proxy listener binds to, and extend
`NetworkPolicy` with the three new policy shapes:

```fbs
enum Transport : byte { Tcp, Udp }

// prefix_length 0 means "host match" on `address`; otherwise a CIDR
// range. The OS lowers this to FWP_V4_ADDR_AND_MASK /
// FWP_V6_ADDR_AND_MASK on the FWPM_CONDITION_IP_REMOTE_ADDRESS condition.
table HostRule { address: string; prefix_length: uint8 = 0; port: uint16 = 0; }
table ProtocolFilter { transport: Transport; ports: [uint16]; }

table proxy_info {
  url:               string;        // existing
  app_container_sid: string;        // new
}

table NetworkPolicy {
  proxy:           proxy_info;      // existing
  allowed_hosts:   [HostRule];      // new
  blocked_hosts:   [HostRule];      // new
  protocols:       [ProtocolFilter];// new
}
```

### 6.4 Tier 1 enforcement — what the OS adds inside `CreateProcessInSandbox`

`CreateProcessInSandbox` runs in an OS service with an existing
network-policy stage (today it applies the proxy URL) and will apply
bidirectional loopback rules for the proxy-AppContainer pattern as
discussed in section 1.2. The new ask: extend that stage so that,
after the sandbox's AppContainer SID is known and before the target
process is started, the OS applies the `NetworkPolicy` from the
FlatBuffer as a set of per-AppContainer outbound filters at the
standard ALE connect-authorization layer (IPv4 and IPv6 in parity).

Design points the spec depends on:

- **Per-AppContainer scoping.** Filters are scoped to the sandbox's
  AppContainer SID. They cannot affect any other process.
- **Default-deny baseline.** AppContainer's capability-driven outbound
  posture (including `internetClient`) does not provide deny-by-default
  at the firewall — the OS layer applying the `NetworkPolicy` does.
  No rule = no outbound; `allowed_hosts` carves explicit holes in
  that baseline.
- **CIDR + port + protocol expressivity.** Host match or CIDR range,
  optional port, TCP/UDP per the rule. On overlap, `blocked_hosts`
  wins over `allowed_hosts`.
- **Lifetime tied to the sandbox process.** The contract is: when the
  sandbox process exits, the OS removes the filters with no caller
  cleanup. The specific mechanism is an implementation choice for the
  `CreateProcessInSandbox` team, not a contract this spec dictates.

### 6.5 OS feature-query API (new ask, Tier 1 only)

Required to make the "fail loud on version skew" guarantee
(requirement 3 in section 1.4) implementable. Without this, the SDK has no
way to know whether the current `CreateProcessInSandbox` honors a
given `NetworkPolicy` field on this build before the launch happens.

**The ask:** a pure-query, side-effect-free, no-privilege-required
API on the same OS-side surface that ships `CreateProcessInSandbox`,
returning a feature bitmap. One bit per `NetworkPolicy` capability:
host allow-list, host block-list, protocol filter, proxy-loopback
pair, IPv6 parity, and any further capabilities added in later
spec revisions.

**Contract.**

- Always present whenever `CreateProcessInSandbox` is present —
  both land in the same servicing payload, so the SDK never sees the
  two out of sync on the same machine.
- The OS sets a bit only when the capability is end-to-end functional
  on this build (no partials, no preview half-states). A missing bit
  means the SDK rejects the launch loudly before calling
  `CreateProcessInSandbox`.
- Additive over time — only new bits, never repurposed.

**SDK use.** Before each launch the SDK queries the bitmap, computes
the bits required by the requested policy, and errors with a typed
"unsupported network feature" message if any bit is missing. On
Tier 2 the bitmap is constant — everything in this spec's table —
because `mxc-service` ships its own implementation.

**Operator probe.** The MXC probe CLI exposes the result as JSON
(tier in use, Tier 1 feature bits supported on this build, Tier 2
feature bits supported by the installed service). Operators run it to
find out *why* a launch was rejected.

**Why not just version-number the API.** Build numbers don't survive
chassis upgrades / OS rollbacks cleanly, Tier 2 servicing branches
can backport individual capabilities, and the SDK should not have to
maintain a "feature X landed in build Y" table for every Windows
build. A bitmap reported by the OS itself is the only stable answer.

### 6.6 Tier 2 enforcement

Same WFP mechanism as Tier 1 (section 6.4), executed by `mxc-service` (section 4).
The SDK creates the sandbox suspended, sends the policy plus the
sandbox process handle to `mxc-service`; the service applies the
filters scoped to the sandbox's AppContainer SID, anchors filter
lifetime to the sandbox process itself (section 3.2), and acks. The SDK
then resumes the sandbox. Sandbox exit reaps the filters with no
caller cleanup and no firewall-policy-store writes. If section 8.3 comes
back unfavorable, this section degrades to the `INetFwRule3`
fallback described in section 3.2.

### 6.7 IPC contract

The IPC surface is the minimum needed for the section 6.6 flow: one call to
apply a policy (per-AppContainer-SID rules + a sandbox process
handle, returning a policy ID), one to remove a policy, one to
query the service's version. The apply call is
per-sandbox carrying the full rule set; the service does not expose a
per-rule surface because filter lifetime is bound to the sandbox
process, not to individual rules.

The returned policy ID is an opaque GUID the service mints per
successful `MxcAddPolicy`. It identifies the per-sandbox rule batch
(and the WFP filters and sublayer the service stood up for it) so a
later `MxcRemovePolicy` can revoke exactly that batch without
disturbing other sandboxes. The SDK holds it for the sandbox's
lifetime and passes it back on teardown.

Sketch of the three verbs `mxc-exec.exe` calls — not normative, the
implementation contract lives in the eventual IDL:

```
typedef enum { MxcRuleAllow, MxcRuleBlock } MXC_RULE_VERB;
typedef enum { MxcTransportTcp, MxcTransportUdp, MxcTransportAny } MXC_TRANSPORT;

typedef struct {
    MXC_RULE_VERB  verb;
    MXC_TRANSPORT  transport;
    PCWSTR         address;        // IPv4 / IPv6 literal, or NULL = any
    BYTE           prefixLength;   // 0 = host match; else CIDR
    USHORT         port;           // 0 = any
} MXC_RULE;

HRESULT MxcAddPolicy(
    [in]  PCWSTR              appContainerSidSddl,
    [in]  HANDLE              sandboxProcess,
    [in]  DWORD               ruleCount,
    [in]  const MXC_RULE*     rules,
    [out] GUID*               policyId);

HRESULT MxcRemovePolicy(
    [in]  REFGUID             policyId);

HRESULT MxcGetVersion(
    [out] DWORD*              serviceVersion);
```

`sandboxProcess` is the live handle the SDK already holds on the
suspended sandbox process; the service uses it for the engine-handle
duplication described in section 3.2 and for lifetime anchoring.

`MxcGetVersion` returns only a version number — no feature bitmap.
Per the section 4 Tier 1/Tier 2 policy, Tier 2 freezes at GA baseline,
so every installed `mxc-service` exposes the same surface. The SDK
only needs to confirm the service is present and recent enough to talk
to; the section 6.5 bitmap exists for Tier 1 negotiation against
varying in-OS builds and has no analogue here.

Transport is LRPC over a local `ncalrpc` endpoint ACL'd to
`BUILTIN\Users` for defense-in-depth (see section 4.2). The real
caller policy is the three-layer authentication described in
section 4.3, which the service runs per call before doing any WFP
work — that is what determines whether a given caller binary (e.g.
`mxc-exec.exe`) is allowed in, not the endpoint ACL. The sandbox
process handle is marshaled across the IPC boundary via the RPC
runtime's native handle-transfer primitive so the service receives a
kernel-validated handle, not a PID it would have to reopen.

## 7. Test plan

Unit / component (new):
- AppContainer-runner network manager: rule generation against schema
  permutations (allow+block both set → reject; DNS in address → reject;
  etc.).
- `mxc-service` MIDL surface — fuzz inputs, verify the 200-rule/5000-rule caps,
  verify `RemovePolicy` on someone-else's-GUID fails, verify image
  verification denies an unsigned caller.

Integration (new):
- Two-sandbox concurrency test: spawn AppContainer SID A and AppContainer SID B with
  disjoint policies; from each, attempt connect to the other's allowed
  endpoint; verify reject. Repeat on Tier 1 and Tier 2.
- Loopback-proxy SSH bypass test (extend the OS-side proxy E2E test
  already in the Tier 1 enforcement path).
- `mxc-service` crash-recovery: kill `mxc-service` mid-launch, verify in-flight
  sandboxes keep their WFP filters (sandbox holds the anchor); kill
  `mxc-service` between launches, restart, verify next sandbox launch
  succeeds. In the section 3.2 fallback path, kill `mxc-service` after rule
  add, restart, verify orphaned `MXC_*` rules are swept against the
  SDK's live-sandbox set.

Stress:
- 200 concurrent sandbox launches → filter count ceiling enforced;
  no BFE engine corruption. (Fallback path: no firewall-store
  corruption.)

Security:
- Hostile-caller test: medium-IL test process not signed by MXC publisher
  connects to LRPC endpoint, asserts every method returns
  `E_ACCESSDENIED`.
- Cross-sandbox tamper: caller A tries to `RemovePolicy` a GUID added by
  caller B → `E_ACCESSDENIED`.

## 8. Open questions

1. Caller-binary verification (section 4.3) performance on hot path.
   Trust-chain extraction is not free; may need to cache by
   `(PID, image SHA)` for the lifetime of the caller process.
2. IPv6 parity end-to-end: confirm the firewall path used by
   `mxc-service` (whether the WFP path in section 3.2 or the
   `INetFwRule3` fallback) accepts IPv6 literals on the address field
   with no separate v6 code path.
3. **WFP engine handle cross-process semantics (section 3.2
   feasibility).** The Tier 2 design in section 3.2 anchors filter
   lifetime to the sandbox by duplicating the WFP engine handle from
   `mxc-service` into the (suspended) sandbox process and then closing
   the service's reference. None of the following is documented; we
   need a two-process PoC against a live BFE before committing:
   (a) whether the engine session survives cross-process handle duplication;
   (b) whether dynamic filters stay alive after the creating service closes its handle while the duplicate stays open;
   (c) whether filters are reaped on sandbox process exit;
   (d) whether the duplicated handle can be granted minimal / non-mutating access so the sandbox cannot use it to add or remove filters;
   (e) consistency of BFE behavior across 23H2, 24H2, 25H2, and current Insider builds.
   If any come back unfavorable, Tier 2 degrades to the `INetFwRule3`
   fallback described in section 3.2 — the schema and the
   `mxc-service` IPC contract are unchanged; only the service's
   post-`AddPolicy` behavior changes, and `mxc-service` adds a startup
   sweep that reconciles `MXC_*` rules against the SDK's live-sandbox
   SID set.
4. **Distribution channel for `mxc-service` (section 4.4).** Working
   assumption: signed MSI distributed via **winget**
   (`winget install Microsoft.MXC.Service`) with `aka.ms/mxc-service`
   direct download as backup for offline / air-gapped operators.
   Microsoft Store as a Win32 app and MSIX with
   `<uap5:Extension Category="windows.service">` (needs
   `packagedServices` restricted capability + Store policy 10.2.4
   approval) both stay open as future surfaces. Open until the
   distribution team confirms.
5. **Multi-protocol proxy support beyond HTTP/HTTPS (section 1.1(c) stretch
   goal).** The per-AppContainer proxy hook lives in WinHTTP, so the
   GA proxy story only covers HTTP/HTTPS. Extending the same
   proxy-on-loopback pattern to SOCKS, raw TCP, and longer-tail
   protocols would let a single proxy AppContainer inspect arbitrary
   sandbox egress. Depends on new OS surfaces outside MXC's control;
   not committed for GA. Open until the relevant networking teams
   weigh in.
6. **Schema shape: three lists vs. unified outbound rules.** We could
   collapse `allowedHosts` / `blockedHosts` /
   `protocols` into a single `outbound: { default, allow[], block[] }`
   with transport and port carried per rule. Cleaner (no cross-list
   interaction to reason about); cost is a breaking change to the
   0.7.0-dev schema, validator, and FlatBuffer mapping. Open until the
   schema reviewer weighs in; if accepted, defer to a 0.8.x cut so the
   change lands as one revision.
7. **`mxc-service` identity: how far down the privilege ladder can the
   runtime service go (section 4.1)?** The preferred design is a
   write-restricted virtual service account (`SERVICE_SID_TYPE_RESTRICTED`
   `NT SERVICE\mxc-service` hosted in a `LocalService` svchost group,
   `RequiredPrivileges` trimmed to the floor), with the MSI granting
   the service SID WFP rights via `FwpmEngineSetSecurityInfo0`. Walk
   the fallback ladder (4.1) until empirical validation against a live
   BFE clears each rung. Three things need a live-BFE check before
   committing: (a) whether built-in `FWPM_LAYER_ALE_AUTH_CONNECT_V4/_V6` layer
   objects carry non-inherited restrictive ACEs that override an
   engine-root grant (probe with `FwpmLayerGetSecurityInfoByKey0`);
   (b) whether a non-`SYSTEM` broker can still `DuplicateHandle` into
   the sandbox process across the integrity boundary if the section
   3.2 handle-anchoring lands; (c) whether `PROCESS_DUP_HANDLE` to the
   medium-IL caller process (needed for the SDK to marshal the sandbox
   handle back) succeeds at the lower identity, including under
   `SERVICE_SID_TYPE_RESTRICTED`. Schema, IPC contract, and section
   4.3 defenses are unchanged at every rung.

## 9. Prior art: OpenAI Codex Windows sandbox

OpenAI shipped a Windows sandbox for Codex
(<https://openai.com/index/building-codex-windows-sandbox/>). Its
network isolation is per-launch, like MXC's, but built on a different
Windows primitive.

| Axis | OpenAI Codex sandbox | MXC (this spec) |
| --- | --- | --- |
| Sandbox principal | Local Windows user (`CodexSandboxOffline` / `CodexSandboxOnline`), created at setup | AppContainer SID, minted per launch |
| Why not AppContainer | Rejected — Codex drives open-ended developer tools (shells, Git, Python), wrong shape | Accepted — MXC's constrained workload makes the tax acceptable |
| Network rule scope | Windows Firewall, scoped to the synthetic Windows user | WFP, scoped to the AppContainer SID |
| First network attempt | Env-var poisoning (`HTTPS_PROXY=http://127.0.0.1:9`, fake `GIT_SSH_COMMAND`, `denybin` on PATH) — abandoned as advisory | Skipped; section 3 commits to WFP for the same reason |
| Admin requirement | Setup only (create users, store DPAPI creds, write firewall rules) | Tier 1: none. Tier 2: once at service install |
| Launch-time helper | `codex-command-runner.exe`, spawned as the sandbox user via `CreateProcessWithLogonW`, to call `CreateRestrictedToken` + `CreateProcessAsUserW` | `mxc-exec.exe` calling `CreateProcessInSandbox` (Tier 1) or RPC into `mxc-service` (Tier 2) |
| Policy expressiveness | Binary: online or offline | Per-launch allow/block host + port lists |

Both designs hit the same Windows Firewall limit, which OpenAI states
directly: *"Windows doesn't allow matching a firewall rule to the
non-principal identity of a restricted token."* They work around it by
running sandboxed code as a synthetic Windows user so user-scoped
rules apply; MXC uses the AppContainer SID as the WFP principal.

### 9.1 Security trade-off

Codex's one-time elevated setup with no runtime privileged process is
not strictly better security than MXC's always-on installed service;
they allocate attack surface differently. Codex pays for the absence
of a live privileged endpoint with persistent local users, DPAPI
credentials on disk (DPAPI protects against offline attackers, not
same-user code), static firewall rules that can drift between
launches, and a `CreateProcessWithLogonW` path with no caller
authentication. MXC Tier 2 pays for per-launch policy and three-layer
caller auth (section 4.3) with an RPC endpoint reachable from medium
integrity. Tier 1 is outside this trade-off: no service, no users, no
stored credentials, no RPC endpoint, no admin at any point.

