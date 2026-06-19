# Process Container Networking — Windows Implementation (GA)

**Status:** draft for review · **Owner:** bbonaby · **Scope:** `processcontainer` backend only.

> Implementation companion to the parent **MXC Network Configuration, GA** doc, which owns the
> shared policy schema, the three connectivity models, and the GA goal (model 2 — deny-all-except-
> proxy). This doc covers only how the Windows `processcontainer` backend enforces those models
> across current, future, and downlevel Windows builds. Schema, design decisions (D1–D8), and
> cross-platform gaps are referenced, not repeated.

## 1. What this backend delivers at GA

Per sandbox, scoped to the sandbox's AppContainer (AC) SID, with **no UAC prompt per launch**, via
two enforcement primitives:

- **WFP outbound filters** — default-deny; allow/block by IP-literal/CIDR + transport + optional
  port (single or inclusive range), IPv4/IPv6 parity, explicit block beats allow. Scoped to the AC SID.
- **Per-AppContainer WinHTTP HTTP/S proxy** — points WinHTTP-stack clients (e.g. the WinHTTP/Chromium
  stack) at a caller-provided loopback proxy AppContainer. The one app-aware path Windows gives us out
  of the box; non-WinHTTP traffic is governed by the WFP filters, never proxied.

### 1.1 What `processcontainer` configures per connectivity model

Each model is a concrete set of AppContainer network capabilities + enforcement. Example configs use
the parent doc's proposed `network` schema.

**Model 1 — direct egress, WFP-filtered (least restrictive).** Grant the AC the `internetClient`
capability (and no other network capability) plus a loopback exemption for same-AC connections; WFP
carries the allow/block rules. No proxy.

```jsonc
{
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        { "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ] }
      ]
    },
    "ingress": { "hostLoopback": "deny" }
    // no "proxy" — direct egress, filtered by WFP
  }
}
```

**Model 2 — proxy-only egress (GA recommended).** Grant the AC **no** `internetClient` (and no other
network capability) plus loopback exemptions for inter-AC (to the proxy AC) and intra-AC
communication, and set the per-AC WinHTTP proxy. With no `internetClient`, the only reachable egress
is the loopback proxy; the system drops everything else.

```jsonc
{
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "hostLoopback": "deny" },
    "proxy": { "http": "127.0.0.1:8080" }
  },
  "processcontainer": {
    "allowedSandboxes": [ "S-1-15-2-…" ]   // AC SID of the loopback proxy
  }
}
```

**Model 3 — fully blocked (most restrictive).** Add no network capabilities and no loopback
exemptions; no proxy. All outbound and inbound is dropped.

```jsonc
{
  "network": {
    "egress": { "default": "deny" },   // no allow rules
    "ingress": { "hostLoopback": "deny" }
    // no "proxy", no network capabilities granted
  }
}
```

### 1.2 Out of GA scope for this backend

Do not infer otherwise from the schema:

- **Transparent TCP/UDP redirection through the proxy** — future; hard OS dependency (§5 #1). GA
  proxying is WinHTTP HTTP/S only.
- L7 classification (e.g. HTTPS vs SSH on :443).
- Durable DNS-name rules.
- Encrypted-payload inspection.
- Inbound/listening policy.

The last four are cross-platform non-goals owned by the parent doc.

## 2. Two enforcement paths: current vs downlevel

Both (a) WFP filter writes and (b) per-AppContainer WinHTTP proxy configuration require a
**privileged context**. *How* that privilege is obtained is the entire implementation story for
this backend, and it splits by Windows build:

- **Tier 1 — the OS applies the policy in-process.** On builds that expose the OS sandbox-creation
  API (`CreateProcessInSandbox`), the OS itself, in its own elevated context, applies the
  per-sandbox WFP filters and wires the WinHTTP proxy *before* the target process runs. No MXC-side
  privileged component, no UAC; filter lifetime is owned by the OS and bound to the sandbox process.
  This is the preferred path and where new capability lands first.
- **Tier 2 — downlevel parity.** On builds without that API, MXC still owes the same GA policy. The
  enforcement primitives exist (AppContainer-scoped WFP, per-AC WinHTTP), but applying them from
  medium-IL `mxc-exec.exe` requires elevation — and prompting UAC on every sandbox launch is
  unacceptable for an interactive agent workflow. **How to obtain that privilege downlevel without
  per-launch UAC is an open design problem (§4), not a settled mechanism.** Today MXC has neither a
  complete Tier 2 enforcement path nor a decided elevation story; it currently raises one UAC per
  launch via an elevated WinHTTP shim, which is exactly what must be replaced.

There is **no third "best-effort" / advisory mode.** Per the parent doc's D1/D7, a configuration the
backend cannot actually enforce is rejected, not run advisory. Cooperative env-var proxy hints
alone do not satisfy the GA proxy or outbound-enforcement commitments.

### 2.1 Fail loud on version skew — never silently downgrade

`CreateProcessInSandbox` is not a single build; its network-policy surface grows over time. A
machine can expose the API but not yet honor a specific policy field MXC asks for. The SDK must
**not** silently fall back to Tier 2 in that case — the two paths have different security and
cleanup properties and the operator would not know. The contract:

- Fall back to Tier 2 only when the API is **absent on the build** — not when it is present but
  missing a requested field.
- For a present-but-incomplete API, the SDK rejects the launch with a typed error **naming the
  missing capability**.

This requires an **OS feature-bitmap query** (one bit per policy capability) that ships with
`CreateProcessInSandbox` — see §5 #4. On Tier 2 the supported set is fixed (whatever the GA Tier 2
path implements), so only Tier 1 needs the probe.

## 3. WFP is the enforcement primitive (both tiers)

Outbound policy is enforced with WFP user-mode filters (`Fwpm*`) at
`FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6` — the standard `connect()`-time authorization point —
scoped to the sandbox via the `FWPM_CONDITION_ALE_PACKAGE_ID` (AppContainer SID) condition. The
AppContainer SID is the per-sandbox identity available at filter-add time; Windows applies the
filters only to outbound traffic from that one sandbox.

- **Admin requirement.** Adding WFP filters is admin-only (the BFE engine access check). On Tier 1
  this is satisfied inside the OS service; on Tier 2 it is the open problem of §4.
- **Cleanup.** Filters added against a dynamic/session engine handle are reaped when the handle
  closes (and BFE auto-closes the handle of an exited process), so filter lifetime ≤ sandbox
  lifetime with no caller cleanup. Tier 1 relies on this; a Tier 2 implementation must reproduce
  equivalent process-bound cleanup.
- **What WFP cannot do here.** Connect-time authorization sees endpoint + transport metadata, not
  payload, so it cannot classify L7 protocols, match DNS names, or inspect encrypted content;
  ordinary filters return permit/block and cannot *rewrite/redirect* a destination (that needs a
  callout — see §5 #1). These limits are the Windows reason behind the cross-platform non-goals in
  the parent doc.

## 4. Open problem — privileged enforcement downlevel (Tier 2) — DECISION OPEN

> This section is deliberately a **problem statement with options, not a chosen design.** It needs
> networking/security reviewer feedback before anything here is committed, and it overlaps the
> separate **MXC elevation design** prerequisite called out in the parent doc (the elevation
> caveat under D2): the per-platform, per-technology elevation story is not solved here.

**Problem.** Downlevel, the WFP and WinHTTP mutations that enforce GA policy need elevation, and
per-launch UAC is unacceptable. "Run something elevated once" is easy; the hard part is the
**trust model around it**:

- **Should MXC own a privileged service at all?** A long-running MXC-owned elevated broker is one
  answer, but it is an always-on privileged attack surface and an ownership/servicing burden. Is
  this MXC's responsibility, or should the privilege come from the OS/platform (the Tier 1 model,
  extended downlevel) so MXC never hosts a broker?
- **Authenticating the caller.** The IPC client is **medium-IL and unpackaged** — no AppContainer
  SID, no MSIX identity, nothing the kernel can vouch for. A hostile same-desktop process can copy
  the client binary, inject into it, or spoof its image path. There is no perfect "trust a
  medium-IL caller" primitive; any broker must assume the caller may be hostile and bound the blast
  radius.
- **Ensuring the user/caller isn't malicious.** Even a correctly-identified caller is driven by a
  user who must not be able to use the broker to widen their own privileges — e.g. apply filters to
  a SID they don't own, tear down another sandbox's policy, or coax a privileged side effect.
- **Who may talk to the broker, and who decides policy** — and how that gate is enforced — is
  unresolved.

**Options (no decision made):**

| Option | Upside | Open risk / why not obviously right |
|---|---|---|
| Per-launch elevated shim (today) | simplest | UAC per launch — already rejected |
| COM elevation moniker | OS-mediated | still prompts; doesn't solve the medium-IL caller |
| Long-running MXC service (e.g. restricted `LocalService` + local RPC) | no per-launch UAC | always-on privileged endpoint; **caller-auth is unsolved** (medium-IL spoof/TOCTOU); is owning a service even MXC's job? |
| OS extends the Tier 1 in-process model downlevel | no MXC broker at all | OS-backport timeline; may not land for GA |
| OS relaxes the WFP user-mode admin gate | no broker needed | long-shot networking-team ask; the admin gate is long-standing |

**If the service route is chosen,** caller authentication is the load-bearing piece and is itself
only *partially* answerable today. Candidate defenses — verify the caller's signed binary at IPC
time, expose a deliberately narrow API (add/remove/version only), scope every filter to the
caller-named AppContainer SID, reject cross-caller teardown, resolve no names, expose no
read/enumerate API — bound the damage, **but** have known gaps to close before GA: TOCTOU between
checking the on-disk image and the running image, leaf-vs-root publisher pinning, endpoint ACLs,
and reliance on under-documented "PID from IPC" APIs. These gaps are *why the decision is open*,
not a finished design.

**Recommendation to reviewers:** prefer keeping privilege in the OS (Tier 1) and treating the
downlevel elevation story as the separate MXC elevation design doc the parent doc already
requires, rather than committing MXC to own a privileged networking broker. Open for discussion.

## 5. Open asks to the OS networking team

GA and post-GA both depend on OS-owned primitives MXC should consume rather than build:

1. **Transparent TCP/UDP proxy redirection — FUTURE, not GA.** Per-AppContainer transparent
   outbound redirection of arbitrary TCP streams and UDP datagrams to the loopback proxy, without
   app cooperation, preserving original destination + originating AC identity, preventing
   direct-egress bypass and redirect loops, per-sandbox and removed on exit. The likely
   implementation class is a WFP **ALE connect-redirect callout**; MXC should **ask for an inbox,
   OS-owned primitive `CreateProcessInSandbox` can consume**, not ship and service its own kernel
   driver. ICMP/raw IP stay block-only. *(This is the capability previously framed as an at-risk GA
   item; it is explicitly out of GA.)*
2. **Per-AppContainer WinHTTP lifecycle APIs — GA dependency.** GA's WinHTTP proxy path needs
   (a) a **per-policy delete** so MXC can tear down exactly the policy it set without clobbering
   other entries on the shared WinHTTP connection-policy tag, and (b) a **non-clobber interface
   bind** so the per-AC proxy can be pinned to the loopback interface without delete-all-and-replace.
   These are open dependencies, tracked as GA blockers.
3. **AC→AC loopback scoping.** Use `NetworkIsolationCreateAppContainerLoopbackRules` (scoped to the
   specific AC→AC pair) for the sandbox↔proxy loopback exemption instead of the system-wide
   `NetworkIsolationSetAppContainerConfig` (which also permits AC→non-AC traffic). Needed in the OS
   Tier 1 path and in any Tier 2 path.
4. **Feature-bitmap query** alongside `CreateProcessInSandbox` (see §2.1): pure-query, no-privilege,
   one bit per *end-to-end-functional* policy capability, additive over time.
5. **(Long shot) Relax the WFP user-mode admin gate** so per-AppContainer filters can be set without
   elevation — would remove the need for any downlevel broker (§4).

## 6. Schema mapping — Windows-specific notes

The policy schema is defined in the parent doc and is container-type-agnostic (D7). Only the
Windows-specific bindings are noted here:

- **Proxy AppContainer SID / AC→AC loopback.** The proxy peer (`processcontainer.allowedSandboxes`)
  is how MXC installs the directional loopback exemption that lets the sandbox reach the loopback
  proxy while AppContainer loopback is otherwise blocked. An external proxy must run inside an
  AppContainer; an MXC-managed proxy derives the SID internally.
- **`internetClient` × WFP — open PoC (GA-blocking).** Determine whether an explicit WFP permit can
  authorize public-network egress on its own, or whether the coarse AppContainer `internetClient`
  capability must also be present. The backend must enforce the *proven* rule and return a typed
  configuration error when the required capability combination is missing — never silently
  broadening the sandbox. The schema must not treat `internetClient` and an outbound policy as
  inherently contradictory.

*(The internal FlatBuffer / IPC rule encodings mirror the public rule model 1:1 and are an
implementation detail, intentionally not specified here.)*

## 7. Open questions

1. `internetClient` × WFP authorization (§6) — GA-blocking PoC.
2. The downlevel privileged-enforcement decision (§4), including caller authentication — **open,
   needs feedback**; overlaps the separate MXC elevation design.
3. Transparent TCP/UDP redirection primitive (§5 #1) — future; needs networking-team ownership.
4. WinHTTP per-policy delete + non-clobber interface bind (§5 #2) — GA dependency.
5. IPv6 parity end-to-end (literal/CIDR, loopback, TCP/UDP/ICMPv6).
6. Per-launch AppContainer-SID uniqueness on Tier 2 (Tier 1 mints an ephemeral SID per launch;
   Tier 2 derives it from a caller-supplied id, so MXC must generate a unique per-launch profile
   name for crash-recovery reconciliation to rely on SID uniqueness).
7. Inbound/listening policy — separate post-GA contract; must not be inferred from outbound.
