# Process Container Networking: Windows Implementation (GA)

**Status:** draft for review · **Owner:** bbonaby · **Scope:** `processcontainer` backend only.

> Implementation companion to the parent **MXC Network Configuration, GA** doc, which owns the
> shared policy schema, the three connectivity models, and the GA goal (model 2, deny-all-except-
> proxy). This doc covers only how the Windows `processcontainer` backend enforces those models
> across current, future, and downlevel Windows builds. Schema, design decisions (D1-D8), and
> cross-platform gaps are referenced, not repeated.

## 1. What this backend delivers at GA

Each sandbox gets two enforcement primitives, scoped to its container SID and applied with **no UAC
prompt per launch**:

- **WFP outbound filters**: default-deny; allow/block by IP-literal/CIDR + transport + optional
  port (single or inclusive range), IPv4/IPv6 parity, explicit block beats allow. Scoped to the container SID.
- **Per-container WinHTTP HTTP/S proxy**: points WinHTTP-stack clients (e.g. the WinHTTP/Chromium
  stack) at a caller-provided loopback proxy container. The one app-aware path Windows gives us out
  of the box.

### 1.1 What `processcontainer` configures per connectivity model

Each model is a specific combination of container network capabilities and enforcement. Example
configs use the parent doc's proposed `network` schema.

**Model 1: direct egress, WFP-filtered (least restrictive).**

- **Capabilities:** `internetClient`, plus a loopback exemption for same-container connections; no
  other network capability.
- **Enforcement:** WFP allow/block rules; no proxy.

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
    // no "proxy": direct egress, filtered by WFP
  }
}
```

**Model 2: proxy-only egress (recommended).**

- **Capabilities:** no `internetClient`; loopback exemptions for inter-container (to the proxy
  container) and intra-container communication; no other network capability.
- **Enforcement:** the per-container WinHTTP proxy. With no `internetClient`, the only reachable
  egress is the loopback proxy; the system drops everything else.

```jsonc
{
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "hostLoopback": "deny" },
    "proxy": { "http": "127.0.0.1:8080" }
  },
  "processcontainer": {
    "allowedSandboxes": [ "S-1-15-2-…" ]   // container SID of the loopback proxy
  }
}
```

**Model 3: fully blocked (most restrictive).**

- **Capabilities:** none; no loopback exemptions.
- **Enforcement:** no proxy; all outbound and inbound dropped.

Since deny-all is the default, model 3 is also the result of providing no network policy at all:
the explicit form, an omitted `network` block, and an empty `"network": {}` are equivalent:

```jsonc
// explicit
{
  "network": {
    "egress": { "default": "deny" },   // no allow rules
    "ingress": { "hostLoopback": "deny" }
    // no "proxy", no network capabilities granted
  }
}
```

```jsonc
// equivalently (model 3 is the default): "network" omitted, or empty
{ /* no "network" key at all */ }
// or
{ "network": {} }
```

### 1.2 Out of GA scope for this backend

Do not infer otherwise from the schema:

- **Transparent TCP/UDP redirection through the proxy.** GA proxying is WinHTTP HTTP/S only.
- L7 classification (e.g. HTTPS vs SSH on :443).
- Durable DNS-name rules.
- Encrypted-payload inspection.
- Inbound/listening policy.

The last four are cross-platform non-goals owned by the parent doc.

## 2. Two enforcement paths: current vs downlevel

Both (a) WFP filter writes and (b) per-container WinHTTP proxy configuration require a
**privileged context**. *How* that privilege is obtained is the entire implementation story for
this backend, and it splits by Windows build:

- **Tier 1: the OS applies the policy in-process.** On builds that expose the OS sandbox-creation
  API (`CreateProcessInSandbox`), the OS itself, in its own elevated context, applies the
  per-sandbox WFP filters and wires the WinHTTP proxy *before* the target process runs. No MXC-side
  privileged component, no UAC; filter lifetime is owned by the OS and bound to the sandbox process.
  This is the preferred path and where new capability lands first.
- **Tier 2: downlevel parity.** On builds without that API, MXC still owes the same GA policy. The
  enforcement primitives exist (container-scoped WFP, per-container WinHTTP), but applying them from
  medium-IL `mxc-exec.exe` requires elevation, and prompting UAC on every sandbox launch is
  unacceptable for an interactive agent workflow. **How to obtain that privilege downlevel without
  per-launch UAC is an open design problem (§4), not a settled mechanism.** Today MXC has neither a
  complete Tier 2 enforcement path nor a decided elevation story. It currently raises one UAC per
  launch via an elevated WinHTTP shim. That is exactly what must be replaced.

### 2.1 Fail loud on version skew: never silently downgrade

`CreateProcessInSandbox` is not a single build; its network-policy surface grows over time. A
machine can expose the API but not yet honor a specific policy field MXC asks for. MXC must
**not** silently fall back to Tier 2 in that case: the two paths have different security and
cleanup properties, and the operator would not know. The contract:

- Fall back to Tier 2 only when the API is **absent on the build**, not when it is present but
  missing a requested field.
- For a present-but-incomplete API, MXC rejects the launch with a typed error **naming the
  missing capability**.

This requires a **companion API alongside `CreateProcessInSandbox`** (see §5 #3) that, for example,
lets MXC enumerate the network features the build actually supports. On Tier 2 the supported set is
fixed (whatever the GA Tier 2 path implements), so only Tier 1 needs to query it.

## 3. WFP is the enforcement primitive (both tiers)

Outbound policy is enforced with WFP user-mode filters (`Fwpm*`) at
`FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6` (the standard `connect()`-time authorization point),
scoped to the sandbox via the `FWPM_CONDITION_ALE_PACKAGE_ID` (container SID) condition. The
container SID is the per-sandbox identity available at filter-add time; Windows applies the
filters only to outbound traffic from that one sandbox.

- **Admin requirement.** Adding WFP filters is admin-only (the BFE engine access check). On Tier 1
  this is satisfied inside the OS service; on Tier 2 it is the open problem of §4.
- **Cleanup.** Filters added against a dynamic/session engine handle are reaped when the handle
  closes (and BFE auto-closes the handle of an exited process), so filter lifetime ≤ sandbox
  lifetime with no caller cleanup. Tier 1 relies on this; a Tier 2 implementation must reproduce
  equivalent process-bound cleanup.

## 4. Open problem: privileged enforcement downlevel (Tier 2) [DECISION OPEN]

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
- **Authenticating the caller.** The IPC client is **medium-IL and unpackaged**: no container
  SID, no MSIX identity, nothing the kernel can vouch for. A hostile same-desktop process can copy
  the client binary, inject into it, or spoof its image path. There is no perfect "trust a
  medium-IL caller" primitive; any broker must assume the caller may be hostile and bound the blast
  radius.
- **Ensuring the user/caller isn't malicious.** Even a correctly-identified caller is driven by a
  user who must not be able to use the broker to widen their own privileges, e.g. apply filters to
  a SID they don't own, tear down another sandbox's policy, or coax a privileged side effect.
- **Who may talk to the broker, and who decides policy** (and how that gate is enforced) is
  unresolved.

**Options (no decision made):**

| Option | Upside | Open risk / why not obviously right |
|---|---|---|
| Per-launch elevated shim (today) | simplest | UAC per launch (already rejected) |
| COM elevation moniker | OS-mediated | still prompts; doesn't solve the medium-IL caller |
| Long-running MXC service (e.g. restricted `LocalService` + local RPC) | no per-launch UAC | always-on privileged endpoint; **caller-auth is unsolved** (medium-IL spoof/TOCTOU); is owning a service even MXC's job? |
| OS extends the Tier 1 in-process model downlevel | no MXC broker at all | OS-backport timeline; may not land for GA |
| OS relaxes the WFP user-mode admin gate | no broker needed | long-shot networking-team ask; the admin gate is long-standing |

**If the service route is chosen,** caller authentication is the load-bearing piece, and it is only
*partially* answerable today. Candidate defenses bound the damage:

- verify the caller's signed binary at IPC time;
- expose a deliberately narrow API (add / remove / version only);
- scope every filter to the caller-named container SID;
- reject cross-caller teardown;
- resolve no names, and expose no read/enumerate API.

Known gaps remain to close before GA; these are *why the decision is open*, not a finished design:

- TOCTOU between checking the on-disk image and the running image;
- leaf-vs-root publisher pinning;
- endpoint ACLs;
- reliance on under-documented "PID from IPC" APIs.

**Recommendation to reviewers:** prefer keeping privilege in the OS (Tier 1) and treating the
downlevel elevation story as the separate MXC elevation design doc the parent doc already
requires, rather than committing MXC to own a privileged networking broker. Open for discussion.

## 5. Open asks to the OS networking team

GA and post-GA both depend on OS-owned primitives MXC should consume rather than build:

1. **Per-container WinHTTP lifecycle APIs: GA dependency.** GA's WinHTTP proxy path needs
   (a) a **per-policy delete** so MXC can tear down exactly the policy it set without clobbering
   other entries on the shared WinHTTP connection-policy tag, and (b) a **non-clobber interface
   bind** so the per-container proxy can be pinned to the loopback interface without delete-all-and-replace.
   These are open dependencies, tracked as GA blockers.
2. **Public documentation for `NetworkIsolationCreateAppContainerLoopbackRules`.** MXC uses this to
   scope the sandbox↔proxy loopback exemption to the specific container-to-container pair, instead of the system-wide
   `NetworkIsolationSetAppContainerConfig` (which also permits container-to-non-container traffic). The container-to-container scoping
   already exists in supported OS builds today; the GA ask is to **publicly document the API on
   learn.microsoft.com** so the downlevel (Tier 2) path can depend on it.
3. **Companion query API** alongside `CreateProcessInSandbox` (see §2.1): a pure-query, no-privilege
   way to enumerate the network features a build supports end-to-end (for example, a per-capability
   bitmap), additive over time.

## 6. Open questions

1. `internetClient` × WFP authorization (GA-blocking PoC): whether an explicit WFP permit can
   authorize public-network egress on its own, or the coarse container `internetClient`
   capability must also be present.
2. The downlevel privileged-enforcement decision (§4), including caller authentication: **open,
   needs feedback**; overlaps the separate MXC elevation design.
3. WinHTTP per-policy delete + non-clobber interface bind (§5 #1): GA dependency.
4. Per-launch container-SID uniqueness on Tier 2 (Tier 1 mints an ephemeral SID per launch;
   Tier 2 derives it from a caller-supplied id, so MXC must generate a unique per-launch profile
   name for crash-recovery reconciliation to rely on SID uniqueness).
5. Inbound/listening policy: separate post-GA contract; must not be inferred from outbound.
