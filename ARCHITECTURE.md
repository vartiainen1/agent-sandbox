# agent-sandbox — Architecture

| | |
|---|---|
| Status | ACCEPTED (Phase 0) |
| Date | 2026-08-19 |
| Phase | 0 — Architecture and Threat Model |
| Supersedes | — |
| Companion docs | `SECURITY_SPEC.md` (what must hold), `THREAT_MODEL.md` (what we defend against), `ADRs/` (why each decision) |

This document is derived from the project design and implementation
specifications (kept out of the repository in `dont touch/`). It is the
single source of truth for *how the system is structured*; `SECURITY_SPEC.md`
defines *what the system must guarantee*; `THREAT_MODEL.md` defines *what the
system defends against*.

---

## 1. Purpose and Scope

`agent-sandbox` is a security-first execution environment that lets an
untrusted AI agent perform real software-engineering work (read/write files,
run tests and builds, install dependencies, inspect Git, generate diffs)
inside an OS-enforced isolation boundary, while the host remains protected
and everything security-relevant is audited.

This document covers **Phase 0**: the architecture, trust boundaries,
security boundary, and the exact set of Linux mechanisms that will be used.
It does not describe a runtime implementation (Phase 1+). No runtime code
exists yet.

Guiding constraints taken from the implementation plan:

- Do not reverse the implementation order (architecture → minimal sandbox →
  security verification → policy → lifecycle → audit → CLI → Git → MCP →
  ecosystem → hardening → independent review).
- Keep the trusted computing base as small as practical.
- Prefer OS-level enforcement over application-level filtering. Shell-command
  filtering is **never** the primary security boundary.
- Fail closed: if a mandatory control cannot be established, hardened
  execution refuses to start.
- Never silently downgrade security; never claim a property that is not
  enforced and tested.

---

## 2. System Context

```
                 USER
                  |
                  v
        LOCAL / CLOUD LLM (untrusted)
                  |
                  |  requests actions
                  v
        CLI / MCP / API  (interfaces - NOT the security boundary)
                  |
                  v
        +----------------------+
        |  POLICY ENGINE       |   "is this action allowed?"   (trusted, host-side)
        +----------------------+
                  |
                  v
        +----------------------+
        |  SECURITY INIT       |   namespaces, caps, seccomp, rlimits,      (trusted, host-side)
        |                      |   cgroups, pivot_root, env sanitization
        +----------------------+
                  |
                  v
        +----------------------+
        |  OS-ENFORCED ISOLATION |  the kernel enforces the boundary
        +----------------------+
                  |
                  v
        +----------------------+
        |  SANDBOXED WORKLOAD  |   repository, build scripts, tests, deps   (untrusted)
        +----------------------+
                  |
                  v
        +----------------------+
        |  AUDIT RECORDER      |   structured events, host-side             (trusted, host-side)
        +----------------------+
                  |
                  v
              RESULT + AUDIT -> USER / AGENT
```

The LLM requests actions. The policy engine decides whether they are
permitted. The operating system enforces the boundary. The audit layer
records what happened. No higher layer may bypass a lower one.

---

## 3. Trust Model

### 3.1 Trusted (trusted computing base, kept minimal)

| Component | Why trusted | Notes |
|---|---|---|
| Linux kernel | Provides every isolation primitive | Kernel compromise is a documented residual risk, out of scope |
| Host-side supervisor | Creates and owns sessions; runs security init | The only component that can touch the boundary |
| Security initialization code | Sets up namespaces, caps, seccomp, limits | Runs before any untrusted code exists |
| Policy validator | Parses/validates policy before use | Rejects malformed or unknown security-critical fields |
| Security-critical configuration | Policy files, allowed-env list, rootfs layout | Host-side, never mounted into the sandbox |
| Audit recorder | Writes structured events outside the sandbox | Audit is observation, not enforcement |

### 3.2 Untrusted (everything else)

- The LLM and its prompts/instructions
- MCP clients, API clients
- The repository: all files, instructions, Git hooks, `.git/config`, `.gitmodules`
- Dependencies and their install scripts
- Build scripts and tests
- Downloaded content and network responses
- Generated code
- Every process executed inside the sandbox

The AI agent is **not** part of the security boundary. MCP is not the
boundary. The API is not the boundary. The audit system is not the boundary.

---

## 4. Security Boundary and Who Creates It

The security boundary is the combination of:

1. **Host-side security initialization** (supervisor, trusted, minimal):
   creates the namespaces, restricts capabilities, applies seccomp, sets
   rlimits, configures cgroups, pivots the root, sanitizes the environment,
   constructs the audit pipe.
2. **OS-enforced isolation**: the kernel enforces everything after init.
   The workload runs inside its own user/mount/PID/network/UTS/IPC
   namespaces, with no_new_privs, a dropped capability bounding set, a
   seccomp filter, and resource limits it cannot raise.

The supervisor **creates** the boundary; the **kernel enforces** it. Nothing
inside the sandbox can modify the boundary (S-025), the policy (S-026), or
the resource limits (S-027) because those objects either live outside the
sandbox (policy files, audit recorder, supervisor state) or are
kernel-enforced and irreversible from inside (no_new_privs, lowered
rlimits, dropped bounding set, seccomp).

---

## 5. Linux Isolation Architecture — Exact Mechanisms

These are the mechanisms selected for the hardened Linux runtime (v0.1
HARDENED mode). Each maps to security invariants in `SECURITY_SPEC.md`.
The exact syscall list for seccomp is finalized empirically in Phase 1
(ADR-008); every other mechanism below is fixed at Phase 0.

| Mechanism | Purpose | Invariants |
|---|---|---|
| User namespace (`unshare(CLONE_NEWUSER)`, uid/gid map 0 → caller) | Rootless isolation; the workload believes it is root but holds zero host privileges; unprivileged | S-008, S-009, S-035 |
| Mount namespace + `pivot_root` into a minimal rootfs | Filesystem isolation by construction; no host path exists in the tree | S-001, S-002, S-028 |
| PID namespace (`CLONE_NEWPID`) | All workload processes are descendants of the sandbox init (PID 1 in ns); host process inspection impossible | S-013, S-008 |
| Network namespace (`CLONE_NEWNET`) | Deny-by-construction network isolation (no interfaces) in v0.1 | S-005, S-006, S-007 |
| UTS + IPC namespaces | Hygiene; isolate hostname and SysV IPC | S-013 |
| cgroups v2 (delegated subtree, `pids.max`, `memory.max`, `cpu.max`, `io.max`) | Resource limits the workload cannot raise; process-tree kill | S-012, S-027, S-014 |
| rlimits (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`, `RLIMIT_CORE=0`) | Unprivileged limits that can only be lowered, never raised | S-012, S-027 |
| `prctl(PR_SET_NO_NEW_PRIVS)` | Blocks all privilege-gaining exec (setuid, file caps, etc.) | S-008, S-010 |
| Capability bounding set drop (`prctl(PR_CAPBSET_DROP, ...)` for every capability) + empty inheritable/ambient sets | Workload has no capabilities, host or namespace | S-009 |
| seccomp BPF filter (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`) | Syscall allowlist; default action denies (EPERM) | S-011 |
| Restricted `/proc` (`hidepid=2`), minimal `/sys`, minimal `/dev` | No host process/device metadata | S-002, S-008 |
| Read-only system layers in the rootfs | Containment; workload cannot tamper with its own tooling | S-001, S-025 |
| Explicit environment allowlist | No blind host-env inheritance | S-003, S-034 |
| Host-side audit pipe (outside the sandbox filesystem) | Structured, session-correlated events | S-022, S-023 |

No single mechanism is the whole boundary. The boundary is the combination,
and every mechanism is verified by tests (adversarial suite, Phase 2+) and
failure tests (Phase 3+).

### 5.1 Privileged components

- **v0.1 has no privileged (setuid/root) component.** Every selected
  mechanism is reachable from an unprivileged process on a stock Linux
  kernel with user namespaces enabled: user namespaces are unprivileged;
  rlimits, `no_new_privs`, bounding-set drops and seccomp are
  unprivileged; cgroup v2 delegation is provided by the host init
  (systemd `Delegate=yes` on the user slice, or an explicit admin grant).
- Normal usage never requires `sudo agent-sandbox`.
- If a later phase requires a privileged helper (e.g., cgroup delegation
  or network setup that cannot be done unprivileged), it is a separate,
  minimal component with a documented interface, treated as part of the
  TCB, and it must drop privileges as early as possible (ADR-002).

---

## 6. Process Model

```
HOST (trusted)                          SANDBOX (untrusted)
+----------------------------------+    +----------------------------------+
| supervisor (session owner)       |    | sandbox init  = PID 1 in the     |
|  - owns the session             |    |   PID namespace                   |
|  - child subreaper              |    |   - sets up the remaining         |
|  - reads audit pipe             |    |     environment (cwd, env)        |
|  - enforces timeouts/output     |    |   - execs the workload command    |
|  - performs destroy             |    |      |                            |
|        | fork/unshare           |    |      v                            |
|        +---------------------> |    |   workload process tree            |
|        |                        |    |   (all descendants of PID 1)      |
+----------------------------------+    +----------------------------------+
```

- The supervisor forks once and the child performs `unshare` for all
  namespaces (user first, then mount/PID/net/UTS/IPC), applies the security
  restrictions, pivots the root, and becomes PID 1 of the new PID namespace
  before executing the workload. Fork+unshare in a single controlled child
  avoids TOCTOU between setup and exec (S-031).
- The supervisor sets itself as a **child subreaper**
  (`prctl(PR_SET_CHILD_SUBREAPER)`) so orphaned descendants reparent to it,
  not to init — enabling reliable cleanup (S-014, S-038).
- **Containment**: because the workload lives in its own PID namespace and
  is a descendant of sandbox init, it cannot see host PIDs, and every
  workload process is inside the sandbox process boundary (S-013).
- **Termination**: destroy = SIGKILL to sandbox init (kills the namespace's
  PID 1) **and** `cgroup.kill` on the session cgroup (kills every process in
  the cgroup regardless of parentage), then verification that no workload
  process remains (S-014, S-038). Killing only the parent is explicitly
  forbidden.
- **ptrace**: no_new_privs + dropped capabilities + seccomp make ptrace of
  host processes impossible; the PID namespace makes host PIDs invisible
  (S-008, S-013).

---

## 7. Filesystem Model

The workload never sees the host filesystem. The sandbox receives a fresh
root filesystem built by the supervisor:

```
/                    (pivot_root target; mount propagation = private)
├── workspace/       RW   fresh copy of the project under test
├── tmp/             RW   tmpfs, size-limited (S-012)
├── home/            RW   minimal home, empty except what policy grants
├── usr/             RO   bind-mounted system layers (toolchain)
├── bin/             RO   bind-mounted system layers
├── lib/             RO   bind-mounted system layers
├── etc/             RO   minimal, sanitized configuration only
├── proc/            RO   mounted with hidepid=2
├── dev/             minimal device nodes only: null, zero, full, random, urandom, tty
└── sys/             not mounted by default (v0.1)
```

- **No host paths by default** (S-002): host `/`, host home, `~/.ssh`,
  `~/.aws`, `~/.config`, `/var/run`, `/run`, Docker sockets, Kubernetes
  config are **never** mounted. The workspace is a **copy** of the project,
  not a bind mount of the host directory — a malicious repository can
  damage only its own copy (S-028, S-032).
- **Symlink/hardlink safety by construction** (S-029, S-030): since no host
  path exists in the rootfs, a symlink to `/etc/passwd` resolves to the
  sandbox's minimal `/etc`, and a symlink to a host path cannot reach it.
  Path traversal outside the rootfs cannot escape a `pivot_root`ed mount
  namespace (S-001).
- **Mounts**: mount propagation is private; the workload cannot see or
  reuse host mount events. `mount(2)` is denied by seccomp in HARDENED mode
  (S-001, S-025).
- **Secret isolation** (S-003): SSH keys, cloud credentials, API tokens,
  GitHub credentials, Kubernetes credentials and application secrets are
  absent from the rootfs by default. The environment is reconstructed from
  an explicit allowlist (S-034). No host sockets (SSH agent, Docker,
  credential managers) are exposed (S-004).
- The supervisor retains the *host-side* view: the original project stays
  untouched on the host; only the copy inside the sandbox is mutable.

---

## 8. Network Model

**v0.1: deny by construction.**

- The workload runs in its own network namespace with **no interfaces
  configured and loopback down**. There is nothing to connect to: no
  loopback, no veth, no NAT, no host network. S-005 (default deny) holds
  structurally, not by firewall rules the workload could inspect or alter.
- Because no network exists, S-006 (private ranges), S-007 (metadata
  endpoints, e.g. `169.254.169.254`), SSRF, DNS rebinding, and Unix-socket
  escapes to host services are unreachable (S-004): the docker socket and
  any host socket path simply do not exist in the rootfs.
- **Explicit allowlists are deferred to v0.2** (design §12, §13). When they
  arrive they must be enforced inside the network namespace (interface +
  routing + a host-side proxy with destination validation), never by
  hostname allowlists alone, and must account for DNS resolution, redirects,
  alternate address forms, and DNS rebinding (security spec §8). Until then,
  network = none.

---

## 9. Resource Model

Two layers, both enforced outside the workload and neither raisable by it
(S-012, S-027):

1. **rlimits** (always applied, unprivileged, irreversible once lowered):
   - `RLIMIT_CPU` — CPU seconds
   - `RLIMIT_AS` — address space (memory proxy, per-process)
   - `RLIMIT_NPROC` — process count
   - `RLIMIT_NOFILE` — file descriptors
   - `RLIMIT_FSIZE` — single-file write size
   - `RLIMIT_CORE = 0` — no core dumps (credential/secret spill)
2. **cgroups v2** (applied to the session subtree when delegated):
   - `pids.max` — total processes (fork-bomb containment)
   - `memory.max` — total memory for the whole tree
   - `cpu.max` — CPU quota
   - `io.max` — disk throughput

- **HARDENED requires cgroup v2 delegation** for memory/pids/io. If the
  host does not delegate cgroups, HARDENED execution is **refused** with the
  specific reason (S-018); the user may explicitly select RESTRICTED, which
  documents that only rlimits are enforced (ADR-007).
- **Disk total**: a total-disk quota without cgroup delegation cannot be
  enforced unprivileged (RLIMIT_FSIZE bounds single files only). HARDENED
  enforces total disk via cgroup `io.max` + workspace size pre-check;
  RESTRICTED documents the gap. This is a flagged, explicit limitation, not
  a silent one (ADR-007).
- **Output limits** (S-037): the supervisor reads stdout/stderr through a
  bounded pipe; after the limit it terminates the session with a truncation
  notice. Audit and API output are separately bounded.

---

## 10. Capability and Seccomp Model

- **Capabilities** (S-009): at security-init, the supervisor drops the
  entire capability bounding set (`PR_CAPBSET_DROP` for every cap) and
  clears inheritable/ambient sets, so the workload and anything it execs
  hold no capabilities — including inside its user namespace. `CAP_SYS_ADMIN`,
  `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`,
  `CAP_DAC_OVERRIDE` and the rest are never granted (design §9).
- **no_new_privs** (S-010): `prctl(PR_SET_NO_NEW_PRIVS)` before exec; the
  workload cannot exec setuid/setgid binaries or gain file capabilities.
- **seccomp** (S-011): BPF filter, default action EPERM (deny), with an
  explicit allowlist derived for the toolchain (Python, shell, git, build
  tools) and finalized empirically in Phase 1 (ADR-008). Dangerous syscalls
  (`mount`, `ptrace`, `unshare`, `setns`, `keyctl`, `bpf`, `clone` with
  CLONE_NEW* flags, `chroot`, `pivot_root`, …) are denied in HARDENED mode.
  Seccomp failure ⇒ refuse HARDENED execution.

---

## 11. Environment, Credentials, and Sockets

- The host environment is **not** inherited (S-034). The supervisor builds
  an explicit environment from an allowlist: `PATH`, `HOME`, `LANG`,
  `LC_ALL`, `TERM`, `TMPDIR` (all pointing inside the sandbox) plus
  policy-declared variables. Everything else is dropped.
- Host credentials are absent by construction (S-003): no mounts, no env,
  no sockets, no agent forwarding.
- Secret injection (design §16) is a future capability gated by narrow,
  command-scoped policy; it is **not** part of v0.1.

---

## 12. Policy Model

- **Capability-based, versioned, validated, immutable per session**
  (S-015, S-021, S-025, S-026). The policy file lives host-side, is parsed
  and validated by the trusted policy validator *before* the session
  starts, and is never mounted into the sandbox.
- Policy declares: filesystem access (workspace RW, everything else deny),
  network (default deny), tool capabilities (e.g. `git.read`,
  `git.commit`, `git.push` — push denied by default), secrets (deny by
  default), privileged operations (deny by default), and resource limits.
- Malformed, conflicting, or unknown security-critical fields ⇒ policy
  rejected, session does not start (S-021). There is no "warn and
  continue" for security-critical policy.
- The policy engine is the single decision point for every requested
  action across CLI, MCP and API (S-015, S-016, S-017; ADR-013). OS
  enforcement remains the backstop: a policy bug can over-allow an action,
  but the sandbox boundary still contains it.

---

## 13. Lifecycle Model

- Sessions are owned by the supervisor (ADR-011): create → exec →
  status → destroy. Every session has a unique ID (`sbx_<ts>_<rand>`,
  design §30) used to correlate audit, Git, errors, memory, decisions,
  diffs and MCP requests (S-023).
- **Cleanup** must hold for every failure class: normal exit, command
  failure, parent death, agent crash, terminal disconnect, timeout, OOM,
  network failure, repeated destroy, partial cleanup, child persistence
  (design §33). Destroy terminates the **whole process tree** (PID 1
  SIGKILL + `cgroup.kill`), unmounts the sandbox mount namespace, removes
  the workspace copy and tmpfs, and verifies nothing remains (S-014,
  S-038).
- **Timeout enforcement** is external and cannot be disabled by the
  workload (S-036).
- **Cleanup failure visibility** (S-038): incomplete cleanup is detected
  and reported; cleanup is never reported as successful when it was not
  (S-024).

---

## 14. Failure Model (Fail Closed)

The supervisor refuses to start a session unless **every mandatory control
for the selected security mode** is established (S-018). Per-control
behavior:

| Control | On failure (HARDENED) |
|---|---|
| User namespace | Refuse execution — reason reported |
| Mount namespace / pivot_root | Refuse execution |
| Network namespace | Refuse execution (network isolation mandatory) |
| PID namespace | Refuse execution |
| cgroup delegation (mandatory controls) | Refuse HARDENED; RESTRICTED is an explicit user choice |
| Capability drops | Refuse execution |
| `no_new_privs` | Refuse execution |
| seccomp | Refuse execution |
| rlimits | Refuse execution |
| Environment sanitization | Refuse execution |
| Policy parse/validate | Reject policy; no session |

Forbidden: `WARNING: security feature unavailable; continuing anyway.`
Required: `HARDENED execution unavailable. Reason: <specific>. Workload
not executed.` (S-018, S-019; design §10, security spec §6–7).

Cleanup failure is the one place "recovery" is attempted — recovery,
recording, and explicit incomplete-state reporting, never a success claim.

---

## 15. Audit Model

- The audit recorder runs **host-side, outside the sandbox filesystem**
  (S-022, S-024). The workload cannot write, truncate, or read the audit
  stream.
- Events are structured JSONL with: session ID, timestamp, event type,
  resource, decision, reason (S-022, S-023). Event classes: session
  creation, policy load, process start/exit, filesystem op, network op,
  denied capability, secret access, policy decision, resource violation,
  sandbox violation, Git op, session termination (design §29).
- **Audit is observation, not enforcement** (S-024): enforcement happens in
  the kernel. If audit recording fails, the documented policy is: execution
  continues (audit failure must not be conflated with protection), and the
  failure is itself recorded/reported where possible.

---

## 16. Control Surface (CLI / MCP / API)

- All interfaces are thin front-ends over a **single enforcement core**
  (ADR-013): validated request → policy decision → security-init →
  execution. There is exactly one code path that touches the boundary.
- CLI (Phase 8), MCP (Phase 11), API (Phase 12) must produce equivalent
  security decisions for equivalent requests. None may bypass policy
  (S-015, S-016, S-017).
- Security mode and session identity are always exposed (S-020, S-023),
  including machine-readable (`--json`).

---

## 17. Security Modes

| Mode | Guarantees | Notes |
|---|---|---|
| HARDENED | All mandatory controls active (namespaces, caps, no_new_privs, seccomp, cgroups+rlimits, pivot_root, env sanitization, net deny) | Failure of any mandatory control ⇒ no execution |
| RESTRICTED | Documented weaker set (e.g. rlimits only — no cgroup delegation; or seccomp relaxed) | Must be explicitly selected; exact differences documented per deployment (S-019, S-020) |
| COMPATIBILITY | Functionality over isolation | Never represented as secure; for functional testing only |

Every session reports its mode. Downgrades are explicit user choices, never
automatic (S-019).

---

## 18. Validation Strategy (Docker ≠ Native)

- **Native Linux is the security target.** All security claims are validated
  on native Linux (GitHub Actions ubuntu runners) — the family CI pattern
  (matrix incl. ubuntu; agent-blame precedent).
- **Docker Desktop is a local *container* validation substrate only**, used
  on this Windows dev machine to run Linux workloads for development
  iteration. Docker Desktop's own isolation is not the product's boundary,
  and results from Docker runs are labeled *container-validated*, never
  *native-Linux-validated* (ADR-014). Where a mechanism behaves differently
  under Docker (e.g. nested namespaces, seccomp inheritance), the native CI
  result is authoritative.
- CI runs: unit, integration, security, adversarial, regression suites on
  ubuntu; platform-skip reasons are explicit, never silent (implementation
  plan §19, §23).

---

## 19. Assumptions and Flagged Decisions

The following assumptions materially affect the security boundary. Each is
a **runtime-checked** assumption with a fail-closed consequence, not a
silent guess:

1. **User namespaces are available and enabled** on the target Linux host
   (`kernel.unprivileged_userns_clone` / `apparmor_restrict_unprivileged_userns`).
   Runtime probe at init; if unavailable ⇒ HARDENED refused (S-018).
2. **cgroup v2 delegation** for the invoking user (systemd `Delegate=yes`,
   or admin grant). Required for HARDENED memory/pids/io limits; absent ⇒
   HARDENED refused, RESTRICTED is explicit (ADR-007).
3. **seccomp allowlist completeness** — the exact syscall list is derived
   empirically in Phase 1 and must be reviewed before any release (ADR-008).
   This is the one mechanism whose Phase-0 specification is intentionally
   deferred; everything else is fixed here.
4. **Rootless runtime correctness** — the entire boundary must work without
   privileges. If a mandatory control turns out to require privilege on a
   given host, that host cannot run HARDENED (fail closed), matching rule 1.
5. **`/proc`/`/sys`/`/dev` exposure** is controlled by construction (minimal
   mounts, `hidepid=2`). Kernel information leaks via these interfaces are
   mitigated but not provably eliminated — residual risk documented in
   `THREAT_MODEL.md`.

If any of these assumptions turns out to be unsatisfiable during Phase 1,
the implementation must **stop and request architectural review**
(implementation plan §32) rather than weaken the boundary.

---

## 20. Phase 0 Acceptance Criteria

The implementation plan requires the architecture to answer the following
questions clearly before proceeding. Answers:

**Q1. What is trusted?**
The minimal TCB: the Linux kernel, the host-side supervisor, the security
initialization code, the policy validator, security-critical configuration,
and the audit recorder (§3.1). Everything else is untrusted.

**Q2. What is untrusted?**
The LLM, MCP/API clients, the repository and its instructions, Git hooks,
dependencies, build scripts, tests, downloaded content, network responses,
generated code, and every sandboxed process (§3.2).

**Q3. What is the security boundary?**
The combination of host-side security initialization plus OS-enforced
isolation: user/mount/PID/network/UTS/IPC namespaces, cgroups v2 + rlimits,
dropped capability bounding set, `no_new_privs`, seccomp, `pivot_root`
filesystem isolation, restricted `/proc`/`/dev`, environment sanitization,
and host-side audit (§4, §5).

**Q4. Which component creates the boundary?**
The host-side supervisor, via its security-initialization code, which runs
**before** any untrusted code exists. The kernel enforces it afterward.
The AI, MCP, API and audit never participate (§4).

**Q5. What happens if initialization fails?**
HARDENED execution refuses to start; the reason is reported specifically;
the workload is not executed (§14). Per-control failure table in §14.

**Q6. What happens if cleanup fails?**
The supervisor attempts recovery, records the failure, exposes the
incomplete-cleanup state, and never reports cleanup as successful (§13,
§14; S-038).

**Q7. How are processes contained?**
User + PID namespaces: every workload process is a descendant of sandbox
init (PID 1 in the namespace); the supervisor is a subreaper; `pids.max`
caps the tree; the workload cannot see host PIDs or ptrace them (§6, §10).

**Q8. How is the filesystem isolated?**
Mount namespace + `pivot_root` into a minimal rootfs built by the
supervisor; workspace is a copy; system layers read-only; `/proc`
`hidepid=2`; minimal `/dev`; no host paths, mounts, or sockets by default
(§7; S-001, S-002, S-028, S-029, S-030).

**Q9. How is the network isolated?**
A dedicated network namespace with no interfaces and loopback down — deny
by construction in v0.1; allowlists deferred to v0.2 with stricter
requirements (§8; S-005, S-006, S-007).

**Q10. How are resources limited?**
rlimits (always, unprivileged, irreversible) + cgroups v2 (when delegated)
for pids/memory/cpu/io; output limited by a bounded supervisor pipe;
timeouts enforced externally (§9; S-012, S-027, S-036, S-037).

**Q11. How are capabilities reduced?**
Full bounding-set drop + cleared inheritable/ambient sets + `no_new_privs`
before exec (§10; S-008, S-009, S-010).

**Q12. How is seccomp configured?**
BPF filter, default-deny (EPERM), explicit allowlist derived for the
toolchain and finalized in Phase 1; mandatory in HARDENED (ADR-008; S-011).

**Q13. How are secrets prevented from leaking?**
By construction: no credential mounts, no env inheritance (explicit
allowlist), no host sockets, workspace is a copy, audit stream outside the
sandbox (§7, §11; S-003, S-004, S-034).

**Q14. How are security decisions enforced?**
Every requested action passes the policy engine (single control surface for
CLI/MCP/API); OS enforcement is the backstop. Policy is validated,
versioned, and immutable per session (§12, §16; S-015, S-016, S-017, S-021,
S-025, S-026).

**Q15. How are security events recorded?**
Structured JSONL audit events with session ID, written host-side outside
the sandbox; audit is observation only, never enforcement (§15; S-022,
S-023, S-024).

All fifteen questions are answered. Phase 0 documentation deliverables:
`ARCHITECTURE.md` (this file), `THREAT_MODEL.md`, `ADRs/` (index + 14
decisions, ADR-001…ADR-014), `SECURITY_SPEC.md` (in-repo). Per the
implementation plan's
instruction — *"If these questions cannot be answered clearly, do not
proceed"* — the answers above are the gate for Phase 1.

---

## 21. Phase 1 Scope and Dependencies

Phase 1 builds the smallest hardened Linux execution prototype, in this
order, using exactly the mechanisms in §5:

1. Runtime skeleton: package layout (`agent_sandbox/runtime`, `isolation`,
   `security`, `execution`, `audit`), models.
2. Namespace setup (user → mount/PID/net/UTS/IPC), uid/gid map, pivot_root
   minimal rootfs.
3. `no_new_privs`, bounding-set drop, seccomp allowlist (derived + reviewed),
   rlimits, cgroup v2 wiring (with delegation probe + fail-closed path).
4. Environment sanitization; bounded output pipe; external timeout.
5. Process-tree cleanup with verification (`cgroup.kill` + PID-1 kill +
   absence check).
6. A `echo hello`-class workload that passes the Phase 1 acceptance
   criteria (executes; cannot access host files/credentials/processes/
   network, raise limits, escape, or leave processes behind).

Phase 1 depends on: the Phase 0 architecture (this file) being accepted,
the threat model, and the seccomp derivation exercise. No MCP, CLI, policy
engine, lifecycle service, audit export, Git integration, or adversarial
suite is in Phase 1 scope — those are Phases 2+.
