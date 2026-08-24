# agent-sandbox

Security-first execution sandbox for autonomous AI agents, providing
OS-enforced isolation, policy-controlled execution, network controls, and
security auditing. An untrusted AI agent (or a hostile repository,
dependency, or build script running under it) gets a useful Linux
environment for real software engineering — files, tests, builds, Git —
while the host is protected by an OS-enforced isolation boundary and
every security-relevant action is audited.

> The AI requests actions. The policy determines whether they are allowed.
> The operating system enforces the boundary. The audit system records the
> result. The host remains protected.

## Why agent-sandbox?

Autonomous agents are asked to run real code — tests, builds, installers,
repository tooling — and that code is hostile by default: a prompt-
injected instruction, a malicious dependency, or a compromised build
script can try to read host secrets, reach the network, or persist past
the task. Persuading the model not to do that is not a boundary;
`agent-sandbox` makes the *operating system* the boundary.

It is for developers building autonomous coding agents and LLM tool
harnesses that need an untrusted workload to do useful software
engineering without being able to harm the host:

- **OS-enforced isolation** — Linux namespaces, full capability drop,
  `no_new_privs`, a derived 70-syscall seccomp allowlist, rlimits and
  cgroup v2, not a prompt.
- **Policy-controlled execution** — the agent requests actions; a
  validated, deny-by-default capability policy decides (S-015).
- **Network controls** — deny by construction, or a strictly
  allowlisted, SSRF-validated path through a validating proxy.
- **Security auditing** — every security-relevant decision is recorded in
  structured, host-side, session-correlated JSONL events (ADR-012).

It is not a general-purpose container runtime and it makes no
production-readiness claim: see [Known limitations](#known-limitations)
and the [Independent Security Review](#independent-security-review)
status.

## Security model

- **Untrusted by default**: the LLM, the repository, its instructions, Git
  hooks, dependencies, build scripts, tests, and network responses are all
  treated as hostile.
- **Rootless, OS-enforced**: user/mount/PID/network namespaces, capability
  bounding-set drop, `no_new_privs`, seccomp, rlimits + cgroups v2,
  `pivot_root` into a minimal rootfs, explicit environment allowlist.
- **Fail closed**: if a mandatory HARDENED control cannot be established,
  the workload is not executed — never a warning-and-continue.
- **No silent downgrade**: HARDENED / RESTRICTED / COMPATIBILITY are
  explicit, per-session, machine-readable modes.
- **Audit is observation, not enforcement**: structured JSONL events,
  host-side, session-correlated.

The AI agent is **not** part of the security boundary. MCP and the API
are interfaces, never the boundary.

## Installation

Requires Linux (x86_64 or aarch64) with Python >= 3.11. Zero runtime
dependencies. aarch64 *enforcement* is not yet verified on native ARM64
hardware (see [Known limitations](#known-limitations)).

```bash
# from a source checkout
pip install -e .

# check the install
agent-sandbox --version
agent-sandbox --help
```

Three equivalent front-ends share the same enforcement core and produce
equivalent security decisions:

| Front-end | Entry point |
|---|---|
| CLI | `agent-sandbox` (console script) or `python -m agent_sandbox` |
| MCP (stdio JSON-RPC 2.0) | `python -m agent_sandbox.mcp` |
| HTTP API | `python -m agent_sandbox.api` |

## Quick start

Requires Linux (x86_64 or aarch64) with Python >= 3.11.
aarch64 enforcement is not yet verified on native ARM64 hardware.

```bash
# Install (editable, zero runtime dependencies)
pip install -e .

# One-shot run (transient session, cleanup verified)
agent-sandbox run --workspace /path/to/project -- echo hello

# Persistent session workflow
agent-sandbox create --workspace /path/to/project
agent-sandbox exec <session-id> -- python -m pytest
agent-sandbox diff <session-id>
agent-sandbox status <session-id>
agent-sandbox logs <session-id>
agent-sandbox destroy <session-id>

# JSON output for automation
agent-sandbox run --workspace /path/to/project --json -- echo hello

# List all sessions
agent-sandbox list
```

All three interfaces (CLI, MCP stdio JSON-RPC, HTTP API) share the same
enforcement core and produce equivalent security decisions.

## CLI reference

Every command builds a validated configuration, initializes a session
fail-closed, and routes through the single execution path
`RuntimeSession.execute()` — the CLI carries no policy or enforcement of
its own.

| Command | Purpose |
|---|---|
| `run --workspace DIR [--mode MODE] [--policy PATH] [--audit PATH] [--json] -- command ...` | One-shot: create, execute, clean up (transient; nothing persisted) |
| `create --workspace DIR [--mode MODE] [--policy PATH] [--json]` | Create + initialize a persisted session (validates policy; never executes) |
| `exec <session-id> [--json] -- command ...` | Execute through a created session (manifest re-validated; fail closed) |
| `status <session-id> [--json]` | Session state, security mode, resource limits, policy version |
| `diff <session-id> [--json] [-- git args ...]` | `git diff` inside the sandbox (gated on the `git.read` capability) |
| `logs <session-id> [--json]` | Session audit events (observational; never an execution blocker) |
| `destroy <session-id> [--json]` | Terminate the live sandbox, verify absence, remove session state |
| `list` | List sessions |
| `git <session-id> <operation> [--json] [-- git args ...]` | Closed, read-only safe-Git set: `status` `diff` `changed` `untracked` `deleted` `base` `current` |

- Commands are **argv vectors**, never shell strings; shell
  metacharacters are data.
- `--json` emits machine-readable output (mode + session identity).
- `--` separates `agent-sandbox` options from the workload command.
- `--version` / `-V` and `--help` / `-h` print version / usage and exit 0.
- A bare legacy one-shot form (`agent-sandbox --workspace DIR -- cmd ...`)
  is still accepted for backward compatibility.

Deterministic exit codes:

| Code | Meaning |
|---|---|
| 0 | success |
| 1..255 | the workload's own exit code |
| 2 | usage / configuration error |
| 3 | initialization refused (fail closed — workload never ran) |
| 4 | execution refused (policy denial / invalid request / unsupported platform) |
| 5 | session error (unknown / destroyed / malformed state — fail closed) |
| 6 | destroy incomplete (survivors detected — not marked destroyed) |

## HTTP API and MCP

Both interfaces are thin front-ends over the same `RuntimeSession.execute()`
gate (ADR-013). The AI agent is never part of the security boundary.

### MCP (stdio JSON-RPC 2.0)

`python -m agent_sandbox.mcp` — a minimal, deterministic surface:

- `initialize` — params: `workspace` (required, absolute host directory),
  `mode`?, `policy`?, `audit`?
- `execute` — params: `session_id` (required), `command` (required, argv
  array)

Errors are fixed JSON-RPC codes (-32700 / -32600 / -32601 / -32602 /
-32603); no host details are leaked.

### HTTP API

`python -m agent_sandbox.api` — stdlib-only HTTP server, loopback-only by
default, 1 MiB request-body cap:

- `POST /initialize` — body `{workspace, mode?, audit?, policy?}`
- `POST /execute` — body `{session_id, command: [argv ...]}`

Deterministic status codes: 400 (malformed JSON / invalid params /
unknown session / invalid argv), 404 (unknown path), 405 (wrong method),
413 (body over the cap), 500 (internal failure — a fixed generic message,
never a traceback or environment detail).

## Configuration

| Setting | Default | Notes |
|---|---|---|
| `mode` | `hardened` | explicit per-session choice: `hardened` / `restricted` / `compatibility`; the runtime never downgrades silently (S-019) |
| `network_mode` | `deny` | `deny` (no usable path) or `allowlist` (veth + validating proxy) |
| `network_allowlist` | — | SSRF-validated destinations (host-side DNS); `allow_private` relaxes only RFC 1918/6598, never loopback/link-local/metadata |
| `policy` | default policy (below) | versioned v1 capability JSON via `--policy PATH`; unknown fields/capabilities rejected; host-side only, never mounted into the sandbox |
| `resources` | — | cgroup v2 `pids` / `memory` / `cpu` / `io`; HARDENED refuses to start without a delegated, enabled subtree |
| environment | six-variable allowlist | the host environment is never inherited (S-034) |
| state dir | `AGENT_SANDBOX_STATE_DIR` or `~/.agent-sandbox` | caller-owned; never mounted into the sandbox |
| `audit` | — | optional JSONL path (`--audit PATH`); ADR-012 structured audit, host-side |

Default policy capabilities: `filesystem.read.workspace`,
`filesystem.write.workspace`, `process.spawn`, `git.read`, `git.commit` —
with `git.push`, `network.connect`, `secrets.read` and `privileged.exec`
denied by default.

## Security and testing evidence

The claims below are backed by the project's automated suites and
documented in `THREAT_MODEL.md` (56 threats, T-001..T-056, mapped to the
S-001..S-040 invariants), `SECURITY_SPEC.md`, `ARCHITECTURE.md` and
`SECURITY_REVIEW.md` (reviewer-ready evidence package).

Implemented protections: rootless user/mount/PID/network namespaces with
`pivot_root` into a minimal rootfs, full capability bounding-set drop,
`no_new_privs`, a derived 70-syscall default-deny seccomp allowlist
(`socket` argument-filtered to AF_INET/AF_INET6), rlimits + cgroup v2,
`/proc`/`/dev`/`/sys` isolation, environment sanitization, bounded
output, external timeout, and verified process-tree containment and
cleanup — each verified by kernel-state read-back and adversarial tests
through the real execution boundary.

Evidence classification (see [Validation labeling](#validation-labeling)):

- **Native Linux VM (Ubuntu 24.04 / kernel 6.8 / x86_64)** — HARDENED
  end-to-end verified: 24/24 PASS (commit 7c1c30e).
- **Adversarial suite** — 59/59 in-sandbox tests PASS through the real
  `RuntimeSession.execute()` boundary; seccomp regression gate PASS.
- **Fuzz harness (Phase 15)** — 21/21 PASS, host-side/unit level; it
  caught three genuine fail-safe defects (F-1/F-3/F-4), all fixed.
- **CI (native Ubuntu 3.11 + 3.12)** — green (GitHub Actions run 38);
  ruff / mypy / bandit / pip-audit / detect-secrets gates block failures.

What is **not** claimed: an independent human security review (REQUIRED /
NOT YET PERFORMED), aarch64 native enforcement (SUBSTRATE-LIMITED), or
production-readiness. Passing the automated suites is not an independent
security audit.

## Validation labeling

| Substrate | Status | Purpose |
|---|---|---|
| Native Linux (GitHub Actions ubuntu) | **Authoritative** — CI runs trace + regression gate + behavioral probe + rootless capability detection + namespace tests + filesystem-boundary tests + proc/dev/sys boundary tests + network deny-by-construction tests + no_new_privs/capability-reduction/seccomp tests + rlimits tests + cgroup v2 tests | Security claims |
| Native Linux VM (Ubuntu 24.04 / kernel 6.8 / x86_64, caller-owned delegated cgroup) | **Authoritative for HARDENED** — P3 HARDENED end-to-end: 24/24 PASS (init READY, workload executes, seccomp + socket deny, zero caps, no_new_privs, namespace/env isolation, timeout/cleanup, audit; commit 7c1c30e) | HARDENED end-to-end verification; never relabeled to other substrates |
| Docker Desktop (container) | Development / reproducible observation; **only substrate where the full rootless mapping + rootfs/pivot_root + proc/dev/sys + network boundary is currently exercised** (uid 1001) | Iteration on Windows; never labeled as native |

**Known native limitation (documented, not hidden)**: the GitHub-hosted
ubuntu-24.04 runner permits unprivileged `unshare(CLONE_NEWUSER)` but its
AppArmor userns restriction denies the `setgroups`-deny write (EACCES), so
the uid 0→caller mapping cannot be established there. The namespace and
filesystem-boundary real-path tests therefore skip on native CI with the
recorded reason (never a false PASS); the fail-closed refusal is verified
natively; and the boundary execution evidence is VERIFIED DOCKER — except
on the native Ubuntu 24.04 / kernel 6.8 VM (commit 7c1c30e), where the
complete HARDENED path, including the rootless mapping and cgroup
enforcement, is verified end-to-end (see
`docs/seccomp-derivation/verification.md`).

## Seccomp derivation (Phase 1 pre-task)

The HARDENED syscall allowlist is a **derived, regression-protected
security artifact** — not a hardcoded list and not "whatever strace
happened to see". The workload set (Tier 0 `echo hello`-class, Tier 1
coreutils + CPython + git + pip) makes exactly **70 syscalls** (tier0
29 + tier1 41 — v0.2 Step 1 expanded the v0.1 46-syscall baseline by 23
network + native-toolchain syscalls, Step 4 added fsync for the pip
dependency-installation workflow; policy.md §5 change records); the
policy allows exactly those (default-deny EPERM), and the behavioral
probe verifies both halves: legitimate workloads pass, and
`socketpair`/`ptrace`/`mount`/`chroot`/`unshare`/`clone` return EPERM.
`socket` itself is allowlisted but **argument-filtered by domain**: only
`AF_INET` (2) / `AF_INET6` (10) are permitted, all other domains
(`AF_UNIX`/`AF_NETLINK`/`AF_PACKET`/…) are denied EPERM — preserving
S-003/S-004 Unix-socket/credential isolation while leaving the v0.2  proxy path open (v0.2 Step 2); v0.2 Step 3 adds the host-side
  validating proxy + firewall, so the allowlist path now provides real
  (allowlist-only) outbound networking through the proxy.

- Canonical artifact: `tools/seccomp-derivation/allowlist.json`
- Regression gate: `check_trace_regression.py` fails any observed syscall
  outside the allowlist (no undocumented expansion)
- Change control: `docs/seccomp-derivation/policy.md` §5
- Known limitations: threads (`clone`/`clone3`) are denied by design
  (npm/cargo dependency workflows are therefore unsupported inside the
  sandbox — measured, no expansion, policy.md §5 decision record);
  the x86_64 allowlist is exactly 70 (tier0=29, tier1=41 — v0.2 Step 1
  added the v0.2 networking syscalls + 15 native toolchain syscalls,
  Step 4 added fsync, policy.md §5 change records), and an
  independently derived aarch64 allowlist (67 syscalls) is
  regression-gated with BPF construction verified — but aarch64 filter
  installation/enforcement remains NOT VERIFIED until a native aarch64
  host is available. v0.2 Step 2: `socket` is argument-filtered to
  AF_INET/AF_INET6 (all other domains EPERM). v0.2 Step 3 implements the
  validating proxy + host firewall, so the allowlist network now provides
  real proxy-mediated outbound networking (IPv4-only; destinations
  strictly allowlisted and SSRF-validated; see ARCHITECTURE.md §8). The rootless
  namespace foundation (uid 0→caller mapping) is validated (Step 2), the
  rootfs/`pivot_root` filesystem boundary is validated (Step 3), the
  `/proc` (`hidepid=2`) + minimal `/dev` + `/sys`-absence boundary is
  validated (Step 4), and the network deny-by-construction boundary
  (only `lo` DOWN, no addresses/routes, no usable path) is validated
  (Step 5) — all container-validated (uid 1001); native rootless mapping
  remains blocked by the GitHub runner's AppArmor restriction, while the
  native Ubuntu 24.04 VM (commit 7c1c30e) verifies the complete HARDENED
  path including cgroup enforcement. Device nodes are
  six identity-verified host bind-mounts (ADR-015); `no_new_privs` is
  established in sandbox PID 1 and its kernel state read back and
  verified (Step 6, S-010); the FULL capability bounding-set drop +
  cleared effective/permitted/inheritable/ambient sets are verified by
  read-back (Step 7, S-009 — the workload holds no capabilities, which
  resolves the Step 5 lo-toggle residual: without CAP_NET_ADMIN the
  workload  cannot bring its own loopback up); the derived 70-syscall
  default-deny seccomp filter is installed as the LAST Stage-A operation
  and verified by kernel-observable read-back + forbidden-syscall EPERM
  enforcement, with fork/exec inheritance  (Step 8, S-011 — the socket
  class is argument-filtered: AF_INET/AF_INET6 allowed for the v0.2
  proxy path, AF_UNIX/AF_NETLINK/AF_PACKET denied, socketpair denied;
  see the v0.2 Step 2 row above); the six mandated rlimits
  (RLIMIT_CPU/AS/NPROC/NOFILE/FSIZE, CORE=0) are lowered (soft == hard)
  in PID 1 AFTER the seccomp install (prlimit64 is allowlisted — no
  filter change) and verified by kernel-state read-back, the workload
  cannot raise them (S-027, Step 9, S-012); cgroup v2 (Step 10,
  ADR-007 READING A) requires ALL FOUR controllers (pids/memory/cpu/io)
  in a delegated subtree — `pids.max`/`memory.max`/`cpu.max` per config
  and `io.max` on the kernel-resolved workspace backing device (an
  unresolvable device is a refusal, never a skip); HARDENED refuses AT
  `resources` with the precise detected reason when delegation is
  unavailable (Docker rootless: cgroupfs read-only; WSL2 privileged:
  memory/io controllers unavailable) — cgroup enforcement is VERIFIED
  (NATIVE) on the documented Ubuntu 24.04 / kernel 6.8 substrate with a
  caller-owned delegated subtree (commit 7c1c30e, all four controllers
  enforced); environment sanitization
  (Step 11), credential/socket isolation (Step 12), bounded output
  (Step 13), external timeout (Step 14) and process-tree containment +
  cleanup verification  (Step 15) complete the mechanism chain - the
  EXECUTION stage registers and the isolated modes initialize to READY
  on a capable substrate; the CLI (`python -m agent_sandbox`), MCP
  (`python -m agent_sandbox.mcp`) and API (`python -m agent_sandbox.api`)
  thin front-ends (ADR-013) are the only ways to reach the boundary and
  carry no security policy. RESTRICTED (rlimits only, ADR-007) completes
  `resources` and advances.

## Known limitations

- **aarch64 runtime enforcement is not verified** — the aarch64 syscall
  allowlist (67 syscalls) is derived and BPF construction is verified, but
  filter installation/enforcement requires a native ARM64 host.
- **Single-process workloads only** — `clone`/`clone3` are denied by
  design (S-014); npm/cargo dependency workflows are therefore unsupported
  inside the sandbox (measured; no syscall expansion).
- **Network** — IPv4-only upstream path; the host firewall requires
  iptables + CAP_NET_ADMIN and fails closed otherwise.
- **Native CI substrate** — GitHub-hosted ubuntu-24.04 runners deny the
  `setgroups` write (AppArmor userns restriction), so namespace and
  filesystem real-path tests skip there (never a false PASS); the full
  rootless mapping + rootfs boundary is exercised on Docker (uid 1001),
  and the complete HARDENED path on the native VM (commit 7c1c30e).
- **No GitHub Release object / PyPI publication** — the v0.2.0 git tag is
  the release marker; no GitHub Release or PyPI package exists.
- **Package version vs release tag** — `pyproject.toml` and
  `agent_sandbox.__version__` still report `0.1.0.dev0` while the release
  tag is `v0.2.0`; a coordinated version bump + release-test update is
  tracked but not yet applied.
- **Independent security review not yet performed** — required before any
  production-ready claim; see the section below.

## Documents

| Document | What it is |
|---|---|
| `ARCHITECTURE.md` | Structure, trust boundaries, exact Linux mechanisms, Phase 0 acceptance criteria |
| `THREAT_MODEL.md` | 56 threats (T-001..T-056) mapped to the security invariants |
| `SECURITY_SPEC.md` | The invariants (S-001…S-040) the implementation must demonstrate |
| `ADRs/` | 14 architecture decision records |
| `docs/seccomp-derivation/` | The reproducible seccomp allowlist derivation (methodology, classification, policy, verification) |
| `RELEASE_CHECKLIST.md` | Phase 20 release hardening checklist — every v0.1 criterion with evidence-backed status |
| `SECURITY_REVIEW.md` | Independent Security Review evidence package — prepared for external reviewer (NOT YET PERFORMED) |

## Independent Security Review

The implementation specification requires an independent security review
before the project can claim production-ready status. The reviewer must
not be the primary author of the security-critical implementation.

**Status: REQUIRED / NOT YET PERFORMED**

`SECURITY_REVIEW.md` contains the reviewer-ready evidence package covering
all 13 security-review areas (trust boundaries, privileged code, namespace
setup, filesystem handling, network enforcement, capability configuration,
seccomp, resource controls, policy enforcement, lifecycle cleanup, race
conditions, MCP/API authorization, audit integrity). The project must NOT
claim production-ready status solely from internal testing.

## Companion tools

`agent-sandbox` is the execution/security layer of the agent-* family:

- [agent-memory](https://github.com/vartiainen1/agent-memory) — trust-filtered memory
- [agent-error-log](https://github.com/vartiainen1/agent-error-log) — error logging
- [agent-decision-log](https://github.com/vartiainen1/agent-decision-log) — decision logging
- [agent-log-ai](https://github.com/vartiainen1/agent-log-ai) — LLM-derived lessons
- [agent-blame](https://github.com/vartiainen1/agent-blame) — history analysis
- [agent-diff-gate](https://github.com/vartiainen1/agent-diff-gate) — change gating

Integrations are optional and must never become part of the security
boundary.

## Release

- **v0.2.0** — annotated, GPG-signed tag at CI-green HEAD `605b688`
  (== `master`); `git tag -v v0.2.0` reports a Good signature. GitHub-side
  verification shows `false` until the signing public key is uploaded to
  the account.
- **master** is pushed; GitHub Actions run 38 is green on native Ubuntu
  3.11 and 3.12.
- **Release artifacts** — deterministic, reproducible sdist + wheel
  (`tools/release/build_release.py`: `SOURCE_DATE_EPOCH` pinned, sdist
  normalization, two-clean-build byte-identity), GNU `SHA256SUMS` +
  per-artifact `.sha256`, and detached-armor GPG signatures (`.asc`) for
  the v0.2.0 artifacts; `verify` fails on tamper.
- **v0.1.0** tag remains local-only (never pushed).
- Release readiness status: `RELEASE_CHECKLIST.md`.

## Development

```bash
python -m unittest discover -s tests      # full suite
python tools/release/test_release.py      # release tooling checks
python tools/seccomp-derivation/check_trace_regression.py   # seccomp gate
```

Test layout: `tests/unit/`, `tests/adversarial/`, `tests/fuzz/`,
`tests/regression/`. CI (`.github/workflows/ci.yml`) runs the full suite
plus ruff, mypy, bandit, pip-audit, detect-secrets, the seccomp
trace/regression gate, and the release-reproducibility gate; security
scan failures block CI.

## Implementation and verification status

| Layer | Status |
|---|---|
| Architecture + threat model (Phase 0) | **COMPLETE** — `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY_SPEC.md`, `ADRs/` |
| Seccomp syscall allowlist derivation (Phase 1 pre-task) | **COMPLETE, container-validated** — 70-syscall HARDENED allowlist (tier0 29 + tier1 41; v0.2 Step 1 expanded the v0.1 46-syscall baseline by 23 network + native-toolchain syscalls, Step 4 added fsync for the dependency-installation workflow, policy.md §5 change records), behaviorally verified |
| v0.2 Step 1 — seccomp expansion | **COMPLETE** — 46 → 69 syscalls (8 v0.2 networking prerequisites + 15 native toolchain variants), aarch64 51 → 66; clone/clone3, ptrace, mount, chroot, unshare, socketpair remain denied; netns remains deny-by-construction; native trace-regression gate PASS |
| v0.2 Step 2 — allowlist network plumbing + socket domain filtering | **COMPLETE** — `network_mode` accepts `deny`/`allowlist`; veth-pair plumbing (create/move/configure/verify/cleanup) + supervisor↔PID-1 net-ready pipe wired; `socket` argument-filtered to AF_INET/AF_INET6 (AF_UNIX/AF_NETLINK/AF_PACKET EPERM — S-003/S-004 preserved); seccomp count unchanged (69). Native VM runbook: `RUNBOOK_v0.2_STEP2_NATIVE_VERIFICATION.md` |
| v0.2 Step 4 / Phase 10 — dependency-installation workflow | **COMPLETE** — curated toolchain adds `python3-pip` (self-contained pip/_vendor incl. CA bundle); `pip install --proxy http://10.255.254.0:8080 ...` works inside the sandbox through the validating proxy. Seccomp: 69 → **70** (+`fsync` only — the single syscall pip genuinely requires, proven under a real default-deny EPERM filter; bind/clock_nanosleep/mremap/readlinkat/rmdir stay denied, clone/clone3 stay denied — pip uses vfork/posix_spawn, thread count 0). Also corrected during measurement: x86_64 `getsockname`/`getpeername` numbers (50/51 → 51/52; the wrong numbers made getpeername always-EPERM in the sandbox). Evidence: `trace-results.json` t1_pip_install (56 successful syscalls, all inside the allowlist); full-sandbox e2e PASS (pip through proxy; disallowed source DENIED; teardown clean — no veth/firewall/proxy leaks). Runbook: `RUNBOOK_v0.2_STEP4_DEPENDENCY_INSTALLATION_NATIVE_VERIFICATION.md` |
| v0.2 Step 3 — validating proxy + host firewall | **COMPLETE** — `isolation/proxy.py` (host-side validating forward proxy: CONNECT protocol, destination allowlist, SSRF gate with host-side DNS resolution — DNS-rebinding safe; `allow_private` relaxes only RFC 1918/6598, never loopback/link-local/metadata) + `network.py install_host_firewall` (iptables INPUT/FORWARD: the proxy port is the ONLY destination accepted from the veth — no direct host access) + `config.py network_allowlist` (strict validation, dead entries rejected, deny-mode consistency). The sandbox's ONLY path out is the proxy; proxy setup/probe/teardown failures fail closed; IPv6 is disabled on the sandbox-side veth (IPv4-only path). Full unit 846 OK / 0 fail / 283 documented skips; adversarial 70 OK; fuzz 21 OK; N1 42 OK; native container e2e verified (workload reaches only the proxy; direct host access DROPPED; AF_UNIX EPERM) — runbook: `RUNBOOK_v0.2_STEP3_VALIDATING_PROXY_NATIVE_VERIFICATION.md`. Known limitation: IPv4-only upstream; iptables + CAP_NET_ADMIN required for the host firewall (fail closed otherwise) |
| Runtime implementation (Phase 1) | **COMPLETE (Steps 1–16)** — minimal skeleton + Linux namespace isolation (Step 2) + minimal root filesystem with `pivot_root`, workspace copy isolation, and private mount propagation (Step 3) + `/proc` isolation (`hidepid=2`), minimal `/dev` (six identity-verified bind-mounted nodes, ADR-015), `/sys` absence (Step 4) + network namespace deny-by-construction (only `lo` DOWN, no addresses/routes, no usable path — Step 5) + no_new_privs (Step 6) + full capability reduction (Step 7) + seccomp filter installation (Step 8) + rlimits (Step 9) + cgroup v2 enforcement module (Step 10) + environment sanitization (Step 11, the approved six-variable sandbox environment — host env never inherited, S-034) + credential/socket isolation (Step 12 — host credential/control-socket paths absent, socket env vars never survive, socket creation denied by the filter, S-003/S-004) + bounded stdout/stderr (Step 13 — S-037 bounded supervisor pipe, terminate + truncation notice, workload cannot bypass) + external timeout enforcement (Step 14 — S-036 supervisor wall-clock deadline, session termination, workload cannot disable/evade/reset) + process-tree containment and cleanup (Step 15 — S-014 child subreaper + namespace-init kill + cgroup.kill where delegated + mandatory S-038 absence verification, survivors never reported as success) + minimal successful workload demonstration (Step 16 — item 22: a workload executes end-to-end through the complete boundary, returning deterministic output and observing the invariants from inside) implemented and tested; the full mandated Phase 1 order (items 1–22) is complete |
| Interfaces (CLI/MCP/API) | **COMPLETE** — three thin front-ends (ADR-013) over the SOLE execution path `RuntimeSession.execute(ExecutionRequest) -> run_in_sandbox()`, sharing one session core (`agent_sandbox/interface` — the same initialize/execute code for MCP and API); CLI (`python -m agent_sandbox`): argv-only (`--` separator), `--json` exposes mode + session identity, deterministic exit codes; **Phase B command surface (implementation.md Phase 8)**: `create`/`exec`/`run`/`status`/`diff`/`logs`/`destroy`/`list` — `create` validates policy + initializes fail-closed and persists a validated session under the caller-owned state dir (`AGENT_SANDBOX_STATE_DIR` or `~/.agent-sandbox`, never mounted into the sandbox); `exec`/`status`/`diff`/`logs`/`destroy` re-open it with STRICT re-validation (unknown/destroyed session or malformed/tampered manifest fails closed, exit 5 — never executed); `diff` runs `git diff` INSIDE the sandbox on /workspace gated on the `git.read` capability (repository contents treated as untrusted, never read host-side); `logs` exposes the session's ADR-012 audit events observationally (S-024 — missing/malformed audit is empty, never an execution blocker) with S-023 session correlation; `destroy` terminates any live sandbox via the existing lifecycle mechanism, VERIFIES absence (S-038) and never claims success on incomplete cleanup (exit 6, retryable); every command routes through the same `RuntimeSession.execute()` READY/REFUSED + policy gate (S-015) — no alternate security path, no subprocess/os.system/execve in the CLI (structural guard); MCP (`python -m agent_sandbox.mcp`): stdio JSON-RPC 2.0, minimum surface (`initialize` + `execute`), id preservation, deterministic -32700/-32600/-32601/-32602/-32603 errors, no host details leak; API (`python -m agent_sandbox.api`): stdlib-only HTTP (zero dependencies), `POST /initialize` + `POST /execute`, loopback-only default bind, deterministic 400/404/405/413/500 errors (internal failures are a fixed generic message); three-way CLI/MCP/API decision equivalence tested (same ExecutionRequest, same payload fields, mode + session identity); the execve bridge runs commands INSIDE the sandbox (workspace-provided binaries; the minimal rootfs has no system binaries — unavailable commands fail deterministically, never on the host); minimal host-side JSONL audit recorder (ADR-012, observational, open-per-record so no audit fd crosses the fork boundary) |
| Phase 2 — adversarial validation | **ACCEPTED AND FROZEN** — P1 (T-047/48/49, commit 5408ce3) + P2 (18 HOST-SIDE-only threats, commit dc1590a) + exec-bridge regression: 59/59 in-sandbox adversarial tests PASS through the real `RuntimeSession.execute() -> run_in_sandbox()` boundary; evidence reconciled in `THREAT_MODEL.md` §7/§10 (22 threats NATIVE VERIFIED, 24 DOCKER VERIFIED, 7 HOST-SIDE, 2 DESIGN INTENT); seccomp regression gate repaired and PASS (allowlist exactly 45, tier0=27/tier1=18); full suite green (Windows 547 run / 0 failures; Docker 547 run / 1 documented non-root environment failure); no enforcement boundary weakened; **P3 HARDENED end-to-end VERIFIED (NATIVE)** (commit 7c1c30e — Ubuntu 24.04 / kernel 6.8 / x86_64 native QEMU VM, caller-owned delegated cgroup subtree, 24/24 PASS, 0 skips/errors); **P4 aarch64 runtime enforcement remains SUBSTRATE-LIMITED / NOT VERIFIED** (native aarch64 required) |
| Phase 4 — capability policy engine | **COMPLETE (v0.1 surface, implementation.md Phase 4 / ADR-010)** — `agent_sandbox/policy.py`: versioned (v1), strictly validated, capability-based policy (filesystem/process/git/network/secrets/privileged), deny-by-default, unknown fields/capabilities rejected (S-021), immutable + host-side only, never mounted into the sandbox (S-026); the single decision path (S-015) is enforced in `RuntimeSession.execute()` — the same gate CLI, MCP and API share (ADR-013) — before any boundary work, with `policy_loaded`/`policy_decision` audit events (S-022/S-023); CLI `--policy PATH` + interface `policy` param; zero new runtime dependencies (stdlib JSON, ADR-010 fallback — TCB rule honored); policy/config resource conflicts rejected (S-027, ADR-007 single source); 45 test additions (validation/decision/immutability/session gate/rootfs-absence/CLI/interface + N1 policy rows) |
| Phase 10 — Dependency Workflows | **Python/pip workflow COMPLETE (v0.2 Step 4, 2026-08-23)** — dependency *containment* was NATIVE VERIFIED earlier (T-048/S-033) and the *installation* workflow is now implemented: `pip install --proxy http://10.255.254.0:8080` runs inside the sandbox through the validating proxy (Step 3) with the curated toolchain's python3-pip; seccomp 69 → 70 (+`fsync` only — the single genuinely-required syscall, proven under a real default-deny EPERM filter; bind/clock_nanosleep/mremap/readlinkat/rmdir stay denied, clone/clone3 stay denied — pip uses vfork/posix_spawn). **Node/Rust (npm/cargo) workflows: MEASURED and INTENTIONALLY UNSUPPORTED (2026-08-23, no syscall expansion)** — real-filter measurement proves both tools unconditionally require `clone3` (Node's platform scheduler thread at startup for every workload; cargo spawning rustc even for `cargo fetch`); clone/clone3 are the S-014 single-process containment boundary, so npm/cargo remain unsupported inside the sandbox and fail closed cleanly (node rc=139, cargo rc=101; no hang, no leak). Decision + evidence: policy.md §5, `test_proxy.py::Phase10NpmCargoDecisionTests` / `Phase10NpmCargoFailClosedTests` |
| Phase 15 — Fuzzing (Phase E) | **COMPLETE (implementation.md Phase 15 / security-spec.md §15)** — deterministic, bounded, stdlib-only fuzz harnesses (fixed seed `0xC0FFEE`, bounded rounds, fully repeatable; zero new dependencies — TCB rule): `tests/fuzz/test_fuzz_parsers.py` fuzzes the security-sensitive parsers (policy `from_dict`/`load_policy_file` — no capability amplification, no policy-state corruption; `RuntimeConfig.from_dict` — network_mode can never parse to anything but the sole v0.1 value `deny`; environment allowlist construction — only the approved six-variable surface; registry session-id gate + manifest read-back — fail closed, identity match enforced; git sanitized-argv builder — hostile args stay single literal argv elements; MCP `parse_message` — deterministic JSON-RPC error codes only; audit recorder — never raises, output stays valid JSONL) and `tests/fuzz/test_fuzz_interfaces.py` fuzzes CLI argv vectors (fail-closed argument/registry paths against an empty state dir — int exit code, never raises, never mutates session state; `create`/`run` excluded by design — they reach the real initialization boundary, covered by the dedicated integration suites) and the audit read-back (fuzzed on-disk JSONL parsed observationally, S-024). **The harness caught three genuine fail-safe defects, all fixed within scope (2026-08-22): F-1** `_parse_network_mode` crashed with `TypeError` on unhashable `network_mode` values → string type-guard added (deterministic `ConfigError`); **F-3** `logs` crashed with `UnicodeDecodeError` on non-UTF-8 audit bytes → `errors="replace"`; **F-4** `logs` crashed with `AttributeError` on valid-JSON non-dict audit lines → `isinstance(ev, dict)` observational skip. 21/21 fuzz tests PASS; N1 harness-hygiene rows added; CI fuzz step added. **Evidence classification: HOST-SIDE / unit-level** — the fuzz harness exercises the validation/protocol layers that run on the trusted side before any boundary work; it does NOT replace native kernel-boundary verification (that remains the native/adversarial suites). |
| Phase 17 — Security Regression Suite | **COMPLETE (implementation.md Phase 21 / security-spec.md)** — `tests/regression/test_s_invariant_coverage.py`: explicit S-001..S-040 coverage matrix mapping every SECURITY_SPEC.md invariant to one or more authoritative test classes; structural gate verifies every mapped module/class exists (44 tests: 31 pass, 13 skipped — Windows substrate — 0 failures); smoke tests run representative methods from each mapped class; evidence classification: HOST-SIDE / unit-level; no production code changed, no seccomp/policy/enforcement change. |
| Phase 16 — Race and Concurrency Testing | **COMPLETE (implementation.md Phase 16 / security-spec.md S-031)** — `tests/unit/test_race_concurrency.py`: 13 host-side race/concurrency tests across 5 classes: `RegistryAtomicityTests` (concurrent writers produce valid manifests, concurrent read-during-write never observes corrupt state, concurrent create/destroy remains consistent — Windows file-locking tolerance documented); `SessionStateRaceTests` (concurrent execute+destroy, concurrent execute-twice, destroy-during-init — state machine remains consistent under concurrency); `CleanupRaceTests` (concurrent destroy idempotent, destroy-during-output-collection terminates cleanly); `WorkspaceConcurrentModificationTests` (concurrent file creation remains contained, symlink-replacement-during-read never exposes host data); `PolicyAccessRaceTests` (concurrent `decide()`/`require()` are deterministic and thread-safe). Documentation: corrected the THREAT_MODEL over-claim referencing non-existent `test_lifecycle.py::RaceTests`; added Phase 16 evidence to T-009 and T-039. No production code changed; no seccomp/policy/enforcement change. **Evidence classification: HOST-SIDE / unit-level** — exercises supervisor-level concurrency; does NOT replace native kernel-boundary verification. |
| Phase 18 — Static and Dependency Analysis | **COMPLETE (implementation.md Phase 18)** — CI-integrated security and code-quality tooling: `ruff` (linting — security + code-quality rules, F/S/B selected, justified exclusions for intentional patterns), `mypy` (type checking — platform-specific Linux-attr ignores documented), `bandit` (Python security scanning — B101/B108/B606/B110/B603/B607 exclusions justified: assert-for-invariants, tempfile-safe-pattern, subprocess-no-shell-safe, observational-fail-safe), `pip-audit` (dependency audit — zero runtime deps verified), `detect-secrets` (secret scanning — baseline with 7 documented false positives: cache files + test fixtures). Coverage measurement available via `coverage.py`. All tools configured in `pyproject.toml`. CI steps added to `.github/workflows/ci.yml` — security-scan failures block CI. No production code changed; no seccomp/policy/enforcement change. **Evidence classification: CI/tooling-level** — proves static analysis and security scanning gates exist; does NOT replace native kernel-boundary verification, adversarial testing, or seccomp verification. |
| Phase 9 — safe Git workflow (Phase C) | **COMPLETE (implementation.md Phase 9)** — `agent_sandbox/git.py`: a CLOSED read-only operation set (status/diff/changed/untracked/deleted/base/current → builtin status/ls-files/merge-base/rev-parse; commit/push/fetch/checkout/submodule are usage errors, never a passthrough) and a sanitized argv builder: highest-precedence `-c` overrides neutralize hostile repository configuration (core.fsmonitor — executed by `git status`/`diff`, diff.external/textconv — executed by `git diff`, aliases, credential helpers, hooks, ssh, pager/editor, submodule recursion, protocol), builtin words alias-pinned, `-C /workspace` pinned, `--no-ext-diff --no-textconv` on diff — all empirically verified against a genuinely hostile fixture (control: plain `git diff` executes the hostile external-diff + fsmonitor scripts; sanitized: zero markers). The repository is hostile input (ARCHITECTURE 3.2); git executes INSIDE the boundary (network deny-by-construction, zero caps, bounded output S-037, timeout S-036, tree cleanup S-038) — the boundary is the enforcement layer, config control is defense-in-depth. CLI: `git <session-id> <operation> [--json] [-- args...]` gated on the existing `git.read` capability through the single policy decision path (S-015 — no second authorization mechanism; CLI/API/MCP decision-equivalent); the Phase B `diff` command uses the sanitized argv. Evidence: `test_git_workflow.py` (20 tests: closed op set, argv construction, CLI routing, policy/session fail-closed, result mapping), `test_git_attacks.py` (7 host-side hostile-config containment tests + 4 real-boundary containment tests, substrate-gated), 5 N1 git fail-closed rows; adversarial 70 run; zero new runtime dependencies |
| Phase 20 — Release Hardening | **COMPLETE (implementation.md section 24)** — documented in `RELEASE_CHECKLIST.md`: every v0.1 security criterion has an evidence-backed status. v0.1 acceptance criteria satisfied (implementation.md section 26): runtime, filesystem/process/network isolation, privilege reduction, resource controls, environment sanitization, fail-closed init, session lifecycle, structured audit, CLI, regression tests, adversarial tests — all VERIFIED. Not claimed: production-ready, fully verified, signed release, independently reviewed. Release artifact reproducibility: **VERIFIED** (`tools/release/build_release.py` — deterministic sdist+wheel with `SOURCE_DATE_EPOCH` pinned, sdist header normalization, two-clean-build byte-identity gate, GNU `SHA256SUMS` + per-artifact `.sha256`, tamper-detecting `verify`; `tools/release/test_release.py` 17/17 PASS, CI Phase 20 step). Release integrity: **VERIFIED** — checksums mechanized + tamper-detecting `verify`; cryptographic signing performed with `AGENT_SANDBOX_GPG_KEY` (the v0.2.0 artifacts in `dist/` carry detached-armor `.asc` signatures; fails closed exit 2 without the key). Signed commits: NOT VERIFIED (commits are not signed); the v0.2.0 **tag** is GPG-signed (see Release). Independent Security Review: REQUIRED / NOT YET PERFORMED (implementation.md section 25). aarch64: SUBSTRATE-LIMITED / NOT VERIFIED. Full SECURITY_SPEC.md coverage: PARTIALLY VERIFIED only. Release tag: CREATED — v0.2.0, annotated + GPG-signed at CI-green HEAD 605b688 (== master). |

This repository contains the security design, the reproducible seccomp
derivation tooling, and the complete Phase 1 runtime (Steps 1-16: skeleton,
namespace isolation, filesystem boundary, `/proc`+`/dev`+`/sys` boundary,
network deny-by-construction, no_new_privs, capability reduction, seccomp
installation, rlimits, cgroup v2, environment sanitization,
credential/socket isolation, bounded output, external timeout, process-tree
containment + cleanup verification, and the minimal successful workload
demonstration) plus the thin CLI/MCP front-ends. On a capable substrate
(Docker uid 1001) the isolated modes initialize to READY and a
workspace-provided command executes end-to-end through the boundary via
`python -m agent_sandbox` (CLI) or `python -m agent_sandbox.mcp` (stdio
JSON-RPC). HARDENED is **end-to-end verified on native Linux** with a
caller-owned/delegated cgroup v2 subtree (commit 7c1c30e — Ubuntu 24.04 /
kernel 6.8 / x86_64 native QEMU VM, 24/24 PASS), and still refuses AT
`resources` with the precise detected reason on hosts without cgroup v2
delegation (ADR-007), so nothing should be used to sandbox a workload on
such a host. The HARDENED substrate requirement is: caller-owned/delegated
cgroup subtree with cpu/io/memory/pids controllers available and enabled,
required resource controls established and read back, and a resolvable
real backing device where io.max enforcement is required; if these cannot
be established HARDENED execution refuses to start (no compatibility
fallback).
Native Linux validation runs in CI and is authoritative over the
Docker-based results (see `docs/seccomp-derivation/verification.md` for
the exact labeling).

## License

[MIT](LICENSE)
