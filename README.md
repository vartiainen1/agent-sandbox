# agent-sandbox

Security-first execution environment for autonomous AI agents. An
untrusted AI agent (or a hostile repository, dependency, or build script
running under it) gets a useful Linux environment for real software
engineering — files, tests, builds, Git — while the host is protected by
an OS-enforced isolation boundary and every security-relevant action is
audited.

> The AI requests actions. The policy determines whether they are allowed.
> The operating system enforces the boundary. The audit system records the
> result. The host remains protected.

## Status — read this first

| Layer | Status |
|---|---|
| Architecture + threat model (Phase 0) | **COMPLETE** — `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY_SPEC.md`, `ADRs/` |
| Seccomp syscall allowlist derivation (Phase 1 pre-task) | **COMPLETE, container-validated** — 45-syscall HARDENED allowlist, behaviorally verified |
| Runtime implementation (Phase 1) | **COMPLETE (Steps 1–16)** — minimal skeleton + Linux namespace isolation (Step 2) + minimal root filesystem with `pivot_root`, workspace copy isolation, and private mount propagation (Step 3) + `/proc` isolation (`hidepid=2`), minimal `/dev` (six identity-verified bind-mounted nodes, ADR-015), `/sys` absence (Step 4) + network namespace deny-by-construction (only `lo` DOWN, no addresses/routes, no usable path — Step 5) + no_new_privs (Step 6) + full capability reduction (Step 7) + seccomp filter installation (Step 8) + rlimits (Step 9) + cgroup v2 enforcement module (Step 10) + environment sanitization (Step 11, the approved six-variable sandbox environment — host env never inherited, S-034) + credential/socket isolation (Step 12 — host credential/control-socket paths absent, socket env vars never survive, socket creation denied by the filter, S-003/S-004) + bounded stdout/stderr (Step 13 — S-037 bounded supervisor pipe, terminate + truncation notice, workload cannot bypass) + external timeout enforcement (Step 14 — S-036 supervisor wall-clock deadline, session termination, workload cannot disable/evade/reset) + process-tree containment and cleanup (Step 15 — S-014 child subreaper + namespace-init kill + cgroup.kill where delegated + mandatory S-038 absence verification, survivors never reported as success) + minimal successful workload demonstration (Step 16 — item 22: a workload executes end-to-end through the complete boundary, returning deterministic output and observing the invariants from inside) implemented and tested; the full mandated Phase 1 order (items 1–22) is complete |
| Interfaces (CLI/MCP/API) | **COMPLETE** — three thin front-ends (ADR-013) over the SOLE execution path `RuntimeSession.execute(ExecutionRequest) -> run_in_sandbox()`, sharing one session core (`agent_sandbox/interface` — the same initialize/execute code for MCP and API); CLI (`python -m agent_sandbox`): argv-only (`--` separator), `--json` exposes mode + session identity, deterministic exit codes; MCP (`python -m agent_sandbox.mcp`): stdio JSON-RPC 2.0, minimum surface (`initialize` + `execute`), id preservation, deterministic -32700/-32600/-32601/-32602/-32603 errors, no host details leak; API (`python -m agent_sandbox.api`): stdlib-only HTTP (zero dependencies), `POST /initialize` + `POST /execute`, loopback-only default bind, deterministic 400/404/405/413/500 errors (internal failures are a fixed generic message); three-way CLI/MCP/API decision equivalence tested (same ExecutionRequest, same payload fields, mode + session identity); the execve bridge runs commands INSIDE the sandbox (workspace-provided binaries; the minimal rootfs has no system binaries — unavailable commands fail deterministically, never on the host); minimal host-side JSONL audit recorder (ADR-012, observational, open-per-record so no audit fd crosses the fork boundary) |

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
JSON-RPC). HARDENED still refuses AT `resources` with the precise
detected reason on hosts without cgroup v2 delegation (ADR-007), so
nothing should be used to sandbox a workload on such a host.
Native Linux validation runs in CI and is authoritative over the
Docker-based results (see `docs/seccomp-derivation/verification.md` for
the exact labeling).

## Security model (the short version)

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
(not yet implemented) are interfaces, never the boundary.

## Documents

| Document | What it is |
|---|---|
| `ARCHITECTURE.md` | Structure, trust boundaries, exact Linux mechanisms, Phase 0 acceptance criteria |
| `THREAT_MODEL.md` | 54 threats mapped to the security invariants |
| `SECURITY_SPEC.md` | The invariants (S-001…S-040) the implementation must demonstrate |
| `ADRs/` | 14 architecture decision records |
| `docs/seccomp-derivation/` | The reproducible seccomp allowlist derivation (methodology, classification, policy, verification) |

## Seccomp derivation (Phase 1 pre-task)

The HARDENED syscall allowlist is a **derived, regression-protected
security artifact** — not a hardcoded list and not "whatever strace
happened to see". The workload set (Tier 0 `echo hello`-class, Tier 1
coreutils + CPython + git) makes exactly **45 syscalls**; the policy
allows exactly those (default-deny EPERM), and the behavioral probe
verifies both halves: legitimate workloads pass, and
`socket`/`ptrace`/`mount`/`chroot`/`unshare`/`clone` return EPERM.

- Canonical artifact: `tools/seccomp-derivation/allowlist.json`
- Regression gate: `check_trace_regression.py` fails any observed syscall
  outside the allowlist (no undocumented expansion)
- Change control: `docs/seccomp-derivation/policy.md` §5
- Known limitations: threads (`clone`) and networking syscalls are denied
  by design in v0.1; the allowlist is x86_64/glibc-specific. The rootless
  namespace foundation (uid 0→caller mapping) is validated (Step 2), the
  rootfs/`pivot_root` filesystem boundary is validated (Step 3), the
  `/proc` (`hidepid=2`) + minimal `/dev` + `/sys`-absence boundary is
  validated (Step 4), and the network deny-by-construction boundary
  (only `lo` DOWN, no addresses/routes, no usable path) is validated
  (Step 5) — all container-validated (uid 1001); native rootless mapping
  remains blocked by the runner's AppArmor restriction. Device nodes are
  six identity-verified host bind-mounts (ADR-015); `no_new_privs` is
  established in sandbox PID 1 and its kernel state read back and
  verified (Step 6, S-010); the FULL capability bounding-set drop +
  cleared effective/permitted/inheritable/ambient sets are verified by
  read-back (Step 7, S-009 — the workload holds no capabilities, which
  resolves the Step 5 lo-toggle residual: without CAP_NET_ADMIN the
  workload cannot bring its own loopback up); the derived 45-syscall
  default-deny seccomp filter is installed as the LAST Stage-A operation
  and verified by kernel-observable read-back + forbidden-syscall EPERM
  enforcement, with fork/exec inheritance  (Step 8, S-011 — the socket
  class is syscall-denied at workload time); the six mandated rlimits
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
  memory/io controllers unavailable), so cgroup enforcement remains
  NOT VERIFIED on every current substrate; environment sanitization
  (Step 11), credential/socket isolation (Step 12), bounded output
  (Step 13), external timeout (Step 14) and process-tree containment +
  cleanup verification  (Step 15) complete the mechanism chain - the
  EXECUTION stage registers and the isolated modes initialize to READY
  on a capable substrate; the CLI (`python -m agent_sandbox`), MCP
  (`python -m agent_sandbox.mcp`) and API (`python -m agent_sandbox.api`)
  thin front-ends (ADR-013) are the only ways to reach the boundary and
  carry no security policy. RESTRICTED (rlimits only, ADR-007) completes
  `resources` and advances.

## Validation labeling

| Substrate | Status | Purpose |
|---|---|---|
| Native Linux (GitHub Actions ubuntu) | **Authoritative** — CI runs trace + regression gate + behavioral probe + rootless capability detection + namespace tests + filesystem-boundary tests + proc/dev/sys boundary tests + network deny-by-construction tests + no_new_privs/capability-reduction/seccomp tests + rlimits tests + cgroup v2 tests | Security claims |
| Docker Desktop (container) | Development / reproducible observation; **only substrate where the full rootless mapping + rootfs/pivot_root + proc/dev/sys + network boundary is currently exercised** (uid 1001) | Iteration on Windows; never labeled as native |

**Known native limitation (documented, not hidden)**: the GitHub-hosted
ubuntu-24.04 runner permits unprivileged `unshare(CLONE_NEWUSER)` but its
AppArmor userns restriction denies the `setgroups`-deny write (EACCES), so
the uid 0→caller mapping cannot be established there. The namespace and
filesystem-boundary real-path tests therefore skip on native CI with the
recorded reason (never a false PASS); the fail-closed refusal is verified
natively; and the boundary execution evidence is VERIFIED DOCKER until a
native host that can provide the mechanism exists (see
`docs/seccomp-derivation/verification.md`).

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

## License

[MIT](LICENSE)
