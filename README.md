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
| Seccomp syscall allowlist derivation (Phase 1 pre-task) | **COMPLETE, container-validated** — 46-syscall HARDENED allowlist (45 derived + the documented 2026-08-22 `+chdir` for the Phase C git closed set, policy.md §5 change record), behaviorally verified |
| Runtime implementation (Phase 1) | **COMPLETE (Steps 1–16)** — minimal skeleton + Linux namespace isolation (Step 2) + minimal root filesystem with `pivot_root`, workspace copy isolation, and private mount propagation (Step 3) + `/proc` isolation (`hidepid=2`), minimal `/dev` (six identity-verified bind-mounted nodes, ADR-015), `/sys` absence (Step 4) + network namespace deny-by-construction (only `lo` DOWN, no addresses/routes, no usable path — Step 5) + no_new_privs (Step 6) + full capability reduction (Step 7) + seccomp filter installation (Step 8) + rlimits (Step 9) + cgroup v2 enforcement module (Step 10) + environment sanitization (Step 11, the approved six-variable sandbox environment — host env never inherited, S-034) + credential/socket isolation (Step 12 — host credential/control-socket paths absent, socket env vars never survive, socket creation denied by the filter, S-003/S-004) + bounded stdout/stderr (Step 13 — S-037 bounded supervisor pipe, terminate + truncation notice, workload cannot bypass) + external timeout enforcement (Step 14 — S-036 supervisor wall-clock deadline, session termination, workload cannot disable/evade/reset) + process-tree containment and cleanup (Step 15 — S-014 child subreaper + namespace-init kill + cgroup.kill where delegated + mandatory S-038 absence verification, survivors never reported as success) + minimal successful workload demonstration (Step 16 — item 22: a workload executes end-to-end through the complete boundary, returning deterministic output and observing the invariants from inside) implemented and tested; the full mandated Phase 1 order (items 1–22) is complete |
| Interfaces (CLI/MCP/API) | **COMPLETE** — three thin front-ends (ADR-013) over the SOLE execution path `RuntimeSession.execute(ExecutionRequest) -> run_in_sandbox()`, sharing one session core (`agent_sandbox/interface` — the same initialize/execute code for MCP and API); CLI (`python -m agent_sandbox`): argv-only (`--` separator), `--json` exposes mode + session identity, deterministic exit codes; **Phase B command surface (implementation.md Phase 8)**: `create`/`exec`/`run`/`status`/`diff`/`logs`/`destroy` — `create` validates policy + initializes fail-closed and persists a validated session under the caller-owned state dir (`AGENT_SANDBOX_STATE_DIR` or `~/.agent-sandbox`, never mounted into the sandbox); `exec`/`status`/`diff`/`logs`/`destroy` re-open it with STRICT re-validation (unknown/destroyed session or malformed/tampered manifest fails closed, exit 5 — never executed); `diff` runs `git diff` INSIDE the sandbox on /workspace gated on the `git.read` capability (repository contents treated as untrusted, never read host-side); `logs` exposes the session's ADR-012 audit events observationally (S-024 — missing/malformed audit is empty, never an execution blocker) with S-023 session correlation; `destroy` terminates any live sandbox via the existing lifecycle mechanism, VERIFIES absence (S-038) and never claims success on incomplete cleanup (exit 6, retryable); every command routes through the same `RuntimeSession.execute()` READY/REFUSED + policy gate (S-015) — no alternate security path, no subprocess/os.system/execve in the CLI (structural guard); MCP (`python -m agent_sandbox.mcp`): stdio JSON-RPC 2.0, minimum surface (`initialize` + `execute`), id preservation, deterministic -32700/-32600/-32601/-32602/-32603 errors, no host details leak; API (`python -m agent_sandbox.api`): stdlib-only HTTP (zero dependencies), `POST /initialize` + `POST /execute`, loopback-only default bind, deterministic 400/404/405/413/500 errors (internal failures are a fixed generic message); three-way CLI/MCP/API decision equivalence tested (same ExecutionRequest, same payload fields, mode + session identity); the execve bridge runs commands INSIDE the sandbox (workspace-provided binaries; the minimal rootfs has no system binaries — unavailable commands fail deterministically, never on the host); minimal host-side JSONL audit recorder (ADR-012, observational, open-per-record so no audit fd crosses the fork boundary) |
| Phase 2 — adversarial validation | **ACCEPTED AND FROZEN** — P1 (T-047/48/49, commit 5408ce3) + P2 (18 HOST-SIDE-only threats, commit dc1590a) + exec-bridge regression: 59/59 in-sandbox adversarial tests PASS through the real `RuntimeSession.execute() -> run_in_sandbox()` boundary; evidence reconciled in `THREAT_MODEL.md` §7/§10 (22 threats NATIVE VERIFIED, 24 DOCKER VERIFIED, 7 HOST-SIDE, 2 DESIGN INTENT); seccomp regression gate repaired and PASS (allowlist exactly 45, tier0=27/tier1=18); full suite green (Windows 547 run / 0 failures; Docker 547 run / 1 documented non-root environment failure); no enforcement boundary weakened; **P3 HARDENED end-to-end VERIFIED (NATIVE)** (commit 7c1c30e — Ubuntu 24.04 / kernel 6.8 / x86_64 native QEMU VM, caller-owned delegated cgroup subtree, 24/24 PASS, 0 skips/errors); **P4 aarch64 runtime enforcement remains SUBSTRATE-LIMITED / NOT VERIFIED** (native aarch64 required) |
| Phase 4 — capability policy engine | **COMPLETE (v0.1 surface, implementation.md Phase 4 / ADR-010)** — `agent_sandbox/policy.py`: versioned (v1), strictly validated, capability-based policy (filesystem/process/git/network/secrets/privileged), deny-by-default, unknown fields/capabilities rejected (S-021), immutable + host-side only, never mounted into the sandbox (S-026); the single decision path (S-015) is enforced in `RuntimeSession.execute()` — the same gate CLI, MCP and API share (ADR-013) — before any boundary work, with `policy_loaded`/`policy_decision` audit events (S-022/S-023); CLI `--policy PATH` + interface `policy` param; zero new runtime dependencies (stdlib JSON, ADR-010 fallback — TCB rule honored); policy/config resource conflicts rejected (S-027, ADR-007 single source); 45 test additions (validation/decision/immutability/session gate/rootfs-absence/CLI/interface + N1 policy rows) |
| Phase 10 — Dependency Workflows | **DEFERRED / ARCHITECTURALLY BLOCKED in v0.1 (implementation.md Phase 10)** — dependency *containment* is NATIVE VERIFIED (T-048/S-033: `test_content_attacks.py::DependencyAttackTests` — install payloads execute inside the boundary and stay contained), but no dependency-*installation* workflow exists. Networked package installation (pip/npm/cargo from registries) is **prohibited by design**: ADR-006 defers all network to v0.2 ("no package installs, git fetch, or any network workflow in v0.1"), the netns is deny-by-construction (no interfaces, loopback down), and the seccomp filter denies the entire socket class. Even an OFFLINE pip install cannot run under the current HARDENED policy: measured natively (pip 24.0, `--no-index --no-deps`, pure wheel, `--target`) it uses **58 distinct syscalls — 14 outside the 46-syscall allowlist, including the forbidden `socket`/`bind` (pip opens sockets even offline) and `clone` (threading) classes** — so enabling it would require weakening the network boundary and the documented thread-denial design. Node/Rust workflows additionally require curated toolchain/TCB decisions. Distinction: (a) dependency **containment** = VERIFIED; (b) dependency **installation workflow** = DEFERRED / NOT IMPLEMENTED |
| Phase 15 — Fuzzing (Phase E) | **COMPLETE (implementation.md Phase 15 / security-spec.md §15)** — deterministic, bounded, stdlib-only fuzz harnesses (fixed seed `0xC0FFEE`, bounded rounds, fully repeatable; zero new dependencies — TCB rule): `tests/fuzz/test_fuzz_parsers.py` fuzzes the security-sensitive parsers (policy `from_dict`/`load_policy_file` — no capability amplification, no policy-state corruption; `RuntimeConfig.from_dict` — network_mode can never parse to anything but the sole v0.1 value `deny`; environment allowlist construction — only the approved six-variable surface; registry session-id gate + manifest read-back — fail closed, identity match enforced; git sanitized-argv builder — hostile args stay single literal argv elements; MCP `parse_message` — deterministic JSON-RPC error codes only; audit recorder — never raises, output stays valid JSONL) and `tests/fuzz/test_fuzz_interfaces.py` fuzzes CLI argv vectors (fail-closed argument/registry paths against an empty state dir — int exit code, never raises, never mutates session state; `create`/`run` excluded by design — they reach the real initialization boundary, covered by the dedicated integration suites) and the audit read-back (fuzzed on-disk JSONL parsed observationally, S-024). **The harness caught three genuine fail-safe defects, all fixed within scope (2026-08-22): F-1** `_parse_network_mode` crashed with `TypeError` on unhashable `network_mode` values → string type-guard added (deterministic `ConfigError`); **F-3** `logs` crashed with `UnicodeDecodeError` on non-UTF-8 audit bytes → `errors="replace"`; **F-4** `logs` crashed with `AttributeError` on valid-JSON non-dict audit lines → `isinstance(ev, dict)` observational skip. 21/21 fuzz tests PASS; N1 harness-hygiene rows added; CI fuzz step added. **Evidence classification: HOST-SIDE / unit-level** — the fuzz harness exercises the validation/protocol layers that run on the trusted side before any boundary work; it does NOT replace native kernel-boundary verification (that remains the native/adversarial suites). |
| Phase 16 — Race and Concurrency Testing | **COMPLETE (implementation.md Phase 16 / security-spec.md S-031)** — `tests/unit/test_race_concurrency.py`: 13 host-side race/concurrency tests across 5 classes: `RegistryAtomicityTests` (concurrent writers produce valid manifests, concurrent read-during-write never observes corrupt state, concurrent create/destroy remains consistent — Windows file-locking tolerance documented); `SessionStateRaceTests` (concurrent execute+destroy, concurrent execute-twice, destroy-during-init — state machine remains consistent under concurrency); `CleanupRaceTests` (concurrent destroy idempotent, destroy-during-output-collection terminates cleanly); `WorkspaceConcurrentModificationTests` (concurrent file creation remains contained, symlink-replacement-during-read never exposes host data); `PolicyAccessRaceTests` (concurrent `decide()`/`require()` are deterministic and thread-safe). Documentation: corrected the THREAT_MODEL over-claim referencing non-existent `test_lifecycle.py::RaceTests`; added Phase 16 evidence to T-009 and T-039. No production code changed; no seccomp/policy/enforcement change. **Evidence classification: HOST-SIDE / unit-level** — exercises supervisor-level concurrency; does NOT replace native kernel-boundary verification. |
| Phase 9 — safe Git workflow (Phase C) | **COMPLETE (implementation.md Phase 9)** — `agent_sandbox/git.py`: a CLOSED read-only operation set (status/diff/changed/untracked/deleted/base/current → builtin status/ls-files/merge-base/rev-parse; commit/push/fetch/checkout/submodule are usage errors, never a passthrough) and a sanitized argv builder: highest-precedence `-c` overrides neutralize hostile repository configuration (core.fsmonitor — executed by `git status`/`diff`, diff.external/textconv — executed by `git diff`, aliases, credential helpers, hooks, ssh, pager/editor, submodule recursion, protocol), builtin words alias-pinned, `-C /workspace` pinned, `--no-ext-diff --no-textconv` on diff — all empirically verified against a genuinely hostile fixture (control: plain `git diff` executes the hostile external-diff + fsmonitor scripts; sanitized: zero markers). The repository is hostile input (ARCHITECTURE 3.2); git executes INSIDE the boundary (network deny-by-construction, zero caps, bounded output S-037, timeout S-036, tree cleanup S-038) — the boundary is the enforcement layer, config control is defense-in-depth. CLI: `git <session-id> <operation> [--json] [-- args...]` gated on the existing `git.read` capability through the single policy decision path (S-015 — no second authorization mechanism; CLI/API/MCP decision-equivalent); the Phase B `diff` command uses the sanitized argv. Evidence: `test_git_workflow.py` (20 tests: closed op set, argv construction, CLI routing, policy/session fail-closed, result mapping), `test_git_attacks.py` (7 host-side hostile-config containment tests + 4 real-boundary containment tests, substrate-gated), 5 N1 git fail-closed rows; adversarial 70 run; zero new runtime dependencies |

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
are interfaces, never the boundary.

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
coreutils + CPython + git) makes exactly **46 syscalls** (45 derived +
the documented 2026-08-22 `+chdir` for the git closed set — native
verification, policy.md §5 change record); the policy
allows exactly those (default-deny EPERM), and the behavioral probe
verifies both halves: legitimate workloads pass, and
`socket`/`ptrace`/`mount`/`chroot`/`unshare`/`clone` return EPERM.

- Canonical artifact: `tools/seccomp-derivation/allowlist.json`
- Regression gate: `check_trace_regression.py` fails any observed syscall
  outside the allowlist (no undocumented expansion)
- Change control: `docs/seccomp-derivation/policy.md` §5
- Known limitations: threads (`clone`) and networking syscalls are denied
  by design in v0.1; the x86_64 allowlist is exactly 46 (tier0=27,
  tier1=19 — the only change from the frozen Phase-2 baseline of 45 is the
  documented 2026-08-22 `+chdir` for the Phase C git closed set, policy.md
  §5), and an independently derived aarch64 allowlist (43 syscalls, commit
  a5338da) is regression-gated with BPF construction verified — but aarch64
  filter installation/enforcement remains NOT VERIFIED until a native
  aarch64 host is available. The rootless
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
  workload  cannot bring its own loopback up); the derived 46-syscall
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
