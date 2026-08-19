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
| Runtime implementation (Phase 1) | **IN PROGRESS (Step 2)** — minimal skeleton + Linux namespace isolation (user/mount/PID/network/UTS/IPC with uid/gid mapping) implemented and tested; still no runnable sandbox/CLI |

This repository currently contains the security design, the reproducible
seccomp derivation tooling, and the first Phase 1 runtime mechanisms
(Step 1 skeleton, Step 2 namespace isolation). **There is still no
runnable sandbox**; HARDENED initialization honestly refuses at the first
mechanism that is not yet implemented (currently `filesystem`), so nothing
here should be used to sandbox a workload. Native Linux validation runs
in CI and is authoritative over the Docker-based results (see
`docs/seccomp-derivation/verification.md` for the exact labeling).

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
  namespace foundation (uid 0→caller mapping) is validated (Step 2); the
  full runtime path (pivot_root, privileges, seccomp, resources) is not
  yet (Steps 3+).

## Validation labeling

| Substrate | Status | Purpose |
|---|---|---|
| Native Linux (GitHub Actions ubuntu) | **Authoritative** — CI runs trace + regression gate + behavioral probe + rootless capability detection + namespace tests | Security claims |
| Docker Desktop (container) | Development / reproducible observation; **only substrate where the full rootless mapping is currently exercised** (uid 1001) | Iteration on Windows; never labeled as native |

**Known native limitation (documented, not hidden)**: the GitHub-hosted
ubuntu-24.04 runner permits unprivileged `unshare(CLONE_NEWUSER)` but its
AppArmor userns restriction denies the `setgroups`-deny write (EACCES), so
the uid 0→caller mapping cannot be established there. The namespace
real-path tests therefore skip on native CI with the recorded reason
(never a false PASS); the fail-closed refusal is verified natively; and
the namespace boundary execution evidence is VERIFIED DOCKER until a
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
