# ADR-001 — Runtime Substrate: Native Linux Syscalls via Python ctypes, Rootless

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

The design forbids a "Docker wrapper" as the product and demands OS-level
enforcement: namespaces, cgroups, seccomp, capabilities, `pivot_root`
(design §4, implementation §2). The implementation must be dependency-light
(family convention) and the TCB must stay small. The dev machine is
Windows; Linux is the target platform, validated natively in CI.

## Decision

- The supervisor and security-init are implemented in **Python 3.11+
  (stdlib-first)**, invoking Linux primitives directly via **ctypes**:
  `unshare(2)`, `prctl(2)` (no_new_privs, bounding-set drop, seccomp,
  subreaper), `setrlimit(2)`, `pivot_root(2)`, `mount(2)` during init only,
  cgroup v2 filesystem writes.
- Execution is **rootless**: user namespaces with uid/gid map 0 → caller.
  `sudo agent-sandbox` is never required (design §5).
- Docker is **not** the security boundary; it is a validation substrate
  only (see ADR-014).

## Consequences

- Positive: no privileged helper in v0.1; the entire boundary is reachable
  unprivileged; TCB is our own small code, not a container runtime.
- Negative: ctypes syscall code is delicate and must be probed through the
  real execution path; seccomp BPF is constructed in-process (ADR-008).
- Risk: a host without user namespaces cannot run HARDENED → fail closed
  (ARCHITECTURE §19).

## References

ARCHITECTURE §5, §5.1; implementation plan §2 (rules 3–5), §35.
