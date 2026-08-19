# ADR-008 — Capabilities and Seccomp: Bounding-Set Drop + no_new_privs + BPF Default-Deny

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-008 (no privilege gain), S-009 (capability restriction), S-010
(no_new_privs), S-011 (syscall restriction). The design (§9–11) forbids
dangerous capabilities and requires seccomp enforcement that is *tested*,
not merely configured. The exact syscall allowlist depends on the actual
toolchain (Python, shell, git, build tools), which does not exist yet.

## Decision

- Drop the **entire capability bounding set** (`PR_CAPBSET_DROP` for every
  capability) and clear inheritable/ambient sets before exec — the workload
  and anything it execs hold no capabilities, including inside its user
  namespace. `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`,
  `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_DAC_OVERRIDE` are never granted.
- Enable `prctl(PR_SET_NO_NEW_PRIVS)` before any untrusted exec (S-010).
- Apply a **seccomp BPF filter** via `prctl(PR_SET_SECCOMP,
  SECCOMP_MODE_FILTER)`, default action **EPERM (deny)**, with an explicit
  allowlist. Filter installation is the last security step before exec.
- Dangerous syscalls denied in HARDENED: `mount`, `umount2`, `ptrace`,
  `unshare`, `setns`, `chroot`, `pivot_root`, `keyctl`, `bpf`, `kexec*`,
  `reboot`, `swapon/swapoff`, `iopl/ioperm`, `clone(CLONE_NEW*)` flags,
  `setuid/setgid`-class and capability syscalls.
- **The exact allowlist is derived empirically in Phase 1** (trace the real
  toolchain under a default-deny filter, review every permitted syscall)
  and reviewed before any release. Until then, seccomp enforcement tests
  assert *behavior* (syscalls actually denied), not config presence.

## Consequences

- Positive: workload has no capabilities, cannot gain privileges, and is
  syscall-restricted with a default-deny stance.
- Negative: allowlist completeness is the one mechanism whose Phase-0 spec
  is intentionally deferred (flagged in ARCHITECTURE §19); a too-tight list
  breaks legitimate workloads (availability), a too-loose one widens the
  kernel surface. Both are caught by tests + review.

## References

ARCHITECTURE §10, §19; THREAT_MODEL T-023…T-027; security spec §10, §15.
