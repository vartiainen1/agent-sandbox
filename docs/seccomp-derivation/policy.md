# Seccomp Derivation — Derived HARDENED Policy

Status: ACCEPTED (Phase 1 pre-task, 2026-08-19) · Source: this derivation
exercise (methodology + classification) · Implementation: Phase 1 step 13
(`agent_sandbox/security/seccomp.py`).

---

## 1. Policy shape

- **Mode**: HARDENED only. The filter is mandatory in HARDENED; if it
  cannot be installed, the workload is not executed (fail closed, S-018).
- **Default action**: `SECCOMP_RET_ERRNO | EPERM` (deny with a usable
  errno). Anything not explicitly allowed is denied.
- **Architecture guard**: a workload on a non-x86_64 architecture is
  killed (`SECCOMP_RET_KILL_PROCESS`) rather than allowed — an allowlist
  derived for one architecture must never be silently applied to another.
- **Install point**: last Stage-A operation, after `no_new_privs`,
  capability drops, rlimits, cgroup joins, and rootfs setup; immediately
  before the workload exec. Everything between install and exec
  (`dup2`, `chdir`, `execve`) is in the allowlist.

## 2. The allowlist (Stage B — workload execution)

46 syscalls (27 tier0 + 19 tier1), all derived and classified in
`syscall-classification.md`:

    access arch_prctl brk chdir close dup2 epoll_create1 execve
    exit_group fcntl fstat futex getcwd getdents64 getegid geteuid
    getgid getpid getppid getrandom gettid getuid ioctl lseek mkdir
    mmap mprotect munmap newfstatat openat pipe2 poll pread64 prlimit64
    read readlink rseq rt_sigaction rt_sigprocmask rt_sigreturn
    set_robust_list set_tid_address unlink vfork wait4 write

Machine-readable form (single source of truth):
`tools/seccomp-derivation/allowlist.json`. The behavioral probe loads it;
the regression gate (`check_trace_regression.py`) fails any observed
syscall outside it; the unit suite (`test_derivation.py`) pins its
integrity (46, sorted, unique, default action).

## 3. What is denied and why (summary)

- **Network syscall class** (`socket` family): denied — v0.1 network is
  deny-by-construction; syscall-level denial is defense-in-depth.
- **Namespace class** (`unshare`, `setns`, `mount`-class, `pivot_root`,
  `chroot`): denied — the sandbox must never change its own isolation.
- **Process-inspection class** (`ptrace`, `process_vm_*`): denied.
- **Privilege class** (`setuid`-class, `setgid`-class, `capset`,
  `chmod`-class, `chown`-class, `mknod`): denied — uid mapping happens in
  Stage A; the workload never needs these.
- **Thread class** (`clone`, `clone3`): denied — not required by the
  traced surface; also the namespace-flag vector. Consequence documented:
  CPython `threading` unavailable in v0.1.
- **Kernel/device class** (`bpf`, `perf_event_open`, `keyctl`,
  `kexec_*`, `reboot`, `swapon`, `swapoff`, `iopl`, `ioperm`,
  `init_module`-class): denied.
- **Unobserved misc** (`madvise`, `readv`, `writev`, `sendfile`,
  `rename`-class, `link`-class, `symlink`-class, `setxattr`-class,
  `open`, `stat`-class, everything else): denied per prefer-removal.

Full per-syscall rationale: `syscall-classification.md`.

## 4. Division of labor (what seccomp is NOT)

Seccomp restricts the **syscall surface**. It is not the filesystem
boundary (that is the rootfs/`pivot_root` + no-host-mounts construction,
which seccomp cannot replace), not the network boundary (the netns with no
interfaces), not the resource boundary (rlimits + cgroups), and not the
credential boundary (no mounts, env allowlist). The layers are
independent: seccomp denies `socket` even if the netns were misconfigured;
the rootfs denies `/etc/passwd` even if `openat` is allowed.

## 5. Change control — NO UNDOCUMENTED SYSCALL EXPANSION

The allowlist is a regression-protected security artifact
(`tools/seccomp-derivation/allowlist.json`) and is **not** edited ad hoc:

1. A workload that needs a syscall outside the allowlist is a derivation
   input, not a policy patch. Re-run the tracer with that workload,
   classify the new syscall (methodology steps 3-7), update the
   classification table, this policy, AND `allowlist.json` together, and
   re-run the verification probe.
2. **Mechanical gate**: `check_trace_regression.py` fails any trace whose
   observed syscall set contains a syscall outside `allowlist.json` — an
   accidental or undocumented expansion is detected in CI and locally.
   The native CI job runs trace → gate → probe on every push.
3. Removing a syscall from the allowlist requires re-running step 11
   (prohibited-op verification) to confirm the behavior still holds.
4. Any change is a code + docs + tests change through the normal review
   path (ADR if it affects the security contract). Required per change:
   explicit diff, documented reason, security-impact assessment, relevant
   test changes, docs update.
5. `allowlist.json` is the machine-readable source of truth; the probe
   loads it, the gate checks against it, and the unit suite pins its
   integrity — this document is the rationale.

### Change record

- **2026-08-22 — `+chdir` (tier1, 45 → 46; tier0=27, tier1=19).** Native
  Phase C verification (Ubuntu 24.04 / kernel 6.8 / x86_64, git 2.43.0)
  proved the closed-set git workflow cannot execute inside the sandbox
  without `chdir`: every closed-set operation (`status`/`diff`/
  `ls-files`/`merge-base`/`rev-parse`, sanitized argv with `-C
  /workspace`) chdirs for the worktree handling and work-tree-top
  resolution, and the default-deny filter returned EPERM (`fatal: cannot
  change to '/workspace': Operation not permitted`). Host/native strace
  of the exact closed set: 38 distinct syscalls, of which `chdir` is the
  ONLY one outside the prior 45-allowlist (no fork/clone needed;
  helpers neutralized). Security impact: `chdir` is cwd-only — no
  privilege gain, no namespace/network/filesystem-boundary escape; the
  path-set enforcement remains the rootfs/`pivot_root` boundary (§4).
  Evidence: `trace-results.json` `t1_git_closedset` (native trace),
  `tests/adversarial/test_git_attacks.py` `SandboxGitContainmentTests`
  4/4 PASS on the native substrate, `tests/native/test_hardened_e2e.py`
  re-run green. Tooling fix in the same change: `trace_workloads.py`
  `parse_trace` now handles strace's `[pid NNNN]` fork-child line prefix
  (the container-era records under-recorded forked-child syscalls — the
  reason git's `chdir` was absent from the derivation); the historical
  container records are preserved verbatim with a note in
  `trace-results.json`.

## 6. Known limitations (documented, not hidden)

- CPython `threading` / thread-based `multiprocessing` are unavailable
  (no `clone`). Re-derive when threads enter the required surface.
- No network syscalls of any kind (also enforced by the netns); socket-
  based libraries fail. Intended for v0.1.
- x86_64/glibc-specific; other architectures must re-derive.
- `ioctl` remains broad; bounded by minimal `/dev` and dropped
  capabilities.
- The filter is syscall-level with one arg rule (`arch_prctl` subset);
  it does not attempt path-based filtering (that is the filesystem
  boundary's role).
