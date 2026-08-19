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

45 syscalls, all derived and classified in `syscall-classification.md`:

    access arch_prctl brk close dup2 epoll_create1 execve exit_group
    fcntl fstat futex getcwd getdents64 getegid geteuid getgid getpid
    getppid getrandom gettid getuid ioctl lseek mkdir mmap mprotect
    munmap newfstatat openat pipe2 poll pread64 prlimit64 read readlink
    rseq rt_sigaction rt_sigprocmask rt_sigreturn set_robust_list
    set_tid_address unlink vfork wait4 write

Machine-readable form: the `ALLOWED` list in
`tools/seccomp-derivation/probe_policy.py` (which also serves as the
reference BPF implementation for Phase 1 step 13).

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

## 5. Change control

The allowlist is **not** edited ad hoc:

1. A workload that needs a syscall outside the allowlist is a derivation
   input, not a policy patch. Re-run the tracer with that workload,
   classify the new syscall (methodology steps 3-7), update the
   classification table and this policy, and re-run the verification probe.
2. Removing a syscall from the allowlist requires re-running step 11
   (prohibited-op verification) to confirm the behavior still holds.
3. Any change is a code + docs + tests change through the normal review
   path (ADR if it affects the security contract).
4. The probe's `ALLOWED` list and this document must stay in sync — the
   probe is the machine-readable source of truth; this document is the
   rationale.

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
