# Seccomp Derivation — Syscall Classification

Per-syscall answers to the derivation questions (methodology step 5).
Evidence source: `tools/seccomp-derivation/trace-results.json`
(container-validated run, 2026-08-19; native re-run pending CI).

Legend:
- **Tier**: 0 = required by the minimal `echo hello`-class workload; 1 =
  required by the intended v0.1 toolchain (coreutils, CPython, git-traced).
- **Stage**: B = workload execution (the only filtered stage; see
  methodology step 2/9). Init (A) and cleanup (C) run unfiltered and never
  appear here.
- **Decision**: ALLOW (in the allowlist) or DENY (excluded; default-deny
  returns EPERM).

---

## 1. Allowed syscalls (45)

### 1.1 Process lifecycle and creation

| Syscall | Tier | Required by | Can it be removed? | What breaks? | Security impact if allowed | Decision |
|---|---|---|---|---|---|---|
| `execve` | 0 | every workload | No | nothing can run | Executes programs — required by definition; `no_new_privs` + dropped caps block privilege gain via exec | ALLOW |
| `vfork` | 1 | dash/git/CPython subprocess | No | `sh` cannot run external commands; python subprocess fails | Process creation; fork-bomb containment is the resource layer's job (`pids.max`, `RLIMIT_NPROC`) | ALLOW |
| `exit_group` | 0 | every workload | No | processes cannot exit | None | ALLOW |
| `wait4` | 1 | dash, git, PID-1 reaping | No | zombie accumulation; **sandbox PID 1 must reap its children** (orphans reparent to it, not to the host subreaper) | None | ALLOW |
| `getpid` | 0 | glibc/Python | No | programs cannot identify themselves | None | ALLOW |
| `getppid` | 0 | glibc/Python | No | job control / parent queries break | None | ALLOW |
| `gettid` | 1 | glibc (TLS bookkeeping) | Removable for Tier 0 only | Python single-threaded startup uses it | None | ALLOW |
| `set_tid_address` | 0 | glibc (thread bookkeeping) | No | glibc startup fails | None | ALLOW |
| `set_robust_list` | 0 | glibc (futex bookkeeping) | No | glibc startup fails | None | ALLOW |
| `rseq` | 0 | glibc restartable sequences | Removable (glibc tolerates EPERM by disabling rseq) | minor perf regression only | None — kept because observed and free | ALLOW |
| `arch_prctl` | 0 | glibc (fsbase/TLS) | No | TLS setup fails; every process breaks | None | ALLOW |

### 1.2 Signals

| Syscall | Tier | Required by | Can it be removed? | What breaks? | Security impact | Decision |
|---|---|---|---|---|---|---|
| `rt_sigaction` | 0 | glibc/Python signal handling | No | signal handlers cannot be installed | None | ALLOW |
| `rt_sigprocmask` | 1 | glibc | No | signal masking broken | None | ALLOW |
| `rt_sigreturn` | 1 | kernel signal trampoline | No | signals cannot return | None | ALLOW |

### 1.3 Memory

| Syscall | Tier | Required by | Can it be removed? | What breaks? | Security impact | Decision |
|---|---|---|---|---|---|---|
| `mmap` | 0 | loader/interpreter | No | nothing can load | None | ALLOW |
| `mprotect` | 0 | loader/JIT | No | code cannot set page permissions | None (W^X is an app-level property; not a seccomp concern) | ALLOW |
| `munmap` | 0 | loader | No | memory cannot be released | None | ALLOW |
| `brk` | 0 | glibc heap | No | heap allocation fails | None | ALLOW |

### 1.4 File I/O (workspace + rootfs surface)

| Syscall | Tier | Required by | Can it be removed? | What breaks? | Security impact | Decision |
|---|---|---|---|---|---|---|
| `openat` | 0 | everything | No | nothing can open files | Filesystem access — the *scope* of paths is enforced by the rootfs/pivot_root boundary, not seccomp (division of labor: seccomp restricts the syscall surface, the filesystem boundary restricts the path set). `open` (legacy) is denied; only `openat` allowed | ALLOW |
| `read` | 0 | everything | No | nothing can read | None | ALLOW |
| `write` | 0 | everything | No | no output | None | ALLOW |
| `close` | 0 | everything | No | fd leak → exhaustion | None | ALLOW |
| `fstat` | 0 | glibc/Python | No | stat of open fds fails | None | ALLOW |
| `newfstatat` | 1 | glibc `stat` | No | every `stat()` fails | None | ALLOW |
| `lseek` | 1 | Python files, git | No | file seeking broken | None | ALLOW |
| `pread64` | 1 | Python files | Removable for Tier 0 | Python file reads fail | None | ALLOW |
| `getdents64` | 1 | `ls`, git | No | directory listing broken | None | ALLOW |
| `access` | 0 | glibc/git | No | permission checks fail | None | ALLOW |
| `readlink` | 1 | Python/glibc | No | symlink resolution fails | None | ALLOW |
| `getcwd` | 0 | shell/Python | No | cwd queries fail | None | ALLOW |
| `mkdir` | 1 | coreutils | No | directory creation broken | None | ALLOW |
| `unlink` | 1 | `rm` | No | file deletion broken | None | ALLOW |
| `dup2` | 1 | shell redirection | No | redirection broken | None | ALLOW |
| `pipe2` | 1 | shell pipelines, subprocess | No | pipes broken | None | ALLOW |
| `fcntl` | 1 | Python (fd flags) | No | fd flag manipulation fails | None | ALLOW |

### 1.5 Misc runtime

| Syscall | Tier | Required by | Can it be removed? | What breaks? | Security impact | Decision |
|---|---|---|---|---|---|---|
| `ioctl` | 1 | git (terminal), glibc | Removable for Tier 0 | git terminal handling breaks | Broad syscall — dangerous uses blocked by layers: minimal `/dev` (no device nodes), no capabilities, `TIOCSTI` restricted by modern kernels. Allowed only because required; re-review if a workload needs device ioctls | ALLOW |
| `prlimit64` | 1 | glibc/Python `getrlimit` | Removable for Tier 0 | resource queries fail | Limit *changes* are kernel-enforced: raising hard limits requires `CAP_SYS_RESOURCE` (dropped), so the workload can only ever lower its own limits | ALLOW |
| `futex` | 1 | CPython (GIL) | No (Tier 1) | Python deadlocks without it | None | ALLOW |
| `poll` | 1 | subprocess wait | No (Tier 1) | subprocess status wait fails | None | ALLOW |
| `epoll_create1` | 1 | CPython internal | Removable for Tier 0 | — | None | ALLOW |
| `getrandom` | 0 | glibc/Python entropy | No | RNG initialization fails | None (kernel entropy source; no fd) | ALLOW |
| `getuid` | 0 | glibc | No | identity queries fail | None | ALLOW |
| `geteuid` | 0 | glibc | No | identity queries fail | None | ALLOW |
| `getgid` | 0 | glibc | No | identity queries fail | None | ALLOW |
| `getegid` | 0 | glibc | No | identity queries fail | None | ALLOW |

**Count: 45 ALLOW.** No syscall in the allowed set enables privilege
escalation, namespace manipulation, process inspection of the host, or
networking on its own; the three broad ones (`ioctl`, `prlimit64`,
`openat`) are documented above with the layers that bound them.

---

## 2. Denied syscalls (high-impact, with rationale)

Everything not in §1 is denied by the default-deny action. The following
are the security-relevant denials, with the reason each is excluded.
**None of these was observed in the workload traces** — every one is
denied by absence, and several (socket, clone) were additionally probed
behaviorally.

| Syscall(s) | Why denied |
|---|---|
| `socket`, `socketpair`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `getsockopt`, `setsockopt`, `shutdown`, `getpeername`, `getsockname` | Networking. v0.1 is deny-by-construction (no interfaces, loopback down); syscall-level denial is defense-in-depth and also blocks AF_UNIX. Verified: `python socket()` → EPERM |
| `clone`, `clone3` | Thread/process creation with flags. Denied because (a) no workload needed it (only `vfork` was observed), and (b) `clone(CLONE_NEW*)` is a namespace-escape primitive. Verified: `threading.Thread().start()` → EPERM. **Known limitation**: CPython threading and thread-based multiprocessing are unavailable in v0.1 |
| `unshare`, `setns` | Namespace manipulation — the sandbox must never change its own isolation |
| `mount`, `umount2`, `pivot_root`, `chroot`, `chroot`-class | Filesystem/namespace boundary manipulation. Verified: `mount` → EPERM |
| `ptrace`, `process_vm_readv`, `process_vm_writev` | Process inspection/injection — the classic sandbox-escape tool. Verified: `ptrace` → EPERM |
| `bpf`, `perf_event_open`, `keyctl`, `add_key`, `request_key`, `fanotify_init`, `inotify_init`-class (unobserved) | Kernel instrumentation / credential keyrings |
| `kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`, `iopl`, `ioperm` | Kernel/device control |
| `init_module`, `finit_module`, `delete_module` | Kernel module loading |
| `mknod`, `mknodat` | Device node creation |
| `setuid`, `setgid`, `setgroups`, `capset`, `setresuid`-class, `setresgid`-class | Identity/privilege change. The userns uid mapping is done in Stage A (unfiltered); the workload never needs these |
| `chmod`, `fchmod`, `fchmodat`, `chown`, `fchown`, `lchown`, `fchownat` | Metadata/ownership change — not observed in the traced surface; denied until a workload genuinely requires it (re-derive) |
| `rename`, `renameat`, `renameat2`, `link`, `linkat`, `symlink`, `symlinkat` | Not observed; denied. Hardlink/symlink creation is a filesystem-boundary concern; if a future workload needs them, re-derive with rationale |
| `setxattr`, `lsetxattr`, `fsetxattr`, `removexattr`-class | Not observed; denied |
| `madvise`, `readv`, `writev`, `sendfile`, `pwrite64`, `open` (legacy), `stat`, `lstat`, `oldstat`-class | Not observed in the traced surface; denied per prefer-removal. (Python/C can fall back to read/write/pread64; if a real workload needs e.g. `writev`, re-derive) |
| everything else | Default-deny: any syscall not explicitly allowed returns EPERM |

---

## 3. Arg-level rules (within allowed syscalls)

The filter is syscall-level by default; the following argument
sensitivities are documented for the seccomp implementation (Phase 1
step 13) and are candidates for arg-aware BPF where cheap:

| Syscall | Rule |
|---|---|
| `arch_prctl` | only `ARCH_SET_FS`/`ARCH_GET_FS` (values 0x1002/0x1003) — deny `ARCH_SET_GS`/`ARCH_SET_CPUID`/`ARCH_GET_CPUID` |
| `openat` | path scope is the filesystem boundary's job (rootfs/pivot_root), not seccomp's — no path arg-filtering (documented division of labor) |
| `ioctl` | deny by arg class is impractical (git needs terminal ioctls); rely on minimal `/dev` + dropped caps; revisit if a workload requests device ioctls |
| `prlimit64` | no arg rule needed: raising hard limits is kernel-denied without `CAP_SYS_RESOURCE` |

The two high-value arg rules (`arch_prctl` subset; everything else is
syscall-level) keep the filter simple and auditable. Arg-aware filtering
that adds complexity without a demonstrated threat is avoided
(methodology step 6: prefer removal/simplicity over cleverness).

---

## 4. Platform dependence

- Syscall numbers and the arch check are **x86_64** (AUDIT_ARCH_X86_64);
  a non-matching architecture is KILLed by the filter. Other architectures
  (aarch64, etc.) must re-derive the table from the same methodology.
- The observed surface is glibc-based ubuntu 24.04 (CPython 3.12). musl or
  other libcs will differ slightly; re-run the tracer on the target.
- Container observation ran as root without a user namespace; native CI
  re-runs with the real uid mapping (verified results in
  `verification.md`).
