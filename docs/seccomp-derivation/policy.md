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

70 syscalls (29 tier0 + 41 tier1), all derived and classified in
`syscall-classification.md`:

    access arch_prctl brk chmod chdir close close_range connect
    copy_file_range dup2 epoll_create1 execve exit_group fadvise64
    fcntl fstat fstatfs fsync futex getcwd getdents64 getegid
    geteuid getgid getpeername getpid getppid getrandom getsockname
    getsockopt gettid getuid ioctl lgetxattr link listxattr lseek
    mkdir mmap mprotect munmap newfstatat openat pipe2 poll pread64
    prlimit64 read readlink recvfrom rename rseq rt_sigaction
    rt_sigprocmask rt_sigreturn sendto set_robust_list
    set_tid_address setsockopt socket statfs statx symlink umask
    uname unlink unlinkat vfork wait4 write

Machine-readable form (single source of truth):
`tools/seccomp-derivation/allowlist.json`. The behavioral probe loads it;
the regression gate (`check_trace_regression.py`) fails any observed
syscall outside it; the unit suite (`test_derivation.py`) pins its
integrity (70, sorted, unique, default action).

## 3. What is denied and why (summary)

- **Network syscall class** (`socketpair`, `bind`, `listen`, `accept`,
  `accept4`, `sendmsg`, `recvmsg`, `shutdown`): denied. `socket`,
  `connect`, `sendto`, `recvfrom`, `getsockopt`, `setsockopt`,
  `getsockname`, `getpeername` are now ALLOWED for v0.2 proxy
  communication (see §5 changelog).
- **Socket DOMAIN argument filtering (v0.2 Step 2)**: the `socket`
  syscall itself is allowlisted, but the BPF filter loads `args[0]` (the
  domain) and allows ONLY `AF_INET` (2) and `AF_INET6` (10). All other
  domains — `AF_UNIX` (1), `AF_NETLINK` (16), `AF_PACKET` (17), and
  everything else — are denied with EPERM. This preserves S-003/S-004
  (credential + Unix-socket isolation): the workload can open an
  inet-family socket for proxy communication but cannot create a Unix
  socket, netlink socket, or raw packet socket. Layout: 4 (header) + N
  (JEQ chain) + 3 (domain sub-chain) + 1 (default deny) + 1 (ALLOW),
  pinned by `test_seccomp.py::test_build_program_layout`.
- **Namespace class** (`unshare`, `setns`, `mount`-class, `pivot_root`,
  `chroot`): denied — the sandbox must never change its own isolation.
- **Process-inspection class** (`ptrace`, `process_vm_*`): denied.
- **Privilege class** (`setuid`-class, `setgid`-class, `capset`,
  `chown`-class, `mknod`): denied — uid mapping happens in
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

- **2026-08-23 — `+socket, connect, sendto, recvfrom, getsockopt,
  setsockopt, getsockname, getpeername` (tier0+1, 46 → 54;
  tier0=29, tier1=25).** v0.2 networking prerequisites: minimum syscall
  set for sandbox-to-proxy loopback communication. `socket`+`connect`
  (tier0) required to create and connect to the validating proxy on
  `127.0.0.1`. `sendto`+`recvfrom`+`getsockopt`+`setsockopt`
  +`getsockname`+`getpeername` (tier1) required for data transfer and
  socket option management. Deliberately excluded: `shutdown` (proxy
  handles lifecycle), `sendmsg`/`recvmsg` (not needed for stream
  sockets), `bind`/`listen`/`accept` (workload is client, not server),
  `clone`/`clone3` (remain denied — threading not required for proxy
  communication). Security impact: network syscalls in isolation do not
  grant network access — the network namespace (no interfaces, loopback
  down) and seccomp are independent layers. The proxy validates all
  outbound destinations. SSRF protection is enforced by the proxy, not
  by seccomp. Native verification pending substrate availability.
  aarch64 allowlist updated correspondingly (43 → 51).

- **2026-08-23 — socket argument-level domain filtering (v0.2 Step 2,
  no syscall-count change; 69 = tier0 29 + tier1 40).** The `socket`
  entry in the BPF JEQ chain no longer jumps straight to RET_ALLOW: it
  jumps to a 3-instruction domain sub-chain that loads `args[0]` and
  allows only `AF_INET` (2) / `AF_INET6` (10), denying everything else
  (`AF_UNIX`/`AF_NETLINK`/`AF_PACKET`/…) with EPERM. Rationale: the v0.2
  allowlist-mode network path needs an AF_INET socket to reach the
  host-side validating proxy, but S-003/S-004 require that the workload
  still cannot create Unix/netlink/raw-packet sockets (host control
  sockets, credential-manager sockets, raw traffic). The deny-by-
  construction netns (no routes, lo DOWN) is unchanged in deny mode and
  remains the enforcement layer in allowlist mode until the proxy exists.
  Seccomp count UNCHANGED (69). Layout pinned by
  `test_seccomp.py::test_build_program_layout`; enforcement spot check
  switched from `socket()` to `socketpair()` (still denied in both modes).

- **2026-08-23 — `+chmod, close_range, copy_file_range, fadvise64,
  fstatfs, lgetxattr, link, listxattr, rename, statfs, statx, symlink,
  umask, uname, unlinkat` (tier1, 54 → 69; tier0=29, tier1=40).**
  Native Ubuntu 24.04 / kernel 6.8 / x86_64 trace of the complete
  workload set observed 63 unique syscalls. 15 syscalls not in the
  54-syscall allowlist were identified via `check_trace_regression.py`.
  All 15 are legitimate toolchain operations: glibc runtime (`close_range`
  batch fd close, `fadvise64` I/O hints, `statx` modern file stat),
  coreutils (`copy_file_range` kernel copy, `fstatfs`/`statfs` fs stats,
  `lgetxattr`/`listxattr` xattr queries, `umask`/`uname` process/system
  info, `unlinkat` modern unlink), and git (`chmod` object permissions,
  `link` hard-linked objects, `rename` atomic file ops, `symlink` refs).
  All 15 are tier1. None enables privilege escalation, namespace escape,
  capability changes, network access, or sandbox escape. `chmod`/`link`/
  `symlink`/`rename` operate only on workload-created files within the
  mount namespace. `clone`/`clone3` remain denied. Network namespace
  remains deny-by-construction. aarch64 mappings verified against
  `asm-generic/unistd.h`: `chmod`→`fchmodat`(53), `link`→`linkat`(37),
  `symlink`→`symlinkat`(36), `rename`→`renameat2`(276); `unlinkat` was
  already in the aarch64 allowlist.

- **2026-08-23 — `+fsync` (tier1, 69 → 70; tier0=29, tier1=41). Phase 10
  (v0.2 Step 4) dependency-installation workflow.** Native measurement
  of `pip install` (networked through the validating CONNECT proxy,
  Debian 13 container, Python 3.11, pip 24.x/25.x, strace 6.13, WSL2
  kernel 6.18) under the REAL 70-syscall filter (the project's own
  `build_program` + `install_filter`, not LD_PRELOAD) proved exactly one
  syscall is genuinely required beyond the 69 baseline: `fsync` — pip's
  `adjacent_tmp_file` (`pip/_internal/utils/filesystem.py`) calls
  `os.fsync` on the downloaded wheel before the atomic rename; the
  install aborts with `PermissionError` when fsync is EPERM'd (verified:
  POLICY=69 FAILED, POLICY=70 INSTALLED). The other five candidates in
  the raw trace — `bind` (urllib3 IPv6-availability probe,
  `connection.py:139`), `clock_nanosleep` (asyncio loop sleep),
  `mremap` (glibc malloc growth), `readlinkat` (dynamic-loader
  `/proc/self/exe` resolution), `rmdir` (pip temp-dir cleanup) — are
  all attempted and EPERM'd under the real filter and pip continues
  (install succeeds with all five denied; rmdir leaves documented
  temp-dir warnings). `clone`/`clone3` are NOT used by pip (thread
  count 0 — pip uses vfork/posix_spawn) and remain denied. Security
  impact: fsync is durability-only (flush an fd the workload already
  holds); no privilege, capability, namespace, network, or filesystem-
  boundary effect; the socket-domain argument filter is unchanged.
  Evidence: `trace-results.json` t1_pip_install (successful surface
  under the real filter, 56 syscalls, all inside the 70 allowlist).
  aarch64: fsync = 82 (asm-generic), 66 → 67.

- **2026-08-23 — x86_64 number correction: `getsockname`/`getpeername`
  (no count change).** The x86_64 syscall numbers in the artifact,
  `seccomp.py::_X86_64` and `probe_policy.py::SYS` were wrong
  (getsockname=50, getpeername=51); the real x86_64 ABI is
  getsockname=51, getpeername=52 (50=listen — which stays denied). The
  wrong numbers made `getpeername` ALWAYS EPERM in the real sandbox
  (latent since Step 1; surfaced by the Phase 10 pip CONNECT tunnel,
  which calls getpeername). Fail-closed direction (denied more than
  intended) — no boundary weakened. Regression test:
  `test_seccomp.py::test_x86_64_socket_syscall_numbers`.

- **2026-08-23 — npm (Node) / cargo (Rust): NO EXPANSION — decision
  record (70 unchanged; tier0=29, tier1=41).** Phase 10 remainder:
  measure whether the npm/cargo dependency-installation workflows can
  run inside the sandbox. Real-filter measurement (project's own
  `build_program` + `install_filter`, strace, Debian 13 / node
  20.19.2 / cargo 1.85.0, WSL2 kernel 6.18) proves BOTH tools
  GENUINELY and UNCONDITIONALLY require `clone3`:
  - Node spawns a platform scheduler thread at startup
    (`uv_thread_create` → `clone3` CLONE_THREAD, src/node_platform.cc
    DelayedTaskScheduler::Start) for EVERY workload — no flag avoids
    it; even `node -e` crashes without it. Node also requires
    `eventfd2` (uv_loop_init), `epoll_ctl`/`epoll_pwait` (libuv event
    loop), `madvise` (V8 heap), and `exit` (thread teardown — the
    filter only allowlists `exit_group`).
  - cargo spawns rustc child processes (`clone3` CLONE_VFORK) even for
    `cargo fetch` (download-only; no compile).
  DECISION: NO POLICY EXPANSION. `clone`/`clone3` are the S-014
  single-process containment boundary (the sandbox is a single-process
  execve bridge — no fork/threads; process-tree cleanup and the PID-1
  model depend on it). A dependency installer wanting threads is NOT a
  security-reviewed justification for process creation. npm/cargo
  remain INTENTIONALLY UNSUPPORTED inside the sandbox; they fail
  closed cleanly (node rc=139 abort at eventfd2, cargo rc=101 at
  clone3 — prompt, no hang, no leak). pip remains the supported
  dependency-installation workflow. Decision pinned by
  `test_proxy.py::Phase10NpmCargoDecisionTests` (clone/clone3 absent
  from allowlist + runtime table, Node's extra syscalls absent) and
  `Phase10NpmCargoFailClosedTests` (in-sandbox attempts fail cleanly).

## 6. Known limitations (documented, not hidden)

- CPython `threading` / thread-based `multiprocessing` are unavailable
  (no `clone`). Re-derive when threads enter the required surface.
- v0.2 networking: `socket`/`connect`/`sendto`/`recvfrom`/`getsockopt`/
  `setsockopt`/`getsockname`/`getpeername` are allowed, the network
  namespace is deny-by-construction in deny mode, and in allowlist mode
  the workload's ONLY path out is the host-side validating proxy (v0.2
  Step 3: destination allowlist + SSRF gate + host firewall; direct host
  access is DROPped). Phase 10 (v0.2 Step 4) adds the curated
  dependency-installation workflow: `pip install --proxy
  http://10.255.254.0:8080 ...` (the toolchain includes python3-pip;
  `fsync` is the single syscall the workflow added). The `socket`
  syscall is argument-filtered to AF_INET/AF_INET6 only (see §3) so no
  Unix/netlink/packet socket can be created even in
  allowlist mode; general outbound networking is not yet possible.
- x86_64/glibc-specific; other architectures must re-derive.
- `ioctl` remains broad; bounded by minimal `/dev` and dropped
  capabilities.
- The filter is syscall-level with one arg rule (`arch_prctl` subset);
  it does not attempt path-based filtering (that is the filesystem
  boundary's role).
