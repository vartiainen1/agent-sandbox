# Seccomp Derivation — Methodology

This document defines the reproducible process by which the agent-sandbox
HARDENED seccomp allowlist is derived. It is a **process**, not a
hardcoded list: anyone can re-run it (container or native Linux) and
obtain the same evidence. The current results live in
`syscall-classification.md` (the table) and `policy.md` (the policy).

The rule this process enforces: *"empirically" never means running a
workload, collecting whatever syscalls happen to occur, and blindly
allowing them all.* Every syscall in the allowlist must survive the
classification step below, and the whole policy must be verified
behaviorally — not by "the BPF filter loaded successfully".

---

## The 12 Steps

### 1. Define the minimal runtime workload

The workload set is tiered so the allowlist is the *smallest practical*
surface, not a wish list:

| Tier | Workloads | Purpose |
|---|---|---|
| Tier 0 | `/bin/sh -c 'echo hello'`, `/bin/sh -c 'exit 0'` | The absolute minimum the hardened runtime must execute (Phase 1 acceptance class) |
| Tier 1 | coreutils file ops (`ls/mkdir/write/cat/cp/rm`), `python3 -c 'print(...)'`, an agent-ish python script (json + pathlib + subprocess), `git init/config/add/status` | The intended v0.1 toolchain surface — the supervisor and every agent-* tool are Python |

Definitions live in `tools/seccomp-derivation/workloads.py`.

### 2. Define the exact runtime initialization sequence

The sandbox has three distinct phases; only one is filtered (see step 9):

- **Stage A — initialization (trusted, UNFILTERED):** the host-side
  supervisor and the sandbox-init child create namespaces, build and
  `pivot_root` the rootfs, mount `/proc` (`hidepid=2`) and minimal `/dev`,
  drop capabilities, set `no_new_privs`, set rlimits, join cgroups, and
  sanitize the environment. These syscalls (`unshare`, `mount`,
  `pivot_root`, `setrlimit`, …) are **never** in the workload allowlist —
  they run before the filter exists.
- **Stage B — workload (FILTERED):** the filter is installed as the last
  security step, then the workload is exec'd. The allowlist covers exactly
  this stage.
- **Stage C — cleanup (trusted, UNFILTERED):** the supervisor SIGKILLs
  the sandbox PID 1, uses `cgroup.kill`, unmounts, removes the workspace
  copy, and verifies. `kill`/`wait4`/`unlink`/`rmdir` here are trusted-side
  and unfiltered.

Consequence: the allowlist only ever needs to cover **workload execution**
(Stage B), which is why it can be this small.

### 3. Observe syscalls made by the runtime and minimal workload

Each workload runs under `strace -f`; syscall names (and argument
summaries for the high-risk syscalls `clone`/`clone3`/`unshare`/`socket`/
`socketpair`/`setns`) are parsed into a machine-readable record.

Harness: `tools/seccomp-derivation/trace_workloads.py` (Linux only).
Re-run:

    docker build -t seccomp-derivation -f tools/seccomp-derivation/Dockerfile tools/seccomp-derivation
    docker run --rm -v "$PWD/tools/seccomp-derivation:/work" -w /work \
        seccomp-derivation python3 trace_workloads.py --out /work/trace-results.json

Native Linux re-run (authoritative, CI): the same script on an ubuntu
runner with strace installed (`--native` semantics are identical; only the
host differs). Evidence record: `tools/seccomp-derivation/trace-results.json`.

Windows Git Bash note: prefix docker commands with `MSYS_NO_PATHCONV=1`
(or use `//work`) — without it, MSYS rewrites the `-w /work` argument
into `C:/Program Files/Git/work` and docker rejects the path (logged in
freebuff-errors.txt, 2026-08-19).

### 4. Classify each observed syscall

Every observed syscall enters `syscall-classification.md` with:

- which tier requires it (Tier 0 / Tier 1)
- which component requires it (dash/sh, coreutils, CPython, git, glibc)
- which stage it belongs to (A init / B workload / C cleanup)
- whether it can be removed (with what breaks)
- its security impact if allowed (see step 6 categories)

### 5. Answer the questions for every candidate

For every syscall considered for the allowlist:

- Why is it required?
- Which component requires it?
- Is it required during sandbox initialization or workload execution?
- Can it be removed?
- What breaks if it is removed?
- What security impact does allowing it have?
- Does it enable privilege escalation, filesystem manipulation, namespace
  manipulation, process inspection, networking, or other dangerous
  behavior?
- Is the behavior architecture/platform dependent?

The answers are one row per syscall in `syscall-classification.md`.

### 6. Prefer removing unnecessary syscalls

A syscall observed in the trace is a **candidate**, not an automatic
inclusion. Rules of thumb applied:

- If a workload class is not part of the intended v0.1 surface, its
  syscalls are NOT included just because they were traced. (Example: git
  is Phase 9 — its 34 syscalls were traced to *inform* the policy, and
  every one of them is already in the Tier 0/1 set, so nothing was added
  for git alone.)
- Syscalls with broad blast radius (`ioctl`, `prlimit64`) are allowed only
  when required AND their dangerous uses are blocked by other layers
  (no caps, minimal `/dev`, kernel-enforced hard limits) — documented per
  syscall.
- Anything not required is denied by the default-deny action. **Denial
  costs nothing in the policy; allowance costs review.**

### 7. Identify dangerous or high-impact syscalls

Dangerous syscalls are handled in one of two ways:

- **Denied outright** (not in the allowlist), with the rationale documented
  in `syscall-classification.md` §Denied: `mount`, `umount2`, `ptrace`,
  `unshare`, `setns`, `chroot`, `pivot_root`, `clone`/`clone3`, `socket`,
  `socketpair`, `connect`, `bind`, `listen`, `accept`, `sendto`,
  `recvfrom`, `sendmsg`, `recvmsg`, `setsockopt`, `getsockopt`, `bpf`,
  `keyctl`, `add_key`, `request_key`, `perf_event_open`, `kexec_*`,
  `reboot`, `swapon`, `swapoff`, `iopl`, `ioperm`, `setuid`, `setgid`,
  `setgroups`, `capset`, `mknod`, `mknodat`, `chmod`-class, `chown`-class,
  `rename`-class, `link`-class, `symlink`-class, `setxattr`-class,
  `process_vm_readv/writev`, `init_module`-class, `madvise`, `readv`,
  `writev`, `sendfile`, `open` (only `openat` allowed), and every other
  unobserved syscall.
- **Allowed with documented justification**, only when required AND the
  dangerous dimension is blocked elsewhere: `ioctl` (no devices, no caps),
  `prlimit64` (hard limits kernel-enforced), `vfork`/`execve` (process
  creation contained by `pids.max`/`RLIMIT_NPROC`), `wait4` (PID-1 reaping
  duty), `getrandom` (no fd, no entropy control), `openat` (path scope is
  the rootfs boundary's job, not seccomp's).

### 8. Distinguish initialization / workload / cleanup syscalls

See step 2. The classification table marks the stage of every syscall.
Only Stage B is filtered; A and C run unfiltered on the trusted side.
This separation is what makes the allowlist small — the runtime never
needs `mount`/`pivot_root`/`unshare` *under* the filter.

### 9. Decide filter placement (before/after init ops) and why

**Decision: the filter is installed LAST — after every Stage-A
operation, immediately before the workload exec.**

Why:

- Stage A needs syscalls that must never be available to the workload
  (`mount`, `pivot_root`, `unshare`, `prctl` capability drops, cgroup
  writes). Installing the filter after A means those syscalls exist only
  in the trusted phase.
- `no_new_privs` must precede the filter for an unprivileged install; the
  filter is installed by the sandbox-init process *after* no_new_privs
  and *before* exec, so no code between filter-install and exec can change
  the security state (the remaining operations — `dup2` stdio setup,
  `chdir`, `execve` — are in the allowlist).
- Stage C (cleanup) runs in the supervisor, which never loaded the filter.
  The filter cannot block cleanup.
- Documented consequence: any future operation that must run *inside* the
  sandbox *after* the filter (e.g. a post-exec setup helper) must be
  re-derived into the allowlist; the derivation process is the gate for
  that change (see `policy.md` §Change control).

### 10. Verify the resulting policy using legitimate workloads

`tools/seccomp-derivation/probe_policy.py` loads the derived filter (built
through the same prctl/ctypes path the runtime will use) in a child that
mirrors the real architecture, then runs the Tier 0 workload and the
Tier 1 toolchain under the filter. A legitimate workload that fails under
the filter means the allowlist is too tight — the derivation must be
revisited, not the filter loosened blindly.

### 11. Verify that prohibited operations are actually blocked

The same probe asserts, behaviorally, that prohibited operations fail:

- direct syscall probes: `socket`, `ptrace`, `mount`, `chroot`, `unshare`,
  `clone` must return **EPERM**
- real-program probes: `python3 -c "import socket; socket.socket()"`,
  `threading.Thread(...).start()` (clone), and `mount` must fail

This is the anti-claim test for *"seccomp is secure because the BPF
filter loaded successfully"*: the question is whether the policy restricts
the workload to the intended surface while still allowing required
functionality — and that is what the probe verifies.

### 12. Document known limitations

See `policy.md` §Limitations and `verification.md`:

- threads (`clone`) are denied → CPython `threading`/thread-based
  `multiprocessing` are unavailable in v0.1 (verified blocked)
- no network syscalls at all → any socket-based library fails (v0.1
  network is deny-by-construction anyway)
- the observed surface is x86_64 ubuntu/glibc; other arches/ libcs must
  re-derive (the arch-check KILLs non-matching architectures)
- container observation ran as root without a user namespace; native CI
  re-runs with the real uid mapping
- git's surface was traced but is Phase 9; if git (or any new workload)
  needs a syscall outside the allowlist, the derivation must be re-run —
  the change-control rule, not a silent edit

---

## Reproducibility

| Artifact | Location |
|---|---|
| Workload definitions | `tools/seccomp-derivation/workloads.py` |
| Tracer | `tools/seccomp-derivation/trace_workloads.py` |
| Verification probe | `tools/seccomp-derivation/probe_policy.py` |
| Toolchain image | `tools/seccomp-derivation/Dockerfile` |
| Evidence (container) | `tools/seccomp-derivation/trace-results.json` |
| Classification | `docs/seccomp-derivation/syscall-classification.md` |
| Derived policy | `docs/seccomp-derivation/policy.md` |
| Verification record | `docs/seccomp-derivation/verification.md` |

A native-Linux CI job re-runs the tracer + probe on ubuntu; its results
are authoritative over the container run (see `verification.md`).
