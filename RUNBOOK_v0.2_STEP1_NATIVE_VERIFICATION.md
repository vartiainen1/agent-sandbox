# v0.2 Step 1 — Native Verification Runbook

> **Status: PENDING — native VM required**
>
> This runbook documents the exact commands, expected results, and
> pass/fail criteria for natively verifying the v0.2 Step 1 seccomp
> allowlist expansion (46 → 54 syscalls) on the Ubuntu 24.04 / kernel 6.8
> / x86_64 QEMU VM.

---

## 1. Native VM prerequisites

| Requirement | Value |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Kernel | Linux 6.8 (or compatible) |
| Architecture | x86_64 |
| Python | >=3.11 (CPython) |
| strace | installed (`apt-get install strace`) |
| cgroup v2 | delegated subtree with cpu/io/memory/pids controllers |
| Git | installed (for git closed-set trace workload) |
| Network | none required (offline verification) |

---

## 2. Setup commands

```bash
# Install strace (required for syscall tracing)
sudo apt-get update && sudo apt-get install -y --no-install-recommends strace

# Verify environment
uname -a          # Expect: Linux 6.8.x ... x86_64
python3 --version # Expect: Python 3.11+ or 3.12+
strace --version  # Expect: strace version 6.x
cat /proc/filesystems | grep cgroup2  # Expect: cgroup2 present
```

---

## 3. Seccomp derivation re-derivation

### 3.1 Trace all workloads

```bash
cd /path/to/agent-sandbox
python3 tools/seccomp-derivation/trace_workloads.py --out /tmp/trace-native.json
```

**Expected result:** exit 0, `/tmp/trace-native.json` created with syscall
observation data. The trace captures all syscalls used by the Tier 0
(`echo hello`-class) and Tier 1 (coreutils + CPython + git) workloads.

### 3.2 Trace regression gate

```bash
python3 tools/seccomp-derivation/check_trace_regression.py /tmp/trace-native.json
```

**Expected result:** exit 0, output:
```
[PASS] artifact validation clean
[PASS] trace: no syscall outside allowlist
```

**This confirms:** every syscall observed in the native trace is in the
54-syscall allowlist, and no undocumented expansion occurred.

### 3.3 Seccomp derivation unit tests

```bash
python3 tools/seccomp-derivation/test_derivation.py
```

**Expected result:** ALL PASS (18/18 checks including):
- allowlist has exactly 54 syscalls
- allowlist is sorted
- allowlist has no duplicates
- tier0 + tier1 == allowlist
- tier0 and tier1 disjoint
- default action is EPERM deny
- artifact validation clean
- committed trace: no syscall outside allowlist
- expansion detected (new syscall flagged)
- BPF instruction count = 4 + 54 + 2
- BPF ends with default-deny then allow
- probe ALLOWED matches artifact

---

## 4. Behavioral seccomp probe

### 4.1 Run the probe

```bash
python3 tools/seccomp-derivation/probe_policy.py
```

### 4.2 Expected results

| Check | Expected |
|---|---|
| allowed getpid under filter | PASS |
| denied ptrace → EPERM | PASS |
| denied mount → EPERM | PASS |
| denied chroot → EPERM | PASS |
| denied unshare → EPERM | PASS |
| denied clone → EPERM | PASS |
| Tier 0 workload `sh -c 'echo hello'` under filter | PASS (exit 0, output `hello`) |
| `python3 -c "import threading; ..."` blocked (clone) | PASS (RuntimeError) |
| `sh -c 'mount ...'` blocked | PASS (MOUNT_BLOCKED) |

### 4.3 Known issue — socket check

**The behavioral probe contains a test `python socket() blocked` (line 225
of `probe_policy.py`) that tests `python3 -c "import socket;
socket.socket()"`.**

Since `socket` is now ALLOWED in the v0.2 allowlist, this test will
**FAIL** on the native VM. The socket syscall will succeed (return a
socket fd) instead of returning EPERM.

**This is expected behavior.** The `socket` syscall is now permitted by
the seccomp filter for v0.2 proxy communication. The probe's socket
check must be updated to reflect this before the native verification can
fully pass.

**Required fix:** Remove `python socket() blocked` from the probe's
denied-programs list, or change it to test a syscall that remains denied
(e.g., `python3 -c "import socket; socket.socketpair()"`).

**This fix is NOT part of v0.2 Step 1 scope** — it is a probe update
that must be applied before the native verification can pass.

---

## 5. HARDENED/P3 native e2e tests

### 5.1 Run the HARDENED e2e suite

```bash
cd /path/to/agent-sandbox
python3 -m unittest tests.native.test_hardened_e2e -v
```

**Expected result:** 24/24 PASS (on the documented substrate with
delegated cgroup v2). This re-confirms the complete HARDENED security
path through RuntimeSession.initialize() → execute() → run_in_sandbox().

### 5.2 Run the full relevant security suites

```bash
# Adversarial suite
python3 -m unittest discover -s tests/adversarial -t . -v

# Fail-closed matrix
python3 -m unittest tests.unit.test_failclosed_matrix -v

# Full unit suite
python3 -m unittest discover -s tests -t . -v
```

---

## 6. Network isolation verification

### 6.1 Confirm the network namespace remains deny-by-construction

The 8 new networking syscalls (socket, connect, sendto, recvfrom,
getsockopt, setsockopt, getsockname, getpeername) are now permitted by
seccomp. The following checks verify that the network namespace仍然
enforces deny-by-construction, independent of seccomp.

### 6.2 Check: no external connectivity

```bash
# Inside the sandbox (after HARDENED initialization):
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('8.8.8.8', 53))
    print('FAIL: external connectivity established')
except OSError as e:
    print(f'PASS: external connection refused: {e}')
finally:
    s.close()
"
```

**Expected:** `PASS: external connection refused: [Errno 101] Network is unreachable`
(or similar — ENETUNREACH because no route exists in the sandbox netns).

### 6.3 Check: metadata endpoint unreachable

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('169.254.169.254', 80))
    print('FAIL: metadata endpoint reachable')
except OSError as e:
    print(f'PASS: metadata endpoint unreachable: {e}')
finally:
    s.close()
"
```

**Expected:** `PASS: metadata endpoint unreachable: [Errno 101] Network is unreachable`

### 6.4 Check: private ranges unreachable

```bash
python3 -c "
import socket
for addr in ['192.168.1.1', '10.0.0.1', '172.16.0.1']:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((addr, 80))
        print(f'FAIL: {addr} reachable')
    except OSError as e:
        print(f'PASS: {addr} unreachable: {e}')
    finally:
        s.close()
"
```

**Expected:** All three `PASS: unreachable`.

### 6.5 Check: loopback-only (when proxy is implemented)

**Not applicable yet.** The proxy is not implemented in Step 1. When
the proxy is implemented (Step 2), the following check will verify that
loopback communication works:

```bash
# Inside the sandbox:
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('127.0.0.1', PROXY_PORT))
    print('PASS: loopback proxy reachable')
except OSError as e:
    print(f'FAIL: loopback unreachable: {e}')
finally:
    s.close()
"
```

---

## 7. Denied-syscall verification

### 7.1 Syscalls that MUST remain denied

| Syscall | Why denied | Verification |
|---|---|---|
| `clone` | Thread/process creation with flags; namespace-escape primitive | `python3 -c "import threading; threading.Thread(target=lambda: None).start()"` → RuntimeError |
| `clone3` | Same as clone | Not explicitly probed (covered by clone) |
| `bind` | Workload is client, not server | Not in allowlist; any bind attempt → EPERM |
| `listen` | Workload is client, not server | Not in allowlist; any listen attempt → EPERM |
| `accept` | Workload is client, not server | Not in allowlist; any accept attempt → EPERM |
| `accept4` | Workload is client, not server | Not in allowlist; any accept attempt → EPERM |
| `shutdown` | Proxy handles connection lifecycle | Not in allowlist; any shutdown attempt → EPERM |
| `sendmsg` | Not needed for stream sockets | Not in allowlist; any sendmsg attempt → EPERM |
| `recvmsg` | Not needed for stream sockets | Not in allowlist; any recvmsg attempt → EPERM |
| `ptrace` | Process inspection/injection | `python3 -c "import ctypes; ctypes.CDLL('libc.so.6').ptrace(0,0,0,0)"` → EPERM |
| `mount` | Filesystem/namespace boundary manipulation | `sh -c 'mount 2>/dev/null'` → blocked |
| `unshare` | Namespace manipulation | Behavioral probe confirms EPERM |

### 7.2 Verification commands

```bash
# Test clone is denied
python3 -c "import threading; threading.Thread(target=lambda: None).start()"
echo "Exit: $?"  # Expect: non-zero (RuntimeError)

# Test ptrace is denied
python3 -c "import ctypes; ctypes.CDLL('libc.so.6').ptrace(0,0,0,0)"
echo "Exit: $?"  # Expect: non-zero (OSError)

# Test mount is denied
sh -c 'mount 2>/dev/null || echo MOUNT_BLOCKED'
# Expect: MOUNT_BLOCKED
```

---

## 8. Unexpected syscall check

### 8.1 Verify no undocumented syscalls in trace

The trace regression gate (`check_trace_regression.py`) automatically
checks this. If any syscall observed in the native trace is NOT in the
54-syscall allowlist, the gate FAILS.

### 8.2 Verify the 8 new syscalls are the only additions

```bash
# Compare the new allowlist against the v0.1 baseline
python3 -c "
import json
d = json.load(open('tools/seccomp-derivation/allowlist.json'))
new = {'socket', 'connect', 'sendto', 'recvfrom', 'getsockopt', 'setsockopt', 'getsockname', 'getpeername'}
old = {'access', 'arch_prctl', 'brk', 'chdir', 'close', 'dup2', 'epoll_create1',
       'execve', 'exit_group', 'fcntl', 'fstat', 'futex', 'getcwd', 'getdents64',
       'getegid', 'geteuid', 'getgid', 'getpid', 'getppid', 'getrandom', 'gettid',
       'getuid', 'ioctl', 'lseek', 'mkdir', 'mmap', 'mprotect', 'munmap',
       'newfstatat', 'openat', 'pipe2', 'poll', 'pread64', 'prlimit64', 'read',
       'readlink', 'rseq', 'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
       'set_robust_list', 'set_tid_address', 'unlink', 'vfork', 'wait4', 'write'}
current = set(d['allowlist'])
added = current - old
removed = old - current
assert added == new, f'Unexpected additions: {added - new}'
assert removed == set(), f'Unexpected removals: {removed}'
print(f'PASS: exactly 8 new syscalls, 0 removed')
print(f'Added: {sorted(added)}')
"
```

**Expected:** `PASS: exactly 8 new syscalls, 0 removed`

---

## 9. Pass/fail checklist

| # | Check | Command | Expected | PASS/FAIL |
|---|---|---|---|---|
| 1 | Native trace | `trace_workloads.py --out /tmp/trace-native.json` | exit 0 | |
| 2 | Trace regression gate | `check_trace_regression.py /tmp/trace-native.json` | PASS, no missing syscalls | |
| 3 | Derivation unit tests | `test_derivation.py` | ALL PASS (18/18) | |
| 4 | Behavioral probe | `probe_policy.py` | ALL PASS (except socket check — see §4.3) | |
| 5 | HARDENED/P3 e2e | `test_hardened_e2e.py` | 24/24 PASS | |
| 6 | Allowlist count | `len(allowlist) == 54` | 54 = tier0 29 + tier1 25 | |
| 7 | External connectivity | socket connect to 8.8.8.8 | ENETUNREACH (deny-by-construction) | |
| 8 | Metadata unreachable | socket connect to 169.254.169.254 | ENETUNREACH | |
| 9 | Private ranges unreachable | socket connect to 192.168.1.1 | ENETUNREACH | |
| 10 | clone denied | threading.Thread().start() | RuntimeError | |
| 11 | ptrace denied | ctypes ptrace call | OSError | |
| 12 | mount denied | `sh -c 'mount'` | MOUNT_BLOCKED | |
| 13 | 8 new syscalls only | diff check | exactly socket/connect/sendto/recvfrom/getsockopt/setsockopt/getsockname/getpeername | |
| 14 | No removed syscalls | diff check | 0 removed from v0.1 baseline | |
| 15 | Rootless capabilities | `check_rootless_capabilities.py` | per-mechanism VERIFIED/BLOCKED with reason | |

---

## 10. aarch64 verification (if native aarch64 substrate available)

```bash
# Trace (requires aarch64 Linux)
python3 tools/seccomp-derivation/trace_workloads.py --out /tmp/trace-aarch64.json

# Regression gate (aarch64)
python3 tools/seccomp-derivation/check_trace_regression.py --aarch64 /tmp/trace-aarch64.json

# Expected: 51 syscalls = tier0 28 + tier1 23
```

---

## 11. Post-verification steps

After all checks pass:

1. Record the exact native VM environment (uname, kernel, Python version)
2. Record the exact trace file hash
3. Record all pass/fail results
4. Update `docs/seccomp-derivation/verification.md` with native evidence
5. Report results to the workspace owner for commit authorization
6. **Do NOT commit until explicitly authorized**

---

## 12. Known issues to resolve before native verification

| Issue | File | Status |
|---|---|---|
| Behavioral probe still tests `socket() blocked` but socket is now ALLOWED | `probe_policy.py:225` | Must be updated before native probe can pass |
| Expected count hardcoded as 46 in probe description | `probe_policy.py:155` | Cosmetic — does not affect probe behavior |
