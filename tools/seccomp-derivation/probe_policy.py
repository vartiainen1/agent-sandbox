"""Behavioral verification of the derived seccomp allowlist (container-
validated; re-run natively in CI with the same script).

This is the derivation's verification step (rules 10-11 of the exercise):
  - legitimate workloads must pass (the filter must not break the surface it
    was derived from);
  - prohibited operations must actually be blocked (EPERM), not merely
    "filter loaded OK".

It also serves as the reference implementation for the Phase 1 seccomp
module: the BPF is built and loaded through the same prctl/ctypes path the
runtime will use.

Architecture note: the filter is loaded in a dedicated child (mirroring the
real runtime: sandbox init loads the filter, then execs the workload), so
the parent stays filter-free and can report results.

Usage (Linux, container or native):
    python3 probe_policy.py
Exit 0 only if every check PASSes.
"""

import ctypes
import os
import sys

# --- x86_64 syscall numbers (documented per-arch; CI runs x86_64 ubuntu) ---
SYS = {
    "read": 0, "write": 1, "close": 3, "fstat": 5, "lseek": 8, "mmap": 9,
    "mprotect": 10, "munmap": 11, "brk": 12, "rt_sigaction": 13,
    "rt_sigprocmask": 14, "rt_sigreturn": 15, "ioctl": 16, "pread64": 17,
    "access": 21,    "dup2": 33, "getpid": 39, "vfork": 58, "execve": 59,
    "exit_group": 231, "wait4": 61, "fcntl": 72, "getcwd": 79,
    "mkdir": 83, "unlink": 87,
    "readlink": 89, "getuid": 102, "getgid": 104, "geteuid": 107,
    "getegid": 108, "getppid": 110, "arch_prctl": 158, "gettid": 186,
    "futex": 202, "getdents64": 217, "set_tid_address": 218,
    "set_robust_list": 273, "newfstatat": 262, "openat": 257,
    "epoll_create1": 291,
    "pipe2": 293, "prlimit64": 302, "getrandom": 318, "rseq": 334,
    "poll": 7,
    # denied probes (must NOT be in the allowlist)
    "socket": 41, "ptrace": 101, "mount": 165, "chroot": 161,
    "unshare": 272, "clone": 56,
}

# The DERIVED allowlist is the canonical security artifact
# (allowlist.json, single source of truth - see policy.md change control).
# Loading it here (instead of an embedded copy) guarantees the probe always
# tests the artifact that the regression gate and the docs describe.
def load_allowlist() -> list[str]:
    import json
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "allowlist.json"), encoding="utf-8") as f:
        data = json.load(f)
    return data["allowlist"]


ALLOWED = load_allowlist()

# --- seccomp/BPF constants ---
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
AUDIT_ARCH_X86_64 = 0xC000003E
# struct seccomp_data offsets
OFF_ARCH = 4
OFF_NR = 0

BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06


class sock_filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class sock_fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(sock_filter))]


def bpf(code, jt=0, jf=0, k=0):
    return sock_filter(code, jt, jf, k)


def build_filter(allow: list[str]) -> sock_fprog:
    """Default-deny allowlist filter. Architecture mismatch => KILL."""
    insns = [
        bpf(BPF_LD | BPF_W | BPF_ABS, k=OFF_ARCH),
        bpf(BPF_JMP | BPF_JEQ | BPF_K, jt=1, jf=0, k=AUDIT_ARCH_X86_64),
        bpf(BPF_RET | BPF_K, k=SECCOMP_RET_KILL_PROCESS),
        bpf(BPF_LD | BPF_W | BPF_ABS, k=OFF_NR),
    ]
    allow_idx = 4 + len(allow) + 1  # position of the trailing RET ALLOW
    for name in allow:
        nr = SYS[name]
        insns.append(bpf(BPF_JMP | BPF_JEQ | BPF_K, jt=allow_idx - (len(insns) + 1),
                         jf=0, k=nr))
    insns.append(bpf(BPF_RET | BPF_K, k=SECCOMP_RET_ERRNO | 1))  # EPERM
    insns.append(bpf(BPF_RET | BPF_K, k=SECCOMP_RET_ALLOW))
    arr = (sock_filter * len(insns))(*insns)
    prog = sock_fprog(len(insns), ctypes.cast(arr, ctypes.POINTER(sock_filter)))
    return prog


_libc = None


def _get_libc():
    """Lazy libc handle so the module is importable on non-Linux hosts
    (unit tests, compile check); actual syscalls are Linux-only at runtime."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
    return _libc


def prctl(option, *args):
    _get_libc().prctl(ctypes.c_int(option), *[ctypes.c_ulong(a) for a in args])


def load_filter(prog) -> None:
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(prog), 0, 0)


def syscall_ret(nr, *args) -> int:
    """Direct syscall via libc; returns -1 and sets errno on failure."""
    libc = _get_libc()
    libc.syscall.restype = ctypes.c_long
    return libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(a) for a in args])


def in_filter_child(pipe_fd) -> int:
    """Load the filter, then probe allowed/denied syscalls directly."""
    try:
        prog = build_filter(ALLOWED)
        load_filter(prog)
        checks = []
        # allowed: getpid must succeed
        pid = syscall_ret(SYS["getpid"])
        checks.append(("allowed getpid", pid > 0))
        # denied: socket / ptrace / mount / chroot / unshare / clone
        for name in ("socket", "ptrace", "mount", "chroot", "unshare", "clone"):
            r = syscall_ret(SYS[name], 0, 0, 0)
            err = ctypes.get_errno()
            checks.append((f"denied {name}", r == -1 and err == 1))  # EPERM
        allok = all(ok for _, ok in checks)
        os.write(pipe_fd, (f"IN_FILTER {'PASS' if allok else 'FAIL'}\n" +
                           "".join(f"  {n}: {'ok' if ok else 'FAIL'}\n" for n, ok in checks)).encode())
        return 0 if allok else 1
    except Exception as e:  # noqa: BLE001 - report to parent
        os.write(pipe_fd, f"IN_FILTER ERROR: {e!r}\n".encode())
        return 2


def workload_child(pipe_fd, cmd) -> int:
    """Load the filter, then exec the workload; report its fate to parent."""
    try:
        prog = build_filter(ALLOWED)
        load_filter(prog)
    except Exception as e:  # noqa: BLE001
        os.write(pipe_fd, f"LOAD ERROR: {e!r}\n".encode())
        return 2
    os.write(pipe_fd, b"FILTER_LOADED\n")
    # Route workload stdout/stderr through the pipe so the parent observes
    # the workload's actual output (dup2 is in the allowlist). The dup2'd
    # fds survive exec (dup2 clears CLOEXEC), so workload output flows to
    # the parent until the workload tree exits.
    os.dup2(pipe_fd, 1)
    os.dup2(pipe_fd, 2)
    # exec replaces this process; the workload's syscall surface is covered
    # by the allowlist or the workload fails with EPERM (non-zero exit).
    os.execvp(cmd[0], cmd)


def spawn_and_observe(make_child, *args) -> tuple[int, str]:
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: no filter yet - the child itself loads it
        os.close(r)
        rc = make_child(w, *args)
        os._exit(rc)
    os.close(w)
    chunks = []
    while True:
        data = os.read(r, 4096)
        if not data:
            break
        chunks.append(data)
    os.close(r)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), b"".join(chunks).decode()


def main() -> int:
    if sys.platform.startswith("win"):
        print("ERROR: seccomp verification requires Linux.", file=sys.stderr)
        return 2
    results = []

    # 1) in-process syscall-level checks under the filter
    rc, out = spawn_and_observe(in_filter_child)
    results.append(("syscall-level probes (socket/ptrace/mount/chroot/unshare/clone -> EPERM)", rc == 0, out))

    # 2) legitimate Tier 0 workload must pass under the filter
    rc, out = spawn_and_observe(workload_child, ["/bin/sh", "-c", "echo hello"])
    results.append(("Tier 0 workload (sh -c 'echo hello') passes", rc == 0, out))

    # 3) prohibited operations in real programs must fail
    for name, cmd in [
        ("python socket() blocked", ["python3", "-c", "import socket; socket.socket()"]),
        ("python clone/threading blocked", ["python3", "-c",
                                            "import threading; threading.Thread(target=lambda: None).start()"]),
        ("sh mount blocked", ["/bin/sh", "-c", "mount 2>/dev/null || echo MOUNT_BLOCKED"]),
    ]:
        rc, out = spawn_and_observe(workload_child, cmd)
        ok = "MOUNT_BLOCKED" in out if "mount" in name else rc != 0
        detail = "\n".join(out.strip().splitlines()[-3:]) or "<no output>"
        results.append((name, ok, detail))

    failed = 0
    for label, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")
        for line in detail.splitlines():
            print(f"        {line}")
        failed += 0 if ok else 1
    print(f"\nRESULT: {'ALL PASS' if failed == 0 else f'{failed} FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
