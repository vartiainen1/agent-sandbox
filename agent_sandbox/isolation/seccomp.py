"""Seccomp filter installation and verification (Phase 1 Step 8, ADR-008,
SECURITY_SPEC.md S-011).

The filter is the LAST Stage-A hardening operation: installed in sandbox
PID 1 AFTER the namespaces/filesystem/network boundary, no_new_privs
(Step 6) and the capability reduction (Step 7), and immediately before
the workload function runs (docs/seccomp-derivation/policy.md section 1,
methodology.md section 9). Everything between install and the workload
(stdio dup2 already done, the workload's own syscalls) is covered by the
allowlist.

The policy is NOT re-derived or embedded here: the single source of
truth is the regression-protected artifact
``tools/seccomp-derivation/allowlist.json`` (54 syscalls as of the
2026-08-22 documented +chdir expansion for the git closed set; default-
deny EPERM; change control in policy.md section 5 - NO UNDOCUMENTED
SYSCALL EXPANSION). This module loads it at program-build time on the trusted
host side, builds the identical default-deny BPF (same instruction
layout as the derivation probe: architecture guard -> KILL on mismatch,
linear JEQ allow chain, trailing RET ALLOW, default RET_ERRNO|EPERM),
and the sandbox installs + verifies it.

Verification is kernel-observable, never "prctl returned success":
- /proc/self/status ``Seccomp: 2`` (SECCOMP_MODE_FILTER) and
  ``Seccomp_filters: 1`` - the read-back at workload time.
- A behavioral spot check AFTER install: a forbidden syscall (socket)
  must fail with EPERM; if it succeeds, the state is unexpected and the
  workload is refused.

Failure semantics (S-018): install failure, verification failure, or
unexpected seccomp state all raise NamespaceSetupError with a
deterministic reason; the fail-closed guard converts it into a refusal
and the workload function is NEVER executed.

Architecture guard (policy.md section 1): the allowlist is derived for
x86_64 only. On any other architecture this module refuses to build or
install the filter (the BPF itself also KILLs on an AUDIT_ARCH mismatch
as defense-in-depth). Import is safe on any platform (the syscall/ctypes
work happens only at call time).
"""

from __future__ import annotations

import ctypes
import json
import pathlib
import platform
import socket
from dataclasses import dataclass

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError

# prctl(2) seccomp options (kernel ABI)
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7
# struct seccomp_data offsets (kernel ABI)
_OFF_ARCH = 4
_OFF_NR = 0
_OFF_ARGS0 = 16  # args[0] — first syscall argument (e.g. socket domain)

# BPF instruction encoding (kernel ABI)
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06

_EPERM = 1

# Socket domain argument values for argument-level filtering.
# socket(AF_INET) and socket(AF_INET6) are allowed for proxy
# communication; all other domains (AF_UNIX, AF_NETLINK, AF_PACKET, etc.)
# are denied to preserve S-003/S-004 credential isolation.
_AF_UNIX = 1
_AF_INET = 2
_AF_INET6 = 10
_AF_NETLINK = 16
_AF_PACKET = 17
_SOCKET_NR = 41  # x86_64 syscall number for socket(2) (reference only)

# The x86_64 syscall numbers for the derived allowlist (kernel ABI;
# cross-checked with the derivation probe's SYS table). The runtime only
# ever loads these on x86_64 (architecture guard below).
_X86_64 = {
    "access": 21, "arch_prctl": 158, "brk": 12, "chmod": 90, "chdir": 80,
    "close": 3, "close_range": 436, "connect": 42, "copy_file_range": 326,
    "dup2": 33, "epoll_create1": 291, "execve": 59, "exit_group": 231,
    "fadvise64": 221, "fcntl": 72, "fstat": 5, "fstatfs": 197,
    "fsync": 74,
    "futex": 202, "getcwd": 79, "getdents64": 217, "getegid": 108,
    "geteuid": 107, "getgid": 104, "getpeername": 52, "getpid": 39,
    "getppid": 110,    "getrandom": 318, "getsockname": 51, "getsockopt": 55,
    "gettid": 186, "getuid": 102, "ioctl": 16, "lgetxattr": 192,
    "link": 86, "listxattr": 194, "lseek": 8, "mkdir": 83, "mmap": 9,
    "mprotect": 10, "munmap": 11, "newfstatat": 262, "openat": 257,
    "pipe2": 293, "poll": 7, "pread64": 17, "prlimit64": 302, "read": 0,
    "readlink": 89, "recvfrom": 45, "rename": 82, "rseq": 334,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
    "sendto": 44, "set_robust_list": 273, "set_tid_address": 218,
    "setsockopt": 54, "socket": 41, "statfs": 137, "statx": 332,
    "symlink": 88, "umask": 95, "uname": 63, "unlink": 87,
    "unlinkat": 263, "vfork": 58, "wait4": 61, "write": 1,
}


class _SockFilter(ctypes.Structure):
    """struct sock_filter (kernel ABI)."""
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class _SockFprog(ctypes.Structure):
    """struct sock_fprog (kernel ABI)."""
    _fields_ = [("len", ctypes.c_ushort),
                ("filter", ctypes.POINTER(_SockFilter))]


# Module-level seam (fork-safe: the sandbox child inherits the parent's
# module state, so tests can inject a failing install or a hostile state
# read and the real path must refuse).
def _prctl(option: int, arg2: int, arg3: int, arg4: int, arg5: int) -> int:
    return syscalls.prctl(option, arg2, arg3, arg4, arg5)


def _read_proc_status_impl() -> str:
    try:
        with open("/proc/self/status", "r", encoding="ascii") as f:
            return f.read()
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read /proc/self/status: {e} - seccomp state "
            "verification impossible, fail closed") from e


_read_proc_status = _read_proc_status_impl


def _detect_arch() -> str:
    """Detect the current CPU architecture for seccomp purposes.
    Returns 'x86_64', 'aarch64', or raises on unsupported."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    raise NamespaceSetupError(
        f"seccomp allowlist not available for architecture {machine!r} "
        "- refusing to build a filter (fail closed)")


def _is_x86_64() -> bool:
    """Architecture guard: true on x86_64 only."""
    try:
        return _detect_arch() == "x86_64"
    except NamespaceSetupError:
        return False


def _allowlist_path(arch: str | None = None) -> pathlib.Path:
    """Return the architecture-specific allowlist artifact path."""
    if arch is None:
        try:
            arch = _detect_arch()
        except NamespaceSetupError:
            arch = "x86_64"  # fallback for tests that mock detection
    base = pathlib.Path(__file__).resolve().parents[2] / "tools" / \
        "seccomp-derivation"
    if arch == "aarch64":
        return base / "allowlist_aarch64.json"
    return base / "allowlist.json"


def load_allowlist(arch: str | None = None) -> tuple[list[str], dict[str, int]]:
    """Load the derived allowlist artifact (the single source of truth).
    Returns (allowlist_names, syscall_number_map).
    Fail closed on an unreadable or invalid artifact - a missing policy
    is a refusal, never a silent 'no filter'."""
    path = _allowlist_path(arch)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise NamespaceSetupError(
            f"cannot load seccomp allowlist artifact {path}: {e} - fail "
            "closed, workload not executed") from e
    allow = data.get("allowlist")
    if not isinstance(allow, list) or not allow:
        raise NamespaceSetupError(
            f"seccomp allowlist artifact {path} has no allowlist - fail "
            "closed, workload not executed")
    numbers = data.get("syscall_numbers")
    if not isinstance(numbers, dict):
        numbers = dict(_X86_64)
    return list(allow), numbers


_ARCH_TABLES: dict[str, dict[str, int]] = {}


def _get_arch_table(arch: str | None = None) -> dict[str, int]:
    """Get the syscall number table for the given architecture."""
    if arch is None:
        arch = _detect_arch()
    if arch not in _ARCH_TABLES:
        _ARCH_TABLES[arch] = dict(_X86_64) if arch == "x86_64" else {}
    return _ARCH_TABLES[arch]


def _audit_arch(arch: str) -> int:
    """Return the AUDIT_ARCH constant for the given architecture."""
    if arch == "x86_64":
        return AUDIT_ARCH_X86_64
    if arch == "aarch64":
        return AUDIT_ARCH_AARCH64
    raise NamespaceSetupError(
        f"unsupported architecture {arch!r} for seccomp (fail closed)")


def build_program(allowlist: list[str] | None = None) -> tuple:
    """Build the default-deny BPF program as a fork-safe tuple of
    (code, jt, jf, k) instructions. Architecture mismatch => KILL; a
    non-allowlisted syscall => RET_ERRNO|EPERM; allowlisted => ALLOW.

    v0.2: the ``socket`` syscall receives argument-level filtering.
    After matching the socket syscall number the filter loads args[0]
    (the domain) and allows only AF_INET (2) and AF_INET6 (10). All
    other domains (AF_UNIX, AF_NETLINK, AF_PACKET, etc.) are denied
    with EPERM. This preserves S-003/S-004 credential isolation while
    permitting the sandbox-to-proxy AF_INET communication.

    Layout (deterministic, pinned by tests)::

        [0]    LD.W.Arch          (load seccomp_data.arch)
        [1]    JEQ.K audit, +1    (architecture match)
        [2]    RET.K  KILL        (architecture mismatch => kill)
        [3]    LD.W.NR            (load seccomp_data.nr)
        [4..4+N-1]  JEQ chain    (N = len(allowlist); socket entry
                                   jumps to the domain sub-chain)
        [4+N]  LD.W.ABS 16        (socket sub-chain: load args[0])
        [4+N+1] JEQ.K 2, +2      (AF_INET  => ALLOW)
        [4+N+2] JEQ.K 10, +1     (AF_INET6 => ALLOW)
        [4+N+3] RET.K  ERRNO|EPERM  (other socket domains => deny;
                                     also serves as default deny for
                                     non-allowlisted syscalls)
        [4+N+4] RET.K  ALLOW     (allowlisted syscalls + AF_INET/6)

    Must be called on the host side (the allowlist artifact is not
    reachable inside the pivoted rootfs); the program tuple is
    inherited across fork into PID 1."""
    arch = _detect_arch()
    if allowlist is not None:
        # Explicit allowlist: use the x86_64 table for backward compat
        numbers = dict(_X86_64)
        audit = AUDIT_ARCH_X86_64
    else:
        allow, numbers = load_allowlist(arch)
        audit = _audit_arch(arch)
        allowlist = allow
    unknown = [name for name in allowlist if name not in numbers]
    if unknown:
        raise NamespaceSetupError(
            "allowlist contains syscalls with no number in the "
            f"{arch} runtime table: {unknown} - fail closed, workload "
            "not executed")
    N = len(allowlist)  # number of allowlisted syscalls
    # Arch-aware socket trigger: the domain sub-chain must fire for the
    # socket syscall number of THIS architecture (x86_64: 41, aarch64:
    # 198), never a hardcoded x86_64 constant - a hardcoded 41 would let
    # the aarch64 socket entry jump straight to ALLOW and silently drop
    # the AF_UNIX/AF_NETLINK/AF_PACKET denial (S-003/S-004 loss).
    socket_nr = numbers.get("socket")
    # RET_ALLOW sits at position 4 + N + 4 (after header, JEQ chain,
    # socket sub-chain, and default-deny).
    ret_allow_idx = 4 + N + 4
    insns: list[tuple[int, int, int, int]] = [
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _OFF_ARCH),
        (_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, audit),
        (_BPF_RET | _BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _OFF_NR),
    ]
    # Build the linear JEQ chain.  The socket syscall entry is special:
    # instead of jumping to RET_ALLOW, it jumps to the domain sub-chain
    # (right after the JEQ chain) that loads args[0] and checks the
    # socket domain.
    socket_sub_chain_idx = 4 + N  # first instruction of the sub-chain
    for name in allowlist:
        nr = numbers[name]
        if nr == socket_nr:
            # Socket: jump to domain sub-chain (load args[0], check
            # AF_INET/AF_INET6).  The sub-chain starts at
            # socket_sub_chain_idx.  BPF jump offset is relative to the
            # NEXT instruction (current + 1 + jt), so subtract (len+1).
            jt = socket_sub_chain_idx - (len(insns) + 1)
            insns.append((_BPF_JMP | _BPF_JEQ | _BPF_K, jt, 0, nr))
        else:
            # Normal syscall: jump straight to RET_ALLOW.
            jt = ret_allow_idx - (len(insns) + 1)
            insns.append((_BPF_JMP | _BPF_JEQ | _BPF_K, jt, 0, nr))
    # Socket domain sub-chain: load args[0] (the domain argument) and
    # allow only AF_INET and AF_INET6.  All other domains (AF_UNIX,
    # AF_NETLINK, AF_PACKET, etc.) fall through to the default deny.
    insns.append((_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _OFF_ARGS0))
    insns.append((_BPF_JMP | _BPF_JEQ | _BPF_K,
                  ret_allow_idx - (len(insns) + 1), 0, _AF_INET))
    insns.append((_BPF_JMP | _BPF_JEQ | _BPF_K,
                  ret_allow_idx - (len(insns) + 1), 0, _AF_INET6))
    # Default deny: applies to non-allowlisted syscalls AND denied
    # socket domains (AF_UNIX, AF_NETLINK, AF_PACKET, etc.).
    insns.append((_BPF_RET | _BPF_K, 0, 0, SECCOMP_RET_ERRNO | _EPERM))
    insns.append((_BPF_RET | _BPF_K, 0, 0, SECCOMP_RET_ALLOW))
    return tuple(insns)


def install_filter(program: tuple) -> None:
    """Install the filter with prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER).
    Requires no_new_privs (established in Step 6) - an unprivileged
    process may only load a filter after no_new_privs is set (ADR-008).
    Raises NamespaceSetupError on failure (fail closed)."""
    insns = [_SockFilter(code, jt, jf, k) for (code, jt, jf, k) in program]
    arr = (_SockFilter * len(insns))(*insns)
    prog = _SockFprog(len(insns), ctypes.cast(arr, ctypes.POINTER(_SockFilter)))
    try:
        _prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
               ctypes.addressof(prog), 0, 0)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot install seccomp filter (prctl PR_SET_SECCOMP): {e} - "
            "fail closed, workload not executed") from e


@dataclass(frozen=True)
class SeccompState:
    """Verified seccomp state (sandbox-internal, kernel read-back)."""

    mode: int       # /proc/self/status Seccomp value (2 = FILTER)
    filters: int    # Seccomp_filters count (1 = exactly our filter)


def _parse_status_field(status: str, field: str) -> int:
    prefix = field + ":"
    for line in status.splitlines():
        if line.startswith(prefix):
            return int(line.split(":", 1)[1].strip())
    raise NamespaceSetupError(
        f"{field} missing from /proc/self/status - seccomp state "
        "verification impossible, fail closed")


def verify_seccomp_state() -> SeccompState:
    """Kernel-observable read-back: /proc/self/status Seccomp must be 2
    (SECCOMP_MODE_FILTER) and Seccomp_filters must be >= 1 (at least our
    filter is active). An unreadable state, a non-FILTER mode, or zero
    filters (our install missing) is a refusal - never a
    warning-and-continue.

    NOTE on the filter count: filters are inherited across fork, so a
    substrate with its own outer filter (Docker Desktop's WSL2 runtime
    applies one even with seccomp=unconfined - empirically Seccomp: 2,
    Seccomp_filters: 1 on the container process) reports 2 after our
    install, while a clean native host reports 1. The MODE (2 = FILTER)
    is the state signal; the count only proves at least one filter (0
    would mean our install did not take)."""
    try:
        status = _read_proc_status()
    except NamespaceSetupError as e:
        raise NamespaceSetupError(
            f"seccomp state verification failed: {e}") from e
    mode = _parse_status_field(status, "Seccomp")
    filters = _parse_status_field(status, "Seccomp_filters")
    problems: list[str] = []
    if mode != SECCOMP_MODE_FILTER:
        problems.append(f"Seccomp mode is {mode}, expected "
                        f"{SECCOMP_MODE_FILTER} (SECCOMP_MODE_FILTER)")
    if filters < 1:
        problems.append(f"Seccomp_filters is {filters}, expected >= 1 "
                        "(our filter must be active)")
    if problems:
        raise NamespaceSetupError(
            "seccomp state verification failed: " + "; ".join(problems)
            + " - fail closed, workload not executed")
    return SeccompState(mode=mode, filters=filters)


def _check_enforcement() -> None:
    """Behavioral spot check AFTER install: a forbidden syscall (socketpair)
    must fail with EPERM. If it succeeds, the filter is not enforcing -
    an unexpected state -> refusal. Uses the Python socket module (the
    syscall is denied by the allowlist). Note: socket is imported at
    module level so the (already-loaded) module is inherited into PID 1
    - a lazy import could not resolve inside the pivoted minimal rootfs.

    v0.2: socket(AF_INET, SOCK_STREAM) is now allowed for proxy
    communication, so we probe socketpair() instead (still denied in
    both deny and allowlist modes)."""
    try:
        # AF_UNIX may not be defined on all platforms (Windows).
        # Use the numeric value directly as a fallback.
        _AF_UNIX_val = getattr(socket, 'AF_UNIX', 1)
        try:
            s1, s2 = socket.socketpair(_AF_UNIX_val, socket.SOCK_STREAM)
        except ValueError:
            # Windows: socketpair only supports AF_INET/AF_INET6.
            # Use AF_INET socketpair as a proxy for filter enforcement.
            s1, s2 = socket.socketpair(socket.AF_INET, socket.SOCK_STREAM)
        s1.close()
        s2.close()
    except OSError as e:
        if e.errno == _EPERM:
            return
        raise NamespaceSetupError(
            f"forbidden syscall probe failed with errno {e.errno}, "
            "expected EPERM - unexpected seccomp behavior, fail closed, "
            "workload not executed") from e
    raise NamespaceSetupError(
        "forbidden syscall probe SUCCEEDED - the filter is not enforcing "
        "(socketpair allowed), fail closed, workload not executed")


def establish_and_verify(program: tuple) -> SeccompState:
    """Install the filter, read the kernel state back, and spot-check
    enforcement. A single entry point for PID 1 so ordering (install ->
    verify -> workload) cannot be inverted."""
    install_filter(program)
    state = verify_seccomp_state()
    _check_enforcement()
    return state
