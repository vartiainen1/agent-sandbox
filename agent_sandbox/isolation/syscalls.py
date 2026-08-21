"""Raw Linux syscall wrappers via ctypes - the thin, audited kernel boundary.

Rules (ADR-001, ARCHITECTURE.md section 5; the seccomp derivation used the
same ctypes discipline):

- A negative syscall return is NEVER success. Every wrapper raises
  ``OSError(errno, strerror(errno))`` on failure - errno is never hidden.
- Identity reads (``getpid``/``getuid``/``getgid``) go through the raw
  ``syscall()`` entry point, NOT libc wrappers, so namespace identity is
  never contaminated by libc-cached values. The verification code in
  userns.py and setup.py trusts only these values.
- Syscall numbers are explicit per architecture (x86_64, aarch64). An
  unsupported architecture fails closed with a deterministic error - it
  never guesses.
- Importing this module is safe on any platform (libc binding is lazy);
  calling the wrappers on a non-Linux host raises OSError, which the
  fail-closed guards translate into a refusal.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform

from agent_sandbox.isolation.errors import NamespaceSetupError


class _SyscallTable:
    """Per-architecture syscall numbers (kernel ABI, not libc)."""

    # x86_64
    X86_64 = {
        "getpid": 39, "getuid": 102, "getgid": 104,
        "unshare": 272, "mount": 165, "umount2": 166,
        "pivot_root": 155, "prctl": 157, "capset": 126,
    }
    # aarch64
    AARCH64 = {
        "getpid": 172, "getuid": 174, "getgid": 175,
        "unshare": 97, "mount": 40, "umount2": 39,
        "pivot_root": 41, "prctl": 167, "capset": 91,
    }


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    raise NamespaceSetupError(
        f"unsupported architecture {machine!r} - syscall numbers unknown, "
        "fail closed (supported: x86_64, aarch64)")


def _number(name: str) -> int:
    table = _SyscallTable.X86_64 if _arch() == "x86_64" else _SyscallTable.AARCH64
    return table[name]


_libc: ctypes.CDLL | None = None
_syscall: ctypes._NamedFuncPointer | None = None


def _get_syscall():
    """Lazy libc binding - import-safe on any platform (Windows dev hosts
    can import this module; only *calls* fail there)."""
    global _libc, _syscall
    if _syscall is None:
        _libc = ctypes.CDLL(None, use_errno=True)
        fn = _libc.syscall
        fn.restype = ctypes.c_long
        fn.argtypes = [
            ctypes.c_long,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        _syscall = fn
    return _syscall


def _raise_errno(name: str) -> None:
    e = ctypes.get_errno()
    raise OSError(e, f"{name}: {os.strerror(e)}")


def _check(ret: int, name: str) -> int:
    """Negative return is NEVER success (ADR-001; deterministic errno)."""
    if ret < 0:
        _raise_errno(name)
    return ret


def _raw(number: int, *args) -> int:
    """Invoke the raw syscall with exactly the declared argument count.
    ctypes validates the number of args against the prototype, so unused
    variadic slots are padded with 0 (the kernel ignores them)."""
    padded = list(args) + [0] * (6 - len(args))
    return int(_get_syscall()(number, *padded))


# ---------------------------------------------------------------------------
# Raw identity reads (never libc-cached)
# ---------------------------------------------------------------------------

def getpid() -> int:
    return _raw(_number("getpid"))


def getuid() -> int:
    return _raw(_number("getuid"))


def getgid() -> int:
    return _raw(_number("getgid"))


# ---------------------------------------------------------------------------
# Namespace / mount operations
# ---------------------------------------------------------------------------

# mount(2) flags (kernel ABI)
MS_RDONLY = 0x1
MS_NOSUID = 0x2
MS_NODEV = 0x4
MS_NOEXEC = 0x8
MS_REMOUNT = 0x20
MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 0x40000
# umount2(2) flags
MNT_DETACH = 0x2


def makedev(major: int, minor: int) -> int:
    """Linux dev_t encoding. The classic (major << 8) | minor encoding is
    exact for majors and minors < 256, which covers every device node in
    the minimal /dev inventory (and rejects out-of-range values loudly)."""
    if not (0 <= major < 256 and 0 <= minor < 256):
        raise NamespaceSetupError(
            f"device number ({major}, {minor}) outside the classic dev_t "
            "encoding - fail closed")
    return (major << 8) | minor


def unshare(flags: int) -> None:
    """unshare(2). Raises OSError with the real errno on failure."""
    _check(_raw(_number("unshare"), flags), "unshare")


def mount(source: bytes, target: bytes, fstype: bytes, flags: int,
          data: bytes = b"") -> None:
    """mount(2). Used only during namespace setup inside the sandbox's own
    user namespace (tmpfs mounts for the mount-isolation verification)."""
    _check(_raw(_number("mount"),
                ctypes.c_char_p(source), ctypes.c_char_p(target),
                ctypes.c_char_p(fstype), flags, ctypes.c_char_p(data)),
           "mount")


def umount2(target: bytes, flags: int = 0) -> None:
    """umount2(2). Unmount inside the sandbox's mount namespace."""
    _check(_raw(_number("umount2"), ctypes.c_char_p(target), flags), "umount2")


def pivot_root(new_root: bytes, put_old: bytes) -> None:
    """pivot_root(2): move the caller's root to ``new_root`` and stack the
    old root at ``put_old`` (both must be mount points). The classic
    rootless pattern calls it as pivot_root(".", ".") after chdir'ing into
    the bind-mounted new root, then detaches the old root with
    umount2(MNT_DETACH). Raises OSError (fail closed) on any failure."""
    _check(_raw(_number("pivot_root"),
                ctypes.c_char_p(new_root), ctypes.c_char_p(put_old)),
           "pivot_root")


# prctl(2) options (kernel ABI)
PR_SET_NO_NEW_PRIVS = 38   # arg2=1 enables no_new_privs for this thread
PR_GET_NO_NEW_PRIVS = 39   # returns 0 or 1 (the current no_new_privs value)
PR_CAPBSET_DROP = 24       # arg2 = capability number to drop from the bounding set
PR_CAP_AMBIENT = 47        # ambient-capability option (see PR_CAP_AMBIENT_CLEAR_ALL)
PR_CAP_AMBIENT_CLEAR_ALL = 4  # PR_CAP_AMBIENT sub-option: clear all ambient caps
PR_SET_CHILD_SUBREAPER = 36  # arg2=1 makes this process reap orphaned descendants
PR_GET_CHILD_SUBREAPER = 37  # returns 0 or 1 (current child-subreaper state)


def prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0,
          arg5: int = 0) -> int:
    """prctl(2): long prctl(int option, unsigned long arg2, ...). Returns
    the raw kernel value (PR_GET_NO_NEW_PRIVS returns 0 or 1; PR_SET
    returns 0 on success). A negative return is NEVER success - raises
    OSError with the real errno (ADR-001)."""
    return _check(_raw(_number("prctl"), option, arg2, arg3, arg4, arg5),
                  "prctl")


# capset(2) - capability set manipulation (clearing one's own sets to
# zero never requires privilege; raising them would, and is never done).
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class CapUserHeader(ctypes.Structure):
    """struct __user_cap_header_struct (kernel ABI)."""
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapUserData(ctypes.Structure):
    """struct __user_cap_data_struct (kernel ABI): one 32-bit word per
    set; _LINUX_CAPABILITY_VERSION_3 uses an array of two for bits 0-63."""
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def prctl_get_child_subreaper() -> int:
    """prctl(PR_GET_CHILD_SUBREAPER): the kernel returns the value via
    arg2 as a pointer to int (unlike PR_GET_NO_NEW_PRIVS which returns
    the value directly). Passing NULL would EFAULT - a real buffer is
    required. Returns 0 or 1. Raises OSError with the real errno on
    failure (never hides errno, ADR-001)."""
    value = ctypes.c_int(0)
    _check(_raw(_number("prctl"), PR_GET_CHILD_SUBREAPER,
                ctypes.byref(value)), "prctl")
    return value.value


def capset(version: int, data: list) -> None:
    """capset(2): set the calling thread's capability sets. ``data`` is a
    list of (effective, permitted, inheritable) tuples (two entries for
    _LINUX_CAPABILITY_VERSION_3, covering bits 0-63). The sandbox uses it
    ONLY to clear every set to zero - lowering one's own capabilities
    never requires privilege. Raises OSError with the real errno on
    failure (fail closed)."""
    hdr = CapUserHeader(version, 0)
    arr = (CapUserData * len(data))(*[CapUserData(*d) for d in data])
    _check(_raw(_number("capset"), ctypes.byref(hdr), ctypes.byref(arr)),
           "capset")



