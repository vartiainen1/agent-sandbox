"""Rootless capability probe (native Linux, detection + recording).

Phase 0 specifies rootless execution: user namespaces with a uid 0 ->
caller mapping, everything unprivileged. The Docker derivation ran as root
without a userns, so it does NOT validate the rootless surface. This probe
detects, on the host it runs on (native CI runner), which rootless
mechanisms are actually exercisable, and records the result honestly.

Per user directive: an unavailable mechanism is DETECTED, RECORDED with a
reason, and reported - never converted into a false PASS. This script does
not claim "rootless sandbox verified"; it reports per-mechanism status:

    uid=<n> root=no/yes
    userns:                 VERIFIED | BLOCKED (<reason>)
    seccomp-as-nonroot:     VERIFIED | BLOCKED (<reason>)
    no_new_privs:           VERIFIED | BLOCKED (<reason>)

Exit 0 always (this is a detection step; enforcement is tested by
probe_policy.py). CI captures the output; a BLOCKED mechanism is a
documented limitation, not a pass.
"""

import ctypes
import os
import sys

CLONE_NEWUSER = 0x10000000
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000

libc = ctypes.CDLL(None, use_errno=True)


def prctl(option, *args):
    return libc.prctl(ctypes.c_int(option), *[ctypes.c_ulong(a) for a in args])


def check_userns() -> tuple[bool, str]:
    """Try to create a user namespace unprivileged (unshare(2))."""
    r = libc.unshare(ctypes.c_int(CLONE_NEWUSER))
    if r == 0:
        # success - we are now inside a new userns; confirm mapping is absent
        # (we only probe availability; the runtime does the full mapping).
        return True, "unshare(CLONE_NEWUSER) succeeded (as uid {})".format(os.geteuid())
    return False, "unshare(CLONE_NEWUSER) failed errno={} ({})".format(
        ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def check_seccomp_nonroot() -> tuple[bool, str]:
    """Install a trivial always-allow filter as the current (non-root) user."""
    class sock_filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

    class sock_fprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(sock_filter))]

    insn = sock_filter(0x0006 | 0x00, 0, 0, SECCOMP_RET_ALLOW)  # RET ALLOW
    arr = (sock_filter * 1)(insn)
    prog = sock_fprog(1, ctypes.cast(arr, ctypes.POINTER(sock_filter)))
    if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return False, "no_new_privs failed errno={} ({})".format(
            ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    if prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(prog), 0, 0) != 0:
        return False, "seccomp filter load failed errno={} ({})".format(
            ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return True, "seccomp filter installed as uid {} after no_new_privs".format(os.geteuid())


def main() -> int:
    if sys.platform.startswith("win"):
        print("ERROR: rootless capability probe requires Linux.", file=sys.stderr)
        return 2
    root = os.geteuid() == 0
    print(f"uid={os.geteuid()} root={'yes' if root else 'no'}")
    if root:
        print("WARNING: running as root - results do NOT validate the rootless path")
    userns_ok, userns_note = check_userns()
    print(f"userns:                 {'VERIFIED' if userns_ok else 'BLOCKED'} ({userns_note})")
    seccomp_ok, seccomp_note = check_seccomp_nonroot()
    print(f"seccomp-as-nonroot:     {'VERIFIED' if seccomp_ok else 'BLOCKED'} ({seccomp_note})")
    nnp_ok = seccomp_ok  # no_new_privs succeeded as part of the seccomp check
    print(f"no_new_privs:           {'VERIFIED' if nnp_ok else 'BLOCKED'}")
    print()
    print("SUMMARY: detection complete. Mechanisms not VERIFIED here are NOT")
    print("claimed. Rootless uid-mapped runtime validation remains a Phase 1")
    print("runtime test on a host that can provide the mechanisms.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
