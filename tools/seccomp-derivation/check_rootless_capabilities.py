"""Rootless capability probe (native Linux, detection + recording).

Phase 0 specifies rootless execution: user namespaces with a uid 0 ->
caller mapping, everything unprivileged. The Docker derivation ran as root
without a userns, so it does NOT validate the rootless surface. This probe
detects, on the host it runs on (native CI runner), which rootless
mechanisms are actually exercisable, and records the result honestly.

IMPORTANT (learned on the ubuntu-24.04 runner, 2026-08-19): probing only
unshare(CLONE_NEWUSER) is NOT the rootless path - the mapping is a
separate, mandatory step. unshare can succeed while the mapping cannot be
established (AppArmor userns restriction denies the setgroups-deny write
with EACCES). This probe therefore exercises the FULL path: unshare ->
setgroups deny -> uid_map/gid_map write -> read-back verify.

Per user directive: an unavailable mechanism is DETECTED, RECORDED with a
reason, and reported - never converted into a false PASS. This script does
not claim "rootless sandbox verified"; it reports per-mechanism status:

    uid=<n> root=no/yes
    userns-mapping:         VERIFIED | BLOCKED (<reason>)
    seccomp-as-nonroot:     VERIFIED | BLOCKED (<reason>)
    no_new_privs:           VERIFIED | BLOCKED (<reason>)

Exit 0 always (this is a detection step; enforcement is tested by
probe_policy.py and tests/unit/test_namespaces.py). CI captures the
output; a BLOCKED mechanism is a documented limitation, not a pass.
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


def check_userns_mapping() -> tuple[bool, str]:
    """Exercise the FULL rootless path: create the user namespace, deny
    setgroups, write the uid 0 -> caller mapping, and verify the read-back.
    unshare success alone is NOT the rootless surface (the mapping is a
    separate mandatory step) - see the module docstring."""
    caller_uid, caller_gid = os.getuid(), os.getgid()
    r = libc.unshare(ctypes.c_int(CLONE_NEWUSER))
    if r != 0:
        return False, "unshare(CLONE_NEWUSER) failed errno={} ({})".format(
            ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    try:
        with open("/proc/self/setgroups", "w", encoding="ascii") as f:
            f.write("deny")
    except OSError as e:
        return False, ("setgroups deny failed errno={} ({}) - the uid 0 -> "
                       "caller mapping cannot be established unprivileged").format(
            e.errno, e.strerror)
    try:
        with open("/proc/self/uid_map", "w", encoding="ascii") as f:
            f.write(f"0 {caller_uid} 1\n")
        with open("/proc/self/gid_map", "w", encoding="ascii") as f:
            f.write(f"0 {caller_gid} 1\n")
    except OSError as e:
        return False, "uid/gid map write failed errno={} ({})".format(
            e.errno, e.strerror)
    # Read back and verify the applied mapping (never trust write success).
    try:
        with open("/proc/self/uid_map", encoding="ascii") as f:
            um = f.read().strip().split()
        with open("/proc/self/gid_map", encoding="ascii") as f:
            gm = f.read().strip().split()
    except OSError as e:
        return False, "mapping read-back failed errno={} ({})".format(
            e.errno, e.strerror)
    uid_ok = len(um) == 3 and um[0] == "0" and int(um[1]) == caller_uid
    gid_ok = len(gm) == 3 and gm[0] == "0" and int(gm[1]) == caller_gid
    if not uid_ok or not gid_ok:
        return False, ("mapping read-back mismatch: uid_map={} gid_map={} "
                       "(expected 0 -> {} and 0 -> {})").format(
            um, gm, caller_uid, caller_gid)
    return True, ("full uid 0 -> caller mapping established and verified "
                  "(unshare + setgroups deny + read-back) as uid {}").format(
        os.geteuid())


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
    userns_ok, userns_note = check_userns_mapping()
    print(f"userns-mapping:         {'VERIFIED' if userns_ok else 'BLOCKED'} ({userns_note})")
    seccomp_ok, seccomp_note = check_seccomp_nonroot()
    print(f"seccomp-as-nonroot:     {'VERIFIED' if seccomp_ok else 'BLOCKED'} ({seccomp_note})")
    nnp_ok = seccomp_ok  # no_new_privs succeeded as part of the seccomp check
    print(f"no_new_privs:           {'VERIFIED' if nnp_ok else 'BLOCKED'}")
    print()
    print("SUMMARY: detection complete. Mechanisms not VERIFIED here are NOT")
    print("claimed. A BLOCKED userns-mapping means the substrate cannot")
    print("exercise the rootless path; the namespace tests skip with the same")
    print("recorded reason (never a false PASS), and the fail-closed refusal")
    print("remains verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
