"""Remaining namespaces: mount, network, UTS, IPC, and PID.

Ordering per ARCHITECTURE.md section 6 / ADR-004: the user namespace is
entered FIRST (it grants namespace-local capabilities), then mount/network/
UTS/IPC, then the PID namespace.

PID-namespace semantics are documented here because they are the classic
foot-gun: a process that calls ``unshare(CLONE_NEWPID)`` does NOT join the
new PID namespace itself - only its CHILDREN do. The first child forked
after ``unshare(CLONE_NEWPID)`` becomes PID 1 of the new namespace. The
supervisor therefore forks a controlled child which unshares and then forks
again; the grandchild is sandbox PID 1 and runs the workload (see setup.py).
The caller's own /proc/self/ns/pid inode does not change after
``unshare(CLONE_NEWPID)`` - PID-namespace distinctness must be verified in
the forked child, not in the unshare caller.
"""

from __future__ import annotations

import os

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

# Namespaces established by enter_remaining_namespaces() (not PID - see above).
_REMAINING_FLAGS = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET

NS_NAMES = ("user", "pid", "mnt", "net", "uts", "ipc")


def ns_identity() -> dict[str, str]:
    """Current process's namespace inodes: {ns_name: inode} for user/pid/
    mnt/net/uts/ipc, read from /proc/self/ns/*. A distinct inode means a
    distinct namespace; identical inodes mean the SAME namespace. An
    unreadable entry is reported as "unavailable" and treated as a failure
    by the verifiers (fail closed - never assume)."""
    out: dict[str, str] = {}
    for name in NS_NAMES:
        path = f"/proc/self/ns/{name}"
        try:
            with open(path, "rb") as f:
                out[name] = str(os.fstat(f.fileno()).st_ino)
        except OSError:
            out[name] = "unavailable"
    return out


def enter_remaining_namespaces() -> None:
    """unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET).

    Requires the user namespace already entered (it provides the
    namespace-local capabilities for these). Raises OSError (fail closed)
    on any failure."""
    syscalls.unshare(_REMAINING_FLAGS)


def enter_pid_namespace() -> None:
    """unshare(CLONE_NEWPID). See the module docstring for the semantics:
    the CALLER does not join the new PID namespace; its next forked child
    becomes PID 1 there. Distinctness is verified in that child."""
    syscalls.unshare(CLONE_NEWPID)


def verify_distinct(host_ns: dict[str, str], sandbox_ns: dict[str, str],
                    expected_same: frozenset[str] = frozenset()) -> None:
    """Verify the namespace boundary: every namespace must differ from the
    host's unless explicitly expected to be the same (only ``pid`` in the
    unshare caller, which legitimately has not changed yet). Raises
    NamespaceSetupError naming every violation."""
    problems: list[str] = []
    for name in NS_NAMES:
        host = host_ns.get(name)
        sbx = sandbox_ns.get(name)
        if sbx is None:
            problems.append(f"{name} namespace missing from sandbox view")
            continue
        if sbx == "unavailable":
            problems.append(f"{name} namespace unreadable inside sandbox - cannot verify")
            continue
        if name in expected_same:
            if host is not None and sbx != host:
                problems.append(f"{name} namespace changed unexpectedly")
        else:
            if host is not None and sbx == host:
                problems.append(f"{name} namespace not distinct from host")
    if problems:
        raise NamespaceSetupError(
            "namespace boundary verification failed: " + "; ".join(problems))
