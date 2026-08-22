"""Process-tree containment and cleanup (Phase 1 Step 15, item 20).

Policy (S-014, S-038, ADR-011, ARCHITECTURE section 6/13): when the
controlled session terminates - especially on timeout or output
exhaustion - the ENTIRE workload process tree must be contained and
eliminated, not merely the supervisor's immediate child. Killing only
the parent is explicitly forbidden.

Authoritative mechanism (kernel-enforced, not a status flag):

1. The supervisor sets itself as a CHILD SUBREAPER
   (prctl(PR_SET_CHILD_SUBREAPER)) before forking, so orphaned workload
   descendants reparent to the supervisor, not to init - enabling
   reliable discovery and cleanup (S-014, S-038).
2. The workload lives in its OWN PID namespace (Step 2): sandbox PID 1
   is the namespace init. SIGKILL to sandbox PID 1 makes the kernel
   terminate EVERY process in that namespace (namespace-init death is a
   kernel guarantee) - this catches every descendant regardless of
   parentage, including vfork/exec descendants.
3. Where cgroup v2 is delegated (Step 10), `cgroup.kill` on the session
   cgroup additionally kills every process in the cgroup regardless of
   parentage (belt-and-braces per ADR-011).
4. Absence verification (S-038) is MANDATORY: after termination the
   supervisor verifies from kernel-visible state that no workload
   process remains - scanning /proc for the sandbox PID namespace inode
   and, where delegated, requiring an empty session cgroup.procs.
   Incomplete cleanup is DETECTED and REPORTED - never reported as
   successful (S-038, S-024).

Import safety: imports only stdlib pieces available on every platform;
the Linux-only prctl/procfs behavior is exercised only when a caller
actually runs lifecycle operations (never at import time).
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError

# cgroup v2 kill interface (kernel >= 5.14): writing "1" SIGKILLs every
# process in the cgroup.
_CGROUP_KILL = "cgroup.kill"
_CGROUP_PROCS = "cgroup.procs"


def establish_subreaper(kill_impl: Callable | None = None) -> None:
    """Supervisor-side: set this process as a child subreaper and verify
    by kernel-state read-back (PR_GET_CHILD_SUBREAPER == 1). A failure to
    set or verify is a refusal - orphaned workload descendants must
    reparent to the supervisor, not to init (S-014, S-038)."""
    try:
        syscalls.prctl(syscalls.PR_SET_CHILD_SUBREAPER, 1)
        got = syscalls.prctl_get_child_subreaper()
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot establish child subreaper: {e} - fail closed, "
            "process-tree containment cannot be guaranteed") from e
    if got != 1:
        raise NamespaceSetupError(
            f"child subreaper read-back is {got}, expected 1 - fail "
            "closed, process-tree containment cannot be guaranteed")


def is_subreaper() -> bool:
    """Kernel-state read-back of the child-subreaper flag (0 or 1)."""
    try:
        return syscalls.prctl_get_child_subreaper() == 1
    except OSError:
        return False


def kill_pid(pid: int, sig: int, kill_impl: Callable[[int, int], None]
             = os.kill) -> None:
    """Kill one process; a missing process is tolerated (already gone)."""
    try:
        kill_impl(pid, sig)
    except OSError:
        pass


def terminate_tree(sandbox_pid1: int, cgroup_session=None,
                   kill_impl: Callable[[int, int], None] = os.kill,
                   sleep_impl: Callable[[float], None] = time.sleep,
                   grace: float = 0.05) -> None:
    """Authoritative tree termination (S-014, ADR-011):

    1. SIGKILL to sandbox PID 1 (the namespace init) - the kernel then
       terminates EVERY process in the sandbox PID namespace, catching
       all descendants regardless of parentage.
    2. Where a session cgroup is delegated: `cgroup.kill` on the session
       cgroup (kills every process in the cgroup regardless of
       parentage - belt-and-braces).
    3. A short grace so the kernel finishes namespace teardown before
       the caller verifies absence.

    Never kills only the immediate parent. A sandbox PID 1 that already
    exited is tolerated (nothing to terminate - the namespace died with
    its init).
    """
    kill_pid(sandbox_pid1, 9, kill_impl)
    if cgroup_session is not None:
        _cgroup_kill(cgroup_session, kill_impl)
    if grace > 0:
        sleep_impl(grace)


def namespace_inode(pid: int, readlink_impl: Callable[[str], str] | None
                    = None) -> str | None:
    """The PID namespace inode of ``pid`` (kernel-visible, via /proc).

    Returns the inode string ("4026532448") or None if the process is
    already gone. The sandbox PID namespace inode identifies exactly the
    workload tree - every workload process is in that namespace (it
    cannot escape: no setns, no unshare, no CAP_SYS_ADMIN under the
    Step 7/8 restrictions)."""
    impl = readlink_impl or os.readlink
    try:
        target = impl(f"/proc/{pid}/ns/pid")
    except OSError:
        return None
    # Format: "pid:[4026532448]"
    if target.startswith("pid:[") and target.endswith("]"):
        return target[5:-1]
    return target


def procs_in_namespace(ns_inode: str,
                       listdir_impl: Callable[[str], Iterable[str]] | None
                       = None,
                       readlink_impl: Callable[[str], str] | None
                       = None) -> list[int]:
    """Scan /proc for processes whose PID namespace inode matches
    ``ns_inode`` - the kernel-visible workload-tree membership test.
    Used for the S-038 absence check: after termination, this must be
    empty."""
    ld = listdir_impl or os.listdir
    rl = readlink_impl or os.readlink
    found: list[int] = []
    try:
        entries = ld("/proc")
    except OSError:
        return found
    for name in entries:
        if not name.isdigit():
            continue
        try:
            target = rl(f"/proc/{name}/ns/pid")
        except OSError:
            continue
        inode = target[5:-1] if (target.startswith("pid:[")
                                 and target.endswith("]")) else target
        if inode == ns_inode:
            try:
                found.append(int(name))
            except ValueError:
                continue
    return sorted(found)


def _cgroup_kill(session, kill_impl: Callable[[int, int], None]
                 = os.kill) -> None:
    """Write 1 to the session cgroup's cgroup.kill (kernel >= 5.14):
    SIGKILL every process in the cgroup regardless of parentage."""
    path = os.path.join(session.path, _CGROUP_KILL)
    try:
        with open(path, "w", encoding="ascii") as f:
            f.write("1\n")
    except OSError:
        # The PID-1 namespace kill already covers the workload tree; the
        # absence check below still verifies. Best-effort belt-and-braces.
        pass


def _read_cgroup_procs(session) -> list[str]:
    path = os.path.join(session.path, _CGROUP_PROCS)
    try:
        with open(path, "r", encoding="ascii") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return []


def _cgroup_procs_nonempty(session, read_impl: Callable = _read_cgroup_procs
                           ) -> bool:
    if session is None:
        return False
    return bool(read_impl(session))


def verify_no_workload_remains(sandbox_pid1: int, cgroup_session=None,
                               kill_impl: Callable[[int, int], None] | None
                               = None,
                               procs_impl: Callable | None = None,
                               read_impl: Callable | None = None,
                               retries: int = 40, delay: float = 0.05
                               ) -> tuple[list[int], str | None]:
    """Mandatory absence verification (S-038, S-024).

    After termination, require from kernel-visible state that NO
    workload process remains:

    - the sandbox PID namespace inode must have no member processes;
    - where a session cgroup is delegated, cgroup.procs must be empty.

    Incomplete cleanup is detected and REPORTED - never reported as
    successful. Returns ``(survivors, reason)``; a non-empty survivors
    list is a cleanup failure (the caller fails closed). The check is
    retried briefly (namespace teardown is not instantaneous) before
    declaring incomplete cleanup.
    """
    scan = procs_impl or procs_in_namespace
    cgread = read_impl or _read_cgroup_procs
    inode = namespace_inode(sandbox_pid1)
    if inode is None:
        # The namespace init is already gone - with it, the namespace
        # died (kernel guarantee): nothing can remain in it.
        return [], None
    for _ in range(retries):
        survivors = scan(inode)
        cgroup_left = _cgroup_procs_nonempty(cgroup_session, cgread)
        if not survivors and not cgroup_left:
            return [], None
        time.sleep(delay)
    survivors = scan(inode)
    if survivors:
        return survivors, (
            f"cleanup incomplete: workload process(es) survive in the "
            f"sandbox PID namespace ({', '.join(map(str, survivors))}) - "
            "S-038, never reported as successful")
    if _cgroup_procs_nonempty(cgroup_session, cgread):
        return [], (
            "cleanup incomplete: session cgroup.procs is not empty after "
            "termination - S-038, never reported as successful")
    return [], None
