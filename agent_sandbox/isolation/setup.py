"""Namespace setup orchestrator - the supervisor's controlled child.

Process shape (ARCHITECTURE.md section 6, ADR-004, ADR-001):

    supervisor (TRUSTED, stays outside all namespaces)
        |  os.fork()
        v
    child A: enters user ns -> verifies uid/gid map -> enters
             mount/net/UTS/IPC -> unshare(CLONE_NEWPID)
        |  os.fork()
        v
    child B (grandchild): PID 1 of the new PID namespace; runs the
             workload function. Everything it spawns stays inside the
             namespace boundary.

Why the double fork: the process that calls unshare(CLONE_NEWPID) does not
itself join the new PID namespace - only its children do (namespaces.py
docstring). Child B is therefore the first process in the new PID
namespace and is PID 1 there (ADR-004).

Step 3 (filesystem boundary): when a rootfs is supplied, child A ALSO
establishes the filesystem boundary before forking - private mount
propagation, the rootfs tree bind-mounted into a mount point, a
size-limited tmpfs at /tmp, pivot_root into the rootfs, and detachment of
the old root (filesystem.py). PID 1 then runs the workload inside the new
root; a failed or unverifiable boundary aborts BEFORE the workload fn runs
(fail closed).

The supervisor NEVER enters the namespaces or the new root: it must keep
its host view (cleanup, audit, timeout - later steps). The NAMESPACES and
FILESYSTEM stage guards therefore probe the real path in forked children
and report a StageCheck back; a failed or unverifiable probe is a refusal,
never a skip.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass

from agent_sandbox.isolation import filesystem as fs_mod
from agent_sandbox.isolation import namespaces, rootfs, syscalls, userns
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage, StageCheck

# The enforcement core (agent_sandbox.security.init) is referenced by module
# (never imported names) so tests can patch its single platform seam
# (_is_linux) and it is seen by this module at call time. This module is
# imported lazily by the initializer, so there is no import cycle.
from agent_sandbox.security import init as _security_init


@dataclass(frozen=True)
class NamespaceState:
    """Verified namespace state after entering the sandbox boundary."""

    userns: userns.UserNamespaceState
    host_ns: dict[str, str]       # captured before entering (outside)
    sandbox_ns: dict[str, str]    # captured after entering (inside)


@dataclass(frozen=True)
class SandboxRun:
    """Result of running a function inside the sandbox boundary."""

    exit_code: int
    output: str


def enter_all_namespaces() -> NamespaceState:
    """Child-side sequence: user ns -> mapping -> verify -> remaining
    namespaces -> PID namespace. Returns the verified NamespaceState.

    Raises NamespaceSetupError / OSError on any failure - the caller (a
    forked child) reports it and the guard refuses. Never continues with
    an unverified state."""
    host_ns = namespaces.ns_identity()               # outside view
    state = userns.enter_user_namespace()            # unshare + map + verify
    namespaces.enter_remaining_namespaces()          # mnt/net/uts/ipc
    namespaces.enter_pid_namespace()                 # caller does NOT join
    sandbox_ns = namespaces.ns_identity()
    # user/mnt/net/uts/ipc must now differ from host; pid legitimately has
    # NOT changed for the unshare caller (documented - verified in the child).
    namespaces.verify_distinct(host_ns, sandbox_ns, expected_same=frozenset({"pid"}))
    return NamespaceState(userns=state, host_ns=host_ns, sandbox_ns=sandbox_ns)


def run_in_sandbox(fn, rootfs_state=None, disk_mb: int = 10240) -> SandboxRun:
    """Run ``fn`` inside the full sandbox boundary.

    Namespaces only (Step 2): ``fn(state)`` - state is the verified
    NamespaceState.
    With a rootfs (Step 3): the filesystem boundary is established too
    (private propagation, bind rootfs, tmpfs /tmp, pivot_root, old-root
    detach, verification) and ``fn(state, fs)`` is called with the
    verified FilesystemState. fn may return a str, captured as ``output``.

    The supervisor stays outside; the kernel enforces the boundary for
    fn's whole process tree. Any boundary failure aborts BEFORE fn runs
    (fail closed - fn never executes on a partial boundary)."""
    out_r, out_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        # Child A: enters the namespaces, establishes the filesystem
        # boundary (if a rootfs is given), then forks so its child becomes
        # PID 1 of the new PID namespace (documented PID semantics).
        os.close(out_r)
        try:
            state = enter_all_namespaces()
            fs_state = None
            if rootfs_state is not None:
                fs_state = fs_mod.establish_rootfs(rootfs_state, disk_mb)
        except BaseException as e:  # noqa: BLE001 - report, don't propagate across fork
            os.write(out_w, f"FAIL setup: {type(e).__name__}: {e}\n".encode())
            os._exit(1)
        grand = os.fork()
        if grand == 0:
            # Child B: PID 1 in the new PID namespace - runs the workload fn.
            os.dup2(out_w, 1)
            os.dup2(out_w, 2)
            os.close(out_w)
            try:
                if fs_state is None:
                    result = fn(state)
                else:
                    result = fn(state, fs_state)
                if result is not None:
                    print(result)
                sys.stdout.flush()
                os._exit(0)
            except BaseException as e:  # noqa: BLE001
                print(f"FAIL workload: {type(e).__name__}: {e}", file=sys.stderr)
                sys.stderr.flush()
                os._exit(1)
        # Child A: wait for PID 1, exit with its status.
        _, status = os.waitpid(grand, 0)
        os._exit(os.waitstatus_to_exitcode(status))

    # Supervisor side: collect output, reap the controlled child.
    os.close(out_w)
    output = b""
    while True:
        chunk = os.read(out_r, 65536)
        if not chunk:
            break
        output += chunk
    _, status = os.waitpid(pid, 0)
    return SandboxRun(exit_code=os.waitstatus_to_exitcode(status),
                      output=output.decode(errors="replace"))


def _pid1_verification(state: NamespaceState) -> str:
    """PID-1-side verification of the sandbox boundary (runs in the first
    process of the new PID namespace). Returns "OK" or "FAIL <detail>"."""
    sandbox_ns = namespaces.ns_identity()
    problems: list[str] = []
    if syscalls.getuid() != 0 or syscalls.getgid() != 0:
        problems.append(
            f"identity not (0,0) in PID 1: uid={syscalls.getuid()} gid={syscalls.getgid()}")
    # PID namespace: the child IS in the new PID namespace now - must differ
    # from the host, and the raw pid must be 1 (first process in the ns).
    if sandbox_ns.get("pid") in (None, "unavailable"):
        problems.append("pid namespace unreadable in PID 1")
    elif sandbox_ns["pid"] == state.host_ns.get("pid"):
        problems.append("pid namespace not distinct from host in PID 1")
    if syscalls.getpid() != 1:
        problems.append(f"raw pid in PID 1 is {syscalls.getpid()}, expected 1")
    if problems:
        return "FAIL " + "; ".join(problems)
    return "OK"


def namespace_probe() -> StageCheck:
    """Real-path probe of the full namespace setup, run in a forked child
    so the supervisor never enters the namespaces. This is the NAMESPACES
    stage guard's evidence: it establishes user+mount+PID+network+UTS+IPC,
    verifies the uid/gid mapping and the PID-1 identity, and reports
    StageCheck(ok=True) only when every verification passed."""
    return _probe_impl()


def _probe_impl() -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="namespace probe requires Linux with os.fork (fail closed "
                   "- namespaces cannot be established on this platform)")
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            state = enter_all_namespaces()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        grand = os.fork()
        if grand == 0:
            # PID 1: verify the boundary from inside and report the verdict
            # through the inherited write_fd (the only verdict writer).
            try:
                verdict = _pid1_verification(state)
                os.write(write_fd, verdict.encode())
            except BaseException as e:  # noqa: BLE001
                os.write(write_fd, f"FAIL {type(e).__name__}: {e}".encode())
            os._exit(0)
        # Child A: wait for PID 1, then exit (closing its write_fd copy).
        _, status = os.waitpid(grand, 0)
        os._exit(0 if os.waitstatus_to_exitcode(status) == 0 else 1)
    os.close(write_fd)
    data = b""
    while True:
        chunk = os.read(read_fd, 65536)
        if not chunk:
            break
        data += chunk
    _, status = os.waitpid(pid, 0)
    msg = data.decode(errors="replace").strip()
    if msg == "OK":
        return StageCheck(
            ok=True,
            reason="user/mount/PID/network/UTS/IPC namespaces established "
                   "and verified in a real forked child (uid/gid map "
                   "0 -> caller, PID 1 identity confirmed)")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"namespace probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _namespaces_guard(config) -> StageCheck:
    """NAMESPACES stage guard (registered below). Probes the real namespace
    path; HARDENED/RESTRICTED refuse unless the full boundary is
    established and verified."""
    return namespace_probe()


def _fs_pid1_verification(state: NamespaceState,
                          fs: fs_mod.FilesystemState) -> str:
    """PID-1-side verification of the filesystem boundary (runs inside the
    new root). Returns "OK" or "FAIL <detail>" - never a silent pass."""
    problems: list[str] = []
    cur = os.stat("/")
    if (cur.st_dev, cur.st_ino) != fs.root_identity:
        problems.append(
            f"root identity mismatch in PID 1: / is {(cur.st_dev, cur.st_ino)}")
    if os.getcwd() != "/":
        problems.append(f"cwd is {os.getcwd()!r}, expected /")
    if not os.path.isdir("/workspace"):
        problems.append("/workspace missing in PID 1")
    hits = fs_mod._probe_absent(fs_mod.MANDATORY_ABSENT_PATHS)
    if hits:
        problems.append("host path(s) reachable in PID 1: " + ", ".join(hits))
    if problems:
        return "FAIL " + "; ".join(problems)
    return "OK"


def filesystem_probe(config) -> StageCheck:
    """Real-path probe of the FILESYSTEM boundary (rootfs build ->
    namespaces -> mounts -> pivot_root -> old-root detach -> in-root
    verification), run in a forked child so the supervisor never enters the
    boundary. This is the FILESYSTEM stage guard's evidence."""
    return _filesystem_probe_impl(config)


def _filesystem_probe_impl(config) -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="filesystem probe requires Linux with os.fork (fail "
                   "closed - the rootfs boundary cannot be established here)")
    # Build the rootfs host-side first (supervisor makes the workspace
    # copy, ARCHITECTURE section 7) so a build failure refuses WITHOUT
    # forking, and the parent can clean the tree afterwards.
    try:
        rootfs_state = rootfs.build_rootfs(config.workspace)
    except NamespaceSetupError as e:
        return StageCheck(ok=False, code=InitFailureCode.STAGE_FAILED,
                          reason=f"rootfs build failed: {e} - fail closed, "
                                 "workload not executed")
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            state = enter_all_namespaces()
            fs_state = fs_mod.establish_rootfs(rootfs_state, config.resources.disk_mb)
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        grand = os.fork()
        if grand == 0:
            # PID 1: verify the filesystem boundary from inside the new root.
            try:
                verdict = _fs_pid1_verification(state, fs_state)
                os.write(write_fd, verdict.encode())
            except BaseException as e:  # noqa: BLE001
                os.write(write_fd, f"FAIL {type(e).__name__}: {e}".encode())
            os._exit(0)
        _, status = os.waitpid(grand, 0)
        os._exit(0 if os.waitstatus_to_exitcode(status) == 0 else 1)
    os.close(write_fd)
    data = b""
    while True:
        chunk = os.read(read_fd, 65536)
        if not chunk:
            break
        data += chunk
    _, status = os.waitpid(pid, 0)
    shutil.rmtree(rootfs_state.layout.dir, ignore_errors=True)  # best-effort
    msg = data.decode(errors="replace").strip()
    if msg == "OK":
        return StageCheck(
            ok=True,
            reason="minimal rootfs + workspace copy + pivot_root + old-root "
                   "detach + private mount propagation established and "
                   "verified in a real forked child")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"filesystem probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _filesystem_guard(config) -> StageCheck:
    """FILESYSTEM stage guard (registered below). Probes the real rootfs
    boundary; HARDENED/RESTRICTED refuse unless it is established and
    verified."""
    return filesystem_probe(config)


# Register the guards with the enforcement core. This module is imported
# lazily by SecurityInitializer (and directly by tests), so the registry
# sees each mechanism exactly when it exists - never before.
_security_init.register_stage_guard(InitStage.NAMESPACES, _namespaces_guard)
_security_init.register_stage_guard(InitStage.FILESYSTEM, _filesystem_guard)
