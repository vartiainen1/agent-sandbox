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

Step 3-4 (filesystem boundary): when a rootfs is supplied, child A ALSO
establishes the filesystem boundary before forking - private mount
propagation, the rootfs tree bind-mounted into a mount point, a
size-limited tmpfs at /tmp, pivot_root into the rootfs, detachment of the
old root, and the minimal /dev tmpfs with its exact 6 device nodes
(filesystem.py).

Step 5 (network deny-by-construction): the netns created in Step 2 is
configured into its final v0.1 state - lo brought DOWN (ensure_loopback_down)
and the resulting state VERIFIED by PID 1 (only lo, lo DOWN, no
addresses, no usable routes, distinct from host netns - network.py); any
unexpected element is a refusal.

Step 6 (no_new_privs, S-010, ADR-008): PID 1 establishes no_new_privs
(prctl PR_SET_NO_NEW_PRIVS) and verifies the kernel-state read-back
(PR_GET_NO_NEW_PRIVS == 1) immediately before invoking the workload
function - ordering is structural, the workload cannot execute before
the invariant is established (privileges.py). It precedes the seccomp
install (Step 13): an unprivileged process may only load a filter after
no_new_privs is set.

Step 7 (capability reduction, S-009, ADR-008): PID 1 then drops the
ENTIRE capability bounding set (PR_CAPBSET_DROP for every capability),
clears the ambient set and clears effective/permitted/inheritable via
capset, and verifies the kernel-state read-back (/proc/self/status
CapBnd/CapEff/CapPrm/CapInh/CapAmb all zero) - the workload holds NO
capabilities, including inside its own user namespace (the Step 5
lo-toggle residual is resolved here: CAP_NET_ADMIN is gone). This
happens AFTER no_new_privs (mandated order) and before the workload fn.

Step 8 (seccomp, S-011, ADR-008): the derived 45-syscall default-deny
filter (allowlist.json - the regression-protected artifact) is built
host-side in child A BEFORE entering the boundary (the artifact is not
reachable inside the pivoted rootfs), then installed in PID 1 as the
LAST hardening operation - after no_new_privs and the capability
reduction, immediately before the workload fn - and verified by
kernel-observable read-back (/proc/self/status Seccomp=2,
Seccomp_filters=1) plus a forbidden-syscall (socket -> EPERM) spot
check (seccomp.py). Install failure, verification failure, or an
unexpected state refuses before the workload runs.

Step 9 (rlimits, S-012/S-027, ADR-007): PID 1 then lowers the six
mandated rlimits (RLIMIT_CPU/AS/NPROC/NOFILE/FSIZE/CORE=0, soft ==
hard) and verifies the kernel-state read-back. Established AFTER the
seccomp install (prlimit64 is in the derived allowlist - no filter
change) and BEFORE the workload fn (resources.py). The RESOURCES stage
is the last mandatory stage implemented so far: HARDENED still refuses
AT RESOURCES (the cgroup v2 half is Step 10), while RESTRICTED
completes its RESOURCES stage with rlimits only (ADR-007).

PID 1 then mounts the sandbox proc view (/proc with hidepid=2 - only PID
1 can mount a procfs showing the sandbox's own processes) and runs the
workload inside the new root; a failed or unverifiable boundary aborts
BEFORE the workload fn runs (fail closed).

The supervisor NEVER enters the namespaces or the new root: it must keep
its host view (cleanup, audit, timeout - later steps). The NAMESPACES,
FILESYSTEM, NETWORK and PRIVILEGES stage guards therefore probe the real
path in forked children and report a StageCheck back; a failed or
unverifiable probe is a refusal, never a skip.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass

from agent_sandbox.config import ResourceLimits
from agent_sandbox.isolation import filesystem as fs_mod
from agent_sandbox.isolation import namespaces, network as net_mod, privileges as priv_mod, resources as resources_mod, rootfs, seccomp as seccomp_mod, syscalls, userns
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage, SecurityMode, StageCheck

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


def run_in_sandbox(fn, rootfs_state=None, disk_mb: int = 10240,
                   limits: ResourceLimits | None = None) -> SandboxRun:
    """Run ``fn`` inside the full sandbox boundary.

    Namespaces only (Step 2): ``fn(state)`` - state is the verified
    NamespaceState.
    With a rootfs (Step 3): the filesystem boundary is established too
    (private propagation, bind rootfs, tmpfs /tmp, pivot_root, old-root
    detach, verification) and ``fn(state, fs)`` is called with the
    verified FilesystemState. fn may return a str, captured as ``output``.
    With ``limits`` (Step 9): PID 1 lowers + verifies the six mandated
    rlimits AFTER the seccomp install and BEFORE the workload fn
    (prlimit64 is allowlisted - no filter change needed).

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
            # Step 8: build the seccomp program host-side BEFORE entering
            # the boundary - the allowlist artifact is not reachable
            # inside the pivoted rootfs; the tuple is inherited into PID 1.
            program = seccomp_mod.build_program()
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
            # PID 1 mounts + verifies the sandbox proc view FIRST (/proc
            # with hidepid=2 - a procfs mount shows the PID namespace of
            # the process that mounts it, so only PID 1 can show the
            # sandbox's own processes; in the rootfs path /proc is not
            # mounted in the new root until this point, and the network
            # state verification reads /proc/self/net/*), then verifies
            # the network deny-by-construction state. Any failure =
            # refusal (never a silent continue on a partial boundary).
            try:
                if fs_state is not None:
                    _mount_and_verify_proc()
                net_mod.verify_deny_by_construction(
                    state.host_ns.get("net", ""))
                # Step 6: no_new_privs established + kernel-state read-back
                # verified BEFORE the workload fn. Step 7: capability
                # reduction (full bounding-set drop + cleared sets) after
                # no_new_privs, verified by read-back. Step 8: the derived
                # 45-syscall default-deny seccomp filter is installed LAST
                # and verified (Seccomp=2 read-back + socket->EPERM spot
                # check). The workload cannot execute on an unverified
                # privilege/syscall state (fail closed).
                priv_mod.establish_and_verify()
                priv_mod.reduce_and_verify()
                seccomp_mod.establish_and_verify(program)
                if limits is not None:
                    resources_mod.establish_and_verify_rlimits(limits)
            except BaseException as e:  # noqa: BLE001
                print(f"FAIL setup: {type(e).__name__}: {e}", file=sys.stderr)
                sys.stderr.flush()
                os._exit(1)
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


def _mount_and_verify_proc() -> None:
    """PID-1-side: mount procfs (hidepid=2) and verify the sandbox proc
    view. Raises NamespaceSetupError on verification failure - the caller
    (run_in_sandbox PID 1) reports it and refuses; never a silent
    continue with a partially configured filesystem."""
    problems = fs_mod.mount_sandbox_proc()
    if problems:
        raise NamespaceSetupError(
            "proc/dev/sys boundary verification failed: " + "; ".join(problems))


def _fs_pid1_verification(state: NamespaceState,
                          fs: fs_mod.FilesystemState) -> str:
    """PID-1-side verification of the filesystem boundary (runs inside the
    new root, after the sandbox proc view is mounted). Returns "OK" or
    "FAIL <detail>" - never a silent pass."""
    problems: list[str] = []
    try:
        problems.extend(fs_mod.mount_sandbox_proc())
    except BaseException as e:  # noqa: BLE001 - mount failure is a refusal
        problems.append(f"proc mount failed: {type(e).__name__}: {e}")
    cur = os.stat("/")
    if (cur.st_dev, cur.st_ino) != fs.root_identity:
        problems.append(
            f"root identity mismatch in PID 1: / is {(cur.st_dev, cur.st_ino)}")
    if os.getcwd() != "/":
        problems.append(f"cwd is {os.getcwd()!r}, expected /")
    if not os.path.isdir("/workspace"):
        problems.append("/workspace missing in PID 1")
    hits = fs_mod._probe_absent(fs_mod.HOST_ABSENT_PATHS)
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
                   "detach + private mount propagation + /proc (hidepid=2) "
                   "+ minimal /dev established and verified in a real forked "
                   "child")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"filesystem probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _filesystem_guard(config) -> StageCheck:
    """FILESYSTEM stage guard (registered below). Probes the real rootfs
    boundary; HARDENED/RESTRICTED refuse unless it is established and
    verified."""
    return filesystem_probe(config)


def network_probe(config) -> StageCheck:
    """Real-path probe of the NETWORK deny-by-construction state (netns
    created in Step 2, configured + verified here), run in a forked child
    so the supervisor never enters the boundary. This is the NETWORK
    stage guard's evidence."""
    return _network_probe_impl(config)


def _network_probe_impl(config) -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="network probe requires Linux with os.fork (fail closed "
                   "- the netns boundary cannot be established here)")
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            state = enter_all_namespaces()
            net_mod.ensure_loopback_down()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        grand = os.fork()
        if grand == 0:
            # PID 1: verify the deny-by-construction state from inside the
            # sandbox netns and report the verdict (the only verdict writer).
            try:
                net_mod.verify_deny_by_construction(
                    state.host_ns.get("net", ""))
                os.write(write_fd, b"OK")
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
    msg = data.decode(errors="replace").strip()
    if msg == "OK":
        return StageCheck(
            ok=True,
            reason="network namespace deny-by-construction state established "
                   "and verified (only loopback, lo DOWN, no addresses, no "
                   "usable routes, distinct from host netns)")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"network probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _network_guard(config) -> StageCheck:
    """NETWORK stage guard (registered below). Probes the real netns
    deny-by-construction state; HARDENED/RESTRICTED refuse unless it is
    established and verified."""
    return network_probe(config)


def privileges_probe(config) -> StageCheck:
    """Real-path probe of the PRIVILEGES mechanism (no_new_privs
    established and the kernel-state read-back verified in PID 1 of a
    forked child, so the supervisor never enters the boundary). This is
    the PRIVILEGES stage guard's evidence."""
    return _privileges_probe_impl(config)


def _privileges_probe_impl(config) -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="privileges probe requires Linux with os.fork (fail "
                   "closed - no_new_privs cannot be established here)")
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
            # PID 1: establish no_new_privs, then perform the capability
            # reduction (full bounding-set drop + cleared sets) and verify
            # both kernel-state read-backs from inside the sandbox; report
            # the verdict (the only verdict writer).
            try:
                priv_mod.establish_and_verify()
                priv_mod.reduce_and_verify()
                os.write(write_fd, b"OK")
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
    msg = data.decode(errors="replace").strip()
    if msg == "OK":
        return StageCheck(
            ok=True,
            reason="no_new_privs established and kernel-state read-back "
                   "verified (PR_GET_NO_NEW_PRIVS == 1); full capability "
                   "bounding-set drop + cleared effective/permitted/"
                   "inheritable/ambient sets verified (CapBnd/CapEff/"
                   "CapPrm/CapInh/CapAmb all zero) in PID 1 of a real "
                   "forked child")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"privileges probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _privileges_guard(config) -> StageCheck:
    """PRIVILEGES stage guard (registered below). Probes the real
    no_new_privs + capability-reduction path; HARDENED/RESTRICTED refuse
    unless it is established and verified."""
    return privileges_probe(config)


def seccomp_probe(config) -> StageCheck:
    """Real-path probe of the SECCOMP mechanism (the derived 45-syscall
    default-deny filter built host-side, installed in PID 1 after
    no_new_privs + capability reduction, kernel-state read-back + socket
    EPERM spot check), run in a forked child so the supervisor never
    enters the boundary. This is the SECCOMP stage guard's evidence."""
    return _seccomp_probe_impl(config)


def _seccomp_probe_impl(config) -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="seccomp probe requires Linux with os.fork (fail "
                   "closed - the filter cannot be installed here)")
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            program = seccomp_mod.build_program()
            state = enter_all_namespaces()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        grand = os.fork()
        if grand == 0:
            # PID 1: no_new_privs -> capability reduction -> seccomp
            # install + read-back + enforcement spot check; report the
            # verdict (the only verdict writer).
            try:
                priv_mod.establish_and_verify()
                priv_mod.reduce_and_verify()
                seccomp_mod.establish_and_verify(program)
                os.write(write_fd, b"OK")
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
    msg = data.decode(errors="replace").strip()
    if msg == "OK":
        return StageCheck(
            ok=True,
            reason="derived 45-syscall default-deny seccomp filter built "
                   "from allowlist.json, installed LAST in PID 1 after "
                   "no_new_privs + capability reduction, kernel-state "
                   "read-back verified (Seccomp mode = SECCOMP_MODE_FILTER, "
                   "filter active) and forbidden socket syscall denied "
                   "with EPERM")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"seccomp probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _seccomp_guard(config) -> StageCheck:
    """SECCOMP stage guard (registered below). Probes the real filter
    path; HARDENED/RESTRICTED refuse unless the filter is installed and
    verified."""
    return seccomp_probe(config)


def resources_probe(config) -> StageCheck:
    """Real-path probe of the RESOURCES mechanism (the six mandated
    rlimits lowered + kernel-state read-back verified in PID 1 after
    no_new_privs + capability reduction + seccomp install), run in a
    forked child so the supervisor never enters the boundary.

    RESOURCES-stage shape (ADR-007): rlimits are the always-applied half
    of the RESOURCES stage. HARDENED additionally mandates cgroup v2
    delegation (Step 10) - until that half is implemented, the probe
    establishes the rlimits (proving the mechanism works) and then
    refuses AT RESOURCES, so the refusal point does not advance beyond
    RESOURCES while the stage is incomplete. RESTRICTED (rlimits only,
    ADR-007) completes its RESOURCES stage here."""
    return _resources_probe_impl(config)


def _resources_probe_impl(config) -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="resources probe requires Linux with os.fork (fail "
                   "closed - rlimits cannot be established here)")
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            program = seccomp_mod.build_program()
            state = enter_all_namespaces()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        grand = os.fork()
        if grand == 0:
            # PID 1: no_new_privs -> capability reduction -> seccomp
            # install -> rlimits lower + read-back; then the verdict
            # depends on the mode (ADR-007): HARDENED refuses AT RESOURCES
            # (cgroup v2 half is Step 10), RESTRICTED is complete with
            # rlimits only. Report the verdict (the only verdict writer).
            try:
                priv_mod.establish_and_verify()
                priv_mod.reduce_and_verify()
                seccomp_mod.establish_and_verify(program)
                resources_mod.establish_and_verify_rlimits(config.resources)
                if config.mode is SecurityMode.HARDENED:
                    os.write(write_fd, b"FAIL cgroup v2 (the HARDENED-"
                                      b"mandatory half of the RESOURCES "
                                      b"stage, ADR-007) is not yet "
                                      b"implemented (Step 15 of the mandated "
                                      b"order) - RESOURCES incomplete, fail "
                                      b"closed, workload not executed")
                else:
                    os.write(write_fd, b"OK")
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
    msg = data.decode(errors="replace").strip()
    if msg == "OK":
        return StageCheck(
            ok=True,
            reason="rlimits established and kernel-state read-back verified "
                   "(RLIMIT_CPU/AS/NPROC/NOFILE/FSIZE/CORE=0, soft == hard) "
                   "after the seccomp install in PID 1 of a real forked "
                   "child; RESTRICTED resource stage complete (rlimits "
                   "only, ADR-007)")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"resources probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _resources_guard(config) -> StageCheck:
    """RESOURCES stage guard (registered below). Probes the real rlimit
    path (and the HARDENED cgroup-v2 requirement); HARDENED/RESTRICTED
    refuse unless the mechanism is established and verified, and HARDENED
    additionally refuses while the cgroup half of the stage is
    unimplemented (the refusal point stays AT RESOURCES)."""
    return resources_probe(config)


# Register the guards with the enforcement core. This module is imported
# lazily by SecurityInitializer (and directly by tests), so the registry
# sees each mechanism exactly when it exists - never before.
_security_init.register_stage_guard(InitStage.NAMESPACES, _namespaces_guard)
_security_init.register_stage_guard(InitStage.FILESYSTEM, _filesystem_guard)
_security_init.register_stage_guard(InitStage.NETWORK, _network_guard)
_security_init.register_stage_guard(InitStage.PRIVILEGES, _privileges_guard)
_security_init.register_stage_guard(InitStage.SECCOMP, _seccomp_guard)
_security_init.register_stage_guard(InitStage.RESOURCES, _resources_guard)
