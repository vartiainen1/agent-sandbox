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
change) and BEFORE the workload fn (resources.py).

Step 10 (cgroup v2, ADR-007 READING A, S-012/S-027/S-014): for HARDENED,
the supervisor prepares the session cgroup HOST-SIDE in the delegated
subtree before entering the boundary - cgroup v2 identity, the four
required controllers (pids/memory/cpu/io), writable-subtree probe,
session creation, io.max backing-device resolution (kernel state, never
guessed), all four limits written + read-back verified - and the
SUPERVISOR then joins sandbox PID 1 into it AFTER the rlimits (host-side
cgroup.procs migration + membership + limit re-verification). PID 1
cannot reach the cgroupfs itself (the rootfs has no /sys by design,
ADR-005); the supervisor-side join also guarantees the workload never
touches the cgroupfs and cannot alter its own limits. Delegation
unavailable, a missing controller, an
unresolvable io device, or any establishment/verification failure makes
HARDENED REFUSE AT RESOURCES with the precise reason - never a partial
success (RESTRICTED completes its RESOURCES stage with rlimits only,
ADR-007, and advances to ENVIRONMENT).

Step 11 (environment sanitization, S-034, ADR-009): PID 1 constructs the
approved six-variable sandbox environment (PATH/HOME/TMPDIR/LANG/LC_ALL/
TERM - the host environment is NEVER inherited), replaces the process
environment and verifies the LIVE environment (exactly the allowlisted
variables with exactly the approved values, no host variable present)
after the cgroup join and BEFORE the workload fn (environment.py). The
ENVIRONMENT stage registers; HARDENED/RESTRICTED advance past it to
EXECUTION (Steps 13-15).

Step 12 (credential/socket isolation, S-003/S-004, ADR-009): from the
WORKLOAD view (rootfs path only) no host credential/control-socket path
is reachable, no socket/credential env variable survived sanitization,
and Unix-socket creation is DENIED by the installed filter. Any exposure
refuses before the workload fn (credentials.py). Completes the
ENVIRONMENT stage (Steps 16-17).

Step 13 (bounded output, S-037, item 18): the supervisor reads
stdout/stderr through a bounded pipe; past the limit it terminates the
session with a truncation notice (output.py).

Step 14 (external timeout, S-036, ADR-011, item 19): the supervisor
enforces an external wall-clock deadline (wall_time_seconds - the
validated ResourceLimits policy, default 900) while collecting the
bounded output: each wait is bounded by the remaining time (select +
time.monotonic, both supervisor-side), and on expiry the supervisor
terminates the session and marks SandboxRun.timed_out with a timeout
notice (timeout.py). The deadline lives entirely in the supervisor - the
workload cannot disable, evade, or reset it (no shared clock, no caps,
no channel).

Step 15 (process-tree containment and cleanup, S-014/S-038, ADR-011,
item 20): the supervisor is a CHILD SUBREAPER (PR_SET_CHILD_SUBREAPER,
verified by kernel-state read-back), termination targets SANDBOX PID 1
- the namespace init, so the kernel terminates the WHOLE workload tree
(vfork/exec descendants included) - plus cgroup.kill where delegated,
and after EVERY run path (normal completion, truncation, timeout) the
supervisor performs MANDATORY absence verification (S-038: no workload
process may remain; a survivor is a recorded cleanup failure in
SandboxRun.cleanup_failure, never a silent success) (lifecycle.py).
Killing only the immediate child is forbidden (ADR-011). Completes the
EXECUTION stage (items 18-21: bounded output, timeout, process-tree
containment, cleanup verification) - the EXECUTION guard registers
below and the isolated modes initialize to READY when every mechanism
is established.

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

from agent_sandbox.config import DEFAULT_ENV_ALLOWLIST, ResourceLimits
from agent_sandbox.isolation import cgroups as cgroups_mod
from agent_sandbox.isolation import credentials as cred_mod
from agent_sandbox.isolation import environment as env_mod
from agent_sandbox.isolation import filesystem as fs_mod
from agent_sandbox.isolation import lifecycle as lifecycle_mod
from agent_sandbox.isolation import output as output_mod
from agent_sandbox.isolation import timeout as timeout_mod
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
    truncated: bool = False  # S-037: True iff the output bound was hit
                              # and the session terminated with a notice
    timed_out: bool = False  # S-036: True iff the external wall-clock
                             # deadline expired and the supervisor
                             # terminated the session
    cleanup_failure: str = ""  # S-038: non-empty iff post-termination
                               # absence verification found a surviving
                               # workload process - never reported as
                               # successful (S-024)


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


def _toolchain_dir() -> str | None:
    """The curated toolchain artifact path (ADR-005 read-only system
    layers) from the AGENT_SANDBOX_TOOLCHAIN env var; None = no system
    layers (the empty-placeholder rootfs). Read HOST-side only - the
    sandbox environment is sanitized independently and the workload
    never sees this variable. A configured-but-invalid path is a
    refusal in the filesystem stage (deterministic - never a silent
    partial toolchain)."""
    return os.environ.get("AGENT_SANDBOX_TOOLCHAIN")


def _sync_wait(fd: int, what: str) -> bool:
    """Wait for a single status byte on a one-directional sync pipe (the
    caller is the SOLE reader; b'1' = success, b'0' or EOF = failure).
    Returns True only on b'1' - everything else fails closed. The pipe
    wiring guarantees no hang: the peer is the sole writer, so its exit
    (any path) delivers EOF."""
    try:
        data = os.read(fd, 1)
    except OSError:
        return False
    return data == b"1"


def _flush_io_before_fork() -> None:
    """Flush the supervisor's buffered stdout/stderr immediately before
    every fork. WITHOUT this, the sandbox child inherits the pre-fork
    stdio buffer across fork; when the workload later prints, the
    inherited buffer (e.g. a server's or test runner's buffered output)
    flushes into the workload's CAPTURED output pipe - supervisor output
    leaking into sandbox workload output (fork-inherited stdio buffer
    pollution, empirically isolated on Ubuntu 24.04/kernel 6.8). Flushing
    here guarantees the child inherits a clean buffer; output semantics
    beyond removing inherited pre-fork buffers are unchanged. Flush
    failures (e.g. closed stream) must never abort the run."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass


def run_in_sandbox(fn, rootfs_state=None, disk_mb: int = 10240,
                   limits: ResourceLimits | None = None,
                   cgroup_session=None,
                   env_allowlist: tuple[str, ...] | None = None,
                   output_mb: int | None = None,
                   wall_time_seconds: int | None = None
                   ) -> SandboxRun:
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
    With ``cgroup_session`` (Step 10, HARDENED): a session cgroup prepared
    host-side by the supervisor in the delegated subtree; the SUPERVISOR
    joins sandbox PID 1 into it (host-side cgroup.procs migration) and
    verifies membership + all four limit read-backs - before releasing
    PID 1 via the go pipe, so the workload fn never runs before the join.
    PID 1 cannot reach the cgroupfs (the rootfs has no /sys by design,
    ADR-005); the supervisor-side join also guarantees the workload never
    touches the cgroupfs and cannot alter its own limits.
    With ``env_allowlist`` (Step 11): PID 1 constructs the approved
    six-variable sandbox environment (PATH/HOME/TMPDIR/LANG/LC_ALL/TERM -
    host env NEVER inherited, S-034) after the cgroup join and verifies
    the live environment (exactly the allowlisted variables with exactly
    the approved values) BEFORE the workload fn.
    With ``output_mb`` (Step 13): the supervisor reads stdout/stderr
    through a bounded pipe (S-037); past the limit it terminates the
    session and marks ``SandboxRun.truncated`` (a truncation notice is
    appended to the output). The bound cannot be bypassed by the
    workload - the pipe is the only output channel, and the kernel
    enforces it (EPIPE/SIGPIPE once the read end is closed).
    With ``wall_time_seconds`` (Step 14): the supervisor enforces an
    external wall-clock deadline (S-036) - each wait for output is
    bounded by the remaining time; on expiry it terminates the session
    and marks ``SandboxRun.timed_out`` (a timeout notice is appended).
    The deadline lives entirely in the supervisor process - the
    workload cannot disable, evade, or reset it (no shared clock, no
    caps, no channel).

    With ``cgroup_session`` (Step 15): the supervisor is a child
    subreaper (S-014) and, on termination, kills the SANDBOX PID 1 (the
    namespace init - kernel then kills the whole namespace) plus
    cgroup.kill where delegated, then verifies absence (S-038): no
    workload process may remain. Killing only the immediate child is
    forbidden (ADR-011).

    The supervisor stays outside; the kernel enforces the boundary for
    fn's whole process tree. Any boundary failure aborts BEFORE fn runs
    (fail closed - fn never executes on a partial boundary)."""
    # Step 15 (S-014): the supervisor becomes a child subreaper so
    # orphaned workload descendants reparent to it, not to init - the
    # precondition for reliable process-tree cleanup. Verified by
    # kernel-state read-back (PR_GET_CHILD_SUBREAPER == 1); failure
    # refuses (containment cannot be guaranteed).
    lifecycle_mod.establish_subreaper()
    out_r, out_w = os.pipe()
    # Control pipe: child A reports sandbox PID 1 (the grandchild that
    # becomes the namespace init) so the supervisor can terminate the
    # WHOLE workload tree - never just the immediate child (S-014).
    ctl_r, ctl_w = os.pipe()
    # One-directional sync pipes for the pre-pivot /proc handshake: PID 1
    # mounts the rootfs /proc BEFORE the setup child pivots (the only
    # ordering that works inside a user namespace on mainline kernels - a
    # procfs mount attempted after pivot_root + detach fails with EPERM),
    # signals completion, waits for the pivot, then verifies the live
    # /proc. Each side is the SOLE writer of its pipe (grand -> ack,
    # child A -> pivot), so a peer exit delivers EOF and can never hang.
    # The curated toolchain artifact (ADR-005), resolved host-side before
    # any fork so child A and PID 1 inherit it for mounting/verification.
    toolchain = _toolchain_dir()
    mount_ack_r, mount_ack_w = os.pipe()
    pivot_done_r, pivot_done_w = os.pipe()
    # Go pipe (HARDENED cgroup join): the supervisor signals sandbox PID 1
    # that the host-side session-cgroup join completed and was verified,
    # so the workload fn never runs before the cgroup stage. Wiring:
    # supervisor -> grand (through child A); grand is the SOLE reader and
    # the supervisor the SOLE writer (child A and grand close their write
    # copies), so a supervisor exit is EOF to grand's wait.
    go_r, go_w = os.pipe()
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        # Child A: enters the namespaces, establishes the filesystem
        # mounts (if a rootfs is given), then forks so its child becomes
        # PID 1 of the new PID namespace (documented PID semantics). The
        # pivot + old-root detach happen AFTER PID 1 has mounted the
        # rootfs /proc (see the grand comment).
        os.close(out_r)
        os.close(ctl_r)
        try:
            # Step 8: build the seccomp program host-side BEFORE entering
            # the boundary - the allowlist artifact is not reachable
            # inside the pivoted rootfs; the tuple is inherited into PID 1.
            program = seccomp_mod.build_program()
            state = enter_all_namespaces()
            if rootfs_state is not None:
                fs_mod.prepare_rootfs(rootfs_state, disk_mb, toolchain)
        except BaseException as e:  # noqa: BLE001 - report, don't propagate across fork
            os.write(out_w, f"FAIL setup: {type(e).__name__}: {e}\n".encode())
            os._exit(1)
        _flush_io_before_fork()
        grand = os.fork()
        if grand != 0:
            # Child A reads the proc-mount ack and writes the pivot-done
            # ack, and never uses the go pipe. Close the ends grand owns
            # ONLY in child A (grand must keep its live copies of the ends
            # it writes/reads, and its own branch closes the ends it does
            # not use), so grand's exit is EOF to these reads.
            os.close(mount_ack_w)
            os.close(pivot_done_r)
            os.close(go_r)
            os.close(go_w)
            # Report sandbox PID 1 to the supervisor at the EARLIEST safe
            # point (right after the fork, before the pivot): the HARDENED
            # supervisor joins it into the session cgroup host-side before
            # any workload code can run, and the termination target is
            # available earlier for the timeout path. The pid is child A's
            # view of grand = the HOST pid of sandbox PID 1.
            os.write(ctl_w, str(grand).encode())
            os.close(ctl_w)
        if grand == 0:
            # Child B: PID 1 in the new PID namespace - runs the workload fn.
            os.dup2(out_w, 1)
            os.dup2(out_w, 2)
            os.close(out_w)
            # Child B inherits ctl_w from child A (child A closed ctl_r
            # BEFORE forking grand, so ctl_r was never inherited here).
            os.close(ctl_w)
            # Child B owns the proc-mount ack (write) and the pivot-done
            # wait (read); close the ends child A owns so child A's exit
            # is EOF to the pivot wait.
            os.close(mount_ack_r)
            os.close(pivot_done_w)
            os.close(go_w)
            # PID 1 mounts + verifies the sandbox proc view at the rootfs
            # /proc BEFORE the setup child pivots (/proc with hidepid=2 -
            # a procfs mount shows the PID namespace of the process that
            # mounts it, so only PID 1 can show the sandbox's own
            # processes). This ordering is REQUIRED on mainline kernels:
            # a procfs mount attempted AFTER pivot_root + old-root detach
            # inside a user namespace fails with EPERM (verified on
            # Ubuntu 24.04/kernel 6.8; the WSL2 kernel behind the Docker
            # evidence tolerated the post-pivot mount). The pre-pivot
            # mount survives the pivot and becomes the live /proc, which
            # is then verified (plus the network deny-by-construction
            # state, which reads /proc/self/net/*). Any failure = refusal
            # (never a silent continue on a partial boundary) and is
            # signaled to the setup child.
            # The mount-ack / pivot-done handshake exists ONLY for the
            # pre-pivot proc mount (rootfs mode). In namespaces-only mode
            # (rootfs_state is None) there is no proc mount and no pivot,
            # and child A never reads mount_ack_r nor writes
            # pivot_done_w - so PID 1 must not touch either pipe here or
            # its write hits a closed read end (BrokenPipeError) and its
            # pivot wait hangs on an EOF that never comes as a b'1'
            # (both would refuse a perfectly valid namespaces-only run).
            if rootfs_state is not None:
                try:
                    problems = fs_mod.mount_sandbox_proc_prepivot()
                    if problems:
                        raise NamespaceSetupError(
                            "proc boundary pre-pivot verification failed: "
                            + "; ".join(problems))
                    os.write(mount_ack_w, b"1")
                except BaseException as e:  # noqa: BLE001
                    print(f"FAIL setup: {type(e).__name__}: {e}",
                          file=sys.stderr)
                    sys.stderr.flush()
                    try:
                        os.write(mount_ack_w, b"0")
                    except OSError:
                        pass
                    os._exit(1)
                if not _sync_wait(pivot_done_r, "pivot"):
                    print("FAIL setup: pivot_root + old-root detach did not "
                          "complete", file=sys.stderr)
                    sys.stderr.flush()
                    os._exit(1)
            os.chdir("/")
            os.close(mount_ack_w)
            os.close(pivot_done_r)
            try:
                # Post-pivot (live /proc): the root boundary verification
                # (root identity, cwd, /workspace, /tmp tmpfs, /dev
                # inventory, host paths absent) and the sandbox proc view
                # verification (procfs at /proc with hidepid=2 + flags,
                # only PID 1 visible, /dev unchanged, /sys absent), then
                # the network deny-by-construction state. Any failure =
                # refusal (never a silent continue on a partial boundary).
                fs_state = None
                if rootfs_state is not None:
                    fs_state = fs_mod._verify_root_boundary(
                        rootfs_state, toolchain)
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
                if cgroup_session is not None:
                    # The HARDENED session-cgroup join is done by the
                    # SUPERVISOR host-side (the rootfs has no /sys by
                    # design, ADR-005, so PID 1 cannot reach the cgroupfs;
                    # see the supervisor side below). Wait for the go
                    # signal: the workload fn must NEVER run before the
                    # join + limit verification completed. Fail closed if
                    # it never arrives (EOF or b'0').
                    if not _sync_wait(go_r, "cgroup join"):
                        raise NamespaceSetupError(
                            "cgroup join did not complete (no supervisor "
                            "go signal) - fail closed, workload not executed")
                    os.close(go_r)
                # Step 11: sanitize the environment in PID 1 AFTER the
                # resource stage and BEFORE the workload fn - construct
                # the approved six variables (host env never inherited,
                # S-034), replace the process environment, then read the
                # LIVE environment back and require exactly the
                # allowlisted variables with the approved values. Any
                # failure refuses (workload never executes on a partial
                # environment).
                env_mod.sanitize_and_verify(env_allowlist)
                # Step 12: verify credential/socket isolation from the
                # WORKLOAD view (rootfs path only - the boundary that
                # makes host credentials/control sockets absent by
                # construction, S-003/S-004): no credential or
                # control-socket path may be reachable, no
                # socket/credential env variable may have survived, and
                # Unix-socket creation must be DENIED by the installed
                # filter (socket class not in the 45-syscall allowlist).
                # Any exposure refuses before the workload fn.
                if fs_state is not None:
                    cred_mod.verify_credential_isolation(
                        require_socket_denial=True)
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
        # Child A: wait for PID 1's pre-pivot proc mount, complete the
        # pivot + old-root detach, signal PID 1, then wait for it and
        # exit with its status (sandbox PID 1 was reported to the
        # supervisor right after the fork, above).
        if rootfs_state is not None:
            if not _sync_wait(mount_ack_r, "proc mount"):
                os.write(out_w, b"FAIL setup: proc mount did not complete\n")
                os._exit(1)
            try:
                fs_mod.pivot_and_detach()
            except BaseException as e:  # noqa: BLE001
                os.write(out_w,
                         f"FAIL setup: {type(e).__name__}: {e}\n".encode())
                try:
                    os.write(pivot_done_w, b"0")
                except OSError:
                    pass
                os._exit(1)
            os.write(pivot_done_w, b"1")
        os.close(mount_ack_r)
        os.close(pivot_done_w)
        # The sandbox PID 1 was reported to the supervisor right after the
        # fork (above); now wait for it and exit with its status.
        _, status = os.waitpid(grand, 0)
        os._exit(os.waitstatus_to_exitcode(status))

    # Supervisor side: learn sandbox PID 1 (the namespace init - the
    # whole workload tree), collect output, reap, verify absence. The
    # sync pipes are private to the children - close the supervisor's
    # copies.
    os.close(out_w)
    os.close(ctl_w)
    os.close(mount_ack_r)
    os.close(mount_ack_w)
    os.close(pivot_done_r)
    os.close(pivot_done_w)
    os.close(go_r)
    try:
        raw = os.read(ctl_r, 64)
    finally:
        os.close(ctl_r)
    try:
        sandbox_pid1 = int(raw.strip().split()[0])
    except (ValueError, IndexError):
        sandbox_pid1 = -1  # child A died before reporting - fail closed
    # HARDENED (S-012/S-027, ADR-007): the supervisor joins sandbox PID 1
    # into the session cgroup HOST-SIDE, BEFORE the workload fn may run.
    # The sandbox rootfs has no /sys by design (ADR-005), so PID 1 cannot
    # reach the cgroupfs itself; the supervisor legitimately owns the
    # delegated subtree (ADR-002: cgroup config inside a delegated subtree
    # is filesystem-permission work). This also means the workload NEVER
    # touches the cgroupfs and cannot alter its own limits. Fail-closed:
    # any join/verification failure terminates the sandbox tree and
    # refuses the run. On success, the go signal releases sandbox PID 1
    # to run the workload.
    if cgroup_session is not None:
        join_kill_target = sandbox_pid1 if sandbox_pid1 >= 1 else pid
        try:
            if sandbox_pid1 < 1:
                raise NamespaceSetupError(
                    "cgroup join impossible: sandbox PID 1 unknown (the "
                    "setup child died before reporting it) - fail closed, "
                    "workload not executed")
            cgroups_mod.join_and_verify(cgroup_session, sandbox_pid1)
        except BaseException as e:  # noqa: BLE001 - fail closed
            try:
                lifecycle_mod.terminate_tree(join_kill_target,
                                             cgroup_session, grace=0.0)
            except Exception:  # noqa: BLE001 - best-effort during refusal
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            raise NamespaceSetupError(
                f"cgroup join failed: {e} - session terminated, fail "
                "closed, workload not executed")
        os.write(go_w, b"1")
        os.close(go_w)
    else:
        os.close(go_w)
    # S-037 (Step 13) + S-036 (Step 14): bounded read with an external
    # wall-clock deadline. On truncation OR timeout the supervisor
    # terminates the session (closes the read end + kills the SANDBOX
    # PID 1 - the namespace init, so the kernel kills the WHOLE workload
    # tree, S-014). Further workload writes fail with EPIPE/SIGPIPE. The
    # workload cannot bypass the bound or the deadline: the pipe is the
    # only channel, and the deadline lives only in this supervisor
    # process. The output read end (out_r) is closed in a finally on
    # EVERY path (success, truncation, timeout, exceptional) - a leaked
    # read end would accumulate descriptors across repeated execute()
    # calls in a long-lived supervisor.
    try:
        bound = output_mb if output_mb is not None else (
            limits.output_mb if limits is not None else None)
        if bound is None:
            # Namespace-only test seam (no resource stage): unbounded read.
            output = b""
            while True:
                chunk = os.read(out_r, 65536)
                if not chunk:
                    break
                output += chunk
            _, status = os.waitpid(pid, 0)
            return _finish_run(status, output.decode(errors="replace"),
                               sandbox_pid1, cgroup_session)
        wall = wall_time_seconds if wall_time_seconds is not None else (
            limits.wall_time_seconds if limits is not None else None)
        limit_bytes = bound * output_mod.MIB
        # Step 15: the termination target is SANDBOX PID 1 (the namespace
        # init), never the immediate child - killing the init makes the
        # kernel terminate the entire namespace (S-014, ADR-011).
        kill_target = sandbox_pid1 if sandbox_pid1 >= 1 else pid
        if wall is None:
            # Bound-only call (Step 13 test seam): no deadline configured.
            data, truncated = output_mod.collect_bounded(
                out_r, kill_target, limit_bytes)
            _, status = os.waitpid(pid, 0)
            text = data.decode(errors="replace")
            if truncated:
                text += output_mod.truncation_notice(bound)
            return _finish_run(status, text, sandbox_pid1, cgroup_session,
                               truncated=truncated)
        data, truncated, timed_out = timeout_mod.collect_session_output(
            out_r, kill_target, limit_bytes, wall)
        _, status = os.waitpid(pid, 0)
        text = data.decode(errors="replace")
        if truncated:
            text += output_mod.truncation_notice(bound)
        if timed_out:
            text += timeout_mod.timeout_notice(wall)
        return _finish_run(status, text, sandbox_pid1, cgroup_session,
                           truncated=truncated, timed_out=timed_out)
    finally:
        # On the truncation/timeout paths the collection already closed
        # the read end (the termination sequence closes it to force
        # EPIPE/SIGPIPE on the workload); tolerate that - the guarantee
        # is that out_r is closed on EVERY path, not closed exactly once.
        try:
            os.close(out_r)
        except OSError:
            pass


def _finish_run(status: int, text: str, sandbox_pid1: int,
                cgroup_session, truncated: bool = False,
                timed_out: bool = False) -> SandboxRun:
    """Supervisor-side completion of every run path (S-014, S-038):

    1. When the session was terminated (truncation/timeout) or the
       workload exited leaving the namespace, the supervisor VERIFIES
       from kernel-visible state that no workload process remains - the
       sandbox PID namespace must have no member processes and, where
       delegated, the session cgroup.procs must be empty.
    2. A surviving workload process is a CLEANUP FAILURE (S-038) -
       detected, recorded, and reported in ``SandboxRun.cleanup_failure``;
       never reported as a successful cleanup (S-024).

    The namespace-init kill already happened in the collection path (or
    the workload exited normally - PID 1 exit also terminates the
    namespace); this is the mandatory absence verification on top.
    """
    cleanup_failure = ""
    if sandbox_pid1 >= 1:
        # Belt-and-braces: cgroup.kill where delegated (kills every
        # process in the cgroup regardless of parentage, ADR-011).
        lifecycle_mod.terminate_tree(sandbox_pid1, cgroup_session,
                                     grace=0.0)
        survivors, reason = lifecycle_mod.verify_no_workload_remains(
            sandbox_pid1, cgroup_session)
        if survivors or reason:
            cleanup_failure = reason or (
                "cleanup incomplete: workload process(es) survive after "
                "termination - S-038, never reported as successful")
    return SandboxRun(exit_code=os.waitstatus_to_exitcode(status),
                      output=text, truncated=truncated,
                      timed_out=timed_out, cleanup_failure=cleanup_failure)


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
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            state = enter_all_namespaces()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        _flush_io_before_fork()
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
    """PID-1-side POST-pivot verification of the sandbox proc view (the
    procfs was mounted pre-pivot by ``mount_sandbox_proc_prepivot``; this
    verifies the live /proc). Raises NamespaceSetupError on verification
    failure - the caller (run_in_sandbox PID 1) reports it and refuses;
    never a silent continue with a partially configured filesystem."""
    problems = fs_mod.verify_sandbox_proc()
    if problems:
        raise NamespaceSetupError(
            "proc/dev/sys boundary verification failed: " + "; ".join(problems))


def _fs_pid1_verification(state: NamespaceState,
                          fs: fs_mod.FilesystemState) -> str:
    """PID-1-side verification of the filesystem boundary (runs inside the
    new root, after the pre-pivot-mounted sandbox proc view is live).
    Returns "OK" or "FAIL <detail>" - never a silent pass."""
    problems: list[str] = []
    try:
        problems.extend(fs_mod.verify_sandbox_proc())
    except BaseException as e:  # noqa: BLE001 - verification failure is a refusal
        problems.append(f"proc view verification failed: {type(e).__name__}: {e}")
    cur = os.stat("/")
    if (cur.st_dev, cur.st_ino) != fs.root_identity:
        problems.append(
            f"root identity mismatch in PID 1: / is {(cur.st_dev, cur.st_ino)}")
    if os.getcwd() != "/":
        problems.append(f"cwd is {os.getcwd()!r}, expected /")
    if not os.path.isdir("/workspace"):
        problems.append("/workspace missing in PID 1")
    # With the curated toolchain, /etc/passwd is PROVIDED as the minimal
    # SANITIZED file (root + nobody only - NSS requires it); its absence
    # check is replaced by the verified-content check inside
    # _verify_root_boundary (toolchain-aware). Without a toolchain the
    # file must not exist, exactly as before.
    absent_paths = fs_mod.HOST_ABSENT_PATHS
    if _toolchain_dir() is not None:
        absent_paths = tuple(
            p for p in absent_paths if p != "/etc/passwd")
    hits = fs_mod._probe_absent(absent_paths)
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
    # One-directional sync pipes for the pre-pivot /proc handshake (the
    # same wiring as run_in_sandbox - see there): PID 1 mounts the rootfs
    # /proc BEFORE the setup child pivots, signals completion, waits for
    # the pivot, then verifies the live /proc.
    mount_ack_r, mount_ack_w = os.pipe()
    pivot_done_r, pivot_done_w = os.pipe()
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            state = enter_all_namespaces()
            fs_mod.prepare_rootfs(rootfs_state, config.resources.disk_mb,
                                  _toolchain_dir())
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        _flush_io_before_fork()
        grand = os.fork()
        if grand != 0:
            # Child A reads the proc-mount ack and writes the pivot-done
            # ack. Close the ends grand owns ONLY in child A (grand must
            # keep its live copies of the ends it writes/reads, and its
            # own branch closes the ends it does not use), so grand's exit
            # is EOF to these reads.
            os.close(mount_ack_w)
            os.close(pivot_done_r)
        if grand == 0:
            # PID 1: mount the rootfs /proc pre-pivot (required ordering
            # on mainline kernels - a procfs mount after pivot+detach in
            # a user namespace fails EPERM), then verify the filesystem
            # boundary from inside the new root.
            os.close(mount_ack_r)
            os.close(pivot_done_w)
            try:
                problems = fs_mod.mount_sandbox_proc_prepivot()
                if problems:
                    raise NamespaceSetupError(
                        "proc boundary pre-pivot verification failed: "
                        + "; ".join(problems))
                os.write(mount_ack_w, b"1")
            except BaseException as e:  # noqa: BLE001
                os.write(write_fd, f"FAIL {type(e).__name__}: {e}".encode())
                try:
                    os.write(mount_ack_w, b"0")
                except OSError:
                    pass
                os._exit(0)
            if not _sync_wait(pivot_done_r, "pivot"):
                os.write(write_fd, b"FAIL pivot_root + old-root detach did "
                                   b"not complete")
                os._exit(0)
            os.chdir("/")
            os.close(mount_ack_w)
            os.close(pivot_done_r)
            try:
                fs_state = fs_mod._verify_root_boundary(
                    rootfs_state, _toolchain_dir())
                verdict = _fs_pid1_verification(state, fs_state)
                os.write(write_fd, verdict.encode())
            except BaseException as e:  # noqa: BLE001
                os.write(write_fd, f"FAIL {type(e).__name__}: {e}".encode())
            os._exit(0)
        # Child A: wait for the pre-pivot proc mount, complete the pivot
        # + old-root detach, signal PID 1, then wait for it.
        if not _sync_wait(mount_ack_r, "proc mount"):
            os.write(write_fd, b"FAIL proc mount did not complete")
            os._exit(1)
        try:
            fs_mod.pivot_and_detach()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            try:
                os.write(pivot_done_w, b"0")
            except OSError:
                pass
            os._exit(1)
        os.write(pivot_done_w, b"1")
        os.close(mount_ack_r)
        os.close(pivot_done_w)
        _, status = os.waitpid(grand, 0)
        os._exit(0 if os.waitstatus_to_exitcode(status) == 0 else 1)
    os.close(write_fd)
    os.close(mount_ack_r)
    os.close(mount_ack_w)
    os.close(pivot_done_r)
    os.close(pivot_done_w)
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
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            state = enter_all_namespaces()
            net_mod.ensure_loopback_down()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        _flush_io_before_fork()
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
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            state = enter_all_namespaces()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        _flush_io_before_fork()
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
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            program = seccomp_mod.build_program()
            state = enter_all_namespaces()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        _flush_io_before_fork()
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
    """Real-path probe of the RESOURCES mechanism: the six mandated
    rlimits lowered + kernel-state read-back verified in PID 1 after
    no_new_privs + capability reduction + seccomp install, and (HARDENED)
    the cgroup v2 session - prepared host-side in the delegated subtree
    (v2 identity, four required controllers, writable-subtree probe,
    session cgroup creation, controller enablement, io.max device
    resolution, all four limits written + read-back) and joined by PID 1
    (cgroup.procs migration + membership + limit re-verification).

    RESOURCES-stage shape (ADR-007, READING A): all four controllers are
    mandatory for HARDENED. When delegation is unavailable (read-only
    cgroupfs, not delegated, missing controller, unresolvable io device,
    or any establishment/verification failure), HARDENED refuses AT
    RESOURCES with the precise detected reason - never a partial success.
    RESTRICTED (rlimits only, ADR-007) completes its RESOURCES stage here."""
    return _resources_probe_impl(config)


def _resources_probe_impl(config) -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="resources probe requires Linux with os.fork (fail "
                   "closed - rlimits cannot be established here)")
    read_fd, write_fd = os.pipe()
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        session = None
        try:
            program = seccomp_mod.build_program()
            # HARDENED: prepare the cgroup session HOST-SIDE in the
            # delegated subtree (before entering the boundary) - detect
            # v2, require the four controllers, probe/establish the
            # session cgroup, resolve the io device, write + read back
            # all four limits. Any delegation/establishment failure is a
            # refusal with the precise reason. RESTRICTED: no cgroup.
            if config.mode is SecurityMode.HARDENED:
                session = cgroups_mod.prepare_session(
                    cgroups_mod.CGROUP_ROOT, f"sbx-{os.getpid()}",
                    config.resources, config.workspace)
            state = enter_all_namespaces()
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL setup: {type(e).__name__}: {e}".encode())
            os._exit(1)
        _flush_io_before_fork()
        grand = os.fork()
        if grand == 0:
            # PID 1: no_new_privs -> capability reduction -> seccomp
            # install -> rlimits lower + read-back -> (HARDENED) join the
            # session cgroup (migrate self + verify membership + limit
            # read-backs). RESTRICTED is complete with rlimits only.
            try:
                priv_mod.establish_and_verify()
                priv_mod.reduce_and_verify()
                seccomp_mod.establish_and_verify(program)
                resources_mod.establish_and_verify_rlimits(config.resources)
                if session is not None:
                    cgroups_mod.join_and_verify(session, os.getpid())
                os.write(write_fd, b"OK")
            except BaseException as e:  # noqa: BLE001
                os.write(write_fd, f"FAIL {type(e).__name__}: {e}".encode())
            os._exit(0)
        _, status = os.waitpid(grand, 0)
        if session is not None:
            cgroups_mod.remove_session(session)
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
        if config.mode is SecurityMode.HARDENED:
            return StageCheck(
                ok=True,
                reason="rlimits established and kernel-state read-back "
                       "verified (RLIMIT_CPU/AS/NPROC/NOFILE/FSIZE/CORE=0, "
                       "soft == hard) after the seccomp install in PID 1 of "
                       "a real forked child; HARDENED cgroup v2 session "
                       "established in the delegated subtree (pids/memory/"
                       "cpu/io.max all written and read back) and PID 1 "
                       "migrated + membership/limit re-verified (RESOURCES "
                       "complete, READING A)")
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
    path and (HARDENED) the cgroup v2 session; HARDENED/RESTRICTED refuse
    unless the mechanism is established and verified, and HARDENED
    refuses whenever cgroup delegation/establishment is unavailable or
    unverifiable (the refusal point stays AT RESOURCES until all four
    controllers are established)."""
    return resources_probe(config)


def environment_probe(config) -> StageCheck:
    """Real-path probe of the ENVIRONMENT mechanism (Steps 11-12):
    construct the approved six-variable sandbox environment - host env
    never inherited, S-034 - replace the process environment, verify the
    LIVE environment (exactly the allowlisted variables with exactly the
    approved values), AND verify the constructed environment carries no
    socket/credential variable (S-003/S-004 - SSH_AUTH_SOCK, DOCKER_HOST,
    AWS_*, KUBECONFIG, ... cannot survive), run in a forked child so the
    supervisor never inherits a sanitized environment.

    ENVIRONMENT-stage shape (ADR-009): the workload environment is the
    six constructed variables only (PATH/HOME/TMPDIR/LANG/LC_ALL/TERM -
    config rejects anything beyond them). Any construction, replacement,
    or verification failure is a refusal with the precise reason. The
    full credential/socket BOUNDARY verification (path reachability +
    socket-creation denial from the workload view) happens inside the
    sandbox in run_in_sandbox (Step 12) and is exercised by the
    sandbox-internal tests."""
    return _environment_probe_impl(config)


def _environment_probe_impl(config) -> StageCheck:
    """Run the real sanitization in a forked child (the supervisor's own
    environment is never mutated - the child replaces only its own).
    """
    read_fd, write_fd = os.pipe()
    _flush_io_before_fork()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            env_mod.sanitize_and_verify(config.env_allowlist)
            # Step 12 probe half: the CONSTRUCTED env must carry no
            # socket/credential variable (S-003/S-004).
            cred_mod.verify_isolated_env(dict(os.environ))
            os.write(write_fd, b"OK")
        except BaseException as e:  # noqa: BLE001
            os.write(write_fd, f"FAIL {type(e).__name__}: {e}".encode())
        os._exit(0)
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
            reason="approved six-variable sandbox environment constructed, "
                   "applied and verified in a real forked child: exactly "
                   "PATH/HOME/LANG/LC_ALL/TERM/TMPDIR with the approved "
                   "values, no host variable present, and no "
                   "socket/credential variable survives (S-034, S-003, "
                   "S-004)")
    return StageCheck(
        ok=False, code=InitFailureCode.STAGE_FAILED,
        reason=msg or f"environment probe child failed (status {status}) - "
                      "fail closed, workload not executed")


def _environment_guard(config) -> StageCheck:
    """ENVIRONMENT stage guard (registered below). Probes the real
    sanitization + verification; HARDENED/RESTRICTED refuse unless the
    constructed environment is established and verified."""
    return environment_probe(config)


def execution_probe(config) -> StageCheck:
    """Real-path probe of the EXECUTION mechanisms (Steps 13-15, items
    18-21): bounded output with session termination (S-037), external
    wall-clock deadline with session termination (S-036), and
    child-subreaper process-tree containment (S-014/S-038). These are
    SUPERVISOR-side mechanisms, so the probe exercises the real
    machinery in forked children (a flooding workload truncated and
    terminated by the real bounded read, a silent workload terminated
    on deadline expiry by the real timer, both reaped) - the
    supervisor's own state changes only by the intended, idempotent
    subreaper flag. This is the EXECUTION stage guard's evidence."""
    return _execution_probe_impl(config)


def _execution_probe_impl(config) -> StageCheck:
    if not _security_init._is_linux() or not hasattr(os, "fork"):
        return StageCheck(
            ok=False, code=InitFailureCode.PLATFORM_UNSUPPORTED,
            reason="execution probe requires Linux with os.fork (fail "
                   "closed - the supervisor-side enforcement machinery "
                   "cannot be exercised here)")
    problems: list[str] = []
    # 1. Child subreaper (S-014): set + kernel-state read-back - the
    #    precondition for reliable process-tree containment.
    try:
        lifecycle_mod.establish_subreaper()
    except NamespaceSetupError as e:
        problems.append(f"child subreaper: {e}")
    # 2. Bounded output (S-037): a flooding child must be truncated and
    #    the session terminated (the flooder must not survive).
    try:
        r, w = os.pipe()
        _flush_io_before_fork()
        flooder = os.fork()
        if flooder == 0:
            os.close(r)
            payload = b"F" * 65536
            try:
                while True:
                    os.write(w, payload)
            except OSError:
                pass
            os._exit(0)
        os.close(w)
        data, truncated = output_mod.collect_bounded(
            r, flooder, 64 * output_mod.KIB)
        _, status = os.waitpid(flooder, 0)
        if not truncated:
            problems.append(
                "bounded output: limit not enforced (no truncation)")
        if os.waitstatus_to_exitcode(status) == 0:
            problems.append(
                "bounded output: flooder completed normally - session "
                "not terminated")
    except BaseException as e:  # noqa: BLE001 - a probe failure is a refusal
        problems.append(f"bounded output: {type(e).__name__}: {e}")
    # 3. External deadline (S-036): a silent child must be terminated on
    #    expiry - the deadline aborts the session, never a status flag.
    try:
        r, w = os.pipe()
        _flush_io_before_fork()
        silent = os.fork()
        if silent == 0:
            os.close(r)
            os.close(w)
            while True:
                pass
        # The supervisor holds w open: EOF can never arrive - only the
        # deadline can end this session.
        data, truncated, timed_out = timeout_mod.collect_session_output(
            r, silent, 64 * output_mod.KIB, wall_time_seconds=1)
        os.close(w)
        _, status = os.waitpid(silent, 0)
        if not timed_out:
            problems.append(
                "external deadline: not enforced (no timeout)")
        if os.waitstatus_to_exitcode(status) == 0:
            problems.append(
                "external deadline: silent child completed normally - "
                "session not terminated")
    except BaseException as e:  # noqa: BLE001 - a probe failure is a refusal
        problems.append(f"external deadline: {type(e).__name__}: {e}")
    if problems:
        return StageCheck(
            ok=False, code=InitFailureCode.STAGE_FAILED,
            reason="execution mechanism probe failed: " + "; ".join(problems))
    return StageCheck(
        ok=True,
        reason="bounded output (S-037), external deadline (S-036) and child "
               "subreaper containment (S-014) exercised on the real "
               "supervisor path: a flooding workload was truncated and "
               "terminated, a silent workload was terminated on deadline "
               "expiry, and the supervisor is a verified child subreaper "
               "(EXECUTION complete, items 18-21)")


def _execution_guard(config) -> StageCheck:
    """EXECUTION stage guard (registered below). Probes the real
    supervisor-side enforcement machinery; HARDENED/RESTRICTED refuse
    unless the mechanisms are established and verified."""
    return execution_probe(config)


# Register the guards with the enforcement core. This module is imported
# lazily by SecurityInitializer (and directly by tests), so the registry
# sees each mechanism exactly when it exists - never before.
_security_init.register_stage_guard(InitStage.NAMESPACES, _namespaces_guard)
_security_init.register_stage_guard(InitStage.FILESYSTEM, _filesystem_guard)
_security_init.register_stage_guard(InitStage.NETWORK, _network_guard)
_security_init.register_stage_guard(InitStage.PRIVILEGES, _privileges_guard)
_security_init.register_stage_guard(InitStage.SECCOMP, _seccomp_guard)
_security_init.register_stage_guard(InitStage.RESOURCES, _resources_guard)
_security_init.register_stage_guard(InitStage.ENVIRONMENT, _environment_guard)
_security_init.register_stage_guard(InitStage.EXECUTION, _execution_guard)
