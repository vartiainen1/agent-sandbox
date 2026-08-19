"""cgroup v2 enforcement (Phase 1 Step 10, ADR-007, SECURITY_SPEC.md
S-012/S-027/S-014).

Policy (READING A - approved 2026-08-19): HARDENED requires ALL four
architecture-named controllers, each limit established and verified by
kernel-state read-back - never a partial session:

    pids.max    = ResourceLimits.processes
    memory.max  = ResourceLimits.memory_mb * 1024 * 1024
    cpu.max     = "{cpu_quota_percent * 1000} 100000"   (fixed 100000 us period)
    io.max      = "{major}:{minor} rbps={io_mbps * MiB} wbps={io_mbps * MiB}"

``io.max`` targets the REAL block device backing the workspace/rootfs
storage, resolved from kernel state (st_dev -> /sys/dev/block ->
/sys/class/block, then /proc/self/mountinfo) - NEVER a guessed major:minor,
never a host-device assumption. If the backing store is not a real block
device (tmpfs/overlay/pseudo), or the device cannot be resolved, HARDENED
REFUSES (the approval's explicit rule: do not silently skip io.max).

Delegation model (no privileged helper, no capability, ADR-002): cgroup
v2 configuration inside a DELEGATED subtree is filesystem-permission
work - the caller's cgroup (the delegation root) must have the four
controllers enabled in its subtree_control, and the supervisor (running
as the caller) creates the session cgroup as a CHILD of that root and
writes the limit files there. No CAP_SYS_ADMIN, no capability
restoration, no syscall beyond the existing allowlist (mkdir/openat/
write/read are all in the derived 45 - no seccomp change).

Flow:
1. ``detect_cgroup_v2`` - v2 filesystem identity + available controllers.
2. ``require_controllers`` - all four must be available.
3. ``probe_delegation`` - can a child cgroup be created + removed in the
   delegated subtree? Returns None when writable, else the precise
   BLOCKED reason (read-only filesystem / not delegated / ...).
4. ``prepare_session`` (supervisor side, in the delegated subtree): enable
   check on the parent subtree_control, create the session cgroup,
   resolve the io device, write all four limits, verify each by read-back.
5. ``join_and_verify`` (sandbox PID 1 side, after rlimits): migrate PID 1
   via cgroup.procs, verify membership + every limit read-back.
6. Workload descendants inherit membership across fork/exec (kernel
   semantics); verified via /proc/<pid>/cgroup.

Every unexpected state raises NamespaceSetupError with a deterministic
reason (fail closed, S-018) - the workload never runs on a partial or
unverifiable cgroup state.

Import-safety: no calls at import (Windows-safe); the probe/guard gate on
the platform seam, and non-Linux hosts fail closed there.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from agent_sandbox.config import ResourceLimits
from agent_sandbox.isolation.errors import NamespaceSetupError

CGROUP_ROOT = "/sys/fs/cgroup"
_V2_MARKER = "cgroup.controllers"
_SUBTREE_CONTROL = "cgroup.subtree_control"
_PROCESSES = "cgroup.procs"
# The four architecture-named controllers (ADR-007; HARDENED requires all).
REQUIRED_CONTROLLERS = ("pids", "memory", "cpu", "io")
# cpu.max period is fixed at 100000 us (approved policy).
CPU_QUOTA_PERIOD_US = 100000
_MIB = 1024 * 1024


# ---------------------------------------------------------------------------
# Module-level seams (fork-safe: the sandbox child inherits the parent's
# module state, so tests can inject failures/hostile state and the real
# path must refuse). All defaults are plain filesystem operations and are
# Windows-safe (they are only CALLED under Linux).
# ---------------------------------------------------------------------------

def _read_file_impl(path: str) -> str:
    with open(path, "r", encoding="ascii") as f:
        return f.read()


def _write_file_impl(path: str, data: str) -> None:
    with open(path, "w", encoding="ascii") as f:
        f.write(data)


def _mkdir_impl(path: str) -> None:
    os.mkdir(path)


def _rmdir_impl(path: str) -> None:
    os.rmdir(path)


def _exists_impl(path: str) -> bool:
    return os.path.exists(path)


def _realpath_impl(path: str) -> str:
    return os.path.realpath(path)


_read_file = _read_file_impl
_write_file = _write_file_impl
_mkdir = _mkdir_impl
_rmdir = _rmdir_impl
_exists = _exists_impl
_realpath = _realpath_impl


# ---------------------------------------------------------------------------
# Policy mapping (config -> cgroup values)
# ---------------------------------------------------------------------------

def cpu_max_value(cpu_quota_percent: int) -> str:
    """cpu.max = \"{quota} 100000\" (fixed 100000 us period; quota in us):
    100% -> 100000/100000 (one full core), 50% -> 50000/100000,
    200% -> 200000/100000. Approved policy, documented in ADR-007."""
    return f"{cpu_quota_percent * 1000} {CPU_QUOTA_PERIOD_US}"


def io_max_value(io_mbps: int, major: int, minor: int) -> str:
    """io.max = \"{major}:{minor} rbps={mbps*MiB} wbps={mbps*MiB}\" on the
    resolved backing block device. Approved policy, documented in ADR-007."""
    rate = io_mbps * _MIB
    return f"{major}:{minor} rbps={rate} wbps={rate}"


def cgroup_policy(limits: ResourceLimits,
                  io_device: tuple[int, int]) -> dict[str, str]:
    """The exact four-limit policy (READING A - all four mandatory). The
    io device must be resolved (never guessed); a missing device is a
    programming/refusal error, never a silent skip of io.max."""
    major, minor = io_device
    return {
        "pids.max": str(limits.processes),
        "memory.max": str(limits.memory_mb * _MIB),
        "cpu.max": cpu_max_value(limits.cpu_quota_percent),
        "io.max": io_max_value(limits.io_mbps, major, minor),
    }


# ---------------------------------------------------------------------------
# Detection + controller discovery
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CgroupV2State:
    """Verified cgroup v2 state (kernel read-back from the cgroupfs)."""

    root: str
    available_controllers: frozenset[str]
    enabled_subtree_controllers: frozenset[str]


def detect_cgroup_v2(root: str = CGROUP_ROOT) -> CgroupV2State:
    """Verify the cgroup v2 filesystem identity and read the available
    controllers. A missing marker (cgroup v1 or no cgroupfs) is a refusal
    with the specific reason - never a silent \"no cgroups\" continue."""
    marker = os.path.join(root, _V2_MARKER)
    if not _exists(marker):
        raise NamespaceSetupError(
            f"cgroup v2 unavailable: {marker} does not exist "
            "(no cgroup v2 filesystem) - fail closed, workload not executed")
    try:
        controllers_text = _read_file(marker)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read cgroup controllers ({marker}): {e} - fail "
            "closed, workload not executed") from e
    available = frozenset(controllers_text.split())
    try:
        subtree_text = _read_file(os.path.join(root, _SUBTREE_CONTROL))
    except OSError:
        subtree_text = ""
    enabled = frozenset(subtree_text.split())
    return CgroupV2State(root=root,
                         available_controllers=available,
                         enabled_subtree_controllers=enabled)


def require_controllers(state: CgroupV2State,
                        required=REQUIRED_CONTROLLERS) -> None:
    """All four architecture-named controllers must be available. A
    missing controller is a refusal naming it - HARDENED never runs with
    a partial controller set (READING A: no partial success)."""
    missing = [c for c in required if c not in state.available_controllers]
    if missing:
        raise NamespaceSetupError(
            "required cgroup controller(s) unavailable: "
            + ", ".join(missing)
            + " - HARDENED refuses, fail closed, workload not executed")


def _own_cgroup_path_impl() -> str:
    """The caller's cgroup path from /proc/self/cgroup (v2 \"0::<path>\").
    The session cgroup is created as a CHILD of this (the delegated
    subtree root). Raises when the v2 entry cannot be read."""
    try:
        text = _read_file("/proc/self/cgroup")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read /proc/self/cgroup: {e} - cgroup delegation "
            "cannot be established, fail closed, workload not executed") from e
    for line in text.splitlines():
        if line.startswith("0::"):
            path = line[3:].strip()
            return path or "/"
    raise NamespaceSetupError(
        "no cgroup v2 ('0::') entry in /proc/self/cgroup - cgroup "
        "delegation cannot be established, fail closed, workload not executed")


_own_cgroup_path = _own_cgroup_path_impl


def _delegation_reason(err: OSError, action: str) -> str:
    if err.errno == 30:  # EROFS
        return "cgroup filesystem is read-only (no writable delegated subtree)"
    if err.errno in (1, 13):  # EPERM, EACCES
        return (f"permission denied ({action}; errno {err.errno}) - the "
                "cgroup subtree is not delegated to this user")
    return f"{action} failed (errno {err.errno}: {err.strerror})"


def probe_delegation(root: str = CGROUP_ROOT) -> str | None:
    """Probe whether a writable delegated subtree exists: CREATE + REMOVE a
    child cgroup in the caller's cgroup. Returns None when writable;
    otherwise the precise BLOCKED reason (read-only / not delegated / ...).
    This is the create/remove delegation test (the approved spec) - never
    "the probe file exists". A cgroup.type write is NOT part of the
    signal: it can return EINVAL for value semantics on a perfectly
    writable subtree (observed on the privileged substrate), so the
    create/remove pair is the delegation proof."""
    parent = os.path.join(root, _own_cgroup_path().lstrip("/"))
    name = f".as-delegation-probe-{os.getpid()}"
    path = os.path.join(parent, name)
    try:
        _mkdir(path)
    except OSError as e:
        return _delegation_reason(e, "child cgroup creation")
    try:
        _rmdir(path)
    except OSError as e:
        return _delegation_reason(e, "child cgroup removal")
    return None


# ---------------------------------------------------------------------------
# io.max device resolution (kernel state, never guessed)
# ---------------------------------------------------------------------------

def _is_real_block_device(major: int, minor: int) -> bool:
    """True iff /sys/dev/block/<maj>:<min> resolves to a real block device
    (has an entry under /sys/class/block). Pseudo devices (tmpfs major 0,
    overlay, drvfs) fail this check."""
    link = f"/sys/dev/block/{major}:{minor}"
    if not _exists(link):
        return False
    try:
        target = _realpath(link)
    except OSError:
        return False
    name = os.path.basename(target)
    return _exists(f"/sys/class/block/{name}")


def _mountinfo_devices_covering(workspace: str) -> list[tuple[int, int]]:
    """All major:minor pairs from /proc/self/mountinfo whose mount point
    covers the workspace path, deepest mount first. Escapes (\\040) are
    decoded. Raises NamespaceSetupError on an unreadable mountinfo."""
    workspace = os.path.abspath(workspace)
    try:
        text = _read_file("/proc/self/mountinfo")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read /proc/self/mountinfo: {e} - io.max device "
            "resolution impossible, fail closed, workload not executed") from e
    found: list[tuple[int, int, int]] = []
    for line in text.splitlines():
        if " - " not in line:
            continue
        head = line.split(" - ", 1)[0]
        parts = head.split()
        if len(parts) < 5:
            continue
        majmin = parts[2].split(":")
        if len(majmin) != 2 or not majmin[0].isdigit() or not majmin[1].isdigit():
            continue
        mount_point = parts[4].replace("\\040", " ")
        if (workspace == mount_point
                or workspace.startswith(mount_point.rstrip("/") + "/")
                or mount_point == "/"):
            found.append((int(majmin[0]), int(majmin[1]), len(mount_point)))
    found.sort(key=lambda item: item[2], reverse=True)
    return [(maj, min_) for maj, min_, _ in found]


def resolve_io_device(workspace: str) -> tuple[int, int]:
    """Resolve the REAL block device backing ``workspace`` from kernel
    state. The device is never guessed and never assumed: st_dev of the
    workspace is checked against /sys/dev/block + /sys/class/block, and
    if that is a pseudo device, the covering mounts in /proc/self/
    mountinfo are checked. When no real block device can be resolved,
    HARDENED REFUSES with the specific reason (approved policy: do NOT
    silently skip io.max)."""
    try:
        st = os.stat(workspace)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot stat workspace {workspace!r}: {e} - io.max device "
            "resolution impossible, fail closed, workload not executed") from e
    st_major, st_minor = os.major(st.st_dev), os.minor(st.st_dev)
    if _is_real_block_device(st_major, st_minor):
        return (st_major, st_minor)
    for maj, min_ in _mountinfo_devices_covering(workspace):
        if _is_real_block_device(maj, min_):
            return (maj, min_)
    raise NamespaceSetupError(
        f"cannot resolve a real backing block device for io.max from "
        f"workspace {workspace!r} (st_dev {st_major}:{st_minor} is not a "
        "real block device and no covering mountinfo entry resolves to "
        "one) - HARDENED refuses, fail closed, workload not executed")


# ---------------------------------------------------------------------------
# Session cgroup: prepare (supervisor side) + join (PID 1 side)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CgroupSession:
    """A prepared session cgroup (created + configured host-side by the
    supervisor in the delegated subtree; joined by sandbox PID 1)."""

    path: str
    limits: ResourceLimits
    io_device: tuple[int, int]


def _enabled_in_parent(parent: str, state: CgroupV2State) -> list[str]:
    """The required controllers must be enabled in the delegated subtree
    root's subtree_control - children can only use controllers enabled
    there (kernel delegation semantics)."""
    if not _exists(os.path.join(parent, _SUBTREE_CONTROL)):
        raise NamespaceSetupError(
            f"delegated subtree {parent} has no {_SUBTREE_CONTROL} - "
            "cgroup controllers cannot be used, fail closed, workload "
            "not executed")
    try:
        text = _read_file(os.path.join(parent, _SUBTREE_CONTROL))
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read {_SUBTREE_CONTROL} in delegated subtree "
            f"{parent}: {e} - fail closed, workload not executed") from e
    enabled = frozenset(text.split())
    missing = [c for c in REQUIRED_CONTROLLERS if c not in enabled]
    if missing:
        raise NamespaceSetupError(
            "required cgroup controller(s) not enabled in the delegated "
            f"subtree {parent}: {', '.join(missing)} - HARDENED refuses, "
            "fail closed, workload not executed")
    return list(REQUIRED_CONTROLLERS)


def _write_limits(path: str, policy: dict[str, str]) -> None:
    """Write every limit file and read it back; a write failure or a
    read-back that differs from the exact value is a refusal (never \"the
    write succeeded\")."""
    for name, expected in policy.items():
        target = os.path.join(path, name)
        try:
            _write_file(target, expected + "\n")
        except OSError as e:
            raise NamespaceSetupError(
                f"cannot write {name} ({expected}) in session cgroup "
                f"{path}: {e} - fail closed, workload not executed") from e
        try:
            actual = _read_file(target).strip()
        except OSError as e:
            raise NamespaceSetupError(
                f"cannot read back {name} in session cgroup {path}: {e} "
                "- fail closed, workload not executed") from e
        if actual != expected:
            raise NamespaceSetupError(
                f"{name} read-back is {actual!r}, expected {expected!r} "
                f"in session cgroup {path} - fail closed, workload not "
                "executed")


def prepare_session(root: str, session_id: str, limits: ResourceLimits,
                    workspace: str) -> CgroupSession:
    """Supervisor-side session preparation (in the delegated subtree):
    detect v2 -> require the four controllers -> verify the parent
    subtree_control enables them -> create the session cgroup -> resolve
    the io device -> write all four limits -> verify each by read-back.
    Any unexpected state raises (fail closed) and the partial cgroup is
    removed best-effort - never a partial session left behind."""
    state = detect_cgroup_v2(root)
    require_controllers(state)
    parent = os.path.join(root, _own_cgroup_path().lstrip("/"))
    blocked = probe_delegation(root)
    if blocked is not None:
        raise NamespaceSetupError(
            f"cgroup delegation unavailable: {blocked} - HARDENED refuses, "
            "fail closed, workload not executed")
    _enabled_in_parent(parent, state)
    path = os.path.join(parent, session_id)
    try:
        _mkdir(path)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot create session cgroup {path}: {e} - fail closed, "
            "workload not executed") from e
    try:
        device = resolve_io_device(workspace)
        policy = cgroup_policy(limits, device)
        _write_limits(path, policy)
    except BaseException:
        try:
            _rmdir(path)
        except OSError:
            pass
        raise
    return CgroupSession(path=path, limits=limits, io_device=device)


def _verify_membership(path: str, pid: int) -> None:
    try:
        procs = _read_file(os.path.join(path, _PROCESSES))
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read {_PROCESSES} in session cgroup {path}: {e} - "
            "fail closed, workload not executed") from e
    if str(pid) not in procs.split():
        raise NamespaceSetupError(
            f"PID {pid} is NOT a member of session cgroup {path} "
            f"({_PROCESSES}: {procs.strip()!r}) - fail closed, workload "
            "not executed")


def join_and_verify(session: CgroupSession, pid: int) -> None:
    """PID-1 side: migrate ``pid`` into the session cgroup via cgroup.procs
    and verify membership + every limit read-back. Any unexpected state
    refuses (fail closed) - the workload never runs outside the session
    cgroup or with an unverified limit."""
    try:
        _write_file(os.path.join(session.path, _PROCESSES), f"{pid}\n")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot migrate PID {pid} into session cgroup "
            f"{session.path}: {e} - fail closed, workload not executed") from e
    _verify_membership(session.path, pid)
    _verify_limits(session.path, session.limits, session.io_device)


def _verify_limits(path: str, limits: ResourceLimits,
                   io_device: tuple[int, int]) -> None:
    """Read every configured limit back from kernel state and require the
    exact value (the join-time re-verification)."""
    policy = cgroup_policy(limits, io_device)
    for name, expected in policy.items():
        try:
            actual = _read_file(os.path.join(path, name)).strip()
        except OSError as e:
            raise NamespaceSetupError(
                f"cannot read {name} in session cgroup {path}: {e} - fail "
                "closed, workload not executed") from e
        if actual != expected:
            raise NamespaceSetupError(
                f"{name} read-back is {actual!r}, expected {expected!r} "
                f"in session cgroup {path} - fail closed, workload not "
                "executed")


def workload_cgroup_path(pid: int) -> str:
    """Kernel read-back of a process's cgroup membership (used to verify
    workload inheritance across fork/exec)."""
    try:
        text = _read_file(f"/proc/{pid}/cgroup")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read /proc/{pid}/cgroup: {e} - workload inheritance "
            "verification impossible, fail closed") from e
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:].strip() or "/"
    raise NamespaceSetupError(
        f"no cgroup v2 entry in /proc/{pid}/cgroup - workload inheritance "
        "verification impossible, fail closed")


def remove_session(session: CgroupSession) -> None:
    """Best-effort removal of the session cgroup (supervisor side, after
    the sandbox exited - the cgroup must be empty). Failures are not a
    refusal (cleanup is the lifecycle stage's job); never raise."""
    try:
        _rmdir(session.path)
    except OSError:
        pass
