"""Filesystem boundary establishment - runs INSIDE the sandbox child
(after the namespace setup), as namespace-local uid 0 with
namespace-local capabilities only.

Sequence (classic rootless pivot_root pattern, ARCHITECTURE.md section 7,
ADR-005):

    1. make the whole mount namespace private  (no propagation either way)
    2. bind the rootfs tree onto itself         (it becomes a mount point)
    3. make the rootfs mount private            (belt-and-braces)
    4. mount a size-limited tmpfs at /tmp
    5. chdir into the rootfs
    6. pivot_root(".", ".")                     (old root stacks at ".")
    7. umount2(".", MNT_DETACH)                 (old root detached)
    8. chdir("/")

Verification (never trust syscall success - fail closed):
    - stat("/") == the pre-pivot identity of the rootfs dir. If the old
      root were still stacked, "/" would BE the old root and this fails.
    - cwd == "/" and "/.." resolves to "/" (mount-root semantics).
    - /workspace exists; /tmp is a separate device (tmpfs).
    - mandatory host paths (/proc, /sys, /dev, host /etc/passwd, host
      home, Docker/WSL paths) are ABSENT by construction.

Note: in Step 3 /proc is intentionally not mounted, so in-sandbox
mountinfo reads are not possible; the detach is verified via the root
identity + host-path-absence probes above (mountinfo-based verification
arrives with /proc isolation in a later step). This is documented, not
hidden.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.isolation.rootfs import RootfsState

# Mandatory-absence probes: host paths that must NOT exist in the minimal
# rootfs. Capability-oriented (absence/denial is the assertion), not tied
# to any particular runner's layout.
MANDATORY_ABSENT_PATHS = (
    "/proc", "/sys", "/dev",
    "/etc/passwd", "/etc/shadow", "/root",
    "/var/run/docker.sock", "/run/docker.sock",
    "/mnt/wsl", "/mnt/c", "/mnt/d",
)


@dataclass(frozen=True)
class FilesystemState:
    """Verified filesystem boundary state (sandbox-internal view)."""

    rootfs: RootfsState
    root_identity: tuple[int, int]      # (st_dev, st_ino) the sandbox / must match
    tmpfs_ok: bool


def _probe_absent(paths: tuple[str, ...]) -> list[str]:
    """Return the subset of ``paths`` that is REACHABLE - each hit is a
    boundary violation."""
    return [p for p in paths if os.path.lexists(p)]


def establish_rootfs(rootfs: RootfsState, disk_mb: int) -> FilesystemState:
    """Establish the filesystem boundary (mounts + pivot_root + detach) and
    VERIFY it. Raises NamespaceSetupError on any failure or verification
    mismatch - the caller (sandbox child) reports it and the guard refuses;
    never a silent fallback to the caller's current root."""
    layout = rootfs.layout
    root_b = layout.dir.encode()

    # 1. Prevent propagation in both directions (S-001/S-025).
    syscalls.mount(b"none", b"/", b"", syscalls.MS_REC | syscalls.MS_PRIVATE, b"")
    # 2. The rootfs tree becomes a mount point (pivot_root requires it).
    syscalls.mount(root_b, root_b, b"", syscalls.MS_BIND | syscalls.MS_REC, b"")
    # 3. The rootfs mount itself is private.
    syscalls.mount(b"none", root_b, b"", syscalls.MS_REC | syscalls.MS_PRIVATE, b"")
    # 4. Size-limited tmpfs at /tmp (kernel-enforced at mount time).
    if disk_mb < 1:
        raise NamespaceSetupError(
            f"tmpfs size {disk_mb}m is invalid - fail closed")
    syscalls.mount(b"tmpfs", layout.tmp.encode(), b"tmpfs", 0,
                   f"size={disk_mb}m".encode())

    # 5-6. chdir into the new root and pivot (old root stacks at ".").
    os.chdir(layout.dir)
    syscalls.pivot_root(b".", b".")
    # 7. Detach the old root.
    syscalls.umount2(b".", syscalls.MNT_DETACH)
    # 8. cwd onto the new root.
    os.chdir("/")

    # 9. VERIFY (fail closed - see the module docstring).
    return _verify_root_boundary(rootfs)


def _verify_root_boundary(rootfs: RootfsState) -> FilesystemState:
    problems: list[str] = []
    st = os.stat("/")
    if (st.st_dev, st.st_ino) != rootfs.root_identity:
        problems.append(
            f"root identity mismatch: / is {(st.st_dev, st.st_ino)}, expected "
            f"{rootfs.root_identity} (old root not detached, or pivot_root "
            "did not take effect)")
    try:
        cwd = os.getcwd()
    except OSError as e:
        problems.append(f"getcwd failed: {e}")
        cwd = ""
    if cwd != "/":
        problems.append(f"cwd is {cwd!r}, expected /")
    if os.path.realpath("/..") != "/":
        problems.append("walk-up from / does not stay at /")
    if not os.path.isdir("/workspace"):
        problems.append("/workspace missing in the new root")
    if not os.path.isdir("/tmp"):
        problems.append("/tmp missing in the new root")
    tmp_dev = os.stat("/tmp").st_dev
    if tmp_dev == os.stat("/").st_dev:
        problems.append("/tmp is not a separate tmpfs device")
    hits = _probe_absent(MANDATORY_ABSENT_PATHS)
    if hits:
        problems.append("host path(s) reachable in sandbox: " + ", ".join(hits))
    if problems:
        raise NamespaceSetupError(
            "rootfs boundary verification failed: " + "; ".join(problems))
    return FilesystemState(
        rootfs=rootfs, root_identity=rootfs.root_identity, tmpfs_ok=True)
