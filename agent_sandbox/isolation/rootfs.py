"""Minimal root filesystem construction - host-side, deliberate, by
construction (ARCHITECTURE.md section 7, ADR-005).

Rules:
- The rootfs is a FRESH directory tree built by the supervisor - never the
  host filesystem used as an implicit rootfs, never a bind mount of the
  host root, never recursive exposure of arbitrary host directories.
- The workspace is a COPY of the project source, not a bind mount
  (S-028): a hostile repository can only damage its own copy.
- Symlinks are preserved as symlinks (S-029/S-030 by construction): a
  symlink to a host path stays pointing at a path that does not exist in
  the minimal rootfs, so it cannot reach host content.
- Absence is the default: no host home, credentials, sockets, /proc, /sys,
  /dev, Docker/WSL integration paths (S-002, S-003, S-004). The layout
  placeholders (usr/bin/lib/etc) exist as EMPTY directories in Step 3; the
  read-only system-layer mounts are a later provisioning step (ADR-005's
  "toolchain image" artifact).
- Any build failure raises NamespaceSetupError - the fail-closed
  initializer converts it into a refusal, never a silent partial rootfs.
"""

from __future__ import annotations

import os
import shutil
import stat as stat_mod
import tempfile
from dataclasses import dataclass

from agent_sandbox.isolation.errors import NamespaceSetupError

# Rootfs layout directories. Logical name -> relative path inside the tree.
# usr/bin/lib/etc exist as empty placeholders in Step 3 (system layers are
# provisioned later); proc/dev/sys are ABSENT (deferred to later steps -
# absence is the safest state).
LAYOUT_DIRS = {
    "workspace": "workspace",
    "tmp": "tmp",
    "home": "home",
    "usr": "usr",
    "bin": "bin",
    "lib": "lib",
    "etc": "etc",
}


@dataclass(frozen=True)
class RootfsLayout:
    """Host-side paths of the rootfs tree."""

    dir: str
    workspace: str
    tmp: str
    home: str
    usr: str
    bin: str
    lib: str
    etc: str


@dataclass(frozen=True)
class RootfsState:
    """A built rootfs tree plus the pre-pivot identity of its root
    directory (st_dev, st_ino) - the value the sandbox's / must match
    after pivot_root (used to detect a failed old-root detach)."""

    layout: RootfsLayout
    source_workspace: str
    root_identity: tuple[int, int]


def build_rootfs(source_workspace: str) -> RootfsState:
    """Build a fresh minimal rootfs tree and copy ``source_workspace`` into
    it as /workspace. Runs host-side (no privileges, no namespaces - the
    supervisor makes the workspace copy per ARCHITECTURE section 7).

    Raises NamespaceSetupError with a deterministic reason on any failure
    (missing/unreadable source, copy failure) - fail closed."""
    if not os.path.isdir(source_workspace):
        raise NamespaceSetupError(
            f"workspace source {source_workspace!r} is not a directory - "
            "the workspace copy cannot be made, fail closed")
    if not os.access(source_workspace, os.R_OK | os.X_OK):
        raise NamespaceSetupError(
            f"workspace source {source_workspace!r} is not readable - "
            "the workspace copy cannot be made, fail closed")

    try:
        root = tempfile.mkdtemp(prefix="as-rootfs-")
        layout = RootfsLayout(
            dir=root,
            workspace=os.path.join(root, "workspace"),
            tmp=os.path.join(root, "tmp"),
            home=os.path.join(root, "home"),
            usr=os.path.join(root, "usr"),
            bin=os.path.join(root, "bin"),
            lib=os.path.join(root, "lib"),
            etc=os.path.join(root, "etc"),
        )
        for rel in LAYOUT_DIRS.values():
            os.makedirs(os.path.join(root, rel), exist_ok=True)
        # Copy the project: symlinks preserved (symlinks=True), so a
        # workspace symlink to a host path remains a symlink whose target
        # does not exist in the rootfs (S-029 by construction).
        # dirs_exist_ok: the empty workspace dir was created above as part
        # of the layout; copytree merges into it (empty, so no collisions).
        shutil.copytree(source_workspace, layout.workspace,
                        symlinks=True, dirs_exist_ok=True)
    except (OSError, shutil.Error) as e:
        raise NamespaceSetupError(
            f"rootfs build failed: {type(e).__name__}: {e} - fail closed, "
            "no execution without a complete rootfs") from e

    st = os.stat(root)
    return RootfsState(
        layout=layout, source_workspace=source_workspace,
        root_identity=(st.st_dev, st.st_ino))


# ---------------------------------------------------------------------------
# Workspace-copy verification (semantic, not path-string checks)
# ---------------------------------------------------------------------------

def workspace_file_sets(source: str, copy: str) -> tuple[set[str], set[str]]:
    """Relative path sets of two trees (dirs marked with a trailing '/'),
    used to verify the copy is faithful. Symlinked dirs are not descended
    (os.walk default), which matches the copy semantics."""

    def walk(base: str) -> set[str]:
        out: set[str] = set()
        for dirpath, dirnames, filenames in os.walk(base):
            rel = os.path.relpath(dirpath, base)
            for n in filenames:
                out.add(os.path.join(rel, n) if rel != "." else n)
            for n in dirnames:
                out.add(os.path.join(rel, n) + "/" if rel != "." else n + "/")
        return out

    return walk(source), walk(copy)


def verify_workspace_copy(source: str, copy: str) -> None:
    """Verify the copy is faithful AND independent: identical relative path
    sets, and the copy root is a different inode than the source root (a
    real copy, not a reference). Raises AssertionError on mismatch."""
    src_set, copy_set = workspace_file_sets(source, copy)
    if src_set != copy_set:
        missing = sorted(src_set - copy_set)
        extra = sorted(copy_set - src_set)
        raise AssertionError(
            f"workspace copy mismatch: missing={missing} extra={extra}")
    src_st = os.stat(source)
    copy_st = os.stat(copy)
    if (src_st.st_dev, src_st.st_ino) == (copy_st.st_dev, copy_st.st_ino):
        raise AssertionError("workspace copy is not a fresh copy "
                             "(same inode as source)")
    # Spot-check content of one regular file if the source has any.
    for rel in sorted(src_set):
        if rel.endswith("/"):
            continue
        src_path = os.path.join(source, rel)
        if not os.path.isfile(src_path) or os.path.islink(src_path):
            continue
        with open(src_path, "rb") as f:
            src_bytes = f.read()
        with open(os.path.join(copy, rel), "rb") as f:
            copy_bytes = f.read()
        if src_bytes != copy_bytes:
            raise AssertionError(f"workspace copy content differs for {rel!r}")
        return
