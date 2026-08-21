"""Filesystem boundary establishment - runs INSIDE the sandbox child
(after the namespace setup), as namespace-local uid 0 with
namespace-local capabilities only.

Sequence (classic rootless pivot_root pattern, ARCHITECTURE.md section 7,
ADR-005; the /proc + /dev mounts are Stage A per
docs/seccomp-derivation/methodology.md section 2 - trusted, UNFILTERED,
before privileges/seccomp):

    setup child (child A - in the new user/mount/net/UTS/IPC namespaces,
                 NOT yet in the new PID namespace):
      1. make the whole mount namespace private  (no propagation either way)
      2. bind the rootfs tree onto itself         (it becomes a mount point)
      3. make the rootfs mount private            (belt-and-braces)
      4. mount a size-limited tmpfs at /tmp
      5. provision the minimal /dev (ADR-015): mount a small sandbox-
         private tmpfs at /dev, then bind-mount EXACTLY the six host
         device nodes (null/zero/full/random/urandom/tty), each source
         identity-verified (S_ISCHR + exact major/minor) BEFORE the bind.
         mknod of device nodes is impossible inside a non-initial user
         namespace (kernel rule - CAP_MKNOD requires initial-userns
         privileges; man 7 user_namespaces), so the standard rootless
         approach (podman/bubblewrap) is used: explicitly allowlisted,
         identity-verified host nodes through the private mount
         namespace. NO host /dev tree is exposed - exactly six nodes,
         nothing else.
      6. chdir into the rootfs                       (prepare_rootfs)
    PID 1 (grandchild B - the first process of the new PID namespace):
      7. mount procfs at the rootfs /proc with MS_NOSUID|MS_NODEV|MS_NOEXEC
         and hidepid=2, and verify the actual mount state - BEFORE the
         pivot (mount_sandbox_proc_prepivot). This ordering is REQUIRED
         on mainline kernels: a procfs mount attempted AFTER pivot_root +
         old-root detach inside a user namespace fails with EPERM
         (empirically isolated on Ubuntu 24.04 / kernel 6.8; the WSL2
         kernel that underlies the Docker evidence tolerated the
         post-pivot mount, which is why this was never seen before). The
         pre-pivot mount survives the pivot and becomes the live /proc.
    setup child:
      8. pivot_root(".", ".")                     (old root stacks at ".")
      9. umount2(".", MNT_DETACH)                 (old root detached)
     10. chdir("/")                                (pivot_and_detach)
    PID 1:
     11. verify the root boundary (root identity, cwd, /workspace, /tmp
         tmpfs, /dev inventory, host paths absent) and the live /proc
         (verify_sandbox_proc): procfs at /proc with hidepid=2 +
         nosuid/nodev/noexec, /dev still the sandbox-private tmpfs,
         only PID 1 visible, /sys absent.

Why the /proc mount happens in PID 1 (not the setup child): a procfs mount
shows the PID namespace of the process that mounted it, and mounting
procfs requires being inside the PID namespace it should show. The setup
child unshared CLONE_NEWPID but did NOT join it (documented PID
semantics) - only its children do. So only PID 1 can mount a procfs that
shows the sandbox's own processes. /dev has no such dependency and is
provisioned by the setup child BEFORE pivot_root (the host /dev paths are
only resolvable pre-pivot).

Verification (never trust syscall success - fail closed):
  setup child: stat("/") == the pre-pivot identity of the rootfs dir; cwd
    == "/" and "/.." resolves to "/"; /workspace present; /tmp is a
    separate tmpfs device; /dev is the sandbox-private tmpfs with EXACTLY
    the six nodes (character type, exact major/minor, mode 0666); /sys
    ABSENT; mandatory host paths ABSENT by construction.
  PID 1: /proc is procfs with hidepid=2 active and nosuid/nodev/noexec;
    the sandbox proc view contains no host processes (the PID namespace
    is the primary boundary - hidepid=2 is defense in depth, per the
    Step 4 charter); /sys still absent; the /dev inventory is unchanged
    and /dev is still the sandbox-private tmpfs mount.

Device-node security claim (ADR-015 - narrower than "sandbox devices"):
"The sandbox receives an explicitly allowlisted set of six identity-
verified character devices through a private mount namespace. No host
/dev tree is exposed." The six inodes originate from the host; the
sandbox cannot create device nodes at all (mknod EPERM in the rootless
userns - kernel-enforced); device access remains further constrained by
the later capability/no_new_privs/seccomp stages.

Mount propagation: the whole namespace is private before any sandbox
mount, so none of /tmp, /dev, /proc propagate to the host mount
namespace (verified by host mountinfo before/after tests).
"""

from __future__ import annotations

import os
import stat as stat_mod
from dataclasses import dataclass

# Module-level lstat alias: the sandbox child runs in a forked copy of this
# process image, so failure-injection tests can patch THIS name to simulate
# a hostile/mismatched host device source (identity verification must refuse
# before anything is bound).
_lstat = os.lstat

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.isolation.rootfs import RootfsState

# Mandatory-absence host paths: must NOT exist in the minimal rootfs,
# regardless of the sandbox's own mounts. /proc and /dev are NOT here -
# they are mounted by design (present-but-isolated); /sys is absent by
# design (ADR-005: no sysfs in v0.1). /etc/passwd is an exception when
# the curated toolchain is provisioned (ADR-005): the toolchain provides
# a minimal SANITIZED /etc/passwd (root + nobody only - NSS requires
# it), verified by content instead of absence (see
# ``_toolchain_etc_problems``). Capability-oriented (absence/denial is
# the assertion), not tied to any particular runner's layout.
HOST_ABSENT_PATHS = (
    "/sys",
    "/etc/passwd", "/etc/shadow", "/root",
    "/var/run/docker.sock", "/run/docker.sock",
    "/mnt/wsl", "/mnt/c", "/mnt/d",
)

# The EXACT minimal /dev inventory (name, major, minor) - Step 4 charter:
# null/zero/full/random/urandom/tty and nothing else. No block devices,
# no host passthrough, no /dev/kvm, no /dev/net, no GPU, no arbitrary
# character devices. Each node is bind-mounted from the host with source
# identity verification (ADR-015); the inventory here is the allowlist.
DEV_NODES = (
    ("null", 1, 3),
    ("zero", 1, 5),
    ("full", 1, 7),
    ("random", 1, 8),
    ("urandom", 1, 9),
    ("tty", 5, 0),
)
DEV_NODE_MODE = 0o666

# Size of the /dev tmpfs (deliberately small and bounded; the six bound
# nodes are tiny - this only needs to hold their directory entries).
DEV_TMPFS_SIZE = "size=1m,mode=0755"


@dataclass(frozen=True)
class FilesystemState:
    """Verified filesystem boundary state (sandbox-internal view)."""

    rootfs: RootfsState
    root_identity: tuple[int, int]      # (st_dev, st_ino) the sandbox / must match
    tmpfs_ok: bool
    dev_mount_ok: bool
    dev_nodes: dict[str, tuple[int, int, int]]  # name -> (major, minor, mode)


def _probe_absent(paths: tuple[str, ...]) -> list[str]:
    """Return the subset of ``paths`` that is REACHABLE - each hit is a
    boundary violation."""
    return [p for p in paths if os.path.lexists(p)]


def _read_mountinfo() -> list[dict]:
    """Parse /proc/self/mountinfo (available inside the sandbox AFTER the
    procfs mount). Returns a list of dicts with the fields this module
    needs: mount_point, fstype, mount_options, super_options."""
    out = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="ascii") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read mountinfo: {e} - mount verification impossible, "
            "fail closed") from e
    for line in lines:
        parts = line.split(" ")
        if len(parts) < 9 or "-" not in parts:
            continue
        dash = parts.index("-")
        mount_options = parts[5]
        fstype = parts[dash + 1]
        super_options = " ".join(parts[dash + 3:])
        out.append({
            # Mountinfo escapes spaces/tabs/newlines/backslashes in paths
            # (\040 etc.); decode so path comparisons are exact.
            "mount_point": parts[4].replace("\\040", " ")
                                       .replace("\\011", "\t")
                                       .replace("\\012", "\n")
                                       .replace("\\134", "\\"),
            "fstype": fstype,
            "mount_options": mount_options,
            "super_options": super_options,
        })
    return out


def prepare_rootfs(rootfs: RootfsState, disk_mb: int,
                   toolchain: str | None = None) -> None:
    """Filesystem stage BEFORE the pivot (runs in the setup child, in the
    new mount namespace): make the namespace private, bind the rootfs
    tree onto itself + make it private, mount the size-limited /tmp,
    provision the minimal /dev (ADR-015), provision the curated read-only
    toolchain system layers (ADR-005) when configured, and chdir into
    the rootfs. The proc mount (``mount_sandbox_proc_prepivot``, in
    PID 1) and the pivot + old-root detach (``pivot_and_detach``, back
    in the setup child) happen separately - the /proc mount MUST
    complete before the pivot (the only ordering that works inside a
    user namespace on mainline kernels, see
    ``mount_sandbox_proc_prepivot``). Raises NamespaceSetupError on any
    failure - the caller reports it and the guard refuses; never a
    silent fallback to the caller's current root."""
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

    # 5. Minimal /dev (ADR-015): sandbox-private tmpfs + exactly the six
    #    identity-verified host device nodes, bind-mounted BEFORE pivot
    #    (the host /dev source paths are only resolvable pre-pivot).
    _provision_dev(layout)

    # 5b. Curated read-only system layers (ADR-005) from the toolchain
    #     artifact, when configured - bind + read-only remount, pre-pivot
    #     (the artifact paths are only resolvable pre-pivot).
    _provision_toolchain(layout, toolchain)

    # 6. cwd into the rootfs so the relative proc mount (PID 1) and the
    #    pivot land in the right tree.
    os.chdir(layout.dir)


def pivot_and_detach() -> None:
    """Complete the pivot: pivot_root(b".", b".") (old root stacks at
    "."), detach the old root, chdir onto the new root. Runs in the
    setup child AFTER PID 1 has mounted the rootfs /proc (the ordering is
    required - a procfs mount attempted after this sequence fails with
    EPERM inside a user namespace on mainline kernels, see
    ``mount_sandbox_proc_prepivot``). The post-pivot boundary verification
    runs in PID 1 (``_verify_root_boundary`` + ``verify_sandbox_proc``)."""
    syscalls.pivot_root(b".", b".")
    syscalls.umount2(b".", syscalls.MNT_DETACH)
    os.chdir("/")


def _provision_dev(layout) -> None:
    """Provision the minimal /dev: mount a sandbox-private tmpfs, then
    bind-mount EXACTLY the six host device nodes. Each source is
    identity-verified (character type + exact major/minor at the expected
    path) BEFORE it is bound - any mismatch, missing device, or failed
    bind raises NamespaceSetupError (fail closed, never a partial /dev).
    The binds live in the sandbox's private mount namespace and do not
    propagate to the host."""
    syscalls.mount(b"tmpfs", layout.dev.encode(), b"tmpfs", 0,
                   DEV_TMPFS_SIZE.encode())
    for name, major, minor in DEV_NODES:
        src = f"/dev/{name}"
        # Source identity verification BEFORE the bind (fail closed): the
        # node we are about to mount must be exactly the expected device.
        try:
            st = _lstat(src)
        except OSError as e:
            raise NamespaceSetupError(
                f"device source {src} unavailable: {e} - fail closed, no "
                "workload execution") from e
        if not stat_mod.S_ISCHR(st.st_mode):
            raise NamespaceSetupError(
                f"device source {src} is not a character device "
                f"(mode {oct(st.st_mode)}) - fail closed")
        want = syscalls.makedev(major, minor)
        if st.st_rdev != want:
            raise NamespaceSetupError(
                f"device source {src} rdev {st.st_rdev} != expected {want} "
                f"({major},{minor}) - fail closed")
        # Regular-file placeholder in the sandbox-private tmpfs; the bind
        # replaces it with the device inode (verified again post-op).
        target = os.path.join(layout.dev, name)
        with open(target, "w"):
            pass
        syscalls.mount(src.encode(), target.encode(), b"", syscalls.MS_BIND, b"")


# The read-only system layers (ADR-005): each is bind-mounted from the
# curated toolchain tree and remounted read-only, so the workload can
# never write to a system layer and never reaches the host (the bind
# sources are the dedicated toolchain artifact - never host system
# directories).
TOOLCHAIN_LAYERS = ("usr", "bin", "lib", "lib64", "etc")


def _bind_readonly(src: bytes, target: bytes) -> None:
    """Bind ``src`` onto ``target`` and remount the bind read-only - the
    standard rootless pattern (a plain bind ignores MS_RDONLY; the RO
    remount is what makes the layer read-only from the workload's
    perspective). Both operations are in the sandbox's private mount
    namespace - no propagation to the host."""
    syscalls.mount(src, target, b"", syscalls.MS_BIND, b"")
    syscalls.mount(b"none", target, b"",
                   syscalls.MS_REMOUNT | syscalls.MS_BIND | syscalls.MS_RDONLY,
                   b"")


def _provision_toolchain(layout, toolchain: str | None) -> None:
    """Provision the curated read-only system layers (ADR-005) from the
    toolchain artifact: bind-mount the toolchain's usr/bin/lib/lib64/etc
    into the rootfs and remount each read-only. The toolchain tree uses
    the merged-usr layout (bin/lib/lib64 -> usr/* symlinks, resolved by
    mount(2)), so all layers resolve to the same curated content. A
    CONFIGURED but invalid toolchain is a refusal (deterministic - never
    a silent partial toolchain); an unset toolchain keeps the current
    empty-placeholder rootfs (workspace-executable workloads only)."""
    if toolchain is None:
        return
    try:
        st = os.stat(toolchain)
    except OSError as e:
        raise NamespaceSetupError(
            f"toolchain {toolchain!r} is not accessible: {e} - the "
            "artifact must be readable by the sandbox's mapped identity "
            "(world-traversable parent dirs, e.g. /opt) - fail closed, "
            "no workload execution") from e
    if not stat_mod.S_ISDIR(st.st_mode):
        raise NamespaceSetupError(
            f"toolchain {toolchain!r} is not a directory - fail closed, "
            "no workload execution")
    try:
        st_usr = os.stat(os.path.join(toolchain, "usr"))
    except OSError as e:
        raise NamespaceSetupError(
            f"toolchain {toolchain!r} usr/ layer is not accessible: {e} "
            "- fail closed, no workload execution") from e
    if not stat_mod.S_ISDIR(st_usr.st_mode):
        raise NamespaceSetupError(
            f"toolchain {toolchain!r} has no usr/ layer - fail closed, "
            "no workload execution")
    for name in TOOLCHAIN_LAYERS:
        src = os.path.join(toolchain, name)
        if not os.path.lexists(src):
            raise NamespaceSetupError(
                f"toolchain {toolchain!r} missing layer {name} - fail "
                "closed, no workload execution")
        target = os.path.join(layout.dir, name)
        if name == "lib64" and not os.path.isdir(target):
            os.makedirs(target)
        if not os.path.isdir(target):
            raise NamespaceSetupError(
                f"rootfs has no {name}/ mount target for the toolchain "
                "layer - fail closed, no workload execution")
        _bind_readonly(src.encode(), target.encode())


def _toolchain_etc_problems() -> list[str]:
    """The toolchain /etc must be the SANITIZED minimal set (ADR-005):
    /etc/passwd contains ONLY root (uid 0) and nobody (uid 65534) - never
    a host user or credential - and /etc/shadow is ABSENT. With the
    toolchain, absence of /etc/passwd is replaced by verified content
    (NSS needs the file); without it, the file must not exist (checked
    by the HOST_ABSENT_PATHS probe). Fail closed on any deviation."""
    problems: list[str] = []
    try:
        with open("/etc/passwd") as f:
            passwd = f.read()
    except OSError as e:
        problems.append(f"cannot read /etc/passwd: {e} - the toolchain "
                        "etc/ layer is not mounted correctly")
        return problems
    for line in passwd.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            problems.append(f"/etc/passwd malformed line: {line!r}")
            continue
        try:
            uid = int(parts[2])
        except ValueError:
            problems.append(f"/etc/passwd malformed uid in line: {line!r}")
            continue
        if uid not in (0, 65534):
            problems.append(
                f"/etc/passwd contains a non-sanitized uid {uid} "
                f"(line {line!r}) - host credential content present - "
                "fail closed")
    if os.path.lexists("/etc/shadow"):
        problems.append(
            "/etc/shadow present in the sandbox - host credential data "
            "reachable - fail closed")
    return problems


def _toolchain_problems(infos: list[dict], interpreter_ok: bool) -> list[str]:
    """Toolchain verification problems (empty = OK): the workload
    interpreter must be present and every system layer must be a
    READ-ONLY mount - a writable system layer could let the workload
    tamper its own toolchain. Fail closed on any deviation."""
    problems: list[str] = []
    if not interpreter_ok:
        problems.append(
            "/usr/bin/python3 missing or not executable - the toolchain "
            "is not mounted into the rootfs")
    for name in TOOLCHAIN_LAYERS:
        lines = [m for m in infos if m["mount_point"] == f"/{name}"]
        if not lines:
            problems.append(f"toolchain layer /{name} is not a mount point")
            continue
        opts = lines[0]["mount_options"]
        if "ro" not in opts:
            problems.append(f"toolchain layer /{name} is not read-only "
                            f"(options {opts!r})")
    return problems


def _verify_root_boundary(rootfs: RootfsState,
                          toolchain: str | None = None) -> FilesystemState:
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

    # /dev: the sandbox-private tmpfs with EXACTLY the six nodes (type,
    # major/minor, mode). "Node exists" is not the verification -
    # identity is.
    dev_problems, dev_nodes = _verify_dev_inventory()
    problems.extend(dev_problems)

    # Host-path absence. With the toolchain, /etc/passwd is PROVIDED as a
    # minimal SANITIZED file (root + nobody only - NSS requires it); its
    # absence check is replaced by the verified-content check below.
    absent_paths = HOST_ABSENT_PATHS
    if toolchain is not None:
        absent_paths = tuple(p for p in HOST_ABSENT_PATHS if p != "/etc/passwd")
    hits = _probe_absent(absent_paths)
    if hits:
        problems.append("host path(s) reachable in sandbox: " + ", ".join(hits))

    # Toolchain system layers (ADR-005), when provisioned: the workload
    # interpreter must be present, every layer must be a READ-ONLY mount
    # (verified from mountinfo - the RO remount is the mechanism), and
    # the toolchain /etc must be the sanitized minimal set.
    if toolchain is not None:
        try:
            infos = _read_mountinfo()
        except NamespaceSetupError as e:
            problems.append(str(e))
            infos = []
        problems.extend(_toolchain_problems(
            infos, os.access("/usr/bin/python3", os.X_OK)))
        problems.extend(_toolchain_etc_problems())

    if problems:
        raise NamespaceSetupError(
            "rootfs boundary verification failed: " + "; ".join(problems))
    return FilesystemState(
        rootfs=rootfs, root_identity=rootfs.root_identity, tmpfs_ok=True,
        dev_mount_ok=True, dev_nodes=dev_nodes)


def _verify_dev_inventory() -> tuple[list[str], dict[str, tuple[int, int, int]]]:
    """Verify /dev is the sandbox-private tmpfs with EXACTLY DEV_NODES,
    each a character device with the exact major/minor/mode. Returns
    (problems, verified_nodes). Ownership is intentionally NOT asserted:
    the six inodes originate from the host (ADR-015), so inside the
    sandbox they map to the overflow uid - mode 0666 makes access
    identical regardless."""
    problems: list[str] = []
    dev = "/dev"
    if not os.path.isdir(dev):
        return [f"{dev} missing in the new root"], {}
    if os.stat(dev).st_dev == os.stat("/").st_dev:
        problems.append("/dev is not a separate device from /")
    try:
        names = sorted(os.listdir(dev))
    except OSError as e:
        return [f"cannot list {dev}: {e}"], {}
    expected = sorted(n for n, _m, _j in DEV_NODES)
    if names != expected:
        problems.append(
            f"/dev inventory mismatch: {names} (expected exactly {expected})")
        return problems, {}
    nodes: dict[str, tuple[int, int, int]] = {}
    for name, major, minor in DEV_NODES:
        path = os.path.join(dev, name)
        try:
            st = _lstat(path)
        except OSError as e:
            problems.append(f"cannot stat {path}: {e}")
            continue
        if not stat_mod.S_ISCHR(st.st_mode):
            problems.append(f"{path} is not a character device "
                            f"(mode {oct(st.st_mode)})")
            continue
        want_dev = syscalls.makedev(major, minor)
        if st.st_rdev != want_dev:
            problems.append(
                f"{path} device number {st.st_rdev} != expected "
                f"{want_dev} ({major},{minor})")
        if (st.st_mode & 0o777) != DEV_NODE_MODE:
            problems.append(f"{path} mode {oct(st.st_mode & 0o777)} != "
                            f"{oct(DEV_NODE_MODE)}")
        nodes[name] = (major, minor, st.st_mode & 0o777)
    return problems, nodes


def mount_sandbox_proc_prepivot() -> list[str]:
    """Mount procfs at the rootfs /proc (hidepid=2, nosuid/nodev/noexec)
    BEFORE pivot_root, and verify the actual mount state. Must run in
    PID 1 of the new PID namespace (the first process that joins it) -
    only then does the procfs show the sandbox's own processes. The
    relative target ``proc`` resolves from the caller's cwd, which
    ``prepare_rootfs`` set to the rootfs dir; after the pivot this mount
    becomes the live /proc. This ordering is REQUIRED on mainline
    kernels: a procfs mount attempted AFTER pivot_root + old-root detach
    inside a user namespace fails with EPERM (empirically isolated on
    Ubuntu 24.04 / kernel 6.8 - bubblewrap-style ordering; the WSL2
    kernel that underlies the Docker evidence tolerated the post-pivot
    mount). Returns a list of problems (empty = OK); raises
    NamespaceSetupError if the mount itself fails. The PID namespace is
    the PRIMARY process-visibility boundary; hidepid=2 is defense in
    depth (Step 4 charter)."""
    syscalls.mount(b"proc", b"proc", b"proc",
                   syscalls.MS_NOSUID | syscalls.MS_NODEV | syscalls.MS_NOEXEC,
                   b"hidepid=2")

    problems: list[str] = []
    try:
        infos = _read_mountinfo()
    except NamespaceSetupError as e:
        problems.append(str(e))
        infos = []

    # Pre-pivot the mount is at <rootfs>/proc (cwd = the rootfs dir); the
    # mountinfo mount point is that absolute path in this namespace.
    expected = os.path.abspath("proc")
    proc_lines = [m for m in infos if m["mount_point"] == expected]
    if not proc_lines:
        problems.append(f"rootfs /proc ({expected}) is not a mount point "
                        "in the sandbox mountinfo")
    else:
        m = proc_lines[0]
        if m["fstype"] != "proc":
            problems.append(f"rootfs /proc fstype is {m['fstype']!r}, "
                            f"expected 'proc'")
        opts = m["mount_options"]
        for flag in ("nosuid", "nodev", "noexec"):
            if flag not in opts:
                problems.append(f"rootfs /proc missing mount flag {flag} "
                                f"(options {opts!r})")
        sup = m["super_options"]
        if not _hidepid_active(sup):
            problems.append(
                f"rootfs /proc hidepid=2 not active (super options {sup!r})")

    return problems


def verify_sandbox_proc() -> list[str]:
    """Post-pivot verification of the sandbox proc view - the procfs PID 1
    mounted pre-pivot via ``mount_sandbox_proc_prepivot`` is now the live
    /proc. Verifies the actual mount state (procfs at /proc with
    hidepid=2 + nosuid/nodev/noexec), that /dev is still the sandbox-
    private tmpfs with the exact inventory, that only sandbox PID 1 is
    visible, and that /sys remains absent. Returns a list of problems
    (empty = OK). The PID namespace is the PRIMARY process-visibility
    boundary; hidepid=2 is defense in depth (Step 4 charter)."""
    problems: list[str] = []
    try:
        infos = _read_mountinfo()
    except NamespaceSetupError as e:
        problems.append(str(e))
        infos = []

    proc_lines = [m for m in infos if m["mount_point"] == "/proc"]
    if not proc_lines:
        problems.append("/proc is not a mount point in the sandbox mountinfo")
    else:
        m = proc_lines[0]
        if m["fstype"] != "proc":
            problems.append(f"/proc fstype is {m['fstype']!r}, expected 'proc'")
        opts = m["mount_options"]
        for flag in ("nosuid", "nodev", "noexec"):
            if flag not in opts:
                problems.append(f"/proc missing mount flag {flag} "
                                f"(options {opts!r})")
        sup = m["super_options"]
        if not _hidepid_active(sup):
            problems.append(
                f"/proc hidepid=2 not active (super options {sup!r})")

    # /dev must still be the sandbox-private tmpfs mount (not the host
    # /dev tree) and the inventory unchanged.
    dev_lines = [m for m in infos if m["mount_point"] == "/dev"]
    if not dev_lines or dev_lines[0]["fstype"] != "tmpfs":
        problems.append("/dev is not the sandbox-private tmpfs mount")
    dev_problems, _nodes = _verify_dev_inventory()
    problems.extend(dev_problems)

    if not os.path.isdir("/proc/1") or not os.access("/proc/1/cmdline", os.R_OK):
        problems.append("/proc/1 (sandbox PID 1) is not visible in the "
                        "sandbox proc view")

    # Host processes must not be exposed through the sandbox proc view.
    # The PID namespace is the boundary: the numeric /proc entries at this
    # point are exactly {1} (the fn/PID-1 process itself).
    pids = set()
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.add(int(entry))
    except OSError as e:
        problems.append(f"cannot enumerate /proc: {e}")
    if pids - {1}:
        problems.append(f"unexpected processes visible in sandbox proc view: "
                        f"{sorted(pids)} (expected only PID 1)")

    # /sys: absence is the mechanism - no sysfs mount, no sysfs dir.
    hits = _probe_absent(("/sys",))
    if hits:
        problems.append("host path(s) reachable in sandbox: " + ", ".join(hits))
    try:
        if any(m["fstype"] == "sysfs" for m in infos):
            problems.append("sysfs is mounted in the sandbox - /sys must be "
                            "absent in v0.1 (ADR-005)")
    except NamespaceSetupError:
        pass  # already reported above

    return problems


# Symbolic hidepid aliases (kernel procfs): value 2 - the hide-all mode
# mandated by the architecture - is printed by newer kernels as
# 'invisible' (and as 'hidpid=2' after a historical kernel typo). The
# comparison is SEMANTIC (mode value), never a spelling match.
_HIDEPID_NAMES = {"off": 0, "ptraceable": 1, "invisible": 2}


def _hidepid_mode(super_options: str) -> int | None:
    """Parse the hidepid mode value out of mountinfo super options
    (numeric or symbolic spelling). Returns None if no hidepid option is
    present - the caller treats that as NOT hidepid=2 (fail closed)."""
    for token in super_options.split(","):
        token = token.strip()
        if token.startswith("hidepid=") or token.startswith("hidpid="):
            raw = token.split("=", 1)[1].strip()
            if raw.isdigit():
                return int(raw)
            return _HIDEPID_NAMES.get(raw)
    return None


def _hidepid_active(super_options: str) -> bool:
    """hidepid=2 (mode value 2, the hide-all mode) must be ACTIVE - verified
    from the actual mount state, never assumed from mount() success.
    Accepts the numeric spelling (hidepid=2), the older kernel typo
    (hidpid=2), and the newer kernels' symbolic alias (hidepid=invisible),
    all of which are mode value 2. Anything else (0/off, 1/ptraceable,
    absent, unknown) is NOT hidepid=2 and fails closed."""
    return _hidepid_mode(super_options) == 2
