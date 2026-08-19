"""User namespace + uid/gid mapping (rootless execution foundation).

The intended model (Phase 1 Step 2 charter; ARCHITECTURE.md section 5):

    UNPRIVILEGED CALLER -> USER NAMESPACE -> UID/GID MAP 0 -> CALLER
        -> SANDBOX-SIDE UID 0 (namespace-local only; NOT host root)

Critical rule: successful ``unshare(CLONE_NEWUSER)`` proves NOTHING about
the mapping. Mapping is a separate, validated step (this module) and the
sandbox NEVER continues with an unexpected identity mapping - a mismatch
raises ``NamespaceSetupError`` and the fail-closed initializer refuses.

setgroups handling follows the Linux requirement: before writing gid_map,
the caller must write "deny" to /proc/self/setgroups (kernel >= 3.19) or
the gid_map write fails for a non-root gid. On kernels without the file
(pre-3.19) there is nothing to deny and the write is skipped.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError

CLONE_NEWUSER = 0x10000000

_PROC = "/proc/self"


def _write_proc(path: str, content: str) -> None:
    with open(path, "w", encoding="ascii") as f:
        f.write(content)


def _read_proc(path: str) -> str:
    with open(path, "r", encoding="ascii") as f:
        return f.read().strip()


def _parse_map(content: str) -> tuple[int, int, int]:
    """Parse a kernel uid_map/gid_map line "inside outside length" into a
    tuple. The kernel pads fields with variable whitespace, so mapping
    verification compares the parsed semantics, never the raw text."""
    parts = content.split()
    if len(parts) != 3:
        raise NamespaceSetupError(f"malformed kernel mapping {content!r}")
    try:
        return tuple(int(p) for p in parts)  # type: ignore[return-value]
    except ValueError:
        raise NamespaceSetupError(
            f"malformed kernel mapping {content!r} (non-numeric field)") from None


@dataclass(frozen=True)
class UserNamespaceState:
    """Verified result of entering the user namespace.

    ``uid_map``/``gid_map`` are the read-back kernel mappings (inside 0 ->
    caller uid/gid). ``sandbox_uid``/``sandbox_gid`` are the raw syscall
    identities INSIDE the namespace (expected 0 - namespace-local, never
    host root)."""

    caller_uid: int
    caller_gid: int
    uid_map: str
    gid_map: str
    setgroups: str
    sandbox_uid: int
    sandbox_gid: int


def enter_user_namespace() -> UserNamespaceState:
    """Enter a new user namespace and establish the 0 -> caller mapping.

    Steps (each verified; any failure raises NamespaceSetupError):
      1. unshare(CLONE_NEWUSER)                      - OSError on failure
      2. deny setgroups                              - required before gid_map
      3. write uid_map  "0 <caller_uid> 1"
      4. write gid_map  "0 <caller_gid> 1"
      5. VERIFY read-back maps equal the intended lines
      6. VERIFY raw identity inside the namespace is (0, 0)
    """
    caller_uid = syscalls.getuid()   # raw: current userns, pre-unshare
    caller_gid = syscalls.getgid()

    # 1. Create the user namespace (raises OSError with errno - fail closed).
    syscalls.unshare(CLONE_NEWUSER)

    # 2. Deny setgroups before the gid_map write (kernel >= 3.19). On older
    #    kernels the file does not exist and there is nothing to deny.
    try:
        _write_proc(f"{_PROC}/setgroups", "deny")
    except FileNotFoundError:
        pass
    except OSError as e:
        if e.errno == 2:  # ENOENT - no setgroups file on this kernel
            pass
        else:
            raise NamespaceSetupError(
                f"setgroups deny failed (errno {e.errno}): {e}") from e

    # 3-4. Write the mappings (0 -> caller). Any failure aborts.
    expected_uid = f"0 {caller_uid} 1"
    expected_gid = f"0 {caller_gid} 1"
    try:
        _write_proc(f"{_PROC}/uid_map", expected_uid + "\n")
        _write_proc(f"{_PROC}/gid_map", expected_gid + "\n")
    except OSError as e:
        raise NamespaceSetupError(
            f"uid/gid mapping write failed (errno {e.errno}): {e} "
            f"(wanted uid_map={expected_uid!r} gid_map={expected_gid!r})") from e

    # 5. VERIFY the kernel actually applied the intended mapping (never
    #    trust that unshare + write "succeeded" - S-031 spirit). The
    #    comparison is SEMANTIC: the kernel pads map columns with variable
    #    whitespace, so only parsed (inside, outside, length) values are
    #    compared - the raw text format is irrelevant to the property.
    uid_map = _read_proc(f"{_PROC}/uid_map")
    gid_map = _read_proc(f"{_PROC}/gid_map")
    uid_ok = _parse_map(uid_map) == (0, caller_uid, 1)
    gid_ok = _parse_map(gid_map) == (0, caller_gid, 1)
    if not uid_ok or not gid_ok:
        raise NamespaceSetupError(
            "uid/gid mapping mismatch: kernel reports "
            f"uid_map={uid_map!r} gid_map={gid_map!r}, expected "
            f"{expected_uid!r} {expected_gid!r} - refusing to continue "
            "with an unexpected identity mapping")

    # 6. VERIFY the sandbox-side identity is the expected one (uid 0 inside
    #    the namespace, which maps back to the unprivileged caller).
    sandbox_uid = syscalls.getuid()
    sandbox_gid = syscalls.getgid()
    if sandbox_uid != 0 or sandbox_gid != 0:
        raise NamespaceSetupError(
            "sandbox identity is not (0, 0) inside the user namespace: "
            f"getuid={sandbox_uid} getgid={sandbox_gid}")

    setgroups = _read_proc(f"{_PROC}/setgroups")
    return UserNamespaceState(
        caller_uid=caller_uid, caller_gid=caller_gid,
        uid_map=expected_uid, gid_map=expected_gid,  # canonical, verified
        setgroups=setgroups, sandbox_uid=sandbox_uid, sandbox_gid=sandbox_gid)
