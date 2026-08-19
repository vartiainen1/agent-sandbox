"""no_new_privs + capability reduction (Phase 1 Steps 6-7, ADR-008,
SECURITY_SPEC.md S-008, S-009, S-010).

Step 6 - ``no_new_privs`` (prctl(PR_SET_NO_NEW_PRIVS, 1)) makes execve(2)
unable to grant the process (or anything it forks) any privileges it
does not already have: setuid/setgid binaries and file capabilities
become inert. The kernel enforces it irrevocably. It must be enabled
before ANY untrusted workload execution, and it is a prerequisite for
the unprivileged seccomp install (Step 13, ADR-008).

Step 7 - capability reduction (ARCHITECTURE.md Q11, ADR-008): the
ENTIRE capability bounding set is dropped (prctl(PR_CAPBSET_DROP) for
every capability), the ambient set is cleared
(prctl(PR_CAP_AMBIENT_CLEAR_ALL)), and effective/permitted/inheritable
are cleared via capset(2) - so the workload holds NO capabilities,
including inside its own user namespace (the ns-local caps that Step 5
observed, e.g. CAP_NET_ADMIN enabling the lo toggle, are removed here).
With an empty bounding set plus no_new_privs, no capability can ever be
acquired again, by this process or anything it execs.

This module follows the Step 5 (network.py) discipline:

- Configuration actions (``set_no_new_privs``, ``drop_bounding_set``,
  ``clear_ambient``, ``clear_capability_sets``) run in sandbox PID 1,
  immediately before the workload function, in the mandated order:
  namespaces/filesystem/network boundary -> no_new_privs -> capability
  reduction -> workload.
- Verification is kernel-state READ-BACK, never "the syscall returned
  success": PR_GET_NO_NEW_PRIVS must be 1, and /proc/self/status
  CapBnd/CapEff/CapPrm/CapInh/CapAmb must all be zero.
- Every failure raises NamespaceSetupError with a deterministic reason;
  the fail-closed guard converts it into a refusal (S-018) - the
  workload never runs on an unverified privilege state.

Placement (ADR-008, docs/seccomp-derivation/methodology.md): no_new_privs
precedes the seccomp filter install (Step 13) - an unprivileged process
may only load a filter after no_new_privs is set - and precedes any
untrusted exec. The capability reduction happens after no_new_privs
(required order per the Step 7 mandate) and before the workload.

Import-safety: the module imports syscalls (import-safe on any platform)
and only CALLS it under Linux; non-Linux hosts fail closed at the guard.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError

# prctl(2) options (kernel ABI) - mirrored from syscalls.py for callers
# that read them without invoking the wrapper.
PR_SET_NO_NEW_PRIVS = syscalls.PR_SET_NO_NEW_PRIVS
PR_GET_NO_NEW_PRIVS = syscalls.PR_GET_NO_NEW_PRIVS
PR_CAPBSET_DROP = syscalls.PR_CAPBSET_DROP
PR_CAP_AMBIENT = syscalls.PR_CAP_AMBIENT
PR_CAP_AMBIENT_CLEAR_ALL = syscalls.PR_CAP_AMBIENT_CLEAR_ALL

# Named capabilities the architecture explicitly forbids (ADR-008). With
# an empty bounding set every capability is absent; these are the ones
# singled out for the per-capability adversarial check.
CAP_DAC_OVERRIDE = 1
CAP_NET_ADMIN = 12
CAP_SYS_MODULE = 16
CAP_SYS_RAWIO = 17
CAP_SYS_PTRACE = 19
CAP_SYS_ADMIN = 21

# /proc/self/status capability fields (kernel-state read-back source).
_CAP_STATUS_FIELDS = ("CapBnd", "CapEff", "CapPrm", "CapInh", "CapAmb")


# Module-level seams (fork-safe: the sandbox child inherits the parent's
# module state, so tests can inject a failing/mismatching syscall or a
# hostile state read and the real path must refuse).
def _prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0,
           arg5: int = 0) -> int:
    return syscalls.prctl(option, arg2, arg3, arg4, arg5)


def _capset_impl(version: int, data: list) -> None:
    syscalls.capset(version, data)


_capset = _capset_impl


def _read_proc_status_impl() -> str:
    try:
        with open("/proc/self/status", "r", encoding="ascii") as f:
            return f.read()
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read /proc/self/status: {e} - capability state "
            "verification impossible, fail closed") from e


_read_proc_status = _read_proc_status_impl


def set_no_new_privs() -> None:
    """Enable no_new_privs for the calling thread (prctl(PR_SET_NO_NEW_PRIVS,
    1)). Inherited across fork and exec, so once PID 1 sets it the entire
    workload tree is covered. Raises NamespaceSetupError on failure -
    fail closed, the workload never runs with an unestablished invariant."""
    try:
        _prctl(PR_SET_NO_NEW_PRIVS, 1)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot enable no_new_privs (prctl PR_SET_NO_NEW_PRIVS): "
            f"{e} - fail closed, workload not executed") from e


def verify_no_new_privs() -> bool:
    """Kernel-state read-back: prctl(PR_GET_NO_NEW_PRIVS) must report the
    bit set (value 1). A non-1 read-back - including 0 (not set) or any
    unexpected value - is a refusal, never a warning-and-continue. Returns
    True on success (the guard's evidence); raises otherwise."""
    try:
        value = _prctl(PR_GET_NO_NEW_PRIVS)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read no_new_privs state (prctl PR_GET_NO_NEW_PRIVS): "
            f"{e} - fail closed, workload not executed") from e
    if value != 1:
        raise NamespaceSetupError(
            f"no_new_privs read-back is {value}, expected 1 - fail closed, "
            "workload not executed")
    return True


def establish_and_verify() -> None:
    """Set no_new_privs and immediately read the kernel state back; a
    single entry point for PID 1 so ordering (set -> verify -> workload)
    cannot be inverted by callers."""
    set_no_new_privs()
    verify_no_new_privs()


# ---------------------------------------------------------------------------
# Step 7: capability reduction (bounding-set drop + cleared sets)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapabilityState:
    """Verified capability state after reduction (sandbox-internal). Each
    field is the parsed /proc/self/status bitmap for that set."""

    bounding: int       # CapBnd
    effective: int      # CapEff
    permitted: int      # CapPrm
    inheritable: int    # CapInh
    ambient: int        # CapAmb

    @property
    def all_zero(self) -> bool:
        return not (self.bounding | self.effective | self.permitted
                    | self.inheritable | self.ambient)


def drop_bounding_set() -> None:
    """Drop EVERY capability from the bounding set (prctl(PR_CAPBSET_DROP)
    for 0..63). EINVAL means the capability does not exist on this kernel
    (beyond CAP_LAST_CAP) and is skipped; any other error fails closed.
    Requires CAP_SETPCAP in the caller's user namespace - sandbox PID 1
    holds it before the reduction (verified by the read-back, never
    assumed). Once dropped, a capability can never be re-added by any
    process in this user namespace."""
    for cap in range(64):
        try:
            _prctl(PR_CAPBSET_DROP, cap)
        except OSError as e:
            if e.errno == errno.EINVAL:
                continue  # invalid capability number on this kernel
            raise NamespaceSetupError(
                f"cannot drop capability {cap} from the bounding set: "
                f"{e} - fail closed, workload not executed") from e


def clear_ambient() -> None:
    """Clear all ambient capabilities (prctl(PR_CAP_AMBIENT,
    PR_CAP_AMBIENT_CLEAR_ALL)). Requires no privilege. Fail closed on
    error."""
    try:
        _prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot clear ambient capabilities: {e} - fail closed, "
            "workload not executed") from e


def clear_capability_sets() -> None:
    """Clear effective/permitted/inheritable to zero via capset(2)
    (_LINUX_CAPABILITY_VERSION_3, two data words covering bits 0-63).
    Lowering one's own sets never requires privilege. Fail closed on
    error - the sandbox never continues with residual capabilities."""
    try:
        _capset(syscalls._LINUX_CAPABILITY_VERSION_3,
                [(0, 0, 0), (0, 0, 0)])
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot clear capability sets (capset): {e} - fail closed, "
            "workload not executed") from e


def reduce_and_verify() -> CapabilityState:
    """Perform the full capability reduction (drop bounding set -> clear
    ambient -> clear effective/permitted/inheritable) and read the kernel
    state back. Returns the verified CapabilityState; any residual
    capability is a refusal (fail closed)."""
    drop_bounding_set()
    clear_ambient()
    clear_capability_sets()
    return verify_capability_reduction()


def _parse_cap_field(status: str, field: str) -> int:
    """Parse one 'CapXXX:\t<hex>' line from /proc/self/status."""
    prefix = field + ":"
    for line in status.splitlines():
        if line.startswith(prefix):
            return int(line.split(":", 1)[1].strip(), 16)
    raise NamespaceSetupError(
        f"{field} missing from /proc/self/status - capability state "
        "verification impossible, fail closed")


def verify_capability_reduction() -> CapabilityState:
    """Kernel-state read-back of the capability sets from
    /proc/self/status. The workload holds no capabilities iff
    CapBnd/CapEff/CapPrm/CapInh/CapAmb are ALL zero; any nonzero set is
    a refusal, never a warning-and-continue."""
    try:
        status = _read_proc_status()
    except NamespaceSetupError as e:
        raise NamespaceSetupError(
            f"capability reduction verification failed: {e}") from e
    values = {f: _parse_cap_field(status, f) for f in _CAP_STATUS_FIELDS}
    state = CapabilityState(bounding=values["CapBnd"],
                            effective=values["CapEff"],
                            permitted=values["CapPrm"],
                            inheritable=values["CapInh"],
                            ambient=values["CapAmb"])
    problems = [f"{f} = 0x{values[f]:x} (expected 0)"
                for f in _CAP_STATUS_FIELDS if values[f]]
    if problems:
        raise NamespaceSetupError(
            "capability reduction verification failed: "
            + "; ".join(problems) + " - fail closed, workload not executed")
    return state
