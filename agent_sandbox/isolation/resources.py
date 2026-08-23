"""rlimits (Phase 1 Step 9, ADR-007, SECURITY_SPEC.md S-012/S-027).

Step 9 applies the always-on, unprivileged, irreversible resource limits:

    RLIMIT_CPU    <- cpu_seconds          (CPU seconds)
    RLIMIT_AS     <- memory_mb * MiB      (address space, per-process)
    RLIMIT_NPROC  <- processes            (process count)
    RLIMIT_NOFILE <- open_files           (file descriptors)
    RLIMIT_FSIZE  <- disk_mb * MiB        (single-file write size)
    RLIMIT_CORE   <- 0                    (no core dumps, T-021)

Both soft and hard are set to the same value: the hard limit is what the
kernel enforces and can NEVER be raised by an unprivileged process
(S-027, T-035); soft == hard means the limit is immediately in force.
They are inherited across fork and exec, so establishing them in sandbox
PID 1 covers the entire workload tree.

Ordering (mandated item 14 AFTER item 13): the limits are established in
PID 1 AFTER the seccomp filter (Step 8) is installed. glibc's
setrlimit(2)/getrlimit(2) map to the prlimit64 syscall, which IS in the
derived 69-syscall allowlist (syscall-classification.md) - so no filter
change is required and no syscall is added. The Step 9 Docker tests
exercise exactly this: rlimits established under the installed filter.

This module follows the Step 5-8 discipline:

- Configuration actions (``apply_rlimits``) run in sandbox PID 1,
  immediately before the workload function, in the mandated order:
  ... -> no_new_privs -> capability reduction -> seccomp -> rlimits ->
  workload.
- Verification is kernel-state READ-BACK (getrlimit), never "the syscall
  returned success": every limit must read back exactly (soft == hard ==
  expected). A mismatch, an unreadable limit, or an unexpected value is
  a refusal (fail closed, S-018).
- Every failure raises NamespaceSetupError with a deterministic reason
  naming the limit; the fail-closed guard converts it into a refusal and
  the workload is never executed.

RESOURCES-stage shape (ADR-007): rlimits are the always-applied half of
the RESOURCES stage. The HARDENED-mandatory half (cgroup v2 delegation,
Step 10) is NOT implemented here - the RESOURCES guard therefore refuses
HARDENED AT the RESOURCES stage until Step 10 lands, while RESTRICTED
(rlimits only, ADR-007) completes its RESOURCES stage with rlimits.

Import-safety: the ``resource`` module is imported at module level (like
socket/platform in seccomp.py) so the already-loaded module is inherited
via fork into PID 1 - a lazy import could not resolve inside the pivoted
minimal rootfs, which has no Python stdlib. IMPORTANT (empirical,
freebuff-errors.txt 2026-08-19): CPython on Windows does NOT ship the
``resource`` module at all, so the import is GUARDED - on a platform
without it the module stays import-safe, the RLIMIT constants are None,
and any attempt to apply/read rlimits raises NamespaceSetupError (fail
closed). The mechanism only runs under Linux; non-Linux hosts fail
closed at the guard.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_sandbox.config import ResourceLimits
from agent_sandbox.isolation.errors import NamespaceSetupError

try:
    import resource as _resource_mod
    _HAS_RESOURCE = True
except ImportError:  # pragma: no cover - Windows/non-Unix: import-safe, fails closed
    _resource_mod = None
    _HAS_RESOURCE = False

# rlimit constants (the Python resource module mirrors the kernel ABI).
# None on platforms without the module (the mechanism fails closed there).
RLIMIT_CPU = _resource_mod.RLIMIT_CPU if _HAS_RESOURCE else None
RLIMIT_AS = _resource_mod.RLIMIT_AS if _HAS_RESOURCE else None
RLIMIT_NPROC = _resource_mod.RLIMIT_NPROC if _HAS_RESOURCE else None
RLIMIT_NOFILE = _resource_mod.RLIMIT_NOFILE if _HAS_RESOURCE else None
RLIMIT_FSIZE = _resource_mod.RLIMIT_FSIZE if _HAS_RESOURCE else None
RLIMIT_CORE = _resource_mod.RLIMIT_CORE if _HAS_RESOURCE else None

_MIB = 1024 * 1024

_RLIMIT_NAMES = {
    RLIMIT_CPU: "RLIMIT_CPU",
    RLIMIT_AS: "RLIMIT_AS",
    RLIMIT_NPROC: "RLIMIT_NPROC",
    RLIMIT_NOFILE: "RLIMIT_NOFILE",
    RLIMIT_FSIZE: "RLIMIT_FSIZE",
    RLIMIT_CORE: "RLIMIT_CORE",
}


def _rlimit_name(which: int) -> str:
    return _RLIMIT_NAMES.get(which, f"rlimit {which}")


@dataclass(frozen=True)
class RlimitsState:
    """Verified rlimit state (sandbox-internal, kernel read-back). Each
    field is the applied soft limit for that resource."""

    cpu_seconds: int
    address_space_bytes: int
    processes: int
    open_files: int
    file_size_bytes: int
    core_bytes: int


def rlimit_policy(limits: ResourceLimits) -> tuple[tuple[int, int], ...]:
    """Map the validated configuration to the exact (resource, value)
    pairs applied by Step 9 (ARCHITECTURE.md section 9, ADR-007). Both
    soft and hard are set to the same value: the hard limit is what the
    kernel enforces and is never raisable (S-027)."""
    return (
        (RLIMIT_CPU, limits.cpu_seconds),
        (RLIMIT_AS, limits.memory_mb * _MIB),
        (RLIMIT_NPROC, limits.processes),
        (RLIMIT_NOFILE, limits.open_files),
        (RLIMIT_FSIZE, limits.disk_mb * _MIB),
        (RLIMIT_CORE, 0),
    )


# Module-level seams (fork-safe: the sandbox child inherits the parent's
# module state, so tests can inject a failing setrlimit/getrlimit or a
# hostile state read and the real path must refuse).
def _set_rlimit_impl(which: int, value: int) -> None:
    if not _HAS_RESOURCE:
        raise NamespaceSetupError(
            "rlimits unavailable on this platform (no resource module) - "
            "fail closed, workload not executed")
    _resource_mod.setrlimit(which, (value, value))


def _get_rlimit_impl(which: int) -> tuple[int, int]:
    if not _HAS_RESOURCE:
        raise NamespaceSetupError(
            "rlimits unavailable on this platform (no resource module) - "
            "fail closed, workload not executed")
    return _resource_mod.getrlimit(which)


_set_rlimit = _set_rlimit_impl
_get_rlimit = _get_rlimit_impl


def apply_rlimits(limits: ResourceLimits) -> None:
    """Lower every mandated rlimit (soft == hard == policy value).
    Unprivileged and irreversible once lowered (S-027). Raises
    NamespaceSetupError with a deterministic reason naming the limit -
    fail closed, the workload never runs with a missing limit."""
    for which, value in rlimit_policy(limits):
        try:
            _set_rlimit(which, value)
        except (OSError, ValueError) as e:
            raise NamespaceSetupError(
                f"cannot set {_rlimit_name(which)} to {value}: {e} - "
                "fail closed, workload not executed") from e


def read_rlimits_state(limits: ResourceLimits) -> RlimitsState:
    """Kernel-state read-back of the six soft limits. Raises
    NamespaceSetupError if any limit cannot be read - an unreadable
    resource state is a refusal, never a silent pass."""
    values: dict[str, int] = {}
    for which, _expected in rlimit_policy(limits):
        try:
            soft, _hard = _get_rlimit(which)
        except (OSError, ValueError) as e:
            raise NamespaceSetupError(
                f"cannot read {_rlimit_name(which)}: {e} - fail closed, "
                "workload not executed") from e
        values[_rlimit_name(which)] = soft
    return RlimitsState(
        cpu_seconds=values["RLIMIT_CPU"],
        address_space_bytes=values["RLIMIT_AS"],
        processes=values["RLIMIT_NPROC"],
        open_files=values["RLIMIT_NOFILE"],
        file_size_bytes=values["RLIMIT_FSIZE"],
        core_bytes=values["RLIMIT_CORE"],
    )


def verify_rlimits(limits: ResourceLimits) -> RlimitsState:
    """Verify the applied state by kernel read-back: for every mandated
    limit, soft AND hard must equal the policy value exactly. Any
    mismatch (soft, hard, or both) is a refusal - never a
    warning-and-continue. Returns the verified RlimitsState."""
    problems: list[str] = []
    values: dict[str, int] = {}
    for which, expected in rlimit_policy(limits):
        try:
            soft, hard = _get_rlimit(which)
        except (OSError, ValueError) as e:
            raise NamespaceSetupError(
                f"cannot read {_rlimit_name(which)}: {e} - fail closed, "
                "workload not executed") from e
        values[_rlimit_name(which)] = soft
        if soft != expected or hard != expected:
            problems.append(
                f"{_rlimit_name(which)} read-back is (soft={soft}, "
                f"hard={hard}), expected ({expected}, {expected})")
    if problems:
        raise NamespaceSetupError(
            "rlimit verification failed: " + "; ".join(problems)
            + " - fail closed, workload not executed")
    return RlimitsState(
        cpu_seconds=values["RLIMIT_CPU"],
        address_space_bytes=values["RLIMIT_AS"],
        processes=values["RLIMIT_NPROC"],
        open_files=values["RLIMIT_NOFILE"],
        file_size_bytes=values["RLIMIT_FSIZE"],
        core_bytes=values["RLIMIT_CORE"],
    )


def establish_and_verify_rlimits(limits: ResourceLimits) -> RlimitsState:
    """Apply the limits and immediately read the kernel state back; a
    single entry point for PID 1 so ordering (apply -> verify ->
    workload) cannot be inverted by callers."""
    apply_rlimits(limits)
    return verify_rlimits(limits)
