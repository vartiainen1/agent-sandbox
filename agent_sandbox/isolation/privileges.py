"""no_new_privs establishment and verification (Phase 1 Step 6, ADR-008,
SECURITY_SPEC.md S-010).

``no_new_privs`` (prctl(PR_SET_NO_NEW_PRIVS, 1)) makes execve(2) unable to
grant the process (or anything it forks) any privileges it does not
already have: setuid/setgid binaries and file capabilities become inert.
The kernel enforces it irrevocably - nothing inside the sandbox can clear
it. It must be enabled before ANY untrusted workload execution, and it is
a prerequisite for the unprivileged seccomp install (Step 13, ADR-008).

This module follows the Step 5 (network.py) discipline:

- ``set_no_new_privs()`` is the supervisor-side configuration action
  (runs in sandbox PID 1, immediately before the workload function).
- ``verify_no_new_privs()`` is the kernel-state READ-BACK via
  prctl(PR_GET_NO_NEW_PRIVS) - never "the prctl call returned success".
  The kernel reports the current value of the bit for the calling thread;
  anything other than 1 is a refusal (fail closed).
- Every failure raises NamespaceSetupError with a deterministic reason;
  the fail-closed guard converts it into a refusal (S-018) - the workload
  never runs on an unverified privilege state.

Placement (ADR-008, docs/seccomp-derivation/methodology.md): no_new_privs
precedes the seccomp filter install (Step 13) - an unprivileged process
may only load a filter after no_new_privs is set - and precedes any
untrusted exec. In run_in_sandbox, PID 1 establishes + verifies it after
the boundary verifications and immediately before invoking the workload
function, so ordering is structural: the workload cannot execute before
the invariant is established and read back.

Import-safety: the module imports syscalls (import-safe on any platform)
and only CALLS it under Linux; non-Linux hosts fail closed at the guard.
"""

from __future__ import annotations

from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError

# prctl(2) options (kernel ABI) - mirrored from syscalls.py for callers
# that read them without invoking the wrapper.
PR_SET_NO_NEW_PRIVS = syscalls.PR_SET_NO_NEW_PRIVS
PR_GET_NO_NEW_PRIVS = syscalls.PR_GET_NO_NEW_PRIVS


# Module-level seam (fork-safe: the sandbox child inherits the parent's
# module state, so tests can inject a failing/mismatching prctl and the
# real path must refuse).
def _prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0,
           arg5: int = 0) -> int:
    return syscalls.prctl(option, arg2, arg3, arg4, arg5)


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
