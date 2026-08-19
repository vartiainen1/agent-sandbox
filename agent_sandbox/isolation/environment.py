"""Environment sanitization (Phase 1 Step 11, ARCHITECTURE.md section 11,
ADR-009, S-034, T-018, T-051).

The host environment is NEVER inherited. The supervisor constructs an
explicit, deterministic sandbox-local environment and applies it in sandbox
PID 1 AFTER the resource stage (cgroup) and BEFORE the workload function.

Approved v0.1 policy (Step 11 approval, 2026-08-19):

    PATH=/usr/local/bin:/usr/bin:/bin
    HOME=/home
    TMPDIR=/tmp
    LANG=C.UTF-8
    LC_ALL=C.UTF-8
    TERM=dumb

These six are the COMPLETE supported environment set in v0.1: config.py
rejects any env_allowlist entry beyond them (no value source - secret /
environment-value injection is explicitly deferred). Host values are never
copied, merged, or selectively inherited - only the constructed variables
exist in the workload environment.

Verification reads the LIVE process environment back after sanitization and
requires EXACTLY the allowlisted variables with EXACTLY the approved values:
any unexpected variable, missing variable, or incorrect value is a refusal
(never "the assignment returned success").

Environment state is pure process state (no syscalls) - sanitization and
verification interact with neither seccomp (45-syscall allowlist unchanged)
nor any earlier stage. The module is Windows import-safe; all mutation goes
through seams so tests can inject failures deterministically.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from agent_sandbox.config import DEFAULT_ENV_ALLOWLIST
from agent_sandbox.isolation.errors import NamespaceSetupError

# The approved, deterministic sandbox-local values (Step 11 approval).
# Never read from the host environment; these are constants.
SANITIZED_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/home",
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
}


@dataclass(frozen=True)
class EnvironmentState:
    """The verified live environment as seen by the workload."""

    variables: dict[str, str] = field(default_factory=dict)
    allowlist: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return bool(self.variables)


# -- seams (patchable for deterministic failure injection) --------------

def _clear_impl() -> None:
    os.environ.clear()


def _set_impl(name: str, value: str) -> None:
    os.environ[name] = value


def _snapshot_impl() -> dict[str, str]:
    return dict(os.environ)


# -- construction -------------------------------------------------------

def construct_environment(allowlist: tuple[str, ...] | None = None
                          ) -> dict[str, str]:
    """The constructed sandbox environment for ``allowlist``.

    ``allowlist`` is the validated config ``env_allowlist`` (a subset of
    the six approved variables; config.py rejects anything beyond them).
    Returns exactly {name: approved-value} for the allowlisted names -
    nothing from the host, nothing extra.
    """
    names = allowlist if allowlist is not None else DEFAULT_ENV_ALLOWLIST
    for name in names:
        if name not in SANITIZED_ENV:
            raise NamespaceSetupError(
                f"environment policy gap: {name!r} has no constructed "
                "value - config should have rejected it, fail closed")
    return {name: SANITIZED_ENV[name] for name in names}


def apply_environment(environment: dict[str, str]) -> None:
    """Replace the process environment with exactly ``environment``.

    The supervisor-side host environment is dropped entirely - no host
    variable survives. Any failure to replace raises NamespaceSetupError
    (fail closed; the workload never sees a partially sanitized env).
    """
    try:
        _clear_impl()
        for name, value in environment.items():
            _set_impl(name, value)
    except OSError as e:
        raise NamespaceSetupError(
            f"environment replacement failed: {e} - fail closed, "
            "workload not executed")


def verify_environment(allowlist: tuple[str, ...] | None = None
                       ) -> EnvironmentState:
    """Verify the LIVE process environment against the policy.

    Requires exactly the allowlisted variables, each with exactly its
    approved value, and no other variable present. Raises
    NamespaceSetupError with a deterministic reason on ANY mismatch -
    unexpected variable, missing variable, or incorrect value. The
    returned state is the verified snapshot.
    """
    names = allowlist if allowlist is not None else DEFAULT_ENV_ALLOWLIST
    expected = {name: SANITIZED_ENV[name] for name in names}
    live = _snapshot_impl()

    unexpected = sorted(set(live) - set(expected))
    if unexpected:
        raise NamespaceSetupError(
            "environment verification failed: unexpected variable(s) "
            f"present: {', '.join(unexpected)} - fail closed, workload "
            "not executed")
    missing = sorted(set(expected) - set(live))
    if missing:
        raise NamespaceSetupError(
            "environment verification failed: missing required "
            f"variable(s): {', '.join(missing)} - fail closed, workload "
            "not executed")
    wrong = {name: live[name] for name in expected
             if live.get(name) != expected[name]}
    if wrong:
        detail = ", ".join(f"{name}={live[name]!r} (expected "
                           f"{expected[name]!r})" for name in sorted(wrong))
        raise NamespaceSetupError(
            "environment verification failed: incorrect value(s): "
            f"{detail} - fail closed, workload not executed")
    return EnvironmentState(variables=dict(live), allowlist=names)


def sanitize_and_verify(allowlist: tuple[str, ...] | None = None
                        ) -> EnvironmentState:
    """Construct, apply, and verify the sandbox environment (PID 1).

    Order: construct -> replace the process environment -> read the live
    environment back and require the exact allowlisted variables/values.
    Any failure at any step raises NamespaceSetupError; the workload must
    not execute on any failure (fail closed, S-018).
    """
    environment = construct_environment(allowlist)
    apply_environment(environment)
    return verify_environment(allowlist)
