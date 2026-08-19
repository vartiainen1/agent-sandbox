"""Core models: security modes, initialization stages, failure states.

These are pure data/enumeration types - no enforcement logic lives here.
Enforcement requirements (which stages a mode requires) live in
``agent_sandbox.security.init`` so configuration stays separate from
enforcement (ARCHITECTURE.md section 12, 17; SECURITY_SPEC.md S-018/S-020).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class SecurityMode(str, enum.Enum):
    """Explicit per-session security mode (SECURITY_SPEC.md S-020).

    Downgrades are explicit user choices made in the configuration; the
    runtime NEVER downgrades automatically (S-019 - no silent downgrade).
    """

    HARDENED = "hardened"
    RESTRICTED = "restricted"
    COMPATIBILITY = "compatibility"


class InitStage(str, enum.Enum):
    """Ordered initialization stages of the hardened runtime.

    Structural stages (CONFIG_VALIDATED, PLATFORM_LINUX) are implemented in
    Phase 1 Step 1. Mechanism stages are declared here and implemented in
    the mandated order (ARCHITECTURE.md section 21); until a stage's guard
    is registered, initialization for any mode that requires it REFUSES
    (fail closed, S-018) - it is never skipped or downgraded.
    """

    CONFIG_VALIDATED = "config_validated"  # structural: configuration validated
    PLATFORM_LINUX = "platform_linux"      # structural: Linux host required
    NAMESPACES = "namespaces"              # mechanism: user/mount/PID/net/UTS/IPC (Step 2)
    FILESYSTEM = "filesystem"              # mechanism: rootfs/pivot_root/workspace/proc/dev/sys (Steps 3-9)
    NETWORK = "network"                    # mechanism: network namespace, deny by construction (Step 10)
    PRIVILEGES = "privileges"              # mechanism: no_new_privs + capability drop (Steps 11-12)
    SECCOMP = "seccomp"                    # mechanism: derived 45-syscall filter (Step 13)
    RESOURCES = "resources"                # mechanism: rlimits + cgroups v2 (Steps 14-15)
    ENVIRONMENT = "environment"            # mechanism: env sanitization, credentials/sockets (Steps 16-17)
    EXECUTION = "execution"                # mechanism: bounded output, timeout, process tree (Steps 18-20)
    READY = "ready"                        # terminal success marker - workload may execute


class InitFailureCode(str, enum.Enum):
    """Stable, machine-readable failure codes (deterministic error
    reporting; never a raw traceback)."""

    CONFIG_INVALID = "config_invalid"
    MODE_UNSUPPORTED = "mode_unsupported"
    PLATFORM_UNSUPPORTED = "platform_unsupported"
    STAGE_UNAVAILABLE = "stage_unavailable"  # mandatory stage has no implementation
    STAGE_FAILED = "stage_failed"            # mandatory stage guard refused


@dataclass(frozen=True)
class InitFailure:
    """A single deterministic initialization failure."""

    code: InitFailureCode
    stage: InitStage | None
    reason: str

    def describe(self) -> str:
        if self.stage is None:
            return f"{self.code.value}: {self.reason}"
        return f"{self.code.value} (stage {self.stage.value}): {self.reason}"


@dataclass(frozen=True)
class InitResult:
    """Explicit result of security initialization.

    ``ok == True`` means every mandatory stage for the configured mode was
    established and the workload MAY execute. ``ok == False`` means the
    workload MUST NOT execute (S-018: refuse, explicit reason, no
    execution). There is no third state and no automatic fallback.
    """

    ok: bool
    mode: SecurityMode
    stage: InitStage | None = None          # last stage reached (None if pre-stage failure)
    failure: InitFailure | None = field(default=None)

    def describe(self) -> str:
        if self.ok:
            return f"initialization OK (mode {self.mode.value}, ready at stage {self.stage.value if self.stage else '-'})"
        assert self.failure is not None
        return f"initialization REFUSED (mode {self.mode.value}): {self.failure.describe()}"


@dataclass(frozen=True)
class ExecutionRefused:
    """Deterministic refusal of a workload execution request."""

    reason: str
    state: str

    def describe(self) -> str:
        return f"execution refused (state {self.state}): {self.reason}"


class ConfigError(ValueError):
    """Configuration rejected at the boundary. Message is deterministic."""
