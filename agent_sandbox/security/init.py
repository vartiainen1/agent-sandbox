"""Fail-closed security initialization.

The initialization state machine walks the ordered stage list for the
configured mode and REFUSES (S-018) at the FIRST stage that is required
but cannot be established:

    HARDENED + mandatory mechanism unavailable
        -> REFUSE EXECUTION
        -> explicit reason (stage + code)
        -> no workload execution

Rules enforced here:
- No silent downgrade (S-019): the mode comes from configuration and is
  never changed by the runtime. There is NO "try hardened then fall back
  to restricted" path - RESTRICTED is an explicit user choice made in the
  configuration, nothing else.
- Deterministic ordering: stages are walked in a fixed order and the first
  refusal is reported (stable, reproducible reasons).
- Stage guards REGISTER as the mechanisms are implemented (Phase 1 steps
  2+). An unregistered stage that a mode requires => STAGE_UNAVAILABLE
  refusal. Steps 2-7 register NAMESPACES, FILESYSTEM, NETWORK, PRIVILEGES
  and SECCOMP (isolation/setup, imported lazily by this module); later
  stages are not, so HARDENED and RESTRICTED initialize only as far as
  the mechanisms that exist and refuse at the first missing one.
  COMPATIBILITY (no isolation claims) initializes with the structural
  stages only.
- The platform seam is ``_is_linux()`` - a single patchable helper. Tests
  patch this helper, NEVER sys.platform itself (global platform spoofing
  breaks CPython 3.12's import machinery; see the _winapi incident,
  freebuff-errors.txt 2026-08-19). Mechanism modules reference it by
  module so the same seam is honored everywhere.
"""

from __future__ import annotations

import sys
from typing import Optional

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.models import (
    InitFailure,
    InitFailureCode,
    InitResult,
    InitStage,
    SecurityMode,
    StageCheck,
    StageGuard,
)

# Structural stages: implemented in Step 1 and required by EVERY mode.
STRUCTURAL_STAGES = (InitStage.CONFIG_VALIDATED, InitStage.PLATFORM_LINUX)

# Mechanism stages: required by the isolated modes (HARDENED + RESTRICTED),
# not by COMPATIBILITY (which makes no isolation claims). The exact
# RESTRICTED differences (e.g. rlimits-only resources, ADR-007) are
# deployment-documented and refined when each mechanism lands.
MECHANISM_STAGES = (
    InitStage.NAMESPACES,
    InitStage.FILESYSTEM,
    InitStage.NETWORK,
    InitStage.PRIVILEGES,
    InitStage.SECCOMP,
    InitStage.RESOURCES,
    InitStage.ENVIRONMENT,
    InitStage.EXECUTION,
)

_ISOLATED_MODES = frozenset({SecurityMode.HARDENED, SecurityMode.RESTRICTED})


# Stage registry: mechanisms register their guards here when implemented
# (Phase 1 steps 2+). A required stage with NO registered guard refuses
# initialization - this is the fail-closed shape, not a stub to be
# papered over.
_STAGE_GUARDS: dict[InitStage, StageGuard] = {}

# Mechanism guards are registered by their modules (e.g. isolation/setup.py
# registers NAMESPACES at import). The modules are imported lazily by the
# initializer so the enforcement core sees exactly the mechanisms that
# exist, and importing agent_sandbox.security.init never pulls in Linux
# mechanism code before it is needed.
_MECHANISM_GUARDS_ENSURED = False


def _ensure_mechanism_guards() -> None:
    """Import implemented mechanism modules so their guards register.
    Idempotent; unregistered mandatory stages still refuse (fail closed)."""
    global _MECHANISM_GUARDS_ENSURED
    if _MECHANISM_GUARDS_ENSURED:
        return
    # noqa: F401 - the import's side effect (guard registration) is the point.
    from agent_sandbox.isolation import setup as _setup  # noqa: F401
    _MECHANISM_GUARDS_ENSURED = True


def register_stage_guard(stage: InitStage, guard: StageGuard) -> None:
    """Register a stage guard. Called by mechanism modules as they are
    implemented. One guard per stage; a duplicate is a programming error."""
    if stage in _STAGE_GUARDS:
        raise RuntimeError(f"stage guard already registered: {stage.value}")
    _STAGE_GUARDS[stage] = guard


def init_sequence(mode: SecurityMode) -> tuple[InitStage, ...]:
    """The ordered stages required for ``mode`` (deterministic)."""
    stages = list(STRUCTURAL_STAGES)
    if mode in _ISOLATED_MODES:
        stages.extend(MECHANISM_STAGES)
    stages.append(InitStage.READY)
    return tuple(stages)


# ---------------------------------------------------------------------------
# Structural guards (real implementations, Step 1)
# ---------------------------------------------------------------------------

def _config_guard(config: RuntimeConfig) -> StageCheck:
    # Configuration was strictly validated at construction (config.py).
    # Re-verify the security-relevant invariants cheaply and deterministically
    # so the state machine does not trust an object it did not check.
    problems = []
    if not isinstance(config.mode, SecurityMode):
        problems.append("mode is not a SecurityMode")
    if not config.workspace or not config.workspace.strip():
        problems.append("workspace is empty")
    return StageCheck(ok=not problems, reason="; ".join(problems))


def _is_linux() -> bool:
    """Patchable by tests. Never patch sys.platform itself - global
    platform spoofing breaks CPython 3.12's import machinery (see the
    _winapi incident, freebuff-errors.txt 2026-08-19)."""
    return sys.platform.startswith("linux")


def _platform_guard(config: RuntimeConfig) -> StageCheck:
    if _is_linux():
        return StageCheck(ok=True)
    return StageCheck(ok=False,
                      code=InitFailureCode.PLATFORM_UNSUPPORTED,
                      reason=f"platform {sys.platform!r} is not Linux - "
                             "agent-sandbox executes Linux workloads only "
                             "(fail closed, no execution on unsupported platforms)")


# Register the structural guards now; mechanism guards arrive with their
# implementation steps.
register_stage_guard(InitStage.CONFIG_VALIDATED, _config_guard)
register_stage_guard(InitStage.PLATFORM_LINUX, _platform_guard)


# ---------------------------------------------------------------------------
# Initializer
# ---------------------------------------------------------------------------

class SecurityInitializer:
    """Walks the stage sequence for the configured mode and returns an
    explicit InitResult. No workload code runs here."""

    def __init__(self, config: RuntimeConfig):
        self._config = config

    def initialize(self) -> InitResult:
        _ensure_mechanism_guards()
        config = self._config
        for stage in init_sequence(config.mode):
            if stage is InitStage.READY:
                return InitResult(ok=True, mode=config.mode, stage=stage)
            guard: Optional[StageGuard] = _STAGE_GUARDS.get(stage)
            if guard is None:
                return InitResult(
                    ok=False, mode=config.mode, stage=stage,
                    failure=InitFailure(
                        code=InitFailureCode.STAGE_UNAVAILABLE, stage=stage,
                        reason=f"mandatory stage {stage.value} has no "
                               "implementation (guard not registered) - "
                               "fail closed, workload not executed"))
            check = guard(config)
            if not check.ok:
                return InitResult(
                    ok=False, mode=config.mode, stage=stage,
                    failure=InitFailure(
                        code=check.code, stage=stage,
                        reason=check.reason or f"stage {stage.value} failed"))
        # Unreachable: every mode's sequence ends with READY.
        return InitResult(ok=False, mode=config.mode,
                          failure=InitFailure(
                              code=InitFailureCode.STAGE_FAILED,
                              stage=None, reason="initialization sequence did not terminate"))
