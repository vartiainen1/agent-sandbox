"""RuntimeSession - the execution gate and the SOLE interface entry
point toward the enforcement core (ADR-013).

The session is the trusted supervisor-side handle for one sandbox
instance. Its central invariant (tested): **later runtime stages cannot
execute unless required initialization succeeded**. ``execute()`` is the
only entry toward workload execution, and it refuses unless the session
state is READY (an explicit successful InitResult).

Interface phase (sub-phase A): ``execute(ExecutionRequest)`` is the
exactly-one code path that touches the boundary:

    RuntimeSession.execute(ExecutionRequest)
        -> run_in_sandbox(command_workload(request), ...)

There is NO other path: the CLI (and later MCP) can only build a
validated request and call this method. No subprocess(), no
os.system(), no host-side execve fallback, no shell - the command is an
argv vector exec'd INSIDE the sandbox by the bridge workload, and its
output/exit/cleanup continue through the Step 13-15 machinery.

Outcomes (distinct and machine-readable):
- ``ExecutionRefused`` - the request NEVER ran (state not READY, invalid
  request, or host-side setup failure such as an unbuildable rootfs or
  unavailable cgroup delegation). ``state`` reflects the session gate.
- ``ExecutionResult`` with exit_code 0 - workload success.
- ``ExecutionResult`` with exit_code != 0 - the workload ran but failed
  (deterministic ``FAIL setup/workload:`` text in ``output``), or the
  session was terminated by the bound/deadline (``truncated``/
  ``timed_out``). ``cleanup_failure`` reports a surviving workload
  process (S-038) - never silently reported as success.

Audit (ADR-012, observational): when an ``AuditRecorder`` is supplied,
the session records session_created, the init decision, the execution
request, and the result/refusal - all session-correlated. Recording
never blocks or alters execution (S-024); recorder failure is
observational.

Trust boundary: this module is TRUSTED supervisor code. The workload runs
inside the isolated environment, never here.
"""

from __future__ import annotations

import enum
import os
import uuid

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.models import (
    ExecutionRefused,
    ExecutionRequest,
    ExecutionResult,
    InitResult,
    SecurityMode,
)
from agent_sandbox.security.init import SecurityInitializer


class SessionState(enum.Enum):
    UNINITIALIZED = "uninitialized"
    READY = "ready"        # initialization succeeded; workload MAY execute
    REFUSED = "refused"    # initialization refused; workload MUST NOT execute


def _can_fork() -> bool:
    """Patchable platform seam (mirrors security.init._is_linux - tests
    patch this helper, never os itself)."""
    return hasattr(os, "fork")


class RuntimeSession:
    def __init__(self, config: RuntimeConfig, audit=None):
        # Configuration is validated + immutable at construction (config.py);
        # we keep a private reference - no setter, no mutation path.
        self._config = config
        self._state = SessionState.UNINITIALIZED
        self._init_result: InitResult | None = None
        # Session identity (S-023): correlates audit events, decisions,
        # and results for this sandbox instance.
        self._session_id = uuid.uuid4().hex
        # Optional ADR-012 recorder (host-side, observational).
        self._audit = audit

    # -- read-only surface -------------------------------------------------
    @property
    def config(self) -> RuntimeConfig:
        return self._config

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def init_result(self) -> InitResult | None:
        return self._init_result

    @property
    def session_id(self) -> str:
        return self._session_id

    # -- audit helper (observational, never raises) -------------------------
    def _record(self, event: str, **fields) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(self._session_id, event, **fields)
        except Exception:  # noqa: BLE001 - observation only (S-024)
            pass

    # -- lifecycle ---------------------------------------------------------
    def initialize(self) -> InitResult:
        """Run security initialization (fail closed). Sets the session
        state from the result; the state is the single gate for execute."""
        self._record("session_created", mode=self._config.mode.value)
        # Phase 4 (S-040): the active security configuration is observable
        # - record the validated policy (version + capability map).
        self._record(
            "policy_loaded",
            version=self._config.policy.version,
            capabilities=dict(self._config.policy.capabilities),
        )
        result = SecurityInitializer(self._config).initialize()
        self._init_result = result
        self._state = SessionState.READY if result.ok else SessionState.REFUSED
        self._record(
            "init_decision",
            ok=result.ok,
            stage=result.stage.value if result.stage else None,
            code=result.failure.code.value if result.failure else None,
            reason=result.failure.reason if result.failure else "",
        )
        return result

    # -- execution gate (the SOLE path to the enforcement core) -------------
    def execute(self, request: ExecutionRequest):
        """Request workload execution through the enforcement core.

        Exactly one execution path: ``execute() -> run_in_sandbox()``.
        Returns ``ExecutionRefused`` (never ran) or ``ExecutionResult``
        (ran - success or failure, see the module docstring)."""
        # 1. Validate the request at the boundary (deterministic).
        from agent_sandbox.execution import validate_request
        try:
            request = validate_request(request)
        except Exception as e:  # noqa: BLE001 - deterministic request error
            self._record("execution_refused",
                         reason=str(e), state=self._state.value)
            return ExecutionRefused(reason=str(e), state=self._state.value)

        # 2. The READY/REFUSED gate: a non-READY session NEVER reaches
        #    the boundary.
        if self._state is not SessionState.READY:
            reason = ("workload execution blocked: initialization did not "
                      "succeed (mandatory security controls not established)")
            self._record("execution_refused", reason=reason,
                         state=self._state.value)
            return ExecutionRefused(reason=reason, state=self._state.value)

        # 3. Phase 4 policy decision (S-015): every requested action passes
        #    the policy engine - the single decision point shared by CLI,
        #    MCP and API (ADR-013). A denied capability refuses the request
        #    BEFORE any boundary work (fail closed, deterministic reason).
        decision = self._config.policy.require(
            "filesystem.read.workspace",
            "filesystem.write.workspace",
            "process.spawn",
        )
        if not decision.allowed:
            reason = ("workload execution blocked by policy: "
                      f"{decision.describe()} - fail closed, workload "
                      "not executed")
            self._record("policy_decision", capability=decision.capability,
                         allowed=False, reason=decision.reason)
            self._record("execution_refused", reason=reason,
                         state=self._state.value)
            return ExecutionRefused(reason=reason, state=self._state.value)
        self._record("policy_decision", capability=decision.capability,
                     allowed=True, reason=decision.reason)

        # 4. The Linux-only runtime refuses deterministically on other
        #    platforms (fail closed - never an alternate path).
        from agent_sandbox.isolation import setup as setup_mod
        from agent_sandbox.security import init as _init_mod
        if not _init_mod._is_linux() or not _can_fork():
            reason = ("workload execution requires Linux with os.fork - "
                      "fail closed, workload not executed")
            self._record("execution_refused", reason=reason,
                         state=self._state.value)
            return ExecutionRefused(reason=reason, state=self._state.value)

        self._record("execution_request", command=list(request.command))

        # 4. Host-side setup (rootfs copy; HARDENED cgroup session) then
        #    the single boundary call.
        from agent_sandbox.isolation import cgroups as cgroups_mod
        from agent_sandbox.isolation import rootfs as rootfs_mod
        from agent_sandbox.isolation.errors import NamespaceSetupError
        from agent_sandbox.execution import command_workload

        rootfs_state = None
        cgroup_session = None
        try:
            rootfs_state = rootfs_mod.build_rootfs(self._config.workspace)
            if self._config.mode is SecurityMode.HARDENED:
                cgroup_session = cgroups_mod.prepare_session(
                    cgroups_mod.CGROUP_ROOT, f"sbx-{os.getpid()}",
                    self._config.resources, self._config.workspace)
            run = setup_mod.run_in_sandbox(
                command_workload(request),
                rootfs_state=rootfs_state,
                limits=self._config.resources,
                cgroup_session=cgroup_session,
                env_allowlist=self._config.env_allowlist,
            )
        except NamespaceSetupError as e:
            # Host-side setup failure: the run never started - refusal.
            reason = f"execution setup failed: {e} - fail closed, workload " \
                     "not executed"
            self._record("execution_refused", reason=reason,
                         state=self._state.value)
            return ExecutionRefused(reason=reason, state=self._state.value)
        except Exception as e:  # noqa: BLE001 - never leak a crash upward
            reason = (f"execution mechanism failed: {type(e).__name__}: {e} "
                      "- fail closed, workload not executed")
            self._record("execution_refused", reason=reason,
                         state=self._state.value)
            return ExecutionRefused(reason=reason, state=self._state.value)
        finally:
            if cgroup_session is not None:
                try:
                    cgroups_mod.remove_session(cgroup_session)
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass
            if rootfs_state is not None:
                import shutil
                shutil.rmtree(rootfs_state.layout.dir, ignore_errors=True)

        result = ExecutionResult(
            session_id=self._session_id,
            mode=self._config.mode,
            exit_code=run.exit_code,
            output=run.output,
            truncated=run.truncated,
            timed_out=run.timed_out,
            cleanup_failure=run.cleanup_failure,
        )
        self._record(
            "execution_result",
            exit_code=result.exit_code,
            truncated=result.truncated,
            timed_out=result.timed_out,
            cleanup_failure=result.cleanup_failure,
        )
        return result
