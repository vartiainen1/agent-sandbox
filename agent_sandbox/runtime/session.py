"""RuntimeSession - the execution gate.

The session is the trusted supervisor-side handle for one sandbox
instance. Its central invariant (tested): **later runtime stages cannot
execute unless required initialization succeeded**. ``execute()`` is the
only entry toward workload execution, and it refuses unless the session
state is READY (an explicit successful InitResult).

In Phase 1 Step 1 the execution mechanism (bounded output, external
timeout, process-tree containment - steps 18-20) is not implemented, so
even a READY session refuses execution with a distinct reason. That is
honest fail-closed structure: the gate works, the mechanism is not there
yet, and nothing pretends otherwise.

Trust boundary: this module is TRUSTED supervisor code. The workload runs
inside the isolated environment, never here.
"""

from __future__ import annotations

import enum

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.models import ExecutionRefused, InitResult
from agent_sandbox.security.init import SecurityInitializer


class SessionState(enum.Enum):
    UNINITIALIZED = "uninitialized"
    READY = "ready"        # initialization succeeded; workload MAY execute
    REFUSED = "refused"    # initialization refused; workload MUST NOT execute


class RuntimeSession:
    def __init__(self, config: RuntimeConfig):
        # Configuration is validated + immutable at construction (config.py);
        # we keep a private reference - no setter, no mutation path.
        self._config = config
        self._state = SessionState.UNINITIALIZED
        self._init_result: InitResult | None = None

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

    # -- lifecycle ---------------------------------------------------------
    def initialize(self) -> InitResult:
        """Run security initialization (fail closed). Sets the session
        state from the result; the state is the single gate for execute."""
        result = SecurityInitializer(self._config).initialize()
        self._init_result = result
        self._state = SessionState.READY if result.ok else SessionState.REFUSED
        return result

    # -- execution gate ----------------------------------------------------
    def execute(self, command: list[str]) -> ExecutionRefused:
        """Request workload execution. ONLY reachable after a successful
        initialization (state READY). Returns a refusal otherwise.

        In Step 1 the execution mechanism is not implemented, so even a
        READY session refuses with a distinct reason - the gate is proven,
        the mechanism is honestly absent."""
        if self._state is not SessionState.READY:
            return ExecutionRefused(
                reason="workload execution blocked: initialization did not "
                       "succeed (mandatory security controls not established)",
                state=self._state.value)
        return ExecutionRefused(
            reason="execution mechanism not implemented (Phase 1 steps 18-20)",
            state=self._state.value)
