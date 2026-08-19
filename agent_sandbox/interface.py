"""Shared interface session core (ADR-013, interface phase sub-phase C).

CLI, MCP and API are THIN front-ends over a single enforcement core.
The MCP (stdio JSON-RPC) and API (HTTP) transports both speak to the
boundary through THIS module, so equivalent requests produce literally
the same decision: the payload-building logic lives exactly once.

    transport request (MCP line / HTTP POST)
        -> SessionManager.initialize(params) | execute(params)
        -> common ExecutionRequest
        -> RuntimeSession.execute()      (the READY/REFUSED gate)
        -> run_in_sandbox()              (the only boundary path)
        -> ExecutionResult / ExecutionRefused
        -> transport response

There is NO other execution path: this module never calls
``run_in_sandbox``, never builds a workload function, never invokes
subprocess/os.system/os.popen/os.execve, and never interprets a shell
string. ``command`` stays an ARGUMENT VECTOR passed verbatim into the
sandbox (S-016/S-017). Sessions are created ONLY through
``initialize``, which runs the real fail-closed ``SecurityInitializer``;
there is no way to reach the boundary without a READY/REFUSED decision.

The payloads returned here are the machine-readable outcomes (S-020,
S-023 - mode + session identity in every one):

- ``initialize`` -> {session_id, mode, state, refused, reason}
- ``execute``    -> {session_id, mode, state, refused, exit_code,
                     output, truncated, timed_out, cleanup_failure}
                    or the refusal {session_id, mode, state: refused,
                     refused: True, reason} - a refusal is never
                    disguised as success.

``InterfaceParamError`` is the deterministic invalid-parameter error
each transport maps to its own error framing (JSON-RPC -32602 / HTTP
400) - the message is user-facing and never leaks internals.

Import safety: stdlib only; nothing Linux-specific at import time.

Trust boundary: this module is TRUSTED supervisor code. The workload
runs inside the isolated environment, never here.
"""

from __future__ import annotations

from agent_sandbox.audit import AuditRecorder
from agent_sandbox.config import RuntimeConfig
from agent_sandbox.models import (
    ConfigError,
    ExecutionRefused,
    ExecutionRequest,
    ExecutionRequestError,
)
from agent_sandbox.runtime.session import RuntimeSession

# The supported security modes (S-020) - identical on every interface.
MODE_VALUES = ("hardened", "restricted", "compatibility")


class InterfaceParamError(ValueError):
    """Deterministic invalid-parameters error (message is user-facing)."""


class SessionManager:
    """The shared session registry + request handling used by the MCP
    and API transports.

    Holds one ``RuntimeSession`` per ``initialize`` call, keyed by
    session id (S-023 - every execution response carries its session
    identity). No security policy lives here: the decisions come from
    the real ``SecurityInitializer`` / ``RuntimeSession.execute()``.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, RuntimeSession] = {}

    @property
    def sessions(self) -> dict[str, RuntimeSession]:
        """Read-only view of the session registry (test/inspection
        surface; production code never mutates it directly)."""
        return self._sessions

    # -- session lifecycle (thin, no policy) --------------------------------
    def _new_session(self, config: RuntimeConfig, audit) -> RuntimeSession:
        """Patchable seam for tests (mirrors the CLI tests' patching of
        SecurityInitializer/RuntimeSession - production creates the real
        session)."""
        return RuntimeSession(config, audit=audit)

    def initialize(self, params: dict) -> dict:
        """Create + initialize a session from validated params. Returns
        the machine-readable decision; raises ``InterfaceParamError`` on
        invalid input (deterministic)."""
        workspace = params.get("workspace")
        mode = params.get("mode", "restricted")
        audit = params.get("audit")

        if not isinstance(workspace, str) or not workspace.strip():
            raise InterfaceParamError(
                "initialize: workspace is required (an absolute host "
                "directory copied into the sandbox)")
        if not isinstance(mode, str) or mode not in MODE_VALUES:
            raise InterfaceParamError(
                f"initialize: invalid mode {mode!r} (supported: "
                f"{', '.join(MODE_VALUES)}) - mode is explicit and never "
                "auto-downgraded")
        if audit is not None and (not isinstance(audit, str) or not audit):
            raise InterfaceParamError("initialize: audit must be a non-empty "
                                      "path")

        try:
            config = RuntimeConfig.from_dict({"mode": mode,
                                              "workspace": workspace})
        except ConfigError as e:
            raise InterfaceParamError(str(e)) from None

        recorder = AuditRecorder(audit) if audit else None
        session = self._new_session(config, recorder)
        result = session.initialize()

        self._sessions[session.session_id] = session
        return {
            "session_id": session.session_id,
            "mode": config.mode.value,
            "state": "ready" if result.ok else "refused",
            "refused": not result.ok,
            "reason": result.failure.describe() if result.failure else "",
        }

    def execute(self, params: dict) -> dict:
        """Execute through the sole enforcement path from validated
        params. Returns the result or refusal payload (never disguises a
        refusal as success); raises ``InterfaceParamError`` on invalid
        input (deterministic)."""
        session_id = params.get("session_id")
        command = params.get("command")

        if not isinstance(session_id, str) or not session_id:
            raise InterfaceParamError("execute: session_id is required "
                                      "(a non-empty string)")
        if not isinstance(command, list) or not command:
            raise InterfaceParamError("execute: command is required "
                                      "(a non-empty argv array)")
        if not all(isinstance(part, str) for part in command):
            raise InterfaceParamError("execute: command argv entries must "
                                      "be strings")

        session = self._sessions.get(session_id)
        if session is None:
            raise InterfaceParamError(f"execute: unknown session "
                                      f"{session_id!r}")

        try:
            request = ExecutionRequest(command=tuple(command))
        except ExecutionRequestError as e:
            raise InterfaceParamError(str(e)) from None

        outcome = session.execute(request)

        if isinstance(outcome, ExecutionRefused):
            return {
                "session_id": session.session_id,
                "mode": session.config.mode.value,
                "state": outcome.state,
                "refused": True,
                "reason": outcome.reason,
            }
        return {
            "session_id": session.session_id,
            "mode": session.config.mode.value,
            "state": "ready",
            "refused": False,
            "exit_code": outcome.exit_code,
            "output": outcome.output,
            "truncated": outcome.truncated,
            "timed_out": outcome.timed_out,
            "cleanup_failure": outcome.cleanup_failure,
        }
