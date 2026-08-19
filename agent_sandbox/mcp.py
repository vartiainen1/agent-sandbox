"""Thin MCP-compatible stdio JSON-RPC 2.0 front-end (ADR-013, interface
phase sub-phase B).

The MCP server carries NO security policy and NO enforcement logic. It is
a thin adapter over the single enforcement core (ADR-013's exactly-one
path) - the session/request logic is shared with the API in
``agent_sandbox.interface``:

    stdio JSON-RPC request
        -> parse / validate (deterministic, zero dependencies)
        -> SessionManager.initialize/execute   (shared with the API)
        -> common ExecutionRequest
        -> RuntimeSession.execute()            (the READY/REFUSED gate)
        -> run_in_sandbox()                    (the only boundary path)
        -> ExecutionResult / ExecutionRefused
        -> JSON-RPC response

There is NO other execution path: this module never calls
``run_in_sandbox``, never builds a workload function, never invokes
subprocess/os.system/os.popen/os.execve, and never interprets a shell
string. ``command`` stays an ARGUMENT VECTOR passed verbatim into the
sandbox (S-016/S-017).

Protocol surface (the minimum actually needed - no invented MCP feature
set, no handshake beyond this):

- ``initialize``  params: workspace (required, absolute host dir),
                  mode (hardened|restricted|compatibility, default
                  restricted), audit (optional host JSONL path).
- ``execute``     params: session_id (required), command (required,
                  non-empty argv array of strings).

JSON-RPC 2.0 behavior (deterministic):
- id preservation on every response; notifications (no id) produce no
  response.
- parse error -32700 (malformed JSON, id null), invalid request -32600
  (non-object, missing/non-string method, batch arrays), method not
  found -32601, invalid params -32602 (missing/invalid parameters,
  unknown session, invalid command argv), internal error -32603.
- NO host details leak: an unexpected exception becomes the fixed
  generic ``internal error`` message - never a traceback, type name,
  environment value, credential, or internal path. Malformed input
  never crashes the server and never enters an alternate execution
  path (a workload only ever runs via RuntimeSession.execute()).

Transport:
- stdin/stdout JSON-RPC framing only (one message per line, the MCP
  stdio convention). stdout carries ONLY responses; diagnostics go to
  stderr. EOF ends ``serve()`` cleanly. Empty lines are skipped.

Decision equivalence with the CLI and API: the same validated
ExecutionRequest through the same RuntimeSession.execute() yields the
same security decision; the response payloads carry the same fields as
the CLI's ``--json`` payloads (mode + session identity included).

Import safety: stdlib only; nothing Linux-specific at import time.

Trust boundary: this module is TRUSTED supervisor code. The workload
runs inside the isolated environment, never here.
"""

from __future__ import annotations

import json
import sys

from agent_sandbox.interface import InterfaceParamError, SessionManager

# JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# The minimal method surface (see the module docstring).
METHOD_INITIALIZE = "initialize"
METHOD_EXECUTE = "execute"

# Fixed generic message for unexpected failures - never leaks host
# exception details, environment, credentials, or internal paths.
_GENERIC_INTERNAL_ERROR = "internal error"


def _error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


def _result(request_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _extract_id(data: dict):
    """Preserve a scalar JSON-RPC id; anything else is treated as absent
    (per the spec the id must be a string/number/null; a non-scalar id is
    itself invalid, so respond with id null - deterministic)."""
    if "id" not in data:
        return None, False
    rid = data["id"]
    if isinstance(rid, (str, int, float)) and not isinstance(rid, bool):
        return rid, True
    return None, False


def parse_message(line: str):
    """Parse one JSON-RPC message line.

    Returns ``(request, error_response)`` - exactly one is not None.
    ``request`` is a dict with at least ``method``; ``error_response``
    is the JSON-RPC error to return immediately (id preserved where
    extractable, null otherwise - deterministic)."""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None, _error(None, PARSE_ERROR, "parse error: invalid JSON")
    if not isinstance(data, dict):
        return None, _error(None, INVALID_REQUEST,
                            "invalid request: JSON-RPC request must be an "
                            "object (batch requests are not supported)")
    rid, _ = _extract_id(data)
    method = data.get("method")
    if not isinstance(method, str) or not method:
        return None, _error(rid, INVALID_REQUEST,
                            "invalid request: missing or non-string method")
    params = data.get("params", {})
    if not isinstance(params, dict):
        return None, _error(rid, INVALID_PARAMS,
                            "invalid params: params must be an object")
    # The "id" key is included ONLY if it was actually in the incoming
    # JSON: a request WITHOUT an id is a notification (never answered).
    request = {"method": method, "params": params}
    if "id" in data:
        request["id"] = data["id"]
    return request, None


class McpServer:
    """The stdio JSON-RPC 2.0 front-end.

    Holds one ``RuntimeSession`` per ``initialize`` call (via the shared
    SessionManager), keyed by session id (S-023 - every execution
    response carries its session identity). Sessions are created only
    through ``initialize``, which runs the real fail-closed
    ``SecurityInitializer``; there is no way to reach the boundary
    without a READY/REFUSED decision.
    """

    def __init__(self) -> None:
        self._manager = SessionManager()

    @property
    def _sessions(self) -> dict:
        """The shared session registry (inspection surface for tests;
        production code never mutates it directly)."""
        return self._manager.sessions

    # -- protocol core ------------------------------------------------------
    def _dispatch(self, method: str, params: dict, request_id):
        if method == METHOD_INITIALIZE:
            return _result(request_id, self._manager.initialize(params))
        if method == METHOD_EXECUTE:
            return _result(request_id, self._manager.execute(params))
        return _error(request_id, METHOD_NOT_FOUND,
                      f"method not found: {method}")

    def handle_line(self, line: str) -> str | None:
        """Process ONE JSON-RPC message line.

        Returns the response JSON string, or None for a notification
        (a request without an id - processed but never answered, per the
        JSON-RPC 2.0 spec). Never raises: malformed input and unexpected
        failures produce deterministic error responses. A workload can
        only ever run through RuntimeSession.execute() - this method has
        no other path to the boundary."""
        request, err = parse_message(line)
        if err is not None:
            return json.dumps(err, sort_keys=True)
        is_notification = "id" not in request
        request_id = request["id"] if not is_notification else None
        try:
            response = self._dispatch(request["method"], request["params"],
                                      request_id)
        except InterfaceParamError as e:
            response = _error(request_id, INVALID_PARAMS,
                              f"invalid params: {e}")
        except Exception:  # noqa: BLE001 - never leak or crash
            response = _error(request_id, INTERNAL_ERROR,
                              _GENERIC_INTERNAL_ERROR)
        if is_notification:
            return None
        try:
            return json.dumps(response, sort_keys=True)
        except Exception:  # noqa: BLE001 - serialization must never crash
            return json.dumps(_error(request_id, INTERNAL_ERROR,
                                     _GENERIC_INTERNAL_ERROR),
                              sort_keys=True)

    # -- transport ----------------------------------------------------------
    def serve(self, stdin=None, stdout=None, stderr=None) -> int:
        """Read JSON-RPC messages from ``stdin`` until EOF, writing ONLY
        responses to ``stdout`` (flushed per message). Diagnostics go to
        ``stderr``. Returns 0 on a clean EOF; never raises."""
        stdin = stdin if stdin is not None else sys.stdin
        stdout = stdout if stdout is not None else sys.stdout
        stderr = stderr if stderr is not None else sys.stderr
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            response = self.handle_line(line)
            if response is None:
                continue  # notification - no response
            try:
                stdout.write(response + "\n")
                stdout.flush()
            except OSError:
                # The peer closed the pipe - terminate deterministically.
                try:
                    stderr.write("agent-sandbox-mcp: output stream closed\n")
                except OSError:  # noqa: BLE001 - nothing left to report
                    pass
                return 0
        return 0


def serve_main() -> int:
    """``python -m agent_sandbox.mcp`` - the stdio MCP server entry
    point. All session parameters (workspace/mode/audit) arrive in the
    ``initialize`` request, so there is nothing to configure on argv."""
    server = McpServer()
    return server.serve()


if __name__ == "__main__":
    sys.exit(serve_main())
