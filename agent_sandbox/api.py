"""Thin HTTP API front-end (ADR-013, interface phase sub-phase C).

The API carries NO security policy and NO enforcement logic. It is a thin
adapter over the single enforcement core - the session/request logic is
shared with the MCP server in ``agent_sandbox.interface``:

    HTTP POST /initialize | /execute
        -> JSON body -> SessionManager.initialize/execute (shared w/ MCP)
        -> common ExecutionRequest
        -> RuntimeSession.execute()      (the READY/REFUSED gate)
        -> run_in_sandbox()              (the only boundary path)
        -> ExecutionResult / ExecutionRefused
        -> JSON response

There is NO other execution path: this module never calls
``run_in_sandbox``, never builds a workload function, never invokes
subprocess/os.system/os.popen/os.execve, and never interprets a shell
string. ``command`` stays an ARGUMENT VECTOR passed verbatim into the
sandbox (S-016/S-017, S-017 = the API cannot bypass).

Transport (stdlib ``http.server`` - ZERO runtime dependencies, consistent
with the project's TCB posture; no framework is required by the
architecture and none is introduced):

- ``POST /initialize``  body {workspace, mode?, audit?} -> the
  machine-readable decision {session_id, mode, state, refused, reason}.
- ``POST /execute``     body {session_id, command: [argv...]} -> the
  result {session_id, mode, state, refused, exit_code, output,
  truncated, timed_out, cleanup_failure} or the refusal
  {refused: True, reason} - a refusal is never disguised as success
  (HTTP 200: the request was valid and processed; the DECISION is the
  payload, identical to the CLI/MCP payloads).
- Anything else: 404 (unknown path) / 405 (wrong method).

Deterministic errors (JSON body ``{"error": {"code", "message"}}``):
- 400 malformed JSON / invalid params / unknown session / invalid argv
  (messages identical to the MCP -32602 messages; never leak internals)
- 413 request body over the 1 MiB cap (transport robustness)
- 500 unexpected failure with the FIXED generic message - never a
  traceback, type name, environment value, credential, or internal path

Binding (v0.1 posture, documented - NOT invented policy): the server
binds 127.0.0.1 (loopback) BY DEFAULT. The interfaces are host-side
supervisor surfaces, not the security boundary (ARCHITECTURE section
16); there is no authentication layer in v0.1 (none is specified by the
architecture, consistent with the local CLI/MCP trust model), so the
loopback default is the containment. Binding to a non-loopback address
is an explicit operator choice and requires a separate review - the
server never does it implicitly.

Audit (ADR-012): the optional ``audit`` path on ``initialize`` attaches
the same host-side JSONL recorder; events are session-correlated and
observational (recorder failure never blocks or alters execution).

Import safety: stdlib only; nothing Linux-specific at import time.

Trust boundary: this module is TRUSTED supervisor code. The workload
runs inside the isolated environment, never here.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agent_sandbox.interface import InterfaceParamError, SessionManager

# Endpoints (the minimum surface - exactly the shared request model).
PATH_INITIALIZE = "/initialize"
PATH_EXECUTE = "/execute"

# Transport robustness: a local peer cannot make the supervisor buffer an
# unbounded request body (the command argv is the only large input and
# it is bounded by the workload contract; 1 MiB is far beyond any sane
# argv). Not a security policy - a resource bound on the transport.
MAX_BODY_BYTES = 1 << 20  # 1 MiB

# Fixed generic message for unexpected failures - never leaks host
# exception details, environment, credentials, or internal paths.
_GENERIC_INTERNAL_ERROR = "internal error"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


class _ApiHandler(BaseHTTPRequestHandler):
    """One HTTP request. Thin: routes to the shared SessionManager and
    frames the response. Never raises out of the request (deterministic
    error responses; malformed input cannot crash the server or reach
    the boundary through any path other than execute())."""

    # Silence the default one-line-per-request stderr log? NO - keep the
    # default (stderr diagnostics are fine; responses go to the socket).

    # -- helpers ------------------------------------------------------------
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass  # peer closed - nothing to report

    def _read_body(self) -> bytes | None:
        """Read the request body up to MAX_BODY_BYTES. Returns None and
        sends a 413 when the body exceeds the cap.

        On an oversized body the in-flight bytes are DRAINED first (up to
        MAX_BODY_BYTES+1, bounded) so the 413 is delivered deterministically
        instead of racing the peer's remaining write against the connection
        close. A hostile huge body is never buffered unbounded - bounded
        work, then 413 + close."""
        length = self.headers.get("Content-Length")
        try:
            n = int(length) if length is not None else 0
        except ValueError:
            n = 0
        if n < 0 or n > MAX_BODY_BYTES:
            try:
                self.rfile.read(MAX_BODY_BYTES + 1)
            except OSError:
                pass  # peer gone - the 413 below is best-effort
            self._send_json(413, {"error": {
                "code": 413,
                "message": "request body too large (limit 1 MiB)"}})
            return None
        try:
            return self.rfile.read(n)
        except OSError:
            self._send_json(500, {"error": {
                "code": 500, "message": _GENERIC_INTERNAL_ERROR}})
            return None

    def _handle(self) -> None:
        # Dispatch is THIN: only the two shared endpoints exist.
        if self.path != PATH_INITIALIZE and self.path != PATH_EXECUTE:
            self._send_json(404, {"error": {
                "code": 404, "message": f"not found: {self.path}"}})
            return

        raw = self._read_body()
        if raw is None:
            return  # 413/500 already sent
        try:
            params = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": {
                "code": 400, "message": "malformed JSON request body"}})
            return
        if not isinstance(params, dict):
            self._send_json(400, {"error": {
                "code": 400, "message": "request body must be a JSON "
                "object"}})
            return

        manager: SessionManager = self.server.manager  # type: ignore[attr-defined]
        try:
            if self.path == PATH_INITIALIZE:
                payload = manager.initialize(params)
            else:
                payload = manager.execute(params)
        except InterfaceParamError as e:
            self._send_json(400, {"error": {"code": 400,
                                            "message": str(e)}})
            return
        except Exception:
            self._send_json(500, {"error": {"code": 500,
                                            "message": _GENERIC_INTERNAL_ERROR}})
            return
        self._send_json(200, payload)

    # -- methods ------------------------------------------------------------
    def do_POST(self) -> None:
        self._handle()

    def do_GET(self) -> None:
        self._send_json(405, {"error": {
            "code": 405,
            "message": "method not allowed (use POST)"}})

    def log_message(self, fmt, *args) -> None:
        # Keep the default access-log behavior on stderr (diagnostics
        # never mix into the HTTP response stream).
        super().log_message(fmt, *args)


class ApiServer(ThreadingHTTPServer):
    """The HTTP front-end. ``manager`` is the shared SessionManager;
    daemon threads so a stuck peer cannot block shutdown."""

    daemon_threads = True

    def __init__(self, host: str, port: int,
                 manager: SessionManager | None = None) -> None:
        self.manager = manager if manager is not None else SessionManager()
        super().__init__((host, port), _ApiHandler)

    @property
    def sessions(self) -> dict:
        """The shared session registry (inspection surface)."""
        return self.manager.sessions


def make_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                manager: SessionManager | None = None) -> ApiServer:
    """Create (but do not start) the API server. ``host`` defaults to
    loopback (v0.1 posture - see the module docstring)."""
    return ApiServer(host, port, manager)


def serve_main(argv: list[str] | None = None) -> int:
    """``python -m agent_sandbox.api`` - the HTTP API server entry
    point. Binds loopback by default; blocks until interrupted."""
    parser = argparse.ArgumentParser(
        prog="agent-sandbox-api",
        description="agent-sandbox HTTP API (thin front-end over the "
                    "sole execution path; binds loopback by default)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"bind address (default: {DEFAULT_HOST} - "
                             "loopback only; non-loopback binding requires "
                             "explicit operator review, there is no auth "
                             "layer in v0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"bind port (default: {DEFAULT_PORT})")
    args = parser.parse_args(argv)

    server = make_server(args.host, args.port)
    host, port = server.server_address[:2]
    print(f"agent-sandbox-api: listening on {host}:{port} "
          "(initialize -> /initialize, execute -> /execute)",
          file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(serve_main())
