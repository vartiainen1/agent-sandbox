"""Interface phase sub-phase B tests - MCP stdio JSON-RPC 2.0 front-end
(ADR-013, ARCHITECTURE section 16).

Invariants under test:
- The MCP server is a THIN adapter: parse/validate -> common
  ExecutionRequest -> RuntimeSession.execute() -> response. It carries
  no security policy, never calls run_in_sandbox/command_workload, and
  never invokes subprocess/os.system/os.popen/os.execve or a shell.
- Exactly one enforcement execution path: RuntimeSession.execute() ->
  run_in_sandbox(). MCP cannot bypass SecurityInitializer or the
  READY/REFUSED gate; a workload only ever runs through execute().
- JSON-RPC 2.0: id preservation, notifications never answered,
  deterministic errors for malformed JSON (-32700), invalid request
  (-32600), unknown method (-32601), invalid params (-32602), and
  internal failures (-32603, GENERIC message - no host details leak).
- Decision equivalence: for equivalent requests CLI and MCP map to the
  same ExecutionRequest and produce equivalent security decisions and
  payloads (mode + session identity in every outcome).
- Transport: stdin/stdout framing only, stdout carries ONLY responses
  (diagnostics to stderr), EOF terminates cleanly, malformed input
  never crashes the server or enters an alternate execution path.
- Audit (ADR-012): the same host-side recorder correlates MCP
  initialize/execute events to one session; recorder failure is
  observational.

Categories (kept separate, per the charter):
- Host-side tests (protocol, validation, dispatch, equivalence,
  structural no-execution guard) - run everywhere.
- Real-sandbox tests (real initialize + execute of a workspace-provided
  static ELF under the ACTUAL runtime filter through the full boundary)
  - gated on the real namespace+filesystem probes succeeding on this
  substrate (native 24.04 runner: SKIPPED with recorded reason; Docker
  uid 1001: VERIFIED DOCKER).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import unittest.mock

from agent_sandbox import mcp as mcp_mod
from agent_sandbox.audit import (
    EXECUTION_REFUSED,
    EXECUTION_REQUEST,
    EXECUTION_RESULT,
    INIT_DECISION,
    SESSION_CREATED,
    AuditRecorder,
)
from agent_sandbox.models import (
    ExecutionRefused,
    ExecutionResult,
    InitResult,
    SecurityMode,
)
from agent_sandbox.runtime.session import RuntimeSession
from agent_sandbox.security.init import SecurityInitializer

from tests.unit import elf_fixture
from tests.unit import test_cli as tcli
from tests.unit import test_credentials as tc
from tests.unit import test_resources as tr

valid_config = tc.valid_config
skip_unless_linux = tc.skip_unless_linux
_require_fs = tr._require_fs

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

_OK_INIT = InitResult(ok=True, mode=SecurityMode.RESTRICTED,
                      stage=None)
_REFUSED_INIT = InitResult(
    ok=False, mode=SecurityMode.RESTRICTED,
    failure=tcli.InitFailure(code=tcli.InitFailureCode.STAGE_FAILED,
                             stage=None, reason="probe refused (test)"))
_OK_RESULT = ExecutionResult(session_id="sid", mode=SecurityMode.RESTRICTED,
                             exit_code=0, output="OUT")
_REFUSAL = ExecutionRefused(reason="execution refused (test)",
                            state="refused")


def _rpc(method: str, params: dict, rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def _line(method: str, params: dict, rid=1) -> str:
    return json.dumps(_rpc(method, params, rid))


def _init_ok(server: mcp_mod.McpServer, workspace: str,
             mode: str = "restricted", rid=1) -> dict:
    """initialize through the real server code path (SecurityInitializer
    patched) and return the response payload."""
    with unittest.mock.patch.object(
            SecurityInitializer, "initialize", return_value=_OK_INIT):
        resp = json.loads(server.handle_line(
            _line(mcp_mod.METHOD_INITIALIZE,
                  {"workspace": workspace, "mode": mode}, rid)))
    assert "error" not in resp, resp
    return resp["result"]


def _execute(server: mcp_mod.McpServer, session_id: str, command: list,
             rid=2):
    return json.loads(server.handle_line(
        _line(mcp_mod.METHOD_EXECUTE,
              {"session_id": session_id, "command": command}, rid)))


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.server = mcp_mod.McpServer()

    def test_id_preserved_string_and_number(self):
        for rid in ("abc", 7):
            with unittest.mock.patch.object(
                    SecurityInitializer, "initialize",
                    return_value=_OK_INIT):
                resp = json.loads(self.server.handle_line(
                    _line("initialize", {"workspace": "/tmp/x"}, rid)))
            self.assertEqual(resp["id"], rid)
            self.assertNotIn("error", resp)

    def test_notification_produces_no_response(self):
        line = json.dumps({"jsonrpc": "2.0", "method": "initialize",
                           "params": {"workspace": "/tmp/x"}})
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=_OK_INIT):
            resp = self.server.handle_line(line)
        self.assertIsNone(resp)

    def test_malformed_json_parse_error(self):
        resp = json.loads(self.server.handle_line("{not json"))
        self.assertEqual(resp["id"], None)
        self.assertEqual(resp["error"]["code"], mcp_mod.PARSE_ERROR)
        self.assertIn("parse error", resp["error"]["message"])

    def test_non_object_invalid_request(self):
        resp = json.loads(self.server.handle_line("[1, 2, 3]"))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_REQUEST)
        resp = json.loads(self.server.handle_line('"just a string"'))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_REQUEST)

    def test_missing_method_invalid_request(self):
        resp = json.loads(self.server.handle_line(
            '{"jsonrpc":"2.0","id":1,"params":{}}'))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_REQUEST)
        self.assertIn("method", resp["error"]["message"])

    def test_params_not_object_invalid_params(self):
        resp = json.loads(self.server.handle_line(
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":[]}'))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)

    def test_unknown_method_never_executes(self):
        resp = json.loads(self.server.handle_line(
            _line("delete_everything", {"workspace": "/tmp/x"})))
        self.assertEqual(resp["error"]["code"], mcp_mod.METHOD_NOT_FOUND)
        self.assertIn("method not found", resp["error"]["message"])
        self.assertEqual(self.server._sessions, {})
        # A subsequent valid execute has no session to run against.
        resp = json.loads(self.server.handle_line(
            _line("execute", {"session_id": "x", "command": ["/bin/true"]})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)

    def test_internal_error_does_not_leak_details(self):
        workspace = tempfile.mkdtemp(prefix="as-mcp-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        payload = _init_ok(self.server, workspace)
        with unittest.mock.patch.object(
                RuntimeSession, "execute",
                side_effect=RuntimeError("SECRET-HOST-DETAIL-42")):
            resp = _execute(self.server, payload["session_id"],
                            ["/workspace/tool"])
        self.assertEqual(resp["error"]["code"], mcp_mod.INTERNAL_ERROR)
        self.assertEqual(resp["error"]["message"], "internal error")
        self.assertNotIn("SECRET-HOST-DETAIL-42", json.dumps(resp))
        self.assertNotIn("Traceback", json.dumps(resp))


class InitializeTests(unittest.TestCase):
    def setUp(self):
        self.server = mcp_mod.McpServer()
        self.workspace = tempfile.mkdtemp(prefix="as-mcp-ws-")
        self.addCleanup(shutil.rmtree, self.workspace, True)

    def test_initialize_ready(self):
        payload = _init_ok(self.server, self.workspace)
        self.assertEqual(payload["state"], "ready")
        self.assertFalse(payload["refused"])
        self.assertEqual(payload["mode"], "restricted")
        self.assertEqual(len(payload["session_id"]), 32)  # uuid hex (S-023)
        self.assertEqual(payload["reason"], "")
        self.assertEqual(len(self.server._sessions), 1)

    def test_initialize_refused_records_session(self):
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize",
                return_value=_REFUSED_INIT):
            resp = json.loads(self.server.handle_line(
                _line("initialize", {"workspace": self.workspace})))
        payload = resp["result"]
        self.assertEqual(payload["state"], "refused")
        self.assertTrue(payload["refused"])
        self.assertIn("probe refused", payload["reason"])
        # The refused session is still stored so execute reports the
        # REFUSED decision (never silently runs).
        self.assertEqual(len(self.server._sessions), 1)

    def test_missing_workspace_invalid_params(self):
        resp = json.loads(self.server.handle_line(
            _line("initialize", {"mode": "restricted"})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        self.assertIn("workspace", resp["error"]["message"])

    def test_non_string_workspace_invalid_params(self):
        resp = json.loads(self.server.handle_line(
            _line("initialize", {"workspace": 42})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)

    def test_invalid_mode_invalid_params(self):
        resp = json.loads(self.server.handle_line(
            _line("initialize", {"workspace": "/tmp/x",
                                 "mode": "supersafe"})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        self.assertIn("invalid mode", resp["error"]["message"])
        self.assertEqual(self.server._sessions, {})

    def test_relative_workspace_config_error_invalid_params(self):
        # RuntimeConfig requires an absolute workspace - the ConfigError
        # must surface as a deterministic invalid-params error.
        resp = json.loads(self.server.handle_line(
            _line("initialize", {"workspace": "relative/dir"})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        self.assertIn("absolute path", resp["error"]["message"])
        self.assertEqual(self.server._sessions, {})

    def test_bad_audit_type_invalid_params(self):
        resp = json.loads(self.server.handle_line(
            _line("initialize", {"workspace": "/tmp/x", "audit": 42})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        self.assertIn("audit", resp["error"]["message"])


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        self.server = mcp_mod.McpServer()
        self.workspace = tempfile.mkdtemp(prefix="as-mcp-ws-")
        self.addCleanup(shutil.rmtree, self.workspace, True)

    def test_execute_success_result_shape(self):
        payload = _init_ok(self.server, self.workspace)
        with unittest.mock.patch.object(
                RuntimeSession, "execute", return_value=_OK_RESULT) as ex:
            resp = _execute(self.server, payload["session_id"],
                            ["/workspace/tool", "a"])
        result = resp["result"]
        self.assertFalse(result["refused"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["output"], "OUT")
        self.assertFalse(result["truncated"])
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["cleanup_failure"], "")
        self.assertEqual(result["session_id"], payload["session_id"])
        self.assertEqual(result["mode"], "restricted")
        # The common ExecutionRequest reached the sole entry point.
        request = ex.call_args.args[0]
        self.assertEqual(request.command, ("/workspace/tool", "a"))

    def test_execute_refused_distinct_from_error(self):
        payload = _init_ok(self.server, self.workspace)
        with unittest.mock.patch.object(
                RuntimeSession, "execute", return_value=_REFUSAL):
            resp = _execute(self.server, payload["session_id"],
                            ["/workspace/tool"])
        result = resp["result"]
        self.assertTrue(result["refused"])
        self.assertIn("execution refused", result["reason"])
        self.assertEqual(result["state"], "refused")
        self.assertNotIn("error", resp)

    def test_execute_refused_session_via_real_gate(self):
        # initialize refused -> the REAL session gate refuses execute
        # (no execute patching): decision equivalence with the CLI.
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize",
                return_value=_REFUSED_INIT):
            payload = json.loads(self.server.handle_line(
                _line("initialize", {"workspace": self.workspace})))[
                    "result"]
        resp = _execute(self.server, payload["session_id"],
                        ["/workspace/tool"])
        result = resp["result"]
        self.assertTrue(result["refused"])
        self.assertIn("initialization did not succeed", result["reason"])
        self.assertEqual(result["state"], "refused")

    def test_unknown_session_invalid_params(self):
        resp = _execute(self.server, "does-not-exist", ["/workspace/tool"])
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        self.assertIn("unknown session", resp["error"]["message"])

    def test_missing_session_id_invalid_params(self):
        resp = json.loads(self.server.handle_line(
            _line("execute", {"command": ["/workspace/tool"]})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)

    def test_command_validation_invalid_params(self):
        payload = _init_ok(self.server, self.workspace)
        for bad in ([], "not-a-list", ["/workspace/tool", 42],
                    ["/workspace/tool\x00x"]):
            resp = _execute(self.server, payload["session_id"], bad)
            self.assertEqual(resp["error"]["code"],
                             mcp_mod.INVALID_PARAMS, bad)
            self.assertNotIn("result", resp)

    def test_invalid_command_never_reaches_execute(self):
        payload = _init_ok(self.server, self.workspace)
        with unittest.mock.patch.object(
                RuntimeSession, "execute") as ex:
            resp = _execute(self.server, payload["session_id"], [])
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        ex.assert_not_called()


class EquivalenceTests(unittest.TestCase):
    """CLI vs MCP: equivalent requests -> equivalent decisions (ADR-013).

    The shared reference is the same RuntimeSession.execute() outcome:
    both interfaces must surface identical payload fields and must reject
    the same invalid inputs before the boundary is touched."""

    def setUp(self):
        self.workspace = tempfile.mkdtemp(prefix="as-mcp-ws-")
        self.addCleanup(shutil.rmtree, self.workspace, True)

    def test_success_payloads_equivalent(self):
        import agent_sandbox.cli as cli_mod
        result = ExecutionResult(session_id="sid",
                                 mode=SecurityMode.RESTRICTED,
                                 exit_code=0, output="OUT")
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=_OK_INIT):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute", return_value=result):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli_mod.main(["--workspace", self.workspace,
                                         "--json", "--", "/workspace/tool"])
        self.assertEqual(code, 0)
        cli_payload = json.loads(out.getvalue())
        # MCP payload (real server path with execute patched).
        server = mcp_mod.McpServer()
        init = _init_ok(server, self.workspace)
        with unittest.mock.patch.object(
                RuntimeSession, "execute", return_value=result):
            mcp_payload = _execute(
                server, init["session_id"], ["/workspace/tool"])["result"]
        for key in ("mode", "refused", "exit_code", "output", "truncated",
                    "timed_out", "cleanup_failure"):
            self.assertEqual(cli_payload[key], mcp_payload[key], key)
        self.assertFalse(cli_payload["refused"])

    def test_refusal_payloads_equivalent(self):
        import agent_sandbox.cli as cli_mod
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=_OK_INIT):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute", return_value=_REFUSAL):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli_mod.main(["--workspace", self.workspace,
                                         "--json", "--", "/workspace/tool"])
        self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED)
        cli_payload = json.loads(out.getvalue())
        server = mcp_mod.McpServer()
        init = _init_ok(server, self.workspace)
        with unittest.mock.patch.object(
                RuntimeSession, "execute", return_value=_REFUSAL):
            mcp_payload = _execute(
                server, init["session_id"], ["/workspace/tool"])["result"]
        for key in ("mode", "refused", "state", "reason"):
            self.assertEqual(cli_payload[key], mcp_payload[key], key)
        self.assertTrue(cli_payload["refused"])

    def test_invalid_mode_rejected_before_initialization(self):
        import agent_sandbox.cli as cli_mod
        with unittest.mock.patch.object(SecurityInitializer,
                                        "initialize") as init:
            code, _, _ = tcli.CliTests()._run_cli(
                ["--mode", "supersafe", "--workspace", self.workspace,
                 "--", "x"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        init.assert_not_called()
        # MCP: invalid params error, no session created.
        server = mcp_mod.McpServer()
        with unittest.mock.patch.object(SecurityInitializer,
                                        "initialize") as init:
            resp = json.loads(server.handle_line(
                _line("initialize", {"workspace": self.workspace,
                                     "mode": "supersafe"})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        self.assertEqual(server._sessions, {})
        init.assert_not_called()

    def test_invalid_command_rejected_before_execution(self):
        import agent_sandbox.cli as cli_mod
        # CLI: no command after '--' -> usage error (exit 2), no execute.
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=_OK_INIT):
            with unittest.mock.patch.object(RuntimeSession,
                                            "execute") as ex:
                code, _, _ = tcli.CliTests()._run_cli(
                    ["--workspace", self.workspace, "--"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        ex.assert_not_called()
        # MCP: empty argv -> invalid params, no execute.
        server = mcp_mod.McpServer()
        init = _init_ok(server, self.workspace)
        with unittest.mock.patch.object(RuntimeSession, "execute") as ex:
            resp = _execute(server, init["session_id"], [])
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        ex.assert_not_called()

    def test_malformed_input_rejected_without_execution(self):
        server = mcp_mod.McpServer()
        init = _init_ok(server, self.workspace)
        with unittest.mock.patch.object(
                RuntimeSession, "execute",
                return_value=_OK_RESULT) as ex:
            resp = json.loads(server.handle_line("this is not json"))
            self.assertEqual(resp["error"]["code"], mcp_mod.PARSE_ERROR)
            resp = _execute(server, init["session_id"],
                            ["/workspace/tool"])
        self.assertNotIn("error", resp)
        self.assertEqual(ex.call_count, 1)  # only the VALID request ran


class McpAuditTests(unittest.TestCase):
    def test_initialize_and_execute_correlate_events(self):
        workspace = tempfile.mkdtemp(prefix="as-mcp-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        audit_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        server = mcp_mod.McpServer()
        # The REAL session.execute() body records the audit events - only
        # the mechanism probes and run_in_sandbox are patched (same
        # discipline as test_cli's session-correlation test).
        from agent_sandbox.isolation import setup as setup_mod
        with tcli._ready_session_context(None):
            resp = json.loads(server.handle_line(_line(
                "initialize", {"workspace": workspace,
                               "audit": audit_path})))
            self.assertNotIn("error", resp, resp)
            payload = resp["result"]
            self.assertFalse(payload["refused"], payload["reason"])
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    return_value=tcli._fake_sandbox_run(exit_code=3,
                                                        output="FAIL")):
                resp = _execute(server, payload["session_id"],
                                ["/workspace/tool"])
        self.assertEqual(resp["result"]["exit_code"], 3)
        with open(audit_path, encoding="utf-8") as f:
            events = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([e["event"] for e in events],
                         [SESSION_CREATED, INIT_DECISION,
                          EXECUTION_REQUEST, EXECUTION_RESULT])
        for ev in events:
            self.assertEqual(ev["session_id"], payload["session_id"])
        self.assertEqual(events[2]["command"], ["/workspace/tool"])
        self.assertEqual(events[3]["exit_code"], 3)

    def test_refusal_recorded(self):
        workspace = tempfile.mkdtemp(prefix="as-mcp-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        audit_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        server = mcp_mod.McpServer()
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize",
                return_value=_REFUSED_INIT):
            payload = json.loads(server.handle_line(_line(
                "initialize", {"workspace": workspace,
                               "audit": audit_path})))[
                    "result"]
        _execute(server, payload["session_id"], ["/workspace/tool"])
        with open(audit_path, encoding="utf-8") as f:
            events = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([e["event"] for e in events],
                         [SESSION_CREATED, INIT_DECISION,
                          EXECUTION_REFUSED])
        self.assertIn("initialization did not succeed",
                      events[2]["reason"])


class StructuralGuardTests(unittest.TestCase):
    def test_mcp_module_has_no_execution_primitives(self):
        # S-016/S-017 + ADR-013: the MCP front-end must never invoke a
        # host-side execution primitive and must not touch the boundary
        # directly - the ONLY workload path is session.execute(), and it
        # lives in the SHARED core (agent_sandbox.interface) used by both
        # the MCP and API transports.
        import ast
        import inspect
        from agent_sandbox import interface as iface_mod
        for mod in (mcp_mod, iface_mod):
            tree = ast.parse(inspect.getsource(mod))
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "subprocess":
                    self.fail(f"{mod.__name__} must not reference subprocess")
                if isinstance(node, ast.Attribute):
                    if (isinstance(node.value, ast.Name)
                            and node.value.id == "os"
                            and node.attr in ("system", "popen", "execve",
                                              "spawnv", "execl",
                                              "posix_spawn")):
                        self.fail(f"{mod.__name__} must not use "
                                  f"os.{node.attr}")
                    if node.attr == "run_in_sandbox":
                        self.fail(f"{mod.__name__} must not call "
                                  "run_in_sandbox directly")
                    if node.attr == "command_workload":
                        self.fail(f"{mod.__name__} must not build a "
                                  "workload function")
            src = inspect.getsource(mod)
            self.assertNotIn("import subprocess", src)
            self.assertNotIn("from agent_sandbox.execution", src)
        # The shared core is where the sole boundary call lives.
        self.assertIn("session.execute", inspect.getsource(iface_mod))

    def test_execution_only_through_session_execute(self):
        # Functional: every code path that could reach a workload funnels
        # through RuntimeSession.execute - unknown methods, malformed
        # input, and invalid params never create a session or run.
        server = mcp_mod.McpServer()
        with unittest.mock.patch.object(RuntimeSession, "execute") as ex:
            for line in ("garbage", "{}",
                         '{"jsonrpc":"2.0","id":1,"method":"nope"}',
                         _line("execute", {"command": ["/x"]}),
                         _line("initialize", {"workspace": 42})):
                server.handle_line(line)
        ex.assert_not_called()
        self.assertEqual(server._sessions, {})


class ServeTransportTests(unittest.TestCase):
    def test_eof_terminates_cleanly(self):
        server = mcp_mod.McpServer()
        out = io.StringIO()
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=_OK_INIT):
            code = server.serve(stdin=io.StringIO(
                _line("initialize", {"workspace": "/tmp/x"}, 1) + "\n"
                "\n"  # empty line - skipped
                + _line("initialize", {"workspace": "/tmp/x"}, 2) + "\n"),
                stdout=out)
        self.assertEqual(code, 0)
        lines = [json.loads(l) for l in out.getvalue().splitlines() if l]
        self.assertEqual([l["id"] for l in lines], [1, 2])
        for l in lines:
            self.assertIn("result", l)
        self.assertEqual(len(server._sessions), 2)

    def test_stdout_contains_only_responses(self):
        # Diagnostics never mix into stdout (JSON-RPC framing purity).
        server = mcp_mod.McpServer()
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize",
                return_value=_REFUSED_INIT):
            code = server.serve(stdin=io.StringIO(
                _line("initialize", {"workspace": "/tmp/x"}) + "\n"
                + "not json\n"), stdout=out, stderr=err)
        self.assertEqual(code, 0)
        for line in out.getvalue().splitlines():
            json.loads(line)  # every stdout line is a JSON-RPC message


class McpSandboxTests(unittest.TestCase):
    """Real initialize + execute through the complete boundary
    (DOCKER VERIFIED on the uid-1001 container; native runner: SKIPPED
    with recorded reason)."""

    def setUp(self):
        if not LINUX:
            self.skipTest("real sandbox requires Linux")
        _require_fs(self)

    def _workspace_with(self, elf_bytes: bytes, name: str = "tool") -> str:
        src = tempfile.mkdtemp(prefix="as-mcp-ws-")
        tool = pathlib.Path(src) / name
        tool.write_bytes(elf_bytes)
        tool.chmod(0o755)
        return src

    def _real_session(self, workspace: str):
        server = mcp_mod.McpServer()
        # REAL SecurityInitializer (no patching) - fails closed if the
        # substrate cannot establish the boundary.
        resp = json.loads(server.handle_line(
            _line("initialize", {"workspace": workspace,
                                 "mode": "restricted"}, 1)))
        self.assertNotIn("error", resp, resp)
        payload = resp["result"]
        self.assertFalse(payload["refused"], payload["reason"])
        return server, payload

    @skip_unless_linux
    def test_mcp_executes_workload_inside_sandbox(self):
        workspace = self._workspace_with(
            elf_fixture.build_write_exit(b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, workspace, True)
        server, payload = self._real_session(workspace)
        resp = _execute(server, payload["session_id"], ["/workspace/tool"])
        self.assertNotIn("error", resp, resp)
        result = resp["result"]
        self.assertFalse(result["refused"])
        self.assertEqual(result["exit_code"], 0, result["output"])
        self.assertIn("STATIC-ELF-OK", result["output"])
        self.assertEqual(result["cleanup_failure"], "")
        self.assertEqual(result["session_id"], payload["session_id"])
        self.assertEqual(result["mode"], "restricted")

    @skip_unless_linux
    def test_mcp_unavailable_command_deterministic_failure(self):
        workspace = self._workspace_with(
            elf_fixture.build_write_exit(b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, workspace, True)
        server, payload = self._real_session(workspace)
        resp = _execute(server, payload["session_id"],
                        ["/workspace/missing"])
        result = resp["result"]
        self.assertNotEqual(result["exit_code"], 0, result["output"])
        self.assertIn("FAIL workload", result["output"])
        self.assertIn("No such file", result["output"])

    @skip_unless_linux
    def test_mcp_timeout_terminates_session(self):
        # The interface does not expose resource tuning (config-level in
        # v0.1), so the 1s wall clock is injected the same way
        # test_cli's real-path tests do: a config wrapper. The MCP
        # request path (initialize params -> config -> session ->
        # execute) stays completely real.
        workspace = self._workspace_with(elf_fixture.build_hang(),
                                         name="toolhang")
        self.addCleanup(shutil.rmtree, workspace, True)
        real_from_dict = tcli.RuntimeConfig.from_dict

        def short_wall(data):
            data = dict(data)
            resources = dict(tcli.valid_config(workspace)["resources"])
            resources["wall_time_seconds"] = 1
            data["resources"] = resources
            return real_from_dict(data)

        server = mcp_mod.McpServer()
        with unittest.mock.patch.object(
                tcli.RuntimeConfig, "from_dict", side_effect=short_wall):
            resp = json.loads(server.handle_line(_line(
                "initialize", {"workspace": workspace,
                               "mode": "restricted"}, 1)))
        self.assertNotIn("error", resp, resp)
        payload = resp["result"]
        self.assertFalse(payload["refused"], payload["reason"])
        resp = _execute(server, payload["session_id"],
                        ["/workspace/toolhang"])
        result = resp["result"]
        self.assertTrue(result["timed_out"], result["output"])
        self.assertEqual(result["cleanup_failure"], "")

    @skip_unless_linux
    def test_malformed_and_unknown_method_never_execute(self):
        workspace = self._workspace_with(
            elf_fixture.build_write_exit(b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, workspace, True)
        server, payload = self._real_session(workspace)
        # Garbage and an unknown method first - both must error without
        # running anything; the following valid execute still works.
        resp = json.loads(server.handle_line("### not json ###"))
        self.assertEqual(resp["error"]["code"], mcp_mod.PARSE_ERROR)
        resp = json.loads(server.handle_line(
            _line("frobnicate", {"workspace": workspace}, 99)))
        self.assertEqual(resp["error"]["code"], mcp_mod.METHOD_NOT_FOUND)
        resp = _execute(server, payload["session_id"], ["/workspace/tool"])
        self.assertEqual(resp["result"]["exit_code"], 0,
                         resp["result"]["output"])


if __name__ == "__main__":
    unittest.main()
