"""Interface phase sub-phase C tests - HTTP API front-end (ADR-013,
ARCHITECTURE section 16, S-017).

Invariants under test:
- The API is a THIN front-end: HTTP POST -> JSON body -> shared
  SessionManager (agent_sandbox.interface, the SAME core the MCP server
  uses) -> common ExecutionRequest -> RuntimeSession.execute() ->
  run_in_sandbox() -> result/refusal -> JSON response. It carries no
  security policy, never calls run_in_sandbox/command_workload, and
  never invokes subprocess/os.system/os.popen/os.execve or a shell.
- Exactly one enforcement execution path: RuntimeSession.execute() ->
  run_in_sandbox(). The API cannot bypass SecurityInitializer or the
  READY/REFUSED gate; a workload only ever runs through execute().
- Deterministic transport behavior: 200 + machine-readable payload for
  valid requests (refusals are payloads, never disguised as success);
  400 malformed JSON/invalid params/unknown session/invalid argv; 404
  unknown path; 405 wrong method; 413 oversized body; 500 GENERIC
  message for internal failures - no host details leak.
- Decision equivalence ACROSS CLI, MCP and API: for equivalent requests
  all three produce the same payload fields (mode + session identity)
  from the same validated ExecutionRequest / execute() outcome.
- Loopback-only default bind; sessions keyed by session_id (S-023);
  audit (ADR-012) session-correlated and observational.

Categories (kept separate, per the charter):
- Host-side tests (protocol, validation, dispatch, equivalence,
  structural no-execution guard, server lifecycle) - run everywhere.
- Real-sandbox tests (real initialize + execute of a workspace-provided
  static ELF over real HTTP under the ACTUAL runtime filter) - gated on
  the real namespace+filesystem probes succeeding on this substrate
  (native 24.04 runner: SKIPPED with recorded reason; Docker uid 1001:
  VERIFIED DOCKER).
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
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request

from agent_sandbox import api as api_mod
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
from tests.unit import test_mcp as tmcp
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


class _HttpClient:
    """Minimal HTTP client for the tests (stdlib urllib only)."""

    def __init__(self, base: str):
        self.base = base

    def post(self, path: str, payload: dict | None = None,
             raw: bytes | None = None):
        data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def get(self, path: str):
        req = urllib.request.Request(self.base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))


@contextlib.contextmanager
def _api_server(manager=None):
    """Start the REAL ApiServer on an ephemeral loopback port."""
    server = api_mod.make_server("127.0.0.1", 0, manager)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, _HttpClient(f"http://127.0.0.1:{port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def _initialize(client: _HttpClient, workspace: str, mode: str = "restricted"
                ) -> tuple[int, dict]:
    with unittest.mock.patch.object(
            SecurityInitializer, "initialize", return_value=_OK_INIT):
        return client.post("/initialize",
                           {"workspace": workspace, "mode": mode})


def _execute(client: _HttpClient, session_id: str, command: list,
             ) -> tuple[int, dict]:
    return client.post("/execute",
                       {"session_id": session_id, "command": command})


class ApiProtocolTests(unittest.TestCase):
    def test_initialize_and_execute_ok(self):
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            status, payload = _initialize(client, workspace)
            self.assertEqual(status, 200)
            self.assertEqual(payload["state"], "ready")
            self.assertFalse(payload["refused"])
            self.assertEqual(payload["mode"], "restricted")
            self.assertEqual(len(payload["session_id"]), 32)  # uuid hex
            with unittest.mock.patch.object(
                    RuntimeSession, "execute", return_value=_OK_RESULT) as ex:
                status, result = _execute(client, payload["session_id"],
                                          ["/workspace/tool", "a"])
            self.assertEqual(status, 200)
            self.assertFalse(result["refused"])
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["output"], "OUT")
            self.assertEqual(result["session_id"], payload["session_id"])
            request = ex.call_args.args[0]
            self.assertEqual(request.command, ("/workspace/tool", "a"))

    def test_malformed_json_400(self):
        with _api_server() as (server, client):
            status, body = client.post("/initialize", raw=b"{not json")
        self.assertEqual(status, 400)
        self.assertIn("malformed JSON", body["error"]["message"])

    def test_non_object_body_400(self):
        with _api_server() as (server, client):
            status, body = client.post("/execute", raw=b"[1, 2]")
        self.assertEqual(status, 400)
        self.assertIn("must be a JSON object", body["error"]["message"])

    def test_unknown_path_404(self):
        with _api_server() as (server, client):
            status, body = client.post("/delete_everything", {"x": 1})
        self.assertEqual(status, 404)
        self.assertIn("not found", body["error"]["message"])

    def test_get_405(self):
        with _api_server() as (server, client):
            status, body = client.get("/initialize")
        self.assertEqual(status, 405)
        self.assertIn("POST", body["error"]["message"])

    def test_oversized_body_413(self):
        with _api_server() as (server, client):
            status, body = client.post("/execute",
                                       raw=b"x" * (api_mod.MAX_BODY_BYTES + 1))
        self.assertEqual(status, 413)
        self.assertIn("too large", body["error"]["message"])

    def test_internal_error_does_not_leak(self):
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            _, payload = _initialize(client, workspace)
            with unittest.mock.patch.object(
                    RuntimeSession, "execute",
                    side_effect=RuntimeError("SECRET-HOST-DETAIL-42")):
                status, body = _execute(client, payload["session_id"],
                                        ["/workspace/tool"])
        self.assertEqual(status, 500)
        self.assertEqual(body["error"]["message"], "internal error")
        self.assertNotIn("SECRET-HOST-DETAIL-42", json.dumps(body))
        self.assertNotIn("Traceback", json.dumps(body))


class ApiInitializeTests(unittest.TestCase):
    def test_invalid_workspace_400(self):
        with _api_server() as (server, client):
            for bad in ({}, {"workspace": 42}, {"workspace": "rel/dir"}):
                status, body = client.post("/initialize", bad)
                self.assertEqual(status, 400, bad)
                self.assertIn("workspace", body["error"]["message"])

    def test_invalid_mode_400_no_session(self):
        with _api_server() as (server, client):
            with unittest.mock.patch.object(SecurityInitializer,
                                            "initialize") as init:
                status, body = client.post(
                    "/initialize", {"workspace": "/tmp/x",
                                    "mode": "supersafe"})
            self.assertEqual(status, 400)
            self.assertIn("invalid mode", body["error"]["message"])
            self.assertEqual(server.sessions, {})
            init.assert_not_called()

    def test_init_refused_returns_refusal_payload(self):
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            with unittest.mock.patch.object(
                    SecurityInitializer, "initialize",
                    return_value=_REFUSED_INIT):
                status, payload = client.post(
                    "/initialize", {"workspace": workspace})
            self.assertEqual(status, 200)  # valid request; DECISION is refused
            self.assertTrue(payload["refused"])
            self.assertEqual(payload["state"], "refused")
            self.assertIn("probe refused", payload["reason"])
            self.assertEqual(len(server.sessions), 1)


class ApiExecuteTests(unittest.TestCase):
    def test_refusal_distinct_from_error(self):
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            _, payload = _initialize(client, workspace)
            with unittest.mock.patch.object(
                    RuntimeSession, "execute", return_value=_REFUSAL):
                status, result = _execute(client, payload["session_id"],
                                          ["/workspace/tool"])
        self.assertEqual(status, 200)
        self.assertTrue(result["refused"])
        self.assertEqual(result["state"], "refused")
        self.assertIn("execution refused", result["reason"])

    def test_refused_session_via_real_gate(self):
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            with unittest.mock.patch.object(
                    SecurityInitializer, "initialize",
                    return_value=_REFUSED_INIT):
                _, payload = client.post("/initialize",
                                         {"workspace": workspace})
            status, result = _execute(client, payload["session_id"],
                                      ["/workspace/tool"])
        self.assertEqual(status, 200)
        self.assertTrue(result["refused"])
        self.assertIn("initialization did not succeed", result["reason"])

    def test_unknown_session_400(self):
        with _api_server() as (server, client):
            status, body = _execute(client, "does-not-exist",
                                    ["/workspace/tool"])
        self.assertEqual(status, 400)
        self.assertIn("unknown session", body["error"]["message"])

    def test_invalid_command_400_never_reaches_execute(self):
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            _, payload = _initialize(client, workspace)
            with unittest.mock.patch.object(RuntimeSession, "execute") as ex:
                for bad in ({}, {"session_id": payload["session_id"],
                                 "command": []},
                            {"session_id": payload["session_id"],
                             "command": ["/x", 42]},
                            {"session_id": payload["session_id"],
                             "command": "/not-a-list"}):
                    status, body = client.post("/execute", bad)
                    self.assertEqual(status, 400, bad)
            ex.assert_not_called()

    def test_missing_session_id_400(self):
        with _api_server() as (server, client):
            status, body = client.post("/execute", {"command": ["/x"]})
        self.assertEqual(status, 400)
        self.assertIn("session_id", body["error"]["message"])


class ApiEquivalenceTests(unittest.TestCase):
    """CLI vs MCP vs API: equivalent requests -> equivalent decisions
    (ADR-013). All three must surface identical payload fields from the
    same validated ExecutionRequest / RuntimeSession.execute() outcome."""

    def setUp(self):
        self.workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, self.workspace, True)

    def _cli_payload(self, result):
        import agent_sandbox.cli as cli_mod
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=_OK_INIT):
            with unittest.mock.patch.object(RuntimeSession, "execute",
                                            return_value=result):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli_mod.main(["--workspace", self.workspace,
                                         "--json", "--", "/workspace/tool"])
        return code, json.loads(out.getvalue())

    def _mcp_payload(self, result):
        server = mcp_mod.McpServer()
        init = tmcp._init_ok(server, self.workspace)
        with unittest.mock.patch.object(RuntimeSession, "execute",
                                        return_value=result):
            return tmcp._execute(server, init["session_id"],
                                 ["/workspace/tool"])["result"]

    def _api_payload(self, result):
        with _api_server() as (server, client):
            _, init = _initialize(client, self.workspace)
            with unittest.mock.patch.object(RuntimeSession, "execute",
                                            return_value=result):
                status, payload = _execute(client, init["session_id"],
                                           ["/workspace/tool"])
        self.assertEqual(status, 200)
        return payload

    def test_success_equivalent_across_all_three(self):
        result = ExecutionResult(session_id="sid",
                                 mode=SecurityMode.RESTRICTED,
                                 exit_code=0, output="OUT")
        code, cli = self._cli_payload(result)
        mcp = self._mcp_payload(result)
        api = self._api_payload(result)
        self.assertEqual(code, 0)
        for key in ("mode", "refused", "exit_code", "output", "truncated",
                    "timed_out", "cleanup_failure"):
            self.assertEqual(cli[key], mcp[key], f"cli/mcp {key}")
            self.assertEqual(cli[key], api[key], f"cli/api {key}")
        self.assertFalse(cli["refused"])

    def test_refusal_equivalent_across_all_three(self):
        import agent_sandbox.cli as cli_mod
        code, cli = self._cli_payload(_REFUSAL)
        mcp = self._mcp_payload(_REFUSAL)
        api = self._api_payload(_REFUSAL)
        self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED)
        for key in ("mode", "refused", "state", "reason"):
            self.assertEqual(cli[key], mcp[key], f"cli/mcp {key}")
            self.assertEqual(cli[key], api[key], f"cli/api {key}")
        self.assertTrue(cli["refused"])

    def test_invalid_mode_rejected_before_initialization_all_three(self):
        import agent_sandbox.cli as cli_mod
        # CLI: usage error, no init.
        with unittest.mock.patch.object(SecurityInitializer,
                                        "initialize") as init:
            code, _, _ = tcli.CliTests()._run_cli(
                ["--mode", "supersafe", "--workspace", self.workspace,
                 "--", "x"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        init.assert_not_called()
        # MCP: -32602, no session.
        server = mcp_mod.McpServer()
        with unittest.mock.patch.object(SecurityInitializer,
                                        "initialize") as init:
            resp = json.loads(server.handle_line(tmcp._line(
                "initialize", {"workspace": self.workspace,
                               "mode": "supersafe"})))
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        self.assertEqual(server._sessions, {})
        init.assert_not_called()
        # API: 400, no session, no init.
        with _api_server() as (server, client):
            with unittest.mock.patch.object(SecurityInitializer,
                                            "initialize") as init:
                status, body = client.post(
                    "/initialize", {"workspace": self.workspace,
                                    "mode": "supersafe"})
            self.assertEqual(status, 400)
            self.assertEqual(server.sessions, {})
            init.assert_not_called()

    def test_invalid_command_rejected_before_execution_all_three(self):
        import agent_sandbox.cli as cli_mod
        # CLI: no command -> usage, no execute.
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=_OK_INIT):
            with unittest.mock.patch.object(RuntimeSession, "execute") as ex:
                code, _, _ = tcli.CliTests()._run_cli(
                    ["--workspace", self.workspace, "--"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        ex.assert_not_called()
        # MCP: -32602, no execute.
        server = mcp_mod.McpServer()
        init = tmcp._init_ok(server, self.workspace)
        with unittest.mock.patch.object(RuntimeSession, "execute") as ex:
            resp = tmcp._execute(server, init["session_id"], [])
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)
        ex.assert_not_called()
        # API: 400, no execute.
        with _api_server() as (server, client):
            _, payload = _initialize(client, self.workspace)
            with unittest.mock.patch.object(RuntimeSession, "execute") as ex:
                status, _ = _execute(client, payload["session_id"], [])
            self.assertEqual(status, 400)
            ex.assert_not_called()

    def test_malformed_input_never_executes(self):
        with _api_server() as (server, client):
            _, payload = _initialize(client, self.workspace)
            with unittest.mock.patch.object(
                    RuntimeSession, "execute",
                    return_value=_OK_RESULT) as ex:
                status, _ = client.post("/execute", raw=b"not json")
                self.assertEqual(status, 400)
                status, result = _execute(client, payload["session_id"],
                                          ["/workspace/tool"])
                self.assertEqual(status, 200)
            self.assertEqual(ex.call_count, 1)  # only the VALID request ran


class ApiAuditTests(unittest.TestCase):
    def test_initialize_and_execute_correlate_events(self):
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        audit_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        from agent_sandbox.isolation import setup as setup_mod
        with _api_server() as (server, client):
            with tcli._ready_session_context(None):
                status, payload = client.post(
                    "/initialize", {"workspace": workspace,
                                    "audit": audit_path})
                self.assertEqual(status, 200)
                self.assertFalse(payload["refused"], payload["reason"])
                with unittest.mock.patch.object(
                        setup_mod, "run_in_sandbox",
                        return_value=tcli._fake_sandbox_run(exit_code=3,
                                                            output="FAIL")):
                    status, result = _execute(client, payload["session_id"],
                                              ["/workspace/tool"])
                self.assertEqual(result["exit_code"], 3)
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
        workspace = tempfile.mkdtemp(prefix="as-api-ws-")
        self.addCleanup(shutil.rmtree, workspace, True)
        audit_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        with _api_server() as (server, client):
            with unittest.mock.patch.object(
                    SecurityInitializer, "initialize",
                    return_value=_REFUSED_INIT):
                _, payload = client.post(
                    "/initialize", {"workspace": workspace,
                                    "audit": audit_path})
            _execute(client, payload["session_id"], ["/workspace/tool"])
        with open(audit_path, encoding="utf-8") as f:
            events = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([e["event"] for e in events],
                         [SESSION_CREATED, INIT_DECISION,
                          EXECUTION_REFUSED])
        self.assertIn("initialization did not succeed",
                      events[2]["reason"])


class ApiStructuralGuardTests(unittest.TestCase):
    def test_api_and_interface_have_no_execution_primitives(self):
        # S-017 + ADR-013: the API front-end must never invoke a
        # host-side execution primitive and must not touch the boundary
        # directly; the ONLY workload path is session.execute() in the
        # shared core (agent_sandbox.interface), which the API reaches
        # exclusively through the SessionManager.
        import ast
        import inspect
        from agent_sandbox import interface as iface_mod
        for mod in (api_mod, iface_mod):
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
        # The API touches the core ONLY through the shared manager.
        self.assertIn("manager.", inspect.getsource(api_mod))
        self.assertIn("session.execute", inspect.getsource(iface_mod))

    def test_api_imports_no_framework(self):
        # stdlib http.server only - zero new runtime dependencies.
        src = pathlib.Path(api_mod.__file__).read_text(encoding="utf-8")
        self.assertIn("from http.server import", src)
        self.assertNotIn("flask", src.lower())
        self.assertNotIn("fastapi", src.lower())
        self.assertNotIn("aiohttp", src.lower())
        self.assertNotIn("django", src.lower())
        self.assertNotIn("requests", src.lower())


class ApiServerLifecycleTests(unittest.TestCase):
    def test_loopback_default_bind(self):
        server = api_mod.make_server()
        self.assertEqual(server.server_address[0], "127.0.0.1")
        server.server_close()

    def test_serve_shutdown_cleanly(self):
        with _api_server() as (server, client):
            self.assertIsInstance(client, _HttpClient)
        # Exiting the context manager shutdown + closed the server.

    def test_ephemeral_port_and_http_roundtrip(self):
        with _api_server() as (server, client):
            status, body = client.post("/initialize", {"workspace": 42})
            self.assertEqual(status, 400)


class ApiSandboxTests(unittest.TestCase):
    """Real initialize + execute over real HTTP through the complete
    boundary (DOCKER VERIFIED on the uid-1001 container; native runner:
    SKIPPED with recorded reason)."""

    def setUp(self):
        if not LINUX:
            self.skipTest("real sandbox requires Linux")
        _require_fs(self)

    def _workspace_with(self, elf_bytes: bytes, name: str = "tool") -> str:
        src = tempfile.mkdtemp(prefix="as-api-ws-")
        tool = pathlib.Path(src) / name
        tool.write_bytes(elf_bytes)
        tool.chmod(0o755)
        return src

    @skip_unless_linux
    def test_api_executes_workload_inside_sandbox(self):
        workspace = self._workspace_with(
            elf_fixture.build_write_exit(b"HTTP-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            # REAL SecurityInitializer (no patching).
            status, payload = client.post(
                "/initialize", {"workspace": workspace,
                                "mode": "restricted"})
            self.assertEqual(status, 200, payload)
            self.assertFalse(payload["refused"], payload["reason"])
            status, result = _execute(client, payload["session_id"],
                                      ["/workspace/tool"])
        self.assertEqual(status, 200, result)
        self.assertFalse(result["refused"])
        self.assertEqual(result["exit_code"], 0, result["output"])
        self.assertIn("HTTP-ELF-OK", result["output"])
        self.assertEqual(result["cleanup_failure"], "")
        self.assertEqual(result["session_id"], payload["session_id"])
        self.assertEqual(result["mode"], "restricted")

    @skip_unless_linux
    def test_api_unavailable_command_deterministic_failure(self):
        workspace = self._workspace_with(
            elf_fixture.build_write_exit(b"HTTP-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            _, payload = client.post(
                "/initialize", {"workspace": workspace,
                                "mode": "restricted"})
            self.assertFalse(payload["refused"], payload["reason"])
            status, result = _execute(client, payload["session_id"],
                                      ["/workspace/missing"])
        self.assertEqual(status, 200)
        self.assertNotEqual(result["exit_code"], 0, result["output"])
        self.assertIn("FAIL workload", result["output"])
        self.assertIn("No such file", result["output"])

    @skip_unless_linux
    def test_api_timeout_terminates_session(self):
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

        with _api_server() as (server, client):
            with unittest.mock.patch.object(
                    tcli.RuntimeConfig, "from_dict",
                    side_effect=short_wall):
                status, payload = client.post(
                    "/initialize", {"workspace": workspace,
                                    "mode": "restricted"})
            self.assertEqual(status, 200, payload)
            self.assertFalse(payload["refused"], payload["reason"])
            status, result = _execute(client, payload["session_id"],
                                      ["/workspace/toolhang"])
        self.assertEqual(status, 200)
        self.assertTrue(result["timed_out"], result["output"])
        self.assertEqual(result["cleanup_failure"], "")

    @skip_unless_linux
    def test_bad_requests_never_execute_over_http(self):
        workspace = self._workspace_with(
            elf_fixture.build_write_exit(b"HTTP-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, workspace, True)
        with _api_server() as (server, client):
            _, payload = client.post(
                "/initialize", {"workspace": workspace,
                                "mode": "restricted"})
            self.assertFalse(payload["refused"], payload["reason"])
            status, body = client.post("/execute", raw=b"###")
            self.assertEqual(status, 400)
            status, body = client.post("/frobnicate", {"x": 1})
            self.assertEqual(status, 404)
            status, body = client.get("/execute")
            self.assertEqual(status, 405)
            # A valid follow-up still executes (no poisoning).
            status, result = _execute(client, payload["session_id"],
                                      ["/workspace/tool"])
        self.assertEqual(status, 200)
        self.assertEqual(result["exit_code"], 0, result["output"])
        self.assertIn("HTTP-ELF-OK", result["output"])


if __name__ == "__main__":
    unittest.main()
