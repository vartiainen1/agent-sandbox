"""Interface phase sub-phase A tests - CLI + execution bridge + minimal
audit (ADR-013, ADR-012, ARCHITECTURE section 16).

Invariants under test:
- Exactly ONE enforcement execution path: RuntimeSession.execute() ->
  run_in_sandbox(). CLI/MCP must never invoke subprocess(), os.system(),
  host-side execve(), or a shell as a fallback.
- Interface code carries no security policy and cannot bypass
  SecurityInitializer or the READY/REFUSED gate.
- REFUSED, execution failure, and successful execution are distinct
  machine-readable outcomes; --json exposes mode + session identity.
- Commands are ARGV VECTORS (never shell strings); shell metacharacters
  are data, never interpreted.
- The execve bridge runs the command INSIDE the sandbox: stdout/stderr
  and exit status continue through the Step 13-15 bounded-output,
  timeout, and process-tree machinery; the sanitized six-variable
  environment is in force at execve time; unavailable commands fail
  deterministically with NO host fallback.
- Audit (ADR-012): host-side JSONL, session-correlated, observational -
  a recorder failure never blocks or alters execution.

Categories (kept separate, per the charter):
- Host-side tests (request model, execute mapping/gate, audit, CLI
  parsing/exit codes, structural no-subprocess guard) - run everywhere.
- Real-sandbox tests (real execve of a workspace-provided static ELF
  under the ACTUAL runtime filter through the full boundary) - gated on
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
import unittest
import unittest.mock

from agent_sandbox import cli as cli_mod
from agent_sandbox.audit import (
    EXECUTION_REFUSED,
    EXECUTION_REQUEST,
    EXECUTION_RESULT,
    INIT_DECISION,
    POLICY_DECISION,
    POLICY_LOADED,
    SESSION_CREATED,
    AuditRecorder,
)
from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import setup as setup_mod
from agent_sandbox.models import (
    ExecutionRefused,
    ExecutionRequest,
    ExecutionResult,
    InitFailure,
    InitFailureCode,
    InitResult,
    SecurityMode,
    StageCheck,
)
from agent_sandbox.runtime import session as session_mod
from agent_sandbox.runtime.session import RuntimeSession, SessionState
from agent_sandbox.security import init as init_mod
from agent_sandbox.security.init import SecurityInitializer
from tests.unit import elf_fixture
from tests.unit import test_credentials as tc
from tests.unit import test_resources as tr

valid_config = tc.valid_config
skip_unless_linux = tc.skip_unless_linux
_require_fs = tr._require_fs

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

# The approved six-variable environment (Step 11 policy).
EXPECTED_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/home",
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
}


def _fake_sandbox_run(exit_code=0, output="", truncated=False,
                      timed_out=False, cleanup_failure=""):
    """A stand-in SandboxRun for execute()-mapping tests."""
    return setup_mod.SandboxRun(
        exit_code=exit_code, output=output, truncated=truncated,
        timed_out=timed_out, cleanup_failure=cleanup_failure)


@contextlib.contextmanager
def _ready_session_context(config):
    """Patch the platform seams + all mechanism probes to PASS so a
    session initializes to READY deterministically on any host (the
    REAL probes are exercised by the real-chain and sandbox tests)."""
    patches = [
        unittest.mock.patch.object(init_mod, "_is_linux", return_value=True),
        unittest.mock.patch.object(session_mod, "_can_fork", return_value=True),
        unittest.mock.patch.object(
            setup_mod, "_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
        unittest.mock.patch.object(
            setup_mod, "_filesystem_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
        unittest.mock.patch.object(
            setup_mod, "_network_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
        unittest.mock.patch.object(
            setup_mod, "_privileges_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
        unittest.mock.patch.object(
            setup_mod, "_seccomp_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
        unittest.mock.patch.object(
            setup_mod, "_resources_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
        unittest.mock.patch.object(
            setup_mod, "_environment_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
        unittest.mock.patch.object(
            setup_mod, "_execution_probe_impl",
            return_value=StageCheck(ok=True, reason="probe ok (test)")),
    ]
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in patches:
            p.stop()


def _make_workspace(elf_name: str, elf_bytes: bytes, marker: str = "x\n"
                    ) -> str:
    """A real workspace source dir containing one executable fixture."""
    src = tempfile.mkdtemp(prefix="as-cli-ws-")
    (pathlib.Path(src) / "marker.txt").write_text(marker)
    tool = pathlib.Path(src) / elf_name
    tool.write_bytes(elf_bytes)
    tool.chmod(0o755)
    return src


class RequestValidationTests(unittest.TestCase):
    def test_valid_request_accepted(self):
        r = ExecutionRequest(command=("/workspace/tool", "a", "b"))
        self.assertEqual(r.command, ("/workspace/tool", "a", "b"))

    def test_empty_command_rejected(self):
        with self.assertRaises(Exception) as cm:
            ExecutionRequest(command=())
        self.assertIn("empty command", str(cm.exception))

    def test_nul_byte_rejected(self):
        with self.assertRaises(Exception) as cm:
            ExecutionRequest(command=("/workspace/tool\x00x",))
        self.assertIn("NUL", str(cm.exception))

    def test_non_string_argv_rejected(self):
        with self.assertRaises(Exception):
            ExecutionRequest(command=("/workspace/tool", 42))

    def test_interface_modules_have_no_shell_or_subprocess(self):
        # Structural guard (S-016/S-017), AST-based so docstrings and
        # comments are ignored: the interface + session code must never
        # import/use subprocess, os.system, os.popen, or os.execve; the
        # ONLY execve is the approved bridge inside execution/__init__.py
        # (and it is only ever CALLED from inside the sandbox).
        import ast
        import inspect

        def uses_forbidden(tree, allowed_execve=False):
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "subprocess":
                    return "subprocess"
                if isinstance(node, ast.Attribute):
                    if (isinstance(node.value, ast.Name)
                            and node.value.id == "os"
                            and node.attr in ("system", "popen", "spawnv",
                                              "execv", "execl", "posix_spawn")):
                        return f"os.{node.attr}"
                    if (isinstance(node.value, ast.Name)
                            and node.value.id == "os"
                            and node.attr in ("execve", "execvpe")
                            and not allowed_execve):
                        return f"os.{node.attr}"
            return None

        from agent_sandbox import cli as _cli
        from agent_sandbox import execution as _exec
        from agent_sandbox.runtime import session as _session
        for mod in (_cli, _session):
            tree = ast.parse(inspect.getsource(mod))
            self.assertIsNone(uses_forbidden(tree),
                              f"{mod.__name__} must not use a host-side "
                              "execution primitive")
        exec_tree = ast.parse(inspect.getsource(_exec))
        self.assertIsNone(uses_forbidden(exec_tree, allowed_execve=True),
                          "execution module must only use the approved "
                          "os.execvpe bridge")
        self.assertIn("os.execvpe", inspect.getsource(_exec))


class SessionExecuteTests(unittest.TestCase):
    def _session(self, mode="restricted", workspace=None, audit=None):
        if workspace is None:
            workspace = _make_workspace("tool", b"\x00")
        cfg = RuntimeConfig.from_dict(valid_config(workspace, mode=mode))
        return RuntimeSession(cfg, audit=audit)

    def test_ready_session_executes_through_run_in_sandbox(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(workspace=src)
        fake = _fake_sandbox_run(exit_code=0, output="OUT")
        with _ready_session_context(None):
            self.assertTrue(session.initialize().ok)
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox", return_value=fake) as ris:
                outcome = session.execute(
                    ExecutionRequest(command=("/workspace/tool", "a")))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.output, "OUT")
        self.assertFalse(outcome.truncated)
        self.assertFalse(outcome.timed_out)
        self.assertEqual(outcome.cleanup_failure, "")
        self.assertEqual(outcome.session_id, session.session_id)
        self.assertIs(outcome.mode, SecurityMode.RESTRICTED)
        # The single boundary call received the execve bridge + the
        # session's limits + the approved env allowlist.
        ris.assert_called_once()
        self.assertTrue(callable(ris.call_args.args[0]),
                        "the workload fn must be the execve bridge")
        kwargs = ris.call_args.kwargs
        self.assertEqual(kwargs["env_allowlist"],
                         ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR"))
        self.assertIs(kwargs["limits"], session.config.resources)

    def test_result_mapping_carries_enforcement_state(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(workspace=src)
        fake = _fake_sandbox_run(exit_code=1, output="O",
                                 truncated=True, timed_out=True,
                                 cleanup_failure="survivor (S-038)")
        with _ready_session_context(None):
            session.initialize()
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox", return_value=fake):
                outcome = session.execute(
                    ExecutionRequest(command=("/workspace/tool",)))
        self.assertEqual(outcome.exit_code, 1)
        self.assertTrue(outcome.truncated)
        self.assertTrue(outcome.timed_out)
        self.assertEqual(outcome.cleanup_failure, "survivor (S-038)")

    def test_refused_session_never_reaches_run_in_sandbox(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(workspace=src)
        with _ready_session_context(None):
            # Inject a namespace-probe failure -> REFUSED.
            with unittest.mock.patch.object(
                    setup_mod, "_probe_impl",
                    return_value=StageCheck(
                        ok=False, reason="probe failed (test)")):
                result = session.initialize()
            self.assertFalse(result.ok)
            self.assertIs(session.state, SessionState.REFUSED)
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox") as ris:
                refusal = session.execute(
                    ExecutionRequest(command=("/workspace/tool",)))
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertIn("initialization did not succeed", refusal.reason)
        self.assertEqual(refusal.state, "refused")
        ris.assert_not_called()

    def test_uninitialized_session_refused(self):
        session = self._session(workspace=_make_workspace("t", b"\x00"))
        with unittest.mock.patch.object(
                setup_mod, "run_in_sandbox") as ris:
            refusal = session.execute(
                ExecutionRequest(command=("/workspace/tool",)))
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertEqual(refusal.state, "uninitialized")
        ris.assert_not_called()

    def test_unsupported_platform_refused(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(workspace=src)
        with _ready_session_context(None):
            session.initialize()
            with unittest.mock.patch.object(
                    session_mod, "_can_fork", return_value=False):
                with unittest.mock.patch.object(
                        setup_mod, "run_in_sandbox") as ris:
                    refusal = session.execute(
                        ExecutionRequest(command=("/workspace/tool",)))
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertIn("requires Linux with os.fork", refusal.reason)
        ris.assert_not_called()

    def test_setup_failure_refused_workload_never_runs(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(workspace=src)
        from agent_sandbox.isolation import rootfs as rootfs_mod
        from agent_sandbox.isolation.errors import NamespaceSetupError
        with _ready_session_context(None):
            session.initialize()
            with unittest.mock.patch.object(
                    rootfs_mod, "build_rootfs",
                    side_effect=NamespaceSetupError("rootfs build failed "
                                                    "(test)")):
                with unittest.mock.patch.object(
                        setup_mod, "run_in_sandbox") as ris:
                    refusal = session.execute(
                        ExecutionRequest(command=("/workspace/tool",)))
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertIn("execution setup failed", refusal.reason)
        self.assertIn("fail closed", refusal.reason)
        ris.assert_not_called()

    def test_unexpected_mechanism_exception_fails_closed(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(workspace=src)
        with _ready_session_context(None):
            session.initialize()
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=RuntimeError("boom")):
                refusal = session.execute(
                    ExecutionRequest(command=("/workspace/tool",)))
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertIn("execution mechanism failed", refusal.reason)
        self.assertIn("fail closed", refusal.reason)


class AuditTests(unittest.TestCase):
    def test_recorder_writes_jsonl(self):
        path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        rec = AuditRecorder(path)
        self.assertTrue(rec.record("s1", SESSION_CREATED, mode="restricted"))
        self.assertTrue(rec.record("s1", INIT_DECISION, ok=True))
        with open(path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(lines), 2)
        for ev in lines:
            self.assertEqual(ev["session_id"], "s1")
            self.assertIn("ts", ev)
        self.assertEqual(lines[0]["event"], SESSION_CREATED)
        self.assertEqual(lines[0]["mode"], "restricted")
        self.assertTrue(lines[1]["ok"])

    def test_recorder_failure_is_observational(self):
        rec = AuditRecorder(os.path.join(
            tempfile.mkdtemp(), "no-such-dir", "audit.jsonl"))
        self.assertFalse(rec.record("s1", SESSION_CREATED))  # no raise

    def test_session_correlates_events(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        audit_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        session = RuntimeSession(
            RuntimeConfig.from_dict(valid_config(src, mode="restricted")),
            audit=AuditRecorder(audit_path))
        with _ready_session_context(None):
            session.initialize()
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    return_value=_fake_sandbox_run(exit_code=0,
                                                   output="OUT")):
                session.execute(ExecutionRequest(command=("/workspace/t",)))
        with open(audit_path, encoding="utf-8") as f:
            events = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([e["event"] for e in events],
                         [SESSION_CREATED, POLICY_LOADED, INIT_DECISION,
                          POLICY_DECISION, EXECUTION_REQUEST,
                          EXECUTION_RESULT])
        for ev in events:
            self.assertEqual(ev["session_id"], session.session_id)
        self.assertEqual(events[4]["command"], ["/workspace/t"])
        self.assertEqual(events[5]["exit_code"], 0)

    def test_refusal_recorded(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        audit_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        session = RuntimeSession(
            RuntimeConfig.from_dict(valid_config(src, mode="restricted")),
            audit=AuditRecorder(audit_path))
        # No initialize: UNINITIALIZED -> refused.
        session.execute(ExecutionRequest(command=("/workspace/t",)))
        with open(audit_path, encoding="utf-8") as f:
            events = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([e["event"] for e in events],
                         [EXECUTION_REFUSED])
        self.assertIn("initialization did not succeed",
                      events[0]["reason"])

    def test_audit_failure_does_not_block_execution(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        # Recorder pointing into a nonexistent directory: every record
        # fails - execution must still proceed (observation only,
        # S-024; no alternate path).
        session = RuntimeSession(
            RuntimeConfig.from_dict(valid_config(src, mode="restricted")),
            audit=AuditRecorder(os.path.join(
                tempfile.mkdtemp(), "missing", "audit.jsonl")))
        with _ready_session_context(None):
            session.initialize()
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    return_value=_fake_sandbox_run(exit_code=0,
                                                   output="OUT")):
                outcome = session.execute(
                    ExecutionRequest(command=("/workspace/t",)))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertEqual(outcome.exit_code, 0)

    def test_recorder_open_per_record_no_persistent_fd(self):
        # ADR-012: no audit fd may ever be open across the fork boundary
        # (the workload must not inherit a handle on the audit stream).
        path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        rec = AuditRecorder(path)
        with unittest.mock.patch("builtins.open",
                                 wraps=open) as m:
            rec.record("s1", SESSION_CREATED)
            rec.record("s1", INIT_DECISION)
        # Two records -> two opens (append), each closed after writing.
        self.assertEqual(m.call_count, 2)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err):
            code = cli_mod.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_no_command_usage_error(self):
        code, _, err = self._run_cli(["--workspace", "/tmp"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        self.assertIn("no command", err)

    def test_unknown_command_shows_usage(self):
        code, _, err = self._run_cli(["nonexistent"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        self.assertIn("unknown command", err)
        self.assertIn("commands:", err)

    def test_no_args_shows_usage(self):
        code, _, err = self._run_cli([])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        self.assertIn("commands:", err)

    def test_version_long_flag(self):
        from agent_sandbox import __version__
        code, out, _ = self._run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)
        self.assertIn("agent-sandbox", out)

    def test_version_short_flag(self):
        from agent_sandbox import __version__
        code, out, _ = self._run_cli(["-V"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

    def test_help_top_level_shows_usage(self):
        code, _, err = self._run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("commands:", err)
        self.assertIn("--version", err)

    def test_help_short_flag_shows_usage(self):
        code, _, err = self._run_cli(["-h"])
        self.assertEqual(code, 0)
        self.assertIn("commands:", err)

    def test_invalid_mode_usage_error(self):
        code, _, _ = self._run_cli(["--mode", "supersafe",
                                    "--workspace", "/tmp", "--", "x"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)

    def test_list_empty_sessions(self):
        base = tempfile.mkdtemp(prefix="as-list-")
        self.addCleanup(shutil.rmtree, base, True)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err):
            code = cli_mod.main(["list"], state_dir=base)
        self.assertEqual(code, 0)
        self.assertIn("no sessions found", out.getvalue())

    def test_list_json_empty(self):
        base = tempfile.mkdtemp(prefix="as-list-")
        self.addCleanup(shutil.rmtree, base, True)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err):
            code = cli_mod.main(["list", "--json"], state_dir=base)
        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["sessions"], [])

    def test_init_refused_exit_3(self):
        refused = InitResult(
            ok=False, mode=SecurityMode.RESTRICTED,
            failure=InitFailure(code=InitFailureCode.STAGE_FAILED,
                                stage=None, reason="probe refused (test)"))
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=refused):
            code, out, _ = self._run_cli(
                ["--workspace", src, "--json", "--", "/workspace/tool"])
        self.assertEqual(code, cli_mod.EXIT_INIT_REFUSED)
        payload = json.loads(out)
        self.assertTrue(payload["refused"])
        self.assertEqual(payload["mode"], "restricted")
        self.assertEqual(payload["state"], "refused")
        self.assertIn("session_id", payload)

    def test_execution_refused_exit_4(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        ok = InitResult(ok=True, mode=SecurityMode.RESTRICTED,
                        stage=None)
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=ok):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute",
                    return_value=ExecutionRefused(
                        reason="execution setup failed: x - fail closed, "
                               "workload not executed",
                        state="ready")):
                code, out, _ = self._run_cli(
                    ["--workspace", src, "--json", "--",
                     "/workspace/tool"])
        self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED)
        payload = json.loads(out)
        self.assertTrue(payload["refused"])
        self.assertEqual(payload["state"], "ready")
        self.assertIn("fail closed", payload["reason"])

    def test_workload_exit_code_propagates(self):
        src = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, src, True)
        ok = InitResult(ok=True, mode=SecurityMode.RESTRICTED,
                        stage=None)
        result = ExecutionResult(session_id="sid123",
                                 mode=SecurityMode.RESTRICTED,
                                 exit_code=7, output="HELLO")
        with unittest.mock.patch.object(
                SecurityInitializer, "initialize", return_value=ok):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute", return_value=result):
                code, out, _ = self._run_cli(
                    ["--workspace", src, "--json", "--",
                     "/workspace/tool"])
        self.assertEqual(code, 7)
        payload = json.loads(out)
        self.assertFalse(payload["refused"])
        self.assertEqual(payload["exit_code"], 7)
        self.assertEqual(payload["output"], "HELLO")
        # The CLI reports the REAL session identity (S-023) - a uuid
        # hex string - not the patched result's value.
        self.assertEqual(len(payload["session_id"]), 32)
        self.assertEqual(payload["mode"], "restricted")


class CliSandboxTests(unittest.TestCase):
    """Real execve through the complete boundary (DOCKER VERIFIED on the
    uid-1001 container; native runner: SKIPPED with recorded reason)."""

    def setUp(self):
        if not LINUX:
            self.skipTest("real sandbox requires Linux")
        _require_fs(self)

    def _session(self, workspace: str, resources_overrides=None):
        cfg_data = valid_config(workspace, mode="restricted")
        if resources_overrides:
            cfg_data["resources"] = dict(cfg_data["resources"])
            cfg_data["resources"].update(resources_overrides)
        session = RuntimeSession(RuntimeConfig.from_dict(cfg_data))
        result = session.initialize()
        self.assertTrue(result.ok, result.describe())
        return session

    @skip_unless_linux
    def test_cli_command_executes_inside_sandbox(self):
        src = _make_workspace("tool", elf_fixture.build_write_exit(
            b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(src)
        outcome = session.execute(
            ExecutionRequest(command=("/workspace/tool",)))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertEqual(outcome.exit_code, 0, outcome.output)
        self.assertIn("STATIC-ELF-OK", outcome.output)
        self.assertFalse(outcome.truncated)
        self.assertFalse(outcome.timed_out)
        self.assertEqual(outcome.cleanup_failure, "")

    @skip_unless_linux
    def test_exit_status_propagates(self):
        src = _make_workspace("tool42", elf_fixture.build_write_exit(
            b"EXIT-42\n", 42))
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(src)
        outcome = session.execute(
            ExecutionRequest(command=("/workspace/tool42",)))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertEqual(outcome.exit_code, 42, outcome.output)
        self.assertIn("EXIT-42", outcome.output)

    @skip_unless_linux
    def test_unavailable_command_deterministic_failure_no_fallback(self):
        src = _make_workspace("tool", elf_fixture.build_write_exit(
            b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(src)
        outcome = session.execute(
            ExecutionRequest(command=("/workspace/missing",)))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertNotEqual(outcome.exit_code, 0, outcome.output)
        self.assertIn("FAIL workload", outcome.output)
        self.assertIn("No such file", outcome.output)

    @skip_unless_linux
    def test_shell_metacharacters_not_interpreted(self):
        # argv is data: "; rm -rf /" must be passed verbatim as a plain
        # argument - no shell exists anywhere in the path (the fixture
        # ignores argv and still succeeds).
        src = _make_workspace("tool", elf_fixture.build_write_exit(
            b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(src)
        outcome = session.execute(ExecutionRequest(
            command=("/workspace/tool", ";", "rm", "-rf", "/")))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertEqual(outcome.exit_code, 0, outcome.output)
        self.assertIn("STATIC-ELF-OK", outcome.output)

    @skip_unless_linux
    def test_sanitized_environment_in_force_at_execve(self):
        # The exec'd command walks its own envp: it must see EXACTLY
        # the approved six variables with the approved values (S-034) -
        # no host variable can leak into the exec'd process.
        src = _make_workspace("toolenv", elf_fixture.build_env_dump())
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(src)
        outcome = session.execute(
            ExecutionRequest(command=("/workspace/toolenv",)))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertEqual(outcome.exit_code, 0, outcome.output)
        lines = sorted(l for l in outcome.output.splitlines() if l)
        expected = sorted(f"{k}={v}" for k, v in EXPECTED_ENV.items())
        self.assertEqual(lines, expected, "exec'd command must see exactly "
                         "the six approved env vars")

    @skip_unless_linux
    def test_bounded_output_active_for_cli_workloads(self):
        src = _make_workspace("toolflood", elf_fixture.build_write_exit(
            b"F" * (2 * 1024 * 1024), 0))
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(src, resources_overrides={"output_mb": 1})
        outcome = session.execute(
            ExecutionRequest(command=("/workspace/toolflood",)))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertTrue(outcome.truncated,
                        "2 MiB write against a 1 MiB bound must truncate")
        self.assertIn("output truncated", outcome.output)
        self.assertLess(len(outcome.output), 2 * 1024 * 1024)

    @skip_unless_linux
    def test_timeout_active_for_cli_workloads(self):
        src = _make_workspace("toolhang", elf_fixture.build_hang())
        self.addCleanup(shutil.rmtree, src, True)
        session = self._session(src,
                                resources_overrides={"wall_time_seconds": 1})
        outcome = session.execute(
            ExecutionRequest(command=("/workspace/toolhang",)))
        self.assertIsInstance(outcome, ExecutionResult)
        self.assertTrue(outcome.timed_out,
                        "a syscall-free infinite loop must be terminated "
                        "by the external deadline")
        self.assertEqual(outcome.cleanup_failure, "",
                         f"no workload process may survive: "
                         f"{outcome.cleanup_failure}")

    @skip_unless_linux
    def test_full_cli_end_to_end_json(self):
        src = _make_workspace("tool", elf_fixture.build_write_exit(
            b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, src, True)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err):
            code = cli_mod.main(["--workspace", src, "--json", "--",
                                 "/workspace/tool"])
        self.assertEqual(code, 0, err.getvalue())
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["refused"])
        self.assertEqual(payload["mode"], "restricted")
        self.assertTrue(payload["session_id"])
        self.assertEqual(payload["exit_code"], 0)
        self.assertIn("STATIC-ELF-OK", payload["output"])
        self.assertEqual(payload["cleanup_failure"], "")


if __name__ == "__main__":
    unittest.main()
