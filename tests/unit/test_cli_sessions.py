"""Phase B CLI surface tests - create/exec/run/status/diff/logs/destroy
over the shared policy-gated RuntimeSession path (ADR-013, S-015).

Invariants under test:
- The CLI adds NO alternate security path: every command routes through
  ``RuntimeSession.execute()`` (the SOLE boundary entry) after the
  READY/REFUSED gate; policy decisions come from the real policy engine.
- ``create`` validates policy and initializes fail-closed, never
  executes a workload, and persists ONLY a READY session.
- ``exec``/``diff`` re-open a session from its stored manifest with
  STRICT re-validation (S-021): unknown, destroyed, or tampered sessions
  fail closed (exit 5) and never execute.
- ``diff`` runs ``git diff`` INSIDE the sandbox (never host-side) and is
  gated on the ``git.read`` capability (S-015 shared decision path).
- ``logs`` exposes the session's ADR-012 audit events observationally
  (S-024 - missing/malformed audit is empty, never an execution
  blocker); events are session-correlated (S-023).
- ``destroy`` terminates any live sandbox via the existing lifecycle
  mechanism, VERIFIES absence (S-038), and never claims successful
  destruction when cleanup is incomplete (retryable).
- ``--json`` is deterministic (sort_keys) and never changes an
  authorization decision.
- CLI and API produce the SAME refusal for the same denied policy
  (decision equivalence).

The CLI never executes host-side processes: it builds argv vectors for
the in-sandbox execve bridge only (structural guard lives in
test_cli.py and still scans this module).
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
from agent_sandbox import registry
from agent_sandbox.config import RuntimeConfig
from agent_sandbox.interface import SessionManager
from agent_sandbox.isolation import lifecycle as lifecycle_mod
from agent_sandbox.isolation import setup as setup_mod
from agent_sandbox.models import (
    ExecutionRequest,
    ExecutionResult,
    InitResult,
    SecurityMode,
)
from agent_sandbox.runtime.session import RuntimeSession
from tests.unit import elf_fixture
from tests.unit.test_cli import (
    _fake_sandbox_run,
    _make_workspace,
    _ready_session_context,
    valid_config,
)

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")


def _run_cli(argv, base):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), \
         contextlib.redirect_stderr(err):
        code = cli_mod.main(argv, state_dir=base)
    return code, out.getvalue(), err.getvalue()


class _CliTestCase(unittest.TestCase):
    """Shared fixture: an isolated state dir + a temp workspace."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="as-sess-")
        self.workspace = _make_workspace("tool", b"\x00")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.addCleanup(shutil.rmtree, self.workspace, True)

    # -- helpers ---------------------------------------------------------
    def create_session(self, workspace=None, policy_path=None,
                       mode="restricted", json_mode=True) -> str:
        argv = ["create", "--workspace", workspace or self.workspace,
                "--mode", mode]
        if policy_path:
            argv += ["--policy", policy_path]
        if json_mode:
            argv += ["--json"]
        with _ready_session_context(None):
            code, out, err = _run_cli(argv, self.base)
        self.assertEqual(code, 0, f"create failed: {err}")
        return json.loads(out)["session_id"]

    def _write_policy(self, capabilities: dict) -> str:
        path = os.path.join(self.base, "policy.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "capabilities": capabilities}, f)
        return path


class RegistryTests(_CliTestCase):
    def test_roundtrip_preserves_validated_config(self):
        config = RuntimeConfig.from_dict(valid_config(self.workspace))
        sid = "a" * 32
        registry.save_session(self.base, sid, config,
                              created="2026-08-22T00:00:00+00:00")
        manifest = registry.load_manifest(self.base, sid)
        self.assertIsNotNone(manifest)
        rebuilt = registry.config_from_manifest(manifest)
        self.assertEqual(rebuilt.mode, config.mode)
        self.assertEqual(rebuilt.workspace, config.workspace)
        self.assertEqual(rebuilt.resources, config.resources)
        self.assertEqual(dict(rebuilt.policy.capabilities),
                         dict(config.policy.capabilities))
        self.assertEqual(rebuilt.policy.version, config.policy.version)

    def test_invalid_session_id_rejected_before_path_use(self):
        with self.assertRaises(registry.RegistryError):
            registry.load_manifest(self.base, "../evil")
        with self.assertRaises(registry.RegistryError):
            registry.ensure_session_dir(self.base, "..")
        self.assertFalse(registry.is_valid_session_id("abc"))
        self.assertTrue(registry.is_valid_session_id("a" * 32))

    def test_unknown_session_is_none(self):
        self.assertIsNone(registry.load_manifest(self.base, "b" * 32))

    def test_tampered_policy_fails_closed_on_rebuild(self):
        config = RuntimeConfig.from_dict(valid_config(self.workspace))
        sid = "c" * 32
        registry.save_session(self.base, sid, config,
                              created="2026-08-22T00:00:00+00:00")
        manifest = registry.load_manifest(self.base, sid)
        # A hostile edit: an UNKNOWN capability -> must fail closed
        # (unknown security-critical fields are rejected, S-021).
        manifest["policy"] = {"version": 1, "capabilities": {
            "filesystem.read.workspace": True,
            "bogus.cap": True,
        }}
        path = registry.manifest_path(self.base, sid)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, sort_keys=True)
        with self.assertRaises(Exception):
            registry.config_from_manifest(
                registry.load_manifest(self.base, sid))

    def test_manifest_never_contains_secret_values(self):
        config = RuntimeConfig.from_dict(valid_config(self.workspace))
        sid = "d" * 32
        registry.save_session(self.base, sid, config,
                              created="2026-08-22T00:00:00+00:00")
        manifest = registry.load_manifest(self.base, sid)
        # The policy surface (S-040) holds only capability booleans - the
        # secrets capability itself is denied by default, never a secret
        # VALUE. No credential-like field may exist anywhere.
        self.assertFalse(
            manifest["policy"]["capabilities"]["secrets.read"])
        self.assertEqual(set(manifest["policy"]),
                         {"version", "capabilities"})
        # Credential FIELD names (exact match - capability names such as
        # "secrets.read" are the documented policy surface, not values).
        forbidden = ("secret", "token", "password", "api_key",
                     "authorization")

        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    self.assertFalse(
                        any(k.lower() == word for word in forbidden),
                        f"manifest must not carry a credential-like field "
                        f"{k!r}")
                    walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(manifest)

    def test_remove_session(self):
        config = RuntimeConfig.from_dict(valid_config(self.workspace))
        sid = "e" * 32
        registry.save_session(self.base, sid, config,
                              created="2026-08-22T00:00:00+00:00")
        registry.remove_session(self.base, sid)
        self.assertIsNone(registry.load_manifest(self.base, sid))


class CreateTests(_CliTestCase):
    def test_create_ready_persists_and_exposes_identity(self):
        with _ready_session_context(None):
            code, out, _ = _run_cli(
                ["create", "--workspace", self.workspace, "--json"],
                self.base)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["state"], "ready")
        self.assertFalse(payload["refused"])
        self.assertEqual(payload["mode"], "restricted")
        sid = payload["session_id"]
        self.assertEqual(len(sid), 32)
        # Persisted for later exec/status/logs/destroy.
        self.assertIsNotNone(registry.load_manifest(self.base, sid))

    def test_create_never_executes_a_workload(self):
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=AssertionError("create must not run "
                                               "a workload")):
                code, _, _ = _run_cli(
                    ["create", "--workspace", self.workspace, "--json"],
                    self.base)
        self.assertEqual(code, 0)

    def test_create_text_mode_reports_identity_and_mode(self):
        with _ready_session_context(None):
            code, out, _ = _run_cli(
                ["create", "--workspace", self.workspace], self.base)
        self.assertEqual(code, 0)
        self.assertIn("created session", out)
        self.assertIn("(mode restricted)", out)

    def test_create_refused_is_never_persisted(self):
        refused = InitResult(
            ok=False, mode=SecurityMode.RESTRICTED,
            failure=None)  # failure=None -> "initialization failed"
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "initialize", return_value=refused):
                code, out, _ = _run_cli(
                    ["create", "--workspace", self.workspace, "--json"],
                    self.base)
        self.assertEqual(code, cli_mod.EXIT_INIT_REFUSED)
        payload = json.loads(out)
        self.assertTrue(payload["refused"])
        self.assertEqual(payload["state"], "refused")
        # Nothing persisted - the empty state dir was cleaned up.
        sessions_dir = os.path.join(self.base, "sessions")
        self.assertTrue(not os.path.isdir(sessions_dir)
                        or not os.listdir(sessions_dir))

    def test_create_invalid_policy_fails_closed(self):
        bad = os.path.join(self.base, "bad.json")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("{not json")
        code, _, err = _run_cli(
            ["create", "--workspace", self.workspace,
             "--policy", bad, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        self.assertIn("configuration error", err)
        sessions_dir = os.path.join(self.base, "sessions")
        self.assertTrue(not os.path.isdir(sessions_dir)
                        or not os.listdir(sessions_dir))

    def test_create_invalid_mode_usage_error(self):
        code, _, _ = _run_cli(
            ["create", "--workspace", self.workspace, "--mode", "nope"],
            self.base)
        self.assertEqual(code, cli_mod.EXIT_USAGE)

    def test_create_missing_workspace_usage_error(self):
        code, _, _ = _run_cli(["create", "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_USAGE)


class ExecTests(_CliTestCase):
    def test_exec_routes_through_the_sole_execution_path(self):
        sid = self.create_session()
        result = ExecutionResult(session_id=sid,
                                 mode=SecurityMode.RESTRICTED,
                                 exit_code=0, output="HELLO")
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    return_value=_fake_sandbox_run(
                        exit_code=0, output="HELLO")) as ris:
                code, out, _ = _run_cli(
                    ["exec", sid, "--json", "--", "/workspace/tool", "a"],
                    self.base)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertFalse(payload["refused"])
        self.assertEqual(payload["exit_code"], 0)
        self.assertEqual(payload["output"], "HELLO")
        self.assertEqual(payload["session_id"], sid)
        # The single boundary call received the execve bridge + argv.
        ris.assert_called_once()
        self.assertTrue(callable(ris.call_args.args[0]))

    def test_exec_passes_argv_verbatim(self):
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute") as ex:
                ex.return_value = ExecutionResult(
                    session_id=sid, mode=SecurityMode.RESTRICTED,
                    exit_code=0, output="")
                code, _, _ = _run_cli(
                    ["exec", sid, "--json", "--", "/workspace/tool",
                     ";", "rm", "-rf", "/"], self.base)
        self.assertEqual(code, 0)
        request = ex.call_args.args[0]
        self.assertIsInstance(request, ExecutionRequest)
        self.assertEqual(request.command,
                         ("/workspace/tool", ";", "rm", "-rf", "/"))

    def test_exec_denied_capability_refuses_before_boundary(self):
        policy = self._write_policy({
            "filesystem.read.workspace": True,
            "filesystem.write.workspace": False,  # denied
            "process.spawn": True,
        })
        sid = self.create_session(policy_path=policy)
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=AssertionError(
                        "denied workload must never reach the boundary")):
                code, out, _ = _run_cli(
                    ["exec", sid, "--json", "--", "/workspace/tool"],
                    self.base)
        self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED)
        payload = json.loads(out)
        self.assertTrue(payload["refused"])
        self.assertIn("DENIED", payload["reason"])
        self.assertIn("filesystem.write.workspace", payload["reason"])

    def test_exec_unknown_session_exit_5(self):
        code, out, _ = _run_cli(
            ["exec", "f" * 32, "--json", "--", "/workspace/tool"],
            self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)
        payload = json.loads(out)
        self.assertTrue(payload["refused"])
        self.assertIn("unknown session", payload["reason"])

    def test_exec_destroyed_session_exit_5(self):
        sid = self.create_session()
        with _ready_session_context(None):
            code, _, _ = _run_cli(["destroy", sid, "--json"], self.base)
        self.assertEqual(code, 0)
        code, out, _ = _run_cli(
            ["exec", sid, "--json", "--", "/workspace/tool"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)
        self.assertIn("unknown session", json.loads(out)["reason"])

    def test_exec_invalid_session_id_exit_5(self):
        code, _, _ = _run_cli(
            ["exec", "../evil", "--json", "--", "/workspace/tool"],
            self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)

    def test_exec_no_command_usage_error(self):
        sid = self.create_session()
        code, _, err = _run_cli(["exec", sid, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        self.assertIn("no command", err)

    def test_exec_tampered_manifest_fails_closed(self):
        sid = self.create_session()
        # Corrupt the stored policy: unknown capability -> re-validation
        # must refuse before any execution.
        manifest = registry.load_manifest(self.base, sid)
        manifest["policy"] = {"version": 1, "capabilities": {
            "filesystem.read.workspace": True,
            "filesystem.write.workspace": True,
            "process.spawn": True,
            "unknown.capability": True,
        }}
        with open(registry.manifest_path(self.base, sid), "w",
                  encoding="utf-8") as f:
            json.dump(manifest, f, sort_keys=True)
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=AssertionError("tampered manifest must "
                                               "never execute")):
                code, out, _ = _run_cli(
                    ["exec", sid, "--json", "--", "/workspace/tool"],
                    self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)
        self.assertIn("invalid", json.loads(out)["reason"])

    def test_exec_reinit_gate_runs_on_every_invocation(self):
        # A persisted READY session re-runs the READY/REFUSED gate on
        # EVERY exec - if initialization now refuses on this invocation,
        # the workload never runs (fail closed, deterministic).
        sid = self.create_session()
        refused = InitResult(ok=False, mode=SecurityMode.RESTRICTED,
                             failure=None)
        with unittest.mock.patch.object(
                RuntimeSession, "initialize", return_value=refused):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=AssertionError(
                        "refused init must never reach the boundary")):
                code, out, _ = _run_cli(
                    ["exec", sid, "--json", "--", "/workspace/tool"],
                    self.base)
        self.assertEqual(code, cli_mod.EXIT_INIT_REFUSED)
        self.assertTrue(json.loads(out)["refused"])


class DiffTests(_CliTestCase):
    def test_diff_runs_git_diff_inside_sandbox(self):
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute") as ex:
                ex.return_value = ExecutionResult(
                    session_id=sid, mode=SecurityMode.RESTRICTED,
                    exit_code=0, output="+two\n")
                code, out, _ = _run_cli(
                    ["diff", sid, "--json"], self.base)
        self.assertEqual(code, 0)
        request = ex.call_args.args[0]
        # The sanitized Phase C git argv (hostile-config neutralization).
        command = request.command
        self.assertEqual(command[0], "git")
        self.assertIn("diff", command)
        self.assertIn("--no-ext-diff", command)
        self.assertIn("--no-textconv", command)
        self.assertIn("-C", command)
        self.assertEqual(command[command.index("-C") + 1], "/workspace")
        self.assertIn("-c", command)
        self.assertIn("alias.diff=diff", command)
        self.assertIn("core.fsmonitor=", command)
        self.assertIn("credential.helper=", command)
        self.assertIn("+two", json.loads(out)["output"])

    def test_diff_passes_git_args_verbatim(self):
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute") as ex:
                ex.return_value = ExecutionResult(
                    session_id=sid, mode=SecurityMode.RESTRICTED,
                    exit_code=0, output="")
                _run_cli(
                    ["diff", sid, "--json", "--", "--stat",
                     "HEAD~1"], self.base)
        request = ex.call_args.args[0]
        # Caller git args are appended VERBATIM after the sanitized
        # fixed flags (argv is data).
        command = request.command
        self.assertEqual(command[0], "git")
        self.assertEqual(command[-2:], ("--stat", "HEAD~1"))

    def test_diff_denied_git_read_refuses_before_boundary(self):
        policy = self._write_policy({
            "filesystem.read.workspace": True,
            "filesystem.write.workspace": True,
            "process.spawn": True,
            # git.read absent -> denied by default.
        })
        sid = self.create_session(policy_path=policy)
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=AssertionError(
                        "git.read-denied diff must never reach the "
                        "boundary")):
                code, out, _ = _run_cli(
                    ["diff", sid, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED)
        payload = json.loads(out)
        self.assertTrue(payload["refused"])
        self.assertIn("git.read", payload["reason"])
        self.assertIn("DENIED", payload["reason"])

    def test_diff_unknown_session_exit_5(self):
        code, _, _ = _run_cli(
            ["diff", "a" * 32, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_diff_real_sandbox(self):
        # Real git diff INSIDE the sandbox on a real git workspace.
        # Requires the ADR-005 toolchain with git in the sandbox; when
        # the substrate lacks it, the probe gates honestly (skip with
        # reason - never relabeled as a pass).
        from tests.unit import test_resources as tr
        tr._require_fs(self)
        try:
            import subprocess
            subprocess.run(["git", "--version"], check=True,
                           capture_output=True)
        except Exception:
            self.skipTest("host git unavailable on this substrate")
        repo = tempfile.mkdtemp(prefix="as-gitrepo-")
        self.addCleanup(shutil.rmtree, repo, True)
        subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
        f = pathlib.Path(repo) / "a.txt"
        f.write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", repo, "add", "a.txt"], check=True)
        f.write_text("one\ntwo\n", encoding="utf-8")

        with _ready_session_context(None):
            code, out, err = _run_cli(
                ["create", "--workspace", repo, "--json"], self.base)
        self.assertEqual(code, 0, err)
        sid = json.loads(out)["session_id"]

        # Probe: does the sandbox toolchain provide git? (exec path -
        # the same argv/bridge used by diff.)
        with _ready_session_context(None):
            code, out, _ = _run_cli(
                ["exec", sid, "--json", "--", "git", "--version"],
                self.base)
        if code != 0:
            self.skipTest("ADR-005 toolchain lacks git inside the "
                          "sandbox on this substrate (exec probe "
                          f"exit={code})")

        with _ready_session_context(None):
            code, out, _ = _run_cli(["diff", sid, "--json"], self.base)
        self.assertEqual(code, 0, out)
        self.assertIn("+two", out)


class StatusTests(_CliTestCase):
    def test_status_exposes_state_mode_resources(self):
        sid = self.create_session()
        code, out, _ = _run_cli(["status", sid, "--json"], self.base)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["session_id"], sid)
        self.assertEqual(payload["state"], "ready")
        self.assertEqual(payload["mode"], "restricted")
        self.assertEqual(payload["workspace"], self.workspace)
        self.assertEqual(payload["policy_version"], 1)
        self.assertIn("resources", payload)
        self.assertIn("capabilities", payload)
        # No host secrets surface through status - the only capability
        # mentioning secrets is the DENIED-by-default boolean.
        self.assertFalse(payload["capabilities"]["secrets.read"])
        blob = json.dumps(payload)
        for word in ("token", "password", "api_key", "authorization"):
            self.assertNotIn(word, blob.lower())

    def test_status_unknown_session_exit_5(self):
        code, _, _ = _run_cli(
            ["status", "b" * 32, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)

    def test_status_text_mode(self):
        sid = self.create_session()
        code, out, _ = _run_cli(["status", sid], self.base)
        self.assertEqual(code, 0)
        self.assertIn(f"session: {sid}", out)
        self.assertIn("mode: restricted", out)


class LogsTests(_CliTestCase):
    def test_logs_show_correlated_events(self):
        sid = self.create_session()
        code, out, _ = _run_cli(["logs", sid, "--json"], self.base)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["session_id"], sid)
        events = payload["events"]
        self.assertTrue(events, "create must have recorded events")
        self.assertEqual(events[0]["event"], "session_created")
        for ev in events:
            self.assertEqual(ev["session_id"], sid)  # S-023 correlation

    def test_logs_text_mode_is_jsonl(self):
        sid = self.create_session()
        code, out, _ = _run_cli(["logs", sid], self.base)
        self.assertEqual(code, 0)
        lines = [l for l in out.splitlines() if l.strip()]
        self.assertTrue(lines)
        for line in lines:
            ev = json.loads(line)
            self.assertEqual(ev["session_id"], sid)

    def test_logs_missing_audit_is_empty_not_error(self):
        sid = self.create_session()
        # Remove the audit file: logs must be observational (S-024).
        os.remove(registry.session_audit_path(self.base, sid))
        code, out, _ = _run_cli(["logs", sid, "--json"], self.base)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["events"], [])

    def test_logs_unknown_session_exit_5(self):
        code, _, _ = _run_cli(["logs", "c" * 32, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)


class DestroyTests(_CliTestCase):
    def test_destroy_removes_session_state(self):
        sid = self.create_session()
        manifest_path = registry.manifest_path(self.base, sid)
        self.assertTrue(os.path.exists(manifest_path))
        code, out, _ = _run_cli(["destroy", sid, "--json"], self.base)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["destroyed"])
        self.assertFalse(payload["cleanup_incomplete"])
        self.assertFalse(os.path.exists(manifest_path))
        self.assertFalse(os.path.isdir(registry.session_dir(
            self.base, sid)))

    def test_destroy_unknown_session_exit_5(self):
        code, _, _ = _run_cli(
            ["destroy", "d" * 32, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)

    def test_destroy_twice_second_exit_5(self):
        sid = self.create_session()
        with _ready_session_context(None):
            code, _, _ = _run_cli(["destroy", sid], self.base)
        self.assertEqual(code, 0)
        code, _, err = _run_cli(["destroy", sid], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)
        self.assertIn("unknown session", err)

    def test_destroy_with_dead_sandbox_pid1_is_clean(self):
        # The recorded sandbox PID 1 is gone (normal case: the run already
        # terminated + verified absence). Destroy terminates (tolerating
        # the missing process) + verifies absence -> clean removal. Uses
        # a pid of a process we spawned and reaped - no real process is
        # ever signaled.
        import subprocess
        p = subprocess.Popen([sys.executable, "-c", "pass"])
        p.wait()
        dead_pid = p.pid
        sid = self.create_session()
        registry.update_last_execution(self.base, sid, dead_pid, None)
        code, out, _ = _run_cli(["destroy", sid, "--json"], self.base)
        self.assertEqual(code, 0, out)
        self.assertTrue(json.loads(out)["destroyed"])

    def test_destroy_incomplete_cleanup_never_claims_destroyed(self):
        sid = self.create_session()
        registry.update_last_execution(self.base, sid, 123456, None)
        # The recorded pid is ARBITRARY - it must never reach the real
        # termination path (F1 rule). Patch the lifecycle seams so the
        # test exercises the reporting path without signaling any real
        # process; assert the lifecycle mechanism WAS invoked.
        with unittest.mock.patch.object(
                lifecycle_mod, "terminate_tree") as tt:
            with unittest.mock.patch.object(
                    lifecycle_mod, "verify_no_workload_remains",
                    return_value=([123456],
                                  "cleanup incomplete: workload "
                                  "process(es) survive - S-038")):
                code, out, err = _run_cli(
                    ["destroy", sid, "--json"], self.base)
        tt.assert_called_once()
        self.assertEqual(code, cli_mod.EXIT_DESTROY_INCOMPLETE)
        payload = json.loads(out)
        self.assertFalse(payload["destroyed"])
        self.assertTrue(payload["cleanup_incomplete"])
        self.assertEqual(payload["survivors"], [123456])
        # The session is NOT removed - destroy is retryable, and the
        # incomplete cleanup is reported explicitly (never success): the
        # exact kernel-visible reason is surfaced to the caller.
        self.assertIsNotNone(registry.load_manifest(self.base, sid))
        self.assertIn("cleanup incomplete", payload["reason"])
        self.assertIn("S-038", payload["reason"])
        self.assertEqual(err, "", "--json output carries the explicit "
                                  "report in the payload")


class EquivalenceTests(_CliTestCase):
    def test_cli_and_api_refusal_identical_for_denied_policy(self):
        policy = self._write_policy({
            "filesystem.read.workspace": True,
            "filesystem.write.workspace": False,
            "process.spawn": True,
        })
        sid = self.create_session(policy_path=policy)
        with _ready_session_context(None):
            code, out, _ = _run_cli(
                ["exec", sid, "--json", "--", "/workspace/tool"],
                self.base)
        self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED)
        cli_refusal = json.loads(out)

        # Same policy + same command through the API transport.
        with _ready_session_context(None):
            mgr = SessionManager()
            init = mgr.initialize({"workspace": self.workspace,
                                   "policy": {
                                       "version": 1,
                                       "capabilities": {
                                           "filesystem.read.workspace":
                                               True,
                                           "filesystem.write.workspace":
                                               False,
                                           "process.spawn": True,
                                       }}})
        self.assertTrue(init["refused"] is False)
        api_refusal = mgr.execute({"session_id": init["session_id"],
                                   "command": ["/workspace/tool"]})
        self.assertTrue(api_refusal["refused"])
        # Decision equivalence: same mode, state, refusal reason.
        self.assertEqual(cli_refusal["mode"], api_refusal["mode"])
        self.assertEqual(cli_refusal["state"], api_refusal["state"])
        self.assertEqual(cli_refusal["reason"], api_refusal["reason"])

    def test_run_legacy_and_subcommand_are_identical(self):
        # The legacy one-shot form and the explicit ``run`` subcommand
        # take the exact same path (same security gate, same payload
        # except the fresh per-invocation session identity).
        src = _make_workspace("tool", elf_fixture.build_write_exit(
            b"STATIC-ELF-OK\n", 0))
        self.addCleanup(shutil.rmtree, src, True)
        result = ExecutionResult(session_id="s", mode=SecurityMode.RESTRICTED,
                                 exit_code=0, output="HELLO")
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute", return_value=result):
                code_legacy, out_legacy, _ = _run_cli(
                    ["--workspace", src, "--json", "--",
                     "/workspace/tool"], self.base)
                code_sub, out_sub, _ = _run_cli(
                    ["run", "--workspace", src, "--json", "--",
                     "/workspace/tool"], self.base)
        self.assertEqual(code_legacy, code_sub)
        norm = lambda p: {k: v for k, v in p.items() if k != "session_id"}
        self.assertEqual(norm(json.loads(out_legacy)),
                         norm(json.loads(out_sub)))


if __name__ == "__main__":
    unittest.main()
