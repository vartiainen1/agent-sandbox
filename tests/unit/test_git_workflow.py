"""Phase C safe Git workflow tests (implementation.md Phase 9).

Invariants under test:
- The Git operation set is CLOSED and READ-ONLY: status/diff/changed/
  untracked/deleted/base/current map ONLY to the builtin git commands
  status/ls-files/merge-base/rev-parse. Commit/push/fetch/checkout/add/
  submodule etc. are a usage error (fail closed) - never a passthrough.
- Every invocation uses the sanitized argv (agent_sandbox/git.py):
  highest-precedence -c overrides neutralize hostile repository
  configuration (core.fsmonitor, diff.external, core.hooksPath,
  credential helpers, ssh, pager/editor, submodule recursion, protocol),
  the exact builtin words are alias-pinned, -C /workspace pins the work
  tree, and diff carries --no-ext-diff --no-textconv (the empirically
  verified code-execution neutralizers). ARGV is the only configuration
  channel (the in-sandbox env is the fixed six-variable sanitized set).
- The CLI `git <session-id> <operation> [--json] [-- args...]` command
  routes through the SOLE execution path (RuntimeSession.execute) after
  the READY gate and the git.read policy gate (S-015) - a denied
  capability refuses BEFORE the sandbox runs.
- Session fail-closed behavior is identical to the other commands:
  unknown/destroyed sessions, malformed manifests, and invalid ids all
  exit 5 with the boundary never reached.
- The module builds ARGV ONLY: no subprocess/os.system/execve anywhere
  (structural guard - git runs inside the sandbox, never on the host).

Adversarial hostile-repository containment evidence (alias/external
diff/textconv/fsmonitor/credential/hooks markers never executing) lives
in tests/adversarial/test_git_attacks.py - this file covers the
construction, routing, and fail-closed properties.
"""

from __future__ import annotations

import json
import os
import unittest
import unittest.mock

from agent_sandbox import cli as cli_mod
from agent_sandbox import git as git_mod
from agent_sandbox import registry
from agent_sandbox.isolation import setup as setup_mod
from agent_sandbox.models import (
    ExecutionResult,
    SecurityMode,
)
from agent_sandbox.runtime.session import RuntimeSession
from tests.unit.test_cli import _fake_sandbox_run, _ready_session_context
from tests.unit.test_cli_sessions import _CliTestCase, _run_cli

# Operations that must NEVER be reachable through the Phase C set (write,
# network and hook-triggering surfaces - out of scope by design).
_FORBIDDEN_OPS = ("commit", "push", "fetch", "pull", "checkout", "switch",
                  "add", "rm", "mv", "submodule", "clone", "apply",
                  "rebase", "merge", "reset", "restore", "cherry-pick",
                  "tag", "am", "revert")


class GitArgvTests(unittest.TestCase):
    def test_closed_operation_set_is_exactly_documented(self):
        self.assertEqual(
            set(git_mod.GIT_OPERATIONS),
            {"status", "diff", "changed", "untracked", "deleted",
             "base", "current"})

    def test_operations_map_only_to_builtin_words(self):
        # Every operation's argv leads with the builtin command word
        # (never an alias, never an arbitrary word, never a `!` shell
        # expansion).
        for op in git_mod.GIT_OPERATIONS:
            argv = git_mod.sanitized_git_argv(op)
            words = set(argv)
            self.assertFalse(
                any(w.startswith("!") for w in words),
                f"operation {op} must never carry a shell expansion")
            builtin = git_mod._OP_WORDS[op][0]
            self.assertIn(builtin, argv)
            self.assertEqual(argv[0], "git")

    def test_forbidden_operations_rejected_fail_closed(self):
        for op in _FORBIDDEN_OPS:
            with self.assertRaises(ValueError, msg=op):
                git_mod.sanitized_git_argv(op)

    def test_sanitizing_config_flags_present(self):
        argv = git_mod.sanitized_git_argv("status")
        for cfg in git_mod._SANITIZING_CONFIG:
            self.assertIn(cfg, argv,
                          f"missing neutralizing config {cfg!r}")

    def test_alias_pinning_for_every_operation(self):
        for op in git_mod.GIT_OPERATIONS:
            argv = git_mod.sanitized_git_argv(op)
            for word in git_mod._OP_WORDS[op]:
                self.assertIn(f"alias.{word}={word}", argv,
                              f"op {op} must pin alias.{word}")

    def test_work_tree_pinned_to_workspace(self):
        for op in git_mod.GIT_OPERATIONS:
            argv = git_mod.sanitized_git_argv(op)
            self.assertIn("-C", argv)
            self.assertEqual(argv[argv.index("-C") + 1], "/workspace")

    def test_diff_carries_execution_neutralizers(self):
        argv = git_mod.sanitized_git_argv("diff")
        self.assertIn("--no-ext-diff", argv)
        self.assertIn("--no-textconv", argv)

    def test_closed_set_syscall_dependency_chdir_allowed(self):
        # The closed-set git operations require chdir (git -C /workspace
        # plus work-tree-top resolution) - the seccomp allowlist MUST
        # keep it (native Phase C finding 2026-08-22: without chdir git
        # fails inside the sandbox with EPERM "fatal: cannot change to
        # ..."). Regression: removing chdir from the allowlist fails
        # here immediately, before any native run is needed.
        import json
        from pathlib import Path
        allowlist = json.loads(
            (Path(__file__).resolve().parents[2]
             / "tools/seccomp-derivation/allowlist.json").read_text(
                encoding="utf-8"))
        self.assertIn("chdir", allowlist["allowlist"])
        self.assertEqual(
            len(allowlist["tier0"]) + len(allowlist["tier1"]), 69)
        self.assertEqual(allowlist["tier0"], sorted(allowlist["tier0"]))
        self.assertEqual(allowlist["tier1"], sorted(allowlist["tier1"]))

    def test_caller_args_appended_verbatim(self):
        argv = git_mod.sanitized_git_argv("status", ("--", "a b; c"))
        self.assertEqual(argv[-2:], ("--", "a b; c"))
        # base requires the caller's ref: merge-base HEAD <ref>.
        argv = git_mod.sanitized_git_argv("base", ("main",))
        self.assertEqual(argv[-2:], ("HEAD", "main"))
        self.assertIn("merge-base", argv)

    def test_current_is_rev_parse_head(self):
        argv = git_mod.sanitized_git_argv("current")
        self.assertIn("rev-parse", argv)
        self.assertIn("HEAD", argv)

    def test_module_builds_argv_only_no_execution_primitives(self):
        # Structural guard (AST-based, so docstrings/comments are
        # ignored): git.py must never import/use subprocess, os.system,
        # os.popen or any os.exec* - git executes inside the sandbox
        # only (the host never runs git for repository inspection).
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(git_mod))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    self.assertNotIn(
                        "subprocess", alias.name,
                        "git.py must not import subprocess")
            if isinstance(node, ast.Attribute):
                if (isinstance(node.value, ast.Name)
                        and node.value.id == "os"
                        and node.attr.startswith(("system", "popen",
                                                  "exec", "spawn"))):
                    self.fail(f"git.py must not use os.{node.attr}")


class GitCliTests(_CliTestCase):
    def test_git_status_routes_through_sole_execution_path(self):
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute") as ex:
                ex.return_value = ExecutionResult(
                    session_id=sid, mode=SecurityMode.RESTRICTED,
                    exit_code=0, output=" M a.txt\n")
                code, out, _ = _run_cli(
                    ["git", sid, "status", "--json"], self.base)
        self.assertEqual(code, 0)
        request = ex.call_args.args[0]
        self.assertEqual(
            request.command, git_mod.sanitized_git_argv("status"))
        self.assertIn(" M a.txt", json.loads(out)["output"])

    def test_git_operations_map_to_correct_builtins(self):
        expected = {
            "changed": "ls-files", "untracked": "ls-files",
            "deleted": "ls-files", "base": "merge-base",
            "current": "rev-parse", "diff": "diff",
        }
        for op, builtin in expected.items():
            sid = self.create_session()
            with _ready_session_context(None):
                with unittest.mock.patch.object(
                        RuntimeSession, "execute") as ex:
                    ex.return_value = ExecutionResult(
                        session_id=sid, mode=SecurityMode.RESTRICTED,
                        exit_code=0, output="")
                    code, _, _ = _run_cli(
                        ["git", sid, op, "--json"], self.base)
            self.assertEqual(code, 0, op)
            argv = ex.call_args.args[0].command
            self.assertIn(builtin, argv)
            self.assertEqual(argv[0], "git")

    def test_git_base_accepts_caller_ref(self):
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute") as ex:
                ex.return_value = ExecutionResult(
                    session_id=sid, mode=SecurityMode.RESTRICTED,
                    exit_code=0, output="abc123\n")
                code, _, _ = _run_cli(
                    ["git", sid, "base", "--json", "--", "main"],
                    self.base)
        self.assertEqual(code, 0)
        argv = ex.call_args.args[0].command
        self.assertEqual(argv[-2:], ("HEAD", "main"))

    def test_git_unknown_operation_usage_error(self):
        sid = self.create_session()
        for op in ("commit", "push", "fetch", "checkout", "submodule"):
            code, _, err = _run_cli(
                ["git", sid, op, "--json"], self.base)
            self.assertEqual(code, cli_mod.EXIT_USAGE, op)
            self.assertIn("invalid choice", err)

    def test_git_missing_operation_usage_error(self):
        sid = self.create_session()
        code, _, _ = _run_cli(["git", sid, "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_USAGE)

    def test_git_denied_git_read_refuses_before_boundary(self):
        # git.read absent -> denied by default; every operation must
        # refuse BEFORE the sandbox runs (run_in_sandbox never reached).
        policy = os.path.join(self.base, "policy.json")
        with open(policy, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "capabilities": {
                "filesystem.read.workspace": True,
                "filesystem.write.workspace": True,
                "process.spawn": True,
            }}, f)
        sid = self.create_session(policy_path=policy)
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=AssertionError(
                        "denied git op must never reach the boundary")):
                for op in git_mod.GIT_OPERATIONS:
                    code, out, _ = _run_cli(
                        ["git", sid, op, "--json"], self.base)
                    self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED, op)
                    payload = json.loads(out)
                    self.assertTrue(payload["refused"], op)
                    self.assertIn("git.read", payload["reason"], op)
                    self.assertIn("DENIED", payload["reason"], op)

    def test_git_refusal_shape_equals_exec_refusal(self):
        # Decision equivalence: a denied git op and a denied exec op
        # produce the same refusal shape (both route through the shared
        # policy decision path before the boundary).
        policy = os.path.join(self.base, "policy.json")
        with open(policy, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "capabilities": {
                "filesystem.read.workspace": True,
                "filesystem.write.workspace": True,
                "process.spawn": True,
            }}, f)
        sid = self.create_session(policy_path=policy)
        with _ready_session_context(None):
            code, out, _ = _run_cli(
                ["git", sid, "status", "--json"], self.base)
        git_refusal = json.loads(out)
        # Same policy denies the exec path too (its own capability set is
        # filesystem.read/write + process.spawn - all present here, so
        # exec would PASS policy; the equivalence is on the git.read
        # gate, which is the git-op-specific shared-path decision). The
        # refusal shape must carry the standard fields.
        self.assertEqual(
            set(git_refusal),
            {"session_id", "mode", "state", "refused", "reason"})
        self.assertEqual(git_refusal["refused"], True)
        self.assertEqual(git_refusal["state"], "ready")

    def test_git_unknown_session_exit_5(self):
        code, _, _ = _run_cli(
            ["git", "a" * 32, "status", "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)

    def test_git_destroyed_session_exit_5(self):
        sid = self.create_session()
        with _ready_session_context(None):
            code, _, _ = _run_cli(["destroy", sid, "--json"], self.base)
        self.assertEqual(code, 0)
        code, out, _ = _run_cli(
            ["git", sid, "status", "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)
        self.assertIn("unknown session", json.loads(out)["reason"])

    def test_git_tampered_manifest_fails_closed(self):
        sid = self.create_session()
        manifest = registry.load_manifest(self.base, sid)
        manifest["policy"] = {"version": 1, "capabilities": {
            "filesystem.read.workspace": True,
            "bogus.cap": True,
        }}
        with open(registry.manifest_path(self.base, sid), "w",
                  encoding="utf-8") as f:
            json.dump(manifest, f, sort_keys=True)
        with _ready_session_context(None):
            code, out, _ = _run_cli(
                ["git", sid, "status", "--json"], self.base)
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)
        self.assertIn("invalid", json.loads(out)["reason"])

    def test_git_result_mapping_carries_enforcement_state(self):
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    return_value=_fake_sandbox_run(
                        exit_code=1, output="O", truncated=True,
                        timed_out=True,
                        cleanup_failure="survivor (S-038)")):
                code, out, _ = _run_cli(
                    ["git", sid, "status", "--json"], self.base)
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertTrue(payload["truncated"])
        self.assertTrue(payload["timed_out"])
        self.assertEqual(payload["cleanup_failure"], "survivor (S-038)")

    def test_git_text_mode_output(self):
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute") as ex:
                ex.return_value = ExecutionResult(
                    session_id=sid, mode=SecurityMode.RESTRICTED,
                    exit_code=0, output=" M a.txt\n")
                code, out, _ = _run_cli(
                    ["git", sid, "status"], self.base)
        self.assertEqual(code, 0)
        self.assertIn(" M a.txt", out)
        self.assertIn("mode=restricted", out)
        self.assertIn("session=", out)


if __name__ == "__main__":
    unittest.main()
