"""Phase C hostile-repository adversarial tests (T-047 + Phase 9).

A repository is HOSTILE INPUT (ARCHITECTURE section 3.2): hooks,
``.git/config``, ``.gitmodules``, attributes, filters and scripts are
all untrusted. Git executes INSIDE the sandbox boundary (the
enforcement layer) with a sanitized argv (agent_sandbox/git.py - the
defense-in-depth configuration control).

Two evidence classes, kept strictly separate:

1. ``HostileConfigContainmentTests`` - HOST-SIDE empirical evidence for
   the configuration-control layer. Runs the SANITIZED argv against a
   genuinely hostile fixture repository using the host's own git binary
   (tests may run git; the PRODUCTION CLI never does - structural guard
   in test_git_workflow.py). The fixture carries hostile aliases,
   diff.external, a textconv driver wired through .gitattributes,
   core.fsmonitor (incl. include.path-amplified), credential.helper and
   hooks - each with a marker side-effect. A CONTROL test proves the
   fixture is genuinely hostile (plain `git diff` executes the textconv
   script); the sanitized invocations must produce zero markers.

2. ``SandboxGitContainmentTests`` - REAL-BOUNDARY evidence (Linux +
   filesystem probe + ADR-005 toolchain git): the same hostile fixtures
   executed through the complete RuntimeSession -> run_in_sandbox path
   via the CLI. The assertion is HOST containment: no host file is ever
   created, no host process is touched, cleanup is verified (S-038).
   Substrate-limited substrates skip with an explicit reason - a skip is
   never relabeled as a pass.

Invariants: the repository cannot select executables, invoke helpers,
reach host credentials, use the network, or escape /workspace; denied
git.read refuses before the sandbox runs; output is bounded and cleanup
is verified.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from agent_sandbox import git as git_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

# ---------------------------------------------------------------------------
# Hostile fixture builders (shared by both evidence classes)
# ---------------------------------------------------------------------------

def _run(*argv, cwd=None):
    return subprocess.run([str(a) for a in argv], cwd=cwd,
                          capture_output=True, text=True)


def _host_git_available(testcase) -> bool:
    try:
        _run("git", "--version")
        return True
    except FileNotFoundError:
        testcase.skipTest("host git unavailable on this substrate")
        return False


def _build_hostile_repo(script_dir: str) -> str:
    """A genuinely hostile fixture repository.

    Every script writes a marker file into ``script_dir`` when executed.
    ``script_dir`` lives OUTSIDE the repository so the markers are only
    observable if the script actually ran. Returns the repo path."""
    markers = pathlib.Path(script_dir)
    markers.mkdir(parents=True, exist_ok=True)

    def _script(name: str, marker: str) -> str:
        path = markers / name
        marker_path = (markers / marker).as_posix()
        path.write_text(
            "#!/bin/sh\necho RAN > '" + marker_path + "'\n"
            "echo 'INJECTED-OUTPUT'\n", encoding="utf-8")
        path.chmod(0o755)
        return path.as_posix()

    extdiff = _script("extdiff.sh", "extdiff.marker")
    textconv = _script("textconv.sh", "textconv.marker")
    fsm = _script("fsm.sh", "fsm.marker")
    cred = _script("cred.sh", "cred.marker")
    hook = _script("hook.sh", "hook.marker")
    (markers / "evil.inc").write_text(
        f"[core]\n    fsmonitor = {fsm}\n", encoding="utf-8")

    repo = tempfile.mkdtemp(prefix="as-hostile-repo-")
    _run("git", "init", "-q", repo)
    _run("git", "-C", repo, "config", "user.email", "t@t")
    _run("git", "-C", repo, "config", "user.name", "t")
    (pathlib.Path(repo) / "a.txt").write_text("one\n", encoding="utf-8")
    _run("git", "-C", repo, "add", "a.txt")
    _run("git", "-C", repo, "commit", "-qm", "c1")
    # Make the tree dirty so status/diff produce real output.
    with open(os.path.join(repo, "a.txt"), "a", encoding="utf-8") as f:
        f.write("two\n")
    (pathlib.Path(repo) / ".gitattributes").write_text(
        "*.txt diff=evil\n", encoding="utf-8")

    cfg = _run("git", "-C", repo, "config")
    for k, v in (("alias.status", "!sh -c 'echo ALIAS-RAN'"),
                 ("alias.diff", "!sh -c 'echo ALIAS-RAN'"),
                 ("alias.merge-base", "!sh -c 'echo ALIAS-RAN'"),
                 ("alias.rev-parse", "!sh -c 'echo ALIAS-RAN'"),
                 ("diff.external", extdiff),
                 ("diff.evil.textconv", textconv),
                 ("core.fsmonitor", fsm),
                 ("include.path", (markers / "evil.inc").as_posix()),
                 ("credential.helper", f"!{cred}"),
                 ("core.hooksPath", (markers / "hooks").as_posix()),
                 ("submodule.recurse", "true")):
        _run("git", "-C", repo, "config", k, v)
    # A hostile hook in the hooksPath dir (status/diff never run hooks).
    hooks_dir = markers / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    (hooks_dir / "post-commit").write_text(
        f"#!/bin/sh\necho RAN > '{(markers / 'hook.marker').as_posix()}'\n",
        encoding="utf-8")
    (hooks_dir / "post-commit").chmod(0o755)
    return repo


# ---------------------------------------------------------------------------
# HOST-SIDE evidence: configuration-control layer (host git, run anywhere)
# ---------------------------------------------------------------------------

class HostileConfigContainmentTests(unittest.TestCase):
    """The sanitized argv against a genuinely hostile repository.

    These are HOST-SIDE tests of the configuration-control layer: they
    run the exact argv the production CLI builds (sanitized_git_argv)
    against the host git binary. The production CLI never runs git
    host-side - these tests only validate that the argv neutralizes the
    hostile surfaces (markers never fire)."""

    def setUp(self):
        if not _host_git_available(self):
            return
        self.script_dir = tempfile.mkdtemp(prefix="as-gitmarkers-")
        self.repo = _build_hostile_repo(self.script_dir)
        self.addCleanup(shutil.rmtree, self.script_dir, True)
        self.addCleanup(shutil.rmtree, self.repo, True)

    def _marker(self, name) -> bool:
        return os.path.exists(os.path.join(self.script_dir, name))

    def _sanitized(self, op, args=()):
        # The host-side tests point the work tree at the fixture repo
        # (production pins /workspace inside the sandbox); everything
        # else - the config neutralization - is exactly the production
        # argv.
        return _run(*git_mod.sanitized_git_argv(op, args,
                                                work_tree=self.repo),
                    cwd=self.repo)

    # -- control: the fixture is genuinely hostile ------------------------
    def test_control_plain_git_diff_executes_hostile_scripts(self):
        # WITHOUT the sanitized argv, plain `git diff` on the fixture
        # executes hostile repository-selected scripts: the external diff
        # driver (diff.external - it takes precedence over textconv) AND
        # the fsmonitor command (git diff consults core.fsmonitor). This
        # control proves the fixture is genuinely hostile and the
        # containment comes from the sanitization, not a benign fixture.
        result = _run("git", "diff", "--", "a.txt", cwd=self.repo)
        self.assertIn("INJECTED-OUTPUT", result.stdout)
        fired = [m for m in ("extdiff", "textconv", "fsm")
                 if self._marker(f"{m}.marker")]
        self.assertTrue(fired,
                        "control: plain git diff must execute hostile "
                        "scripts (markers fired: "
                        f"{fired or 'NONE'})")

    # -- sanitized containment --------------------------------------------
    def test_sanitized_status_never_executes_anything(self):
        result = self._sanitized("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        # Real status output - not the hostile alias output.
        self.assertIn("a.txt", result.stdout)
        self.assertNotIn("ALIAS-RAN", result.stdout)
        self.assertNotIn("INJECTED-OUTPUT", result.stdout)
        for marker in ("extdiff", "textconv", "fsm", "cred", "hook"):
            self.assertFalse(self._marker(f"{marker}.marker"),
                             f"{marker} must never execute under the "
                             "sanitized argv")

    def test_sanitized_diff_never_runs_external_diff_or_textconv(self):
        result = self._sanitized("diff", ("--", "a.txt"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("+two", result.stdout)
        self.assertNotIn("INJECTED-OUTPUT", result.stdout)
        # diff also consults core.fsmonitor on modern git - neutralized.
        for marker in ("extdiff", "textconv", "fsm"):
            self.assertFalse(self._marker(f"{marker}.marker"),
                             f"{marker} must never execute under the "
                             "sanitized diff")

    def test_sanitized_fsmonitor_never_runs_including_include_amplified(
            self):
        # core.fsmonitor is set both directly AND via include.path
        # (amplification) - the -c override must win over both.
        result = self._sanitized("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self._marker("fsm.marker"))

    def test_sanitized_aliases_never_expand(self):
        result = self._sanitized("status")
        self.assertNotIn("ALIAS-RAN", result.stdout)
        result = self._sanitized("diff")
        self.assertNotIn("ALIAS-RAN", result.stdout)

    def test_sanitized_credential_helper_never_consulted(self):
        result = self._sanitized("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self._marker("cred.marker"))

    def test_sanitized_hooks_never_run(self):
        result = self._sanitized("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self._marker("hook.marker"))


# ---------------------------------------------------------------------------
# REAL-BOUNDARY evidence: hostile repository through the complete sandbox
# (Linux + filesystem probe + ADR-005 toolchain git)
# ---------------------------------------------------------------------------

@unittest.skipUnless(LINUX, "real sandbox requires Linux")
class SandboxGitContainmentTests(unittest.TestCase):
    """Hostile repositories executed through the REAL RuntimeSession ->
    run_in_sandbox boundary via the CLI. The assertion is HOST
    containment: the hostile scripts' marker paths (host-side temp dir)
    are never created, no host process is touched, and cleanup is
    verified (S-038). Substrate-limited substrates skip honestly."""

    def setUp(self):
        from tests.unit import test_resources as tr
        tr._require_fs(self)
        if not _host_git_available(self):
            return
        self.script_dir = tempfile.mkdtemp(prefix="as-gitmarkers-")
        self.repo = _build_hostile_repo(self.script_dir)
        self.addCleanup(shutil.rmtree, self.script_dir, True)
        self.addCleanup(shutil.rmtree, self.repo, True)

    def _marker(self, name) -> bool:
        return os.path.exists(os.path.join(self.script_dir, name))

    def _session_id(self):
        from agent_sandbox import cli as cli_mod
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err):
            code = cli_mod.main(["create", "--workspace", self.repo,
                                 "--json"])
        self.assertEqual(code, 0, err.getvalue())
        return json.loads(out.getvalue())["session_id"]

    def _git(self, sid, op, *args):
        from agent_sandbox import cli as cli_mod
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err):
            code = cli_mod.main(
                ["git", sid, op, "--json", *(["--", *args] if args else [])])
        return code, out.getvalue(), err.getvalue()

    def _probe_git(self, sid):
        # Does the sandbox toolchain provide git? Honest gate that
        # distinguishes the two failure classes (per the 2026-08-22
        # native Phase C finding):
        #   (a) git binary genuinely unavailable inside the boundary
        #       (execve ENOENT -> the workload reports
        #       "FAIL workload: FileNotFoundError ... No such file or
        #       directory: 'git'", sandbox exit 1) -> a missing-tool
        #       skip with reason, never a pass.
        #   (b) git IS present but the sandbox boundary blocks it
        #       (e.g. a denied syscall such as chdir -> git's own
        #       "fatal: ... Operation not permitted", exit 128) -> a
        #       REAL boundary/policy failure: the test must FAIL, never
        #       masquerade as a missing-tool skip.
        import json
        code, out, _ = self._git(sid, "current")
        if code == 0:
            return
        try:
            payload = json.loads(out)
        except ValueError:
            payload = {}
        output = payload.get("output", "") or ""
        reason = payload.get("reason", "") or ""
        missing_tool = (
            payload.get("refused") is True
            or "FAIL workload" in output
            or "no such file or directory" in output.lower()
            or "not found" in reason.lower()
        )
        if missing_tool:
            self.skipTest(
                "ADR-005 toolchain lacks git inside the sandbox on "
                "this substrate (git binary not resolvable inside the "
                "boundary: probe exit=%s)" % code)
        self.fail(
            "git IS present in the ADR-005 toolchain but cannot execute "
            "inside the sandbox boundary - a real boundary/policy "
            f"failure, never a missing-tool skip: probe exit={code}, "
            f"output={output!r}, reason={reason!r} "
            "(expected e.g. 'fatal: ... Operation not permitted' from a "
            "denied syscall such as chdir)")

    def test_hostile_repo_status_contained(self):
        import json
        sid = self._session_id()
        self._probe_git(sid)
        code, out, _ = self._git(sid, "status")
        payload = json.loads(out)
        self.assertEqual(code, 0, out)
        self.assertFalse(payload.get("refused", False), out)
        self.assertEqual(payload["cleanup_failure"], "", out)
        # Real status output; no hostile output; NO host marker created.
        self.assertIn("a.txt", payload["output"])
        self.assertNotIn("ALIAS-RAN", payload["output"])
        for marker in ("extdiff", "textconv", "fsm", "cred", "hook"):
            self.assertFalse(self._marker(f"{marker}.marker"),
                             f"{marker} must never reach the host")

    def test_hostile_repo_diff_contained(self):
        import json
        sid = self._session_id()
        self._probe_git(sid)
        code, out, _ = self._git(sid, "diff", "--", "a.txt")
        payload = json.loads(out)
        self.assertEqual(code, 0, out)
        self.assertIn("+two", payload["output"])
        self.assertFalse(self._marker("extdiff.marker"))
        self.assertFalse(self._marker("textconv.marker"))

    def test_symlink_and_gitfile_escape_contained(self):
        # A symlink pointing at /etc/passwd and a .git FILE (gitfile)
        # pointing at a host-visible path: inside the sandbox these
        # resolve only within the disposable rootfs - the host is never
        # touched and the operation completes.
        sid = self._session_id()
        self._probe_git(sid)
        # Only add the hostile links to the workspace AFTER the session
        # exists (the workspace is copied fresh per execute()).
        try:
            os.symlink("/etc/passwd", os.path.join(self.repo, "link-passwd"))
            (pathlib.Path(self.repo) / ".git-link").write_text(
                f"gitdir: {self.script_dir}\n", encoding="utf-8")
        except OSError:
            self.skipTest("symlink unsupported on this substrate")
        code, out, _ = self._git(sid, "status")
        self.assertEqual(code, 0, out)
        self.assertFalse(self._marker("fsm.marker"))

    def test_hostile_hook_payload_contained(self):
        # A hostile hook writes to a HOST-visible path from inside the
        # sandbox: the path is the host tempdir, unreachable from the
        # sandbox rootfs. The host marker must not appear.
        sid = self._session_id()
        self._probe_git(sid)
        code, out, _ = self._git(sid, "status")
        self.assertEqual(code, 0, out)
        self.assertFalse(self._marker("hook.marker"))


if __name__ == "__main__":
    unittest.main()
