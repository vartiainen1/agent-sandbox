"""Phase 1 Step 15 tests - process-tree containment and cleanup
(S-014, S-038, ADR-011, ARCHITECTURE.md section 6/13, T-036..T-039):
when the controlled session terminates - especially on timeout or
output exhaustion - the ENTIRE workload process tree must be contained
and eliminated, NOT merely the supervisor's immediate child. Killing
only the parent is explicitly forbidden.

Authoritative mechanism (kernel-enforced, never a status flag):

- The supervisor is a CHILD SUBREAPER (PR_SET_CHILD_SUBREAPER, verified
  by kernel-state read-back) so orphaned workload descendants reparent
  to it, not to init.
- The workload lives in its OWN PID namespace (Step 2): SIGKILL to
  sandbox PID 1 (the namespace init) makes the kernel terminate EVERY
  process in that namespace - catching all descendants regardless of
  parentage, including vfork/exec descendants.
- Where cgroup v2 is delegated (Step 10): cgroup.kill additionally
  kills every process in the session cgroup regardless of parentage.
- Absence verification (S-038) is MANDATORY: after termination the
  supervisor verifies from kernel-visible state that no workload
  process remains (sandbox PID namespace inode scan + empty session
  cgroup.procs where delegated). Incomplete cleanup is detected and
  REPORTED - never reported as successful (S-038, S-024).

Categories (kept separate, per the charter):
- Host-side lifecycle logic (runs everywhere - deterministic seams for
  the prctl/procfs/cgroup operations).
- Real-sandbox tests (real run_in_sandbox under the ACTUAL runtime
  filter) - gated on the real namespace+filesystem probes succeeding on
  this substrate (native 24.04 runner: SKIPPED with recorded reason;
  Docker uid 1001: VERIFIED DOCKER).
"""

from __future__ import annotations

import os
import pathlib
import unittest
import unittest.mock

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import lifecycle as lifecycle_mod

from tests.unit import test_credentials as tc
from tests.unit import test_resources as tr

valid_config = tc.valid_config
skip_unless_linux = tc.skip_unless_linux
_require_fs = tr._require_fs


class SubreaperTests(unittest.TestCase):
    """Supervisor-side child-subreaper establishment - runs everywhere
    (the prctl seam is injected; real prctl is exercised on Linux)."""

    def test_establish_and_verify_subreaper(self):
        calls = []
        def fake_prctl(option, arg2=0, *args):
            calls.append((option, arg2))
            return 0
        with unittest.mock.patch.object(lifecycle_mod.syscalls,
                                        "prctl", fake_prctl), \
             unittest.mock.patch.object(
                 lifecycle_mod.syscalls, "prctl_get_child_subreaper",
                 return_value=1):
            lifecycle_mod.establish_subreaper()
        self.assertEqual(calls[0], (36, 1))   # PR_SET_CHILD_SUBREAPER, 1

    def test_set_failure_fails_closed(self):
        def boom(_option, _arg2=0, *_a):
            raise OSError("prctl denied")
        with unittest.mock.patch.object(lifecycle_mod.syscalls,
                                        "prctl", boom):
            with self.assertRaises(Exception) as cm:
                lifecycle_mod.establish_subreaper()
        self.assertIn("subreaper", str(cm.exception).lower())

    def test_verify_mismatch_fails_closed(self):
        with unittest.mock.patch.object(lifecycle_mod.syscalls,
                                        "prctl", lambda *a: 0), \
             unittest.mock.patch.object(
                 lifecycle_mod.syscalls, "prctl_get_child_subreaper",
                 return_value=0):
            with self.assertRaises(Exception) as cm:
                lifecycle_mod.establish_subreaper()
        self.assertIn("read-back", str(cm.exception))

    def test_is_subreaper_reads_kernel_state(self):
        with unittest.mock.patch.object(
                lifecycle_mod.syscalls, "prctl_get_child_subreaper",
                return_value=1):
            self.assertTrue(lifecycle_mod.is_subreaper())
        with unittest.mock.patch.object(
                lifecycle_mod.syscalls, "prctl_get_child_subreaper",
                return_value=0):
            self.assertFalse(lifecycle_mod.is_subreaper())


class NamespaceInodeTests(unittest.TestCase):
    """Sandbox PID namespace inode discovery (the workload-tree
    membership test) - deterministic seams."""

    def test_inode_parsed_from_proc(self):
        with unittest.mock.patch.object(
                lifecycle_mod.os, "readlink",
                return_value="pid:[4026532448]"):
            self.assertEqual(lifecycle_mod.namespace_inode(1234),
                             "4026532448")

    def test_missing_process_returns_none(self):
        def boom(_p):
            raise OSError("no such process")
        with unittest.mock.patch.object(lifecycle_mod.os, "readlink", boom):
            self.assertIsNone(lifecycle_mod.namespace_inode(99999))

    def test_scan_finds_members(self):
        def fake_listdir(_p):
            return ["1", "10", "100", "notapid"]
        def fake_readlink(p):
            if "notapid" in p:
                raise OSError("no such file")
            if p == "/proc/10/ns/pid":
                return "pid:[4026532448]"
            return "pid:[999]"
        with unittest.mock.patch.object(lifecycle_mod.os,
                                        "listdir", fake_listdir), \
             unittest.mock.patch.object(lifecycle_mod.os,
                                        "readlink", fake_readlink):
            self.assertEqual(
                lifecycle_mod.procs_in_namespace("4026532448"), [10])

    def test_scan_empty(self):
        with unittest.mock.patch.object(lifecycle_mod.os, "listdir",
                                        lambda _p: []):
            self.assertEqual(lifecycle_mod.procs_in_namespace("1"), [])


class TerminateTreeTests(unittest.TestCase):
    """Authoritative tree termination semantics (S-014) - seams."""

    def test_kills_sandbox_pid1_not_just_parent(self):
        killed = []
        class FakeSession:
            path = "/tmp/cg"
        with unittest.mock.patch.object(lifecycle_mod, "_cgroup_kill",
                                        lambda *a: None):
            lifecycle_mod.terminate_tree(
                42, FakeSession(), kill_impl=lambda p, s: killed.append(p),
                sleep_impl=lambda s: None)
        self.assertIn(42, killed)  # the namespace init was SIGKILLed

    def test_already_gone_pid1_tolerated(self):
        killed = []
        lifecycle_mod.terminate_tree(
            42, None, kill_impl=lambda p, s: killed.append(p),
            sleep_impl=lambda s: None)
        self.assertIn(42, killed)

    def test_cgroup_kill_belt_and_braces(self):
        # Where the session cgroup is delegated, cgroup.kill is invoked
        # in addition to the namespace-init SIGKILL.
        writes = []
        class FakeSession:
            path = "/sys/fs/cgroup/sbx"
        with unittest.mock.patch("builtins.open") as m:
            m.return_value.__enter__.return_value.write.side_effect = \
                lambda s: writes.append(s)
            with unittest.mock.patch.object(
                    lifecycle_mod.os.path, "join",
                    lambda *a: "/sys/fs/cgroup/sbx/cgroup.kill"):
                lifecycle_mod._cgroup_kill(FakeSession())
        self.assertTrue(any("1" in w for w in writes))


class AbsenceVerificationTests(unittest.TestCase):
    """Mandatory S-038 absence verification - deterministic seams."""

    def test_no_survivors_ok(self):
        with unittest.mock.patch.object(
                lifecycle_mod, "namespace_inode",
                return_value="4026532448"), \
             unittest.mock.patch.object(
                lifecycle_mod, "procs_in_namespace", return_value=[]):
            survivors, reason = lifecycle_mod.verify_no_workload_remains(1)
        self.assertEqual(survivors, [])
        self.assertIsNone(reason)

    def test_survivors_detected_and_reported(self):
        with unittest.mock.patch.object(
                lifecycle_mod, "namespace_inode",
                return_value="4026532448"), \
             unittest.mock.patch.object(
                lifecycle_mod, "procs_in_namespace",
                return_value=[4242]), \
             unittest.mock.patch.object(lifecycle_mod.time,
                                        "sleep", lambda s: None):
            survivors, reason = lifecycle_mod.verify_no_workload_remains(
                1, retries=2)
        self.assertEqual(survivors, [4242])
        self.assertIn("cleanup incomplete", reason or "")
        self.assertIn("S-038", reason or "")

    def test_namespace_init_gone_means_nothing_remains(self):
        # The namespace init is already gone - with it the namespace died
        # (kernel guarantee): nothing can remain in it.
        with unittest.mock.patch.object(lifecycle_mod, "namespace_inode",
                                        return_value=None):
            survivors, reason = lifecycle_mod.verify_no_workload_remains(1)
        self.assertEqual(survivors, [])
        self.assertIsNone(reason)

    def test_cgroup_procs_not_empty_reported(self):
        with unittest.mock.patch.object(
                lifecycle_mod, "namespace_inode",
                return_value="4026532448"), \
             unittest.mock.patch.object(
                lifecycle_mod, "procs_in_namespace", return_value=[]), \
             unittest.mock.patch.object(lifecycle_mod.time,
                                        "sleep", lambda s: None):
            class FakeSession:
                path = "/sys/fs/cgroup/sbx"
            with unittest.mock.patch.object(
                    lifecycle_mod, "_read_cgroup_procs",
                    return_value=["4242"]):
                survivors, reason = lifecycle_mod.verify_no_workload_remains(
                    1, FakeSession(), retries=2)
        self.assertIn("cgroup.procs", reason or "")


class SandboxLifecycleIntegrationTests(unittest.TestCase):
    """Real run_in_sandbox process-tree containment (S-014, S-038) - the
    workload runs under the ACTUAL runtime filter; the supervisor is a
    real child subreaper and verifies real absence after each run."""

    def _run(self, fn, wall_time_seconds=None, output_mb=None):
        _require_fs(self)
        from agent_sandbox.isolation import rootfs as rootfs_mod
        from agent_sandbox.isolation import setup
        src = tr_tempdir()
        self.addCleanup(_rmtree, src)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(_rmtree, rootfs_state.layout.dir)
        kwargs = {
            "rootfs_state": rootfs_state,
            "limits": RuntimeConfig.from_dict(valid_config(src)).resources,
            "env_allowlist": ("PATH", "HOME", "LANG", "LC_ALL", "TERM",
                              "TMPDIR"),
        }
        if wall_time_seconds is not None:
            kwargs["wall_time_seconds"] = wall_time_seconds
        if output_mb is not None:
            kwargs["output_mb"] = output_mb
        return setup.run_in_sandbox(fn, **kwargs)

    @skip_unless_linux
    def test_supervisor_is_subreaper(self):
        # The supervisor process (this test) must have been set as a
        # child subreaper by run_in_sandbox.
        from agent_sandbox.isolation import setup
        _require_fs(self)
        run = setup.run_in_sandbox(lambda state: "OK")
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertTrue(lifecycle_mod.is_subreaper(),
                        "supervisor must be a child subreaper (S-014)")

    @skip_unless_linux
    def test_normal_completion_leaves_no_workload_process(self):
        run = self._run(lambda state, fs: "DONE")
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertIn("DONE", run.output)
        self.assertEqual(run.cleanup_failure, "",
                         f"cleanup must be complete, got {run.cleanup_failure}")

    @skip_unless_linux
    def test_timeout_terminates_whole_tree(self):
        # The workload forks a lingering descendant (via the allowlisted
        # vfork - clone is NOT in the 45-syscall allowlist), then hangs.
        # The supervisor's timeout must kill sandbox PID 1 and the kernel
        # must terminate the whole namespace - no survivors.
        def hang_with_descendant(state, fs):
            import ctypes
            libc = ctypes.CDLL(None)
            pid = libc.vfork()
            if pid == 0:
                # child: spin forever (no syscalls - survives the filter)
                while True:
                    pass
            # parent: suspended at vfork until the child execs/exits -
            # never reaches the pipe. The workload hangs with no output;
            # the supervisor's deadline fires and kills the namespace
            # init, and the kernel kills the whole tree (child included).
            return "NEVER REACHED"
        run = self._run(hang_with_descendant, wall_time_seconds=2)
        self.assertTrue(run.timed_out)
        self.assertEqual(run.cleanup_failure, "",
                         f"no workload process may survive, got "
                         f"{run.cleanup_failure}")

    @skip_unless_linux
    def test_output_truncation_terminates_whole_tree(self):
        # A flooding workload (with a lingering vfork descendant) hits
        # the output bound: the supervisor terminates the session and
        # the whole tree must be gone.
        #
        # vfork semantics: the PARENT is suspended until the child
        # execs/exits - so the CHILD must be the flooder (write is in
        # the 45-syscall allowlist; clone/fork are not). The parent
        # (sandbox PID 1) never resumes; when truncation fires the
        # supervisor kills the namespace init and the kernel kills the
        # whole namespace, flooding child included.
        def flood_with_descendant(state, fs):
            import ctypes
            libc = ctypes.CDLL(None)
            pid = libc.vfork()
            if pid == 0:
                # child: flood stdout forever via ctypes write (no
                # Python frames pushed into the shared vfork stack).
                buf = ctypes.create_string_buffer(b"F" * 65536)
                while True:
                    libc.write(1, buf, 65536)
            # parent: never reached - suspended at vfork until the
            # child execs/exits; the descendant is alive when the
            # truncation fires.
            return "NEVER REACHED"
        run = self._run(flood_with_descendant, output_mb=1)
        self.assertTrue(run.truncated)
        self.assertEqual(run.cleanup_failure, "",
                         f"no workload process may survive, got "
                         f"{run.cleanup_failure}")


def tr_tempdir():
    import tempfile
    return tempfile.mkdtemp(prefix="as-lifecycle-int-")


def _rmtree(p):
    import shutil
    shutil.rmtree(p, True)
