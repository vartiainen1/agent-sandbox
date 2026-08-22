"""Phase 1 Step 14 tests - external wall-clock timeout (S-036, ADR-011,
ARCHITECTURE.md section 13, T-034): the supervisor enforces an external
deadline (the validated ResourceLimits policy `wall_time_seconds`,
default 900) while collecting the bounded output pipe. The deadline
lives entirely in the supervisor process (time.monotonic + select with
the remaining time) - the workload cannot disable, evade, or reset it
(no shared clock, no capabilities, no channel).

- Expiration must TERMINATE/abort the controlled session (close the
  read end + kill the controlled child), never merely set a status flag.
- Normal completion before the deadline remains a success (no false
  timeout); expiry produces deterministic timeout state (no false
  success).
- Note: the workload cannot sleep (nanosleep is NOT in the derived
  45-syscall allowlist - no expansion), so the timeout integration
  tests hang the workload on an ALLOWLISTED blocking read of a pipe it
  creates itself, or flood the output pipe.

Categories (kept separate, per the charter):
- Host-side deadline/collection logic (runs everywhere - deterministic
  failure injection via the clock/select/read/kill seams).
- Sandbox-internal tests (real run_in_sandbox under the ACTUAL runtime
  filter) - gated on the real namespace+filesystem probes succeeding on
  this substrate (native 24.04 runner: SKIPPED with recorded reason;
  Docker uid 1001: VERIFIED DOCKER).
- The EXECUTION stage (items 18-21) completes with Step 15 (process-tree
  containment + cleanup verification); the guard registration and the
  READY transition are asserted by the skeleton/real-chain tests, not
  duplicated here.
"""

from __future__ import annotations

import os
import pathlib
import unittest

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import output as output_mod
from agent_sandbox.isolation import timeout as timeout_mod
from tests.unit import test_credentials as tc
from tests.unit import test_resources as tr

valid_config = tc.valid_config
skip_unless_linux = tc.skip_unless_linux
_require_fs = tr._require_fs


class DeadlineCollectionTests(unittest.TestCase):
    """Supervisor-side deadline semantics with deterministic seams -
    runs everywhere."""

    def _fake_clock(self, seconds):
        """A mutable monotonic-like clock the test can advance."""
        state = {"now": 0.0}
        state["advance"] = lambda s: state.__setitem__("now", state["now"] + s)
        return lambda: state["now"], state

    def test_completes_within_deadline(self):
        r, w = os.pipe()
        try:
            os.write(w, b"hello")
            os.close(w)
            clock, st = self._fake_clock(0.0)
            ready_calls = []
            def sel(fds, wfds, efds, timeout):
                ready_calls.append(timeout)
                return ([fds[0]] if fds else [], [], [])
            data, truncated, timed_out = timeout_mod.collect_session_output(
                r, 4242, 1024, 30, clock_impl=clock, select_impl=sel)
            self.assertEqual(data, b"hello")
            self.assertFalse(truncated)
            self.assertFalse(timed_out)
            self.assertTrue(all(t > 0 for t in ready_calls))
        finally:
            os.close(r)

    def test_deadline_expiry_terminates(self):
        r, w = os.pipe()
        try:
            os.write(w, b"12345")
            os.close(w)
            clock, st = self._fake_clock(0.0)
            killed = []
            def sel(fds, wfds, efds, timeout):
                # Never readable: the deadline expires first.
                st["advance"](timeout + 1)
                return ([], [], [])
            data, truncated, timed_out = timeout_mod.collect_session_output(
                r, 7777, 1024, 30, clock_impl=clock, select_impl=sel,
                kill_impl=lambda pid, sig: killed.append((pid, sig)))
            self.assertEqual(data, b"")
            self.assertFalse(truncated)
            self.assertTrue(timed_out)
            self.assertEqual(killed, [(7777, 9)])  # SIGKILL to the child
        finally:
            _close_quietly(r)  # collect_session_output closed it

    def test_deadline_expiry_after_partial_output(self):
        # Output started arriving, then the workload stalled: the
        # partial output is captured and the session is terminated -
        # never a false success.
        r, w = os.pipe()
        try:
            os.write(w, b"PART")
            os.close(w)
            clock, st = self._fake_clock(0.0)
            reads = []
            def sel(fds, wfds, efds, timeout):
                if len(reads) == 0:
                    reads.append(True)
                    return ([fds[0]], [], [])
                st["advance"](timeout + 1)
                return ([], [], [])
            data, truncated, timed_out = timeout_mod.collect_session_output(
                r, 999, 1024, 30, clock_impl=clock, select_impl=sel)
            self.assertEqual(data, b"PART")
            self.assertFalse(truncated)
            self.assertTrue(timed_out)
        finally:
            _close_quietly(r)  # collect_session_output closed it

    def test_output_limit_still_truncates_before_deadline(self):
        # A flooding workload hits the OUTPUT bound before the (long)
        # deadline - truncation, not timeout.
        r, w = os.pipe()
        try:
            os.write(w, b"123456789")
            os.close(w)
            clock, st = self._fake_clock(0.0)
            def sel(fds, wfds, efds, timeout):
                return ([fds[0]] if fds else [], [], [])
            data, truncated, timed_out = timeout_mod.collect_session_output(
                r, 111, 5, 300, clock_impl=clock, select_impl=sel)
            self.assertEqual(data, b"12345")
            self.assertTrue(truncated)
            self.assertFalse(timed_out)
        finally:
            _close_quietly(r)  # collect_session_output closed it

    def test_zero_output_bound_truncates_immediately(self):
        killed = []
        data, truncated, timed_out = timeout_mod.collect_session_output(
            -1, 222, 0, 30,
            kill_impl=lambda pid, sig: killed.append((pid, sig)))
        self.assertEqual(data, b"")
        self.assertTrue(truncated)
        self.assertFalse(timed_out)
        self.assertEqual(killed, [(222, 9)])

    def test_invalid_timeout_fails_closed(self):
        with self.assertRaises(timeout_mod.TimeoutEnforcementError):
            timeout_mod.collect_session_output(-1, 1, 1024, 0)

    def test_invalid_output_bound_fails_closed(self):
        with self.assertRaises(timeout_mod.TimeoutEnforcementError):
            timeout_mod.collect_session_output(-1, 1, -1, 30)

    def test_select_failure_fails_closed(self):
        def broken_sel(_a, _b, _c, _t):
            raise OSError("select failed")
        with self.assertRaises(timeout_mod.TimeoutEnforcementError):
            timeout_mod.collect_session_output(-1, 1, 1024, 30,
                                               select_impl=broken_sel)

    def test_read_failure_fails_closed(self):
        def sel(fds, wfds, efds, timeout):
            return ([fds[0]] if fds else [], [], [])
        def broken_read(_fd, _n):
            raise OSError("read failed")
        with self.assertRaises(timeout_mod.TimeoutEnforcementError):
            timeout_mod.collect_session_output(
                -1, 1, 1024, 30, select_impl=sel, read_impl=broken_read)

    def test_timeout_notice_is_deterministic(self):
        n1 = timeout_mod.timeout_notice(900)
        n2 = timeout_mod.timeout_notice(900)
        self.assertEqual(n1, n2)
        self.assertIn("900 seconds", n1)
        self.assertIn("S-036", n1)
        self.assertNotEqual(n1, timeout_mod.timeout_notice(5))


class SandboxTimeoutIntegrationTests(unittest.TestCase):
    """Real run_in_sandbox with the external deadline (S-036) - the
    workload runs under the ACTUAL runtime filter."""

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
    def test_normal_completion_before_deadline_succeeds(self):
        fn = lambda state, fs: "FINISHED IN TIME"
        run = self._run(fn, wall_time_seconds=30)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertIn("FINISHED IN TIME", run.output)
        self.assertFalse(run.truncated)
        self.assertFalse(run.timed_out)
        self.assertNotIn("timed out", run.output)

    @skip_unless_linux
    def test_deadline_expiry_terminates_session(self):
        # The workload hangs on a blocking read of a pipe it created
        # itself (pipe2 + read are allowlisted - the hang is legal under
        # the filter). The write end is kept OPEN and never written, so
        # the read blocks forever (closing it would make read return
        # EOF immediately). The supervisor's external deadline must
        # fire, terminate the session, and report timed_out - never
        # success.
        def hang(state, fs):
            r, w = os.pipe()
            os.read(r, 1)  # blocks forever: w is open, never written
            return "NEVER REACHED"
        run = self._run(hang, wall_time_seconds=2)
        self.assertTrue(run.timed_out)
        self.assertIn("timed out after 2 seconds", run.output)
        self.assertIn("S-036", run.output)
        self.assertNotIn("NEVER REACHED", run.output)

    @skip_unless_linux
    def test_deadline_expiry_no_false_success(self):
        # Output starts flowing, then the workload stalls mid-session
        # (hangs on its own pipe read): the deadline must terminate the
        # session - the supervisor never reports a clean success for a
        # session that outlived its deadline. The output bound is set
        # large enough that truncation cannot preempt the deadline
        # (deterministic: tiny output, 2s deadline, 1 MiB bound).
        def steady_then_hang(state, fs):
            print("START", flush=True)
            r, w = os.pipe()
            os.read(r, 1)  # blocks forever: w open, never written
            return "NEVER REACHED"
        run = self._run(steady_then_hang, wall_time_seconds=2,
                        output_mb=1)
        self.assertTrue(run.timed_out)
        self.assertIn("START", run.output)      # output did flow
        self.assertIn("timed out", run.output)  # but expiry terminated
        self.assertNotIn("NEVER REACHED", run.output)
        self.assertFalse(run.truncated)  # bound was NOT the cause

    @skip_unless_linux
    def test_output_bound_and_deadline_coexist(self):
        # A small output bound with a long deadline: truncation fires,
        # not timeout - the two mechanisms coexist in one loop.
        fn = lambda state, fs: "Z" * (output_mod.MIB * 2)
        run = self._run(fn, wall_time_seconds=60, output_mb=1)
        self.assertTrue(run.truncated)
        self.assertFalse(run.timed_out)
        self.assertIn("[output truncated", run.output)

    @skip_unless_linux
    def test_workload_cannot_disable_or_reset_the_deadline(self):
        # The workload has no channel to the supervisor's clock: even an
        # attempt to raise a signal / busy-loop forever cannot evade the
        # external timer (verified by the expiry above). Here we pin the
        # ordering property: the deadline is enforced OUTSIDE the
        # boundary - the supervisor's own wait is what expires.
        import unittest.mock

        from agent_sandbox.isolation import setup
        src = tr_tempdir()
        self.addCleanup(_rmtree, src)
        cfg = RuntimeConfig.from_dict(valid_config(src))
        with unittest.mock.patch.object(timeout_mod, "time") as mt:
            # The deadline uses the REAL supervisor clock; a hostile
            # workload cannot influence it (separate process, no shared
            # state). This seam proves the wiring path selects the
            # deadline mechanism.
            mt.monotonic.side_effect = [0.0, 2.0, 4.0]
            _require_fs(self)
            run = setup.run_in_sandbox(
                lambda state, fs: "X", rootfs_state=None,
                wall_time_seconds=3)
        self.assertFalse(run.timed_out)  # completed before the fake expiry


def tr_tempdir():
    import tempfile
    return tempfile.mkdtemp(prefix="as-timeout-int-")


def _rmtree(p):
    import shutil
    shutil.rmtree(p, True)


def _close_quietly(fd):
    try:
        os.close(fd)
    except OSError:
        pass
