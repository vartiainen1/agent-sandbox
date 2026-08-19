"""Phase 1 Step 6 tests - no_new_privs (REAL Linux execution, S-010,
ADR-008): PR_SET_NO_NEW_PRIVS established in sandbox PID 1 BEFORE any
workload code runs, and the KERNEL STATE read back and verified
(PR_GET_NO_NEW_PRIVS == 1) - never "the prctl call returned success".
Any failure or unexpected state REFUSES before the workload executes.

Categories (kept separate, per the charter):
- Host-side wrapper/verification logic (runs everywhere).
- Sandbox-internal tests (run inside the real sandbox via
  run_in_sandbox) - gated on the real namespace probe succeeding on this
  substrate (native 24.04 runner: SKIPPED with recorded reason; Docker
  uid 1001: VERIFIED DOCKER).
- Probe + integration: the PRIVILEGES stage guard's real path, and the
  fail-closed chain (HARDENED refusal advances to SECCOMP).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import unittest.mock

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import privileges as priv_mod
from agent_sandbox.isolation import setup
from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real no_new_privs operations require Linux with os.fork "
           "(non-Linux fail-closed behavior is covered by test_skeleton.py)")


def valid_config(workspace: str, mode: str = "hardened") -> dict:
    return {
        "mode": mode,
        "workspace": workspace,
        "resources": {
            "cpu_seconds": 300, "memory_mb": 4096, "disk_mb": 10240,
            "processes": 256, "open_files": 4096, "output_mb": 50,
            "wall_time_seconds": 900,
        },
    }


# Real-path capability gates (same discipline as the other suites).
_ns_status: tuple[bool, str] | None = None


def _ns_available() -> tuple[bool, str]:
    """Namespace-only substrate check (the real NAMESPACES probe)."""
    global _ns_status
    if _ns_status is None:
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            check = setup._probe_impl()
        _ns_status = (check.ok, check.reason)
    return _ns_status


def _require_ns(self) -> None:
    ok, reason = _ns_available()
    if not ok:
        self.skipTest("namespace substrate unavailable on this host: " + reason)


_fs_status: tuple[bool, str] | None = None


def _fs_available() -> tuple[bool, str]:
    """Full-boundary substrate check (the real FILESYSTEM probe)."""
    global _fs_status
    if _fs_status is None:
        with tempfile.TemporaryDirectory(prefix="as-nnp-gate-") as src:
            (pathlib.Path(src) / "marker.txt").write_text("gate\n")
            cfg = RuntimeConfig.from_dict(valid_config(src))
            with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
                check = setup._filesystem_probe_impl(cfg)
        _fs_status = (check.ok, check.reason)
    return _fs_status


def _require_fs(self) -> None:
    ok, reason = _fs_available()
    if not ok:
        self.skipTest("filesystem boundary substrate unavailable on this host: " + reason)


class NoNewPrivsHostTests(unittest.TestCase):
    """Fail-closed wrapper/verification logic - runs everywhere."""

    def test_prctl_option_constants(self):
        self.assertEqual(syscalls.PR_SET_NO_NEW_PRIVS, 38)
        self.assertEqual(syscalls.PR_GET_NO_NEW_PRIVS, 39)

    def test_prctl_syscall_number_matches_arch(self):
        number = syscalls._number("prctl")
        if syscalls._arch() == "x86_64":
            self.assertEqual(number, 157)
        else:
            self.assertEqual(number, 167)

    def test_prctl_negative_return_raises_oserror(self):
        # Negative syscall return is NEVER success (ADR-001): the wrapper
        # must raise, never silently pass a negative value through.
        with unittest.mock.patch.object(syscalls, "_raw", return_value=-1):
            with self.assertRaises(OSError):
                syscalls.prctl(syscalls.PR_SET_NO_NEW_PRIVS, 1)

    def test_set_failure_is_deterministic_refusal(self):
        def boom(option, arg2=0, arg3=0, arg4=0, arg5=0):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        with unittest.mock.patch.object(priv_mod, "_prctl", boom):
            with self.assertRaises(NamespaceSetupError) as cm:
                priv_mod.set_no_new_privs()
        self.assertIn("cannot enable no_new_privs", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_readback_failure_is_deterministic_refusal(self):
        def boom(option, arg2=0, arg3=0, arg4=0, arg5=0):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        with unittest.mock.patch.object(priv_mod, "_prctl", boom):
            with self.assertRaises(NamespaceSetupError) as cm:
                priv_mod.verify_no_new_privs()
        self.assertIn("cannot read no_new_privs state", str(cm.exception))

    def test_readback_zero_refused(self):
        # The kernel reports the bit NOT set -> the invariant does not
        # hold -> refuse (never treat prctl-set success as evidence).
        with unittest.mock.patch.object(priv_mod, "_prctl", return_value=0):
            with self.assertRaises(NamespaceSetupError) as cm:
                priv_mod.verify_no_new_privs()
        self.assertIn("read-back is 0, expected 1", str(cm.exception))

    def test_readback_unexpected_value_refused(self):
        with unittest.mock.patch.object(priv_mod, "_prctl", return_value=2):
            with self.assertRaises(NamespaceSetupError) as cm:
                priv_mod.verify_no_new_privs()
        self.assertIn("read-back is 2, expected 1", str(cm.exception))

    def test_verify_ok_when_readback_is_one(self):
        with unittest.mock.patch.object(priv_mod, "_prctl", return_value=1):
            self.assertTrue(priv_mod.verify_no_new_privs())

    def test_establish_and_verify_calls_set_then_verify(self):
        # Ordering pin: establish_and_verify performs SET then GET (the
        # read-back). Never the reverse, never GET alone.
        calls: list[int] = []

        def spy(option, arg2=0, arg3=0, arg4=0, arg5=0):
            calls.append(option)
            return 1

        with unittest.mock.patch.object(priv_mod, "_prctl", spy):
            priv_mod.establish_and_verify()
        self.assertEqual(calls, [syscalls.PR_SET_NO_NEW_PRIVS,
                                 syscalls.PR_GET_NO_NEW_PRIVS])


class NoNewPrivsBoundaryTests(unittest.TestCase):
    """The no_new_privs invariant INSIDE the sandbox (real Linux)."""

    def setUp(self):
        _require_ns(self)
        self._marker_dir = tempfile.mkdtemp(prefix="as-nnp-")
        self.addCleanup(shutil.rmtree, self._marker_dir, True)

    @skip_unless_linux
    def test_no_new_privs_established_and_readback(self):
        # The raw kernel read-back from inside the sandbox (PID 1): the
        # bit must be set there, not merely "the prctl set call returned".
        def fn(state):
            return json.dumps({
                "readback": priv_mod._prctl(priv_mod.PR_GET_NO_NEW_PRIVS),
                "uid": syscalls.getuid(),
                "pid": syscalls.getpid(),
            })

        run = setup.run_in_sandbox(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output.strip())
        self.assertEqual(data["readback"], 1)
        self.assertEqual(data["uid"], 0)
        self.assertEqual(data["pid"], 1)

    @skip_unless_linux
    def test_ordering_workload_not_executed_before_invariant(self):
        # The workload fn must NEVER run if no_new_privs cannot be
        # established: its marker must not appear anywhere on the host.
        marker = str(pathlib.Path(self._marker_dir) / "ran.txt")

        def boom(option, arg2=0, arg3=0, arg4=0, arg5=0):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        def fn(state):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        with unittest.mock.patch.object(priv_mod, "_prctl", boom):
            run = setup.run_in_sandbox(fn)
        self.assertNotEqual(run.exit_code, 0)
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertFalse(os.path.exists(marker),
                         "workload executed before no_new_privs was established")
        self.assertIn("no_new_privs", run.output)

    @skip_unless_linux
    def test_setup_failure_refuses(self):
        # Deterministic refusal path: STAGE_FAILED-shaped failure in the
        # sandbox child -> non-zero exit + explicit reason, no workload.
        marker = str(pathlib.Path(self._marker_dir) / "ran.txt")

        def boom(option, arg2=0, arg3=0, arg4=0, arg5=0):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        def fn(state):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        with unittest.mock.patch.object(priv_mod, "_prctl", boom):
            run = setup.run_in_sandbox(fn)
        self.assertNotEqual(run.exit_code, 0)
        self.assertIn("FAIL setup", run.output)
        self.assertIn("cannot enable no_new_privs", run.output)
        self.assertFalse(os.path.exists(marker))

    @skip_unless_linux
    def test_verification_failure_refuses(self):
        # set succeeds, but the kernel-state read-back reports 0 -> the
        # invariant was NOT established -> refuse before the workload.
        marker = str(pathlib.Path(self._marker_dir) / "ran.txt")
        calls = [0]

        def flaky(option, arg2=0, arg3=0, arg4=0, arg5=0):
            calls[0] += 1
            return 1 if calls[0] == 1 else 0  # set ok, read-back says NOT set

        def fn(state):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        with unittest.mock.patch.object(priv_mod, "_prctl", flaky):
            run = setup.run_in_sandbox(fn)
        self.assertNotEqual(run.exit_code, 0)
        self.assertIn("read-back is 0, expected 1", run.output)
        self.assertFalse(os.path.exists(marker))

    @skip_unless_linux
    def test_unexpected_readback_state_refuses(self):
        calls = [0]

        def weird(option, arg2=0, arg3=0, arg4=0, arg5=0):
            calls[0] += 1
            return 2 if calls[0] >= 2 else 1  # set ok, read-back unexpected

        def fn(state):
            return "WORKLOAD RAN"

        with unittest.mock.patch.object(priv_mod, "_prctl", weird):
            run = setup.run_in_sandbox(fn)
        self.assertNotEqual(run.exit_code, 0)
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertIn("read-back is 2, expected 1", run.output)


class PrivilegesProbeTests(unittest.TestCase):
    @skip_unless_linux
    def test_privileges_probe_ok(self):
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-nnp-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))
        check = setup._privileges_probe_impl(cfg)
        self.assertTrue(check.ok, check.reason)
        self.assertIn("no_new_privs", check.reason)
        self.assertIn("read-back", check.reason)

    @skip_unless_linux
    def test_privileges_probe_setup_failure_refuses(self):
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-nnp-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))

        def boom(option, arg2=0, arg3=0, arg4=0, arg5=0):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        with unittest.mock.patch.object(priv_mod, "_prctl", boom):
            check = setup._privileges_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cannot enable no_new_privs", check.reason)

    @skip_unless_linux
    def test_privileges_probe_readback_mismatch_refuses(self):
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-nnp-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))
        calls = [0]

        def flaky(option, arg2=0, arg3=0, arg4=0, arg5=0):
            calls[0] += 1
            return 1 if calls[0] == 1 else 0

        with unittest.mock.patch.object(priv_mod, "_prctl", flaky):
            check = setup._privileges_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("read-back is 0, expected 1", check.reason)


class IntegrationTests(unittest.TestCase):
    @skip_unless_linux
    def test_hardened_refuses_at_seccomp_after_real_chain(self):
        # Full real path: the NAMESPACES, FILESYSTEM, NETWORK and
        # PRIVILEGES probes all pass; HARDENED then refuses at SECCOMP
        # (the next unimplemented stage) - fail closed, no execution.
        _require_fs(self)
        src = tempfile.mkdtemp(prefix="as-nnp-int-")
        self.addCleanup(shutil.rmtree, src, True)
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.SECCOMP)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertIn("no implementation", result.failure.reason)

    def test_privileges_guard_registered(self):
        # The PRIVILEGES stage guard is the real probe - registered by
        # isolation/setup at import (visible on every platform).
        self.assertIs(init_mod._STAGE_GUARDS[InitStage.PRIVILEGES],
                      setup._privileges_guard)


if __name__ == "__main__":
    unittest.main()
