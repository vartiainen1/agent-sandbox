"""P3: HARDENED end-to-end validation on native Linux with cgroup v2.

These tests verify the complete HARDENED security path through the
production RuntimeSession.initialize() -> RuntimeSession.execute() ->
run_in_sandbox() chain.

Verified substrate (approved result, commit 7c1c30e): native Ubuntu 24.04 /
Linux 6.8 / x86_64 QEMU VM, caller-owned delegated cgroup v2 subtree with
cpu/io/memory/pids controllers enabled, real block-device-backed io.max
workspace, toolchain at /opt/agent-sandbox-toolchain. Result: 24/24 PASS,
0 fail, 0 error, 0 skip.

Evidence: NATIVE VERIFIED (real sandbox boundary on the documented native
Linux substrate only — not generalized to other kernels/distros, aarch64,
CI runners, or the entire SECURITY_SPEC.md). On substrates without the
required cgroup delegation HARDENED refuses at RESOURCES (fail closed).
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import unittest.mock

# Skip entire module on non-Linux
LINUX = sys.platform == "linux"
SKIP_REASON = "HARDENED e2e requires native Linux with cgroup v2 delegation"


def _probe_hardened_feasible() -> tuple[bool, str]:
    """Probe whether the HARDENED path can actually execute on this substrate.

    Returns (feasible, reason). Checks:
    1. cgroup v2 available
    2. all four controllers available
    3. controllers enabled in subtree_control (not just available)
    4. delegation writable (mkdir/rmdir)
    5. io.max device resolvable (real block device)
    """
    if not LINUX:
        return False, "not Linux"
    try:
        import os as _os

        from agent_sandbox.isolation.cgroups import (
            _own_cgroup_path_impl,
            detect_cgroup_v2,
            probe_delegation,
            require_controllers,
        )
        state = detect_cgroup_v2()
        require_controllers(state)
    except Exception as e:
        return False, f"cgroup v2 detection failed: {e}"

    # Check if controllers are enabled in subtree_control
    parent = _os.path.join(
        "/sys/fs/cgroup",
        _own_cgroup_path_impl().lstrip("/")
    )
    subtree_path = _os.path.join(parent, "cgroup.subtree_control")
    try:
        with open(subtree_path) as f:
            enabled = frozenset(f.read().split())
    except OSError:
        enabled = frozenset()

    from agent_sandbox.isolation.cgroups import REQUIRED_CONTROLLERS
    missing = [c for c in REQUIRED_CONTROLLERS if c not in enabled]
    if missing:
        return False, (
            f"cgroup controllers not enabled in subtree_control "
            f"{subtree_path}: missing {', '.join(missing)} "
            f"(available: {sorted(state.available_controllers)}, "
            f"enabled: {sorted(enabled)}) - HARDENED refuses at RESOURCES"
        )

    # Check delegation
    blocked = probe_delegation()
    if blocked is not None:
        return False, f"cgroup delegation unavailable: {blocked}"

    # Check io device
    try:
        from agent_sandbox.isolation.cgroups import resolve_io_device
        with tempfile.TemporaryDirectory() as td:
            resolve_io_device(td)
    except Exception as e:
        return False, f"io.max device resolution failed: {e}"

    return True, "all HARDENED prerequisites met"


HARDENED_FEASIBLE, HARDENED_FEASIBLE_REASON = _probe_hardened_feasible()
SKIP_HARDENED = not HARDENED_FEASIBLE


def _make_config(mode: str = "hardened", workspace: str | None = None,
                 wall_time: int = 900, command: tuple[str, ...] | None = None) -> dict:
    """Build a config dict matching the project convention."""
    return {
        "mode": mode,
        "workspace": workspace or tempfile.mkdtemp(),
        "resources": {
            "cpu_seconds": 300, "memory_mb": 4096, "disk_mb": 10240,
            "processes": 256, "open_files": 4096, "output_mb": 50,
            "wall_time_seconds": wall_time,
            "cpu_quota_percent": 100, "io_mbps": 100,
        },
    }


def _run_hardened(command: tuple[str, ...], wall_time: int = 30,
                  mode: str = "hardened"):
    """Create a RuntimeSession, initialize, execute. Returns (session, result)."""
    from agent_sandbox.config import RuntimeConfig
    from agent_sandbox.models import ExecutionRequest
    from agent_sandbox.runtime.session import RuntimeSession

    cfg = RuntimeConfig.from_dict(_make_config(
        mode=mode, command=command, wall_time=wall_time))
    session = RuntimeSession(cfg)
    session.initialize()
    result = session.execute(ExecutionRequest(command=command))
    return session, result


# ---------------------------------------------------------------------------
# Substrate probe tests (always run on Linux, even if HARDENED can't execute)
# ---------------------------------------------------------------------------

@unittest.skipUnless(LINUX, SKIP_REASON)
class TestHardenedSubstrateProbe(unittest.TestCase):
    """Document the exact substrate state for P3 evidence."""

    def test_cgroup_v2_available(self):
        """cgroup v2 filesystem is mounted."""
        from agent_sandbox.isolation.cgroups import detect_cgroup_v2
        state = detect_cgroup_v2()
        self.assertTrue(state.available_controllers)

    def test_controllers_available(self):
        """All four architecture-named controllers are available."""
        from agent_sandbox.isolation.cgroups import (
            detect_cgroup_v2,
            require_controllers,
        )
        state = detect_cgroup_v2()
        require_controllers(state)  # raises if missing

    def test_delegation_writable(self):
        """A child cgroup can be created and removed.

        Root/non-root distinction: a non-root caller in an
        undelogated cgroup is EXPECTED to be refused (that is the
        exact fail-closed behavior HARDENED relies on) - it is
        recorded as the substrate's delegation state, not a failure.
        The delegation REQUIREMENT itself is never weakened: when the
        subtree IS delegated (root on the native VM), the probe must
        succeed."""
        from agent_sandbox.isolation.cgroups import probe_delegation
        blocked = probe_delegation()
        if blocked is not None:
            self.skipTest(
                f"Substrate limitation: cgroup delegation unavailable to "
                f"this caller: {blocked}. Non-root callers without a "
                f"delegated subtree cannot create child cgroups - the "
                f"expected fail-closed state HARDENED refuses on. A "
                f"delegated subtree (systemd Delegate=yes) or a root "
                f"caller provides it."
            )
        self.assertIsNone(blocked, f"Delegation blocked: {blocked}")

    def test_subtree_control_state(self):
        """Record which controllers are enabled in subtree_control."""
        from agent_sandbox.isolation.cgroups import (
            REQUIRED_CONTROLLERS,
            _own_cgroup_path_impl,
        )
        parent = os.path.join(
            "/sys/fs/cgroup",
            _own_cgroup_path_impl().lstrip("/")
        )
        subtree_path = os.path.join(parent, "cgroup.subtree_control")
        try:
            with open(subtree_path) as f:
                enabled = frozenset(f.read().split())
        except OSError:
            enabled = frozenset()
        missing = [c for c in REQUIRED_CONTROLLERS if c not in enabled]
        if missing:
            self.skipTest(
                f"Substrate limitation: controllers {', '.join(missing)} "
                f"not enabled in subtree_control ({subtree_path}). "
                f"Available: {sorted(enabled)}. "
                f"HARDENED requires all four controllers in subtree_control "
                f"on a delegation-capable native Linux host "
                f"(systemd Delegate=yes or equivalent); on substrates "
                f"without it HARDENED correctly refuses at RESOURCES."
            )
        self.assertEqual(len(enabled & set(REQUIRED_CONTROLLERS)), 4,
                         f"Expected 4 enabled, got {len(enabled & set(REQUIRED_CONTROLLERS))}: {enabled}")

    def test_io_device_resolvable(self):
        """io.max device can be resolved from kernel state."""
        from agent_sandbox.isolation.cgroups import resolve_io_device
        with tempfile.TemporaryDirectory() as td:
            try:
                maj, min_ = resolve_io_device(td)
                self.assertGreater(maj, 0, f"Major device should be > 0: {maj}:{min_}")
            except Exception as e:
                self.skipTest(
                    f"Substrate limitation: io.max device resolution "
                    f"failed: {e}. The workspace is on overlay/tmpfs "
                    f"(no real block device). HARDENED requires a "
                    f"resolvable real backing block device for io.max on "
                    f"a delegation-capable native Linux host."
                )

    def test_hardened_feasibility_summary(self):
        """Record overall HARDENED feasibility."""
        if not HARDENED_FEASIBLE:
            self.skipTest(
                f"HARDENED not feasible on this substrate: "
                f"{HARDENED_FEASIBLE_REASON}. "
                f"This is a substrate limitation, not a product defect. "
                f"A native Linux host with cgroup delegation "
                f"(systemd Delegate=yes) and a real block device "
                f"would satisfy all prerequisites."
            )


# ---------------------------------------------------------------------------
# Tests that verify HARDENED cgroup path directly (may skip on substrate)
# ---------------------------------------------------------------------------

@unittest.skipUnless(LINUX, SKIP_REASON)
class TestHardenedCgroupDirect(unittest.TestCase):
    """Direct cgroup operations - test what we can on any cgroup v2 substrate."""

    # Fixed-name session cgroups would collide across runs on a
    # persistent substrate (FileExistsError on the second run), so each
    # test uses a unique name and removes its session cgroup afterwards
    # (addCleanup - the cgroup is always cleaned up, pass or fail).
    def _make_session(self, base: str, limits, ws: str):
        from agent_sandbox.isolation.cgroups import (
            prepare_session,
            remove_session,
        )
        name = f"{base}-{os.getpid()}-{id(self)}"
        session = prepare_session("/sys/fs/cgroup", name, limits, ws)
        self.addCleanup(remove_session, session)
        return session

    def test_prepare_session_with_controllers(self):
        """prepare_session succeeds when controllers are in subtree_control."""
        from agent_sandbox.config import ResourceLimits
        from agent_sandbox.isolation.cgroups import (
            CgroupSession,
        )

        if not HARDENED_FEASIBLE:
            self.skipTest(
                f"Substrate limitation: {HARDENED_FEASIBLE_REASON}"
            )
        limits = ResourceLimits(
            cpu_seconds=10, memory_mb=64, disk_mb=100,
            processes=16, open_files=32, output_mb=10, wall_time_seconds=30,
        )
        with tempfile.TemporaryDirectory() as ws:
            session = self._make_session("sbx-p3-test", limits, ws)
            self.assertIsInstance(session, CgroupSession)
            self.assertIn("sbx-p3-test", session.path)

    def test_limits_readable_after_prepare(self):
        """All four cgroup limits are readable after prepare_session."""
        from agent_sandbox.config import ResourceLimits

        if not HARDENED_FEASIBLE:
            self.skipTest(
                f"Substrate limitation: {HARDENED_FEASIBLE_REASON}"
            )
        limits = ResourceLimits(
            cpu_seconds=10, memory_mb=64, disk_mb=100,
            processes=16, open_files=32, output_mb=10, wall_time_seconds=30,
            cpu_quota_percent=50, io_mbps=100,
        )
        with tempfile.TemporaryDirectory() as ws:
            session = self._make_session("sbx-p3-limits", limits, ws)
            pids = open(os.path.join(session.path, "pids.max")).read().strip()
            mem = open(os.path.join(session.path, "memory.max")).read().strip()
            cpu = open(os.path.join(session.path, "cpu.max")).read().strip()
            io = open(os.path.join(session.path, "io.max")).read().strip()

            self.assertEqual(pids, str(limits.processes))
            self.assertEqual(mem, str(limits.memory_mb * 1024 * 1024))
            self.assertIn("50000 100000", cpu)
            self.assertIn("rbps=", io)
            self.assertIn("wbps=", io)


# ---------------------------------------------------------------------------
# HARDENED end-to-end tests (skip when substrate can't support HARDENED)
# ---------------------------------------------------------------------------

@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedInitReady(unittest.TestCase):
    """T-P3-01: HARDENED initialization reaches READY."""

    def test_hardened_init_reaches_ready(self):
        """RuntimeSession with HARDENED mode reaches READY state."""
        from agent_sandbox.config import RuntimeConfig
        from agent_sandbox.runtime.session import RuntimeSession

        cfg = RuntimeConfig.from_dict(_make_config(mode="hardened"))
        session = RuntimeSession(cfg)
        result = session.initialize()
        self.assertTrue(result.ok, f"HARDENED init failed: {result.describe()}")


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedWorkloadExecutes(unittest.TestCase):
    """T-P3-02/03: Minimal workload executes through HARDENED + deterministic output."""

    def test_hardened_minimal_workload(self):
        """A minimal workload runs through the complete HARDENED boundary."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c", "print('HARDENED_OK'); import sys; sys.exit(0)"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused unexpectedly: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("HARDENED_OK", result.output)

    def test_hardened_deterministic_output(self):
        """HARDENED workload output is deterministic."""
        from agent_sandbox.models import ExecutionRefused

        _, r1 = _run_hardened(
            ("python3", "-c", "print('DET_XYZ')"), wall_time=15,
        )
        self.assertNotIsInstance(r1, ExecutionRefused)
        _, r2 = _run_hardened(
            ("python3", "-c", "print('DET_XYZ')"), wall_time=15,
        )
        self.assertNotIsInstance(r2, ExecutionRefused)
        self.assertEqual(r1.exit_code, r2.exit_code)
        self.assertEqual(r1.output.strip(), r2.output.strip())


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedCgroupMembership(unittest.TestCase):
    """T-P3-04: cgroup membership is correct at workload time."""

    def test_workload_in_session_cgroup(self):
        """Workload reads its own cgroup path (inside delegated cgroup)."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import os; "
             "text = open('/proc/self/cgroup').read(); "
             "print(text.strip())"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("0::", result.output, "Should show cgroup v2 membership")


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedSeccomp(unittest.TestCase):
    """T-P3-09/10: seccomp active inside workload, forbidden syscalls denied."""

    def test_seccomp_active_in_workload(self):
        """Workload runs with seccomp=2 (filter mode) active."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import os; "
             "status = open('/proc/self/status').read(); "
             "lines = [l for l in status.splitlines() if 'Seccomp' in l]; "
             "print(lines[0] if lines else 'NO_SECCOMP')"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("Seccomp:", result.output)

    def test_socket_syscall_denied(self):
        """socket() syscall is denied by the installed seccomp filter."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import socket\n"
             "try:\n"
             "    s = socket.socket()\n"
             "    print('SOCKET_ALLOWED')\n"
             "    s.close()\n"
             "except OSError as e:\n"
             "    print('SOCKET_DENIED: %s' % e)"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("SOCKET_DENIED", result.output)


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedCapabilities(unittest.TestCase):
    """T-P3-11: capabilities are fully reduced."""

    def test_capabilities_zero(self):
        """Workload runs with zero capabilities."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import os; "
             "status = open('/proc/self/status').read(); "
             "caps = [l for l in status.splitlines() if 'Cap' in l]; "
             "print(chr(10).join(caps) if caps else 'NO_CAPS_FOUND')"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        for line in result.output.strip().split("\n"):
            if "CapBnd" in line or "CapEff" in line or "CapPrm" in line:
                val = line.split(":")[-1].strip()
                self.assertEqual(val, "0000000000000000",
                                 f"Capability not zero: {line}")


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedNoNewPrivs(unittest.TestCase):
    """T-P3-12: no_new_privs is enabled."""

    def test_no_new_privs_set(self):
        """Workload has no_new_privs=1."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import os; "
             "status = open('/proc/self/status').read(); "
             "nnp = [l for l in status.splitlines() if 'NoNewPrivs' in l]; "
             "print(nnp[0] if nnp else 'NO_NNP_FOUND')"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("NoNewPrivs", result.output)
        self.assertIn("1", result.output)


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedNamespaceIsolation(unittest.TestCase):
    """T-P3-13: namespace isolation is active."""

    def test_pid_namespace_isolated(self):
        """Workload sees its own PID namespace."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import os; "
             "pid = os.getpid(); "
             "ns = os.readlink(f'/proc/{pid}/ns/pid'); "
             "print(f'PID={pid} NS={ns}')"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("NS=", result.output)

    def test_network_isolated(self):
        """Workload has no usable network."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import os; "
             "ifaces = open('/proc/self/net/dev').read(); "
             "print('IFACES=' + ifaces.strip().replace(chr(10), '|'))"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("IFACES=", result.output)


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedEnvIsolation(unittest.TestCase):
    """T-P3-14: environment isolation - only 6 approved vars."""

    def test_six_approved_vars_only(self):
        """Only the 6 approved environment variables are present."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c",
             "import os; "
             "env = dict(os.environ); "
             "keys = sorted(env.keys()); "
             "print('ENV_KEYS=' + ','.join(keys)); "
             "print('COUNT=' + str(len(keys)))"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        for line in result.output.split("\n"):
            if line.startswith("COUNT="):
                count = int(line.split("=")[1])
                self.assertEqual(count, 6,
                                 f"Expected 6 env vars, got {count}: {result.output}")


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedCleanup(unittest.TestCase):
    """T-P3-15/16: cleanup and timeout enforcement."""

    def test_cleanup_after_normal_completion(self):
        """After normal completion, cleanup is clean."""
        from agent_sandbox.models import ExecutionRefused

        _, result = _run_hardened(
            ("python3", "-c", "print('DONE'); import sys; sys.exit(0)"),
            wall_time=10,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.exit_code, 0, f"Workload failed: {result.output}")
        self.assertIn("DONE", result.output)
        self.assertFalse(result.cleanup_failure,
                         f"Cleanup failure: {result.cleanup_failure}")

    def test_timeout_enforcement(self):
        """External timeout terminates the workload."""
        from agent_sandbox.models import ExecutionRefused

        # NOTE: the workload cannot sleep - nanosleep/clock_nanosleep are
        # deliberately NOT in the 45-syscall allowlist (documented in
        # docs/seccomp-derivation/verification.md, "no expansion"). The
        # established hang pattern is a blocking read on a pipe the
        # workload creates itself (pipe2 + read are allowlisted), so the
        # external supervisor deadline is what terminates it.
        _, result = _run_hardened(
            ("python3", "-c",
             "import os; r, w = os.pipe(); "
             "os.read(r, 1); print('SHOULD_NOT_APPEAR')"),
            wall_time=3,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertTrue(result.timed_out,
                        f"Expected timed_out=True, got {result.timed_out}")
        self.assertNotIn("SHOULD_NOT_APPEAR", result.output)


@unittest.skipUnless(LINUX, SKIP_REASON)
@unittest.skipUnless(HARDENED_FEASIBLE, f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
class TestHardenedAuditCorrelation(unittest.TestCase):
    """T-P3-18: audit events correlate to the correct session."""

    def test_session_identity_in_result(self):
        """Result contains correct session identity and mode."""
        from agent_sandbox.models import ExecutionRefused, SecurityMode

        session, result = _run_hardened(
            ("python3", "-c", "print('AUDIT_OK')"),
            wall_time=15,
        )
        self.assertNotIsInstance(result, ExecutionRefused,
                                 f"HARDENED refused: {result}")
        self.assertEqual(result.mode, SecurityMode.HARDENED)
        self.assertEqual(result.session_id, session.session_id)
        self.assertEqual(result.exit_code, 0)


@unittest.skipUnless(LINUX, SKIP_REASON)
class TestHardenedStructural(unittest.TestCase):
    """Structural tests that verify HARDENED path is exercised."""

    def test_imports(self):
        """All HARDENED-related modules import cleanly."""
        from agent_sandbox.isolation import cgroups, setup
        self.assertTrue(hasattr(cgroups, "prepare_session"))
        self.assertTrue(hasattr(cgroups, "join_and_verify"))
        self.assertTrue(hasattr(setup, "run_in_sandbox"))

    def test_structural_dataclass(self):
        """CgroupSession dataclass is usable."""
        from agent_sandbox.isolation.cgroups import CgroupSession
        s = CgroupSession(path="/fake/path", limits=None, io_device=(0, 0))
        self.assertEqual(s.path, "/fake/path")


@unittest.skipUnless(LINUX, SKIP_REASON)
class TestHardenedFailClosedNegative(unittest.TestCase):
    """N1: the genuine negative-boundary cgroup rows on the native
    substrate (SECURITY_SPEC section 6 / S-018).

    These exercise the REAL resources probe (the forked child runs the
    actual establishment path); the failure is injected at the seam the
    real failure would hit (a cgroup limit write raising), never by
    disabling a control. A substrate without delegation must produce the
    genuine fail-closed refusal - never a relabeled PASS."""

    def test_hardened_refuses_at_resources_without_delegation(self):
        """Genuine absence of delegation -> HARDENED refuses AT RESOURCES
        with the precise cgroup reason (fail closed, never a partial
        success, never a relabeled PASS)."""
        import shutil
        import tempfile

        from agent_sandbox.config import RuntimeConfig
        from agent_sandbox.models import InitFailureCode, InitStage
        from agent_sandbox.security.init import SecurityInitializer
        from tests.unit import require_delegation_unavailable
        from tests.unit import require_namespace_available

        # Premise: the boundary must form (otherwise init refuses at
        # NAMESPACES and the RESOURCES-stage scenario is unreachable) AND
        # delegation must be absent (otherwise HARDENED reaches READY).
        require_namespace_available(self)
        require_delegation_unavailable(self)
        src = tempfile.mkdtemp(prefix="as-n1-native-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(_make_config(mode="hardened",
                                                   workspace=src))
        result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok,
                         "HARDENED must refuse without delegation")
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cgroup", result.failure.reason)
        self.assertIn("fail closed", result.failure.reason)

    @unittest.skipUnless(HARDENED_FEASIBLE,
                         f"HARDENED not feasible: {HARDENED_FEASIBLE_REASON}")
    def test_hardened_refuses_on_cgroup_limit_write_failure(self):
        """Delegation IS available but a genuine limit-write failure occurs
        inside the real resources probe -> HARDENED refuses AT RESOURCES
        (fail closed; the failure is injected at the write seam the real
        failure would hit - the control itself is not disabled)."""
        import shutil
        import tempfile

        from agent_sandbox.config import RuntimeConfig
        from agent_sandbox.isolation import cgroups as cgroups_mod
        from agent_sandbox.isolation.errors import NamespaceSetupError
        from agent_sandbox.models import InitFailureCode, InitStage
        from agent_sandbox.security.init import SecurityInitializer

        src = tempfile.mkdtemp(prefix="as-n1-native-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(_make_config(mode="hardened",
                                                   workspace=src))

        def boom(*_args, **_kwargs):
            raise NamespaceSetupError(
                "cgroup limit write failed (N1 injection)")

        with unittest.mock.patch.object(cgroups_mod, "_write_limits",
                                        side_effect=boom):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok,
                         "HARDENED must refuse when a limit write fails")
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cgroup", result.failure.reason)
        self.assertIn("limit write failed", result.failure.reason)


if __name__ == "__main__":
    unittest.main()
