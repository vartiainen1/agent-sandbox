"""Phase 1 Step 9 tests - rlimits (REAL Linux execution, S-012/S-027,
ADR-007): the six mandated limits (RLIMIT_CPU/AS/NPROC/NOFILE/FSIZE/
CORE=0) are lowered (soft == hard) in sandbox PID 1 AFTER the seccomp
install and verified by kernel-state read-back (getrlimit) - never
"the syscall returned success". Any set/read-back failure or unexpected
value REFUSES before the workload. Inheritance across the workload tree
and the S-027 "cannot raise" property are tested.

Ordering constraint (charter): seccomp (Step 8) is already installed, so
the rlimits must be establishable through the existing 45-syscall
allowlist. glibc's setrlimit/getrlimit map to prlimit64, which IS
allowlisted - the sandbox-internal tests here exercise exactly that
(limits established under the ACTUAL runtime filter).

Categories (kept separate, per the charter):
- Host-side policy/apply/verify logic (runs everywhere).
- Sandbox-internal tests (run inside the real sandbox under the actual
  filter) - gated on the real namespace probe succeeding on this
  substrate (native 24.04 runner: SKIPPED with recorded reason; Docker
  uid 1001: VERIFIED DOCKER).
- Probe + integration: the RESOURCES stage guard's real path - HARDENED
  refuses AT RESOURCES (cgroup v2 half is Step 10), RESTRICTED completes
  its RESOURCES stage with rlimits only (ADR-007) and advances to
  ENVIRONMENT.
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

try:
    import resource  # Unix-only: available on Linux (the real runs)
    _HAS_RESOURCE = True
except ImportError:  # pragma: no cover - Windows: import-safe, tests skip
    resource = None
    _HAS_RESOURCE = False

from agent_sandbox.config import ResourceLimits, RuntimeConfig
from agent_sandbox.isolation import resources as resources_mod
from agent_sandbox.isolation import setup
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real rlimit operations require Linux with os.fork "
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
    global _fs_status
    if _fs_status is None:
        with tempfile.TemporaryDirectory(prefix="as-rs-gate-") as src:
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


def _limits() -> ResourceLimits:
    return RuntimeConfig.from_dict(valid_config("/tmp/x")).resources


class ResourcePolicyTests(unittest.TestCase):
    """Policy mapping + apply/verify logic - runs everywhere."""

    def setUp(self):
        # Windows CPython has no `resource` module, so the module's RLIMIT
        # constants are None there. Give them distinct sentinel values so
        # the policy/apply/verify logic (and the name mapping) is testable
        # identically on every platform. On Linux the real constants are
        # used untouched.
        self._const_patches = []
        if not _HAS_RESOURCE:
            names = {}
            for i, name in enumerate(("RLIMIT_CPU", "RLIMIT_AS",
                                      "RLIMIT_NPROC", "RLIMIT_NOFILE",
                                      "RLIMIT_FSIZE", "RLIMIT_CORE")):
                p = unittest.mock.patch.object(resources_mod, name, 1000 + i)
                p.start()
                self._const_patches.append(p)
                names[1000 + i] = name
            # Map the sentinels to their canonical names so the
            # deterministic reasons/state keys stay platform-independent.
            p = unittest.mock.patch.dict(resources_mod._RLIMIT_NAMES, names)
            p.start()
            self._const_patches.append(p)

    def tearDown(self):
        for p in self._const_patches:
            p.stop()

    def test_rlimit_policy_mapping(self):
        # Exact mapping (ARCHITECTURE.md section 9, ADR-007): CPU seconds,
        # AS in bytes, NPROC count, NOFILE count, FSIZE in bytes, CORE 0.
        # References the module's own constants so the test also pins the
        # guarded-import behavior on platforms without `resource`.
        limits = _limits()
        self.assertEqual(resources_mod.rlimit_policy(limits), (
            (resources_mod.RLIMIT_CPU, 300),
            (resources_mod.RLIMIT_AS, 4096 * 1024 * 1024),
            (resources_mod.RLIMIT_NPROC, 256),
            (resources_mod.RLIMIT_NOFILE, 4096),
            (resources_mod.RLIMIT_FSIZE, 10240 * 1024 * 1024),
            (resources_mod.RLIMIT_CORE, 0),
        ))

    def test_policy_core_is_zero(self):
        # RLIMIT_CORE=0 is non-negotiable (T-021: no core dumps).
        limits = _limits()
        policy = dict(resources_mod.rlimit_policy(limits))
        self.assertEqual(policy[resources_mod.RLIMIT_CORE], 0)

    def test_apply_sets_all_six_soft_and_hard(self):
        limits = _limits()
        calls: list[tuple[int, int]] = []

        def fake_set(which: int, value: int) -> None:
            calls.append((which, value))

        with unittest.mock.patch.object(resources_mod, "_set_rlimit", fake_set):
            resources_mod.apply_rlimits(limits)
        self.assertEqual(calls, list(resources_mod.rlimit_policy(limits)))

    def test_apply_failure_refuses(self):
        def boom(which: int, value: int) -> None:
            raise OSError(1, "setrlimit EPERM (simulated)")

        with unittest.mock.patch.object(resources_mod, "_set_rlimit", boom):
            with self.assertRaises(NamespaceSetupError) as cm:
                resources_mod.apply_rlimits(_limits())
        self.assertIn("cannot set RLIMIT_CPU", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_verify_readback_ok(self):
        limits = _limits()
        expected = dict(resources_mod.rlimit_policy(limits))

        def fake_get(which: int):
            return (expected[which], expected[which])

        with unittest.mock.patch.object(resources_mod, "_get_rlimit", fake_get):
            state = resources_mod.verify_rlimits(limits)
        self.assertEqual(state.cpu_seconds, 300)
        self.assertEqual(state.address_space_bytes, 4096 * 1024 * 1024)
        self.assertEqual(state.processes, 256)
        self.assertEqual(state.open_files, 4096)
        self.assertEqual(state.file_size_bytes, 10240 * 1024 * 1024)
        self.assertEqual(state.core_bytes, 0)

    def test_verify_soft_mismatch_refuses(self):
        # Any read-back other than (soft == hard == expected) is a
        # refusal - never a warning-and-continue (S-027).
        def fake_get(which: int):
            return (0, 0)

        with unittest.mock.patch.object(resources_mod, "_get_rlimit", fake_get):
            with self.assertRaises(NamespaceSetupError) as cm:
                resources_mod.verify_rlimits(_limits())
        self.assertIn("RLIMIT_CPU read-back is (soft=0, hard=0), "
                      "expected (300, 300)", str(cm.exception))
        self.assertIn("rlimit verification failed", str(cm.exception))

    def test_verify_hard_mismatch_refuses(self):
        # A hard limit that differs from the policy means the applied
        # limit is not what the kernel enforces - refusal.
        def fake_get(which: int):
            expected = dict(resources_mod.rlimit_policy(_limits()))[which]
            return (expected, expected + 1)

        with unittest.mock.patch.object(resources_mod, "_get_rlimit", fake_get):
            with self.assertRaises(NamespaceSetupError) as cm:
                resources_mod.verify_rlimits(_limits())
        self.assertIn("hard=301", str(cm.exception))

    def test_verify_read_failure_refuses(self):
        def boom(which: int):
            raise OSError(1, "getrlimit failed (simulated)")

        with unittest.mock.patch.object(resources_mod, "_get_rlimit", boom):
            with self.assertRaises(NamespaceSetupError) as cm:
                resources_mod.verify_rlimits(_limits())
        self.assertIn("cannot read RLIMIT_CPU", str(cm.exception))

    def test_establish_order_apply_before_verify(self):
        # Ordering (apply -> verify) is structural in the single entry
        # point - the workload cannot run between them.
        order: list[str] = []

        def fake_set(which: int, value: int) -> None:
            order.append("apply")

        def fake_get(which: int):
            order.append("verify")
            expected = dict(resources_mod.rlimit_policy(_limits()))[which]
            return (expected, expected)

        with unittest.mock.patch.object(resources_mod, "_set_rlimit", fake_set):
            with unittest.mock.patch.object(resources_mod, "_get_rlimit", fake_get):
                resources_mod.establish_and_verify_rlimits(_limits())
        self.assertEqual(order, ["apply"] * 6 + ["verify"] * 6)


class ResourceProbeTests(unittest.TestCase):
    """RESOURCES stage guard - the fail-closed shape (host-side, no real
    namespace needed for the platform path)."""

    def test_resources_probe_platform_fail_closed(self):
        cfg = RuntimeConfig.from_dict(
            valid_config(tempfile.mkdtemp(prefix="as-rs-")))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=False):
            check = setup._resources_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.PLATFORM_UNSUPPORTED)
        self.assertIn("rlimits cannot be established", check.reason)

    def test_resources_guard_registered(self):
        self.assertIs(init_mod._STAGE_GUARDS[InitStage.RESOURCES],
                      setup._resources_guard)

    @skip_unless_linux
    def test_hardened_resources_probe_blocks_without_delegation(self):
        # The probe establishes the rlimits and then attempts the cgroup
        # v2 session for HARDENED. On this substrate delegation is
        # unavailable (Docker rootless: cgroupfs read-only), so the probe
        # REFUSES AT RESOURCES with the precise detected reason - never a
        # partial success, never a silent downgrade to rlimits-only. On a
        # delegation-capable host the probe passes (privileged-substrate
        # tests in test_cgroups.py).
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-rs-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))
        check = setup._resources_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cgroup", check.reason)
        self.assertIn("fail closed", check.reason)
        self.assertNotIn("OK", check.reason)

    @skip_unless_linux
    def test_restricted_resources_probe_ok(self):
        # RESTRICTED's RESOURCES stage is rlimits only (ADR-007) - the
        # probe establishes + verifies and reports OK.
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-rs-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src, mode="restricted"))
        check = setup._resources_probe_impl(cfg)
        self.assertTrue(check.ok, check.reason)
        self.assertIn("rlimits established", check.reason)
        self.assertIn("RESTRICTED resource stage complete", check.reason)


class ResourceBoundaryTests(unittest.TestCase):
    """The limits INSIDE the sandbox (real Linux, under the ACTUAL
    runtime filter, established AFTER the seccomp install)."""

    def setUp(self):
        _require_ns(self)
        self._marker_dir = tempfile.mkdtemp(prefix="as-rs-")
        self.addCleanup(shutil.rmtree, self._marker_dir, True)
        self._src = tempfile.mkdtemp(prefix="as-rs-ws-")
        self.addCleanup(shutil.rmtree, self._src, True)
        self._cfg = RuntimeConfig.from_dict(valid_config(self._src))

    def _policy_dict(self) -> dict[int, int]:
        return dict(resources_mod.rlimit_policy(self._cfg.resources))

    @skip_unless_linux
    def test_limits_established_and_readback_in_pid1(self):
        # Kernel-state read-back AT WORKLOAD TIME: every limit must read
        # back (soft == hard == policy value) - the workload runs with the
        # exact applied limits.
        def fn(state):
            vals = {}
            for which, _ in resources_mod.rlimit_policy(self._cfg.resources):
                soft, hard = resource.getrlimit(which)
                vals[resources_mod._rlimit_name(which)] = [soft, hard]
            return json.dumps(vals)

        run = setup.run_in_sandbox(fn, limits=self._cfg.resources)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output.strip())
        for which, value in resources_mod.rlimit_policy(self._cfg.resources):
            name = resources_mod._rlimit_name(which)
            self.assertEqual(data[name], [value, value],
                             f"{name} must read back (soft == hard == value)")

    @skip_unless_linux
    def test_rlimits_work_under_installed_filter(self):
        # Empirical ordering proof: the rlimits are established AFTER the
        # seccomp install (run_in_sandbox PID-1 order), and they succeed -
        # glibc's setrlimit/getrlimit map to prlimit64, which IS in the
        # 45-syscall allowlist. No filter change, no syscall added. The
        # workload ALSO runs under the filter (Seccomp=2) with the limits
        # in force - one view of the full Stage-A state.
        def fn(state):
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            st = ""
            with open("/proc/self/status", "r", encoding="ascii") as f:
                st = f.read()
            mode = -1
            for line in st.splitlines():
                if line.startswith("Seccomp:"):
                    mode = int(line.split(":", 1)[1].strip())
            return json.dumps({"nofile": [soft, hard], "seccomp": mode})

        run = setup.run_in_sandbox(fn, limits=self._cfg.resources)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output.strip())
        self.assertEqual(data["nofile"], [4096, 4096])
        self.assertEqual(data["seccomp"], 2, "filter must be active with limits")

    @skip_unless_linux
    def test_workload_cannot_raise_a_limit(self):
        # S-027 / T-035: a lowered hard limit can NEVER be raised by the
        # workload (kernel rule - raising requires CAP_SYS_RESOURCE, which
        # Step 7 removed). The attempt must fail.
        def fn(state):
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
                return "RAISED-OK"
            except (OSError, ValueError) as e:
                return "DENIED:" + type(e).__name__

        run = setup.run_in_sandbox(fn, limits=self._cfg.resources)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertTrue(run.output.strip().startswith("DENIED"),
                        f"raise attempt must be denied, got: {run.output}")

    @skip_unless_linux
    def test_workload_not_executed_when_set_fails(self):
        # rlimit establishment failure -> REFUSE, workload never runs
        # (marker-absent evidence).
        marker = str(pathlib.Path(self._marker_dir) / "ran-set.txt")

        def fn(state):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        def boom(which: int, value: int) -> None:
            raise OSError(1, "setrlimit EPERM (simulated)")

        with unittest.mock.patch.object(resources_mod, "_set_rlimit", boom):
            run = setup.run_in_sandbox(fn, limits=self._cfg.resources)
        self.assertNotEqual(run.exit_code, 0)
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertFalse(os.path.exists(marker))
        self.assertIn("cannot set RLIMIT_CPU", run.output)

    @skip_unless_linux
    def test_unexpected_limit_readback_refuses(self):
        # Verification failure (unexpected read-back) -> REFUSE, workload
        # never runs (marker-absent evidence).
        marker = str(pathlib.Path(self._marker_dir) / "ran-verify.txt")

        def fn(state):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        def fake_get(which: int):
            return (0, 0)

        with unittest.mock.patch.object(resources_mod, "_get_rlimit", fake_get):
            run = setup.run_in_sandbox(fn, limits=self._cfg.resources)
        self.assertNotEqual(run.exit_code, 0)
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertFalse(os.path.exists(marker))
        self.assertIn("rlimit verification failed", run.output)
        self.assertIn("RLIMIT_CPU read-back is (soft=0, hard=0)", run.output)


class ResourceIntegrationTests(unittest.TestCase):
    """Full real chain through the fail-closed initializer."""

    @skip_unless_linux
    def test_hardened_real_chain_blocks_at_resources_without_delegation(self):
        # Full real path: all mechanism probes through RESOURCES run
        # (namespaces, filesystem, network, privileges, seccomp, rlimits);
        # HARDENED then refuses AT RESOURCES because cgroup v2 delegation
        # is unavailable on this substrate (Docker rootless: cgroupfs
        # read-only) - the refusal point stays at RESOURCES, fail closed.
        # On a delegation-capable host the chain would advance to
        # ENVIRONMENT (asserted by the privileged-substrate tests in
        # test_cgroups.py).
        _require_fs(self)
        src = tempfile.mkdtemp(prefix="as-rs-int-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cgroup", result.failure.reason)
        self.assertIn("fail closed", result.failure.reason)

    @skip_unless_linux
    def test_restricted_real_chain_advances_to_execution(self):
        # RESTRICTED completes RESOURCES (rlimits only, ADR-007) and
        # ENVIRONMENT (sanitization, Step 11) and refuses at the next
        # unimplemented stage (EXECUTION). Fail closed either way; never
        # a silent pass.
        _require_fs(self)
        src = tempfile.mkdtemp(prefix="as-rs-int-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src, mode="restricted"))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.EXECUTION)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertIn("no implementation", result.failure.reason)


if __name__ == "__main__":
    unittest.main()
