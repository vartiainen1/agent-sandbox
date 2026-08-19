"""Phase 1 Step 16 tests - minimal successful workload demonstration
(item 22, the FINAL mandated Phase 1 item).

This is the first END-TO-END proof that a workload can cross the
COMPLETE v0.1 boundary:

    proc -> network -> NNP -> caps -> seccomp -> rlimits -> cgroup
    -> environment -> credentials/sockets -> bounded output
    -> external timeout -> process-tree containment/cleanup -> workload

It does NOT re-prove each mechanism (Steps 1-15 already did, with their
own evidence). It proves SUCCESSFUL WORKLOAD EXECUTION: the workload
actually runs, returns deterministic output, observes the established
invariants from INSIDE, and the supervisor observes a clean session.

The minimal workload returns fully deterministic evidence from inside
the boundary: pid == 1 (PID 1 of the sandbox namespace), uid/gid == 0
(mapped identity), the approved six-variable environment with exactly
the approved values, kernel-state read-backs (NoNewPrivs=1, Seccomp=2,
all capability sets zero), and the six mandated rlimits (soft == hard).
No host environment variable or credential/control-socket path is
reachable.

Categories (kept separate, per the charter):
- Host-side contract tests (runs everywhere).
- Real-sandbox end-to-end tests (real run_in_sandbox under the ACTUAL
  runtime filter + the full fail-closed initializer) - gated on the
  real namespace+filesystem probes succeeding on this substrate
  (native 24.04 runner: SKIPPED with recorded reason; Docker uid 1001:
  VERIFIED DOCKER). The end-to-end path is exercised in RESTRICTED mode
  (rlimits-only resources, ADR-007): HARDENED's cgroup half cannot
  reach READY on any current substrate (Step 10 delegation limitation)
  and correctly refuses AT RESOURCES - never a silent pass.
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
from agent_sandbox.isolation import credentials as cred_mod
from agent_sandbox.isolation import environment as env_mod
from agent_sandbox.security import init as init_mod
from agent_sandbox.security.init import SecurityInitializer
from agent_sandbox.models import ExecutionRequest, InitStage

from tests.unit import test_credentials as tc
from tests.unit import test_resources as tr

valid_config = tc.valid_config
skip_unless_linux = tc.skip_unless_linux
_require_fs = tr._require_fs

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

# The deterministic output contract of the minimal successful workload.
SENTINEL = "MINIMAL-WORKLOAD-OK"

# The approved six-variable environment (Step 11 policy, ADR-009) -
# pinned against the authoritative module so the contract cannot drift.
EXPECTED_ENV = dict(env_mod.SANITIZED_ENV)
EXPECTED_ENV_KEYS = sorted(("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL",
                            "TERM"))


def _minimal_workload(state, fs):
    """The minimal successful workload: returns fully deterministic
    evidence collected from INSIDE the complete boundary. Only
    allowlisted syscalls are used (getpid/getuid/getgid/openat/read/
    prlimit64/write - the 45-syscall gate)."""
    evidence = {}
    evidence["sentinel"] = SENTINEL
    evidence["pid"] = os.getpid()
    evidence["uid"] = os.getuid()
    evidence["gid"] = os.getgid()
    evidence["env"] = dict(os.environ)
    status = ""
    with open("/proc/self/status") as f:
        status = f.read()
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
                  "NoNewPrivs", "Seccomp"):
        for line in status.splitlines():
            if line.startswith(field + ":"):
                evidence[field] = line.split(":", 1)[1].strip()
    import resource as _resource
    evidence["rlimits"] = {}
    for attr in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_NPROC",
                 "RLIMIT_NOFILE", "RLIMIT_FSIZE", "RLIMIT_CORE"):
        res = getattr(_resource, attr)
        evidence["rlimits"][attr] = list(_resource.getrlimit(res))
    return json.dumps(evidence)


class WorkloadContractTests(unittest.TestCase):
    """Host-side contract tests - run everywhere."""

    def test_sentinel_is_stable(self):
        self.assertEqual(SENTINEL, "MINIMAL-WORKLOAD-OK")

    def test_env_contract_matches_authoritative_policy(self):
        # The expected environment the workload asserts must be exactly
        # the approved six-variable sandbox environment (Step 11,
        # ADR-009) - a drift here would break the end-to-end contract.
        self.assertEqual(EXPECTED_ENV, env_mod.SANITIZED_ENV)
        self.assertEqual(sorted(EXPECTED_ENV), EXPECTED_ENV_KEYS)
        self.assertEqual(len(EXPECTED_ENV), 6)


class WorkloadGateTests(unittest.TestCase):
    """The successful path reaches READY only after all required guards
    (deterministic seams - the REAL chain is exercised on the capable
    substrate by the EndToEnd tests below and the real-chain tests in
    test_environment/test_resources/test_credentials)."""

    def setUp(self):
        self._patch = unittest.mock.patch.object(
            init_mod, "_is_linux", return_value=True)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_execute_blocked_until_initialization_succeeds(self):
        # A workload may not execute until every required guard passed.
        # With a probe failure injected, initialization REFUSES and the
        # session gate blocks execution.
        from agent_sandbox.isolation import setup as setup_mod
        from agent_sandbox.runtime.session import RuntimeSession
        from agent_sandbox.models import ExecutionRefused, InitFailureCode

        # Everything before EXECUTION passes; the EXECUTION guard fails.
        ok = unittest.mock.patch.object(
            setup_mod, "_probe_impl",
            return_value=tc_stage_check_ok())
        fs_ok = unittest.mock.patch.object(
            setup_mod, "_filesystem_probe_impl",
            return_value=tc_stage_check_ok())
        net_ok = unittest.mock.patch.object(
            setup_mod, "_network_probe_impl",
            return_value=tc_stage_check_ok())
        priv_ok = unittest.mock.patch.object(
            setup_mod, "_privileges_probe_impl",
            return_value=tc_stage_check_ok())
        sc_ok = unittest.mock.patch.object(
            setup_mod, "_seccomp_probe_impl",
            return_value=tc_stage_check_ok())
        res_ok = unittest.mock.patch.object(
            setup_mod, "_resources_probe_impl",
            return_value=tc_stage_check_ok())
        env_ok = unittest.mock.patch.object(
            setup_mod, "_environment_probe_impl",
            return_value=tc_stage_check_ok())
        exec_fail = unittest.mock.patch.object(
            setup_mod, "_execution_probe_impl",
            return_value=tc_stage_check_ok(ok=False,
                                           reason="execution probe failed (test)"))
        with ok, fs_ok, net_ok, priv_ok, sc_ok, res_ok, env_ok, exec_fail:
            session = RuntimeSession(RuntimeConfig.from_dict(
                valid_config("/srv/w", mode="restricted")))
            result = session.initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertEqual(result.failure.stage, InitStage.EXECUTION)
        refusal = session.execute(ExecutionRequest(command=("/bin/echo",
                                                            "hello")))
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertIn("initialization did not succeed", refusal.reason)

    def test_all_guards_pass_reaches_ready(self):
        from agent_sandbox.isolation import setup as setup_mod
        from agent_sandbox.runtime.session import RuntimeSession

        ok = unittest.mock.patch.object(
            setup_mod, "_probe_impl",
            return_value=tc_stage_check_ok())
        fs_ok = unittest.mock.patch.object(
            setup_mod, "_filesystem_probe_impl",
            return_value=tc_stage_check_ok())
        net_ok = unittest.mock.patch.object(
            setup_mod, "_network_probe_impl",
            return_value=tc_stage_check_ok())
        priv_ok = unittest.mock.patch.object(
            setup_mod, "_privileges_probe_impl",
            return_value=tc_stage_check_ok())
        sc_ok = unittest.mock.patch.object(
            setup_mod, "_seccomp_probe_impl",
            return_value=tc_stage_check_ok())
        res_ok = unittest.mock.patch.object(
            setup_mod, "_resources_probe_impl",
            return_value=tc_stage_check_ok())
        env_ok = unittest.mock.patch.object(
            setup_mod, "_environment_probe_impl",
            return_value=tc_stage_check_ok())
        exec_ok = unittest.mock.patch.object(
            setup_mod, "_execution_probe_impl",
            return_value=tc_stage_check_ok())
        with ok, fs_ok, net_ok, priv_ok, sc_ok, res_ok, env_ok, exec_ok:
            session = RuntimeSession(RuntimeConfig.from_dict(
                valid_config("/srv/w", mode="restricted")))
            result = session.initialize()
        self.assertTrue(result.ok, result.describe())
        self.assertEqual(result.stage, InitStage.READY)


def tc_stage_check_ok(ok=True, reason="probe ok (test)"):
    from agent_sandbox.models import StageCheck
    return StageCheck(ok=ok, reason=reason)


class EndToEndWorkloadTests(unittest.TestCase):
    """Real-sandbox end-to-end demonstration (item 22) - the workload
    crosses the COMPLETE boundary under the ACTUAL runtime filter
    (DOCKER VERIFIED on the uid-1001 container; native runner: SKIPPED
    with recorded reason)."""

    def setUp(self):
        if not LINUX:
            self.skipTest("real sandbox requires Linux")
        _require_fs(self)

    def _run(self, fn, output_mb=None, wall_time_seconds=None):
        from agent_sandbox.isolation import rootfs as rootfs_mod
        from agent_sandbox.isolation import setup
        src = tempfile.mkdtemp(prefix="as-wl-int-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)
        kwargs = {
            "rootfs_state": rootfs_state,
            "limits": RuntimeConfig.from_dict(
                valid_config(src, mode="restricted")).resources,
            "env_allowlist": ("PATH", "HOME", "LANG", "LC_ALL", "TERM",
                              "TMPDIR"),
        }
        if output_mb is not None:
            kwargs["output_mb"] = output_mb
        if wall_time_seconds is not None:
            kwargs["wall_time_seconds"] = wall_time_seconds
        return setup.run_in_sandbox(fn, **kwargs)

    @skip_unless_linux
    def test_minimal_successful_workload_executes(self):
        # The acceptance proof: the workload actually executes, returns
        # deterministic output, observes every established invariant
        # from INSIDE, and the supervisor observes a clean session.
        run = self._run(_minimal_workload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertFalse(run.truncated)
        self.assertFalse(run.timed_out)
        self.assertEqual(run.cleanup_failure, "",
                         f"no workload process may survive: "
                         f"{run.cleanup_failure}")
        data = json.loads(run.output)
        self.assertEqual(data["sentinel"], SENTINEL)
        # PID 1 of the sandbox PID namespace; mapped uid/gid 0.
        self.assertEqual(data["pid"], 1)
        self.assertEqual((data["uid"], data["gid"]), (0, 0))
        # Exactly the approved six-variable environment - no host
        # variable, no missing/incorrect value (S-034).
        self.assertEqual(data["env"], EXPECTED_ENV)
        # Kernel-state invariants (Steps 6-8).
        self.assertEqual(data["NoNewPrivs"], "1")
        self.assertEqual(data["Seccomp"], "2")
        for cap in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertEqual(int(data[cap], 16), 0,
                             f"{cap} must be empty in the workload")
        # The six mandated rlimits, soft == hard (Step 9, ADR-007).
        rl = data["rlimits"]
        limits = RuntimeConfig.from_dict(
            valid_config("/srv/w", mode="restricted")).resources
        self.assertEqual(rl["RLIMIT_CPU"], [limits.cpu_seconds] * 2)
        self.assertEqual(rl["RLIMIT_AS"],
                         [limits.memory_mb * 1024 * 1024] * 2)
        self.assertEqual(rl["RLIMIT_NPROC"], [limits.processes] * 2)
        self.assertEqual(rl["RLIMIT_NOFILE"], [limits.open_files] * 2)
        self.assertEqual(rl["RLIMIT_FSIZE"],
                         [limits.disk_mb * 1024 * 1024] * 2)
        self.assertEqual(rl["RLIMIT_CORE"], [0, 0])

    @skip_unless_linux
    def test_bounded_output_and_timeout_configuration_active(self):
        # The output bound and the wall-clock deadline are ACTIVE (a
        # flooding/hanging workload trips them - proven in Steps 13-14)
        # but the minimal workload completes within both.
        run = self._run(_minimal_workload, output_mb=1,
                        wall_time_seconds=60)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertFalse(run.truncated)
        self.assertFalse(run.timed_out)
        data = json.loads(run.output)
        self.assertEqual(data["sentinel"], SENTINEL)

    @skip_unless_linux
    def test_full_initializer_reaches_ready_then_workload_executes(self):
        # The complete journey: every real guard passes (on this
        # substrate) -> READY -> the workload executes through the
        # complete boundary. Only after ALL required guards.
        src = tempfile.mkdtemp(prefix="as-wl-ready-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        cfg = RuntimeConfig.from_dict(valid_config(src, mode="restricted"))
        with unittest.mock.patch.object(init_mod, "_is_linux",
                                        return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertTrue(result.ok, result.describe())
        self.assertEqual(result.stage, InitStage.READY)
        run = self._run(_minimal_workload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(json.loads(run.output)["sentinel"], SENTINEL)

    @skip_unless_linux
    def test_verification_failure_prevents_execution(self):
        # Marker-absent: if a required verification refuses inside
        # PID 1, the workload fn (which writes the marker) never runs.
        src = tempfile.mkdtemp(prefix="as-wl-fail-")
        self.addCleanup(shutil.rmtree, src, True)
        marker = pathlib.Path(src) / "marker.txt"
        marker.write_text("x\n")

        def fn(state, fs):
            marker.write_text("WORKLOAD-RAN\n")
            return "should not happen"

        with unittest.mock.patch.object(
                cred_mod, "_lexists_impl", return_value=True):
            run = self._run(fn)
        self.assertNotEqual(run.exit_code, 0)
        self.assertIn("FAIL setup", run.output)
        self.assertNotIn("WORKLOAD-RAN", marker.read_text())

    @skip_unless_linux
    def test_no_host_env_or_credential_leakage(self):
        # From the workload view: no credential/control-socket path is
        # reachable and the environment carries exactly the approved
        # six variables - no host variable leaked in (S-003/S-004,
        # S-034), demonstrated end-to-end at workload time.
        def fn(state, fs):
            hits = sorted(p for p in cred_mod.CREDENTIAL_PATHS
                          if os.path.lexists(p))
            return json.dumps({"hits": hits,
                               "env_keys": sorted(os.environ.keys())})

        run = self._run(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        self.assertEqual(data["hits"], [],
                         "credential/control-socket paths must be "
                         "unreachable from the workload")
        self.assertEqual(data["env_keys"], EXPECTED_ENV_KEYS)


if __name__ == "__main__":
    unittest.main()
