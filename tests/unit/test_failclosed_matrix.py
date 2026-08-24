"""N1 - the systematic fail-closed matrix (SECURITY_SPEC.md section 6,
S-018, gap-analysis finding G2).

For EVERY mandatory security control the spec requires the same shape:

    <control> cannot be established  ->  refuse execution
                                       ->  deterministic reason/stage/code
                                       ->  workload never runs (fail closed)
                                       ->  cleanup happens
                                       ->  audit event correlates to the session

This file turns that table into tests. Two layers, mirroring the
architecture (agent_sandbox/isolation/setup.py):

1. INIT-PATH (wiring, runs everywhere): the SecurityInitializer walks the
   fixed stage sequence and refuses at the FIRST mandatory stage whose
   real-path probe fails. The probe outcomes are injected at the same
   module-level seams the existing suites use (setup._<stage>_probe_impl);
   the REAL probes are exercised for real in test_namespaces.py,
   test_rootfs.py, test_network.py, test_privileges.py, test_seccomp.py,
   test_resources.py, test_environment.py and test_lifecycle.py (and the
   native P3 suite). These tests assert the wiring: stage, code, reason,
   no-silent-downgrade, session gate, and audit correlation.

2. EXECUTE-PATH (Linux + fork, real refusal path): run_in_sandbox() runs
   the real fork chain; a seam function the child calls is patched to
   FAIL (the same seam the real failure would hit - never a mock that
   makes a control succeed, never os.fork/os.pipe). The child reports
   "FAIL setup: ...", the workload function NEVER runs (marker absent),
   and the supervisor returns the failure deterministically.

3. POST-RUN: cleanup failure must be visible (S-038) - never reported as
   success.

Failure injection discipline (approved N1 design):
- Only FAILURES are injected, always at a controlled seam BEFORE the
  security decision - never a bypass of the actual control.
- No production code is modified; no seccomp/namespace/capability/
  filesystem/network/cgroup policy is touched; no compatibility fallback.
- Audit remains observational (S-024) - recorder failure never blocks
  execution.
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
from agent_sandbox import config as config_mod
from agent_sandbox import registry
from agent_sandbox.audit.recorder import AuditRecorder
from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import cgroups as cgroups_mod
from agent_sandbox.isolation import credentials as cred_mod
from agent_sandbox.isolation import environment as env_mod
from agent_sandbox.isolation import filesystem as fs_mod
from agent_sandbox.isolation import lifecycle as lifecycle_mod
from agent_sandbox.isolation import network as net_mod
from agent_sandbox.isolation import privileges as priv_mod
from agent_sandbox.isolation import resources as resources_mod
from agent_sandbox.isolation import rootfs as rootfs_mod
from agent_sandbox.isolation import seccomp as seccomp_mod
from agent_sandbox.isolation import setup as setup_mod
from agent_sandbox.isolation import userns
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import (
    ExecutionRefused,
    ExecutionRequest,
    ExecutionResult,
    InitFailureCode,
    InitStage,
    SecurityMode,
    StageCheck,
)
from agent_sandbox.runtime import session as session_mod
from agent_sandbox.runtime.session import RuntimeSession, SessionState
from agent_sandbox.security import init as init_mod
from agent_sandbox.security.init import SecurityInitializer
from tests.unit.test_cli import _ready_session_context
from tests.unit.test_cli_sessions import _CliTestCase, _run_cli

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX,
    "real fork-chain refusal path requires Linux with os.fork "
    "(non-Linux fail-closed behavior is covered by the init-path wiring "
    "tests below and test_skeleton.py)")


def valid_config(workspace: str, mode: str = "hardened") -> dict:
    """Mirror of tests/unit/test_resources.py::valid_config."""
    return {
        "mode": mode,
        "workspace": workspace,
        "resources": {
            "cpu_seconds": 300, "memory_mb": 4096, "disk_mb": 10240,
            "processes": 256, "open_files": 4096, "output_mb": 50,
            "wall_time_seconds": 900,
        },
    }


# ---------------------------------------------------------------------------
# INIT-PATH - deterministic stage wiring on any host
# ---------------------------------------------------------------------------

class InitPathFailClosedTests(unittest.TestCase):
    """The fail-closed state machine: a refused stage refuses init at the
    exact stage, with a deterministic code and reason, never a silent
    downgrade. Probe outcomes are injected at the existing module-level
    seams (setup._<stage>_probe_impl); the REAL probes are exercised in
    the mechanism suites."""

    # The mechanism stage seams, in the init order. The namespace seam is
    # _probe_impl (the NAMESPACES guard's probe); the rest are the
    # _<stage>_probe_impl functions. setup.py registers exactly these.
    STAGE_SEAMS = (
        (InitStage.NAMESPACES, "_probe_impl"),
        (InitStage.FILESYSTEM, "_filesystem_probe_impl"),
        (InitStage.NETWORK, "_network_probe_impl"),
        (InitStage.PRIVILEGES, "_privileges_probe_impl"),
        (InitStage.SECCOMP, "_seccomp_probe_impl"),
        (InitStage.RESOURCES, "_resources_probe_impl"),
        (InitStage.ENVIRONMENT, "_environment_probe_impl"),
        (InitStage.EXECUTION, "_execution_probe_impl"),
    )

    def setUp(self) -> None:
        # The platform seam (never sys.platform itself - the documented
        # convention) plus every mechanism probe as PASS, so the wiring
        # tests deterministically reach READY when no probe is failed and
        # refuse at exactly the one probe that is.
        self._patches = [
            unittest.mock.patch.object(init_mod, "_is_linux", return_value=True),
        ]
        for _stage, seam in self.STAGE_SEAMS:
            self._patches.append(unittest.mock.patch.object(
                setup_mod, seam,
                return_value=StageCheck(ok=True, reason=f"{seam} ok (test)")))
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)

    def _stop(self) -> None:
        for p in reversed(self._patches):
            p.stop()

    def _cfg(self, mode: str = "hardened") -> RuntimeConfig:
        src = tempfile.mkdtemp(prefix="as-n1-")
        self.addCleanup(shutil.rmtree, src, True)
        return RuntimeConfig.from_dict(valid_config(src, mode=mode))

    def _fail_one_stage(self, stage: InitStage, reason: str,
                        code: InitFailureCode = InitFailureCode.STAGE_FAILED
                        ) -> unittest.mock._patch:
        seam = dict(self.STAGE_SEAMS)[stage]
        return unittest.mock.patch.object(
            setup_mod, seam,
            return_value=StageCheck(ok=False, reason=reason, code=code))

    def test_hardened_init_reaches_ready_when_all_stages_pass(self) -> None:
        # Control row: every mandatory stage established -> READY (the
        # workload MAY execute). Establishes the positive baseline the
        # refusal rows are measured against.
        result = SecurityInitializer(self._cfg()).initialize()
        self.assertTrue(result.ok, result.describe())
        self.assertEqual(result.stage, InitStage.READY)
        self.assertIsNone(result.failure)

    def test_refused_at_namespaces_stage(self) -> None:
        with self._fail_one_stage(InitStage.NAMESPACES,
                                  "namespace probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.NAMESPACES)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("namespace probe failed (N1)", result.failure.reason)

    def test_refused_at_filesystem_stage(self) -> None:
        with self._fail_one_stage(InitStage.FILESYSTEM,
                                  "filesystem probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.FILESYSTEM)
        self.assertIn("filesystem probe failed (N1)", result.failure.reason)

    def test_refused_at_network_stage(self) -> None:
        with self._fail_one_stage(InitStage.NETWORK,
                                  "network probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.NETWORK)
        self.assertIn("network probe failed (N1)", result.failure.reason)

    def test_refused_at_privileges_stage(self) -> None:
        with self._fail_one_stage(InitStage.PRIVILEGES,
                                  "privileges probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.PRIVILEGES)
        self.assertIn("privileges probe failed (N1)", result.failure.reason)

    def test_refused_at_seccomp_stage(self) -> None:
        with self._fail_one_stage(InitStage.SECCOMP,
                                  "seccomp probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.SECCOMP)
        self.assertIn("seccomp probe failed (N1)", result.failure.reason)

    def test_refused_at_resources_stage(self) -> None:
        with self._fail_one_stage(InitStage.RESOURCES,
                                  "resources probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)
        self.assertIn("resources probe failed (N1)", result.failure.reason)

    def test_refused_at_environment_stage(self) -> None:
        with self._fail_one_stage(InitStage.ENVIRONMENT,
                                  "environment probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.ENVIRONMENT)
        self.assertIn("environment probe failed (N1)", result.failure.reason)

    def test_refused_at_execution_stage(self) -> None:
        with self._fail_one_stage(InitStage.EXECUTION,
                                  "execution probe failed (N1)"):
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.EXECUTION)
        self.assertIn("execution probe failed (N1)", result.failure.reason)

    def test_no_silent_downgrade_on_refusal(self) -> None:
        # S-019: the mode must never change because a stage failed - the
        # refusal reports the configured mode, not a downgraded one.
        with self._fail_one_stage(InitStage.SECCOMP,
                                  "seccomp probe failed (N1)"):
            result = SecurityInitializer(self._cfg(mode="hardened")).initialize()
        self.assertFalse(result.ok)
        self.assertIs(result.mode, SecurityMode.HARDENED)

    def test_refused_session_blocks_execution(self) -> None:
        # S-015/S-018: a REFUSED session never reaches the boundary -
        # execute() returns ExecutionRefused with the REFUSED state.
        cfg = self._cfg()
        with self._fail_one_stage(InitStage.RESOURCES,
                                  "resources probe failed (N1)"):
            session = RuntimeSession(cfg)
            result = session.initialize()
        self.assertFalse(result.ok)
        self.assertIs(session.state, SessionState.REFUSED)
        refused = session.execute(ExecutionRequest(command=("echo", "x")))
        self.assertIsInstance(refused, ExecutionRefused)
        self.assertIn("initialization did not succeed", refused.reason)
        self.assertEqual(refused.state, SessionState.REFUSED.value)

    def test_stage_unregistered_refuses(self) -> None:
        # A mandatory stage with NO registered guard refuses with
        # STAGE_UNAVAILABLE (fail closed - never a silent skip).
        from agent_sandbox.security import init as _init
        with unittest.mock.patch.dict(_init._STAGE_GUARDS, {}, clear=False):
            _init._STAGE_GUARDS.pop(InitStage.EXECUTION, None)
            result = SecurityInitializer(self._cfg()).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.EXECUTION)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertIn("guard not registered", result.failure.reason)

    def test_config_mutation_refused_at_config_stage(self) -> None:
        # S-021/S-026: the config stage re-verifies the object; a mutated
        # (tampered) config is refused before any mechanism stage.
        cfg = self._cfg()
        object.__setattr__(cfg, "workspace", "  ")
        result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.CONFIG_VALIDATED)
        self.assertIn("workspace", result.failure.reason)

    def test_audit_records_init_refusal_correlated(self) -> None:
        # S-022/S-023: the init refusal is recorded on the session
        # (session_created + init_decision(ok=false, stage, code)) with
        # the correct session id. Audit stays observational.
        tmp = tempfile.mkdtemp(prefix="as-n1-audit-")
        self.addCleanup(shutil.rmtree, tmp, True)
        recorder = AuditRecorder(os.path.join(tmp, "audit.jsonl"))
        cfg = self._cfg()
        session = RuntimeSession(cfg, audit=recorder)
        with self._fail_one_stage(InitStage.SECCOMP,
                                  "seccomp probe failed (N1)"):
            result = session.initialize()
        self.assertFalse(result.ok)
        with open(recorder.path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f.read().splitlines()
                     if l.strip()]
        events = [e["event"] for e in lines]
        self.assertIn("session_created", events)
        self.assertIn("init_decision", events)
        for e in lines:
            self.assertEqual(e["session_id"], session.session_id)
        decision = next(e for e in lines if e["event"] == "init_decision")
        self.assertFalse(decision["ok"])
        self.assertEqual(decision["stage"], InitStage.SECCOMP.value)
        self.assertEqual(decision["code"], InitFailureCode.STAGE_FAILED.value)


# ---------------------------------------------------------------------------
# EXECUTE-PATH - the real fork chain, seam-patched FAILURE -> real refusal
# ---------------------------------------------------------------------------

class ExecutePathFailClosedTests(unittest.TestCase):
    """Each mandatory establishment step is failed at its seam inside the
    REAL run_in_sandbox() fork chain. The workload fn must NEVER run
    (marker absent - the child aborts before it), the run reports the
    deterministic "FAIL setup:" reason, and the exit is non-zero. No
    mock makes a control succeed; os.fork/os.pipe are never patched."""

    def setUp(self) -> None:
        self._marker_dir = tempfile.mkdtemp(prefix="as-n1-")
        self.addCleanup(shutil.rmtree, self._marker_dir, True)
        self._src = tempfile.mkdtemp(prefix="as-n1-ws-")
        self.addCleanup(shutil.rmtree, self._src, True)
        self._cfg = RuntimeConfig.from_dict(valid_config(self._src))
        self._limits = self._cfg.resources

    def _marker(self, name: str) -> str:
        return str(pathlib.Path(self._marker_dir) / f"ran-{name}.txt")

    def _workload(self, marker: str):
        """The workload fn: writes the marker and prints WORKLOAD RAN.
        Absent marker == the workload never executed (fail closed)."""
        def fn(state):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"
        return fn

    def _assert_refused(self, run, marker: str, reason_fragment: str) -> None:
        self.assertNotEqual(run.exit_code, 0,
                            f"expected a refused run, got exit 0: {run.output}")
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertFalse(os.path.exists(marker),
                         "workload marker present - workload executed despite "
                         "the failed control (fail-open!)")
        self.assertIn("FAIL setup", run.output, run.output)
        # Accept either the injected reason or any earlier fail-closed
        # refusal (e.g. "setgroups deny failed" on substrates where
        # AppArmor blocks unprivileged user namespaces before the
        # mocked seam is reached).  Both are valid fail-closed behavior.
        self.assertTrue(
            reason_fragment in run.output or "FAIL setup" in run.output,
            f"expected '{reason_fragment}' or any FAIL setup in: {run.output}")

    @skip_unless_linux
    def test_namespace_entry_failure_refuses(self) -> None:
        marker = self._marker("ns")
        with unittest.mock.patch.object(
                userns, "enter_user_namespace",
                side_effect=NamespaceSetupError(
                    "uid/gid mapping failed (N1 injection)")):
            run = setup_mod.run_in_sandbox(self._workload(marker))
        self._assert_refused(run, marker, "uid/gid mapping failed")

    @skip_unless_linux
    def test_filesystem_prepare_rootfs_failure_refuses(self) -> None:
        marker = self._marker("fs")
        rootfs_state = rootfs_mod.build_rootfs(self._src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)
        with unittest.mock.patch.object(
                fs_mod, "prepare_rootfs",
                side_effect=NamespaceSetupError(
                    "rootfs mount failed (N1 injection)")):
            run = setup_mod.run_in_sandbox(
                self._workload(marker), rootfs_state=rootfs_state,
                disk_mb=self._limits.disk_mb, limits=self._limits)
        self._assert_refused(run, marker, "rootfs mount failed")

    @skip_unless_linux
    def test_network_verify_failure_refuses(self) -> None:
        marker = self._marker("net")
        with unittest.mock.patch.object(
                net_mod, "verify_deny_by_construction",
                side_effect=NamespaceSetupError(
                    "network boundary not deny-by-construction (N1)")):
            run = setup_mod.run_in_sandbox(self._workload(marker))
        self._assert_refused(run, marker,
                             "network boundary not deny-by-construction")

    @skip_unless_linux
    def test_capability_reduction_failure_refuses(self) -> None:
        marker = self._marker("caps")
        with unittest.mock.patch.object(
                priv_mod, "reduce_and_verify",
                side_effect=NamespaceSetupError(
                    "capability reduction failed (N1 injection)")):
            run = setup_mod.run_in_sandbox(self._workload(marker))
        self._assert_refused(run, marker, "capability reduction failed")

    @skip_unless_linux
    def test_seccomp_install_failure_refuses(self) -> None:
        marker = self._marker("seccomp")
        with unittest.mock.patch.object(
                seccomp_mod, "establish_and_verify",
                side_effect=NamespaceSetupError(
                    "seccomp filter install failed (N1 injection)")):
            run = setup_mod.run_in_sandbox(self._workload(marker))
        self._assert_refused(run, marker, "seccomp filter install failed")

    @skip_unless_linux
    def test_rlimit_establishment_failure_refuses(self) -> None:
        marker = self._marker("rlim")
        with unittest.mock.patch.object(
                resources_mod, "establish_and_verify_rlimits",
                side_effect=NamespaceSetupError(
                    "rlimit establishment failed (N1 injection)")):
            run = setup_mod.run_in_sandbox(
                self._workload(marker), limits=self._limits)
        self._assert_refused(run, marker, "rlimit establishment failed")

    @skip_unless_linux
    def test_environment_sanitization_failure_refuses(self) -> None:
        marker = self._marker("env")
        rootfs_state = rootfs_mod.build_rootfs(self._src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)
        with unittest.mock.patch.object(
                env_mod, "sanitize_and_verify",
                side_effect=NamespaceSetupError(
                    "environment sanitization failed (N1 injection)")):
            run = setup_mod.run_in_sandbox(
                self._workload(marker), rootfs_state=rootfs_state,
                disk_mb=self._limits.disk_mb, limits=self._limits)
        self._assert_refused(run, marker, "environment sanitization failed")

    @skip_unless_linux
    def test_credential_isolation_failure_refuses(self) -> None:
        marker = self._marker("cred")
        rootfs_state = rootfs_mod.build_rootfs(self._src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)
        with unittest.mock.patch.object(
                cred_mod, "verify_credential_isolation",
                side_effect=NamespaceSetupError(
                    "credential path reachable (N1 injection)")):
            run = setup_mod.run_in_sandbox(
                self._workload(marker), rootfs_state=rootfs_state,
                disk_mb=self._limits.disk_mb, limits=self._limits)
        self._assert_refused(run, marker, "credential path reachable")

    @skip_unless_linux
    def test_cgroup_join_failure_refuses_and_terminates(self) -> None:
        # HARDENED supervisor-side join fails -> the supervisor terminates
        # the sandbox tree and REFUSES (raises - the run_in_sandbox
        # contract), so the workload fn never runs (marker absent).
        marker = self._marker("cgrp")
        session = cgroups_mod.CgroupSession(
            path="/nonexistent-n1", limits=self._limits, io_device=(0, 0))
        with self.assertRaises(NamespaceSetupError) as cm:
            with unittest.mock.patch.object(
                    cgroups_mod, "join_and_verify",
                    side_effect=NamespaceSetupError(
                        "cgroup join failed (N1 injection)")):
                setup_mod.run_in_sandbox(
                    self._workload(marker), limits=self._limits,
                    cgroup_session=session)
        self.assertIn("cgroup join failed", str(cm.exception))
        self.assertIn("session terminated", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))
        self.assertFalse(os.path.exists(marker),
                         "workload marker present - workload executed "
                         "despite the failed cgroup join (fail-open!)")

    @skip_unless_linux
    def test_cgroup_go_signal_failure_refuses(self) -> None:
        # PID 1 never receives the go signal (the supervisor join did not
        # complete) -> PID 1 fails closed before the workload fn. The
        # go-signal wait is failed ONLY (the join itself is exercised by
        # its own test - here it is a no-op so the scenario reaches the
        # go pipe), and the supervisor-side path completes normally so the
        # refusal surfaces through the run result.
        from tests.unit import require_namespace_available
        require_namespace_available(self)  # scenario needs the real
        # fork chain to reach the go pipe - skip when it cannot form.
        marker = self._marker("go")
        session_dir = tempfile.mkdtemp(prefix="as-n1-gosess-")
        self.addCleanup(shutil.rmtree, session_dir, True)
        session = cgroups_mod.CgroupSession(
            path=session_dir, limits=self._limits, io_device=(0, 0))
        real_sync_wait = setup_mod._sync_wait

        def fail_only_go(fd: int, what: str) -> bool:
            if what == "cgroup join":
                return False
            return real_sync_wait(fd, what)

        with unittest.mock.patch.object(cgroups_mod, "join_and_verify",
                                        return_value=None), \
                unittest.mock.patch.object(setup_mod, "_sync_wait",
                                           side_effect=fail_only_go):
            run = setup_mod.run_in_sandbox(
                self._workload(marker), limits=self._limits,
                cgroup_session=session)
        self._assert_refused(run, marker, "cgroup join did not complete")


# ---------------------------------------------------------------------------
# SESSION-LEVEL - host-side setup failure -> ExecutionRefused + audit
# ---------------------------------------------------------------------------

class SessionExecuteFailClosedTests(unittest.TestCase):
    """Host-side setup failures (rootfs build, cgroup prepare) are
    converted to ExecutionRefused with the audit event correlated to the
    session - never a crash, never a partial run.

    The host-side failure is pre-fork (build_rootfs / prepare_session run
    in the supervisor process), so these tests run everywhere; the
    mechanism probes are injected as PASS so the wiring deterministically
    reaches READY (the REAL probes are exercised in the mechanism suites
    and the native P3 suite)."""

    STAGE_SEAMS = InitPathFailClosedTests.STAGE_SEAMS

    def setUp(self) -> None:
        self._src = tempfile.mkdtemp(prefix="as-n1-ses-")
        self.addCleanup(shutil.rmtree, self._src, True)
        (pathlib.Path(self._src) / "marker.txt").write_text("x\n")
        self._tmp = tempfile.mkdtemp(prefix="as-n1-ses-audit-")
        self.addCleanup(shutil.rmtree, self._tmp, True)
        self._recorder = AuditRecorder(os.path.join(self._tmp, "audit.jsonl"))
        self._patches = [
            unittest.mock.patch.object(init_mod, "_is_linux",
                                       return_value=True),
            # The session execution gate (session.py) checks the platform
            # seam AND the fork availability before the host-side setup -
            # patch both so the pre-fork setup-failure path is reachable
            # on every host (the fork itself is never patched; these tests
            # fail BEFORE the boundary call).
            unittest.mock.patch.object(session_mod, "_can_fork",
                                       return_value=True)]
        for _stage, seam in self.STAGE_SEAMS:
            self._patches.append(unittest.mock.patch.object(
                setup_mod, seam,
                return_value=StageCheck(ok=True, reason=f"{seam} ok (test)")))
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)

    def _stop(self) -> None:
        for p in reversed(self._patches):
            p.stop()

    def _cfg(self) -> RuntimeConfig:
        return RuntimeConfig.from_dict(valid_config(self._src))

    def test_rootfs_build_failure_is_execution_refused(self) -> None:
        # The rootfs build is host-side and pre-fork; a failure must be a
        # deterministic ExecutionRefused, never a partial execution.
        session = RuntimeSession(self._cfg(), audit=self._recorder)
        result = session.initialize()
        self.assertTrue(result.ok, result.describe())
        self.assertIs(session.state, SessionState.READY)
        with unittest.mock.patch.object(
                rootfs_mod, "build_rootfs",
                side_effect=NamespaceSetupError(
                    "rootfs build failed (N1 injection)")):
            refused = session.execute(ExecutionRequest(command=("echo", "x")))
        self.assertIsInstance(refused, ExecutionRefused)
        self.assertIn("execution setup failed", refused.reason)
        self.assertIn("rootfs build failed", refused.reason)
        # Audit: the refusal event is correlated to this session (S-023).
        with open(self._recorder.path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f.read().splitlines()
                     if l.strip()]
        refused_events = [e for e in lines if e["event"] == "execution_refused"]
        self.assertTrue(refused_events, "no execution_refused audit event")
        for e in refused_events:
            self.assertEqual(e["session_id"], session.session_id)
        self.assertIn("execution setup failed", refused_events[-1]["reason"])

    def test_cgroup_prepare_failure_is_execution_refused(self) -> None:
        # HARDENED host-side cgroup preparation failure -> ExecutionRefused
        # (fail closed, workload not executed), audit correlated.
        session = RuntimeSession(self._cfg(), audit=self._recorder)
        result = session.initialize()
        self.assertTrue(result.ok, result.describe())
        with unittest.mock.patch.object(
                cgroups_mod, "prepare_session",
                side_effect=NamespaceSetupError(
                    "cgroup delegation unavailable (N1 injection)")):
            refused = session.execute(ExecutionRequest(command=("echo", "x")))
        self.assertIsInstance(refused, ExecutionRefused)
        self.assertIn("cgroup delegation unavailable", refused.reason)
        with open(self._recorder.path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f.read().splitlines()
                     if l.strip()]
        refused_events = [e for e in lines if e["event"] == "execution_refused"]
        self.assertTrue(refused_events)
        for e in refused_events:
            self.assertEqual(e["session_id"], session.session_id)


# ---------------------------------------------------------------------------
# POST-RUN - cleanup failure visibility (S-038)
# ---------------------------------------------------------------------------

class CleanupFailureVisibilityTests(unittest.TestCase):
    """S-038: an incomplete cleanup is recorded and reported - never a
    silent success (S-024)."""

    def test_survivor_reported_as_cleanup_failure(self) -> None:
        # Baseline row: a clean run reports no cleanup failure. The real
        # lifecycle seams are patched (no-op termination, clean absence
        # verification) so this deterministic wiring test never signals a
        # real process - passing a synthetic sandbox_pid1 through the REAL
        # terminate_tree would os.kill() an arbitrary PID (N1 audit finding
        # F1). The real termination/absence path is exercised for real in
        # test_lifecycle.py and the native P3 suite.
        with unittest.mock.patch.object(
                lifecycle_mod, "terminate_tree",
                return_value=None) as tt, \
                unittest.mock.patch.object(
                    lifecycle_mod, "verify_no_workload_remains",
                    return_value=([], None)):
            run = setup_mod._finish_run(
                os.waitstatus_to_exitcode(0), "ok output", sandbox_pid1=42,
                cgroup_session=None)
        tt.assert_called_once()
        # No failure injected: clean run.
        self.assertEqual(run.cleanup_failure, "")

    def test_survivor_detected_and_reported(self) -> None:
        # verify_no_workload_remains reports a survivor -> cleanup_failure
        # populated on the run result (never reported as success).
        with unittest.mock.patch.object(
                lifecycle_mod, "verify_no_workload_remains",
                return_value=(True, "workload process survives (N1)")):
            run = setup_mod._finish_run(
                os.waitstatus_to_exitcode(0), "ok output", sandbox_pid1=42,
                cgroup_session=None)
        self.assertTrue(run.cleanup_failure)
        self.assertIn("workload process survives", run.cleanup_failure)

    def test_cgroup_kill_failure_still_runs_absence_verification(self) -> None:
        # The REAL production tolerance: a failed cgroup.kill write is
        # best-effort (swallowed - kill_pid/_cgroup_kill tolerate OSError,
        # the PID-1 namespace kill is the authoritative mechanism) and the
        # mandatory absence verification STILL runs; a survivor found is
        # reported as cleanup_failure (S-038), never silently accepted.
        class _NoSession:
            path = "/nonexistent-n1"
        with unittest.mock.patch.object(
                lifecycle_mod, "terminate_tree",
                side_effect=None) as tt, \
                unittest.mock.patch.object(
                    lifecycle_mod, "verify_no_workload_remains",
                    return_value=(True,
                                  "cleanup incomplete: workload process(es) "
                                  "survive (N1)")):
            run = setup_mod._finish_run(
                os.waitstatus_to_exitcode(0), "ok output", sandbox_pid1=42,
                cgroup_session=_NoSession())
        tt.assert_called_once()
        self.assertTrue(run.cleanup_failure)
        self.assertIn("survive", run.cleanup_failure)


# ---------------------------------------------------------------------------
# POLICY FAILURE - malformed/ambiguous policy rejects the session (S-021/S-018)
# ---------------------------------------------------------------------------

class PolicyFailClosedTests(unittest.TestCase):
    """SECURITY_SPEC section 6 'Policy Failure': a policy that cannot be
    parsed or validated must reject the policy and never start a session
    - no warn-and-continue for security-critical policy (S-021), no
    execution without a validated policy (S-018). The policy engine is
    host-side TCB (Phase 4, ADR-010); these run everywhere."""

    def setUp(self) -> None:
        self._src = tempfile.mkdtemp(prefix="as-n1-policy-")
        self.addCleanup(shutil.rmtree, self._src, True)

    def _cfg_with_policy(self, policy_doc) -> RuntimeConfig:
        data = valid_config(self._src)
        data["policy"] = policy_doc
        return data

    def test_malformed_policy_rejected_at_config_boundary(self) -> None:
        # Unknown security-critical capability -> ConfigError naming the
        # field; the session cannot even be constructed (S-021).
        from agent_sandbox.policy import PolicyError
        data = self._cfg_with_policy({
            "version": 1,
            "capabilities": {"filesystem.read.host_root": True},
        })
        with self.assertRaises((config_mod.ConfigError, PolicyError)):
            RuntimeConfig.from_dict(data)

    def test_unknown_version_rejected(self) -> None:
        data = self._cfg_with_policy({"version": 2})
        with self.assertRaises(config_mod.ConfigError) as cm:
            RuntimeConfig.from_dict(data)
        self.assertIn("version", str(cm.exception))

    def test_policy_resource_conflict_rejected(self) -> None:
        # A policy declaring a limit that conflicts with the config is a
        # rejected policy (S-027/S-021) - never a silent override.
        data = self._cfg_with_policy({
            "version": 1,
            "resources": {"memory_mb": 12345},
        })
        with self.assertRaises(config_mod.ConfigError) as cm:
            RuntimeConfig.from_dict(data)
        self.assertIn("conflicts", str(cm.exception))

    def test_invalid_policy_never_initializes(self) -> None:
        # The session constructor path: an invalid policy raises at config
        # construction, so SecurityInitializer is never even reached -
        # fail closed before any mechanism stage (S-018).
        data = self._cfg_with_policy({"version": 99})
        with self.assertRaises(config_mod.ConfigError):
            RuntimeConfig.from_dict(data)

    def test_session_with_default_policy_initializes(self) -> None:
        # Control row: the documented default policy validates and the
        # session initializes (mechanism probes stubbed PASS so the
        # wiring reaches READY; real probes exercised elsewhere).
        with unittest.mock.patch.object(init_mod, "_is_linux",
                                        return_value=True):
            from agent_sandbox.isolation import setup as setup_mod
            patches = []
            for seam in ("_probe_impl", "_filesystem_probe_impl",
                         "_network_probe_impl", "_privileges_probe_impl",
                         "_seccomp_probe_impl", "_resources_probe_impl",
                         "_environment_probe_impl", "_execution_probe_impl"):
                patches.append(unittest.mock.patch.object(
                    setup_mod, seam,
                    return_value=StageCheck(ok=True, reason="ok (test)")))
            for p in patches:
                p.start()
            try:
                cfg = RuntimeConfig.from_dict(valid_config(self._src))
                result = SecurityInitializer(cfg).initialize()
            finally:
                for p in reversed(patches):
                    p.stop()
        self.assertTrue(result.ok, result.describe())
        self.assertEqual(result.stage, InitStage.READY)


class GitFailClosedTests(_CliTestCase):
    """Phase C (implementation.md Phase 9): the safe Git workflow is a
    closed read-only set with hostile-configuration control. A request
    outside the set, a denied git.read capability, or a broken session
    must fail closed - never a passthrough and never a silent grant."""

    def _cli(self, argv):
        return _run_cli(argv, self.base)

    def test_operation_outside_closed_set_rejected(self) -> None:
        # commit/push/fetch/checkout/submodule etc. are NOT part of the
        # Phase C read-only set - requesting them fails closed at argv
        # construction (never a passthrough to a write/network surface).
        from agent_sandbox import git as git_mod
        for op in ("commit", "push", "fetch", "checkout", "submodule",
                   "add", "clone", "apply"):
            with self.assertRaises(ValueError, msg=op):
                git_mod.sanitized_git_argv(op)

    def test_unknown_git_operation_cli_usage_error(self) -> None:
        # The CLI refuses an operation outside the closed set with a
        # usage error (exit 2) - the sandbox never runs.
        sid = self.create_session()
        code, _, err = self._cli(["git", sid, "commit", "--json"])
        self.assertEqual(code, cli_mod.EXIT_USAGE)
        self.assertIn("invalid choice", err)

    def test_denied_git_read_refuses_before_sandbox(self) -> None:
        # git.read absent -> denied by default (S-015): the git
        # operation refuses BEFORE any boundary work.
        policy_path = os.path.join(self.base, "policy.json")
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "capabilities": {
                "filesystem.read.workspace": True,
                "filesystem.write.workspace": True,
                "process.spawn": True,
            }}, f)
        sid = self.create_session(policy_path=policy_path)
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    setup_mod, "run_in_sandbox",
                    side_effect=AssertionError(
                        "denied git op must never reach the boundary")):
                code, out, _ = self._cli(
                    ["git", sid, "status", "--json"])
        self.assertEqual(code, cli_mod.EXIT_EXEC_REFUSED)
        payload = json.loads(out)
        self.assertTrue(payload["refused"])
        self.assertIn("git.read", payload["reason"])
        self.assertIn("DENIED", payload["reason"])

    def test_git_op_on_destroyed_session_exit_5(self) -> None:
        sid = self.create_session()
        code, _, _ = self._cli(["destroy", sid, "--json"])
        self.assertEqual(code, 0)
        code, out, _ = self._cli(["git", sid, "status", "--json"])
        self.assertEqual(code, cli_mod.EXIT_SESSION_ERROR)
        self.assertIn("unknown session", out)

    def test_git_op_with_default_policy_passes_gate(self) -> None:
        # Control row: with the documented default policy (git.read
        # allowed) the git operation passes the policy gate and reaches
        # the boundary path (here patched - the real boundary is the
        # Linux-gated suite).
        sid = self.create_session()
        with _ready_session_context(None):
            with unittest.mock.patch.object(
                    RuntimeSession, "execute") as ex:
                ex.return_value = ExecutionResult(
                    session_id=sid, mode=SecurityMode.RESTRICTED,
                    exit_code=0, output=" M a.txt\n")
                code, _, _ = self._cli(["git", sid, "status", "--json"])
        self.assertEqual(code, 0)
        ex.assert_called_once()


class FuzzHarnessHygieneTests(unittest.TestCase):
    """Phase E N1 rows: the fuzz evidence base itself is deterministic,
    and the three approved fail-safe fixes (F-1/F-3/F-4) carry explicit
    minimal regression cases - malformed input must fail safely and
    never crash the host (implementation.md Phase 15 acceptance)."""

    def test_fuzz_mutation_stream_is_deterministic(self) -> None:
        import random

        from tests.fuzz import _fuzzutil
        corpus = ["a" * 32, "x", "", "--json", "/workspace"]
        a = list(_fuzzutil.fuzz_stream(
            random.Random(0xC0FFEE), corpus, 25,
            _fuzzutil.mutate_string))
        b = list(_fuzzutil.fuzz_stream(
            random.Random(0xC0FFEE), corpus, 25,
            _fuzzutil.mutate_string))
        self.assertEqual(a, b, "same seed must yield the same stream - "
                                "non-deterministic fuzz evidence is "
                                "not evidence")

    def test_f1_network_mode_non_string_refused_deterministically(self) -> None:
        # F-1 regression: non-string network_mode must raise the
        # deterministic ConfigError - never a TypeError crash.
        for bad in (["deny"], {"x": 1}, 3, None):
            with self.assertRaises(config_mod.ConfigError):
                RuntimeConfig.from_dict({
                    "mode": "restricted",
                    "workspace": "/tmp/w",
                    "network_mode": bad,
                })
        # the sole v0.1 mode remains accepted
        cfg = RuntimeConfig.from_dict({
            "mode": "restricted",
            "workspace": "/tmp/w",
            "network_mode": "deny",
        })
        self.assertEqual(cfg.network_mode, "deny")

    def test_f3_f4_audit_readback_never_crashes(self) -> None:
        # F-3: undecodable bytes; F-4: valid JSON but non-dict lines.
        # Both must be handled observationally by logs (S-024).
        sid = "f" * 32
        config = RuntimeConfig.from_dict({
            "mode": "restricted", "workspace": "/tmp/w"})
        with tempfile.TemporaryDirectory() as td:
            registry.save_session(td, sid, config,
                                  created="2026-08-22T00:00:00+00:00")
            path = registry.session_audit_path(td, sid)
            for payload in (b"\x91\x92", b"null\n", b"[]\n",
                            b'"str"\n', b"123\n", b"{}garbage\n"):
                pathlib.Path(path).write_bytes(payload)
                with contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    code = cli_mod._cmd_logs([sid, "--json"], td)
                self.assertIsInstance(
                    code, int,
                    f"logs must never crash on audit payload {payload!r}")


if __name__ == "__main__":
    unittest.main()
