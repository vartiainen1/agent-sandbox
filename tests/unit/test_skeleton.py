"""Phase 1 Step 1 skeleton tests (stdlib unittest).

Run from the repository root:
    python -m unittest discover -s tests -t . -v

Covers the required Step 1 characteristics:
- valid configuration accepted
- invalid configuration rejected (deterministic, field-naming)
- unsupported security mode rejected
- HARDENED initialization failure cannot result in workload execution
- initialization errors are explicit and deterministic
- configuration cannot mutate after validation (frozen)
- security initialization has an explicit state/result
- later runtime stages (execute) cannot run unless init succeeded
- no silent downgrade (S-019): mode never changes during init

Behavioral wiring tests - the fail-closed state machine is exercised with
stage-guard outcomes injected (this file), while the REAL mechanisms are
tested for real in tests/unit/test_namespaces.py on Linux. The two seams
patched here: the ``_is_linux`` helper (never sys.platform itself - see the
3.12 _winapi lesson in freebuff-errors.txt) and the namespace probe
implementation (``isolation.setup._probe_impl``), so these wiring tests
are deterministic on any host.
"""

import unittest
import unittest.mock
from dataclasses import FrozenInstanceError

from agent_sandbox import config as config_mod
from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import setup as setup_mod
from agent_sandbox.models import (
    ConfigError, ExecutionRefused, InitFailureCode, InitResult, InitStage,
    SecurityMode, StageCheck)
from agent_sandbox.runtime.session import RuntimeSession, SessionState
from agent_sandbox.security import init as init_mod
from agent_sandbox.security.init import SecurityInitializer, init_sequence


def _fake_resources_probe(config):
    """Mode-aware RESOURCES probe stand-in (Step 9): HARDENED refuses AT
    RESOURCES (the cgroup v2 half of the stage is Step 10, ADR-007);
    RESTRICTED completes its RESOURCES stage with rlimits only and
    advances. Mirrors the real ``_resources_probe_impl`` semantics."""
    if config.mode is SecurityMode.HARDENED:
        return StageCheck(
            ok=False, code=InitFailureCode.STAGE_FAILED,
            reason="cgroup v2 (the HARDENED-mandatory half of the RESOURCES "
                   "stage, ADR-007) is not yet implemented (Step 15 of the "
                   "mandated order) - RESOURCES incomplete, fail closed, "
                   "workload not executed")
    return StageCheck(ok=True, reason="rlimits established (test)")


def valid_config(**overrides) -> dict:
    base = {
        "mode": "hardened",
        "workspace": "/srv/agent-workspace",
        "network_mode": "deny",
        "env_allowlist": ["PATH", "HOME", "TMPDIR"],
        "resources": {
            "cpu_seconds": 300, "memory_mb": 4096, "disk_mb": 10240,
            "processes": 256, "open_files": 4096, "output_mb": 50,
            "wall_time_seconds": 900,
        },
    }
    base.update(overrides)
    return base


class ConfigValidationTests(unittest.TestCase):
    def test_valid_config_accepted(self):
        cfg = RuntimeConfig.from_dict(valid_config())
        self.assertIs(cfg.mode, SecurityMode.HARDENED)
        self.assertEqual(cfg.workspace, "/srv/agent-workspace")
        self.assertEqual(cfg.network_mode, "deny")
        self.assertEqual(cfg.resources.memory_mb, 4096)
        self.assertTrue(cfg.is_hardened)

    def test_minimal_config_gets_defaults(self):
        cfg = RuntimeConfig.from_dict({"mode": "hardened", "workspace": "/w"})
        self.assertEqual(cfg.network_mode, "deny")
        self.assertEqual(cfg.env_allowlist,
                         ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR"))
        self.assertEqual(cfg.resources.processes, 256)

    def test_unsupported_mode_rejected(self):
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict(valid_config(mode="supersafe"))
        self.assertIn("unsupported security mode", str(cm.exception))
        self.assertIn("supersafe", str(cm.exception))

    def test_missing_mode_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(valid_config(mode=None))

    def test_workspace_must_be_absolute(self):
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict(valid_config(workspace="relative/path"))
        self.assertIn("workspace", str(cm.exception))

    def test_missing_workspace_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(valid_config(workspace=""))

    def test_unknown_top_level_field_rejected(self):
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict(valid_config(extra_field="x"))
        self.assertIn("unknown configuration field", str(cm.exception))
        self.assertIn("extra_field", str(cm.exception))

    def test_unknown_resource_field_rejected(self):
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict(valid_config(resources={
                **valid_config()["resources"], "evil_limit": 1}))
        self.assertIn("evil_limit", str(cm.exception))

    def test_zero_and_negative_limits_rejected(self):
        for bad in (0, -1):
            with self.assertRaises(ConfigError):
                RuntimeConfig.from_dict(valid_config(resources={
                    **valid_config()["resources"], "cpu_seconds": bad}))

    def test_bool_is_not_a_valid_limit(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(valid_config(resources={
                **valid_config()["resources"], "cpu_seconds": True}))

    def test_allowlist_network_mode_rejected_in_v01(self):
        # v0.2 feature - must not be accepted while unenforceable (S-021)
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict(valid_config(network_mode="allowlist"))
        self.assertIn("not supported in v0.1", str(cm.exception))

    def test_env_allowlist_invalid_entries_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(valid_config(env_allowlist=["A=B"]))
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(valid_config(env_allowlist=["A", "A"]))

    def test_config_immutable_after_validation(self):
        cfg = RuntimeConfig.from_dict(valid_config())
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            cfg.mode = SecurityMode.COMPATIBILITY  # type: ignore[misc]

    def test_errors_are_deterministic(self):
        bad = valid_config(mode="supersafe")
        with self.assertRaises(ConfigError) as a:
            RuntimeConfig.from_dict(bad)
        with self.assertRaises(ConfigError) as b:
            RuntimeConfig.from_dict(dict(bad))
        self.assertEqual(str(a.exception), str(b.exception))


class InitializationTests(unittest.TestCase):
    def setUp(self):
        # Real host behavior for the platform stage would make the refusal
        # point host-dependent; patch the helper (never sys.platform) so
        # mechanism-stage refusals are deterministic across hosts. The real
        # mechanism probes (namespaces, filesystem, network) are also
        # injected here as PASS so the wiring tests deterministically reach
        # the next unimplemented stage; the REAL probes are exercised in
        # tests/unit/test_namespaces.py, test_rootfs.py and test_network.py.
        self._patch = unittest.mock.patch.object(init_mod, "_is_linux", return_value=True)
        self._patch.start()
        self._patch_fs = unittest.mock.patch.object(
            setup_mod, "_filesystem_probe_impl",
            return_value=StageCheck(ok=True, reason="filesystem probe ok (test)"))
        self._patch_fs.start()
        self._patch_net = unittest.mock.patch.object(
            setup_mod, "_network_probe_impl",
            return_value=StageCheck(ok=True, reason="network probe ok (test)"))
        self._patch_net.start()
        self._patch_priv = unittest.mock.patch.object(
            setup_mod, "_privileges_probe_impl",
            return_value=StageCheck(ok=True, reason="privileges probe ok (test)"))
        self._patch_priv.start()
        self._patch_sc = unittest.mock.patch.object(
            setup_mod, "_seccomp_probe_impl",
            return_value=StageCheck(ok=True, reason="seccomp probe ok (test)"))
        self._patch_sc.start()
        # RESOURCES probe (Step 9): mode-aware like the real probe -
        # HARDENED refuses AT RESOURCES (the cgroup v2 half of the stage
        # is Step 10, ADR-007), RESTRICTED completes its RESOURCES stage
        # with rlimits only and advances.
        self._patch_res = unittest.mock.patch.object(
            setup_mod, "_resources_probe_impl",
            side_effect=_fake_resources_probe)
        self._patch_res.start()

    def tearDown(self):
        self._patch_res.stop()
        self._patch_sc.stop()
        self._patch_priv.stop()
        self._patch_net.stop()
        self._patch_fs.stop()
        self._patch.stop()

    def _patch_probe(self, ok: bool, reason: str = "",
                     code: InitFailureCode = InitFailureCode.STAGE_FAILED):
        """Inject a deterministic namespace-probe outcome for wiring tests
        (the REAL probe is exercised in tests/unit/test_namespaces.py)."""
        return unittest.mock.patch.object(
            setup_mod, "_probe_impl",
            return_value=StageCheck(ok=ok, reason=reason, code=code))

    def test_hardened_init_refuses_at_next_unimplemented_stage(self):
        # Steps 2-9: NAMESPACES, FILESYSTEM, NETWORK, PRIVILEGES, SECCOMP
        # and RESOURCES (rlimits) guards are registered and pass; HARDENED
        # then refuses AT RESOURCES because the cgroup v2 half of the
        # stage is Step 10 (ADR-007) - the refusal point stays at
        # RESOURCES, fail closed, never skip.
        cfg = RuntimeConfig.from_dict(valid_config(mode="hardened"))
        with self._patch_probe(True, reason="probe ok (test)"):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertIs(result.mode, SecurityMode.HARDENED)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)
        self.assertIn("cgroup v2", result.failure.reason)
        self.assertIn("RESOURCES incomplete", result.failure.reason)

    def test_hardened_init_refuses_when_namespace_probe_fails(self):
        cfg = RuntimeConfig.from_dict(valid_config(mode="hardened"))
        with self._patch_probe(False, reason="namespace probe failed (test)"):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertEqual(result.failure.stage, InitStage.NAMESPACES)
        self.assertIn("namespace probe failed (test)", result.failure.reason)

    def test_hardened_init_refuses_when_filesystem_probe_fails(self):
        # The FILESYSTEM guard (real rootfs/pivot_root boundary) must be
        # able to refuse init: a failed or unverifiable boundary is a
        # refusal, never a skip and never a silent continue.
        cfg = RuntimeConfig.from_dict(valid_config(mode="hardened"))
        with self._patch_probe(True, reason="probe ok (test)"):
            with unittest.mock.patch.object(
                    setup_mod, "_filesystem_probe_impl",
                    return_value=StageCheck(
                        ok=False, reason="filesystem probe failed (test)")):
                result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertEqual(result.failure.stage, InitStage.FILESYSTEM)
        self.assertIn("filesystem probe failed (test)", result.failure.reason)

    def test_restricted_init_refused_at_next_unimplemented_stage(self):
        # RESTRICTED's RESOURCES stage is rlimits only (ADR-007): it
        # completes RESOURCES and refuses at the next unimplemented stage
        # (ENVIRONMENT) - fail closed, never a silent pass.
        cfg = RuntimeConfig.from_dict(valid_config(mode="restricted"))
        with self._patch_probe(True, reason="probe ok (test)"):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertEqual(result.failure.stage, InitStage.ENVIRONMENT)
        self.assertIn("no implementation", result.failure.reason)

    def test_platform_fail_closed_on_non_linux(self):
        cfg = RuntimeConfig.from_dict(valid_config(mode="compatibility"))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=False):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.code, InitFailureCode.PLATFORM_UNSUPPORTED)
        self.assertIn("not Linux", result.failure.reason)

    def test_init_result_is_explicit(self):
        cfg = RuntimeConfig.from_dict(valid_config(mode="hardened"))
        with self._patch_probe(True, reason="probe ok (test)"):
            result = SecurityInitializer(cfg).initialize()
        self.assertIsInstance(result, InitResult)
        self.assertTrue(result.describe().startswith("initialization REFUSED"))
        self.assertIn("resources", result.describe())
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)
        self.assertIsNotNone(result.failure.reason)

    def test_no_silent_downgrade(self):
        # HARDENED with a missing mechanism must REFUSE, never return
        # ok=True in a weaker mode. The result mode is always the
        # configured mode (probes injected as PASS so the refusal is
        # deterministically at the next unimplemented stage).
        cfg = RuntimeConfig.from_dict(valid_config(mode="hardened"))
        with self._patch_probe(True, reason="probe ok (test)"):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertIs(result.mode, SecurityMode.HARDENED)
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)

    def test_stage_order_is_deterministic(self):
        seq = init_sequence(SecurityMode.HARDENED)
        self.assertEqual(seq, (
            InitStage.CONFIG_VALIDATED, InitStage.PLATFORM_LINUX,
            InitStage.NAMESPACES, InitStage.FILESYSTEM, InitStage.NETWORK,
            InitStage.PRIVILEGES, InitStage.SECCOMP, InitStage.RESOURCES,
            InitStage.ENVIRONMENT, InitStage.EXECUTION, InitStage.READY))
        self.assertEqual(init_sequence(SecurityMode.HARDENED), seq)
        self.assertEqual(init_sequence(SecurityMode.COMPATIBILITY),
                         (InitStage.CONFIG_VALIDATED, InitStage.PLATFORM_LINUX,
                          InitStage.READY))

    def test_only_steps_2_to_8_stages_registered(self):
        # Pins the honest Step 9 state: exactly NAMESPACES, FILESYSTEM,
        # NETWORK, PRIVILEGES, SECCOMP and RESOURCES (rlimits only) are
        # implemented (registered by isolation/setup). Stages 9+
        # (ENVIRONMENT..EXECUTION) remain unregistered, so HARDENED
        # refuses at the first missing one instead of pretending the
        # boundary is complete.
        self.assertIn(InitStage.NAMESPACES, init_mod._STAGE_GUARDS)
        self.assertIn(InitStage.FILESYSTEM, init_mod._STAGE_GUARDS)
        self.assertIn(InitStage.NETWORK, init_mod._STAGE_GUARDS)
        self.assertIn(InitStage.PRIVILEGES, init_mod._STAGE_GUARDS)
        self.assertIn(InitStage.SECCOMP, init_mod._STAGE_GUARDS)
        self.assertIn(InitStage.RESOURCES, init_mod._STAGE_GUARDS)
        for stage in init_mod.MECHANISM_STAGES:
            if stage in (InitStage.NAMESPACES, InitStage.FILESYSTEM,
                         InitStage.NETWORK, InitStage.PRIVILEGES,
                         InitStage.SECCOMP, InitStage.RESOURCES):
                continue
            self.assertNotIn(stage, init_mod._STAGE_GUARDS,
                             f"{stage.value} must not be implemented in Step 9")

    def test_duplicate_stage_guard_registration_raises(self):
        # Registering a guard for an already-registered stage must raise
        # WITHOUT mutating the registry (no test-order pollution). Uses the
        # structural stage, not a mechanism stage, so this test never
        # pretends a mechanism exists.
        with self.assertRaises(RuntimeError):
            init_mod.register_stage_guard(InitStage.CONFIG_VALIDATED,
                                          lambda c: None)
        self.assertIn(InitStage.CONFIG_VALIDATED, init_mod._STAGE_GUARDS)
        # Registry unpolluted by the failed duplicate: the mechanism guards
        # are exactly the Step 9 set (NAMESPACES, FILESYSTEM, NETWORK,
        # PRIVILEGES, SECCOMP, RESOURCES) and ENVIRONMENT is unregistered.
        self.assertIn(InitStage.NETWORK, init_mod._STAGE_GUARDS)
        self.assertIn(InitStage.RESOURCES, init_mod._STAGE_GUARDS)
        self.assertNotIn(InitStage.ENVIRONMENT, init_mod._STAGE_GUARDS)


class SessionGateTests(unittest.TestCase):
    def setUp(self):
        self._patch = unittest.mock.patch.object(init_mod, "_is_linux", return_value=True)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_execute_before_init_is_blocked(self):
        session = RuntimeSession(RuntimeConfig.from_dict(valid_config(mode="hardened")))
        self.assertIs(session.state, SessionState.UNINITIALIZED)
        refusal = session.execute(["echo", "hello"])
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertIn("initialization did not succeed", refusal.reason)
        self.assertEqual(refusal.state, "uninitialized")

    def test_hardened_refusal_blocks_execution(self):
        session = RuntimeSession(RuntimeConfig.from_dict(valid_config(mode="hardened")))
        result = session.initialize()
        self.assertFalse(result.ok)
        self.assertIs(session.state, SessionState.REFUSED)
        refusal = session.execute(["echo", "hello"])
        self.assertIsInstance(refusal, ExecutionRefused)
        self.assertIn("initialization did not succeed", refusal.reason)
        self.assertEqual(refusal.state, "refused")

    def test_execute_after_ready_reaches_execution_gate(self):
        # COMPATIBILITY initializes structurally; execute then proceeds
        # past the security gate to the (honestly unimplemented) runner.
        session = RuntimeSession(
            RuntimeConfig.from_dict(valid_config(mode="compatibility")))
        result = session.initialize()
        self.assertTrue(result.ok, result.describe())
        self.assertIs(session.state, SessionState.READY)
        refusal = session.execute(["echo", "hello"])
        self.assertIn("execution mechanism not implemented", refusal.reason)
        self.assertEqual(refusal.state, "ready")

    def test_session_config_is_readonly(self):
        session = RuntimeSession(RuntimeConfig.from_dict(valid_config()))
        cfg = session.config
        self.assertIsInstance(cfg, RuntimeConfig)
        with self.assertRaises(AttributeError):
            session.config = cfg  # type: ignore[misc]

    def test_initialize_is_idempotent_statewise(self):
        session = RuntimeSession(RuntimeConfig.from_dict(valid_config(mode="hardened")))
        r1 = session.initialize()
        r2 = session.initialize()
        self.assertEqual(r1.describe(), r2.describe())
        self.assertIs(session.state, SessionState.REFUSED)


class RealPlatformTests(unittest.TestCase):
    """Behavioral test on THIS host: on a non-Linux host (e.g. the Windows
    dev machine) every mode must fail closed at the platform stage."""

    @unittest.skipIf(init_mod._is_linux(), "only meaningful on a non-Linux host")
    def test_real_non_linux_host_refuses_any_mode(self):
        for mode in ("hardened", "restricted", "compatibility"):
            cfg = RuntimeConfig.from_dict(valid_config(mode=mode))
            result = SecurityInitializer(cfg).initialize()
            self.assertFalse(result.ok, f"{mode} must refuse on non-Linux")
            self.assertEqual(result.failure.code,
                             InitFailureCode.PLATFORM_UNSUPPORTED)
            self.assertIsNotNone(result.failure.reason)


if __name__ == "__main__":
    unittest.main()
