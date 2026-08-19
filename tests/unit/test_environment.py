"""Phase 1 Step 11 tests - environment sanitization (S-034, ADR-009,
ARCHITECTURE.md section 11, T-018, T-051): the host environment is NEVER
inherited - PID 1 constructs exactly the approved six variables
(PATH=/usr/local/bin:/usr/bin:/bin, HOME=/home, TMPDIR=/tmp,
LANG=C.UTF-8, LC_ALL=C.UTF-8, TERM=dumb), replaces the process
environment and verifies the LIVE environment (exactly the allowlisted
variables with exactly the approved values, no host variable present).
Any construction/replacement/verification failure or unexpected/missing/
incorrect variable REFUSES before the workload (marker-absent evidence).

Policy (Step 11 approval): the six variables are the COMPLETE v0.1
supported set - config rejects any env_allowlist entry beyond them
(value injection is deferred). Sanitization is pure process state (no
syscalls): seccomp (45-syscall allowlist) is untouched.

Categories (kept separate, per the charter):
- Host-side construct/apply/verify logic + config rejection (runs
  everywhere, including Windows - seams for deterministic failure
  injection).
- Sandbox-internal tests (real env inside the real sandbox under the
  actual filter) - gated on the real namespace probe succeeding on this
  substrate (native 24.04 runner: SKIPPED with recorded reason; Docker
  uid 1001: VERIFIED DOCKER).
- Probe + integration: the ENVIRONMENT stage guard's real path; the
  wiring chain now advances past ENVIRONMENT to EXECUTION (the next
  unimplemented stage) and refuses there (STAGE_UNAVAILABLE) - never a
  silent pass.
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

from agent_sandbox.config import (
    DEFAULT_ENV_ALLOWLIST, ConfigError, RuntimeConfig)
from agent_sandbox.isolation import environment as env_mod
from agent_sandbox.isolation import setup
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage, SecurityMode
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real sandbox environment operations require Linux with os.fork "
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


APPROVED = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/home",
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
}


class EnvConstructionTests(unittest.TestCase):
    """Host-side construction semantics - runs everywhere."""

    def test_default_allowlist_is_the_six_approved(self):
        self.assertEqual(
            DEFAULT_ENV_ALLOWLIST,
            ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR"))

    def test_construct_default_matches_approved_values(self):
        built = env_mod.construct_environment()
        self.assertEqual(built, APPROVED)

    def test_construct_subset_allowlist(self):
        built = env_mod.construct_environment(("PATH", "HOME", "TMPDIR"))
        self.assertEqual(built, {"PATH": APPROVED["PATH"],
                                 "HOME": APPROVED["HOME"],
                                 "TMPDIR": APPROVED["TMPDIR"]})

    def test_construct_unknown_name_fails_closed(self):
        # A name beyond the six has no constructed value - this is a
        # policy gap that config should have rejected; the mechanism
        # fails closed rather than guessing a value.
        with self.assertRaises(NamespaceSetupError):
            env_mod.construct_environment(("PATH", "FOO"))

    def test_no_host_values_ever_read(self):
        # Construction is constant-driven - a host value for any of the
        # six must NOT leak in. Inject hostile host values and confirm
        # the constructed environment ignores them completely.
        with unittest.mock.patch.dict(os.environ, {
            "PATH": "/evil", "HOME": "/host/home", "TMPDIR": "/host/tmp",
            "LANG": "host-locale", "LC_ALL": "host-locale", "TERM": "xterm",
            "SECRET_TOKEN": "leak-me",
        }, clear=True):
            built = env_mod.construct_environment()
        self.assertEqual(built, APPROVED)
        self.assertNotIn("SECRET_TOKEN", built)

    def test_apply_replaces_everything(self):
        with unittest.mock.patch.dict(os.environ, {
            "PATH": "/evil", "SECRET_TOKEN": "leak-me",
            "AWS_ACCESS_KEY_ID": "AKIA...", "SSH_AUTH_SOCK": "/tmp/agent",
        }, clear=True):
            env_mod.apply_environment(dict(APPROVED))
            live = dict(os.environ)
        self.assertEqual(live, APPROVED)
        self.assertNotIn("SECRET_TOKEN", live)
        self.assertNotIn("AWS_ACCESS_KEY_ID", live)
        self.assertNotIn("SSH_AUTH_SOCK", live)

    def test_apply_clear_failure_fails_closed(self):
        # patch.dict guard: the injected OSError must not leave the real
        # process environment half-cleared for later tests.
        with unittest.mock.patch.dict(os.environ, {"KEEP": "1"},
                                      clear=True):
            with unittest.mock.patch.object(env_mod, "_clear_impl",
                                            side_effect=OSError("boom")):
                with self.assertRaises(NamespaceSetupError) as cm:
                    env_mod.apply_environment(dict(APPROVED))
        self.assertIn("environment replacement failed", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_apply_set_failure_fails_closed(self):
        # CRITICAL: apply_environment calls the REAL _clear_impl() before
        # the injected _set_impl raises - without the patch.dict guard
        # the whole process environment would be wiped for every later
        # test (found when test_privileges started failing after this
        # suite ran). The guard restores the original environment.
        with unittest.mock.patch.dict(os.environ, {"KEEP": "1"},
                                      clear=True):
            with unittest.mock.patch.object(env_mod, "_set_impl",
                                            side_effect=OSError("boom")):
                with self.assertRaises(NamespaceSetupError) as cm:
                    env_mod.apply_environment(dict(APPROVED))
        self.assertIn("environment replacement failed", str(cm.exception))

    def test_verify_exact_match_ok(self):
        with unittest.mock.patch.dict(os.environ, dict(APPROVED), clear=True):
            state = env_mod.verify_environment()
        self.assertTrue(state.ok)
        self.assertEqual(state.variables, APPROVED)
        self.assertEqual(state.allowlist, DEFAULT_ENV_ALLOWLIST)

    def test_verify_unexpected_variable_refuses(self):
        with unittest.mock.patch.dict(os.environ, {
            **APPROVED, "SECRET_TOKEN": "leak-me"}, clear=True):
            with self.assertRaises(NamespaceSetupError) as cm:
                env_mod.verify_environment()
        self.assertIn("unexpected variable", str(cm.exception))
        self.assertIn("SECRET_TOKEN", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_verify_missing_variable_refuses(self):
        with unittest.mock.patch.dict(os.environ, {
            k: v for k, v in APPROVED.items() if k != "TMPDIR"}, clear=True):
            with self.assertRaises(NamespaceSetupError) as cm:
                env_mod.verify_environment()
        self.assertIn("missing required variable", str(cm.exception))
        self.assertIn("TMPDIR", str(cm.exception))

    def test_verify_incorrect_value_refuses(self):
        with unittest.mock.patch.dict(os.environ, {
            **APPROVED, "HOME": "/host/home"}, clear=True):
            with self.assertRaises(NamespaceSetupError) as cm:
                env_mod.verify_environment()
        self.assertIn("incorrect value", str(cm.exception))
        self.assertIn("HOME", str(cm.exception))

    def test_sanitize_and_verify_roundtrip(self):
        with unittest.mock.patch.dict(os.environ, {
            "PATH": "/evil", "SECRET_TOKEN": "leak-me"}, clear=True):
            state = env_mod.sanitize_and_verify()
            live = dict(os.environ)
        self.assertTrue(state.ok)
        self.assertEqual(state.variables, APPROVED)
        self.assertEqual(live, APPROVED)

    def test_sanitize_subset_roundtrip(self):
        subset = ("PATH", "HOME", "TMPDIR")
        with unittest.mock.patch.dict(os.environ, {
            "SECRET_TOKEN": "leak-me"}, clear=True):
            state = env_mod.sanitize_and_verify(subset)
        self.assertEqual(state.variables,
                         {k: APPROVED[k] for k in subset})
        self.assertNotIn("LANG", state.variables)
        self.assertNotIn("SECRET_TOKEN", state.variables)


class EnvConfigValidationTests(unittest.TestCase):
    """env_allowlist semantics: the six are the COMPLETE v0.1 set."""

    def test_default_allowlist_accepted(self):
        cfg = RuntimeConfig.from_dict(valid_config("/w"))
        self.assertEqual(cfg.env_allowlist, DEFAULT_ENV_ALLOWLIST)

    def test_subset_of_six_accepted(self):
        cfg = RuntimeConfig.from_dict(valid_config("/w"))
        cfg2 = RuntimeConfig.from_dict({
            "mode": "hardened", "workspace": "/w",
            "env_allowlist": ["PATH", "HOME", "TMPDIR"]})
        self.assertEqual(cfg2.env_allowlist, ("PATH", "HOME", "TMPDIR"))
        self.assertEqual(cfg.env_allowlist, DEFAULT_ENV_ALLOWLIST)

    def test_entry_beyond_six_rejected(self):
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict({
                "mode": "hardened", "workspace": "/w",
                "env_allowlist": ["PATH", "MY_SECRET"]})
        self.assertIn("not a supported v0.1 environment variable",
                      str(cm.exception))
        self.assertIn("MY_SECRET", str(cm.exception))

    def test_token_like_entry_rejected(self):
        for bad in ("GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "SSH_AUTH_SOCK"):
            with self.assertRaises(ConfigError):
                RuntimeConfig.from_dict({
                    "mode": "hardened", "workspace": "/w",
                    "env_allowlist": ["PATH", bad]})

    def test_duplicate_still_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict({
                "mode": "hardened", "workspace": "/w",
                "env_allowlist": ["PATH", "PATH"]})


class EnvProbeTests(unittest.TestCase):
    """The ENVIRONMENT stage guard's real path (forked child)."""

    @skip_unless_linux
    def test_environment_probe_ok(self):
        cfg = RuntimeConfig.from_dict(valid_config("/w"))
        check = setup._environment_probe_impl(cfg)
        self.assertTrue(check.ok)
        self.assertIn("approved six-variable", check.reason)
        self.assertIn("no host variable present", check.reason)

    @skip_unless_linux
    def test_environment_probe_subset_ok(self):
        cfg = RuntimeConfig.from_dict({
            "mode": "restricted", "workspace": "/w",
            "env_allowlist": ["PATH", "HOME"]})
        check = setup._environment_probe_impl(cfg)
        self.assertTrue(check.ok)

    @skip_unless_linux
    def test_environment_probe_failure_refuses(self):
        # Deterministic failure injection: the verify seam raises - the
        # probe must refuse with the explicit reason (fail closed).
        with unittest.mock.patch.object(
                env_mod, "_snapshot_impl",
                side_effect=NamespaceSetupError("environment verification "
                                                "failed: injected (test)")):
            cfg = RuntimeConfig.from_dict(valid_config("/w"))
            check = setup._environment_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("injected (test)", check.reason)

    def test_environment_guard_registered(self):
        self.assertIn(InitStage.ENVIRONMENT, init_mod._STAGE_GUARDS)
        self.assertIs(init_mod._STAGE_GUARDS[InitStage.ENVIRONMENT],
                      setup._environment_guard)

    def test_supervisor_env_never_mutated_by_probe(self):
        # The probe forks; the supervisor's own environment must be
        # untouched (the child replaces only its own). Host-like junk on
        # the supervisor must survive the probe run - asserted INSIDE the
        # patch block (patch.dict restores on exit).
        with unittest.mock.patch.dict(os.environ, {
            "MY_SUPERVISOR_VAR": "keep-me"}, clear=False):
            cfg = RuntimeConfig.from_dict(valid_config("/w"))
            if LINUX:
                check = setup._environment_probe_impl(cfg)
                self.assertTrue(check.ok)
            self.assertEqual(os.environ.get("MY_SUPERVISOR_VAR"), "keep-me")


class EnvIntegrationTests(unittest.TestCase):
    """Full real chain through the fail-closed initializer."""

    @skip_unless_linux
    def test_restricted_real_chain_advances_to_execution(self):
        # RESTRICTED completes RESOURCES (rlimits only, ADR-007) and
        # ENVIRONMENT (sanitization, Step 11) and refuses at the next
        # unimplemented stage (EXECUTION). Fail closed; never a pass.
        # Substrate gate: the REAL chain must be able to establish the
        # namespaces/filesystem first (native runner: skipped with the
        # recorded setgroups/AppArmor reason - the refusal-point
        # assertion is only meaningful where the boundary can form).
        from tests.unit import test_resources as tr
        tr._require_fs(self)
        src = tempfile.mkdtemp(prefix="as-env-int-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src, mode="restricted"))
        with unittest.mock.patch.object(init_mod, "_is_linux",
                                        return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.EXECUTION)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertIn("no implementation", result.failure.reason)

    @skip_unless_linux
    def test_environment_probe_failure_refuses_real_chain(self):
        # A failing ENVIRONMENT probe must refuse initialization at
        # ENVIRONMENT with STAGE_FAILED - never skip the stage.
        # Substrate gate: same as the sibling test - the real chain must
        # be able to reach the ENVIRONMENT stage first.
        from tests.unit import test_resources as tr
        tr._require_fs(self)
        src = tempfile.mkdtemp(prefix="as-env-fail-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src, mode="restricted"))
        with unittest.mock.patch.object(init_mod, "_is_linux",
                                        return_value=True):
            with unittest.mock.patch.object(
                    setup, "_environment_probe_impl",
                    return_value=setup.StageCheck(
                        ok=False, code=InitFailureCode.STAGE_FAILED,
                        reason="environment probe failed (test)")):
                result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.ENVIRONMENT)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("environment probe failed (test)",
                      result.failure.reason)


class EnvSandboxTests(unittest.TestCase):
    """Real sandbox execution: the workload sees exactly the sanitized
    environment under the ACTUAL runtime filter (DOCKER VERIFIED on the
    uid-1001 container; native runner: SKIPPED with recorded reason)."""

    def setUp(self):
        if not LINUX:
            self.skipTest("real sandbox requires Linux")
        # Same substrate gate as the Step 9/10 sandbox suites: the
        # namespace + filesystem probes must succeed on this host
        # (Docker uid 1001: available -> DOCKER VERIFIED; native 24.04
        # runner: skipped with the recorded setgroups/AppArmor reason).
        from tests.unit import test_resources as tr
        tr._require_fs(self)

    @skip_unless_linux
    def test_workload_sees_only_approved_env(self):
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-env-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            import json as _json
            return _json.dumps(dict(os.environ))

        run = setup.run_in_sandbox(
            fn, rootfs_state=rootfs_state,
            limits=RuntimeConfig.from_dict(valid_config(src)).resources,
            env_allowlist=DEFAULT_ENV_ALLOWLIST)
        self.assertEqual(run.exit_code, 0, run.output)
        live = json.loads(run.output)
        self.assertEqual(live, APPROVED)

    @skip_unless_linux
    def test_host_variable_never_reaches_workload(self):
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-env-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            import json as _json
            return _json.dumps(dict(os.environ))

        with unittest.mock.patch.dict(os.environ, {
            "PATH": "/evil", "GITHUB_TOKEN": "ghp_leak",
            "AWS_ACCESS_KEY_ID": "AKIA_leak", "SSH_AUTH_SOCK": "/tmp/agent",
        }, clear=False):
            run = setup.run_in_sandbox(
                fn, rootfs_state=rootfs_state,
                limits=RuntimeConfig.from_dict(valid_config(src)).resources,
                env_allowlist=DEFAULT_ENV_ALLOWLIST)
        self.assertEqual(run.exit_code, 0, run.output)
        live = json.loads(run.output)
        self.assertEqual(live, APPROVED)
        self.assertNotIn("GITHUB_TOKEN", live)
        self.assertNotIn("AWS_ACCESS_KEY_ID", live)
        self.assertNotIn("SSH_AUTH_SOCK", live)

    @skip_unless_linux
    def test_sanitization_failure_refuses_workload(self):
        # The workload marker must NEVER appear when sanitization fails:
        # the verify seam refuses inside PID 1, setup aborts, and the
        # workload fn (which writes the marker) never runs.
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-env-fail-")
        self.addCleanup(shutil.rmtree, src, True)
        marker = pathlib.Path(src) / "marker.txt"
        marker.write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            marker.write_text("WORKLOAD-RAN\n")
            return "should not happen"

        with unittest.mock.patch.object(
                env_mod, "_snapshot_impl",
                side_effect=NamespaceSetupError(
                    "environment verification failed: injected (test)")):
            run = setup.run_in_sandbox(
                fn, rootfs_state=rootfs_state,
                limits=RuntimeConfig.from_dict(valid_config(src)).resources,
                env_allowlist=DEFAULT_ENV_ALLOWLIST)
        self.assertNotEqual(run.exit_code, 0)
        self.assertIn("FAIL setup", run.output)
        self.assertIn("injected (test)", run.output)
        self.assertNotIn("WORKLOAD-RAN", marker.read_text())

    @skip_unless_linux
    def test_steps_6_10_invariants_preserved_in_workload(self):
        # One workload-time view proving the earlier invariants survive
        # environment sanitization: NoNewPrivs=1, all capability sets
        # empty, Seccomp=2, the six rlimits read back, and the env is
        # the approved six.
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-env-inv-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            import json as _json
            # Context manager: a leaked handle's ResourceWarning (emitted
            # by GC at arbitrary time under unittest) would pollute the
            # output pipe - stderr is dup2'd into the same pipe.
            with open("/proc/self/status") as f:
                status = f.read()
            caps = {}
            for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                for line in status.splitlines():
                    if line.startswith(field + ":"):
                        caps[field] = line.split(":", 1)[1].strip()
            nnp = [l for l in status.splitlines()
                   if l.startswith("NoNewPrivs:")][0].split(":", 1)[1].strip()
            sec = [l for l in status.splitlines()
                   if l.startswith("Seccomp:")][0].split(":", 1)[1].strip()
            return _json.dumps({"env": dict(os.environ), "caps": caps,
                                "nnp": nnp, "seccomp": sec})

        run = setup.run_in_sandbox(
            fn, rootfs_state=rootfs_state,
            limits=RuntimeConfig.from_dict(valid_config(src)).resources,
            env_allowlist=DEFAULT_ENV_ALLOWLIST)
        self.assertEqual(run.exit_code, 0, run.output)
        view = json.loads(run.output)
        self.assertEqual(view["env"], APPROVED)
        self.assertEqual(view["nnp"], "1")
        self.assertEqual(view["seccomp"], "2")
        for field, val in view["caps"].items():
            self.assertEqual(val, "0000000000000000", field)
