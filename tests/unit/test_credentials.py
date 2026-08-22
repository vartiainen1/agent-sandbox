"""Phase 1 Step 12 tests - credential/socket isolation (S-003, S-004,
ADR-009, ARCHITECTURE.md sections 7/11, T-016, T-019, T-020, T-022):
host credentials and control sockets are ABSENT BY CONSTRUCTION - Step
12 VERIFIES the boundary from the workload view and fails closed on ANY
exposure:

- credential paths / control-socket paths must be UNREACHABLE
  (filesystem reachability, not env-variable removal);
- no socket/credential environment variable may survive the Step 11
  sanitized environment (SSH_AUTH_SOCK, DOCKER_HOST, AWS_*, KUBECONFIG,
  GITHUB_TOKEN, ...);
- Unix-socket creation must be DENIED inside the sandbox (seccomp
  denies the socket syscall class - socket/connect/bind are not in the
  derived 45-syscall allowlist, no expansion).

Categories (kept separate, per the charter):
- Host-side verification logic (path/environment/socket seams, runs
  everywhere, including Windows - deterministic failure injection).
- Sandbox-internal tests (real boundary under the ACTUAL runtime
  filter) - gated on the real namespace+filesystem probes succeeding on
  this substrate (native 24.04 runner: SKIPPED with recorded reason;
  Docker uid 1001: VERIFIED DOCKER).
- Probe + integration: the ENVIRONMENT stage guard's real path now
  covers the socket/credential env check; the full mechanism chain
  (Steps 2-15) completes to READY on a capable substrate (asserted by
  the real-chain tests, not duplicated here).
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
from agent_sandbox.isolation import setup
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real sandbox credential checks require Linux with os.fork "
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


class CredentialPathTests(unittest.TestCase):
    """Host-side path-reachability verification - runs everywhere."""

    def test_no_credential_paths_when_absent(self):
        with unittest.mock.patch.object(cred_mod, "_lexists_impl",
                                        return_value=False):
            reachable = cred_mod.verify_no_credential_paths(
                ("/home/.ssh", "/var/run/docker.sock"))
        self.assertEqual(reachable, ())

    def test_reachable_credential_path_refuses(self):
        with unittest.mock.patch.object(cred_mod, "_lexists_impl",
                                        return_value=True):
            with self.assertRaises(NamespaceSetupError) as cm:
                cred_mod.verify_no_credential_paths(("/home/.ssh",))
        self.assertIn("reachable host path", str(cm.exception))
        self.assertIn("/home/.ssh", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_multiple_reachable_paths_all_reported(self):
        with unittest.mock.patch.object(
                cred_mod, "_lexists_impl",
                side_effect=lambda p: (p.startswith("/var/run")
                                       or "containerd" in p)):
            with self.assertRaises(NamespaceSetupError) as cm:
                cred_mod.verify_no_credential_paths(
                    ("/var/run/docker.sock", "/home/.ssh",
                     "/run/containerd/containerd.sock"))
        msg = str(cm.exception)
        self.assertIn("/var/run/docker.sock", msg)
        self.assertIn("/run/containerd/containerd.sock", msg)
        self.assertNotIn("/home/.ssh", msg)  # absent - not a hit

    def test_canonical_paths_list_covers_named_surfaces(self):
        # The architecture-named credential/control surfaces must all be
        # in the verification list (S-003/S-004).
        for expected in ("/home/.ssh", "/root/.ssh", "/home/.aws",
                         "/home/.kube", "/var/run/docker.sock",
                         "/run/docker.sock", "/root", "/run"):
            self.assertIn(expected, cred_mod.CREDENTIAL_PATHS, expected)


class SocketEnvTests(unittest.TestCase):
    """Host-side env verification - runs everywhere."""

    def test_clean_env_ok(self):
        hits = cred_mod.verify_no_socket_env(
            {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home"})
        self.assertEqual(hits, ())

    def test_socket_env_var_refuses(self):
        for bad in ("SSH_AUTH_SOCK", "DOCKER_HOST", "AWS_ACCESS_KEY_ID",
                    "KUBECONFIG", "GITHUB_TOKEN"):
            with self.assertRaises(NamespaceSetupError) as cm:
                cred_mod.verify_no_socket_env({"PATH": "/x", bad: "/y"})
            self.assertIn(bad, str(cm.exception))
            self.assertIn("fail closed", str(cm.exception))

    def test_empty_value_not_a_hit(self):
        # An empty env var is not a live credential/socket reference.
        hits = cred_mod.verify_no_socket_env(
            {"PATH": "/x", "SSH_AUTH_SOCK": ""})
        self.assertEqual(hits, ())

    def test_socket_env_names_cover_named_surfaces(self):
        for expected in ("SSH_AUTH_SOCK", "DOCKER_HOST",
                         "AWS_ACCESS_KEY_ID", "KUBECONFIG"):
            self.assertIn(expected, cred_mod.SOCKET_ENV_NAMES, expected)


class SocketCreationTests(unittest.TestCase):
    """Socket-creation denial verification."""

    def test_denied_reports_true(self):
        with unittest.mock.patch.object(
                cred_mod, "_socket_creation_denied_impl",
                return_value=True):
            self.assertTrue(cred_mod.verify_socket_creation_denied())

    def test_allowed_reports_false(self):
        with unittest.mock.patch.object(
                cred_mod, "_socket_creation_denied_impl",
                return_value=False):
            self.assertFalse(cred_mod.verify_socket_creation_denied())

    def test_require_denial_fails_closed_when_allowed(self):
        with unittest.mock.patch.object(
                cred_mod, "_socket_creation_denied_impl",
                return_value=False):
            with unittest.mock.patch.object(cred_mod, "_lexists_impl",
                                            return_value=False):
                with self.assertRaises(NamespaceSetupError) as cm:
                    cred_mod.verify_credential_isolation(
                        require_socket_denial=True)
        self.assertIn("NOT denied", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))


class CredentialIsolationTests(unittest.TestCase):
    """Full Step 12 verification logic - runs everywhere."""

    def test_verify_credential_isolation_ok(self):
        with unittest.mock.patch.object(cred_mod, "_lexists_impl",
                                        return_value=False):
            with unittest.mock.patch.object(
                    cred_mod, "_socket_creation_denied_impl",
                    return_value=True):
                state = cred_mod.verify_credential_isolation(
                    require_socket_denial=True)
        self.assertTrue(state.socket_creation_denied)
        self.assertEqual(state.reachable, ())
        self.assertEqual(state.socket_env, ())

    def test_path_violation_refuses_before_socket_check(self):
        with unittest.mock.patch.object(cred_mod, "_lexists_impl",
                                        return_value=True):
            with self.assertRaises(NamespaceSetupError):
                cred_mod.verify_credential_isolation(
                    require_socket_denial=True)

    def test_verify_isolated_env_ok(self):
        state = cred_mod.verify_isolated_env(
            {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home",
             "TMPDIR": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
             "TERM": "dumb"})
        self.assertEqual(state.socket_env, ())

    def test_verify_isolated_env_refuses_on_leak(self):
        with self.assertRaises(NamespaceSetupError) as cm:
            cred_mod.verify_isolated_env(
                {"PATH": "/x", "SSH_AUTH_SOCK": "/tmp/agent"})
        self.assertIn("SSH_AUTH_SOCK", str(cm.exception))


class CredentialProbeTests(unittest.TestCase):
    """The ENVIRONMENT guard's real path (forked child)."""

    @skip_unless_linux
    def test_environment_probe_ok_covers_credentials(self):
        cfg = RuntimeConfig.from_dict(valid_config("/w"))
        check = setup._environment_probe_impl(cfg)
        self.assertTrue(check.ok)
        self.assertIn("no socket/credential variable survives",
                      check.reason)

    @skip_unless_linux
    def test_environment_probe_refuses_on_env_leak(self):
        # A host var injected pre-sanitization cannot survive - the probe
        # replaces the environment wholesale (the Step 11 property) before
        # the socket check. The refusal path is a socket/credential var
        # SURVIVING the constructed env: inject the violation at the
        # verify_no_socket_env seam and assert the probe refuses.
        with unittest.mock.patch.object(
                cred_mod, "verify_no_socket_env",
                side_effect=NamespaceSetupError(
                    "credential/socket isolation violation: environment "
                    "variable(s) survived sanitization: SSH_AUTH_SOCK - "
                    "fail closed, workload not executed")):
            cfg = RuntimeConfig.from_dict(valid_config("/w"))
            check = setup._environment_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("SSH_AUTH_SOCK", check.reason)

    def test_environment_guard_registered(self):
        self.assertIn(InitStage.ENVIRONMENT, init_mod._STAGE_GUARDS)


class CredentialIntegrationTests(unittest.TestCase):
    """Full real chain through the fail-closed initializer."""

    @skip_unless_linux
    def test_restricted_real_chain_completes_to_ready(self):
        # Steps 13-15 complete the EXECUTION stage (bounded output,
        # timeout, process-tree containment + cleanup verification) -
        # RESTRICTED now initializes to READY on a capable substrate
        # (never a silent pass: every mechanism must be established and
        # verified).
        from tests.unit import test_resources as tr
        tr._require_fs(self)
        src = tempfile.mkdtemp(prefix="as-cred-int-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src, mode="restricted"))
        with unittest.mock.patch.object(init_mod, "_is_linux",
                                        return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertTrue(result.ok, result.describe())
        self.assertEqual(result.stage, InitStage.READY)
        self.assertIsNone(result.failure)


class CredentialSandboxTests(unittest.TestCase):
    """Real sandbox execution: the workload view under the ACTUAL runtime
    filter (DOCKER VERIFIED on the uid-1001 container; native runner:
    SKIPPED with recorded reason)."""

    def setUp(self):
        if not LINUX:
            self.skipTest("real sandbox requires Linux")
        from tests.unit import test_resources as tr
        tr._require_fs(self)

    @skip_unless_linux
    def test_credential_paths_unreachable_in_workload(self):
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-cred-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            import json as _json
            reachable = {p: os.path.lexists(p)
                         for p in cred_mod.CREDENTIAL_PATHS
                         if "/" not in p.replace("/", "", 1) or True}
            hits = sorted(p for p in cred_mod.CREDENTIAL_PATHS
                          if os.path.lexists(p))
            return _json.dumps({"hits": hits})

        run = setup.run_in_sandbox(
            fn, rootfs_state=rootfs_state,
            limits=RuntimeConfig.from_dict(valid_config(src)).resources,
            env_allowlist=("PATH", "HOME", "LANG", "LC_ALL", "TERM",
                           "TMPDIR"))
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        self.assertEqual(data["hits"], [],
                         "credential/control-socket paths must be "
                         "unreachable from the workload")

    @skip_unless_linux
    def test_socket_creation_denied_in_workload(self):
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-cred-sock-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            import json as _json
            import socket as _s
            try:
                s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                s.close()
                return _json.dumps({"denied": False})
            except PermissionError:
                return _json.dumps({"denied": True})
            except OSError as e:
                return _json.dumps({"denied": True, "errno": e.errno})

        run = setup.run_in_sandbox(
            fn, rootfs_state=rootfs_state,
            limits=RuntimeConfig.from_dict(valid_config(src)).resources,
            env_allowlist=("PATH", "HOME", "LANG", "LC_ALL", "TERM",
                           "TMPDIR"))
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        self.assertTrue(data["denied"],
                        "Unix-socket creation must be denied by the "
                        "filter at workload time")

    @skip_unless_linux
    def test_credential_verification_failure_refuses_workload(self):
        # Marker-absent: if the credential verification refuses inside
        # PID 1, the workload fn (which writes the marker) never runs.
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-cred-fail-")
        self.addCleanup(shutil.rmtree, src, True)
        marker = pathlib.Path(src) / "marker.txt"
        marker.write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            marker.write_text("WORKLOAD-RAN\n")
            return "should not happen"

        with unittest.mock.patch.object(
                cred_mod, "_lexists_impl", return_value=True):
            run = setup.run_in_sandbox(
                fn, rootfs_state=rootfs_state,
                limits=RuntimeConfig.from_dict(valid_config(src)).resources,
                env_allowlist=("PATH", "HOME", "LANG", "LC_ALL", "TERM",
                               "TMPDIR"))
        self.assertNotEqual(run.exit_code, 0)
        self.assertIn("FAIL setup", run.output)
        self.assertIn("reachable host path", run.output)
        self.assertNotIn("WORKLOAD-RAN", marker.read_text())

    @skip_unless_linux
    def test_steps_6_11_invariants_preserved_in_workload(self):
        # One workload-time view: NoNewPrivs=1, caps empty, Seccomp=2,
        # the approved six env vars, no socket env var, credential paths
        # unreachable, socket creation denied.
        from agent_sandbox.isolation import rootfs as rootfs_mod
        src = tempfile.mkdtemp(prefix="as-cred-inv-")
        self.addCleanup(shutil.rmtree, src, True)
        (pathlib.Path(src) / "marker.txt").write_text("x\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        self.addCleanup(shutil.rmtree, rootfs_state.layout.dir, True)

        def fn(state, fs):
            import json as _json
            import socket as _s
            status = ""
            with open("/proc/self/status") as f:
                status = f.read()
            caps = {}
            for field in ("CapInh", "CapPrm", "CapEff", "CapBnd",
                          "CapAmb"):
                for line in status.splitlines():
                    if line.startswith(field + ":"):
                        caps[field] = line.split(":", 1)[1].strip()
            nnp = [l for l in status.splitlines()
                   if l.startswith("NoNewPrivs:")][0].split(":", 1)[1].strip()
            sec = [l for l in status.splitlines()
                   if l.startswith("Seccomp:")][0].split(":", 1)[1].strip()
            try:
                s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                s.close()
                sock_denied = False
            except (PermissionError, OSError):
                sock_denied = True
            return _json.dumps({
                "env": dict(os.environ), "caps": caps, "nnp": nnp,
                "seccomp": sec, "sock_denied": sock_denied,
                "ssh_sock": os.environ.get("SSH_AUTH_SOCK"),
                "cred_hits": sorted(p for p in cred_mod.CREDENTIAL_PATHS
                                    if os.path.lexists(p)),
            })

        run = setup.run_in_sandbox(
            fn, rootfs_state=rootfs_state,
            limits=RuntimeConfig.from_dict(valid_config(src)).resources,
            env_allowlist=("PATH", "HOME", "LANG", "LC_ALL", "TERM",
                           "TMPDIR"))
        self.assertEqual(run.exit_code, 0, run.output)
        view = json.loads(run.output)
        self.assertEqual(view["nnp"], "1")
        self.assertEqual(view["seccomp"], "2")
        for field, val in view["caps"].items():
            self.assertEqual(val, "0000000000000000", field)
        self.assertIsNone(view["ssh_sock"])
        self.assertTrue(view["sock_denied"])
        self.assertEqual(view["cred_hits"], [])
        self.assertEqual(sorted(view["env"]),
                         ["HOME", "LANG", "LC_ALL", "PATH", "TERM",
                          "TMPDIR"])
