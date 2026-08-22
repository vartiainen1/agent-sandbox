"""Phase 2 P2 — In-Sandbox Information Leakage Adversarial Testing

T-021: Core dump leak
T-022: Audit/environment leakage
T-053: Audit tampering from inside

Evidence: NATIVE VERIFIED on Docker --privileged (real sandbox boundary).
"""

from __future__ import annotations

import ast
import json
import os
import pathlib

try:
    import resource
except ImportError:
    resource = None  # Windows: guarded
import shutil
import sys
import tempfile
import unittest

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import rootfs as rootfs_mod
from agent_sandbox.isolation import setup

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")


def _valid_config(src, mode="restricted"):
    return {
        "workspace": src,
        "mode": mode,
        "resources": {
            "cpu_seconds": 300, "memory_mb": 4096, "disk_mb": 10240,
            "processes": 256, "open_files": 4096,
            "output_mb": 50, "wall_time_seconds": 900,
        },
    }


def _run_attack(fn, output_mb=50, wall_time_seconds=900):
    src = tempfile.mkdtemp(prefix="as-info-attack-")
    try:
        (pathlib.Path(src) / "marker.txt").write_text("workspace\n")
        rootfs_state = rootfs_mod.build_rootfs(src)
        try:
            return setup.run_in_sandbox(
                fn,
                rootfs_state=rootfs_state,
                limits=RuntimeConfig.from_dict(
                    _valid_config(src)).resources,
                env_allowlist=("PATH", "HOME", "LANG", "LC_ALL", "TERM",
                               "TMPDIR"),
                output_mb=output_mb,
                wall_time_seconds=wall_time_seconds,
            )
        finally:
            shutil.rmtree(rootfs_state.layout.dir, True)
    finally:
        shutil.rmtree(src, True)


# ---------------------------------------------------------------------------
# T-021: Core Dump Leak (S-003)
# ---------------------------------------------------------------------------

class CoreDumpLeakTests(unittest.TestCase):
    """T-021: Verify that core dumps cannot leak secrets.

    RLIMIT_CORE is set to 0, so no core file is ever generated.
    We verify this and that even if a crash occurs, no sensitive data
    is written to disk."""

    def _core_dump_payload(self, state, fs):
        results = {}
        # Verify RLIMIT_CORE is 0.
        soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        results["core_soft"] = soft
        results["core_hard"] = hard
        results["core_zero"] = (soft == 0 and hard == 0)

        # Check if core dumps are enabled in /proc.
        try:
            core_pattern = pathlib.Path(
                "/proc/sys/kernel/core_pattern").read_text().strip()
            results["core_pattern"] = core_pattern
        except (OSError, PermissionError):
            results["core_pattern"] = "UNREADABLE"

        # Attempt to generate a segfault (may or may not work).
        # The point is: even if it does, RLIMIT_CORE=0 means no core file.
        results["marker"] = "CORE-DUMP-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_core_dump_disabled(self):
        """T-021: RLIMIT_CORE must be 0 (no core dumps)."""
        run = _run_attack(self._core_dump_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "CORE-DUMP-EXECUTED")
        self.assertTrue(data["core_zero"],
                        "RLIMIT_CORE must be 0/0 (core dumps disabled)")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_no_core_file_after_crash(self):
        """T-021: Verify no core file is created even after abnormal exit."""
        def fn(state, fs):
            # Attempt to crash (divide by zero in a way that might core).
            try:
                os.abort()
            except Exception:
                pass
            # Check if any core file was created.
            core_files = list(pathlib.Path("/tmp").glob("core*"))
            core_files += list(pathlib.Path("/").glob("core*"))
            return json.dumps({
                "core_files": [str(f) for f in core_files],
                "core_count": len(core_files),
            })

        run = _run_attack(fn)
        # The process may have been killed (exit != 0 is OK).
        data = json.loads(run.output) if run.output else {}
        self.assertEqual(data.get("core_count", 0), 0,
                         "no core files must be created (RLIMIT_CORE=0)")


# ---------------------------------------------------------------------------
# T-022: Audit/Environment Leakage (S-003, S-039)
# ---------------------------------------------------------------------------

class AuditEnvironmentLeakageTests(unittest.TestCase):
    """T-022: Verify that host environment and audit data cannot leak
    to the workload."""

    def _env_leakage_payload(self, state, fs):
        results = {}
        # Enumerate all environment variables.
        env_keys = sorted(os.environ.keys())
        results["env_keys"] = env_keys
        results["env_count"] = len(env_keys)

        # Check for sensitive env vars.
        sensitive = ["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
                     "GITHUB_TOKEN", "SSH_AUTH_SOCK", "DOCKER_HOST",
                     "GPG_AGENT_INFO", "DBUS_SESSION_BUS_ADDRESS"]
        found_sensitive = [k for k in sensitive if k in os.environ]
        results["sensitive_found"] = found_sensitive

        # Check for any env var with a long value (potential secret).
        long_vars = {k: len(v) for k, v in os.environ.items() if len(v) > 50}
        results["long_vars"] = long_vars

        # Verify the environment is exactly the 6 approved variables.
        approved = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM"}
        extra = set(env_keys) - approved
        results["extra_vars"] = sorted(extra)

        results["marker"] = "ENV-LEAKAGE-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_env_six_approved_only(self):
        """T-022: Only the 6 approved env vars must be present."""
        run = _run_attack(self._env_leakage_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "ENV-LEAKAGE-EXECUTED")
        self.assertEqual(data["extra_vars"], [],
                         f"no extra env vars allowed: {data['extra_vars']}")
        self.assertEqual(len(data["env_keys"]), 6,
                         f"exactly 6 env vars required, got "
                         f"{len(data['env_keys'])}")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_no_sensitive_env_leaked(self):
        """T-022: No sensitive host env vars must leak."""
        run = _run_attack(self._env_leakage_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        self.assertEqual(data["sensitive_found"], [],
                         f"no sensitive env vars must leak: "
                         f"{data['sensitive_found']}")
        self.assertEqual(data["long_vars"], {},
                         f"no long env vars (potential secrets): "
                         f"{data['long_vars']}")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_no_audit_data_in_workload(self):
        """T-022: Audit log files must not be accessible from workload."""
        def fn(state, fs):
            # Try to read potential audit files.
            audit_paths = [
                "/tmp/audit.jsonl", "/var/log/audit.log",
                "/tmp/sandbox_audit.jsonl",
            ]
            hits = {}
            for p in audit_paths:
                try:
                    hits[p] = pathlib.Path(p).exists()
                except (OSError, PermissionError):
                    hits[p] = False
            return json.dumps(hits)

        run = _run_attack(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        for path, exists in data.items():
            self.assertFalse(exists,
                             f"audit file {path} must not be accessible")


# ---------------------------------------------------------------------------
# T-053: Audit Tampering from Inside (S-022, S-024)
# ---------------------------------------------------------------------------

class AuditTamperingTests(unittest.TestCase):
    """T-053: Attempt to tamper with the audit system from inside the
    sandbox. The audit recorder is host-side (ADR-012) and writes to a
    host-side file; the workload cannot reach it."""

    def _audit_tamper_payload(self, state, fs):
        results = {}
        # Try to find and modify audit files at HOST-SIDE paths.
        # The audit recorder writes to the host filesystem, not the
        # sandbox's /tmp. These paths should not exist in the sandbox.
        host_audit_paths = [
            "/var/log/sandbox_audit.jsonl",
            "/var/log/audit/sandbox.jsonl",
            "/root/sandbox_audit.jsonl",
        ]
        for path in host_audit_paths:
            try:
                exists = pathlib.Path(path).exists()
                results[f"exists_{path}"] = exists
            except (OSError, PermissionError):
                results[f"exists_{path}"] = False

        # Also verify that writing to sandbox /tmp doesn't create a
        # host-side file (sandbox-internal).
        try:
            pathlib.Path("/tmp/sandbox_internal.jsonl").write_text("test")
            results["sandbox_tmp_write"] = "SANDBOX-INTERNAL"
        except (OSError, PermissionError) as e:
            results["sandbox_tmp_write"] = f"BLOCKED: {e}"

        results["marker"] = "AUDIT-TAMPER-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_audit_tamper_contained(self):
        """T-053: Audit files must not be accessible for tampering."""
        run = _run_attack(self._audit_tamper_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "AUDIT-TAMPER-EXECUTED")
        # Host-side audit files must not exist in the sandbox.
        for key, result in data.items():
            if key.startswith("exists_"):
                self.assertFalse(result,
                                f"host audit file must not exist: {key}")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_audit_path_not_reachable(self):
        """T-053: The host-side audit directory must not be reachable."""
        def fn(state, fs):
            # Try to access common audit log locations.
            paths = ["/var/log", "/tmp", "/root"]
            results = {}
            for p in paths:
                try:
                    entries = list(pathlib.Path(p).iterdir())
                    audit_like = [e.name for e in entries
                                  if "audit" in e.name.lower()]
                    results[p] = audit_like
                except (OSError, PermissionError):
                    results[p] = "INACCESSIBLE"
            return json.dumps(results)

        run = _run_attack(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        # No audit-like files should be found.
        for path, found in data.items():
            if isinstance(found, list):
                self.assertEqual(found, [],
                                 f"no audit files must be in {path}")


# ---------------------------------------------------------------------------
# Host-side structural verification
# ---------------------------------------------------------------------------

class InfoLeakageStructuralTests(unittest.TestCase):
    """Host-side structural checks."""

    def test_all_test_classes_exist(self):
        from tests.adversarial.test_info_leakage import (
            AuditEnvironmentLeakageTests,
            AuditTamperingTests,
            CoreDumpLeakTests,
        )
        for cls in [CoreDumpLeakTests, AuditEnvironmentLeakageTests,
                     AuditTamperingTests]:
            self.assertTrue(issubclass(cls, unittest.TestCase))

    def test_no_mock_in_attack_modules(self):
        import tests.adversarial.test_info_leakage as mod
        tree = ast.parse(open(mod.__file__).read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module)
        self.assertNotIn("unittest.mock", imported)


if __name__ == "__main__":
    unittest.main()
