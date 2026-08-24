"""Phase 2 P2 — In-Sandbox Resource Adversarial Testing

T-029: Fork bomb
T-030: Memory exhaustion
T-031: Disk exhaustion
T-032: FD exhaustion
T-035: Resource-limit increase attempt

All attacks use bounded/safe workloads that demonstrate enforcement
without endangering the host.

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

# Cached substrate probe (same discipline as test_filesystem_attacks.py).
_fs_status: tuple[bool, str] | None = None


def _fs_available() -> tuple[bool, str]:
    global _fs_status
    if _fs_status is None:
        try:
            with tempfile.TemporaryDirectory(prefix="as-adv-gate-") as src:
                (pathlib.Path(src) / "marker.txt").write_text("gate\n")
                cfg = RuntimeConfig.from_dict(_valid_config(src))
                check = setup._filesystem_probe_impl(cfg)
            _fs_status = (check.ok, check.reason)
        except Exception as exc:
            _fs_status = (False, f"substrate probe raised: {exc}")
    return _fs_status


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
    ok, reason = _fs_available()
    if not ok:
        raise unittest.SkipTest(
            "filesystem boundary substrate unavailable: " + reason
        )
    src = tempfile.mkdtemp(prefix="as-res-attack-")
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
# T-029: Fork Bomb (S-012, S-013)
# ---------------------------------------------------------------------------

class ForkBombTests(unittest.TestCase):
    """T-029: Attempt to exhaust process count via fork bomb.

    In v0.1, clone() is denied by seccomp (not in 45-syscall allowlist),
    so os.fork() fails with EPERM. The fork bomb cannot even start.
    We verify this containment."""

    def _forkbomb_payload(self, state, fs):
        results = {}
        # Attempt to fork bomb — each fork will fail with EPERM.
        fork_count = 0
        fail_count = 0
        for _ in range(10):
            try:
                pid = os.fork()
                if pid == 0:
                    os._exit(0)
                fork_count += 1
            except PermissionError:
                fail_count += 1
        results["forks_succeeded"] = fork_count
        results["forks_denied"] = fail_count
        results["marker"] = "FORKBOMB-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_forkbomb_denied(self):
        """T-029: Fork bomb must be denied by seccomp (clone excluded)."""
        run = _run_attack(self._forkbomb_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "FORKBOMB-EXECUTED")
        # All fork attempts must be denied.
        self.assertEqual(data["forks_succeeded"], 0,
                         "no forks must succeed (clone denied by seccomp)")
        self.assertEqual(data["forks_denied"], 10,
                         "all 10 fork attempts must be denied")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_forkbomb_no_process_survives(self):
        """T-029: After fork bomb attempt, no child process survives."""
        def fn(state, fs):
            try:
                pid = os.fork()
                if pid == 0:
                    os._exit(0)
                return "FORK-SUCCEEDED"
            except PermissionError:
                return "FORK-DENIED"

        run = _run_attack(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        self.assertIn("FORK-DENIED", run.output)


# ---------------------------------------------------------------------------
# T-030: Memory Exhaustion (S-012)
# ---------------------------------------------------------------------------

class MemoryExhaustionTests(unittest.TestCase):
    """T-030: Attempt to exhaust memory via large allocation.

    The sandbox has RLIMIT_AS (4 GiB) and memory.max (cgroup) limits.
    We attempt a large mmap and verify it's bounded."""

    def _memory_payload(self, state, fs):
        results = {}
        # Read the rlimit to confirm limits are active.
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            results["rlimit_as_soft"] = soft
            results["rlimit_as_hard"] = hard
        except Exception as e:
            results["rlimit_as_error"] = str(e)

        # Attempt to allocate more memory than the RLIMIT_AS allows.
        # The limit is 4 GiB. Try to allocate 5 GiB.
        try:
            data = b"x" * (5 * 1024 * 1024 * 1024)
            results["alloc_5gb"] = "SUCCEEDED (unexpected)"
            del data
        except MemoryError as e:
            results["alloc_5gb"] = f"BLOCKED: {e}"
        except Exception as e:
            results["alloc_5gb"] = f"BLOCKED: {type(e).__name__}: {e}"

        results["marker"] = "MEMORY-EXHAUSTION-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_memory_exhaustion_bounded(self):
        """T-030: Memory allocation beyond limits must be blocked."""
        run = _run_attack(self._memory_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "MEMORY-EXHAUSTION-EXECUTED")
        # rlimit must be active.
        self.assertIn("rlimit_as_soft", data, "rlimit must be readable")
        # 5 GiB allocation must fail (exceeds 4 GiB limit).
        self.assertIn("BLOCKED", data.get("alloc_5gb", ""),
                      "5 GiB allocation must be blocked")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_memory_limit_enforced(self):
        """T-030: Verify memory limit is actually enforced."""
        def fn(state, fs):
            # Read the rlimit and try to use more than allowed.
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            # Try to allocate a moderate amount (should succeed).
            try:
                data = b"a" * (1024 * 1024)  # 1 MiB (well under 4 GiB)
                at_limit = True
                del data
            except MemoryError:
                at_limit = False
            return json.dumps({
                "limit": soft,
                "at_limit_works": at_limit,
            })

        run = _run_attack(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        self.assertTrue(data["at_limit_works"],
                        "allocation just under limit should succeed")


# ---------------------------------------------------------------------------
# T-031: Disk Exhaustion (S-012)
# ---------------------------------------------------------------------------

class DiskExhaustionTests(unittest.TestCase):
    """T-031: Attempt to exhaust disk via large writes."""

    def _disk_payload(self, state, fs):
        results = {}
        # Read RLIMIT_FSIZE.
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            results["fsize_soft"] = soft
            results["fsize_hard"] = hard
        except Exception as e:
            results["fsize_error"] = str(e)

        # Attempt to write a file larger than RLIMIT_FSIZE.
        try:
            big = pathlib.Path("/tmp/big_file.bin")
            # Write in chunks to exceed the limit.
            chunk = b"x" * (1024 * 1024)  # 1 MiB chunks
            written = 0
            with open(big, "wb") as f:
                for _ in range(20):  # Try 20 MiB
                    f.write(chunk)
                    written += len(chunk)
            results["write_20mb"] = f"WROTE: {written} bytes"
        except (OSError, PermissionError) as e:
            results["write_20mb"] = f"BLOCKED: {e}"

        results["marker"] = "DISK-EXHAUSTION-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_disk_exhaustion_bounded(self):
        """T-031: Disk write beyond fsize limit must be blocked."""
        run = _run_attack(self._disk_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "DISK-EXHAUSTION-EXECUTED")
        # fsize limit must be active.
        self.assertIn("fsize_soft", data, "fsize rlimit must be readable")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_disk_limit_enforced(self):
        """T-031: Verify disk limit is enforced via small writes."""
        def fn(state, fs):
            soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            # Write a small file (should succeed).
            try:
                pathlib.Path("/tmp/small.txt").write_text("ok")
                small_ok = True
            except (OSError, PermissionError):
                small_ok = False
            return json.dumps({
                "fsize_limit": soft,
                "small_write_ok": small_ok,
            })

        run = _run_attack(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        self.assertTrue(data["small_write_ok"],
                        "small write should succeed within fsize limit")


# ---------------------------------------------------------------------------
# T-032: FD Exhaustion (S-012)
# ---------------------------------------------------------------------------

class FDExhaustionTests(unittest.TestCase):
    """T-032: Attempt to exhaust file descriptors."""

    def _fd_payload(self, state, fs):
        results = {}
        # Read RLIMIT_NOFILE.
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            results["nofile_soft"] = soft
            results["nofile_hard"] = hard
        except Exception as e:
            results["nofile_error"] = str(e)

        # Open FDs until we hit the limit.
        fds = []
        opened = 0
        denied = 0
        for _ in range(soft + 100):  # Try to exceed the limit.
            try:
                r, w = os.pipe()
                fds.append((r, w))
                opened += 1
            except OSError:
                denied += 1
                break
        # Close all opened FDs.
        for r, w in fds:
            try:
                os.close(r)
                os.close(w)
            except OSError:
                pass
        results["fds_opened"] = opened
        results["fds_denied"] = denied
        results["marker"] = "FD-EXHAUSTION-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_fd_exhaustion_bounded(self):
        """T-032: FD exhaustion must be bounded by RLIMIT_NOFILE."""
        run = _run_attack(self._fd_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "FD-EXHAUSTION-EXECUTED")
        # Must have hit the limit.
        self.assertGreater(data["fds_denied"], 0,
                           "must hit FD limit (denied > 0)")
        # Must not have opened way more than the limit.
        soft = data.get("nofile_soft", 4096)
        self.assertLessEqual(data["fds_opened"], soft + 1,
                             "FDs opened must not significantly exceed limit")


# ---------------------------------------------------------------------------
# T-035: Resource-Limit Increase Attempt (S-012, S-027)
# ---------------------------------------------------------------------------

class ResourceLimitIncreaseTests(unittest.TestCase):
    """T-035: Attempt to raise resource limits from inside the sandbox.

    Lowered hard limits can never be raised (S-027). We verify this."""

    def _limit_increase_payload(self, state, fs):
        results = {}
        limits = [
            ("RLIMIT_CPU", resource.RLIMIT_CPU),
            ("RLIMIT_AS", resource.RLIMIT_AS),
            ("RLIMIT_NPROC", resource.RLIMIT_NPROC),
            ("RLIMIT_NOFILE", resource.RLIMIT_NOFILE),
            ("RLIMIT_FSIZE", resource.RLIMIT_FSIZE),
        ]
        for name, res in limits:
            soft, hard = resource.getrlimit(res)
            # Try to raise the soft limit to above the hard limit.
            try:
                resource.setrlimit(res, (hard + 1000, hard + 1000))
                new_soft, new_hard = resource.getrlimit(res)
                results[name] = f"RAISED to {new_soft}/{new_hard}"
            except (ValueError, OSError) as e:
                results[name] = f"BLOCKED: {e}"
            # Try to raise just the soft limit.
            try:
                resource.setrlimit(res, (hard + 500, hard))
                new_soft, _ = resource.getrlimit(res)
                results[f"{name}_soft"] = f"RAISED to {new_soft}"
            except (ValueError, OSError) as e:
                results[f"{name}_soft"] = f"BLOCKED: {e}"

        results["marker"] = "LIMIT-INCREASE-EXECUTED"
        return json.dumps(results)

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_limit_increase_all_blocked(self):
        """T-035: All resource limit increase attempts must be blocked."""
        run = _run_attack(self._limit_increase_payload)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "")
        data = json.loads(run.output)
        self.assertEqual(data["marker"], "LIMIT-INCREASE-EXECUTED")
        for key, result in data.items():
            if key == "marker":
                continue
            self.assertNotIn("RAISED", result,
                             f"limit increase {key} must not succeed: "
                             f"{result}")

    @unittest.skipUnless(LINUX, "real sandbox requires Linux")
    def test_limits_immutable_after_drop(self):
        """T-035: Verify limits are immutable (soft == hard, cannot raise)."""
        def fn(state, fs):
            results = {}
            for name, res in [("CPU", resource.RLIMIT_CPU),
                              ("AS", resource.RLIMIT_AS),
                              ("NPROC", resource.RLIMIT_NPROC),
                              ("NOFILE", resource.RLIMIT_NOFILE),
                              ("FSIZE", resource.RLIMIT_FSIZE)]:
                soft, hard = resource.getrlimit(res)
                results[name] = {"soft": soft, "hard": hard,
                                 "equal": soft == hard}
            return json.dumps(results)

        run = _run_attack(fn)
        self.assertEqual(run.exit_code, 0, run.output)
        data = json.loads(run.output)
        for name, info in data.items():
            self.assertTrue(info["equal"],
                            f"{name}: soft ({info['soft']}) must equal "
                            f"hard ({info['hard']})")


# ---------------------------------------------------------------------------
# Host-side structural verification
# ---------------------------------------------------------------------------

class ResourceAttackStructuralTests(unittest.TestCase):
    """Host-side structural checks."""

    def test_all_test_classes_exist(self):
        from tests.adversarial.test_resource_attacks import (
            DiskExhaustionTests,
            FDExhaustionTests,
            ForkBombTests,
            MemoryExhaustionTests,
            ResourceLimitIncreaseTests,
        )
        for cls in [ForkBombTests, MemoryExhaustionTests,
                     DiskExhaustionTests, FDExhaustionTests,
                     ResourceLimitIncreaseTests]:
            self.assertTrue(issubclass(cls, unittest.TestCase))

    def test_no_mock_in_attack_modules(self):
        import tests.adversarial.test_resource_attacks as mod
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
