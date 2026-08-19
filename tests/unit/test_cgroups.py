"""Phase 1 Step 10 tests - cgroup v2 enforcement (S-012/S-027/S-014,
ADR-007 READING A): cgroup v2 identity, the four required controllers
(pids/memory/cpu/io), delegation/writability probe, session cgroup
creation, io.max backing-device resolution from kernel state (never
guessed), all four limits written + read-back verified, PID-1 migration +
membership + workload inheritance. Every unexpected state fails closed.

Evidence labels (kept separate, per the charter):
- HOST-SIDE VERIFIED: policy mapping, formatting, detection, delegation
  reasons, device resolution, failure injection (runs everywhere).
- DOCKER ROOTLESS BLOCKED: cgroupfs is read-only -> HARDENED refuses at
  RESOURCES with the precise detected reason; NEVER an enforcement PASS.
- PRIVILEGED SUBSTRATE VERIFIED: the full mechanism is exercised only
  where a writable delegated subtree exists (the privileged validation
  container, or a genuine delegation host) - mechanism behavior only,
  NOT rootless delegation proof.
- NATIVE ROOTLESS NOT VERIFIED: recorded skip/block on the runner.
"""

from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock

from agent_sandbox.config import ConfigError, ResourceLimits, RuntimeConfig
from agent_sandbox.isolation import cgroups as cg
from agent_sandbox.isolation import setup
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real cgroup operations require Linux with os.fork "
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


def _limits() -> ResourceLimits:
    return RuntimeConfig.from_dict(valid_config("/tmp/x")).resources


class CgroupPolicyTests(unittest.TestCase):
    """Exact policy mapping - runs everywhere."""

    def test_cpu_max_formatting(self):
        # cpu.max = "{percent * 1000} 100000" (fixed 100000 us period).
        self.assertEqual(cg.cpu_max_value(100), "100000 100000")
        self.assertEqual(cg.cpu_max_value(50), "50000 100000")
        self.assertEqual(cg.cpu_max_value(200), "200000 100000")
        self.assertEqual(cg.CPU_QUOTA_PERIOD_US, 100000)

    def test_io_max_formatting(self):
        # io.max = "{major}:{minor} rbps={mbps*MiB} wbps={mbps*MiB}".
        self.assertEqual(
            cg.io_max_value(1024, 8, 17),
            "8:17 rbps=1073741824 wbps=1073741824")
        self.assertEqual(
            cg.io_max_value(50, 7, 0),
            "7:0 rbps=52428800 wbps=52428800")

    def test_cgroup_policy_all_four_exact(self):
        limits = _limits()
        policy = cg.cgroup_policy(limits, (8, 17))
        self.assertEqual(policy, {
            "pids.max": "256",
            "memory.max": "4294967296",
            "cpu.max": "100000 100000",
            "io.max": "8:17 rbps=1073741824 wbps=1073741824",
        })

    def test_cgroup_policy_custom_values(self):
        cfg = RuntimeConfig.from_dict({
            "mode": "hardened", "workspace": "/tmp/x",
            "resources": dict(valid_config("/tmp/x")["resources"],
                              cpu_quota_percent=50, io_mbps=64,
                              processes=100, memory_mb=1024),
        })
        policy = cg.cgroup_policy(cfg.resources, (259, 0))
        self.assertEqual(policy["pids.max"], "100")
        self.assertEqual(policy["memory.max"], "1073741824")
        self.assertEqual(policy["cpu.max"], "50000 100000")
        self.assertEqual(policy["io.max"], "259:0 rbps=67108864 wbps=67108864")


class CgroupConfigTests(unittest.TestCase):
    """The approved policy values - config validation (runs everywhere)."""

    def test_defaults_when_absent(self):
        limits = _limits()
        self.assertEqual(limits.cpu_quota_percent, 100)
        self.assertEqual(limits.io_mbps, 1024)

    def test_valid_values_accepted(self):
        for percent in (1, 100, 10000):
            cfg = RuntimeConfig.from_dict({
                "mode": "hardened", "workspace": "/tmp/x",
                "resources": dict(valid_config("/tmp/x")["resources"],
                                  cpu_quota_percent=percent),
            })
            self.assertEqual(cfg.resources.cpu_quota_percent, percent)
        for mbps in (1, 1024, 1048576):
            cfg = RuntimeConfig.from_dict({
                "mode": "hardened", "workspace": "/tmp/x",
                "resources": dict(valid_config("/tmp/x")["resources"],
                                  io_mbps=mbps),
            })
            self.assertEqual(cfg.resources.io_mbps, mbps)

    def test_cpu_quota_percent_out_of_bounds_rejected(self):
        for bad in (0, -1, 10001, 3.5, True, "50"):
            with self.assertRaises(ConfigError) as cm:
                RuntimeConfig.from_dict({
                    "mode": "hardened", "workspace": "/tmp/x",
                    "resources": dict(valid_config("/tmp/x")["resources"],
                                      cpu_quota_percent=bad),
                })
            self.assertIn("cpu_quota_percent", str(cm.exception))

    def test_io_mbps_out_of_bounds_rejected(self):
        for bad in (0, -5, 1048577, "1024", False):
            with self.assertRaises(ConfigError) as cm:
                RuntimeConfig.from_dict({
                    "mode": "hardened", "workspace": "/tmp/x",
                    "resources": dict(valid_config("/tmp/x")["resources"],
                                      io_mbps=bad),
                })
            self.assertIn("io_mbps", str(cm.exception))


class CgroupDetectionTests(unittest.TestCase):
    """Detection / controllers / delegation - runs everywhere (seams)."""

    def test_detect_v2_marker_missing_refuses(self):
        with unittest.mock.patch.object(cg, "_exists", return_value=False):
            with self.assertRaises(NamespaceSetupError) as cm:
                cg.detect_cgroup_v2("/nonexistent")
        self.assertIn("cgroup v2 unavailable", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_detect_v2_parses_controllers(self):
        def fake_read(path):
            if path.endswith("cgroup.controllers"):
                return "cpuset cpu io memory hugetlb pids rdma\n"
            if path.endswith("cgroup.subtree_control"):
                return "cpu memory pids\n"
            raise AssertionError(f"unexpected read: {path}")

        with unittest.mock.patch.object(cg, "_exists", return_value=True):
            with unittest.mock.patch.object(cg, "_read_file", fake_read):
                state = cg.detect_cgroup_v2("/sys/fs/cgroup")
        self.assertIn("pids", state.available_controllers)
        self.assertIn("io", state.available_controllers)
        self.assertIn("memory", state.enabled_subtree_controllers)

    def test_require_controllers_missing_refuses(self):
        state = cg.CgroupV2State(root="/", available_controllers=frozenset(
            {"pids", "memory", "cpu"}), enabled_subtree_controllers=frozenset())
        with self.assertRaises(NamespaceSetupError) as cm:
            cg.require_controllers(state)
        self.assertIn("io", str(cm.exception))
        self.assertIn("HARDENED refuses", str(cm.exception))

    def test_probe_delegation_readonly_reason(self):
        def ro_mkdir(path):
            raise OSError(errno.EROFS, "Read-only file system")

        with unittest.mock.patch.object(cg, "_own_cgroup_path", return_value="/"):
            with unittest.mock.patch.object(cg, "_mkdir", ro_mkdir):
                reason = cg.probe_delegation("/sys/fs/cgroup")
        self.assertIsNotNone(reason)
        self.assertIn("read-only", reason)

    def test_probe_delegation_not_delegated_reason(self):
        def denied_mkdir(path):
            raise OSError(errno.EACCES, "Permission denied")

        with unittest.mock.patch.object(cg, "_own_cgroup_path", return_value="/"):
            with unittest.mock.patch.object(cg, "_mkdir", denied_mkdir):
                reason = cg.probe_delegation("/sys/fs/cgroup")
        self.assertIsNotNone(reason)
        self.assertIn("not delegated", reason)

    def test_probe_delegation_ok_returns_none(self):
        created = []

        def ok_mkdir(path):
            created.append(path)

        def ok_rmdir(path):
            pass

        def ok_write(path, data):
            pass

        with unittest.mock.patch.object(cg, "_own_cgroup_path", return_value="/"):
            with unittest.mock.patch.object(cg, "_mkdir", ok_mkdir):
                with unittest.mock.patch.object(cg, "_rmdir", ok_rmdir):
                    with unittest.mock.patch.object(cg, "_write_file", ok_write):
                        reason = cg.probe_delegation("/sys/fs/cgroup")
        self.assertIsNone(reason)
        self.assertEqual(len(created), 1, "child cgroup must be created+removed")

    def test_own_cgroup_path_parsing(self):
        with unittest.mock.patch.object(
                cg, "_read_file",
                return_value="12:memory:/x\n0::/user.slice/foo.scope\n"):
            self.assertEqual(cg._own_cgroup_path_impl(),
                             "/user.slice/foo.scope")

    def test_own_cgroup_path_missing_v2_refuses(self):
        with unittest.mock.patch.object(cg, "_read_file", return_value=""):
            with self.assertRaises(NamespaceSetupError):
                cg._own_cgroup_path_impl()


class CgroupIoDeviceTests(unittest.TestCase):
    """io.max device resolution - kernel state, never guessed."""

    def test_resolve_from_st_dev_real_device(self):
        with unittest.mock.patch.object(cg, "os") as fake_os:
            fake_os.stat.return_value.st_dev = 0x8011  # major 8, minor 17
            fake_os.major.return_value = 8
            fake_os.minor.return_value = 17
            fake_os.path.realpath.return_value = "/sys/devices/.../block/sdb"
            fake_os.path.basename.return_value = "sdb"
            with unittest.mock.patch.object(cg, "_exists", return_value=True):
                device = cg.resolve_io_device("/workspace")
        self.assertEqual(device, (8, 17))

    def test_resolve_from_mountinfo_fallback(self):
        # st_dev is pseudo (no /sys/dev/block), but a covering mountinfo
        # entry resolves to a real block device.
        mountinfo = (
            "36 35 0:59 / / rw - overlay overlay rw\n"
            "40 36 8:1 /var/lib/docker /var/lib/docker rw - ext4 /dev/sda1 rw\n"
        )

        def fake_exists(path):
            if path.startswith("/sys/dev/block/0:59"):
                return False
            if path == "/sys/dev/block/8:1":
                return True
            return path == "/sys/class/block/sda1"

        def fake_realpath(path):
            if path == "/sys/dev/block/8:1":
                return "/sys/devices/.../block/sda1"
            return path

        with unittest.mock.patch.object(cg, "os") as fake_os:
            fake_os.stat.return_value.st_dev = 0x3B  # major 0, minor 59
            fake_os.major.return_value = 0
            fake_os.minor.return_value = 59
            fake_os.path.realpath.side_effect = fake_realpath
            fake_os.path.basename.side_effect = lambda p: p.rsplit("/", 1)[-1]
            with unittest.mock.patch.object(cg, "_exists", fake_exists):
                with unittest.mock.patch.object(cg, "_read_file",
                                                return_value=mountinfo):
                    device = cg.resolve_io_device("/var/lib/docker/x")
        self.assertEqual(device, (8, 1))

    def test_unresolvable_device_refuses(self):
        mountinfo = "36 35 0:59 / / rw - overlay overlay rw\n"

        with unittest.mock.patch.object(cg, "os") as fake_os:
            fake_os.stat.return_value.st_dev = 0x3B
            fake_os.major.return_value = 0
            fake_os.minor.return_value = 59
            with unittest.mock.patch.object(cg, "_exists", return_value=False):
                with unittest.mock.patch.object(cg, "_read_file",
                                                return_value=mountinfo):
                    with self.assertRaises(NamespaceSetupError) as cm:
                        cg.resolve_io_device("/workspace")
        self.assertIn("cannot resolve a real backing block device",
                      str(cm.exception))
        self.assertIn("HARDENED refuses", str(cm.exception))
        # io.max is NEVER silently skipped: the refusal is the policy.
        self.assertIn("fail closed", str(cm.exception))


class CgroupFailureTests(unittest.TestCase):
    """Establish/join failure injection - runs everywhere (seams)."""

    def _state(self):
        return cg.CgroupV2State(
            root="/sys/fs/cgroup", available_controllers=frozenset(
                ("pids", "memory", "cpu", "io")),
            enabled_subtree_controllers=frozenset())

    def _session(self):
        return cg.CgroupSession(path="/sys/fs/cgroup/sbx-1",
                                limits=_limits(), io_device=(8, 17))

    def test_prepare_session_create_failure_refuses(self):
        def ro_mkdir(path):
            raise OSError(errno.EROFS, "Read-only file system")

        with unittest.mock.patch.object(cg, "_own_cgroup_path", return_value="/"):
            with unittest.mock.patch.object(cg, "detect_cgroup_v2",
                                            return_value=self._state()):
                with unittest.mock.patch.object(cg, "probe_delegation",
                                                return_value=None):
                    with unittest.mock.patch.object(cg, "_exists",
                                                    return_value=True):
                        with unittest.mock.patch.object(cg, "_read_file",
                                                        return_value="pids memory cpu io\n"):
                            with unittest.mock.patch.object(cg, "_mkdir", ro_mkdir):
                                with self.assertRaises(NamespaceSetupError) as cm:
                                    cg.prepare_session("/sys/fs/cgroup", "sbx-1",
                                                       _limits(), "/tmp/x")
        self.assertIn("cannot create session cgroup", str(cm.exception))

    def test_prepare_session_io_device_unresolvable_refuses(self):
        # The approved policy: an unresolvable io device is a HARDENED
        # refusal, never a silent skip of io.max. The partial session must
        # be removed best-effort.
        removed = []

        def ok_mkdir(path):
            pass

        def ok_rmdir(path):
            removed.append(path)

        def fake_os(workspace):
            raise NamespaceSetupError("cannot resolve a real backing block "
                                      "device for io.max - HARDENED refuses")

        with unittest.mock.patch.object(cg, "_own_cgroup_path", return_value="/"):
            with unittest.mock.patch.object(cg, "detect_cgroup_v2",
                                            return_value=self._state()):
                with unittest.mock.patch.object(cg, "probe_delegation",
                                                return_value=None):
                    with unittest.mock.patch.object(cg, "_exists",
                                                    return_value=True):
                        with unittest.mock.patch.object(cg, "_read_file",
                                                        return_value="pids memory cpu io\n"):
                            with unittest.mock.patch.object(cg, "_mkdir", ok_mkdir):
                                with unittest.mock.patch.object(cg, "_rmdir", ok_rmdir):
                                    with unittest.mock.patch.object(
                                            cg, "resolve_io_device", fake_os):
                                        with self.assertRaises(NamespaceSetupError):
                                            cg.prepare_session(
                                                "/sys/fs/cgroup", "sbx-1",
                                                _limits(), "/tmp/x")
        self.assertEqual(len(removed), 1, "partial session must be removed")

    def test_limit_write_failure_refuses(self):
        def ro_write(path, data):
            raise OSError(errno.EROFS, "Read-only file system")

        with unittest.mock.patch.object(cg, "_write_file", ro_write):
            with self.assertRaises(NamespaceSetupError) as cm:
                cg._write_limits("/sys/fs/cgroup/sbx-1",
                                 {"pids.max": "256"})
        self.assertIn("cannot write pids.max", str(cm.exception))

    def test_limit_readback_mismatch_refuses(self):
        def noop_write(path, data):
            pass

        def fake_read(path):
            return "999\n"  # tampered / wrong value

        with unittest.mock.patch.object(cg, "_write_file", noop_write):
            with unittest.mock.patch.object(cg, "_read_file", fake_read):
                with self.assertRaises(NamespaceSetupError) as cm:
                    cg._write_limits("/sys/fs/cgroup/sbx-1",
                                     {"pids.max": "256"})
        self.assertIn("read-back is '999', expected '256'", str(cm.exception))

    def test_join_migration_failure_refuses(self):
        def denied_write(path, data):
            raise OSError(errno.EACCES, "Permission denied")

        with unittest.mock.patch.object(cg, "_write_file", denied_write):
            with self.assertRaises(NamespaceSetupError) as cm:
                cg.join_and_verify(self._session(), 1)
        self.assertIn("cannot migrate PID 1", str(cm.exception))

    def test_join_membership_mismatch_refuses(self):
        writes = []

        def ok_write(path, data):
            writes.append((path, data))

        def fake_read(path):
            return "42\n"  # PID 1 not present -> tampered membership

        with unittest.mock.patch.object(cg, "_write_file", ok_write):
            with unittest.mock.patch.object(cg, "_read_file", fake_read):
                with self.assertRaises(NamespaceSetupError) as cm:
                    cg.join_and_verify(self._session(), 1)
        self.assertIn("NOT a member", str(cm.exception))

    def test_join_limit_readback_mismatch_refuses(self):
        writes = []

        def ok_write(path, data):
            writes.append((path, data))

        def fake_read(path):
            if path.endswith("cgroup.procs"):
                return "1\n"
            if path.endswith("pids.max"):
                return "1\n"  # tampered
            return "4294967296\n"

        with unittest.mock.patch.object(cg, "_write_file", ok_write):
            with unittest.mock.patch.object(cg, "_read_file", fake_read):
                with self.assertRaises(NamespaceSetupError) as cm:
                    cg.join_and_verify(self._session(), 1)
        self.assertIn("pids.max read-back is '1', expected '256'",
                      str(cm.exception))

    def test_missing_limit_file_refuses(self):
        def missing(path):
            raise OSError(errno.ENOENT, "No such file or directory")

        with unittest.mock.patch.object(cg, "_read_file", missing):
            with self.assertRaises(NamespaceSetupError) as cm:
                cg._verify_limits("/sys/fs/cgroup/sbx-1", _limits(), (8, 17))
        self.assertIn("cannot read pids.max", str(cm.exception))


class CgroupProbeTests(unittest.TestCase):
    """RESOURCES guard fail-closed shape (host-side)."""

    def test_resources_probe_platform_fail_closed(self):
        cfg = RuntimeConfig.from_dict(
            valid_config(tempfile.mkdtemp(prefix="as-cg-")))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=False):
            check = setup._resources_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.PLATFORM_UNSUPPORTED)

    @skip_unless_linux
    def test_hardened_resources_probe_blocks_without_delegation(self):
        # DOCKER ROOTLESS BLOCKED / NATIVE NOT VERIFIED: on this substrate
        # the delegation probe reports the precise reason (Docker rootless:
        # cgroupfs read-only) and HARDENED refuses AT RESOURCES - never a
        # cgroup enforcement PASS.
        from tests.unit import test_resources as tr
        tr._require_ns(self)
        src = tempfile.mkdtemp(prefix="as-cg-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))
        check = setup._resources_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cgroup", check.reason)
        self.assertIn("fail closed", check.reason)


class CgroupDelegationGatedTests(unittest.TestCase):
    """PRIVILEGED SUBSTRATE VERIFIED: the complete mechanism, exercised
    only where a writable delegated subtree exists (the privileged
    validation container, or a genuine systemd-delegated host). NEVER
    represented as rootless delegation proof."""

    def setUp(self):
        if not LINUX:
            self.skipTest("real cgroup operations require Linux")
        blocked = cg.probe_delegation()
        if blocked is not None:
            self.skipTest(
                "no writable delegated cgroup subtree on this substrate: "
                + blocked + " (DOCKER ROOTLESS BLOCKED / NATIVE NOT "
                "VERIFIED - recorded, never a PASS)")
        # HARDENED requires ALL four controllers available AND enabled in
        # the delegated subtree's subtree_control (READING A - no partial
        # success). The full-mechanism test runs only on a substrate that
        # provides the complete controller set; otherwise it records the
        # precise reason (e.g. Docker Desktop WSL2 cannot enable memory/io
        # even privileged) and skips - never a false PASS.
        try:
            state = cg.detect_cgroup_v2()
            cg.require_controllers(state)
            parent = os.path.join(cg.CGROUP_ROOT,
                                  cg._own_cgroup_path().lstrip("/"))
            cg._enabled_in_parent(parent, state)
        except NamespaceSetupError as e:
            self.skipTest(
                "HARDENED cgroup controllers unavailable on this substrate: "
                + str(e))
        self._src = tempfile.mkdtemp(prefix="as-cg-del-")
        self.addCleanup(shutil.rmtree, self._src, True)

    @skip_unless_linux
    def test_full_mechanism_privileged_substrate(self):
        # The complete mechanism: session cgroup created + controllers
        # enabled + all four limits written + PID 1 migrated + membership
        # and every limit read-back verified + workload inheritance.
        # PRIVILEGED SUBSTRATE VERIFIED (mechanism behavior only).
        cfg = RuntimeConfig.from_dict(valid_config(self._src))
        session = cg.prepare_session(
            cg.CGROUP_ROOT, f"sbx-{os.getpid()}", cfg.resources, self._src)
        self.addCleanup(cg.remove_session, session)
        expected = cg.cgroup_policy(cfg.resources, session.io_device)

        def fn(state):
            # The workload reads its OWN kernel-state membership + the
            # session limits - inheritance/membership proof from inside.
            import json as _json
            readback = {}
            for name in ("pids.max", "memory.max", "cpu.max", "io.max"):
                with open(session.path + "/" + name, "r") as f:
                    readback[name] = f.read().strip()
            with open("/proc/self/cgroup", "r") as f:
                self_cgroup = f.read().strip()
            return _json.dumps({"limits": readback,
                                "cgroup": self_cgroup})

        run = setup.run_in_sandbox(fn, limits=cfg.resources,
                                   cgroup_session=session)
        self.assertEqual(run.exit_code, 0, run.output)
        # join_and_verify already refused on any read-back/membership
        # mismatch (exact values), so a successful run is the exact-value
        # proof; the workload additionally confirms the membership path
        # from inside and the session's kernel read-backs.
        data = _json_loads(run.output.strip())
        for name, value in expected.items():
            self.assertEqual(data["limits"][name], value,
                             f"{name} must read back exactly {value}")
        self.assertIn(session.path, data["cgroup"],
                      "workload must be a member of the session cgroup")


def _json_loads(text):
    import json as _j
    return _j.loads(text)


if __name__ == "__main__":
    unittest.main()
