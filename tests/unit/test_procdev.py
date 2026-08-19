"""Phase 1 Step 4 tests - /proc isolation (hidepid=2), minimal /dev
(identity-verified bind-mounts, ADR-015), and /sys absence (REAL Linux
execution).

Categories (kept separate, per the charter):
- Host-side rootfs checks (no sys dir in the tree) - run everywhere.
- Sandbox-internal boundary tests (run inside the pivot_root'd rootfs via
  run_in_sandbox(rootfs=...)) - gated on the real FILESYSTEM probe
  succeeding on this substrate (native 24.04 runner: SKIPPED with
  recorded reason; Docker uid 1001: VERIFIED DOCKER).
- Failure-mode tests: every mandatory boundary failure must REFUSE.

The security distinction this suite pins (Step 4 charter):
- PRIMARY boundary: PID namespace (host processes invisible), mount
  namespace, pivot_root, private propagation.
- DEFENSE IN DEPTH: /proc hidepid=2 (verified as an ACTUAL mount option,
  not assumed from mount() success), the exact minimal /dev inventory,
  /sys absence.
- Device claim (ADR-015): "The sandbox receives an explicitly
  allowlisted set of six identity-verified character devices through a
  private mount namespace. No host /dev tree is exposed." The inodes
  originate from the host; mknod is kernel-unavailable in the userns.
"""

from __future__ import annotations

import errno
import json
import os
import pathlib
import shutil
import stat as stat_mod
import subprocess
import sys
import tempfile
import types
import unittest
import unittest.mock

from agent_sandbox.isolation import filesystem as fs_mod
from agent_sandbox.isolation import rootfs as rootfs_mod
from agent_sandbox.isolation import setup, syscalls
from agent_sandbox.models import InitFailureCode
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real filesystem boundary operations require Linux with os.fork "
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


def make_source() -> str:
    d = tempfile.mkdtemp(prefix="as-src-")
    (pathlib.Path(d) / "marker.txt").write_text("hello-agent-sandbox\n")
    return d


def _run(fn, rootfs_state=None) -> str:
    run = setup.run_in_sandbox(fn, rootfs_state=rootfs_state)
    assert run.exit_code == 0, f"sandbox run failed (exit {run.exit_code}): {run.output}"
    return run.output.strip()


# Real-path capability gate (same discipline as test_namespaces/test_rootfs).
_fs_status: tuple[bool, str] | None = None


def _fs_available() -> tuple[bool, str]:
    global _fs_status
    if _fs_status is None:
        with tempfile.TemporaryDirectory(prefix="as-gate-src-") as src:
            (pathlib.Path(src) / "marker.txt").write_text("gate\n")
            from agent_sandbox.config import RuntimeConfig
            cfg = RuntimeConfig.from_dict(valid_config(src))
            with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
                check = setup._filesystem_probe_impl(cfg)
        _fs_status = (check.ok, check.reason)
    return _fs_status


def _require_fs(self) -> None:
    ok, reason = _fs_available()
    if not ok:
        self.skipTest(
            "filesystem boundary substrate unavailable on this host: " + reason)


def _sandbox_mountinfo() -> list[dict]:
    return fs_mod._read_mountinfo()


def _sandbox_proc_line() -> dict:
    for m in _sandbox_mountinfo():
        if m["mount_point"] == "/proc":
            return m
    raise AssertionError("/proc not in sandbox mountinfo")


class DevMountTests(unittest.TestCase):
    """The /dev mount itself: sandbox-private tmpfs, exact inventory,
    per-node identity, behavior, no host tree."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_dev_tmpfs_is_private(self):
        # /dev must be the sandbox-private tmpfs mount, not the host /dev
        # tree: mountinfo shows a tmpfs at /dev, on a device distinct
        # from the rootfs root.
        def fn(state, fs):
            dev_lines = [m for m in _sandbox_mountinfo() if m["mount_point"] == "/dev"]
            return json.dumps({
                "dev_fstype": dev_lines[0]["fstype"] if dev_lines else None,
                "dev_is_separate": os.stat("/dev").st_dev != os.stat("/").st_dev,
            })

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["dev_fstype"], "tmpfs",
                         "/dev must be the sandbox-private tmpfs")
        self.assertTrue(data["dev_is_separate"])

    @skip_unless_linux
    def test_dev_exact_inventory(self):
        def fn(state, fs):
            return json.dumps(sorted(os.listdir("/dev")))

        names = json.loads(_run(fn, self.rootfs))
        self.assertEqual(names, sorted(n for n, _m, _j in fs_mod.DEV_NODES))

    @skip_unless_linux
    def test_dev_null_identity(self):
        self._assert_node_identity("null", 1, 3)

    @skip_unless_linux
    def test_dev_zero_identity(self):
        self._assert_node_identity("zero", 1, 5)

    @skip_unless_linux
    def test_dev_full_identity(self):
        self._assert_node_identity("full", 1, 7)

    @skip_unless_linux
    def test_dev_random_identity(self):
        self._assert_node_identity("random", 1, 8)

    @skip_unless_linux
    def test_dev_urandom_identity(self):
        self._assert_node_identity("urandom", 1, 9)

    @skip_unless_linux
    def test_dev_tty_identity(self):
        self._assert_node_identity("tty", 5, 0)

    def _assert_node_identity(self, name, major, minor):
        # type + exact major/minor + mode - "node exists" is not the
        # verification. Ownership is intentionally not asserted (host
        # inodes, ADR-015).
        def fn(state, fs):
            st = os.lstat(f"/dev/{name}")
            return json.dumps({"ischr": stat_mod.S_ISCHR(st.st_mode),
                               "rdev": st.st_rdev,
                               "want": syscalls.makedev(major, minor),
                               "mode": st.st_mode & 0o777})

        data = json.loads(_run(fn, self.rootfs))
        self.assertTrue(data["ischr"], f"/dev/{name} is not a char device")
        self.assertEqual(data["rdev"], data["want"],
                         f"/dev/{name} device number mismatch")
        self.assertEqual(data["mode"], 0o666, f"/dev/{name} mode mismatch")

    @skip_unless_linux
    def test_dev_null_writable(self):
        def fn(state, fs):
            with open("/dev/null", "wb") as f:
                f.write(b"x" * 4096)
            with open("/dev/null", "rb") as f:
                return f.read(4) == b""

        self.assertTrue(_run(fn, self.rootfs))

    @skip_unless_linux
    def test_dev_zero_readable(self):
        def fn(state, fs):
            with open("/dev/zero", "rb") as f:
                return f.read(16) == b"\x00" * 16

        self.assertTrue(_run(fn, self.rootfs))

    @skip_unless_linux
    def test_dev_full_behavior(self):
        def fn(state, fs):
            results = {}
            try:
                with open("/dev/full", "wb") as f:
                    f.write(b"x")
                results["write"] = "ok"
            except OSError as e:
                results["write"] = f"errno:{e.errno}"
            with open("/dev/full", "rb") as f:
                results["read_hex"] = f.read(4).hex()
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["write"], f"errno:{errno.ENOSPC}",
                         "/dev/full must fail writes with ENOSPC")
        self.assertEqual(data["read_hex"], "00000000",
                         "/dev/full must read as zeros")

    @skip_unless_linux
    def test_dev_random_and_urandom_readable(self):
        def fn(state, fs):
            out = {}
            for name in ("random", "urandom"):
                with open(f"/dev/{name}", "rb") as f:
                    out[name] = len(f.read(16))
            return json.dumps(out)

        data = json.loads(_run(fn, self.rootfs))
        for name in ("random", "urandom"):
            self.assertEqual(data[name], 16,
                             f"/dev/{name} did not yield 16 bytes")

    @skip_unless_linux
    def test_dev_tty_behavior(self):
        # /dev/tty requires a controlling terminal: without one (supervisor
        # pipe stdout) open fails with ENXIO - behavior per the environment.
        def fn(state, fs):
            st = os.lstat("/dev/tty")
            try:
                with open("/dev/tty", "rb"):
                    opened = "ok"
            except OSError as e:
                opened = f"errno:{e.errno}"
            return json.dumps({"ischr": stat_mod.S_ISCHR(st.st_mode),
                               "rdev": st.st_rdev, "open": opened})

        data = json.loads(_run(fn, self.rootfs))
        self.assertTrue(data["ischr"])
        self.assertEqual(data["rdev"], syscalls.makedev(5, 0))
        self.assertIn(data["open"], ("ok", f"errno:{errno.ENXIO}"),
                      f"unexpected /dev/tty behavior: {data['open']}")

    @skip_unless_linux
    def test_host_dev_tree_not_exposed(self):
        # The host /dev tree is never exposed wholesale: exactly the six
        # allowlisted nodes exist, /dev is the sandbox-private tmpfs (not
        # a bind of the host /dev), and no host device names are present.
        def fn(state, fs):
            dev_lines = [m for m in _sandbox_mountinfo() if m["mount_point"] == "/dev"]
            return json.dumps({"entries": sorted(os.listdir("/dev")),
                               "fstype": dev_lines[0]["fstype"] if dev_lines else None})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["entries"],
                         sorted(n for n, _m, _j in fs_mod.DEV_NODES))
        self.assertEqual(data["fstype"], "tmpfs")

    @skip_unless_linux
    def test_forbidden_device_paths_absent(self):
        # Common unwanted / host devices must be absent/unreachable:
        # no /dev/mem, kmem, kmsg, port, sda, nvme*, fuse, net, ptmx,
        # console, kvm - no arbitrary host device paths.
        forbidden = ("/dev/mem", "/dev/kmem", "/dev/kmsg", "/dev/port",
                     "/dev/sda", "/dev/nvme0n1", "/dev/fuse", "/dev/net",
                     "/dev/net/tun", "/dev/ptmx", "/dev/console", "/dev/kvm",
                     "/dev/nvidia0")

        def fn(state, fs):
            return json.dumps({p: os.path.lexists(p) for p in forbidden})

        data = json.loads(_run(fn, self.rootfs))
        for p, present in data.items():
            self.assertFalse(present, f"forbidden device {p} reachable")

    @skip_unless_linux
    def test_device_creation_attempt_refused(self):
        # The sandbox cannot create additional device nodes: mknod of a
        # char device fails with EPERM (kernel rule - mknod requires
        # initial-userns privileges; ADR-015 documents this as the reason
        # /dev uses bind-mounts).
        def fn(state, fs):
            results = {}
            try:
                os.mknod("/dev/evil", stat_mod.S_IFCHR | 0o600,
                         syscalls.makedev(1, 3))
                results["mknod"] = "ok"
            except OSError as e:
                results["mknod"] = f"errno:{e.errno}"
            results["inventory"] = sorted(os.listdir("/dev"))
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["mknod"], f"errno:{errno.EPERM}",
                         "mknod of a device node must fail with EPERM "
                         "inside the rootless userns")
        self.assertEqual(data["inventory"],
                         sorted(n for n, _m, _j in fs_mod.DEV_NODES),
                         "the /dev inventory must be unchanged")

    @skip_unless_linux
    def test_workspace_cannot_influence_dev_construction(self):
        # A hostile workspace cannot influence /dev provisioning through
        # symlinks or path manipulation: the rootfs /dev is created fresh
        # by the supervisor (outside the workspace copy), and workspace
        # symlinks aimed at device paths resolve inside the rootfs where
        # those devices do not exist.
        (pathlib.Path(self.src) / "dev").mkdir()
        (pathlib.Path(self.src) / "dev" / "null").symlink_to("/dev/sda")
        (pathlib.Path(self.src) / "devlink").symlink_to("/dev/null")
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

        def fn(state, fs):
            results = {}
            for p in ("/workspace/dev/null", "/workspace/devlink"):
                try:
                    with open(p, "rb") as f:
                        f.read(1)
                    results[p] = "OPENED"
                except OSError as e:
                    results[p] = f"blocked:{e.errno}"
            results["dev_inventory"] = sorted(os.listdir("/dev"))
            st = os.lstat("/dev/null")
            results["null_rdev"] = st.st_rdev
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs))
        # The sandbox /dev is unaffected by the hostile workspace.
        self.assertEqual(data["dev_inventory"],
                         sorted(n for n, _m, _j in fs_mod.DEV_NODES))
        self.assertEqual(data["null_rdev"], syscalls.makedev(1, 3))
        # /workspace/dev/null resolves to /dev/sda (absent) -> blocked.
        self.assertTrue(data["/workspace/dev/null"].startswith("blocked:"),
                        data["/workspace/dev/null"])
        # /workspace/devlink resolves to /dev/null - the allowlisted node
        # (fine: it IS the sandbox's own null device, not a host path).
        self.assertEqual(data["/workspace/devlink"], "OPENED")


class ProcMountTests(unittest.TestCase):
    """/proc: actual mount state (procfs, flags, hidepid=2), sandbox-only
    process view, kernel interfaces not readable as host data."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_proc_mount_present(self):
        def fn(state, fs):
            return _sandbox_proc_line()["fstype"]

        self.assertEqual(_run(fn, self.rootfs), "proc")

    @skip_unless_linux
    def test_proc_hidepid_enabled(self):
        def fn(state, fs):
            return _sandbox_proc_line()["super_options"]

        self.assertTrue(fs_mod._hidepid_active(_run(fn, self.rootfs)),
                        "hidepid=2 must be active on the sandbox /proc")

    @skip_unless_linux
    def test_proc_mount_flags(self):
        def fn(state, fs):
            return _sandbox_proc_line()["mount_options"]

        opts = _run(fn, self.rootfs)
        for flag in ("nosuid", "nodev", "noexec"):
            self.assertIn(flag, opts, f"/proc missing mount flag {flag}")

    @skip_unless_linux
    def test_host_processes_not_visible(self):
        # PRIMARY boundary: the PID namespace. A REAL host process (spawned
        # by the supervisor on the host side, never PID 1 - in the test
        # container the unittest process itself is host PID 1, which would
        # collide with the sandbox's own PID 1) must not exist in the
        # sandbox proc view; the only visible process is PID 1 (the fn
        # itself). hidepid=2 is defense in depth, not the boundary.
        helper = subprocess.Popen([sys.executable, "-c",
                                   "import time; time.sleep(30)"])

        def _kill_helper():
            helper.kill()
            helper.wait()

        self.addCleanup(_kill_helper)
        host_pid = helper.pid
        self.assertNotEqual(host_pid, 1,
                            "host helper must not be PID 1 (collision "
                            "with the sandbox's own PID 1)")

        def fn(state, fs):
            pids = set()
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    pids.add(int(entry))
            host_paths = {p: os.path.lexists(f"/proc/{p}")
                          for p in (host_pid, 2, 3)}
            return json.dumps({"pids": sorted(pids), "host_paths": host_paths})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["pids"], [1],
                         "sandbox proc view must contain only PID 1")
        self.assertEqual(data["host_paths"],
                         {str(host_pid): False, "2": False, "3": False},
                         "host processes must be invisible in the sandbox proc view")

    @skip_unless_linux
    def test_proc_1_is_sandbox_self(self):
        def fn(state, fs):
            cmdline = pathlib.Path("/proc/1/cmdline").read_bytes()
            return json.dumps({"self_pid": int(pathlib.Path("/proc/self/stat")
                                               .read_text().split()[0]),
                               "cmdline_len": len(cmdline)})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["self_pid"], 1)
        self.assertGreater(data["cmdline_len"], 0)

    @skip_unless_linux
    def test_proc_kernel_interfaces_not_readable_as_host_data(self):
        # Kernel-metadata procfs files (T-052 residual) must not expose
        # REAL host kernel data: /proc/kcore requires CAP_SYS_RAWIO in the
        # INITIAL user namespace (rootless sandbox never has it -> blocked),
        # and /proc/iomem on restricted kernels is either blocked or prints
        # SANITIZED zeroed address ranges - never real physical addresses.
        # (kallsyms is intentionally NOT asserted: its disclosure depends
        # on host kptr_restrict, a host-side policy outside the sandbox
        # boundary - documented as a known limitation, constrained by the
        # later seccomp stage.)
        def fn(state, fs):
            results = {}
            for p in ("/proc/kcore", "/proc/iomem"):
                try:
                    with open(p, "rb") as f:
                        content = f.read(4096)
                    results[p] = {"open": "ok", "len": len(content),
                                  "text": content.decode("ascii", "replace")}
                except OSError as e:
                    results[p] = {"open": "blocked", "errno": e.errno}
            return json.dumps(results)

        def _sanitized_or_blocked(r) -> bool:
            if r["open"] == "blocked":
                return True
            if r["len"] == 0:
                return True
            # Readable: every address range line must be zeroed (restricted
            # kernels print "00000000-00000000") - any non-zero hex digit
            # in an address field is a real physical-address disclosure.
            for line in r["text"].splitlines():
                if " : " not in line:
                    continue
                addr = line.split(" : ")[0].strip()
                digits = [c for c in addr if c in "0123456789abcdefABCDEF"]
                if digits and any(d != "0" for d in digits):
                    return False
            return True

        data = json.loads(_run(fn, self.rootfs))
        for p, r in data.items():
            self.assertTrue(_sanitized_or_blocked(r),
                            f"{p} exposed real kernel data to the sandbox "
                            f"({r.get('text', r)!r})")

class SysAbsenceTests(unittest.TestCase):
    """/sys: absence is the mechanism (ADR-005) - no sysfs mount, no
    sysfs dir, no reachable host sysfs information."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_sys_absent(self):
        probes = ("/sys", "/sys/class", "/sys/kernel", "/sys/devices",
                  "/sys/firmware", "/sys/block")

        def fn(state, fs):
            return json.dumps({p: os.path.lexists(p) for p in probes})

        data = json.loads(_run(fn, self.rootfs))
        for p, present in data.items():
            self.assertFalse(present, f"/sys path {p} reachable in sandbox")

    @skip_unless_linux
    def test_sys_host_paths_unreachable(self):
        # No sysfs mount, and a workspace symlink aimed at host sysfs
        # resolves inside the rootfs where /sys does not exist.
        (pathlib.Path(self.src) / "syslink").symlink_to("/sys/class/net")
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

        def fn(state, fs):
            results = {}
            try:
                with open("/workspace/syslink", "rb") as f:
                    f.read(1)
                results["syslink"] = "OPENED"
            except OSError as e:
                results["syslink"] = f"blocked:{e.errno}"
            results["sysfs_mount"] = any(
                m["fstype"] == "sysfs" for m in _sandbox_mountinfo())
            results["sys_exists"] = os.path.lexists("/sys")
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs))
        self.assertTrue(data["syslink"].startswith("blocked:"),
                        data["syslink"])
        self.assertFalse(data["sysfs_mount"])
        self.assertFalse(data["sys_exists"])

    def test_sys_not_in_rootfs_tree(self):
        # Host-side (runs everywhere): the built rootfs tree contains no
        # sys directory at all.
        state = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, state.layout.dir, True)
        self.assertFalse(os.path.exists(os.path.join(state.layout.dir, "sys")))


class HostBatteryTests(unittest.TestCase):
    """Extends the Step 3 host-path battery now that /proc and /dev are
    mounted by design (present-but-isolated): everything else stays
    absent."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_host_absent_paths_inside(self):
        def fn(state, fs):
            return json.dumps({p: os.path.lexists(p)
                               for p in fs_mod.HOST_ABSENT_PATHS})

        data = json.loads(_run(fn, self.rootfs))
        for p, present in data.items():
            self.assertFalse(present, f"host path {p} reachable in sandbox")

    @skip_unless_linux
    def test_host_workspace_source_unreachable(self):
        src = self.src

        def fn(state, fs):
            return json.dumps({"src": os.path.lexists(src)})

        data = json.loads(_run(fn, self.rootfs))
        self.assertFalse(data["src"])


class MountPropagationTests(unittest.TestCase):
    """The MS_PRIVATE isolation must remain intact: sandbox /proc + /dev +
    /tmp mounts must NOT appear in the host mount namespace."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_mount_propagation_remains_private(self):
        def mountinfo():
            with open("/proc/self/mountinfo", "r", encoding="ascii") as f:
                return sorted(f.read().splitlines())

        before = mountinfo()

        def fn(state, fs):
            sandbox_mounts = sorted(m["mount_point"] for m in _sandbox_mountinfo())
            return json.dumps({"sandbox_mounts": sandbox_mounts})

        data = json.loads(_run(fn, self.rootfs))
        for mp in ("/proc", "/dev", "/tmp"):
            self.assertIn(mp, data["sandbox_mounts"],
                          f"{mp} missing from sandbox mountinfo")
        after = mountinfo()
        self.assertEqual(before, after,
                         "sandbox mounts leaked into the host mount namespace")


class FailureModeTests(unittest.TestCase):
    """Every mandatory Step 4 failure must become a REFUSAL with an
    explicit reason - never a silent continue with a partially configured
    filesystem."""

    def _probe_with(self, workspace: str) -> object:
        from agent_sandbox.config import RuntimeConfig
        cfg = RuntimeConfig.from_dict(valid_config(workspace))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            return setup._filesystem_probe_impl(cfg)

    def _assert_refused(self, check, reason_part: str) -> None:
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn(reason_part, check.reason)

    @skip_unless_linux
    def test_dev_mount_failure_refused(self):
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_mount = syscalls.mount

        def boom(source, target, fstype, flags, data=b""):
            if target.endswith(b"/dev") and fstype == b"tmpfs":
                raise OSError(errno.EPERM, "mount: Operation not permitted")
            return real_mount(source, target, fstype, flags, data)

        try:
            syscalls.mount = boom
            self._assert_refused(self._probe_with(src), "mount")
        finally:
            syscalls.mount = real_mount

    @skip_unless_linux
    def test_proc_mount_failure_refused(self):
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_mount = syscalls.mount

        def boom(source, target, fstype, flags, data=b""):
            if target == b"/proc":
                raise OSError(errno.EPERM, "mount: Operation not permitted")
            return real_mount(source, target, fstype, flags, data)

        try:
            syscalls.mount = boom
            self._assert_refused(self._probe_with(src), "proc")
        finally:
            syscalls.mount = real_mount

    @skip_unless_linux
    def test_wrong_major_minor_refused(self):
        # Simulate a host source node with the wrong identity (e.g. the
        # host /dev/null replaced by another device): the source
        # verification must refuse before anything is bound. os.stat_result
        # is immutable, so the simulated lstat returns a duck-typed
        # stand-in with the attributes the verifier reads (st_mode,
        # st_rdev).
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_lstat = fs_mod._lstat

        def wrong_null(path):
            if path == "/dev/null":
                return types.SimpleNamespace(
                    st_mode=stat_mod.S_IFCHR | 0o666,
                    st_rdev=syscalls.makedev(1, 11))  # kmsg, not null
            return real_lstat(path)

        try:
            fs_mod._lstat = wrong_null
            # The deterministic refusal message reports the actual rdev
            # mismatch ("rdev 267 != expected 259 (1,3)").
            self._assert_refused(self._probe_with(src), "rdev")
        finally:
            fs_mod._lstat = real_lstat

    @skip_unless_linux
    def test_unexpected_device_refused(self):
        # Simulate a host source node that is not a character device: the
        # source verification must refuse.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_lstat = fs_mod._lstat

        def regular_file(path):
            if path == "/dev/zero":
                return types.SimpleNamespace(
                    st_mode=stat_mod.S_IFREG | 0o644,
                    st_rdev=0)
            return real_lstat(path)

        try:
            fs_mod._lstat = regular_file
            self._assert_refused(self._probe_with(src), "not a character device")
        finally:
            fs_mod._lstat = real_lstat

    @skip_unless_linux
    def test_extra_device_refused(self):
        # An extra node bound into /dev must fail the exact-inventory
        # verification.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_mount = syscalls.mount

        def extra(source, target, fstype, flags, data=b""):
            real_mount(source, target, fstype, flags, data)
            if target.endswith(b"/tty"):  # after the last legit bind
                # Bind the sandbox's OWN just-mounted /dev/null onto an
                # extra node (no dependence on any host device path):
                # create the placeholder (as the legit binds do), then
                # bind. /dev now has 7 entries -> exact-inventory
                # verification must refuse.
                with open(target[:-4] + b"/kmsg", "w"):
                    pass
                real_mount(target[:-4] + b"/null", target[:-4] + b"/kmsg",
                           b"", syscalls.MS_BIND, b"")

        try:
            syscalls.mount = extra
            self._assert_refused(self._probe_with(src), "inventory mismatch")
        finally:
            syscalls.mount = real_mount

    @skip_unless_linux
    def test_verification_failure_refused(self):
        # Post-operation verification failing must refuse - the boundary
        # cannot be considered established on unverifiable evidence.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_verify = fs_mod._verify_dev_inventory

        def broken():
            return ["/dev verification failed (simulated)"], {}

        try:
            fs_mod._verify_dev_inventory = broken
            self._assert_refused(self._probe_with(src), "verification failed")
        finally:
            fs_mod._verify_dev_inventory = real_verify

    @skip_unless_linux
    def test_sys_mounted_refused(self):
        # An unexpected /sys exposure must refuse.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_mount = syscalls.mount

        def leaky(source, target, fstype, flags, data=b""):
            real_mount(source, target, fstype, flags, data)
            if target.endswith(b"/dev") and fstype == b"tmpfs":
                # Simulate an unexpected /sys exposure: create a sys dir in
                # the rootfs tree (host-side path pre-pivot) and mount a
                # tmpfs over it. After pivot_root this becomes a mounted
                # /sys -> the absence check must refuse.
                sys_dir = target[:-4] + b"/sys"
                os.makedirs(sys_dir, exist_ok=True)
                real_mount(b"tmpfs", sys_dir, b"tmpfs", 0, b"size=1m")

        try:
            syscalls.mount = leaky
            self._assert_refused(self._probe_with(src), "host path(s) reachable")
        finally:
            syscalls.mount = real_mount


class IntegrationTests(unittest.TestCase):
    @skip_unless_linux
    def test_probe_reason_covers_procdev(self):
        # The real FILESYSTEM probe (gated) now establishes and verifies
        # /proc + /dev too - its OK reason must say so.
        ok, reason = _fs_available()
        if not ok:
            self.skipTest("filesystem boundary substrate unavailable: " + reason)
        self.assertIn("hidepid", reason)
        self.assertIn("minimal /dev", reason)


if __name__ == "__main__":
    unittest.main()
