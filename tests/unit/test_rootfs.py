"""Phase 1 Step 3 tests - minimal root filesystem + pivot_root + workspace
isolation + mount propagation (REAL Linux execution).

Categories (kept separate, per the charter):
- Host-side rootfs build / workspace-copy semantics (no sandbox needed).
- Sandbox-internal filesystem boundary tests (run inside the pivot_root'd
  rootfs via run_in_sandbox(rootfs=...)) - gated on the real FILESYSTEM
  probe succeeding on this substrate (native 24.04 runner: SKIPPED with
  recorded reason; Docker uid 1001: VERIFIED DOCKER).
- Failure-mode tests: every mandatory boundary failure must REFUSE.

The distinction the charter demands: syscall success is never the proof -
the tests verify the RESULTING boundary (root identity, detached old root,
host-path absence, real workspace-copy semantics, no propagation).
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

from agent_sandbox.isolation import filesystem as fs_mod
from agent_sandbox.isolation import rootfs as rootfs_mod
from agent_sandbox.isolation import setup, syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage, StageCheck
from agent_sandbox.security import init as init_mod
from agent_sandbox.security.init import SecurityInitializer

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
    """A small project tree used as the workspace source."""
    d = tempfile.mkdtemp(prefix="as-src-")
    (pathlib.Path(d) / "marker.txt").write_text("hello-agent-sandbox\n")
    (pathlib.Path(d) / "config.yaml").write_text("key: value\n")
    (pathlib.Path(d) / "sub").mkdir()
    (pathlib.Path(d) / "sub" / "nested.txt").write_text("nested content\n")
    return d


def _run(fn, rootfs_state=None) -> str:
    run = setup.run_in_sandbox(fn, rootfs_state=rootfs_state)
    assert run.exit_code == 0, f"sandbox run failed (exit {run.exit_code}): {run.output}"
    return run.output.strip()


# ---------------------------------------------------------------------------
# Real-path capability gate (same discipline as test_namespaces.py)
# ---------------------------------------------------------------------------

_fs_status: tuple[bool, str] | None = None


def _fs_available() -> tuple[bool, str]:
    """Does THIS substrate provide the full filesystem boundary (namespaces
    + rootfs + pivot_root)? Probed once for real; a substrate that cannot
    makes the real-path tests skip with the recorded reason."""
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


class RootfsBuildTests(unittest.TestCase):
    """Host-side rootfs construction - no sandbox needed."""

    def setUp(self):
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)

    def test_layout_dirs_created(self):
        state = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, state.layout.dir, True)
        for rel in rootfs_mod.LAYOUT_DIRS.values():
            self.assertTrue(os.path.isdir(os.path.join(state.layout.dir, rel)),
                            f"layout dir {rel} missing")
        self.assertTrue(os.path.isdir(state.layout.workspace))

    def test_workspace_copy_faithful(self):
        state = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, state.layout.dir, True)
        rootfs_mod.verify_workspace_copy(self.src, state.layout.workspace)

    def test_workspace_copy_is_fresh_copy(self):
        state = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, state.layout.dir, True)
        src_st = os.stat(self.src)
        copy_st = os.stat(state.layout.workspace)
        self.assertNotEqual((src_st.st_dev, src_st.st_ino),
                            (copy_st.st_dev, copy_st.st_ino))

    def test_symlinks_preserved_in_copy(self):
        (pathlib.Path(self.src) / "link_abs").symlink_to("/etc/passwd")
        (pathlib.Path(self.src) / "link_rel").symlink_to("sub/nested.txt")
        state = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, state.layout.dir, True)
        self.assertTrue(os.path.islink(os.path.join(state.layout.workspace, "link_abs")))
        self.assertTrue(os.path.islink(os.path.join(state.layout.workspace, "link_rel")))

    def test_build_rejects_missing_source(self):
        with self.assertRaises(NamespaceSetupError) as cm:
            rootfs_mod.build_rootfs("/nonexistent/workspace-source")
        self.assertIn("not a directory", str(cm.exception))

    def test_build_rejects_file_source(self):
        f = os.path.join(self.src, "a-file.txt")
        pathlib.Path(f).write_text("x")
        with self.assertRaises(NamespaceSetupError):
            rootfs_mod.build_rootfs(f)


class WorkspaceIsolationTests(unittest.TestCase):
    """Workspace copy semantics INSIDE the sandbox (both directions)."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_workspace_available_and_readable_inside(self):
        def fn(state, fs):
            marker = pathlib.Path("/workspace/marker.txt").read_text()
            nested = pathlib.Path("/workspace/sub/nested.txt").read_text()
            return json.dumps({"marker": marker.strip(), "nested": nested.strip()})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["marker"], "hello-agent-sandbox")
        self.assertEqual(data["nested"], "nested content")

    @skip_unless_linux
    def test_sandbox_changes_do_not_modify_host_source(self):
        before = rootfs_mod.workspace_file_sets(self.src, self.src)[0]

        def fn(state, fs):
            w = pathlib.Path("/workspace")
            (w / "marker.txt").write_text("MODIFIED BY SANDBOX\n")
            (w / "created-in-sandbox.txt").write_text("new\n")
            (w / "sub" / "nested.txt").unlink()
            return "done"

        self.assertEqual(_run(fn, self.rootfs), "done")
        # Host source untouched: content unchanged, file set unchanged,
        # no sandbox-created files.
        self.assertEqual(pathlib.Path(self.src, "marker.txt").read_text(),
                         "hello-agent-sandbox\n")
        self.assertTrue(pathlib.Path(self.src, "sub", "nested.txt").exists())
        self.assertFalse(pathlib.Path(self.src, "created-in-sandbox.txt").exists())
        self.assertEqual(rootfs_mod.workspace_file_sets(self.src, self.src)[0], before)

    @skip_unless_linux
    def test_sandbox_created_files_invisible_on_host_source(self):
        def fn(state, fs):
            (pathlib.Path("/workspace") / "secret-from-sandbox.txt").write_text("x\n")
            return "created"

        self.assertEqual(_run(fn, self.rootfs), "created")
        self.assertFalse(pathlib.Path(self.src, "secret-from-sandbox.txt").exists())

    @skip_unless_linux
    def test_symlink_escapes_blocked(self):
        # Workspace symlinks aimed at host paths must not reach host
        # content: absolute, relative traversal, chains, and a self-loop.
        (pathlib.Path(self.src) / "link_abs").symlink_to("/etc/passwd")
        (pathlib.Path(self.src) / "link_esc").symlink_to("../../../../../../etc/passwd")
        (pathlib.Path(self.src) / "link_chain_a").symlink_to("link_chain_b")
        (pathlib.Path(self.src) / "link_chain_b").symlink_to("/etc/passwd")
        (pathlib.Path(self.src) / "link_loop").symlink_to("link_loop")
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

        def fn(state, fs):
            results = {}
            for name in ("link_abs", "link_esc", "link_chain_a", "link_loop"):
                p = pathlib.Path("/workspace") / name
                try:
                    with open(p, "rb") as f:
                        f.read(1)
                    results[name] = "OPENED"
                except OSError as e:
                    results[name] = f"blocked:{e.errno}"
            # The resolved lexical targets must not exist inside the rootfs
            # (no host content reachable) and /etc/passwd must be absent.
            results["etc_passwd_exists"] = os.path.lexists("/etc/passwd")
            results["realpath_abs"] = os.path.realpath("/workspace/link_abs")
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs))
        for name in ("link_abs", "link_esc", "link_chain_a", "link_loop"):
            self.assertTrue(data[name].startswith("blocked:"),
                            f"{name} must not open: {data[name]}")
        self.assertFalse(data["etc_passwd_exists"])
        self.assertEqual(data["realpath_abs"], "/etc/passwd")  # resolves in-rootfs


class PivotRootTests(unittest.TestCase):
    """The actual filesystem boundary inside the sandbox."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_pivot_root_installed(self):
        def fn(state, fs):
            st = os.stat("/")
            return json.dumps({
                "root": (st.st_dev, st.st_ino),
                "expected": list(fs.root_identity),
                "cwd": os.getcwd(),
                "up": os.path.realpath("/.."),
            })

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(tuple(data["root"]), tuple(data["expected"]),
                         "sandbox / is not the built rootfs")
        self.assertEqual(data["cwd"], "/")
        self.assertEqual(data["up"], "/")

    @skip_unless_linux
    def test_old_root_detached_host_paths_absent(self):
        def fn(state, fs):
            absent = {p: os.path.lexists(p) for p in fs_mod.MANDATORY_ABSENT_PATHS}
            placeholders = {p: os.path.isdir(p) for p in ("/usr", "/bin", "/lib", "/etc")}
            tmp_is_tmpfs = os.stat("/tmp").st_dev != os.stat("/").st_dev
            return json.dumps({"absent": absent, "placeholders": placeholders,
                               "tmp_is_tmpfs": tmp_is_tmpfs,
                               "workspace": os.path.isdir("/workspace")})

        data = json.loads(_run(fn, self.rootfs))
        for p, present in data["absent"].items():
            self.assertFalse(present, f"host path {p} reachable in sandbox")
        for p, ok in data["placeholders"].items():
            self.assertTrue(ok, f"rootfs placeholder {p} missing")
        self.assertTrue(data["tmp_is_tmpfs"])
        self.assertTrue(data["workspace"])

    @skip_unless_linux
    def test_host_source_unreachable_from_sandbox(self):
        # The ACTUAL host path of the workspace source (not a hardcoded
        # runner path) must not exist inside the sandbox, and host /tmp
        # content must not be visible either. Note: /tmp EXISTS in the
        # sandbox by design - it is the sandbox's OWN size-limited tmpfs
        # (filesystem.py), not the host directory. The meaningful
        # assertions are: (1) the exact host source path is absent,
        # (2) a host /tmp marker file is absent, (3) the sandbox /tmp is a
        # different device than the host /tmp.
        src = self.src
        host_tmp_dev = os.stat(tempfile.gettempdir()).st_dev
        host_marker = os.path.join(
            tempfile.gettempdir(), "as-host-marker-" + os.path.basename(src))
        with open(host_marker, "w", encoding="ascii") as f:
            f.write("host-only\n")
        self.addCleanup(os.unlink, host_marker)

        def fn(state, fs):
            return json.dumps({"src_exists": os.path.lexists(src),
                               "marker_exists": os.path.lexists(host_marker),
                               "sandbox_tmp_dev": os.stat("/tmp").st_dev})

        data = json.loads(_run(fn, self.rootfs))
        self.assertFalse(data["src_exists"])
        self.assertFalse(data["marker_exists"])
        self.assertNotEqual(data["sandbox_tmp_dev"], host_tmp_dev,
                            "sandbox /tmp must be its own tmpfs, not the host /tmp")

    @skip_unless_linux
    def test_mount_propagation_no_host_leak(self):
        # A mount created inside the sandbox must not propagate to the host:
        # the host mountinfo is byte-identical before/after, and the host
        # path under the rootfs tree stays on the rootfs device (no tmpfs).
        def mountinfo():
            with open("/proc/self/mountinfo", "r", encoding="ascii") as f:
                return sorted(f.read().splitlines())

        before = mountinfo()
        target_rel = "workspace/.probe-mnt"

        def fn(state, fs):
            t = pathlib.Path("/workspace/.probe-mnt")
            t.mkdir()
            syscalls.mount(b"tmpfs", str(t).encode(), b"tmpfs", 0, b"size=1m")
            (t / "marker").write_text("sandbox-mount\n")
            return json.dumps({"is_tmpfs": os.stat(str(t)).st_dev != os.stat("/workspace").st_dev,
                               "marker": (t / "marker").read_text().strip()})

        data = json.loads(_run(fn, self.rootfs))
        self.assertTrue(data["is_tmpfs"])
        self.assertEqual(data["marker"], "sandbox-mount")
        after = mountinfo()
        self.assertEqual(before, after, "sandbox mount leaked into host mount namespace")
        host_target = os.path.join(self.rootfs.layout.dir, target_rel)
        self.assertTrue(os.path.isdir(host_target))
        self.assertEqual(os.stat(host_target).st_dev,
                         os.stat(self.rootfs.layout.dir).st_dev,
                         "host-side path unexpectedly on tmpfs (mount leaked)")


class FailureModeTests(unittest.TestCase):
    """Every mandatory filesystem failure must REFUSE execution."""

    def _probe_with(self, workspace: str) -> StageCheck:
        from agent_sandbox.config import RuntimeConfig
        cfg = RuntimeConfig.from_dict(valid_config(workspace))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            return setup._filesystem_probe_impl(cfg)

    @skip_unless_linux
    def test_build_failure_refused(self):
        # No fork happens: a missing workspace source refuses up front.
        check = self._probe_with("/nonexistent/workspace-source")
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("rootfs build failed", check.reason)

    @skip_unless_linux
    def test_pivot_root_failure_refused(self):
        # Requires the full real path (namespaces + mounts) so the pivot
        # itself is reached - skipped with reason where the substrate
        # cannot provide it.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_pivot = syscalls.pivot_root

        def boom(new_root, put_old):
            raise OSError(1, "pivot_root: Operation not permitted")

        try:
            syscalls.pivot_root = boom
            check = self._probe_with(src)
        finally:
            syscalls.pivot_root = real_pivot
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("pivot_root", check.reason)

    @skip_unless_linux
    def test_old_root_detach_failure_refused(self):
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_umount2 = syscalls.umount2

        def boom(target, flags):
            raise OSError(1, "umount2: Operation not permitted")

        try:
            syscalls.umount2 = boom
            check = self._probe_with(src)
        finally:
            syscalls.umount2 = real_umount2
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("umount2", check.reason)

    @skip_unless_linux
    def test_root_identity_mismatch_refused(self):
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_verify = fs_mod._verify_root_boundary

        def broken_verify(rootfs):
            raise NamespaceSetupError("root identity mismatch (simulated)")

        try:
            fs_mod._verify_root_boundary = broken_verify
            check = self._probe_with(src)
        finally:
            fs_mod._verify_root_boundary = real_verify
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("root identity mismatch", check.reason)


class GuardAndIntegrationTests(unittest.TestCase):
    def test_filesystem_guard_registered(self):
        self.assertIs(init_mod._STAGE_GUARDS[InitStage.FILESYSTEM],
                      setup._filesystem_guard)

    @skip_unless_linux
    def test_hardened_init_refuses_at_network(self):
        # Full real path: namespaces + rootfs + pivot_root verified, then
        # HARDENED refuses at NETWORK (the next unimplemented stage).
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        from agent_sandbox.config import RuntimeConfig
        cfg = RuntimeConfig.from_dict(valid_config(src))
        result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.NETWORK)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertIn("no implementation", result.failure.reason)


if __name__ == "__main__":
    unittest.main()
