"""ADR-005 curated toolchain layer tests.

Categories:
- Provisioning fail-closed shape (runs everywhere - the refusal happens
  BEFORE any mount): missing dir / missing layer / missing target.
- Mount sequence (runs everywhere - syscalls.mount is mocked): every
  layer is bound then remounted read-only (the RO remount is the
  mechanism), and no mounts happen when the toolchain is unset.
- Read-only verification (pure logic on fake mountinfo): the interpreter
  must be present and every layer must be a read-only mount.
- Build integrity (Linux + dpkg only): build_toolchain.build() produces
  a tree with python3, the merged-usr symlinks, /etc and a MANIFEST.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import types
import unittest
import unittest.mock

from agent_sandbox.isolation import filesystem as fs_mod
from agent_sandbox.isolation import syscalls
from agent_sandbox.isolation.errors import NamespaceSetupError

LINUX = sys.platform.startswith("linux")


def _layout(dirpath: str):
    """Minimal RootfsLayout stand-in: only .dir is used by the toolchain
    provisioning."""
    return types.SimpleNamespace(dir=dirpath)


def _make_toolchain(root: str) -> None:
    """A valid curated toolchain tree (merged-usr layout)."""
    for d in ("usr/bin", "usr/lib", "usr/lib64", "etc"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    with open(os.path.join(root, "usr/bin/python3"), "w") as f:
        f.write("#!/bin/sh\necho ok\n")
    os.chmod(os.path.join(root, "usr/bin/python3"), 0o755)
    for link, target in (("bin", "usr/bin"), ("lib", "usr/lib"),
                         ("lib64", "usr/lib64")):
        os.symlink(target, os.path.join(root, link))


def _make_layout(root: str) -> None:
    for d in ("usr", "bin", "lib", "etc"):
        os.makedirs(os.path.join(root, d), exist_ok=True)


class ToolchainProvisionTests(unittest.TestCase):
    """Fail-closed shape of the toolchain provisioning."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="as-tc-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.layout = _layout(os.path.join(self.tmp, "rootfs"))
        os.makedirs(self.layout.dir, exist_ok=True)

    def test_unset_toolchain_is_noop(self):
        calls = []
        with unittest.mock.patch.object(syscalls, "mount",
                                        side_effect=lambda *a, **k: calls.append(a)):
            fs_mod._provision_toolchain(self.layout, None)
        self.assertEqual(calls, [], "unset toolchain must not mount anything")

    def test_missing_dir_refuses(self):
        with self.assertRaises(NamespaceSetupError) as cm:
            fs_mod._provision_toolchain(self.layout, "/nonexistent/toolchain")
        self.assertIn("is not accessible", str(cm.exception))

    def test_non_dir_refuses(self):
        f = os.path.join(self.tmp, "tc-file")
        open(f, "w").close()
        with self.assertRaises(NamespaceSetupError) as cm:
            fs_mod._provision_toolchain(self.layout, f)
        self.assertIn("is not a directory", str(cm.exception))

    def test_missing_usr_layer_refuses(self):
        tc = os.path.join(self.tmp, "tc")
        os.makedirs(tc)
        with self.assertRaises(NamespaceSetupError) as cm:
            fs_mod._provision_toolchain(self.layout, tc)
        self.assertIn("usr/ layer is not accessible", str(cm.exception))

    def test_missing_layer_refuses(self):
        _make_layout(self.layout.dir)
        tc = os.path.join(self.tmp, "tc")
        os.makedirs(os.path.join(tc, "usr"))
        with unittest.mock.patch.object(syscalls, "mount",
                                        side_effect=lambda *a, **k: None):
            with self.assertRaises(NamespaceSetupError) as cm:
                fs_mod._provision_toolchain(self.layout, tc)
        self.assertIn("missing layer bin", str(cm.exception))

    def test_missing_rootfs_target_refuses(self):
        tc = os.path.join(self.tmp, "tc")
        _make_toolchain(tc)
        with self.assertRaises(NamespaceSetupError) as cm:
            fs_mod._provision_toolchain(self.layout, tc)
        self.assertIn("has no usr/ mount target", str(cm.exception))


class ToolchainMountSequenceTests(unittest.TestCase):
    """Every layer is bound then remounted read-only; the RO remount is
    the mechanism, verified from the exact syscall sequence."""

    def test_all_layers_bound_then_remounted_ro(self):
        tmp = tempfile.mkdtemp(prefix="as-tcm-")
        self.addCleanup(shutil.rmtree, tmp, True)
        tc = os.path.join(tmp, "tc")
        _make_toolchain(tc)
        layout = _layout(os.path.join(tmp, "rootfs"))
        _make_layout(layout.dir)

        calls: list[tuple] = []
        with unittest.mock.patch.object(
                syscalls, "mount",
                side_effect=lambda *a, **k: calls.append(a)):
            fs_mod._provision_toolchain(layout, tc)

        by_layer: dict[str, list[tuple]] = {}
        for call in calls:
            src, target, _ftype, flags, _data = call
            name = os.path.basename(target).decode()
            by_layer.setdefault(name, []).append((src, flags))
        self.assertEqual(sorted(by_layer), ["bin", "etc", "lib", "lib64",
                                            "usr"])
        for name, ops in by_layer.items():
            self.assertEqual(len(ops), 2, f"{name}: expected bind+RO")
            bind, remount = ops
            self.assertEqual(bind[0], os.path.join(tc, name).encode(),
                             f"{name}: bind source must be the toolchain layer")
            self.assertTrue(bind[1] & syscalls.MS_BIND,
                            f"{name}: first op must be the bind")
            self.assertTrue(remount[1] & syscalls.MS_REMOUNT,
                            f"{name}: second op must be the RO remount")
            self.assertTrue(remount[1] & syscalls.MS_RDONLY,
                            f"{name}: remount must set MS_RDONLY")
            self.assertTrue(remount[1] & syscalls.MS_BIND,
                            f"{name}: RO remount must be the bind remount")
        # lib64 target is created if absent (the rootfs layout has no dir).
        self.assertTrue(os.path.isdir(os.path.join(layout.dir, "lib64")))


class ToolchainVerificationTests(unittest.TestCase):
    """_toolchain_problems: interpreter present + every layer RO; empty =
    OK; any deviation fails closed."""

    def _infos(self, layers, ro=True):
        out = []
        for name in layers:
            opts = "rw,relatime" if not ro else "ro,relatime"
            out.append({"mount_point": f"/{name}", "fstype": "ext4",
                        "mount_options": opts, "super_options": ""})
        return out

    def test_ok_when_interpreter_and_all_ro(self):
        infos = self._infos(fs_mod.TOOLCHAIN_LAYERS)
        self.assertEqual(fs_mod._toolchain_problems(infos, True), [])

    def test_missing_interpreter_refuses(self):
        infos = self._infos(fs_mod.TOOLCHAIN_LAYERS)
        problems = fs_mod._toolchain_problems(infos, False)
        self.assertTrue(any("python3" in p for p in problems))

    def test_writable_layer_refuses(self):
        infos = self._infos(fs_mod.TOOLCHAIN_LAYERS, ro=False)
        problems = fs_mod._toolchain_problems(infos, True)
        self.assertTrue(any("not read-only" in p for p in problems))

    def test_missing_mount_refuses(self):
        infos = self._infos(fs_mod.TOOLCHAIN_LAYERS[:-1])
        problems = fs_mod._toolchain_problems(infos, True)
        self.assertTrue(any("not a mount point" in p for p in problems))


@unittest.skipUnless(LINUX, "build integrity requires Linux (dpkg/ldd)")
class ToolchainBuildIntegrityTests(unittest.TestCase):
    """build_toolchain.build() produces a usable artifact - or skips with
    the precise reason when the build host lacks the declared packages."""

    def test_build_produces_artifact(self):
        try:
            import tools.toolchain.build_toolchain as bt  # type: ignore
        except ImportError:
            self.skipTest("build_toolchain module not importable here")
        try:
            bt._run(["dpkg", "--version"])
            bt._run(["ldd", "--version"])
        except Exception as e:  # noqa: BLE001 - environment reason
            self.skipTest(f"dpkg/ldd unavailable: {e}")
        tmp = tempfile.mkdtemp(prefix="as-tcb-")
        self.addCleanup(shutil.rmtree, tmp, True)
        out = os.path.join(tmp, "toolchain")
        try:
            bt.build(out)
        except bt.BuildError as e:
            self.skipTest(f"build host lacks declared packages: {e}")
        self.assertTrue(os.path.isfile(os.path.join(out, "usr/bin/python3")),
                        "python3 must be in the artifact")
        for link, target in (("bin", "usr/bin"), ("lib", "usr/lib")):
            self.assertTrue(os.path.islink(os.path.join(out, link)),
                            f"{link} must be a merged-usr symlink")
            self.assertEqual(os.readlink(os.path.join(out, link)), target)
        # lib64 is a REAL directory by documented design (build_toolchain
        # docstring): the dynamic loader must be reachable at
        # /lib64/ld-linux-*.so.2 (the kernel loads it from there), so
        # lib64 cannot be a merged-usr symlink to usr/lib64.
        lib64 = os.path.join(out, "lib64")
        self.assertTrue(os.path.isdir(lib64) and not os.path.islink(lib64),
                        "lib64 must be a real directory (loader host)")
        self.assertTrue(
            any(name.startswith("ld-linux")
                for name in os.listdir(lib64)),
            "lib64 must hold the dynamic loader (ld-linux-*)")
        self.assertTrue(os.path.isfile(os.path.join(out, "etc/passwd")))
        self.assertTrue(os.path.isfile(os.path.join(out, "MANIFEST")))


if __name__ == "__main__":
    unittest.main()
