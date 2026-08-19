"""Phase 1 Step 2 namespace isolation tests - REAL Linux tests.

These execute actual namespace operations in forked children (the
supervisor/test process never enters the namespaces - ARCHITECTURE.md
section 6). They run natively on ubuntu CI (AUTHORITATIVE) and inside the
Docker derivation container as a non-root user (CONTAINER-VALIDATED only;
never labeled native).

On a non-Linux host they SKIP with an explicit reason - the fail-closed
behavior for non-Linux (refusal at the platform stage) is covered by
tests/unit/test_skeleton.py instead. The wiring tests that must run on
every host (guard failure -> initializer refusal) live in test_skeleton.py
with the probe outcome injected; here the REAL probe and REAL syscalls are
exercised.

Validation categories (per the Phase 1 Step 2 charter):
    VERIFIED NATIVE  - namespace tests passing on ubuntu CI
    VERIFIED DOCKER  - same tests passing as non-root in the Docker container
    NOT VERIFIED     - anything not exercised by either (reported, not claimed)
"""

from __future__ import annotations

import errno
import json
import os
import sys
import tempfile
import unittest
import unittest.mock

from agent_sandbox.isolation import namespaces, setup, syscalls, userns
from agent_sandbox.models import InitFailureCode, InitStage, StageCheck
from agent_sandbox.security import init as init_mod
from agent_sandbox.security.init import SecurityInitializer

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real namespace operations require Linux with os.fork "
           "(non-Linux fail-closed behavior is covered by test_skeleton.py)")

# Real-path capability gate: whether THIS substrate can establish the full
# rootless namespace boundary (user ns + uid 0 -> caller mapping + the rest).
# Some substrates allow unshare(CLONE_NEWUSER) but block the mapping write
# (e.g. the GitHub ubuntu-24.04 runner's AppArmor userns restriction denies
# the setgroups-deny write with EACCES). For those, the real-path tests
# SKIP with the recorded reason - never a fail-as-bug, never a
# pass-as-verified. The fail-closed refusal itself is still verified (the
# guard refuses when the mechanism is unavailable), and the Docker container
# (uid 1001) provides the VERIFIED DOCKER execution evidence.
_rootless_status: tuple[bool, str] | None = None


def _rootless_available() -> tuple[bool, str]:
    global _rootless_status
    if _rootless_status is None:
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            check = setup.namespace_probe()
        _rootless_status = (check.ok, check.reason)
    return _rootless_status


def _require_rootless(self) -> None:
    ok, reason = _rootless_available()
    if not ok:
        self.skipTest(
            "rootless namespace substrate unavailable on this host: " + reason)


def valid_config(mode: str = "hardened") -> dict:
    return {
        "mode": mode,
        "workspace": "/srv/agent-workspace",
        "resources": {
            "cpu_seconds": 300, "memory_mb": 4096, "disk_mb": 10240,
            "processes": 256, "open_files": 4096, "output_mb": 50,
            "wall_time_seconds": 900,
        },
    }


def _run(fn) -> str:
    """Run fn inside the namespace boundary; assert it succeeded."""
    run = setup.run_in_sandbox(fn)
    assert run.exit_code == 0, f"sandbox run failed (exit {run.exit_code}): {run.output}"
    return run.output.strip()


def _proc_net_ifaces() -> set[str]:
    """Interface names from /proc/net/dev. This is the authoritative,
    per-reader-network-namespace source: /sys/class/net reflects the sysfs
    mount's netns, not the reader's (observed in the Docker container), so
    it cannot prove interface isolation. /proc/net/dev always reflects the
    reader's current netns."""
    ifaces: set[str] = set()
    try:
        with open("/proc/net/dev", "r", encoding="ascii") as f:
            for line in f.read().splitlines()[2:]:
                name = line.split(":")[0].strip()
                if name:
                    ifaces.add(name)
    except OSError:
        pass
    return ifaces


def _mountinfo() -> list[str]:
    with open("/proc/self/mountinfo", "r", encoding="ascii") as f:
        return sorted(f.read().splitlines())


class NamespaceCreationTests(unittest.TestCase):
    def setUp(self):
        _require_rootless(self)

    @skip_unless_linux
    def test_user_namespace_creation(self):
        host_user = namespaces.ns_identity()["user"]

        def fn(state):
            return namespaces.ns_identity()["user"]

        self.assertNotEqual(_run(fn), host_user)

    @skip_unless_linux
    def test_uid_mapping(self):
        caller_uid = os.getuid()

        def fn(state):
            return json.dumps({"uid_map": state.userns.uid_map,
                               "caller_uid": state.userns.caller_uid})

        data = json.loads(_run(fn))
        self.assertEqual(data["uid_map"], f"0 {caller_uid} 1")
        self.assertEqual(data["caller_uid"], caller_uid)

    @skip_unless_linux
    def test_gid_mapping(self):
        caller_gid = os.getgid()

        def fn(state):
            return json.dumps({"gid_map": state.userns.gid_map,
                               "caller_gid": state.userns.caller_gid})

        data = json.loads(_run(fn))
        self.assertEqual(data["gid_map"], f"0 {caller_gid} 1")
        self.assertEqual(data["caller_gid"], caller_gid)

    @skip_unless_linux
    def test_setgroups_denied(self):
        def fn(state):
            return state.userns.setgroups

        self.assertEqual(_run(fn), "deny")

    @skip_unless_linux
    def test_host_caller_remains_unprivileged(self):
        # The expected relationship (charter): host unprivileged caller,
        # sandbox-side mapped uid 0. Requires a non-root caller (CI runner
        # uid 1001, Docker -u 1001). A root caller cannot demonstrate this
        # and must not silently pass.
        self.assertNotEqual(
            os.geteuid(), 0,
            "requires a non-root caller to demonstrate host-unprivileged "
            "execution (native CI / Docker run as uid 1001)")

        def fn(state):
            return json.dumps({"uid": state.userns.sandbox_uid,
                               "gid": state.userns.sandbox_gid})

        data = json.loads(_run(fn))
        self.assertEqual((data["uid"], data["gid"]), (0, 0))

    @skip_unless_linux
    def test_sandbox_identity_is_expected(self):
        def fn(state):
            return json.dumps({"uid": syscalls.getuid(), "gid": syscalls.getgid()})

        data = json.loads(_run(fn))
        self.assertEqual((data["uid"], data["gid"]), (0, 0))

    @skip_unless_linux
    def test_pid_namespace_creation(self):
        host_pid_ns = namespaces.ns_identity()["pid"]

        def fn(state):
            return json.dumps({"pid_ns": namespaces.ns_identity()["pid"],
                               "raw_pid": syscalls.getpid()})

        data = json.loads(_run(fn))
        # The fn process IS the first process of the new PID namespace
        # (documented PID semantics: unshare caller -> fork -> PID 1).
        self.assertNotEqual(data["pid_ns"], host_pid_ns)
        self.assertEqual(data["raw_pid"], 1)

    @skip_unless_linux
    def test_host_process_invisibility(self):
        # Kernel-enforced: only the sandbox's own processes exist in the new
        # PID namespace. The host/test-process pid and nearby pids must not
        # resolve to anything (kill(pid, 0) -> ESRCH). Edge case: when the
        # test process IS pid 1 (as in a container), its own pid is
        # legitimately visible because the fn process itself is sandbox
        # PID 1 - the assertion tolerates exactly that one pid.
        host_pid = os.getpid()

        def fn(state):
            visible = []
            for pid in (host_pid, host_pid + 1, host_pid + 2):
                try:
                    os.kill(pid, 0)
                    visible.append(pid)
                except ProcessLookupError:
                    pass
            legit_self = {1}  # sandbox PID 1 = the fn process itself
            if set(visible) <= legit_self:
                return "HOST_PROCESS_INVISIBLE"
            return f"HOST_PROCESS_VISIBLE:{sorted(visible)}"

        self.assertEqual(_run(fn), "HOST_PROCESS_INVISIBLE")

    @skip_unless_linux
    def test_mount_namespace_creation(self):
        host_mnt = namespaces.ns_identity()["mnt"]

        def fn(state):
            return namespaces.ns_identity()["mnt"]

        self.assertNotEqual(_run(fn), host_mnt)

    @skip_unless_linux
    def test_host_mount_namespace_unchanged(self):
        # A tmpfs mounted inside the sandbox's mount namespace must NOT
        # appear in the host mount namespace (mount propagation does not
        # cross the new private mount ns).
        before = _mountinfo()

        def fn(state):
            d = tempfile.mkdtemp(prefix="as-mnt-", dir="/tmp")
            try:
                syscalls.mount(b"tmpfs", d.encode(), b"tmpfs", 0)
                with open(os.path.join(d, "marker"), "w", encoding="ascii") as f:
                    f.write("sandbox-only")
                visible_inside = any(
                    "tmpfs" in line and d in line for line in _mountinfo())
                syscalls.umount2(d.encode())
                return json.dumps({"dir": d, "visible_inside": visible_inside})
            finally:
                if os.path.exists(d):
                    os.rmdir(d)

        data = json.loads(_run(fn))
        self.assertTrue(data["visible_inside"])
        after = _mountinfo()
        self.assertEqual(before, after)  # host mount namespace unchanged
        self.assertNotIn(data["dir"], after)  # no leak of the sandbox mount

    @skip_unless_linux
    def test_network_namespace_creation(self):
        host_net = namespaces.ns_identity()["net"]

        def fn(state):
            return namespaces.ns_identity()["net"]

        self.assertNotEqual(_run(fn), host_net)

    @skip_unless_linux
    def test_no_host_network_interfaces(self):
        host_ifaces = _proc_net_ifaces()
        self.assertGreater(
            len(host_ifaces), 1,
            "test host should expose real interfaces (lo + at least one "
            "host/container interface) for the comparison to be meaningful")

        def fn(state):
            with open("/proc/net/route", "r", encoding="ascii") as f:
                routes = f.read().strip()
            return json.dumps({"ifaces": sorted(_proc_net_ifaces()),
                               "routes": routes})

        data = json.loads(_run(fn))
        # A fresh network namespace has only loopback (down) and no routes -
        # host interfaces are not inherited (deny-by-construction foundation).
        self.assertEqual(data["ifaces"], ["lo"])
        self.assertEqual(data["routes"], "")

    @skip_unless_linux
    def test_combined_namespace_setup(self):
        host_ns = namespaces.ns_identity()

        def fn(state):
            sbx = namespaces.ns_identity()
            return json.dumps({"ns": sbx, "uid": syscalls.getuid(),
                               "gid": syscalls.getgid(), "pid": syscalls.getpid()})

        data = json.loads(_run(fn))
        for name in namespaces.NS_NAMES:
            self.assertNotEqual(
                data["ns"][name], host_ns[name],
                f"{name} namespace must be distinct from host in the "
                "combined setup")
        self.assertEqual((data["uid"], data["gid"]), (0, 0))
        self.assertEqual(data["pid"], 1)


class FailureModeTests(unittest.TestCase):
    """Failure-mode tests on the REAL probe path (Linux only): a failed or
    unverifiable namespace setup must become a refusal with an explicit
    reason - never a silent continue.

    The two tests that patch unshare(CLONE_NEWUSER) itself (EPERM) fail
    before any mapping write, so they run on ANY Linux substrate. The two
    that need a working mapping path (tampered read-back / tampered ns
    state) are gated on substrate capability like the creation tests."""

    def _refused_check(self, expected_reason_part: str) -> StageCheck:
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            check = setup.namespace_probe()
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn(expected_reason_part, check.reason)
        return check

    @skip_unless_linux
    def test_namespace_setup_failure_refuses_execution(self):
        def boom(flags):
            raise OSError(errno.EPERM, "unshare: Operation not permitted")

        real_unshare = syscalls.unshare
        try:
            syscalls.unshare = boom
            self._refused_check("Operation not permitted")
        finally:
            syscalls.unshare = real_unshare

    @skip_unless_linux
    def test_namespace_setup_failure_blocks_initializer(self):
        def boom(flags):
            raise OSError(errno.EPERM, "unshare: Operation not permitted")

        real_unshare = syscalls.unshare
        try:
            syscalls.unshare = boom
            with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
                result = SecurityInitializer(_config("hardened")).initialize()
        finally:
            syscalls.unshare = real_unshare
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.NAMESPACES)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("Operation not permitted", result.failure.reason)

    @skip_unless_linux
    def test_incorrect_uid_gid_mapping_refused(self):
        # Tamper the read-back mapping on the REAL path: the userns entry
        # and mapping writes genuinely happen; the verification must detect
        # the unexpected read-back and refuse - never continue with an
        # identity it did not confirm. Requires a substrate where the
        # mapping path itself is available.
        _require_rootless(self)
        real_read = userns._read_proc

        def tampered(path):
            if path.endswith("uid_map"):
                return "0 99999 1"
            return real_read(path)

        with unittest.mock.patch.object(userns, "_read_proc", tampered):
            self._refused_check("mapping mismatch")

    @skip_unless_linux
    def test_unexpected_namespace_state_refused(self):
        # Simulate "the namespace was not actually created": the verifier
        # must detect non-distinct namespaces and refuse. Requires a
        # substrate where the mapping path itself is available.
        _require_rootless(self)
        host = namespaces.ns_identity()
        with unittest.mock.patch.object(namespaces, "ns_identity", return_value=host):
            self._refused_check("not distinct from host")


class ProbeIntegrationTests(unittest.TestCase):
    @skip_unless_linux
    def test_namespace_probe_ok_and_hardened_refuses_at_seccomp(self):
        # The real probes establish the full namespace boundary AND the
        # filesystem boundary (real rootfs + pivot_root, built from a real
        # workspace); HARDENED then refuses at the NEXT unimplemented stage
        # (SECCOMP) - the fail-closed chain works end to end. Skipped
        # (with reason) on a substrate that cannot provide the mapping.
        _require_rootless(self)
        check = setup.namespace_probe()
        self.assertTrue(check.ok, check.reason)
        with tempfile.TemporaryDirectory(prefix="as-ns-ws-") as ws:
            cfg = _config("hardened", workspace=ws)
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.SECCOMP)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertIn("no implementation", result.failure.reason)

    @skip_unless_linux
    def test_combined_run_verifies_all_namespaces_in_one_child(self):
        # run_in_sandbox: one child establishes the full boundary and the
        # PID-1 grandchild reports the combined view (all six distinct,
        # identity (0,0), raw pid 1).
        _require_rootless(self)
        host_ns = namespaces.ns_identity()

        def fn(state):
            sbx = namespaces.ns_identity()
            return json.dumps({"ns": sbx, "uid": syscalls.getuid(),
                               "gid": syscalls.getgid(), "pid": syscalls.getpid()})

        data = json.loads(_run(fn))
        for name in namespaces.NS_NAMES:
            self.assertNotEqual(data["ns"][name], host_ns[name])
        self.assertEqual((data["uid"], data["gid"]), (0, 0))
        self.assertEqual(data["pid"], 1)

    def test_namespaces_guard_registered(self):
        # The NAMESPACES stage guard is the real probe - registered by
        # isolation/setup at import (visible on every platform).
        self.assertIs(init_mod._STAGE_GUARDS[InitStage.NAMESPACES],
                      setup._namespaces_guard)

    @unittest.skipIf(LINUX, "only meaningful on a non-Linux host")
    def test_probe_refuses_platform_unsupported_off_linux(self):
        check = setup.namespace_probe()
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.PLATFORM_UNSUPPORTED)
        self.assertIn("fail closed", check.reason)


def _config(mode: str, workspace: str = "/srv/agent-workspace"):
    from agent_sandbox.config import RuntimeConfig
    cfg = valid_config(mode=mode)
    cfg["workspace"] = workspace
    return RuntimeConfig.from_dict(cfg)


if __name__ == "__main__":
    unittest.main()
