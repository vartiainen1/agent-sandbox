"""Phase 1 Step 8 tests - seccomp filter installation (REAL Linux
execution, S-011, ADR-008): the derived 45-syscall default-deny filter is
installed as the LAST Stage-A operation (after no_new_privs + capability
reduction) and verified by kernel-observable read-back (Seccomp=2,
Seccomp_filters=1) plus a forbidden-syscall spot check. Install failure,
verification failure, or unexpected state REFUSES before the workload.

Categories (kept separate, per the charter):
- Host-side BPF/allowlist/verification logic (runs everywhere).
- Sandbox-internal tests (run inside the real sandbox under the ACTUAL
  runtime filter) - gated on the real namespace probe succeeding on this
  substrate (native 24.04 runner: SKIPPED with recorded reason; Docker
  uid 1001: VERIFIED DOCKER).
- Probe + integration: the SECCOMP stage guard's real path, and the
  fail-closed chain (HARDENED refusal advances to RESOURCES).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import sys
import tempfile
import unittest
import unittest.mock

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import privileges as priv_mod
from agent_sandbox.isolation import seccomp as sc_mod
from agent_sandbox.isolation import setup
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import InitFailureCode, InitStage
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real seccomp operations require Linux with os.fork "
           "(non-Linux fail-closed behavior is covered by test_skeleton.py)")

# The 45-syscall derived allowlist (pinned - NO UNDOCUMENTED EXPANSION;
# policy.md section 5). Any change must go through the derivation process.
EXPECTED_ALLOWLIST = [
    "access", "arch_prctl", "brk", "close", "dup2", "epoll_create1",
    "execve", "exit_group", "fcntl", "fstat", "futex", "getcwd",
    "getdents64", "getegid", "geteuid", "getgid", "getpid", "getppid",
    "getrandom", "gettid", "getuid", "ioctl", "lseek", "mkdir", "mmap",
    "mprotect", "munmap", "newfstatat", "openat", "pipe2", "poll",
    "pread64", "prlimit64", "read", "readlink", "rseq", "rt_sigaction",
    "rt_sigprocmask", "rt_sigreturn", "set_robust_list", "set_tid_address",
    "unlink", "vfork", "wait4", "write",
]

STATUS_FILTERED = (
    "Name:\tpython\n"
    "Seccomp:\t2\n"
    "Seccomp_filters:\t1\n"
    "NoNewPrivs:\t1\n"
    "CapBnd:\t0000000000000000\n"
    "CapEff:\t0000000000000000\n"
)

STATUS_UNFILTERED = (
    "Name:\tpython\n"
    "Seccomp:\t0\n"
    "Seccomp_filters:\t0\n"
    "NoNewPrivs:\t1\n"
    "CapBnd:\t0000000000000000\n"
    "CapEff:\t0000000000000000\n"
)


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


# Real-path capability gates (same discipline as the other suites).
_ns_status: tuple[bool, str] | None = None


def _ns_available() -> tuple[bool, str]:
    global _ns_status
    if _ns_status is None:
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            check = setup._probe_impl()
        _ns_status = (check.ok, check.reason)
    return _ns_status


def _require_ns(self) -> None:
    ok, reason = _ns_available()
    if not ok:
        self.skipTest("namespace substrate unavailable on this host: " + reason)


_fs_status: tuple[bool, str] | None = None


def _fs_available() -> tuple[bool, str]:
    global _fs_status
    if _fs_status is None:
        with tempfile.TemporaryDirectory(prefix="as-sc-gate-") as src:
            (pathlib.Path(src) / "marker.txt").write_text("gate\n")
            cfg = RuntimeConfig.from_dict(valid_config(src))
            with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
                check = setup._filesystem_probe_impl(cfg)
        _fs_status = (check.ok, check.reason)
    return _fs_status


def _require_fs(self) -> None:
    ok, reason = _fs_available()
    if not ok:
        self.skipTest("filesystem boundary substrate unavailable on this host: " + reason)


def make_source() -> str:
    d = tempfile.mkdtemp(prefix="as-sc-src-")
    (pathlib.Path(d) / "marker.txt").write_text("hello-agent-sandbox\n")
    return d


def _run(fn, rootfs_state=None) -> str:
    run = setup.run_in_sandbox(fn, rootfs_state=rootfs_state)
    assert run.exit_code == 0, f"sandbox run failed (exit {run.exit_code}): {run.output}"
    return run.output.strip()


class SeccompHostTests(unittest.TestCase):
    """BPF/allowlist/verification logic - runs everywhere."""

    def test_allowlist_loaded_from_artifact(self):
        allow, numbers = sc_mod.load_allowlist()
        self.assertEqual(len(allow), 45)
        self.assertEqual(len(set(allow)), 45, "allowlist must be unique")
        self.assertEqual(allow, sorted(allow), "allowlist must be sorted")

    def test_allowlist_not_silently_expanded(self):
        # Pins the exact 45-syscall set - NO UNDOCUMENTED SYSCALL
        # EXPANSION (policy.md section 5). A change here requires the
        # full derivation process.
        allow, _ = sc_mod.load_allowlist()
        self.assertEqual(allow, EXPECTED_ALLOWLIST)

    def test_prctl_seccomp_constants(self):
        self.assertEqual(sc_mod.PR_SET_SECCOMP, 22)
        self.assertEqual(sc_mod.SECCOMP_MODE_FILTER, 2)
        self.assertEqual(sc_mod.SECCOMP_RET_ERRNO | 1, 0x00050001)
        self.assertEqual(sc_mod.AUDIT_ARCH_X86_64, 0xC000003E)

    def test_x86_64_table_covers_allowlist(self):
        allow, _ = sc_mod.load_allowlist()
        missing = [n for n in allow if n not in sc_mod._X86_64]
        self.assertEqual(missing, [])

    def test_build_program_layout(self):
        # Deterministic default-deny layout: arch guard first (KILL on
        # mismatch), then the JEQ allow chain, default RET_ERRNO|EPERM
        # BEFORE the trailing RET ALLOW (policy.md section 1).
        prog = sc_mod.build_program(EXPECTED_ALLOWLIST)
        self.assertEqual(len(prog), 4 + 45 + 2)
        self.assertEqual(prog[0], (0x20, 0, 0, sc_mod._OFF_ARCH))       # LD arch
        self.assertEqual(prog[1], (0x15, 1, 0, sc_mod.AUDIT_ARCH_X86_64))  # JEQ arch
        self.assertEqual(prog[2], (0x06, 0, 0, sc_mod.SECCOMP_RET_KILL_PROCESS))
        self.assertEqual(prog[3], (0x20, 0, 0, sc_mod._OFF_NR))         # LD nr
        self.assertEqual(prog[-2], (0x06, 0, 0, sc_mod.SECCOMP_RET_ERRNO | 1))
        self.assertEqual(prog[-1], (0x06, 0, 0, sc_mod.SECCOMP_RET_ALLOW))
        # Every JEQ's jump target lands exactly on the trailing ALLOW.
        for insn in prog[4:-2]:
            self.assertEqual(insn[0], 0x15, "allow checks must be JEQ")
            target = len(prog) - 1  # index of RET ALLOW
            self.assertEqual(insn[1], target - (prog.index(insn) + 1))

    def test_build_unknown_syscall_refuses(self):
        with self.assertRaises(NamespaceSetupError) as cm:
            sc_mod.build_program(["not_a_syscall"])
        self.assertIn("no", str(cm.exception).lower())
        self.assertIn("runtime table", str(cm.exception))

    def test_arch_guard_refuses_non_x86_64(self):
        with unittest.mock.patch.object(sc_mod, "_detect_arch", side_effect=NamespaceSetupError("unsupported architecture")):
            with self.assertRaises(NamespaceSetupError) as cm:
                sc_mod.build_program(EXPECTED_ALLOWLIST)
        self.assertIn("unsupported architecture", str(cm.exception))

    def test_install_failure_refuses(self):
        def boom(option, arg2, arg3, arg4, arg5):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        with unittest.mock.patch.object(sc_mod, "_prctl", boom):
            with self.assertRaises(NamespaceSetupError) as cm:
                sc_mod.install_filter(sc_mod.build_program(EXPECTED_ALLOWLIST))
        self.assertIn("cannot install seccomp filter", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_verify_state_readback_ok(self):
        with unittest.mock.patch.object(sc_mod, "_read_proc_status",
                                        return_value=STATUS_FILTERED):
            state = sc_mod.verify_seccomp_state()
        self.assertEqual(state.mode, 2)
        self.assertEqual(state.filters, 1)

    def test_verify_state_unfiltered_refuses(self):
        with unittest.mock.patch.object(sc_mod, "_read_proc_status",
                                        return_value=STATUS_UNFILTERED):
            with self.assertRaises(NamespaceSetupError) as cm:
                sc_mod.verify_seccomp_state()
        self.assertIn("Seccomp mode is 0", str(cm.exception))

    def test_verify_state_filter_count_refuses(self):
        # Zero filters = our install did not take -> refusal. (A count of
        # 2 on Docker Desktop is legitimate: the WSL2 runtime's own outer
        # filter plus ours - the mode check is the state signal.)
        fake = STATUS_FILTERED.replace("Seccomp_filters:\t1",
                                       "Seccomp_filters:\t0")
        with unittest.mock.patch.object(sc_mod, "_read_proc_status",
                                        return_value=fake):
            with self.assertRaises(NamespaceSetupError) as cm:
                sc_mod.verify_seccomp_state()
        self.assertIn("Seccomp_filters is 0", str(cm.exception))

    def test_verify_state_outer_filter_tolerated(self):
        # Docker Desktop's runtime applies its own outer filter (count 2
        # after our install) - the mode is what matters.
        fake = STATUS_FILTERED.replace("Seccomp_filters:\t1",
                                       "Seccomp_filters:\t2")
        with unittest.mock.patch.object(sc_mod, "_read_proc_status",
                                        return_value=fake):
            state = sc_mod.verify_seccomp_state()
        self.assertEqual(state.mode, 2)
        self.assertEqual(state.filters, 2)

    def test_verify_state_unreadable_refuses(self):
        def boom():
            raise sc_mod.NamespaceSetupError("cannot read /proc/self/status (simulated)")

        with unittest.mock.patch.object(sc_mod, "_read_proc_status", boom):
            with self.assertRaises(NamespaceSetupError) as cm:
                sc_mod.verify_seccomp_state()
        self.assertIn("verification failed", str(cm.exception))

    def test_check_enforcement_eperm_ok(self):
        def eperm(*a, **k):
            raise OSError(1, "Operation not permitted")

        with unittest.mock.patch.object(sc_mod.socket, "socket", eperm):
            sc_mod._check_enforcement()  # must not raise

    def test_check_enforcement_unexpected_errno_refuses(self):
        def other(*a, **k):
            raise OSError(13, "Permission denied")

        with unittest.mock.patch.object(sc_mod.socket, "socket", other):
            with self.assertRaises(NamespaceSetupError) as cm:
                sc_mod._check_enforcement()
        self.assertIn("errno 13", str(cm.exception))

    def test_check_enforcement_success_refuses(self):
        class FakeSocket:
            def close(self):
                return None

        with unittest.mock.patch.object(sc_mod.socket, "socket",
                                        return_value=FakeSocket()):
            with self.assertRaises(NamespaceSetupError) as cm:
                sc_mod._check_enforcement()
        self.assertIn("not enforcing", str(cm.exception))


class SeccompBoundaryTests(unittest.TestCase):
    """The filter INSIDE the sandbox (real Linux, under the ACTUAL
    runtime filter - this IS the behavioral probe under the project
    filter)."""

    def setUp(self):
        _require_ns(self)
        self._marker_dir = tempfile.mkdtemp(prefix="as-sc-")
        self.addCleanup(shutil.rmtree, self._marker_dir, True)

    def _status_field(self, status: str, field: str) -> int:
        prefix = field + ":"
        for line in status.splitlines():
            if line.startswith(prefix):
                return int(line.split(":", 1)[1].strip())
        return -1

    @skip_unless_linux
    def test_filter_installed_before_workload(self):
        # Kernel-observable read-back AT WORKLOAD TIME: the workload runs
        # under SECCOMP_MODE_FILTER with at least one filter active (our
        # install; Docker Desktop adds its own outer filter on top, so the
        # count there is 2 - the mode is the state signal).
        def fn(state, fs):
            st = sc_mod._read_proc_status()
            return json.dumps({
                "mode": self._status_field(st, "Seccomp"),
                "filters": self._status_field(st, "Seccomp_filters"),
            })

        data = json.loads(_run(fn, self.rootfs_state()))
        self.assertEqual(data["mode"], 2, "workload must run under "
                         "SECCOMP_MODE_FILTER")
        self.assertGreaterEqual(data["filters"], 1,
                                "at least our filter must be active")

    def rootfs_state(self):
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        state = None
        from agent_sandbox.isolation import rootfs as rootfs_mod
        state = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, state.layout.dir, True)
        return state

    @skip_unless_linux
    def test_allowed_syscalls_work_under_filter(self):
        # A legitimate workload under the filter: file writes/reads,
        # directory listing, stat - all allowlisted syscalls.
        def fn(state, fs):
            p = pathlib.Path("/workspace/seccomp-probe.txt")
            p.write_text("hello-under-filter\n")
            content = p.read_text().strip()
            entries = sorted(os.listdir("/workspace"))
            st = os.stat("/workspace")
            return json.dumps({"content": content, "entries": entries,
                               "dev": st.st_dev})

        data = json.loads(_run(fn, self.rootfs_state()))
        self.assertEqual(data["content"], "hello-under-filter")
        self.assertIn("seccomp-probe.txt", data["entries"])
        self.assertGreater(data["dev"], 0)

    @skip_unless_linux
    def test_forbidden_syscall_denied(self):
        # Representative forbidden syscalls: socket (network class) and
        # prctl (privilege class) must fail EPERM under the filter.
        # (socket is imported at module level so the loaded module is
        # inherited into PID 1 - the minimal rootfs has no stdlib.)
        def fn(state, fs):
            results = {}
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.close()
                results["socket"] = "OK"
            except OSError as e:
                results["socket"] = f"errno:{e.errno}"
            try:
                priv_mod._prctl(priv_mod.PR_GET_NO_NEW_PRIVS)
                results["prctl"] = "OK"
            except OSError as e:
                results["prctl"] = f"errno:{e.errno}"
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs_state()))
        self.assertEqual(data["socket"], "errno:1", "socket must fail EPERM")
        self.assertEqual(data["prctl"], "errno:1", "prctl must fail EPERM")

    @skip_unless_linux
    def test_forbidden_syscall_cannot_be_enabled(self):
        # The workload cannot load a different filter or alter the policy:
        # prctl(PR_SET_SECCOMP) and prctl(PR_CAPBSET_DROP) are denied
        # (prctl itself is not in the allowlist).
        def fn(state, fs):
            results = {}
            for label, option in (("seccomp", sc_mod.PR_SET_SECCOMP),
                                  ("capbset_drop", priv_mod.PR_CAPBSET_DROP)):
                try:
                    priv_mod._prctl(option, 1, 0, 0, 0)
                    results[label] = "OK"
                except OSError as e:
                    results[label] = f"errno:{e.errno}"
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs_state()))
        self.assertEqual(data["seccomp"], "errno:1")
        self.assertEqual(data["capbset_drop"], "errno:1")

    @skip_unless_linux
    def test_fork_denied_under_filter(self):
        # fork(2) is not in the allowlist: process creation is restricted
        # to the allowed vfork/execve path, whose children inherit the
        # filter (exec inheritance tested separately).
        def fn(state, fs):
            try:
                os.fork()
                return "FORK_OK"
            except OSError as e:
                return f"errno:{e.errno}"

        self.assertEqual(_run(fn, self.rootfs_state()), "errno:1",
                         "fork must fail EPERM under the filter")

    @skip_unless_linux
    def test_exec_inheritance(self):
        # The filter is inherited across execve: an exec'd helper (a fresh
        # interpreter) still gets EPERM on a forbidden syscall. Runs in
        # the namespaces-only sandbox so the interpreter path resolves.
        helper = (
            "import socket\n"
            "try:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    print('SOCKET_OK')\n"
            "except OSError as e:\n"
            "    print('SOCKET_EPERM:%d' % e.errno)\n"
        )

        def fn(state):
            os.execv(sys.executable, [sys.executable, "-c", helper])

        run = setup.run_in_sandbox(fn)
        self.assertIn("SOCKET_EPERM:1", run.output,
                      "the exec'd helper must still be under the filter")
        self.assertNotIn("SOCKET_OK", run.output)

    @skip_unless_linux
    def test_nnp_and_caps_preserved_under_filter(self):
        # Steps 6-7 invariants hold at workload time under the filter:
        # no_new_privs set, capability sets empty (read via status fields
        # - prctl itself is denied by the filter).
        def fn(state, fs):
            st = sc_mod._read_proc_status()
            return json.dumps({
                "nnp": self._status_field(st, "NoNewPrivs"),
                "capbnd": self._status_field(st, "CapBnd"),
                "capeff": self._status_field(st, "CapEff"),
            })

        data = json.loads(_run(fn, self.rootfs_state()))
        self.assertEqual(data["nnp"], 1, "no_new_privs must remain set")
        self.assertEqual(data["capbnd"], 0, "capability sets must stay empty")
        self.assertEqual(data["capeff"], 0)

    @skip_unless_linux
    def test_workload_not_executed_on_install_failure(self):
        marker = str(pathlib.Path(self._marker_dir) / "ran-sc.txt")

        def boom(option, arg2, arg3, arg4, arg5):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        def fn(state, fs):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        with unittest.mock.patch.object(sc_mod, "_prctl", boom):
            run = setup.run_in_sandbox(fn, self.rootfs_state())
        self.assertNotEqual(run.exit_code, 0)
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertFalse(os.path.exists(marker),
                         "workload executed despite seccomp install failure")
        self.assertIn("cannot install seccomp filter", run.output)

    @skip_unless_linux
    def test_workload_not_executed_on_verify_failure(self):
        marker = str(pathlib.Path(self._marker_dir) / "ran-sc-verify.txt")

        def fn(state, fs):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        with unittest.mock.patch.object(sc_mod, "_read_proc_status",
                                        return_value=STATUS_UNFILTERED):
            run = setup.run_in_sandbox(fn, self.rootfs_state())
        self.assertNotEqual(run.exit_code, 0)
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertFalse(os.path.exists(marker))
        self.assertIn("Seccomp mode is 0", run.output)

    @skip_unless_linux
    def test_unexpected_seccomp_state_refuses(self):
        # SECCOMP_MODE_STRICT (1) is an unexpected state -> refusal; the
        # workload never runs on an unverified seccomp state.
        marker = str(pathlib.Path(self._marker_dir) / "ran-sc-state.txt")
        fake = STATUS_FILTERED.replace("Seccomp:\t2", "Seccomp:\t1")

        def fn(state, fs):
            pathlib.Path(marker).write_text("ran\n")
            return "WORKLOAD RAN"

        with unittest.mock.patch.object(sc_mod, "_read_proc_status",
                                        return_value=fake):
            run = setup.run_in_sandbox(fn, self.rootfs_state())
        self.assertNotEqual(run.exit_code, 0)
        self.assertNotIn("WORKLOAD RAN", run.output)
        self.assertFalse(os.path.exists(marker))
        self.assertIn("Seccomp mode is 1", run.output)


class SeccompProbeTests(unittest.TestCase):
    @skip_unless_linux
    def test_seccomp_probe_ok(self):
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-sc-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))
        check = setup._seccomp_probe_impl(cfg)
        self.assertTrue(check.ok, check.reason)
        self.assertIn("45-syscall default-deny", check.reason)
        self.assertIn("EPERM", check.reason)

    @skip_unless_linux
    def test_seccomp_probe_install_failure_refuses(self):
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-sc-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))

        def boom(option, arg2, arg3, arg4, arg5):
            raise OSError(1, "prctl: Operation not permitted (simulated)")

        with unittest.mock.patch.object(sc_mod, "_prctl", boom):
            check = setup._seccomp_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cannot install seccomp filter", check.reason)

    @skip_unless_linux
    def test_seccomp_probe_verify_failure_refuses(self):
        _require_ns(self)
        src = tempfile.mkdtemp(prefix="as-sc-ws-")
        self.addCleanup(shutil.rmtree, src, True)
        cfg = RuntimeConfig.from_dict(valid_config(src))
        with unittest.mock.patch.object(sc_mod, "_read_proc_status",
                                        return_value=STATUS_UNFILTERED):
            check = setup._seccomp_probe_impl(cfg)
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("Seccomp mode is 0", check.reason)

    def test_seccomp_guard_registered(self):
        self.assertIs(init_mod._STAGE_GUARDS[InitStage.SECCOMP],
                      setup._seccomp_guard)


class IntegrationTests(unittest.TestCase):
    @skip_unless_linux
    def test_hardened_refuses_at_resources_after_real_chain(self):
        # Full real path: all mechanism probes through RESOURCES run
        # (namespaces, filesystem, network, privileges, seccomp, rlimits);
        # HARDENED then refuses AT RESOURCES because cgroup v2 delegation
        # is unavailable on this substrate (Docker rootless: cgroupfs
        # read-only) - the refusal point stays at RESOURCES, fail closed.
        # On a delegation-capable host this probe would pass and the
        # chain completes through ENVIRONMENT (Steps 11-12) and
        # EXECUTION (Steps 13-15) to READY (asserted by the
        # privileged-substrate tests in test_cgroups.py); the premise -
        # refusal without delegation - is absent there and the test skips
        # with the recorded reason.
        from tests.unit import require_delegation_unavailable
        require_delegation_unavailable(self)
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.RESOURCES)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_FAILED)
        self.assertIn("cgroup", result.failure.reason)
        self.assertIn("fail closed", result.failure.reason)


if __name__ == "__main__":
    unittest.main()
