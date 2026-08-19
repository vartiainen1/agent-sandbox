"""Phase 1 Step 5 tests - network namespace deny-by-construction (REAL
Linux execution): only loopback, lo DOWN, no addresses, no usable routes,
no host interfaces, no path out; the workload cannot gain any usable
network path; unexpected state must REFUSE.

Categories (kept separate, per the charter):
- Host-side parsing/verification logic (runs everywhere).
- Sandbox-internal boundary tests (run inside the real sandbox via
  run_in_sandbox(rootfs=...)) - gated on the real FILESYSTEM probe
  succeeding on this substrate (native 24.04 runner: SKIPPED with
  recorded reason; Docker uid 1001: VERIFIED DOCKER).
- Failure-mode tests: every unexpected network state must REFUSE.

Empirical facts this suite pins (Step 5 probe, container):
- The fresh netns is deny-by-construction: only lo (DOWN, no addresses),
  no IPv4 routes, no host interfaces; connect() -> ENETUNREACH.
- Since Step 7 (capability reduction, PRIVILEGES stage), the workload
  CANNOT toggle lo: CAP_NET_ADMIN is removed from the sandbox's
  effective/permitted sets and bounding set, so the ioctl lo-up attempt
  FAILS (EPERM) and lo stays DOWN - the Step 5 documented residual
  ("workload can toggle its own lo via ns-local CAP_NET_ADMIN until Step
  12") is RESOLVED here. The suite asserts the attempt fails and the
  deny-by-construction state holds (no usable path, no host escape);
  seccomp (Step 13) remains outstanding for the syscall layer.
- The workload cannot reach the host netns (no host pid visible -> no
  host ns fd path; setns/iface-move need initial-userns privileges).
- Netlink route/iface mutations returned EOPNOTSUPP in the validation
  environment even as root+CAP_NET_ADMIN - a Docker-Desktop/WSL2 artifact,
  NOT the security mechanism; the tests therefore assert the structural
  property (no usable path), not the environment's EOPNOTSUPP.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import struct
import sys
import tempfile
import types
import unittest
import unittest.mock

try:
    import fcntl  # Linux-only; the sandbox tests never run on Windows
except ImportError:  # pragma: no cover
    fcntl = None

from agent_sandbox.isolation import network as net_mod
from agent_sandbox.isolation import rootfs as rootfs_mod
from agent_sandbox.isolation import setup
from agent_sandbox.models import InitFailureCode
from agent_sandbox.security import init as init_mod

LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")

skip_unless_linux = unittest.skipUnless(
    LINUX, "real network namespace operations require Linux with os.fork "
           "(non-Linux fail-closed behavior is covered by test_skeleton.py)")

IFF_UP = 0x1
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914


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


# Real-path capability gate (same discipline as the other suites).
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


def _lo_flags_inside() -> int:
    """ioctl SIOCGIFFLAGS on lo (runs inside the sandbox)."""
    assert fcntl is not None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH", b"lo", 0)
        return struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
    finally:
        s.close()


def _bring_lo_up_inside() -> str:
    """Attempt to bring lo UP from inside the sandbox (ioctl). Returns
    'OK' or 'errno:N'. Since Step 7 (capability reduction) the attempt
    FAILS (EPERM - no CAP_NET_ADMIN); before Step 7 it succeeded
    (ns-local CAP_NET_ADMIN) with localhost-only effect. The tests assert
    the current, stronger behavior."""
    assert fcntl is not None
    try:
        flags = _lo_flags_inside()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH", b"lo", flags | IFF_UP))
        finally:
            s.close()
        return "OK"
    except OSError as e:
        return f"errno:{e.errno}"


def _try_connect_inside(host: str, port: int) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        return "OK"
    except OSError as e:
        return f"errno:{e.errno}"
    finally:
        s.close()


class ParsingTests(unittest.TestCase):
    """Host-side parsing logic - runs everywhere (no sandbox needed)."""

    def test_parse_dev_names(self):
        dev = ("Inter-|   Receive                                                |  Transmit\n"
               " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
               "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n")
        self.assertEqual(net_mod._parse_dev_names(dev), ["lo"])

    def test_parse_dev_names_empty(self):
        self.assertEqual(net_mod._parse_dev_names(""), [])

    def test_parse_route_devices(self):
        ipv6 = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n")
        self.assertEqual(net_mod._parse_route_devices(ipv6), ["lo"])

    def test_parse_fib_trie_addresses(self):
        trie = ("Main:\n"
                "  +-- 127.0.0.0/8 2 0 2\n"
                "     |-- 127.0.0.1\n"
                "        /32 host LOCAL\n")
        self.assertEqual(net_mod._parse_fib_trie_addresses(trie), ["127.0.0.1"])
        self.assertEqual(net_mod._parse_fib_trie_addresses(""), [])

    def test_parse_if_inet6_addresses(self):
        self.assertEqual(
            net_mod._parse_if_inet6_addresses(
                "00000000000000000000000000000001 01 80 10 80       lo\n"),
            ["00000000000000000000000000000001"])
        self.assertEqual(net_mod._parse_if_inet6_addresses(""), [])


class NetworkBoundaryTests(unittest.TestCase):
    """The deny-by-construction state INSIDE the sandbox (real Linux)."""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_loopback_is_down(self):
        def fn(state, fs):
            return json.dumps({"flags": _lo_flags_inside(),
                               "up": bool(_lo_flags_inside() & IFF_UP)})

        data = json.loads(_run(fn, self.rootfs))
        self.assertFalse(data["up"], f"lo must be DOWN (flags {data['flags']})")

    @skip_unless_linux
    def test_no_non_loopback_interfaces(self):
        def fn(state, fs):
            return net_mod._parse_dev_names(net_mod._read_proc_net("dev"))

        self.assertEqual(_run(fn, self.rootfs), "['lo']")

    @skip_unless_linux
    def test_no_ipv4_addresses(self):
        def fn(state, fs):
            return json.dumps(net_mod._parse_fib_trie_addresses(
                net_mod._read_proc_net("fib_trie")))

        self.assertEqual(_run(fn, self.rootfs), "[]")

    @skip_unless_linux
    def test_no_ipv6_addresses(self):
        def fn(state, fs):
            return json.dumps(net_mod._parse_if_inet6_addresses(
                net_mod._read_proc_net("if_inet6")))

        self.assertEqual(_run(fn, self.rootfs), "[]")

    @skip_unless_linux
    def test_no_routes(self):
        # No IPv4 routes; IPv6 routes (fresh-netns ::/0 dev lo entries on
        # some kernels) reference ONLY the DOWN loopback - nothing usable.
        def fn(state, fs):
            route = net_mod._read_proc_net("route")
            ipv6 = net_mod._read_proc_net("ipv6_route")
            v4 = [l for l in route.splitlines() if l.strip() and not l.startswith("Iface")]
            devices = net_mod._parse_route_devices(ipv6)
            return json.dumps({"v4_routes": len(v4), "v6_devices": devices,
                               "lo_down": not bool(_lo_flags_inside() & IFF_UP)})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["v4_routes"], 0, "IPv4 route table must be empty")
        self.assertEqual(set(data["v6_devices"]), {"lo"},
                         "IPv6 routes must reference only lo")
        self.assertTrue(data["lo_down"], "lo must be DOWN so no route is usable")

    @skip_unless_linux
    def test_no_default_route(self):
        # /proc/net/route (IPv4) must have no default (0.0.0.0) entry; the
        # IPv6 ::/0 entries (if present) reference only the DOWN lo.
        def fn(state, fs):
            route = net_mod._read_proc_net("route")
            ipv6 = net_mod._read_proc_net("ipv6_route")
            v4_default = [l for l in route.splitlines()
                          if "00000000" in l.split()[1:3]]
            return json.dumps({
                "v4_default": len(v4_default),
                "v6_default_on_lo_only": all(
                    parts[-1] == "lo" for parts in
                    (line.split() for line in ipv6.splitlines() if line))})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["v4_default"], 0, "no IPv4 default route")
        self.assertTrue(data["v6_default_on_lo_only"],
                        "IPv6 default routes must reference only the DOWN lo")

    @skip_unless_linux
    def test_socket_network_path_unusable(self):
        # socket() and even bind() may succeed (creation is
        # namespace-independent and the kernel does not validate bind
        # addresses against the empty address table here - recorded
        # honestly, not asserted); the PATH must be unusable: every
        # connect fails ENETUNREACH (no route) and a bound listener is
        # unreachable from any source. "No usable network path" is the
        # acceptance criterion - bind() succeeding is inert.
        def fn(state, fs):
            results = {}
            for host in ("8.8.8.8", "127.0.0.1", "169.254.169.254"):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((host, 443))
                    results[f"connect_{host}"] = "OK"
                except OSError as e:
                    results[f"connect_{host}"] = f"errno:{e.errno}"
                s.close()
            # A listener in the netns is unreachable even from the same
            # netns (lo DOWN, no route) - no service can be reached.
            ln = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                ln.bind(("127.0.0.1", 0))
                ln.listen(1)
                port = ln.getsockname()[1]
                c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    c.connect(("127.0.0.1", port))
                    results["listen_reachable"] = "OK"
                except OSError as e:
                    results["listen_reachable"] = f"errno:{e.errno}"
                c.close()
            except OSError as e:
                results["listen_setup"] = f"errno:{e.errno}"
            finally:
                ln.close()
            return json.dumps(results)

        data = json.loads(_run(fn, self.rootfs))
        for host in ("8.8.8.8", "127.0.0.1", "169.254.169.254"):
            self.assertEqual(data[f"connect_{host}"], "errno:101",
                             f"connect to {host} must fail ENETUNREACH "
                             "(no usable network path)")
        self.assertEqual(data["listen_reachable"], "errno:101",
                         "no listener may be reachable (no route)")

    @skip_unless_linux
    def test_connect_refused_or_unavailable(self):
        def fn(state, fs):
            return json.dumps({
                "public": _try_connect_inside("8.8.8.8", 443),
                "loopback": _try_connect_inside("127.0.0.1", 1),
            })

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["public"], "errno:101",
                         "public connect must fail ENETUNREACH")
        self.assertEqual(data["loopback"], "errno:101",
                         "loopback connect must fail ENETUNREACH (lo DOWN)")

    @skip_unless_linux
    def test_host_network_namespace_unchanged(self):
        # Host /proc/net/dev + route must be byte-identical before and
        # after a full sandbox run (mount/netns isolation, no leakage).
        def host_state():
            out = {}
            for f in ("dev", "route", "ipv6_route"):
                with open(f"/proc/net/{f}", "r", encoding="ascii") as fh:
                    out[f] = fh.read()
            return out

        before = host_state()

        def fn(state, fs):
            return net_mod._parse_dev_names(net_mod._read_proc_net("dev"))

        _run(fn, self.rootfs)
        self.assertEqual(before, host_state(),
                         "sandbox network activity must not change the host "
                         "network namespace state")


class WorkloadReenableTests(unittest.TestCase):
    """The workload cannot re-enable networking: since Step 7 the
    capability reduction has removed CAP_NET_ADMIN, so even the lo
    flag-toggle FAILS and lo stays DOWN; the structural property (no
    usable path, no host escape) holds on every substrate. (The tests
    assert the security boundary, never the environment's EOPNOTSUPP
    artifact.)"""

    def setUp(self):
        _require_fs(self)
        self.src = make_source()
        self.addCleanup(shutil.rmtree, self.src, True)
        self.rootfs = rootfs_mod.build_rootfs(self.src)
        self.addCleanup(shutil.rmtree, self.rootfs.layout.dir, True)

    @skip_unless_linux
    def test_workload_cannot_enable_loopback(self):
        # Step 7 (capability reduction) removed CAP_NET_ADMIN: the lo-up
        # attempt now FAILS (EPERM) and lo stays DOWN - the Step 5
        # documented residual is resolved. Every non-loopback connect
        # still fails ENETUNREACH and the host netns stays unreachable.
        def fn(state, fs):
            attempt = _bring_lo_up_inside()
            return json.dumps({
                "attempt": attempt,
                "lo_up": bool(_lo_flags_inside() & IFF_UP),
                "connect_public": _try_connect_inside("8.8.8.8", 443),
                "connect_metadata": _try_connect_inside("169.254.169.254", 80),
                "connect_host_gw": _try_connect_inside("192.168.1.1", 80),
            })

        data = json.loads(_run(fn, self.rootfs))
        self.assertNotEqual(data["attempt"], "OK",
                            "lo-up must fail after the Step 7 capability drop")
        self.assertFalse(data["lo_up"], "lo must stay DOWN after the attempt")
        for label in ("connect_public", "connect_metadata", "connect_host_gw"):
            self.assertEqual(data[label], "errno:101",
                             f"{label} must fail ENETUNREACH after the "
                             f"workload's lo-up attempt ({data['attempt']})")

    @skip_unless_linux
    def test_workload_cannot_add_route(self):
        # Attempt to add an IPv4 route: assert no usable route results.
        # (On the validation kernel the netlink mutation itself fails with
        # EOPNOTSUPP - a Docker-Desktop/WSL2 artifact; on a native kernel
        # it may succeed, but any route points at sandbox-local devices
        # with no host-side peer, so the path stays unusable.)
        def fn(state, fs):
            attempts = {}
            try:
                attempts["netlink"] = _netlink_add_route_inside()
            except OSError as e:
                attempts["netlink"] = f"errno:{e.errno}"
            route = net_mod._read_proc_net("route")
            v4 = [l for l in route.splitlines() if l.strip() and not l.startswith("Iface")]
            return json.dumps({"attempts": attempts, "v4_routes": len(v4),
                               "connect": _try_connect_inside("8.8.8.8", 443)})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["v4_routes"], 0,
                         "no usable IPv4 route may exist after the attempt")
        self.assertEqual(data["connect"], "errno:101",
                         "connect must still fail ENETUNREACH")

    @skip_unless_linux
    def test_workload_cannot_create_interface(self):
        def fn(state, fs):
            try:
                result = _netlink_add_iface_inside()
            except OSError as e:
                result = f"errno:{e.errno}"
            names = net_mod._parse_dev_names(net_mod._read_proc_net("dev"))
            return json.dumps({"attempt": result, "interfaces": names})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["interfaces"], ["lo"],
                         "only lo may exist after the attempt")

    @skip_unless_linux
    def test_workload_cannot_escape_to_host_netns(self):
        # No host pid is visible in the sandbox proc view, so no host netns
        # fd path exists; every visible /proc/<pid>/ns/net is the sandbox's
        # own netns. setns(CLONE_NEWNET) to a host netns is structurally
        # impossible (and would need CAP_SYS_ADMIN in the initial userns).
        def fn(state, fs):
            pids = sorted(int(e) for e in os.listdir("/proc") if e.isdigit())
            own = str(os.fstat(os.open("/proc/self/ns/net", os.O_RDONLY)).st_ino)
            ns_of = {}
            for p in pids:
                try:
                    st = os.stat(f"/proc/{p}/ns/net")
                    ns_of[str(p)] = str(st.st_ino)
                except OSError as e:
                    ns_of[str(p)] = f"errno:{e.errno}"
            return json.dumps({"pids": pids, "own": own, "ns_of": ns_of})

        data = json.loads(_run(fn, self.rootfs))
        self.assertEqual(data["pids"], [1], "only sandbox PID 1 is visible")
        for p, ns in data["ns_of"].items():
            self.assertEqual(ns, data["own"],
                             f"visible pid {p} must be in the sandbox's own "
                             "netns - no host netns fd path exists")

    @skip_unless_linux
    def test_loopback_up_attempt_keeps_deny_by_construction(self):
        # Step 7 resolved the lo-toggle residual: without CAP_NET_ADMIN the
        # workload cannot bring lo UP, so the deny-by-construction state is
        # now enforced by the capability drop itself (plus the netns).
        def fn(state, fs):
            attempt = _bring_lo_up_inside()
            return json.dumps({
                "attempt": attempt,
                "lo_up": bool(_lo_flags_inside() & IFF_UP),
                "public": _try_connect_inside("8.8.8.8", 443),
                "host_gw": _try_connect_inside("172.16.0.1", 80),
            })

        data = json.loads(_run(fn, self.rootfs))
        self.assertNotEqual(data["attempt"], "OK",
                            "lo-up must fail after the Step 7 capability drop")
        self.assertFalse(data["lo_up"],
                         "lo must remain DOWN after the attempt")
        self.assertEqual(data["public"], "errno:101")
        self.assertEqual(data["host_gw"], "errno:101")


def _netlink_add_route_inside() -> str:
    RTM_NEWROUTE = 24
    RTA_DST = 1
    RTA_OIF = 4
    NLM_F_REQUEST = 0x1
    NLM_F_ACK = 0x4
    NLM_F_CREATE = 0x400
    NLM_F_EXCL = 0x200
    NLMSG_ERROR = 2
    rtmsg = struct.pack("BBBBBBBBi", 2, 8, 0, 0, 254, 3, 0, 1, 0)
    payload = b"\x00" + rtmsg
    payload += struct.pack("HH", 8, RTA_DST) + bytes([10, 0, 0, 0])
    payload += struct.pack("HH", 8, RTA_OIF) + struct.pack("I", 1)
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((0, 0))
    s.settimeout(5)
    s.send(struct.pack("IHHII", 16 + len(payload), RTM_NEWROUTE,
                       NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                       1, 0) + payload)
    d = s.recv(4096)
    ln, typ, fl, se, pi = struct.unpack_from("IHHII", d, 0)
    s.close()
    if typ == NLMSG_ERROR:
        return f"errno:{-struct.unpack('i', d[16:20])[0]}"
    return "OK"


def _netlink_add_iface_inside() -> str:
    RTM_NEWLINK = 16
    IFLA_IFNAME = 3
    IFLA_LINKINFO = 18
    IFLA_INFO_KIND = 1
    NLM_F_REQUEST = 0x1
    NLM_F_ACK = 0x4
    NLM_F_CREATE = 0x400
    NLM_F_EXCL = 0x200
    NLMSG_ERROR = 2
    kind = b"dummy"
    info = struct.pack("HH", 4 + len(kind) + 1, IFLA_INFO_KIND) + kind + b"\x00"
    li = struct.pack("HH", 4 + len(info), IFLA_LINKINFO) + info
    name = b"dummy0\x00"
    payload = struct.pack("B", 0) + struct.pack("BBHIII", 0, 0, 0, 0, 0, 0)
    payload += struct.pack("HH", 4 + len(name), IFLA_IFNAME) + name
    payload += li
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((0, 0))
    s.settimeout(5)
    s.send(struct.pack("IHHII", 16 + len(payload), RTM_NEWLINK,
                       NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                       1, 0) + payload)
    d = s.recv(4096)
    ln, typ, fl, se, pi = struct.unpack_from("IHHII", d, 0)
    s.close()
    if typ == NLMSG_ERROR:
        return f"errno:{-struct.unpack('i', d[16:20])[0]}"
    return "OK"


class FailureModeTests(unittest.TestCase):
    """Every unexpected network state must REFUSE with an explicit reason -
    never a silent continue, never a warning-and-continue."""

    def _probe_with(self, workspace: str) -> object:
        from agent_sandbox.config import RuntimeConfig
        cfg = RuntimeConfig.from_dict(valid_config(workspace))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            return setup._network_probe_impl(cfg)

    def _assert_refused(self, check, reason_part: str) -> None:
        self.assertFalse(check.ok)
        self.assertEqual(check.code, InitFailureCode.STAGE_FAILED)
        self.assertIn(reason_part, check.reason)

    @skip_unless_linux
    def test_network_namespace_failure_refuses(self):
        # The real path: when the deny-by-construction state cannot be
        # established (here: lo is UP and cannot be brought down -
        # simulated), the probe must refuse, never silently continue.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_flags = net_mod._if_flags
        real_set = net_mod._set_if_flags

        def lo_up(name):
            if name == "lo":
                return 0x49  # UP | LOOPBACK | MULTICAST
            return real_flags(name)

        def boom(name, flags):
            raise OSError(13, "set flags: Operation not permitted")

        try:
            net_mod._if_flags = lo_up
            net_mod._set_if_flags = boom
            self._assert_refused(self._probe_with(src), "cannot bring lo down")
        finally:
            net_mod._if_flags = real_flags
            net_mod._set_if_flags = real_set

    @skip_unless_linux
    def test_unexpected_interface_refuses(self):
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_dev = net_mod._read_proc_net

        def extra_iface(name):
            if name == "dev":
                return ("Inter-|   Receive                                                |  Transmit\n"
                        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
                        "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n"
                        "  eth0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n")
            return real_dev(name)

        try:
            net_mod._read_proc_net = extra_iface
            self._assert_refused(self._probe_with(src), "unexpected interfaces")
        finally:
            net_mod._read_proc_net = real_dev

    @skip_unless_linux
    def test_unexpected_route_refuses(self):
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_dev = net_mod._read_proc_net

        def extra_route(name):
            if name == "route":
                return ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                        "lo\t00000000\t01000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n")
            return real_dev(name)

        try:
            net_mod._read_proc_net = extra_route
            self._assert_refused(self._probe_with(src), "unexpected IPv4 routes")
        finally:
            net_mod._read_proc_net = real_dev

    @skip_unless_linux
    def test_unexpected_address_refuses(self):
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_dev = net_mod._read_proc_net

        def extra_addr(name):
            if name == "fib_trie":
                return ("Main:\n  +-- 10.0.0.0/8 1 0 1\n     |-- 10.0.0.1\n        /32 host LOCAL\n")
            return real_dev(name)

        try:
            net_mod._read_proc_net = extra_addr
            self._assert_refused(self._probe_with(src), "unexpected IPv4 addresses")
        finally:
            net_mod._read_proc_net = real_dev

    @skip_unless_linux
    def test_loopback_up_verification_refuses(self):
        # The verification must refuse if lo is UP at verify time even
        # though the config step could not (in this injection) be the fix:
        # simulate ensure_loopback_down seeing lo DOWN (call 1) but the
        # verify-time read (call 2, in PID 1 after the fork) seeing lo UP -
        # the counter travels through the fork, so call 1 is the child A
        # config read and call 2 is the PID-1 verification read.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_flags = net_mod._if_flags
        calls = [0]

        def lo_flaky(name):
            if name == "lo":
                calls[0] += 1
                return 0x49 if calls[0] >= 2 else real_flags(name)
            return real_flags(name)

        try:
            net_mod._if_flags = lo_flaky
            self._assert_refused(self._probe_with(src), "loopback is UP")
        finally:
            net_mod._if_flags = real_flags

    @skip_unless_linux
    def test_verification_failure_refuses(self):
        # Unreadable state -> verification impossible -> refuse.
        _require_fs(self)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        real_dev = net_mod._read_proc_net

        def broken(name):
            if name == "dev":
                raise net_mod.NamespaceSetupError("cannot read /proc/self/net/dev (simulated)")
            return real_dev(name)

        try:
            net_mod._read_proc_net = broken
            self._assert_refused(self._probe_with(src), "verification failed")
        finally:
            net_mod._read_proc_net = real_dev


class IntegrationTests(unittest.TestCase):
    @skip_unless_linux
    def test_network_probe_ok_and_hardened_refuses_at_seccomp(self):
        # Full real path: namespaces + filesystem + network + no_new_privs
        # boundary verified, then HARDENED refuses at SECCOMP (the next
        # unimplemented stage).
        ok, reason = _fs_available()
        if not ok:
            self.skipTest("filesystem boundary substrate unavailable: " + reason)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        from agent_sandbox.config import RuntimeConfig
        from agent_sandbox.models import InitStage
        from agent_sandbox.security.init import SecurityInitializer
        cfg = RuntimeConfig.from_dict(valid_config(src))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            result = SecurityInitializer(cfg).initialize()
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.stage, InitStage.SECCOMP)
        self.assertEqual(result.failure.code, InitFailureCode.STAGE_UNAVAILABLE)
        self.assertIn("no implementation", result.failure.reason)

    @skip_unless_linux
    def test_probe_reason_covers_network(self):
        ok, reason = _fs_available()
        if not ok:
            self.skipTest("filesystem boundary substrate unavailable: " + reason)
        src = make_source()
        self.addCleanup(shutil.rmtree, src, True)
        from agent_sandbox.config import RuntimeConfig
        cfg = RuntimeConfig.from_dict(valid_config(src))
        with unittest.mock.patch.object(init_mod, "_is_linux", return_value=True):
            check = setup._network_probe_impl(cfg)
        self.assertTrue(check.ok, check.reason)
        self.assertIn("deny-by-construction", check.reason)


if __name__ == "__main__":
    unittest.main()
