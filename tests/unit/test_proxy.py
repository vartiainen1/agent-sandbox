"""Tests for the v0.2 validating forward proxy (isolation/proxy.py).

Covers, per the Step 3 requirements:
- CONNECT request parsing (valid / malformed / bounds)
- SSRF classification (public vs loopback / RFC1918 / link-local /
  metadata 169.254.169.254 / multicast / unspecified / reserved)
- Allowlist matching (host+port, case-insensitive hostnames, no
  hostname<->literal cross-matching)
- Host-side resolution + destination gate (DNS-rebinding denial,
  allow_private relaxation, unresolvable -> denied)
- network_allowlist configuration validation (fail closed)
- Registry manifest round-trip
- Proxy process integration (Linux): echo-server e2e, denied paths,
  proxy-down fail-closed, termination without leaked processes
- Full-sandbox e2e (Linux + root + ip + iptables): the workload's ONLY
  path out is the proxy; direct host access is blocked by the host
  firewall; AF_UNIX stays denied by the seccomp argument filter.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import unittest
from unittest.mock import patch

from agent_sandbox.config import NetworkAllow, RuntimeConfig
from agent_sandbox.isolation import proxy as proxy_mod
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import ConfigError

# IPv4 address families/constants used by mocked getaddrinfo results.
_AF_INET = socket.AF_INET
_SOCK_STREAM = socket.SOCK_STREAM


def _allow(*entries) -> tuple:
    return tuple(entries)


def _public_allowlist() -> tuple:
    return _allow(NetworkAllow(host="example.com", port=443),
                  NetworkAllow(host="8.8.8.8", port=53),
                  NetworkAllow(host="10.0.0.5", port=8443, allow_private=True))


# ---------------------------------------------------------------------------
# CONNECT request parsing + host grammar
# ---------------------------------------------------------------------------

class ParseRequestTests(unittest.TestCase):
    """parse_connect_request: exactly CONNECT <host> <port>, fail closed."""

    def test_valid_request(self):
        self.assertEqual(
            proxy_mod.parse_connect_request("CONNECT example.com 443\r\n"),
            ("example.com", 443))
        self.assertEqual(
            proxy_mod.parse_connect_request("CONNECT 8.8.8.8 53\n"),
            ("8.8.8.8", 53))

    def test_malformed_verb(self):
        self.assertIsNone(proxy_mod.parse_connect_request("GET / HTTP/1.1"))
        self.assertIsNone(proxy_mod.parse_connect_request("connect example.com 443"))

    def test_missing_or_extra_tokens(self):
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT example.com"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT example.com 443 extra"))

    def test_invalid_port(self):
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT example.com 0"))
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT example.com 65536"))
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT example.com abc"))
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT example.com -1"))
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT example.com 44x3"))

    def test_invalid_host(self):
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT 443"))
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT '' 443"))
        self.assertIsNone(proxy_mod.parse_connect_request("CONNECT 443"))

    def test_empty_and_whitespace(self):
        self.assertIsNone(proxy_mod.parse_connect_request(""))
        self.assertIsNone(proxy_mod.parse_connect_request("   \r\n"))
        self.assertIsNone(proxy_mod.parse_connect_request(None))

    def test_oversized_line_rejected(self):
        host = "a" * (proxy_mod._MAX_REQUEST_LINE + 10)
        self.assertIsNone(
            proxy_mod.parse_connect_request(f"CONNECT {host} 443"))


class HostGrammarTests(unittest.TestCase):
    """validate_host: hostname or strict IPv4 literal."""

    def test_valid_hostnames(self):
        for host in ("example.com", "pypi.org", "sub.domain.example",
                     "xn--bcher-kva.example", "a"):
            self.assertTrue(proxy_mod.validate_host(host), host)

    def test_invalid_hostnames(self):
        for host in ("-bad.example", "bad-.example", "bad..example",
                     "a" * 254, "with space", "under_score.example",
                     "exa mple.com"):
            self.assertFalse(proxy_mod.validate_host(host), host)

    def test_valid_ipv4(self):
        for ip in ("8.8.8.8", "0.0.0.0", "255.255.255.255", "10.0.0.5"):  # noqa: S104
            self.assertTrue(proxy_mod.validate_host(ip), ip)

    def test_invalid_ipv4(self):
        for ip in ("08.8.8.8", "256.1.1.1", "1.2.3", "1.2.3.4.5",
                   "1.2.3.4.5", "127.1", "1..2.3"):
            self.assertFalse(proxy_mod.validate_host(ip), ip)


# ---------------------------------------------------------------------------
# SSRF classification
# ---------------------------------------------------------------------------

class SsrfClassificationTests(unittest.TestCase):
    """is_blocked_ip: the always-denied and relaxable classes."""

    def test_public_addresses_allowed(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34", "172.217.0.0"):
            self.assertIsNone(proxy_mod.is_blocked_ip(ip), ip)

    def test_loopback_denied(self):
        for ip in ("127.0.0.1", "127.255.255.254"):
            self.assertIsNotNone(proxy_mod.is_blocked_ip(ip), ip)

    def test_private_ranges_denied(self):
        for ip in ("10.0.0.1", "172.16.0.1", "172.31.255.254",
                   "192.168.0.1", "100.64.0.1"):
            self.assertEqual(
                proxy_mod.is_blocked_ip(ip),
                "private range destination denied (requires allow_private)",
                ip)

    def test_link_local_and_metadata_denied(self):
        for ip in ("169.254.1.1", "169.254.169.254"):
            self.assertIsNotNone(proxy_mod.is_blocked_ip(ip), ip)

    def test_multicast_unspecified_reserved_denied(self):
        for ip in ("224.0.0.1", "0.0.0.0", "240.0.0.1"):  # noqa: S104
            self.assertIsNotNone(proxy_mod.is_blocked_ip(ip), ip)

    def test_invalid_address_denied(self):
        self.assertIsNotNone(proxy_mod.is_blocked_ip("not-an-ip"))
        self.assertIsNotNone(proxy_mod.is_blocked_ip("8.8.8.8.8"))


# ---------------------------------------------------------------------------
# Allowlist matching
# ---------------------------------------------------------------------------

class AllowlistMatchingTests(unittest.TestCase):
    """match_allowlist: host+port; hostnames case-insensitive; no
    hostname<->IP-literal cross-matching."""

    def test_exact_match(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        self.assertIsNotNone(proxy_mod.match_allowlist("example.com", 443, al))

    def test_hostname_case_insensitive(self):
        al = _allow(NetworkAllow(host="PyPI.org", port=443))
        self.assertIsNotNone(proxy_mod.match_allowlist("pypi.org", 443, al))

    def test_port_mismatch_denied(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        self.assertIsNone(proxy_mod.match_allowlist("example.com", 80, al))

    def test_unlisted_host_denied(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        self.assertIsNone(proxy_mod.match_allowlist("github.com", 443, al))

    def test_hostname_does_not_match_ip_literal(self):
        al = _allow(NetworkAllow(host="8.8.8.8", port=53))
        self.assertIsNone(proxy_mod.match_allowlist("eight-eight-eight-eight", 53, al))
        self.assertIsNone(proxy_mod.match_allowlist("dns.google", 53, al))
        self.assertIsNotNone(proxy_mod.match_allowlist("8.8.8.8", 53, al))


# ---------------------------------------------------------------------------
# Resolution + the destination gate
# ---------------------------------------------------------------------------

class DestinationGateTests(unittest.TestCase):
    """check_destination: the single gate (syntax + allowlist + SSRF)."""

    def _addrinfo(self, *ips):
        return [(_AF_INET, _SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]

    def test_allowlisted_hostname_public_allowed(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        with patch("agent_sandbox.isolation.proxy.socket.getaddrinfo",
                   return_value=self._addrinfo("93.184.216.34")):
            ok, reason, target = proxy_mod.check_destination("example.com", 443, al)
        self.assertTrue(ok, reason)
        self.assertEqual(target, "93.184.216.34")

    def test_ip_literal_allowed(self):
        al = _allow(NetworkAllow(host="8.8.8.8", port=53))
        ok, reason, target = proxy_mod.check_destination("8.8.8.8", 53, al)
        self.assertTrue(ok, reason)
        self.assertEqual(target, "8.8.8.8")

    def test_dns_rebinding_to_private_denied(self):
        """An allowlisted hostname resolving to a private address must be
        denied - the host-side resolution is the DNS-rebinding guard."""
        al = _allow(NetworkAllow(host="example.com", port=443))
        with patch("agent_sandbox.isolation.proxy.socket.getaddrinfo",
                   return_value=self._addrinfo("10.0.0.7")):
            ok, reason, _ = proxy_mod.check_destination("example.com", 443, al)
        self.assertFalse(ok)
        self.assertIn("private range", reason)

    def test_dns_rebinding_to_loopback_denied(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        with patch("agent_sandbox.isolation.proxy.socket.getaddrinfo",
                   return_value=self._addrinfo("127.0.0.1")):
            ok, reason, _ = proxy_mod.check_destination("example.com", 443, al)
        self.assertFalse(ok)
        self.assertIn("loopback", reason)

    def test_allow_private_relaxes_private_only(self):
        al = _allow(NetworkAllow(host="10.0.0.5", port=8443, allow_private=True))
        ok, reason, target = proxy_mod.check_destination("10.0.0.5", 8443, al)
        self.assertTrue(ok, reason)
        self.assertEqual(target, "10.0.0.5")

    def test_allow_private_never_relaxes_loopback(self):
        al = _allow(NetworkAllow(host="127.0.0.1", port=80, allow_private=True))
        ok, reason, _ = proxy_mod.check_destination("127.0.0.1", 80, al)
        self.assertFalse(ok)
        self.assertIn("loopback", reason)

    def test_allow_private_never_relaxes_metadata(self):
        al = _allow(NetworkAllow(host="169.254.169.254", port=80,
                                 allow_private=True))
        ok, reason, _ = proxy_mod.check_destination("169.254.169.254", 80, al)
        self.assertFalse(ok)
        self.assertIn("link-local", reason)

    def test_unlisted_destination_denied(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        ok, reason, _ = proxy_mod.check_destination("github.com", 443, al)
        self.assertFalse(ok)
        self.assertIn("not in allowlist", reason)

    def test_unresolvable_hostname_denied(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        with patch("agent_sandbox.isolation.proxy.socket.getaddrinfo",
                   side_effect=OSError(2, "Name or service not known")):
            ok, reason, _ = proxy_mod.check_destination("example.com", 443, al)
        self.assertFalse(ok)
        self.assertIn("resolution failed", reason)

    def test_malformed_host_denied(self):
        al = _allow(NetworkAllow(host="example.com", port=443))
        ok, reason, _ = proxy_mod.check_destination("bad host!", 443, al)
        self.assertFalse(ok)
        self.assertIn("malformed", reason)

    def test_any_private_resolution_denied_even_with_public(self):
        """If a hostname resolves to BOTH a public and a private address,
        the destination is denied (a private reachable address is never
        acceptable - all resolved addresses must pass)."""
        al = _allow(NetworkAllow(host="example.com", port=443))
        with patch("agent_sandbox.isolation.proxy.socket.getaddrinfo",
                   return_value=self._addrinfo("93.184.216.34", "10.0.0.9")):
            ok, reason, _ = proxy_mod.check_destination("example.com", 443, al)
        self.assertFalse(ok)
        self.assertIn("private range", reason)


# ---------------------------------------------------------------------------
# network_allowlist configuration validation
# ---------------------------------------------------------------------------

def _cfg(**overrides):
    base = {"mode": "hardened", "workspace": "/tmp/w"}
    base.update(overrides)
    return base


class ConfigAllowlistTests(unittest.TestCase):
    """network_allowlist: strict, fail-closed configuration validation."""

    def test_default_empty(self):
        cfg = RuntimeConfig.from_dict(_cfg())
        self.assertEqual(cfg.network_allowlist, ())

    def test_valid_allowlist_accepted(self):
        cfg = RuntimeConfig.from_dict(_cfg(
            network_mode="allowlist",
            network_allowlist=[
                {"host": "pypi.org", "port": 443},
                {"host": "10.0.0.5", "port": 8443, "allow_private": True},
            ]))
        self.assertEqual(len(cfg.network_allowlist), 2)
        self.assertEqual(cfg.network_allowlist[0].host, "pypi.org")
        self.assertEqual(cfg.network_allowlist[0].port, 443)
        self.assertFalse(cfg.network_allowlist[0].allow_private)
        self.assertTrue(cfg.network_allowlist[1].allow_private)

    def test_deny_mode_with_allowlist_rejected(self):
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict(_cfg(
                network_mode="deny",
                network_allowlist=[{"host": "pypi.org", "port": 443}]))
        self.assertIn("require", str(cm.exception).lower())

    def test_non_list_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(_cfg(
                network_mode="allowlist", network_allowlist="pypi.org:443"))

    def test_non_mapping_entry_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(_cfg(
                network_mode="allowlist", network_allowlist=["pypi.org"]))

    def test_unknown_entry_field_rejected(self):
        with self.assertRaises(ConfigError) as cm:
            RuntimeConfig.from_dict(_cfg(
                network_mode="allowlist",
                network_allowlist=[{"host": "pypi.org", "port": 443,
                                    "wildcard": True}]))
        self.assertIn("wildcard", str(cm.exception))

    def test_missing_host_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(_cfg(
                network_mode="allowlist",
                network_allowlist=[{"port": 443}]))

    def test_malformed_host_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(_cfg(
                network_mode="allowlist",
                network_allowlist=[{"host": "bad host!", "port": 443}]))

    def test_bad_port_rejected(self):
        for port in (0, 65536, "443", True, -1):
            with self.assertRaises(ConfigError):
                RuntimeConfig.from_dict(_cfg(
                    network_mode="allowlist",
                    network_allowlist=[{"host": "pypi.org", "port": port}]))

    def test_bad_allow_private_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(_cfg(
                network_mode="allowlist",
                network_allowlist=[{"host": "pypi.org", "port": 443,
                                    "allow_private": "yes"}]))

    def test_dead_entries_rejected(self):
        """A literal the proxy would always deny is a dead allowlist entry
        - rejected at configuration time (fail closed)."""
        for host, priv in (("127.0.0.1", True),      # loopback, never relaxable
                           ("169.254.169.254", True),  # metadata, never relaxable
                           ("10.0.0.5", False),        # private without opt-in
                           ("0.0.0.0", True),  # noqa: S104
                           ("224.0.0.1", True)):
            with self.assertRaises(ConfigError):
                RuntimeConfig.from_dict(_cfg(
                    network_mode="allowlist",
                    network_allowlist=[{"host": host, "port": 80,
                                        "allow_private": priv}]))

    def test_duplicate_entries_rejected(self):
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(_cfg(
                network_mode="allowlist",
                network_allowlist=[
                    {"host": "pypi.org", "port": 443},
                    {"host": "PyPI.org", "port": 443},  # case-insensitive dup
                ]))

    def test_allow_private_public_entry_accepted(self):
        cfg = RuntimeConfig.from_dict(_cfg(
            network_mode="allowlist",
            network_allowlist=[{"host": "8.8.8.8", "port": 53,
                                "allow_private": True}]))
        self.assertEqual(len(cfg.network_allowlist), 1)

    def test_allowlist_immutable(self):
        cfg = RuntimeConfig.from_dict(_cfg(
            network_mode="allowlist",
            network_allowlist=[{"host": "pypi.org", "port": 443}]))
        with self.assertRaises(Exception):
            cfg.network_allowlist[0].port = 80  # frozen dataclass


class RegistryRoundTripTests(unittest.TestCase):
    """The manifest stores and rebuilds the allowlist exactly."""

    def test_manifest_round_trip(self):
        from agent_sandbox import registry as reg
        cfg = RuntimeConfig.from_dict(_cfg(
            network_mode="allowlist",
            network_allowlist=[
                {"host": "pypi.org", "port": 443},
                {"host": "10.0.0.5", "port": 8443, "allow_private": True},
            ]))
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            session_id = "a" * 32
            reg.save_session(td, session_id, cfg, created="2026-08-23T00:00:00")
            manifest = reg.load_manifest(td, session_id)
            self.assertIn("network_allowlist", manifest)
            rebuilt = reg.config_from_manifest(manifest)
        self.assertEqual(rebuilt.network_allowlist, cfg.network_allowlist)

    def test_absent_allowlist_defaults_empty(self):
        from agent_sandbox import registry as reg
        manifest = {
            "schema": 1, "session_id": "b" * 32, "created": "",
            "mode": "hardened", "workspace": "/tmp/w",
            "network_mode": "deny", "env_allowlist": None,
            "resources": None, "policy": None, "last_execution": None,
        }
        cfg = reg.config_from_manifest(manifest)
        self.assertEqual(cfg.network_allowlist, ())


# ---------------------------------------------------------------------------
# Proxy process integration (Linux)
# ---------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _container_ip() -> str:
    """The test host's (container's) primary IPv4 - a private, non-loopback
    address the proxy can reach via local delivery for the echo server."""
    try:
        infos = socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if not ip.startswith("127."):
                return ip
    except OSError:
        pass
    if shutil.which("hostname"):
        import subprocess
        result = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5)
        for ip in result.stdout.split():
            if not ip.startswith("127."):
                return ip
    raise RuntimeError("cannot determine a non-loopback container IP")


def _start_echo_server() -> tuple[int, int]:
    """Fork a single-threaded echo server bound to 0.0.0.0. Returns
    (pid, port). The child echoes each connection until EOF."""
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("0.0.0.0", 0))  # noqa: S104 - test echo fixture must accept from any interface
    port = listen.getsockname()[1]
    listen.listen(8)
    pid = os.fork()
    if pid == 0:
        while True:
            try:
                conn, _addr = listen.accept()
            except OSError:
                os._exit(0)
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
    listen.close()
    return pid, port


def _stop_echo_server(pid: int) -> None:
    try:
        os.kill(pid, 15)  # SIGTERM
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass


def _wait_proxy(ip: str, port: int, timeout: float = 3.0) -> bool:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proxy_mod.proxy_listening(ip, port, timeout=0.2):
            return True
        time.sleep(0.05)
    return False


def _pgid_members(pgid: int) -> list[int]:
    """Live processes whose process-group id equals ``pgid`` (read from
    /proc/<pid>/stat). Used to prove the proxy listener AND its handlers
    are gone after termination - robust against pid reuse."""
    members: list[int] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "r", encoding="ascii") as f:
                parts = f.read().rsplit(")", 1)[1].split()
            # stat fields after comm: state ppid pgrp session ...
            if len(parts) > 2 and parts[2] == str(pgid):
                members.append(int(entry))
        except (OSError, ValueError, IndexError):
            continue
    return members


@unittest.skipUnless(
    platform.system() == "Linux" and hasattr(os, "fork"),
    "proxy process integration tests require Linux with os.fork")
class ProxyProcessIntegrationTests(unittest.TestCase):
    """The proxy end-to-end without the sandbox: spawn, CONNECT over a
    real echo server, deny paths, proxy-down fail-closed, teardown."""

    def setUp(self):
        self.echo_ip = _container_ip()
        self.echo_pid, self.echo_port = _start_echo_server()
        self.proxy_pid = -1
        self.proxy_port = _free_port()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        if self.proxy_pid >= 1:
            proxy_mod.terminate_proxy(self.proxy_pid)
        _stop_echo_server(self.echo_pid)

    def _spawn(self, allowlist, listen_ip="127.0.0.1"):
        self.proxy_pid = proxy_mod.spawn_proxy(
            allowlist, listen_ip=listen_ip, port=self.proxy_port)
        self.assertTrue(
            _wait_proxy(listen_ip, self.proxy_port),
            "proxy did not start listening")
        return self.proxy_pid

    def _connect(self, host, port, timeout=10.0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", self.proxy_port))
            s.sendall(f"CONNECT {host} {port}\r\n".encode("ascii"))
            status = b""
            while b"\n" not in status:
                chunk = s.recv(256)
                if not chunk:
                    break
                status += chunk
        except OSError:
            s.close()
            raise
        return s, status.decode("ascii", errors="replace").strip()

    def test_valid_allowed_destination_permitted(self):
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True))
        self._spawn(allowlist)
        s, status = self._connect(self.echo_ip, self.echo_port)
        self.assertTrue(status.startswith("OK"), status)
        s.sendall(b"hello-proxy")
        echoed = s.recv(64)
        self.assertEqual(echoed, b"hello-proxy")
        s.close()

    def test_disallowed_destination_denied(self):
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True))
        self._spawn(allowlist)
        s, status = self._connect("example.com", 443)
        self.assertTrue(status.startswith("DENIED"), status)
        self.assertIn("not in allowlist", status)
        s.close()

    def test_unauthorized_port_denied(self):
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True))
        self._spawn(allowlist)
        s, status = self._connect(self.echo_ip, 9999)
        self.assertTrue(status.startswith("DENIED"), status)
        s.close()

    def test_private_without_allow_private_denied(self):
        """The echo target is a private container address; without
        allow_private the proxy must deny it (the SSRF gate), even though
        host+port match an allowlist entry."""
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port))  # no allow_private
        self._spawn(allowlist)
        s, status = self._connect(self.echo_ip, self.echo_port)
        self.assertTrue(status.startswith("DENIED"), status)
        self.assertIn("private range", status)
        s.close()

    def test_malformed_request_denied(self):
        self._spawn(_allow())
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect(("127.0.0.1", self.proxy_port))
        s.sendall(b"GET / HTTP/1.1\r\n")
        status = b""
        while b"\n" not in status:
            chunk = s.recv(256)
            if not chunk:
                break
            status += chunk
        self.assertTrue(status.startswith(b"DENIED"), status)
        s.close()

    def test_empty_allowlist_denies_everything(self):
        self._spawn(_allow())
        s, status = self._connect(self.echo_ip, self.echo_port)
        self.assertTrue(status.startswith("DENIED"), status)
        s.close()

    def test_proxy_down_fails_closed(self):
        """A dead proxy endpoint must be refused by the probe - the
        sandbox's only path out is gone, fail closed."""
        self.assertFalse(_wait_proxy("127.0.0.1", _free_port(), timeout=0.5))
        # A direct connect to the dead endpoint is refused (fail closed -
        # no silent path appears).
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            with self.assertRaises(OSError):
                s.connect(("127.0.0.1", _free_port()))
        finally:
            s.close()

    def test_termination_reaps_listener_and_handlers(self):
        """terminate_proxy reaps the listener AND its handlers - no leaked
        proxy processes."""
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True))
        self._spawn(allowlist)
        # Hold one live tunnel open while we terminate.
        s, status = self._connect(self.echo_ip, self.echo_port)
        self.assertTrue(status.startswith("OK"), status)
        pid = self.proxy_pid
        self.assertTrue(proxy_mod.terminate_proxy(pid))
        self.proxy_pid = -1
        # No process may remain in the proxy's process group (the listener
        # setsid'd, handlers inherited the group) - robust against pid
        # reuse, unlike os.kill(pid, 0).
        self.assertEqual(_pgid_members(pid), [])
        s.close()

    def test_spawn_fails_closed_without_fork(self):
        class _NoForkOS:
            pass
        with patch("agent_sandbox.isolation.proxy.os", _NoForkOS()):
            with self.assertRaises(NamespaceSetupError):
                proxy_mod.spawn_proxy(())


# ---------------------------------------------------------------------------
# Full-sandbox e2e (Linux + root + ip + iptables)
# ---------------------------------------------------------------------------

def _have_tools() -> bool:
    return (shutil.which("ip") is not None
            and shutil.which("iptables") is not None)


@unittest.skipUnless(
    platform.system() == "Linux" and hasattr(os, "fork"),
    "full-sandbox proxy tests require Linux with os.fork")
@unittest.skipUnless(_have_tools(), "requires the ip and iptables binaries")
class FullSandboxProxyTests(unittest.TestCase):
    """End-to-end through the REAL sandbox: the workload's only path out
    is the validating proxy; direct host access is blocked by the host
    firewall; AF_UNIX stays denied by the seccomp argument filter."""

    def setUp(self):
        self.echo_ip = _container_ip()
        self.echo_pid, self.echo_port = _start_echo_server()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        _stop_echo_server(self.echo_pid)

    def test_sandbox_network_goes_through_proxy_only(self):
        from agent_sandbox.isolation import setup as setup_mod
        if os.geteuid() != 0:
            self.skipTest("sandbox network e2e requires root")
        allowlist = (NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True),)
        ip, port = self.echo_ip, self.echo_port

        def fn(state):
            out = {}
            # 1. Through the proxy (the ONLY path out). The sockets must
            #    be closed on EVERY path: a leaked socket emits a
            #    ResourceWarning into the captured output at GC, which
            #    would corrupt the JSON result (a known leak pattern -
            #    closed in finally).
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(20)
                s.connect(("10.255.254.0", 8080))
                s.sendall(f"CONNECT {ip} {port}\r\n".encode("ascii"))
                status = b""
                while b"\n" not in status:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    status += chunk
                s.sendall(b"ping-from-sandbox")
                echoed = s.recv(64)
                out["proxy"] = (status.decode(errors="replace").strip(),
                                echoed.decode(errors="replace").strip())
            except OSError as e:
                out["proxy"] = f"ERR {type(e).__name__}: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            # 2. Direct connection to the host service must be BLOCKED
            #    (host firewall: only the proxy port is accepted).
            d = None
            try:
                d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                d.settimeout(6)
                d.connect((ip, port))
                d.close()
                out["direct"] = "UNEXPECTED-SUCCESS"
            except OSError:
                out["direct"] = "blocked"
            finally:
                if d is not None:
                    try:
                        d.close()
                    except OSError:
                        pass
            # 3. AF_UNIX must be denied by the seccomp argument filter
            #    (S-003/S-004 preserved - no control/credential sockets).
            u = None
            try:
                u = socket.socket(1, socket.SOCK_STREAM)  # AF_UNIX = 1
                u.close()
                out["af_unix"] = "UNEXPECTED-SUCCESS"
            except OSError as e:
                out["af_unix"] = f"blocked:{getattr(e, 'errno', None)}"
            finally:
                if u is not None:
                    try:
                        u.close()
                    except OSError:
                        pass
            import json
            return json.dumps(out)

        run = setup_mod.run_in_sandbox(
            fn, network_mode="allowlist", network_allowlist=allowlist)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "", run.cleanup_failure)
        out = json.loads(run.output)
        self.assertEqual(out["proxy"][0], "OK")
        self.assertEqual(out["proxy"][1], "ping-from-sandbox")
        self.assertEqual(out["direct"], "blocked")
        self.assertTrue(out["af_unix"].startswith("blocked"), out["af_unix"])

        # Teardown evidence: veth gone, firewall rules gone.
        self.assertFalse(
            os.path.exists("/sys/class/net/veth-sbx-h"))
        import subprocess
        rules = subprocess.run(
            ["iptables", "-S"], capture_output=True, text=True, timeout=5,
        ).stdout
        self.assertNotIn("veth-sbx-h", rules)


if __name__ == "__main__":
    unittest.main()
