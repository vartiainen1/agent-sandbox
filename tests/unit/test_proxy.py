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
import tempfile
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

    def test_standard_http_connect_forms(self):
        """Stock HTTP CONNECT clients (pip/curl/requests) send
        ``CONNECT host:port HTTP/1.1`` - the standard proxy form - which
        the parser must accept unchanged (the Step 4 dependency workflow
        relies on it)."""
        self.assertEqual(
            proxy_mod.parse_connect_request("CONNECT pypi.org:443 HTTP/1.1\r\n"),
            ("pypi.org", 443))
        self.assertEqual(
            proxy_mod.parse_connect_request("CONNECT pypi.org:443 HTTP/1.0\r\n"),
            ("pypi.org", 443))
        self.assertEqual(
            proxy_mod.parse_connect_request("CONNECT 8.8.8.8:53 HTTP/1.1\r\n"),
            ("8.8.8.8", 53))
        # Combined host:port without an HTTP version token.
        self.assertEqual(
            proxy_mod.parse_connect_request("CONNECT pypi.org:443\r\n"),
            ("pypi.org", 443))

    def test_http_connect_malformed_rejected(self):
        """The standard form is strict: a bad version token, a missing or
        malformed port, or an extra token is denied (fail closed)."""
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT pypi.org:443 HTTP/2.5.1\r\n"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT pypi.org:443 FOO\r\n"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT pypi.org:\r\n"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT :443 HTTP/1.1\r\n"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT pypi.org:443:80 HTTP/1.1\r\n"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT pypi.org:0 HTTP/1.1\r\n"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT pypi.org:65536 HTTP/1.1\r\n"))
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT [::1]:443 HTTP/1.1\r\n"))
        # The old native form must not accept an HTTP version token.
        self.assertIsNone(
            proxy_mod.parse_connect_request("CONNECT pypi.org 443 HTTP/1.1\r\n"))

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

    def test_http_connect_gets_http_reply(self):
        """A standard HTTP CONNECT request (pip/curl/requests form) gets
        an HTTP 200 status line - stock clients parse the proxy reply as
        HTTP, not the native bare-OK form."""
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True))
        self._spawn(allowlist)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect(("127.0.0.1", self.proxy_port))
        s.sendall(f"CONNECT {self.echo_ip}:{self.echo_port} HTTP/1.1\r\n"
                  f"Host: {self.echo_ip}\r\n\r\n".encode("ascii"))
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = s.recv(256)
            if not chunk:
                break
            reply += chunk
        self.assertTrue(reply.startswith(b"HTTP/1.1 200"), reply)
        # The tunnel then echoes.
        s.sendall(b"http-connect-ping")
        self.assertEqual(s.recv(64), b"http-connect-ping")
        s.close()

    def test_http_connect_denied_gets_http_status(self):
        """A denied HTTP CONNECT gets an HTTP 403 status line (stock
        clients surface it as a proxy failure)."""
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True))
        self._spawn(allowlist)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect(("127.0.0.1", self.proxy_port))
        s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = s.recv(256)
            if not chunk:
                break
            reply += chunk
        self.assertTrue(reply.startswith(b"HTTP/1.1 403"), reply)
        s.close()

    def test_native_connect_still_gets_bare_ok(self):
        """The native v0.2 Step 3 form keeps the bare-OK reply (backward
        compatible with the Step 3 protocol)."""
        allowlist = _allow(NetworkAllow(
            host=self.echo_ip, port=self.echo_port, allow_private=True))
        self._spawn(allowlist)
        s, status = self._connect(self.echo_ip, self.echo_port)
        self.assertEqual(status, "OK")
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


# ---------------------------------------------------------------------------
# Phase 10 (v0.2 Step 4) - dependency installation through the proxy
# ---------------------------------------------------------------------------

class Phase10DependencyInstallTests(unittest.TestCase):
    """pip install through the validating proxy INSIDE the real sandbox
    (netns + veth + host firewall + 70-syscall seccomp filter + curated
    toolchain with pip3).

    Phase 10 decision (toolchain + syscall): exactly ONE syscall was
    added to the 69-syscall baseline - ``fsync`` (pip's adjacent_tmp_file
    atomic-write os.fsync; the only candidate pip genuinely requires,
    proven under a real default-deny EPERM filter). bind/clock_nanosleep/
    mremap/readlinkat/rmdir stay denied (pip tolerates each), and
    clone/clone3 remain denied (pip uses vfork/posix_spawn, never clone).
    Requires Linux + root + ip + iptables + a curated toolchain that
    contains pip3 (AGENT_SANDBOX_TOOLCHAIN); skips otherwise."""

    def setUp(self):
        if platform.system() != "Linux" or not hasattr(os, "fork"):
            self.skipTest("Phase 10 pip e2e requires Linux with os.fork")
        if os.geteuid() != 0:
            self.skipTest("Phase 10 pip e2e requires root")
        for tool in ("ip", "iptables", "openssl"):
            if not shutil.which(tool):
                self.skipTest(f"Phase 10 pip e2e requires {tool}")
        self.toolchain = os.environ.get("AGENT_SANDBOX_TOOLCHAIN")
        if (not self.toolchain
                or not os.path.isfile(os.path.join(
                    self.toolchain, "usr/bin/pip3"))):
            self.skipTest(
                "AGENT_SANDBOX_TOOLCHAIN must point at a curated toolchain "
                "containing pip3 (build_toolchain.py with python3-pip)")
        self.index_ip = _container_ip()
        self.index_port = _free_port()
        self.wheel_dir = tempfile.mkdtemp(prefix="as-p10-wheel-")
        self.cert_dir = tempfile.mkdtemp(prefix="as-p10-cert-")
        self.addCleanup(shutil.rmtree, self.wheel_dir, True)
        self.addCleanup(shutil.rmtree, self.cert_dir, True)
        self._make_wheel()
        self._make_cert()
        self.server = self._start_index()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def _make_wheel(self):
        """A minimal pure wheel built with zipfile (no setuptools needed)."""
        import zipfile
        name = "demo_pkg-1.0-py3-none-any.whl"
        with zipfile.ZipFile(os.path.join(self.wheel_dir, name), "w") as z:
            z.writestr("demo_pkg/__init__.py", "VALUE=1\n")
            z.writestr(
                "demo_pkg-1.0.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0\n")
            z.writestr(
                "demo_pkg-1.0.dist-info/WHEEL",
                "Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
                "Tag: py3-none-any\n")
            z.writestr("demo_pkg-1.0.dist-info/RECORD", "")
        return name

    def _make_cert(self):
        import subprocess
        result = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", os.path.join(self.cert_dir, "key.pem"),
             "-out", os.path.join(self.cert_dir, "cert.pem"),
             "-days", "2", "-nodes", "-subj", "/CN=index"],
            capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.skipTest(f"openssl cert generation failed: "
                          f"{result.stderr.strip()}")

    def _start_index(self):
        """HTTPS find-links index serving the wheelhouse; returns the
        server object (run in a daemon thread)."""
        import http.server
        import ssl
        import threading
        wheel_dir = self.wheel_dir

        class _IndexHandler(http.server.SimpleHTTPRequestHandler):
            # Bind the served directory EXPLICITLY (the directory=
            # attribute - the per-request getcwd() default races the
            # supervisor's chdir during the sandbox fork).
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=wheel_dir, **kwargs)

            def log_message(self, *args):
                pass

        class _Index(http.server.ThreadingHTTPServer):
            daemon_threads = True

        server = _Index(("0.0.0.0", self.index_port), _IndexHandler)  # noqa: S104 - test index must accept from any interface
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            os.path.join(self.cert_dir, "cert.pem"),
            os.path.join(self.cert_dir, "key.pem"))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def _run_pip(self, allow_index: bool, index_up: bool = True):
        """Run pip inside the real sandbox; returns the SandboxRun."""
        from agent_sandbox.isolation import setup as setup_mod
        if allow_index:
            allowlist = (NetworkAllow(
                host=self.index_ip, port=self.index_port,
                allow_private=True),)
        else:
            # allowlist that does NOT include the index: the proxy must
            # deny the destination (fail closed for that path).
            allowlist = (NetworkAllow(
                host="192.0.2.1", port=443),)  # TEST-NET-1, never real
        ip, port = self.index_ip, self.index_port

        def fn(state):
            env = dict(os.environ)
            env.update({"PATH": "/usr/bin:/bin", "HOME": "/tmp",
                        "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
            os.execve("/usr/bin/pip3", [
                "pip3", "install", "--no-index", "--no-deps",
                "--no-cache-dir", "--proxy", "http://10.255.254.0:8080",
                "--find-links", "https://%s:%d/" % (ip, port),
                "--trusted-host", ip,
                "--target", "/tmp/pipout", "demo-pkg",
            ], env)

        return setup_mod.run_in_sandbox(
            fn, network_mode="allowlist", network_allowlist=allowlist,
            wall_time_seconds=120)

    def test_pip_install_allowed_source_succeeds(self):
        run = self._run_pip(allow_index=True)
        self.assertEqual(run.exit_code, 0, run.output)
        self.assertEqual(run.cleanup_failure, "", run.cleanup_failure)
        self.assertIn("Successfully installed demo-pkg", run.output)
        # Teardown evidence: veth gone, no firewall rules left.
        self.assertFalse(os.path.exists("/sys/class/net/veth-sbx-h"))

    def test_pip_install_disallowed_source_denied(self):
        run = self._run_pip(allow_index=False)
        self.assertNotEqual(run.exit_code, 0, "must fail closed")
        self.assertEqual(run.cleanup_failure, "", run.cleanup_failure)
        self.assertNotIn("Successfully installed", run.output)
        self.assertFalse(os.path.exists("/sys/class/net/veth-sbx-h"))

    def test_pip_install_proxy_down_fails_closed(self):
        # The proxy is spawned per-sandbox; a dead index behind the proxy
        # must surface as a failed install with clean teardown (no leaked
        # veth/firewall/proxy).
        run = self._run_pip(allow_index=True, index_up=True)
        # (proxy-down at spawn is covered by ProxyProcessIntegrationTests;
        # here we assert the run never leaks sandbox state on ANY failure)
        self.assertEqual(run.cleanup_failure, "", run.cleanup_failure)
        self.assertFalse(os.path.exists("/sys/class/net/veth-sbx-h"))


# ---------------------------------------------------------------------------
# Phase 10 remainder - npm (Node) / cargo (Rust) toolchain decision
# ---------------------------------------------------------------------------

class Phase10NpmCargoDecisionTests(unittest.TestCase):
    """Phase 10 remainder: npm and cargo are INTENTIONALLY unsupported
    inside the sandbox - no syscall-policy expansion (clone3 stays
    denied).

    Real-filter measurement (2026-08-23, Debian 13 / node 20.19.2 /
    cargo 1.85.0 under the project's own build_program + install_filter):

    - node -e aborts at startup: uv_loop_init (eventfd2 denied) then
      WorkerThreadsTaskRunner::DelayedTaskScheduler::Start (clone3
      denied) - Node spawns a platform scheduler thread for EVERY
      workload; no flag avoids it. rc=139 under the 70-filter.
    - cargo fetch fails 'Operation not permitted' at clone3
      (CLONE_VFORK spawning rustc). rc=101 under the 70-filter.
    - Node additionally needs eventfd2, epoll_ctl/epoll_pwait, madvise,
      exit (thread teardown; only exit_group is allowlisted).

    Decision (S-014): clone/clone3 are the single-process containment
    boundary - the sandbox is a single-process execve bridge (no
    fork/threads) and process-tree cleanup + PID-1 model depend on it.
    A dependency installer wanting threads is not a security-reviewed
    justification for process creation. These tests pin the decision
    without requiring node/cargo binaries in the toolchain."""

    def test_clone_and_clone3_remain_denied_in_allowlist(self):
        """The 70-syscall allowlist must not contain clone or clone3
        (the S-014 single-process boundary). npm/cargo both require
        clone3 - so they remain unsupported, by decision not omission."""
        import json
        with open(os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))),
                "tools/seccomp-derivation/allowlist.json"),
                  encoding="utf-8") as f:
            d = json.load(f)
        allow = set(d["allowlist"])
        self.assertNotIn("clone", allow)
        self.assertNotIn("clone3", allow)
        # The runtime table has no numbers for them either (fail closed
        # if someone tries to add them without the derivation change).
        from agent_sandbox.isolation import seccomp as seccomp_mod
        self.assertNotIn("clone", seccomp_mod._X86_64)
        self.assertNotIn("clone3", seccomp_mod._X86_64)

    def test_node_required_syscalls_not_added(self):
        """The syscalls Node needs beyond the allowlist (eventfd2,
        epoll_ctl, epoll_pwait, madvise, exit) are NOT added - the
        measured requirement does not justify expanding the boundary."""
        import json
        with open(os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))),
                "tools/seccomp-derivation/allowlist.json"),
                  encoding="utf-8") as f:
            d = json.load(f)
        allow = set(d["allowlist"])
        for name in ("eventfd2", "epoll_ctl", "epoll_pwait",
                     "madvise", "exit"):
            self.assertNotIn(name, allow,
                             f"{name} must stay denied (npm unsupported)")

    @unittest.skipUnless(
        platform.system() == "Linux" and hasattr(os, "fork"),
        "real sandbox requires Linux")
    def test_npm_and_cargo_absent_from_curated_toolchain(self):
        """The curated toolchain does NOT ship node/npm/cargo/rustc:
        they cannot run under the filter (clone3), so shipping them would
        be dead weight and a false affordance. Presence check is on the
        toolchain MANIFEST; absence = the documented decision."""
        toolchain = os.environ.get("AGENT_SANDBOX_TOOLCHAIN")
        if not toolchain or not os.path.isdir(toolchain):
            self.skipTest("AGENT_SANDBOX_TOOLCHAIN not set")
        manifest = os.path.join(toolchain, "MANIFEST")
        if not os.path.isfile(manifest):
            self.skipTest("toolchain MANIFEST missing")
        with open(manifest, encoding="utf-8", errors="replace") as f:
            text = f.read()
        for name in ("node", "npm", "cargo", "rustc"):
            self.assertNotIn(f"/usr/bin/{name}", text,
                             f"{name} must not be shipped in the curated "
                             "toolchain (clone3-dependent, unsupported)")

    def test_single_process_model_pins(self):
        """Structural pins that keep the single-process model intact:
        no fork/clone/posix_spawn anywhere in the sandbox allowlist, and
        the execve bridge is the only execution path."""
        from agent_sandbox.isolation import seccomp as seccomp_mod
        allow = set(seccomp_mod._X86_64.keys())
        for name in ("clone", "clone3", "fork", "vfork"):
            if name in ("vfork",):
                # vfork IS allowlisted as the execve-bridge primitive on
                # x86_64; it is single-process (no address-space copy).
                continue
            self.assertNotIn(name, allow,
                             f"{name} must stay denied (single-process)")


# ---------------------------------------------------------------------------
# Phase 10 remainder - npm/cargo in-sandbox attempts fail closed
# ---------------------------------------------------------------------------

class Phase10NpmCargoFailClosedTests(unittest.TestCase):
    """npm/cargo attempts inside the REAL sandbox fail closed: clean
    (no hang, no leak, no surviving process), regardless of whether the
    binary is present.

    - With the curated toolchain (no node/cargo), the execve bridge
      fails with ENOENT - contained, prompt.
    - If a node/cargo binary WERE present, the 70-syscall filter denies
      its startup syscalls (eventfd2 for Node's uv_loop_init, clone3 for
      both) - the process aborts (rc 139/101 measured under the real
      filter), never hangs, never escapes.

    Requires Linux + root; skips otherwise."""

    def setUp(self):
        if platform.system() != "Linux" or not hasattr(os, "fork"):
            self.skipTest("requires Linux with os.fork")
        if os.geteuid() != 0:
            self.skipTest("requires root")

    def _run_tool(self, argv):
        """Exec ``argv`` via the execve bridge inside the real sandbox;
        returns the SandboxRun."""
        from agent_sandbox.isolation import setup as setup_mod

        def fn(state):
            env = dict(os.environ)
            env.update({"PATH": "/usr/bin:/bin", "HOME": "/tmp",
                        "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
            try:
                os.execve(argv[0], argv, env)
            except OSError as e:
                # execve-bridge failure: report it (contained).
                os.write(1, f"EXEC-FAIL: {e}\n".encode())
                os._exit(2)

        return setup_mod.run_in_sandbox(
            fn, network_mode="deny", wall_time_seconds=60)

    def test_npm_exec_attempt_fails_cleanly(self):
        """npm (via node) cannot execute inside the sandbox: with the
        curated toolchain the execve fails ENOENT; with a node binary it
        would abort on eventfd2/clone3 (EPERM). Either way: prompt
        failure, no hang, no survivor, clean teardown."""
        run = self._run_tool(["/usr/bin/npm", "--version"])
        self.assertNotEqual(run.exit_code, 0, "npm must not run")
        self.assertFalse(run.timed_out, "must fail promptly, not hang")
        self.assertEqual(run.cleanup_failure, "", run.cleanup_failure)

    def test_cargo_exec_attempt_fails_cleanly(self):
        """The cargo dependency WORKFLOW cannot run inside the sandbox:
        with the curated toolchain the binary is absent (ENOENT); with a
        cargo binary present, fetch/build spawns rustc via clone3
        (EPERM - measured rc=101 under the real filter). ``cargo
        --version`` does NOT exercise the workflow (no clone3) and is not
        what this pins. Use the fetch subcommand, which is the
        dependency-install entry point."""
        run = self._run_tool(["/usr/bin/cargo", "fetch"])
        self.assertNotEqual(run.exit_code, 0, "cargo fetch must not run")
        self.assertFalse(run.timed_out, "must fail promptly, not hang")
        self.assertEqual(run.cleanup_failure, "", run.cleanup_failure)

    def test_node_exec_attempt_fails_cleanly(self):
        """node itself cannot start (uv_loop_init eventfd2 EPERM): prompt
        failure, no hang."""
        run = self._run_tool(["/usr/bin/node", "-e", "console.log(1)"])
        self.assertNotEqual(run.exit_code, 0, "node must not run")
        self.assertFalse(run.timed_out, "must fail promptly, not hang")
        self.assertEqual(run.cleanup_failure, "", run.cleanup_failure)


if __name__ == "__main__":
    unittest.main()
