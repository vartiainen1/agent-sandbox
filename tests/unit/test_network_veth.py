"""Tests for v0.2 allowlist network plumbing (veth-pair to validating proxy).

These tests cover:
- Config validation for allowlist network mode
- Module-level constants and structure
- Fail-closed behavior for missing ip command
- Verification functions (host-side unit tests)
- Integration tests (Linux-only, skip on non-Linux)
"""

from __future__ import annotations

import os
import platform
import unittest
from unittest.mock import patch

from agent_sandbox.config import RuntimeConfig
from agent_sandbox.isolation import network as net_mod
from agent_sandbox.isolation.errors import NamespaceSetupError
from agent_sandbox.models import ConfigError


def _valid_config(**overrides):
    """Return a minimal valid config dict."""
    base = {"mode": "hardened", "workspace": "/tmp/test-workspace"}
    base.update(overrides)
    return base


class AllowlistConfigTests(unittest.TestCase):
    """Tests for allowlist network mode configuration."""

    def test_allowlist_mode_accepted(self):
        """allowlist is a valid network mode."""
        cfg = RuntimeConfig.from_dict(
            _valid_config(network_mode="allowlist"))
        self.assertEqual(cfg.network_mode, "allowlist")

    def test_deny_mode_accepted(self):
        """deny remains the default network mode."""
        cfg = RuntimeConfig.from_dict(_valid_config())
        self.assertEqual(cfg.network_mode, "deny")

    def test_unsupported_network_mode_rejected(self):
        """Only 'deny' and 'allowlist' are supported."""
        with self.assertRaises(ConfigError):
            RuntimeConfig.from_dict(
                _valid_config(network_mode="bogus"))

    def test_allowlist_mode_in_supported_set(self):
        """allowlist appears in SUPPORTED_NETWORK_MODES."""
        from agent_sandbox.config import SUPPORTED_NETWORK_MODES
        self.assertIn("allowlist", SUPPORTED_NETWORK_MODES)
        self.assertIn("deny", SUPPORTED_NETWORK_MODES)
        self.assertEqual(len(SUPPORTED_NETWORK_MODES), 2)


class VethConstantsTests(unittest.TestCase):
    """Tests for veth-pair constants and module structure."""

    def test_veth_names_within_limit(self):
        """Linux interface names must be <= 15 characters."""
        self.assertLessEqual(len(net_mod._VETH_HOST), 15)
        self.assertLessEqual(len(net_mod._VETH_SANDBOX), 15)

    def test_proxy_subnet_is_private(self):
        """The proxy subnet should use RFC 1918 or RFC 6598 address space."""
        self.assertTrue(net_mod._PROXY_SUBNET_PREFIX.startswith("10."))

    def test_proxy_subnet_mask_is_point_to_point(self):
        """/31 provides exactly two usable addresses (RFC 3021)."""
        self.assertEqual(net_mod._PROXY_SUBNET_MASK, 31)

    def test_sandbox_and_host_ips_in_subnet(self):
        """Both IPs should be in the same /31 subnet."""
        self.assertEqual(
            net_mod._SANDBOX_IPPlain, f"{net_mod._PROXY_SUBNET_PREFIX}.1")
        self.assertEqual(
            net_mod._HOST_IPPlain, f"{net_mod._PROXY_SUBNET_PREFIX}.0")

    def test_cleanup_function_exists(self):
        """cleanup_veth_pair should be a callable."""
        self.assertTrue(callable(net_mod.cleanup_veth_pair))

    def test_setup_allowlist_veth_exists(self):
        """setup_allowlist_veth should be a callable."""
        self.assertTrue(callable(net_mod.setup_allowlist_veth))


class VethFailClosedTests(unittest.TestCase):
    """Fail-closed tests for veth-pair operations."""

    def test_get_ifindex_missing_interface(self):
        """_get_ifindex raises NamespaceSetupError for missing interface."""
        with self.assertRaises(NamespaceSetupError):
            net_mod._get_ifindex("nonexistent-iface-12345")

    def test_create_veth_pair_ip_not_found(self):
        """create_veth_pair fails closed when ip command is missing."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod.create_veth_pair()
            self.assertIn("ip command not found", str(cm.exception))

    def test_create_veth_pair_returns_error(self):
        """create_veth_pair fails closed when ip returns non-zero."""
        mock_result = type("Result", (), {
            "returncode": 1,
            "stderr": "RTNETLINK answers: Operation not permitted",
        })()
        with patch("subprocess.run", return_value=mock_result):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod.create_veth_pair()
            self.assertIn("veth pair creation failed", str(cm.exception))

    def test_move_veth_ip_not_found(self):
        """move_veth_to_netns fails closed when ip is missing."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod.move_veth_to_netns("veth-sbx-s", 12345)
            self.assertIn("ip command not found", str(cm.exception))

    def test_move_veth_returns_error(self):
        """move_veth_to_netns fails closed when ip returns non-zero."""
        mock_result = type("Result", (), {
            "returncode": 1,
            "stderr": "No such process",
        })()
        with patch("subprocess.run", return_value=mock_result):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod.move_veth_to_netns("veth-sbx-s", 12345)
            self.assertIn("moving", str(cm.exception))

    def test_configure_host_side_ip_not_found(self):
        """configure_host_side_veth fails closed when ip is missing."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(NamespaceSetupError):
                net_mod.configure_host_side_veth()

    def test_run_ip_timeout(self):
        """_run_ip fails closed on timeout."""
        import subprocess
        with patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired("ip", 5.0)):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod._run_ip(["link", "show"])
            self.assertIn("timed out", str(cm.exception))

    def test_install_host_firewall_ip_tables_not_found(self):
        """install_host_firewall fails closed when iptables is missing."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod.install_host_firewall()
            self.assertIn("iptables command not found", str(cm.exception))

    def test_install_host_firewall_returns_error(self):
        """install_host_firewall fails closed when iptables fails."""
        mock_result = type("Result", (), {
            "returncode": 1,
            "stderr": "Permission denied (you must be root)",
        })()
        with patch("subprocess.run", return_value=mock_result):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod.install_host_firewall()
            self.assertIn("iptables", str(cm.exception))

    def test_install_host_firewall_timeout(self):
        """install_host_firewall fails closed on timeout."""
        import subprocess
        with patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired("iptables", 5.0)):
            with self.assertRaises(NamespaceSetupError) as cm:
                net_mod.install_host_firewall()
            self.assertIn("timed out", str(cm.exception))

    def test_cleanup_tolerates_missing_iptables(self):
        """cleanup_veth_pair is best-effort: a missing iptables binary must
        not raise (teardown is never a security gate)."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            net_mod.cleanup_veth_pair()  # must not raise

    def test_setup_allowlist_veth_installs_firewall(self):
        """setup_allowlist_veth installs the host firewall (the sandbox's
        only path must be the proxy - no direct host access)."""
        results = []

        def fake_run(cmd, **kwargs):
            results.append(list(cmd))
            return type("Result", (), {"returncode": 0, "stderr": ""})()

        with patch("subprocess.run", side_effect=fake_run), \
             patch.object(net_mod, "_get_ifindex", return_value=42):
            net_mod.setup_allowlist_veth(12345)
            calls = [c for c in results if c and c[0] == "iptables"]
            self.assertEqual(len(calls), 3)
            # INPUT: accept only the proxy port, drop everything else;
            # FORWARD: drop everything from the veth interface.
            self.assertIn("--dport", calls[0])
            self.assertEqual(calls[0][-2:], ["-j", "ACCEPT"])
            self.assertEqual(calls[1][-2:], ["-j", "DROP"])
            self.assertEqual(calls[2][-2:], ["-j", "DROP"])


class VerifyAllowlistNetworkTests(unittest.TestCase):
    """Tests for verify_allowlist_network (host-side, mocked)."""

    def test_verification_fails_on_unexpected_interfaces(self):
        """Verification fails if unexpected interfaces are present."""
        # Mock _read_proc_net to return data with unexpected interfaces
        dev_content = "Inter-|   Receive                  |  Transmit\n face |bytes    packets errs drop fifo compressed multicast|bytes    packets errs drop fifo frame compressed\n    lo:       0       0    0    0     0          0         0        0       0    0    0     0       0          0\n eth0:       0       0    0    0     0          0         0        0       0    0    0     0       0          0\n"
        empty_route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        empty_ipv6 = ""
        empty_fib = ""
        empty_if6 = ""

        def mock_read(name):
            return {
                "dev": dev_content,
                "route": empty_route,
                "ipv6_route": empty_ipv6,
                "fib_trie": empty_fib,
                "if_inet6": empty_if6,
            }[name]

        # Mock _if_flags to return 0 (lo DOWN) for both lo and eth0
        def mock_if_flags(name):
            return 0  # no flags = DOWN

        with patch.object(net_mod, "_read_proc_net", side_effect=mock_read), \
             patch.object(net_mod, "_if_flags", side_effect=mock_if_flags), \
             patch.object(net_mod, "os") as mock_os:
            # Mock os.fstat for netns identity check
            mock_fstat = type("Stat", (), {"st_ino": 999999})()
            mock_file = type("File", (), {"fileno": lambda self: 0})()
            mock_open = patch("builtins.open")
            with mock_open as m_open:
                m_open.return_value.__enter__ = lambda s: s
                m_open.return_value.__exit__ = lambda s, *a: False
                m_open.return_value.fileno = lambda: 0
                with patch("agent_sandbox.isolation.network.os.fstat",
                           return_value=mock_fstat):
                    with self.assertRaises(NamespaceSetupError) as cm:
                        net_mod.verify_allowlist_network("host-ns-123")
                    self.assertIn("unexpected interfaces", str(cm.exception))


@unittest.skipUnless(
    platform.system() == "Linux",
    "veth-pair integration tests require Linux")
class VethIntegrationTests(unittest.TestCase):
    """Integration tests that require real veth-pair operations (Linux only)."""

    def test_create_and_cleanup_veth_pair(self):
        """Create a veth pair and clean it up."""
        if os.geteuid() != 0:
            self.skipTest("veth operations require root")
        try:
            ifindex = net_mod.create_veth_pair()
            self.assertIsInstance(ifindex, int)
            self.assertGreater(ifindex, 0)
            # Verify the interface exists
            self.assertTrue(
                os.path.exists(f"/sys/class/net/{net_mod._VETH_HOST}"))
            self.assertTrue(
                os.path.exists(f"/sys/class/net/{net_mod._VETH_SANDBOX}"))
        finally:
            net_mod.cleanup_veth_pair()
            # Verify cleanup
            self.assertFalse(
                os.path.exists(f"/sys/class/net/{net_mod._VETH_HOST}"))


if __name__ == "__main__":
    unittest.main()
