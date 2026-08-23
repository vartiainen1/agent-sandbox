"""Network namespace configuration (Phase 1 Step 5, ADR-006; v0.2 Step 2).

v0.1 (deny by construction): The sandbox's network namespace (created by
unshare(CLONE_NEWNET) in Step 2) is configured into its final v0.1
state: loopback DOWN, no addresses, no usable routes, no host
interfaces, no path out. The kernel already provides this as the
FRESH-netns default; this module makes the intent explicit (ensure lo
down), VERIFIES the resulting state (never trusts syscall success), and
REFUSES on any unexpected element (fail closed).

v0.2 (allowlist via validating proxy): When network_mode="allowlist",
a veth pair is created by the supervisor, one end is moved into the
sandbox's netns, and the sandbox has a single controlled path to a
host-side validating proxy. The proxy enforces destination restrictions;
the sandbox itself never has direct external network access.

Verification sources (empirically chosen, Step 5 probe):
- /proc/self/net/{dev,route,ipv6_route,fib_trie,if_inet6} - the
  authoritative per-netns state view (the PID-1 procfs mount is per-netns
  via self/net; readable without any capability). NOTE: netlink dumps are
  NOT a reliable source here - on the validation kernels (Docker
  Desktop/WSL2 6.x) RTM_GETLINK dumps return empty and RTM_GETADDR
  returns EOPNOTSUPP inside the userns-owned netns, while /proc/net is
  complete (empirically verified; recorded in
  docs/seccomp-derivation/verification.md).
- ioctl(SIOCGIFFLAGS) on lo for the link state (fcntl on an AF_INET
  socket) - works without netlink and without privileges.

Empirical boundary facts (Step 5 probe, container):
- The workload CAN toggle lo (ns-local CAP_NET_ADMIN in the userns-owned
  netns); bringing lo up yields localhost-only connectivity (127.0.0.1,
  ::1 appear) and NO external path (connect to any non-loopback target
  still fails ENETUNREACH). Full prevention of even the lo toggle lands
  with the Step 12 capability drop (removes CAP_NET_ADMIN) + Step 13
  seccomp. This module verifies the SECURITY property that holds at every
  step: no usable network path by construction.
- The workload cannot reach the host netns: no host pid is visible in the
  sandbox proc view (Step 4), so no host netns fd path exists; setns to a
  host netns would additionally require CAP_SYS_ADMIN in the initial
  userns. Moving an interface to the host netns would require CAP_NET_ADMIN
  in the initial userns. Both fail closed by the kernel.
- Netlink mutations (RTM_NEWROUTE/RTM_NEWLINK) returned EOPNOTSUPP in the
  validation environment even as root with CAP_NET_ADMIN - that is a
  Docker-Desktop/WSL2 environment artifact, NOT the security mechanism,
  and is not relied upon (a native kernel may permit them; the island
  netns makes them harmless - no host-side peer device exists).

Failure semantics: every violation raises NamespaceSetupError with a
deterministic reason; the fail-closed guard converts it into a refusal.
Unexpected state is NEVER auto-fixed and continued.
"""

from __future__ import annotations

import os
import socket
import struct
import subprocess
from dataclasses import dataclass

try:
    import fcntl  # Linux-only; imported lazily by the ioctl helpers
except ImportError:  # pragma: no cover - non-Linux dev hosts stay import-safe
    fcntl = None

from agent_sandbox.isolation.errors import NamespaceSetupError

IFF_UP = 0x1
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

# procfs files read per-netns via /proc/self/net (the reader's own netns).
_PROC_NET_FILES = ("dev", "route", "ipv6_route", "fib_trie", "if_inet6")

# Module-level seams (fork-safe: the sandbox child inherits the parent's
# module state, so tests can inject a hostile/unexpected state read and
# the real verification path must refuse).
def _read_proc_net_impl(name: str) -> str:
    try:
        with open(f"/proc/self/net/{name}", "r", encoding="ascii") as f:
            return f.read()
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read /proc/self/net/{name}: {e} - network state "
            "verification impossible, fail closed") from e


# Module-level seam alias (fork-safe: the sandbox child inherits the
# parent's module state, so tests can inject a hostile/unexpected state
# read and the real verification path must refuse).
_read_proc_net = _read_proc_net_impl


def _if_flags(name: str) -> int:
    """ioctl(SIOCGIFFLAGS) on ``name`` (works in any netns the process is
    in; needs no privilege for the read). Raises OSError - the caller
    fails closed on an unreadable interface."""
    if fcntl is None:
        raise OSError(38, "fcntl unavailable - not Linux (fail closed)")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH", name.encode()[:15], 0)
        return struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
    finally:
        s.close()


def _set_if_flags(name: str, flags: int) -> None:
    """ioctl(SIOCSIFFLAGS) - the supervisor-side configuration primitive.
    Inside the sandbox's userns-owned netns, ns-local CAP_NET_ADMIN
    permits flag changes on the netns's own interfaces (empirically
    verified). Raises OSError on failure (fail closed)."""
    if fcntl is None:
        raise OSError(38, "fcntl unavailable - not Linux (fail closed)")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH", name.encode()[:15], flags))
    finally:
        s.close()


@dataclass(frozen=True)
class NetworkState:
    """Verified deny-by-construction network state (sandbox-internal)."""

    interfaces: tuple[str, ...]          # names, in /proc/net/dev order
    loopback_down: bool
    ipv4_addresses: tuple[str, ...]      # from fib_trie (empty = none)
    ipv6_addresses: tuple[str, ...]      # from if_inet6 (empty = none)
    ipv4_routes: int                     # count of /proc/net/route entries
    non_loopback_route_devices: tuple[str, ...]  # devices in ipv6_route != lo
    netns_distinct_from_host: bool


def _parse_dev_names(dev: str) -> list[str]:
    """Interface names from /proc/net/dev (the first column; the header
    line starts with 'Inter-|')."""
    names: list[str] = []
    for line in dev.splitlines():
        if ":" not in line or line.strip().startswith("Inter-"):
            continue
        name = line.split(":", 1)[0].strip()
        if name:
            names.append(name)
    return names


def _parse_route_devices(ipv6_route: str) -> list[str]:
    """Devices referenced by /proc/net/ipv6_route lines (last column)."""
    devices: list[str] = []
    for line in ipv6_route.splitlines():
        parts = line.split()
        if len(parts) >= 10:
            devices.append(parts[9])
    return devices


def _parse_fib_trie_addresses(fib_trie: str) -> list[str]:
    """IPv4 addresses from /proc/net/fib_trie: lines like '  |-- 127.0.0.1'
    (a dotted quad immediately under the trie node markers)."""
    addrs: list[str] = []
    for line in fib_trie.splitlines():
        stripped = line.strip()
        if stripped.startswith("|-- "):
            cand = stripped[4:].strip()
            parts = cand.split()
            if parts and parts[0].count(".") == 3:
                addrs.append(parts[0])
    return addrs


def _parse_if_inet6_addresses(if_inet6: str) -> list[str]:
    """IPv6 addresses from /proc/net/if_inet6 (first column = hex address)."""
    addrs: list[str] = []
    for line in if_inet6.splitlines():
        parts = line.split()
        if parts:
            addrs.append(parts[0])
    return addrs


def ensure_loopback_down() -> None:
    """Configuration action: ensure lo is DOWN (the deny-by-construction
    state). A fresh netns already has lo down; this makes the intent
    explicit and handles kernels whose fresh state differs. Failure to
    set the state is a refusal (fail closed), never a silent continue.
    Runs in the sandbox child (ns-local CAP_NET_ADMIN in the
    userns-owned netns - empirically sufficient for lo flag changes)."""
    try:
        flags = _if_flags("lo")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read lo flags during network configuration: {e} - "
            "fail closed") from e
    if flags & IFF_UP:
        try:
            _set_if_flags("lo", flags & ~IFF_UP)
        except OSError as e:
            raise NamespaceSetupError(
                f"cannot bring lo down: {e} - fail closed, network "
                "deny-by-construction state not established") from e


def verify_deny_by_construction(host_netns: str) -> NetworkState:
    """Verify the sandbox netns is in the deny-by-construction state and
    RETURN the verified state. Every violation raises
    NamespaceSetupError with a deterministic reason - the guard refuses
    (S-018), the workload never runs on an unverified network boundary.

    Checks (empirical, Step 5 probe - the fresh-netns deny-by-construction
    state):
    - /proc/net/dev lists EXACTLY lo.
    - lo is DOWN (ioctl SIOCGIFFLAGS, IFF_UP clear).
    - no IPv4 addresses (/proc/net/fib_trie empty) and no IPv6 addresses
      (/proc/net/if_inet6 empty) - nothing usable for communication.
    - no IPv4 routes (/proc/net/route empty).
    - every /proc/net/ipv6_route entry names lo as the device (a fresh
      netns on some kernels carries inert ::/0 dev lo entries; with lo
      DOWN and address-less they cannot carry traffic; a route on any
      OTHER device is a boundary violation).
    - the netns is distinct from the host's (/proc/self/ns/net inode !=
      host inode).
    """
    problems: list[str] = []
    try:
        dev = _read_proc_net("dev")
        route = _read_proc_net("route")
        ipv6_route = _read_proc_net("ipv6_route")
        fib_trie = _read_proc_net("fib_trie")
        if_inet6 = _read_proc_net("if_inet6")
    except NamespaceSetupError as e:
        raise NamespaceSetupError(
            f"network state verification failed: {e}") from e

    names = _parse_dev_names(dev)
    if names != ["lo"]:
        problems.append(
            f"unexpected interfaces in sandbox netns: {names} "
            "(expected exactly ['lo'])")

    try:
        lo_flags = _if_flags("lo")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read lo flags during verification: {e} - fail "
            "closed") from e
    loopback_down = not bool(lo_flags & IFF_UP)
    if not loopback_down:
        problems.append("loopback is UP - deny-by-construction requires lo DOWN")

    v4_addrs = _parse_fib_trie_addresses(fib_trie)
    if v4_addrs:
        problems.append(f"unexpected IPv4 addresses in sandbox netns: {v4_addrs}")
    v6_addrs = _parse_if_inet6_addresses(if_inet6)
    if v6_addrs:
        problems.append(f"unexpected IPv6 addresses in sandbox netns: {v6_addrs}")

    v4_route_lines = [l for l in route.splitlines() if l.strip() and not l.startswith("Iface")]
    if v4_route_lines:
        problems.append(f"unexpected IPv4 routes in sandbox netns: {v4_route_lines}")

    non_lo = [d for d in _parse_route_devices(ipv6_route) if d != "lo"]
    if non_lo:
        problems.append(
            f"IPv6 routes reference non-loopback device(s) {non_lo} - "
            "no host device may be reachable")

    try:
        with open("/proc/self/ns/net", "r", encoding="ascii") as f:
            own = str(os.fstat(f.fileno()).st_ino)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read own netns identity: {e} - fail closed") from e
    distinct = bool(host_netns) and own != host_netns
    if not distinct:
        problems.append(
            "sandbox netns is not distinct from the host netns "
            f"(own {own}, host {host_netns!r})")

    if problems:
        raise NamespaceSetupError(
            "network deny-by-construction verification failed: "
            + "; ".join(problems))
    return NetworkState(
        interfaces=tuple(names), loopback_down=loopback_down,
        ipv4_addresses=tuple(v4_addrs), ipv6_addresses=tuple(v6_addrs),
        ipv4_routes=len(v4_route_lines),
        non_loopback_route_devices=tuple(non_lo),
        netns_distinct_from_host=distinct)


# ---------------------------------------------------------------------------
# v0.2 allowlist network plumbing (veth-pair to validating proxy)
# ---------------------------------------------------------------------------

# Private /31 point-to-point link for sandbox <-> proxy communication.
# The /31 prefix provides exactly two usable addresses (RFC 3021).
_PROXY_SUBNET_PREFIX = "10.255.254"
_PROXY_SUBNET_MASK = 31
_SANDBOX_IP = f"{_PROXY_SUBNET_PREFIX}.1/{_PROXY_SUBNET_MASK}"
_HOST_IP = f"{_PROXY_SUBNET_PREFIX}.0/{_PROXY_SUBNET_MASK}"
_HOST_IPPlain = f"{_PROXY_SUBNET_PREFIX}.0"  # for route src=, no prefix
_SANDBOX_IPPlain = f"{_PROXY_SUBNET_PREFIX}.1"

# Interface names (max 15 chars for Linux)
_VETH_HOST = "veth-sbx-h"
_VETH_SANDBOX = "veth-sbx-s"

# Proxy port on the host-side interface (TCP)
_PROXY_PORT = 8080


def create_veth_pair() -> int:
    """Create a veth pair on the HOST side. Returns the ifindex of the
    sandbox-side end (to be moved into the sandbox's netns by the
    supervisor).

    This MUST be called from the supervisor process, BEFORE the sandbox
    child enters its network namespace. The veth pair is created in the
    host's netns.

    Raises NamespaceSetupError on failure (fail closed).
    """
    try:
        result = subprocess.run(
            [
                "ip", "link", "add",
                _VETH_HOST, "type", "veth",
                "peer", "name", _VETH_SANDBOX,
            ],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            raise NamespaceSetupError(
                f"veth pair creation failed: {result.stderr.strip()} - "
                "fail closed, allowlist network not established")
    except FileNotFoundError:
        raise NamespaceSetupError(
            "ip command not found - cannot create veth pair, fail closed")
    except subprocess.TimeoutExpired:
        raise NamespaceSetupError(
            "veth pair creation timed out - fail closed")
    # Return the ifindex of the sandbox-side end
    return _get_ifindex(_VETH_SANDBOX)


def _get_ifindex(ifname: str) -> int:
    """Read the ifindex of a named interface via /sys/class/net/<if>/ifindex.
    Raises NamespaceSetupError if the interface does not exist.
    """
    try:
        with open(f"/sys/class/net/{ifname}/ifindex", "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError) as e:
        raise NamespaceSetupError(
            f"cannot read ifindex for {ifname}: {e} - fail closed") from e


def move_veth_to_netns(ifname: str, target_pid: int) -> None:
    """Move interface ``ifname`` into the network namespace of
    ``target_pid``. This MUST be called from the supervisor process
    (which has CAP_NET_ADMIN in the initial/user namespace).

    Raises NamespaceSetupError on failure (fail closed).
    """
    try:
        result = subprocess.run(
            ["ip", "link", "set", "dev", ifname, "netns", str(target_pid)],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            raise NamespaceSetupError(
                f"moving {ifname} to netns {target_pid} failed: "
                f"{result.stderr.strip()} - fail closed")
    except FileNotFoundError:
        raise NamespaceSetupError(
            "ip command not found - cannot move interface, fail closed")
    except subprocess.TimeoutExpired:
        raise NamespaceSetupError(
            f"moving {ifname} to netns timed out - fail closed")


def configure_host_side_veth(proxy_port: int = _PROXY_PORT) -> None:
    """Configure the host-side end of the veth pair: assign IP, bring up,
    add a route for the proxy subnet.

    This MUST be called from the supervisor (host netns).
    Raises NamespaceSetupError on failure (fail closed).
    """
    _run_ip([
        "addr", "add", _HOST_IP, "dev", _VETH_HOST,
    ])
    _run_ip(["link", "set", "dev", _VETH_HOST, "up"])
    # Route for the proxy subnet (already directly connected via /31)


def configure_sandbox_side_veth() -> None:
    """Configure the sandbox-side end of the veth pair INSIDE the sandbox
    netns: assign IP, bring up, disable IPv6 (the allowlist path is
    IPv4-only - the kernel auto-assigns a link-local IPv6 to a freshly
    moved veth, which the netns verification must refuse), and set the
    default route via the host-side proxy.

    This MUST be called from inside the sandbox netns (PID 1 or the
    setup child after entering the netns).
    Raises NamespaceSetupError on failure (fail closed).
    """
    _run_ip(["addr", "add", _SANDBOX_IP, "dev", _VETH_SANDBOX])
    _run_ip(["link", "set", "dev", _VETH_SANDBOX, "up"])
    # Disable IPv6 on the sandbox-side interface: a moved veth is
    # auto-assigned a fe80::/64 link-local address and connected route,
    # and verify_allowlist_network must refuse ANY IPv6 in the netns
    # (the /31 proxy link is IPv4-only). The knob is per-netns (the
    # interface is in the sandbox netns here); writing it removes the
    # link-local address + route. Failure = refusal (the allowlist netns
    # would not be IPv4-only - fail closed).
    _disable_ipv6(_VETH_SANDBOX)
    # Default route through the host-side proxy endpoint
    _run_ip([
        "route", "add", "default",
        "via", _HOST_IPPlain,
        "dev", _VETH_SANDBOX,
    ])


def _disable_ipv6(ifname: str) -> None:
    """Write ``disable_ipv6=1`` for ``ifname`` via the per-netns procfs
    knob (/proc/sys/net/ipv6/conf/<if>/disable_ipv6). Must be called from
    the netns that owns the interface. Raises NamespaceSetupError on any
    failure (fail closed - the allowlist netns must be IPv4-only)."""
    path = f"/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6"
    try:
        with open(path, "w", encoding="ascii") as f:
            f.write("1")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot disable IPv6 on {ifname} ({e}) - the allowlist netns "
            "must be IPv4-only, fail closed") from e


def _run_ip(args: list[str], timeout: float = 5.0) -> None:
    """Run ``ip <args>```. Raises NamespaceSetupError on failure.
    """
    try:
        result = subprocess.run(
            ["ip"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            raise NamespaceSetupError(
                f"ip {' '.join(args)} failed: {result.stderr.strip()} "
                "- fail closed, allowlist network not established")
    except FileNotFoundError:
        raise NamespaceSetupError(
            "ip command not found - fail closed")
    except subprocess.TimeoutExpired:
        raise NamespaceSetupError(
            f"ip {' '.join(args)} timed out - fail closed")


def setup_allowlist_veth(sandbox_pid: int,
                         proxy_port: int = _PROXY_PORT) -> None:
    """Supervisor-side orchestration: create the veth pair, move one end
    into the sandbox's netns, configure the host-side end, and install
    the host-side firewall that makes the proxy the sandbox's ONLY path.

    Called AFTER the sandbox child has created its network namespace
    (reported its PID via the ctl pipe), but BEFORE the workload runs.
    The sandbox child must then call ``configure_sandbox_side_veth()``
    from inside the netns to complete the configuration.

    Raises NamespaceSetupError on any failure (fail closed).
    """
    create_veth_pair()
    move_veth_to_netns(_VETH_SANDBOX, sandbox_pid)
    configure_host_side_veth(proxy_port)
    # The sandbox's default route points at the host veth endpoint, so
    # WITHOUT host-side filtering the sandbox could reach host-local
    # services directly (traffic arriving on veth-sbx-h destined to a
    # host address is delivered locally) - bypassing the proxy entirely.
    # install_host_firewall makes the proxy port the ONLY accepted
    # destination from the veth interface (fail closed on any failure).
    install_host_firewall(proxy_port)


def setup_allowlist_network_from_sandbox() -> None:
    """Sandbox-side (inside the netns) completion of the veth-pair setup:
    configure the sandbox-side interface and set the default route.

    This MUST be called from inside the sandbox netns, AFTER the
    supervisor has moved the sandbox-side veth into the netns.
    Raises NamespaceSetupError on failure (fail closed).
    """
    configure_sandbox_side_veth()
    # Ensure loopback remains down (deny-by-construction for lo)
    ensure_loopback_down()


def verify_allowlist_network(host_netns: str,
                            proxy_port: int = _PROXY_PORT) -> NetworkState:
    """Verify the sandbox netns is in the allowlist network state:
    exactly one non-loopback interface (veth-sbx-s), the veth is UP,
    the expected /31 address is assigned, the default route points to
    the host-side proxy, and the netns is distinct from the host.

    The loopback interface remains DOWN (deny-by-construction for lo;
    the proxy path goes through the veth only).

    Raises NamespaceSetupError on any verification failure (fail closed).
    """
    problems: list[str] = []
    try:
        dev = _read_proc_net("dev")
        route = _read_proc_net("route")
        ipv6_route = _read_proc_net("ipv6_route")
        fib_trie = _read_proc_net("fib_trie")
        if_inet6 = _read_proc_net("if_inet6")
    except NamespaceSetupError as e:
        raise NamespaceSetupError(
            f"allowlist network verification failed: {e}") from e

    names = _parse_dev_names(dev)
    # Allow list mode: expect ["lo", "veth-sbx-s"] (order may vary)
    expected = {"lo", _VETH_SANDBOX}
    actual = set(names)
    if actual != expected:
        problems.append(
            f"unexpected interfaces in allowlist netns: {names} "
            f"(expected exactly {sorted(expected)})")

    # lo must remain DOWN
    try:
        lo_flags = _if_flags("lo")
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read lo flags during allowlist verification: {e}") from e
    loopback_down = not bool(lo_flags & IFF_UP)
    if not loopback_down:
        problems.append("loopback is UP - allowlist mode requires lo DOWN")

    # veth must be UP
    try:
        veth_flags = _if_flags(_VETH_SANDBOX)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read {_VETH_SANDBOX} flags: {e} - fail closed") from e
    veth_up = bool(veth_flags & IFF_UP)
    if not veth_up:
        problems.append(
            f"{_VETH_SANDBOX} is DOWN - allowlist mode requires it UP")

    # Check for the /31 address on the veth
    v4_addrs = _parse_fib_trie_addresses(fib_trie)
    # The sandbox IP should be in the addresses
    if _SANDBOX_IPPlain not in v4_addrs:
        problems.append(
            f"expected sandbox IP {_SANDBOX_IPPlain} not found in "
            f"addresses: {v4_addrs}")

    # The allowlist path is IPv4-only (the /31 link to the proxy):
    # unexpected IPv6 addresses are refused (mirrors the deny version).
    v6_addrs = _parse_if_inet6_addresses(if_inet6)
    if v6_addrs:
        problems.append(
            f"unexpected IPv6 addresses in allowlist netns: {v6_addrs}")

    # IPv6 routes (fresh-netns ::/0 dev lo entries on some kernels) must
    # reference ONLY the loopback - nothing usable off the /31 link.
    non_lo = [d for d in _parse_route_devices(ipv6_route) if d != "lo"]
    if non_lo:
        problems.append(
            f"IPv6 routes reference non-loopback device(s) {non_lo} - "
            "no host device may be reachable")

    # Check for a default route via the host-side proxy
    route_lines = [l for l in route.splitlines()
                   if l.strip() and not l.startswith("Iface")]
    has_default_route = False
    for line in route_lines:
        parts = line.split()
        # /proc/net/route format: Iface Destination Gateway Flags ...
        if len(parts) >= 3 and parts[1] == "00000000":  # 0.0.0.0 default
            has_default_route = True
            break
    if not has_default_route:
        problems.append("no default route found in allowlist netns")

    # Netns must be distinct from host
    try:
        with open("/proc/self/ns/net", "r", encoding="ascii") as f:
            own = str(os.fstat(f.fileno()).st_ino)
    except OSError as e:
        raise NamespaceSetupError(
            f"cannot read own netns identity: {e} - fail closed") from e
    distinct = bool(host_netns) and own != host_netns
    if not distinct:
        problems.append(
            "sandbox netns is not distinct from host netns "
            f"(own {own}, host {host_netns!r})")

    if problems:
        raise NamespaceSetupError(
            "allowlist network verification failed: "
            + "; ".join(problems))
    return NetworkState(
        interfaces=tuple(names), loopback_down=loopback_down,
        ipv4_addresses=tuple(v4_addrs), ipv6_addresses=tuple(v6_addrs),
        ipv4_routes=len(route_lines),
        non_loopback_route_devices=(),
        netns_distinct_from_host=distinct)


def install_host_firewall(proxy_port: int = _PROXY_PORT) -> None:
    """Install the host-side firewall that confines the sandbox to the
    validating proxy (v0.2 Step 3; the destination enforcement the v0.2
    Step 2 docs list as outstanding). On the HOST-side veth interface
    (the sandbox's only physical path out):

    - INPUT: accept only TCP to the proxy port; DROP everything else
      (host-local services on any other host address/port are
      unreachable from the sandbox - no arbitrary host access).
    - FORWARD: DROP all traffic from the veth interface (no routing
      through the host to any other network).

    Requires the ``iptables`` binary and CAP_NET_ADMIN in the host netns.
    Any failure raises NamespaceSetupError (fail closed - the allowlist
    network is NOT established without destination enforcement). The
    rules are removed by ``remove_host_firewall`` during teardown.
    """
    _run_iptables([
        "-A", "INPUT", "-i", _VETH_HOST, "-p", "tcp",
        "--dport", str(proxy_port), "-j", "ACCEPT",
    ])
    _run_iptables(["-A", "INPUT", "-i", _VETH_HOST, "-j", "DROP"])
    _run_iptables(["-A", "FORWARD", "-i", _VETH_HOST, "-j", "DROP"])


def remove_host_firewall() -> None:
    """Best-effort removal of the host firewall rules (teardown, not a
    security gate - failures are ignored). Idempotent: missing rules are
    tolerated (the iptables delete of an absent rule is non-fatal)."""
    _run_iptables_best_effort([
        "-D", "INPUT", "-i", _VETH_HOST, "-p", "tcp",
        "--dport", str(_PROXY_PORT), "-j", "ACCEPT",
    ])
    _run_iptables_best_effort([
        "-D", "INPUT", "-i", _VETH_HOST, "-j", "DROP"])
    _run_iptables_best_effort([
        "-D", "FORWARD", "-i", _VETH_HOST, "-j", "DROP"])


def _run_iptables(args: list[str]) -> None:
    """Run ``iptables <args>``. Raises NamespaceSetupError on failure.
    """
    try:
        result = subprocess.run(
            ["iptables"] + args,
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            raise NamespaceSetupError(
                f"iptables {' '.join(args)} failed: "
                f"{result.stderr.strip()} - fail closed, allowlist "
                "destination enforcement not established")
    except FileNotFoundError:
        raise NamespaceSetupError(
            "iptables command not found - cannot confine the sandbox to "
            "the proxy, fail closed")
    except subprocess.TimeoutExpired:
        raise NamespaceSetupError(
            f"iptables {' '.join(args)} timed out - fail closed")


def _run_iptables_best_effort(args: list[str]) -> None:
    try:
        subprocess.run(
            ["iptables"] + args,
            capture_output=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def cleanup_veth_pair() -> None:
    """Best-effort cleanup of the host firewall rules and the host-side
    veth pair. Called by the supervisor during session teardown.
    Failures are logged but do not raise (cleanup is best-effort, not a
    security gate). The sandbox-side veth disappears when the sandbox
    netns is destroyed.
    """
    remove_host_firewall()
    for ifname in (_VETH_HOST, _VETH_SANDBOX):
        try:
            subprocess.run(
                ["ip", "link", "del", ifname],
                capture_output=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
