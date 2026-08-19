"""Network namespace deny-by-construction state (Phase 1 Step 5, ADR-006).

The sandbox's network namespace (created by unshare(CLONE_NEWNET) in Step
2) is configured into its final v0.1 state here: loopback DOWN, no
addresses, no usable routes, no host interfaces, no path out. The kernel
already provides this as the FRESH-netns default; this module makes the
intent explicit (ensure lo down), VERIFIES the resulting state (never
trusts syscall success), and REFUSES on any unexpected element (fail
closed - an unexpected interface/route/address is a boundary violation,
never a warning-and-continue).

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
