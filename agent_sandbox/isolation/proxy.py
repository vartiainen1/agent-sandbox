"""Host-side validating forward proxy (v0.2 Step 3, ADR-006 extension).

The allowlist network path (ARCHITECTURE.md section 8) is a veth pair
between the sandbox netns and the host plus this host-side proxy. The
sandbox has exactly one route: its default route through the /31 link to
the host endpoint (``veth-sbx-h``). ALL outbound traffic from the
sandbox is therefore a TCP connection to this proxy - the sandbox has no
other path out (no interfaces, no routes, loopback down, and the seccomp
filter restricts socket creation to AF_INET/AF_INET6, both of which
require the routing path).

The proxy enforces the destination allowlist (``network_allowlist``):

- A workload connects to the proxy and sends ONE request line::

      CONNECT <host> <port>\\r\\n

  ``<host>`` is a hostname or an IPv4 literal; ``<port>`` is 1..65535.
- The proxy validates the destination against the operator-supplied
  allowlist (host + port must match an entry) and then validates the
  RESOLVED addresses (SSRF protection, security spec section 13): the
  target must not be loopback, link-local, multicast, unspecified,
  reserved, or a private range - unless the allowlist entry explicitly
  sets ``allow_private`` (which relaxes ONLY the private-range check;
  loopback / link-local / metadata endpoints such as 169.254.169.254
  remain denied unconditionally).
- Allowed -> ``OK\\n`` and a bidirectional byte stream to the target.
  Denied or malformed -> ``DENIED <reason>\\n`` and the connection is
  closed. Any parse/validation ambiguity fails closed.

The proxy runs HOST-SIDE as a child of the session supervisor (trusted
code, ADR-002). It is spawned only when ``network_mode=\"allowlist\"``
and is verified listening BEFORE the sandbox is released to run the
workload (fail closed). It binds ONLY to the host-side veth IP, never to
a wildcard, so it is unreachable from any other host interface.

DNS rebinding is mitigated structurally: hostname resolution happens in
the TRUSTED proxy, never in the sandbox, and every resolved address must
independently pass the SSRF checks at connect time.

IPv6 is not supported by the v0.2 proxy (the /31 link is IPv4-only and
the allowlist netns verification refuses IPv6 addresses); an IPv6
destination is denied by ``is_blocked_ip``.

Process model: the supervisor forks ONE proxy process (the listener).
The listener forks one handler process per accepted connection (inetd
style) so a stalled or hostile connection cannot block others. On
SIGTERM the listener kills and reaps its handlers and exits 0 - the
supervisor's teardown is ``terminate_proxy`` (SIGTERM + bounded reap),
so no proxy or handler process survives a session (no leaked
processes/sockets; handler sockets are closed by the kernel on exit).

Windows: the module is import-safe on any platform (pure stdlib); the
process functions fail closed with a clear error where ``os.fork`` is
unavailable.
"""

from __future__ import annotations

import ipaddress
import os
import re
import select
import signal
import socket
import time

from agent_sandbox.isolation.errors import NamespaceSetupError

# The request protocol: exactly one line, three tokens, verb "CONNECT".
_REQUEST_VERB = "CONNECT"
_MAX_REQUEST_LINE = 4096  # bound on the request line (fail closed beyond)
_SHUTTLE_BUF = 65536
_CONNECT_TIMEOUT = 10.0   # upstream connect bound (fail closed on timeout)
_SHUTTLE_IDLE = 30.0      # idle bound on an established tunnel

_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IPV4_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
# Any all-numeric dotted string ("08.8.8.8", "1.2.3", "127.1"): an
# alternate/confused IP representation that must NEVER pass as a
# hostname (security spec section 13 - alternate address forms).
_DOTTED_NUMERIC_RE = re.compile(r"^\d+(\.\d+)+")
# RFC 6598 shared address space (100.64.0.0/10) - classified as private.
_RFC6598_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


# ---------------------------------------------------------------------------
# Pure validation (host-side, deterministic; unit-tested without a network)
# ---------------------------------------------------------------------------

def validate_host(host: str) -> bool:
    """A well-formed destination host: a DNS hostname or a strict IPv4
    literal (4 dotted decimal octets, no leading zeros, no shorthand).
    Alternate/confused IP representations ("08.8.8.8", "1.2.3",
    "127.1", "2130706433") are rejected - they are neither a strict
    literal nor a legitimate hostname and must never pass the syntax
    gate (security spec section 13)."""
    if not isinstance(host, str) or not host:
        return False
    if is_ipv4_literal(host):
        return True
    if _DOTTED_NUMERIC_RE.match(host) or host.isdigit():
        return False
    if len(host) > 253 or host.endswith("."):
        return False
    return all(_HOSTNAME_LABEL.match(part) is not None
               for part in host.split("."))


def is_ipv4_literal(host: str) -> bool:
    m = _IPV4_RE.match(host)
    if m is None:
        return False
    return all(0 <= int(part) <= 255 for part in m.groups())


def is_blocked_ip(ip: str) -> str | None:
    """SSRF classification of one IPv4 address. Returns a deterministic
    reason if the address is blocked, None if it is a permitted target.

    Always blocked (never relaxable): loopback (host itself), link-local
    (includes the cloud-metadata endpoint 169.254.169.254), multicast,
    unspecified, reserved, and IPv6 (the v0.2 path is IPv4-only).
    Private ranges (RFC 1918 / RFC 6598) are blocked unless the allowlist
    entry explicitly opts in via ``allow_private``.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return "not a valid IPv4 address"
    if addr.is_loopback:
        return "loopback destination denied"
    if addr.is_link_local:
        return "link-local destination denied (includes cloud metadata)"
    if addr.is_multicast:
        return "multicast destination denied"
    if addr.is_unspecified:
        return "unspecified address denied"
    if addr.is_reserved:
        return "reserved address denied"
    # RFC 6598 (100.64.0.0/10, shared address space) is classified as a
    # private-range block - explicit check so the classification does not
    # depend on the Python version's is_private behavior.
    if addr in _RFC6598_NETWORK or addr.is_private:
        return "private range destination denied (requires allow_private)"
    return None


_PRIVATE_BLOCK_REASON = "private range destination denied (requires allow_private)"


_HTTP_VERSION_RE = re.compile(r"^HTTP/\d+(\.\d+)?$")


def parse_connect_request(line: str) -> tuple[str, int] | None:
    """Parse one CONNECT request line. Returns ``(host, port)`` or None
    (malformed -> fail closed).

    Two wire forms are accepted (the second is the STANDARD HTTP CONNECT
    form, which lets stock clients - pip/curl/requests with a proxy URL -
    use the validating proxy unchanged):

    - ``CONNECT <host> <port>``            (the v0.2 Step 3 native form)
    - ``CONNECT <host>:<port> [HTTP/1.1]`` (standard HTTP CONNECT)

    The host must pass ``validate_host`` (a hostname or strict IPv4
    literal) and the port must be 1..65535. Anything else - wrong verb,
    extra tokens, a non-decimal port, an absent port - is None (fail
    closed)."""
    if not isinstance(line, str):
        return None
    stripped = line.strip()
    if len(stripped) > _MAX_REQUEST_LINE:
        return None
    parts = stripped.split()
    if not parts or parts[0] != _REQUEST_VERB:
        return None
    host = None
    port_text = None
    if len(parts) == 2:
        # CONNECT <host>:<port>
        host, port_text = _split_target(parts[1])
    elif len(parts) == 3:
        # CONNECT <host> <port>            (native form)
        # CONNECT <host>:<port> HTTP/1.x   (standard HTTP CONNECT -
        #   stock clients send exactly this; note it is THREE tokens)
        a, b = parts[1], parts[2]
        if b.isdigit() and validate_host(a):
            host, port_text = a, b
        elif _HTTP_VERSION_RE.match(b):
            host, port_text = _split_target(a)
    # else: four-or-more tokens, wrong verb -> rejected below.
    if host is None:
        return None
    if not validate_host(host):
        return None
    if port_text is None or not port_text.isdigit():
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    return host, port


def _split_target(target: str) -> tuple[str | None, str | None]:
    """Split a ``host:port`` target. Returns ``(host, port_text)`` or
    ``(None, None)`` for anything that is not exactly one colon (an IPv6
    literal or a bare host is rejected - the v0.2 proxy is
    IPv4/hostname-only)."""
    if target.count(":") != 1:
        return None, None
    return target.rsplit(":", 1)


def _hosts_match(a: str, b: str) -> bool:
    """Allowlist host matching: hostname-vs-hostname is case-insensitive,
    IPv4 literal-vs-IPv4 literal is exact; a hostname never matches an
    IP literal and vice versa (the proxy resolves hostnames at runtime
    and SSRF-checks the resolved addresses - the literal itself is not a
    proxy for a hostname allow entry)."""
    if is_ipv4_literal(a) or is_ipv4_literal(b):
        return is_ipv4_literal(a) and is_ipv4_literal(b) and a == b
    return a.casefold() == b.casefold()


def match_allowlist(host: str, port: int, allowlist) -> object | None:
    """Return the first allowlist entry matching ``host`` and ``port``,
    or None. Entries are the validated ``NetworkAllow`` objects from the
    configuration (host + port + optional ``allow_private``)."""
    for entry in allowlist:
        if entry.port == port and _hosts_match(host, entry.host):
            return entry
    return None


def resolve_host(host: str) -> tuple[bool, str, list[str]]:
    """Resolve ``host`` host-side. Returns ``(ok, reason, ips)``. An IPv4
    literal resolves to itself. A hostname is resolved over AF_INET;
    resolution failure is a denial (fail closed - the destination cannot
    be validated, so it must not be reachable)."""
    if is_ipv4_literal(host):
        return True, "", [host]
    try:
        infos = socket.getaddrinfo(
            host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as e:
        return False, f"hostname resolution failed: {e}", []
    ips: list[str] = []
    for info in infos:
        # AF_INET is requested explicitly, so the sockaddr's first
        # element is the dotted-quad string (typeshed types it str|int
        # for the IPv6 variant; convert defensively).
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return False, "hostname resolved to no addresses", []
    return True, "", ips


def check_destination(host: str, port: int, allowlist) -> tuple[bool, str, str | None]:
    """The single destination gate: syntax + allowlist + SSRF. Returns
    ``(allowed, reason, target_ip)``. ``target_ip`` is the first
    permitted resolved address. Every failure is deterministic and names
    the reason (fail closed - an unvalidatable destination is denied)."""
    if not validate_host(host):
        return False, f"malformed destination host {host!r}", None
    entry = match_allowlist(host, port, allowlist)
    if entry is None:
        return False, f"destination {host}:{port} not in allowlist", None
    ok, reason, ips = resolve_host(host)
    if not ok:
        return False, reason, None
    allow_private = bool(getattr(entry, "allow_private", False))
    for ip in ips:
        blocked = is_blocked_ip(ip)
        if blocked is None:
            continue
        if allow_private and blocked == _PRIVATE_BLOCK_REASON:
            continue
        return False, f"{blocked} ({ip})", None
    return True, "allowed by allowlist", ips[0]


def is_allowed_allow_entry(host: str, allow_private: bool) -> str | None:
    """Config-time validation of one allowlist entry's host. Returns
    None if the entry is forwardable in principle, or a deterministic
    reason why it can NEVER be forwarded (fail closed - reject dead
    allowlist entries at configuration time). Hostname entries always
    return None: resolution happens at runtime and the proxy enforces
    the SSRF checks on every resolved address."""
    if not is_ipv4_literal(host):
        return None
    blocked = is_blocked_ip(host)
    if blocked is None:
        return None
    if allow_private and blocked == _PRIVATE_BLOCK_REASON:
        return None
    return blocked


# ---------------------------------------------------------------------------
# The proxy process (Linux; fails closed where os.fork is unavailable)
# ---------------------------------------------------------------------------

def spawn_proxy(allowlist, listen_ip: str = "127.0.0.1",
                port: int = 8080, close_fds: tuple[int, ...] = ()) -> int:
    """Fork a host-side validating proxy. Returns the listener pid.

    ``close_fds`` lists file descriptors the proxy child must close
    immediately (the session's sandbox pipes - the proxy is a host-side
    helper and must never hold a sandbox boundary fd). Raises
    NamespaceSetupError on failure (fail closed).

    The supervisor MUST probe ``proxy_listening`` before releasing the
    sandbox: a proxy that is not listening means the workload cannot
    reach its only path out, and the run must fail closed.
    """
    if not hasattr(os, "fork"):
        raise NamespaceSetupError(
            "validating proxy requires os.fork (Linux) - fail closed, "
            "allowlist network not established")
    _flush_io()
    pid = os.fork()
    if pid != 0:
        return pid
    # Proxy child: drop inherited sandbox pipes, start a new session, run
    # the accept loop (never returns; exits via SIGTERM or failure).
    for fd in close_fds:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.setsid()
    except OSError:
        pass
    try:
        run_proxy(allowlist, listen_ip, port)
    except BaseException:
        pass
    os._exit(1)


def run_proxy(allowlist, listen_ip: str, port: int) -> None:
    """The listener accept loop (runs in the forked proxy child). Binds
    ONLY to ``listen_ip`` - never a wildcard. Forks one handler per
    accepted connection. On SIGTERM: kills + reaps handlers, exits 0."""
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen.bind((listen_ip, port))
        listen.listen(16)
    except OSError as e:
        listen.close()
        raise NamespaceSetupError(
            f"proxy bind/listen on {listen_ip}:{port} failed: {e} - "
            "fail closed, allowlist network not established") from e

    stop = {"flag": False}

    def _on_sigterm(signum, frame):
        stop["flag"] = True

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError):  # pragma: no cover - not in main thread
        pass

    # A short accept timeout is REQUIRED for prompt shutdown: PEP 475
    # makes Python retry a signal-interrupted accept() transparently, so
    # the SIGTERM handler's stop flag would otherwise never be re-checked
    # (the listener would ignore SIGTERM). With a bounded accept timeout
    # the loop wakes periodically and exits within one timeout period.
    listen.settimeout(0.5)

    children: set[int] = set()
    try:
        while not stop["flag"]:
            try:
                conn, _addr = listen.accept()
            except OSError:
                continue
            if stop["flag"]:
                try:
                    conn.close()
                except OSError:
                    pass
                break
            pid = os.fork()
            if pid == 0:
                # Handler: closes the inherited listener, serves one
                # connection, exits.
                try:
                    listen.close()
                except OSError:
                    pass
                try:
                    _handle(conn, allowlist)
                except BaseException:
                    pass
                os._exit(0)
            children.add(pid)
            try:
                conn.close()
            except OSError:
                pass
    finally:
        try:
            listen.close()
        except OSError:
            pass
        # Shutdown: the handlers hold only socket fds (no state) - kill
        # and reap them so no proxy process survives the session.
        for cpid in list(children):
            try:
                os.kill(cpid, signal.SIGKILL)
            except OSError:
                pass
        for cpid in list(children):
            try:
                os.waitpid(cpid, 0)
            except OSError:
                pass


def _handle(client: socket.socket, allowlist) -> None:
    """Serve one CONNECT request: read the request line, gate the
    destination, then either deny (fail closed) or bridge the client to
    the validated target."""
    client.settimeout(_CONNECT_TIMEOUT)
    try:
        line = _read_request_line(client)
        parsed = parse_connect_request(line) if line else None
        http = _request_is_http(line)
        if parsed is None:
            _deny(client, "malformed CONNECT request", http=http)
            return
        host, port = parsed
        allowed, reason, target_ip = check_destination(host, port, allowlist)
        if not allowed:
            _deny(client, reason, http=http)
            return
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            upstream.settimeout(_CONNECT_TIMEOUT)
            upstream.connect((target_ip, port))
        except OSError as e:
            upstream.close()
            _deny(client, f"upstream connection failed: {e}", http=http)
            return
        client.settimeout(None)
        upstream.settimeout(None)
        try:
            # Reply in the client's own protocol: stock HTTP CONNECT
            # clients (pip/curl/requests) parse the proxy's response as
            # an HTTP status line; the native v0.2 Step 3 clients expect
            # the bare ``OK`` line.
            if http:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                client.sendall(b"OK\n")
        except OSError:
            client.close()
            upstream.close()
            return
        _shuttle(client, upstream)
        client.close()
        upstream.close()
    except OSError:
        try:
            client.close()
        except OSError:
            pass


def _read_request_line(client: socket.socket) -> str:
    """Read the request line: bytes up to and including the first LF,
    bounded to _MAX_REQUEST_LINE bytes (a longer or LF-less stream is
    malformed -> fail closed)."""
    buf = b""
    while b"\n" not in buf:
        chunk = client.recv(256)
        if not chunk:
            break
        buf += chunk
        if len(buf) > _MAX_REQUEST_LINE:
            return ""
    line = buf.split(b"\n", 1)[0].rstrip(b"\r")
    try:
        return line.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return ""


def _request_is_http(line: str) -> bool:
    """True when the request line is the standard HTTP CONNECT form
    (``CONNECT host:port HTTP/1.x`` - the client parses the proxy reply
    as HTTP). The native v0.2 Step 3 form (``CONNECT host port``)
    expects the bare ``OK``/``DENIED`` lines."""
    if not isinstance(line, str):
        return False
    parts = line.strip().split()
    return (len(parts) == 3
            and parts[1].count(":") == 1
            and _HTTP_VERSION_RE.match(parts[2]) is not None)


def _deny(client: socket.socket, reason: str, http: bool = False) -> None:
    """Fail-closed reply in the client's own protocol (HTTP status line
    for HTTP CONNECT clients, bare DENIED line for the native clients),
    then close."""
    try:
        if http:
            body = f"{reason}\n".encode("ascii", errors="replace")
            client.sendall(
                f"HTTP/1.1 403 Forbidden\r\nContent-Length: "
                f"{len(body)}\r\n\r\n".encode("ascii") + body)
        else:
            client.sendall(
                f"DENIED {reason}\n".encode("ascii", errors="replace"))
    except OSError:
        pass
    try:
        client.close()
    except OSError:
        pass


def _shuttle(a: socket.socket, b: socket.socket) -> None:
    """Bidirectional byte bridge between the client and the upstream
    target. Reads from each side and forwards to the other; EOF on one
    side half-closes the other; returns when both sides are done or an
    idle bound expires (fail closed - a stalled tunnel is torn down)."""
    a_done = b_done = False
    while not (a_done and b_done):
        rlist = []
        if not a_done:
            rlist.append(a)
        if not b_done:
            rlist.append(b)
        try:
            ready, _, _ = select.select(rlist, [], [], _SHUTTLE_IDLE)
        except OSError:
            return
        if not ready:
            return  # idle bound expired
        for sock in ready:
            other = b if sock is a else a
            try:
                data = sock.recv(_SHUTTLE_BUF)
            except OSError:
                data = b""
            if data:
                try:
                    other.sendall(data)
                except OSError:
                    return
            else:
                if sock is a:
                    a_done = True
                else:
                    b_done = True
                try:
                    other.shutdown(socket.SHUT_WR)
                except OSError:
                    pass


def proxy_listening(listen_ip: str, port: int, timeout: float = 0.5) -> bool:
    """Probe whether the proxy is accepting connections (the supervisor's
    pre-release check). False on any failure - a proxy that cannot be
    reached means the sandbox's only path out is dead, fail closed."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((listen_ip, port))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def wait_proxy_listening(listen_ip: str, port: int,
                         timeout: float = 3.0) -> bool:
    """Poll ``proxy_listening`` until the proxy accepts a connection or
    the bounded deadline expires. The supervisor uses this after
    ``spawn_proxy``: the forked child needs a moment to bind+listen, so a
    single probe would race the child's startup. Expiry is a denial
    (fail closed - the sandbox's only path out was never live)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proxy_listening(listen_ip, port, timeout=0.25):
            return True
        time.sleep(0.05)
    return False


def terminate_proxy(pid: int, grace: float = 2.0) -> bool:
    """SIGTERM the proxy listener (which kills + reaps its handlers) and
    reap it within ``grace`` seconds; SIGKILL + reap as a backstop.
    Returns True when the process is reaped. Best-effort (teardown, not
    a security gate) - never raises."""
    if pid < 1:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.monotonic() + grace
    while True:
        try:
            got, _ = os.waitpid(pid, os.WNOHANG)
            if got == pid:
                return True
        except ChildProcessError:
            return True
        except OSError:
            return False
        if time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
        return True
    except ChildProcessError:
        return True
    except OSError:
        return False


def _flush_io() -> None:
    """Flush stdio before forking so the proxy child never duplicates
    buffered supervisor output."""
    import sys
    try:
        sys.stdout.flush()
    except OSError:
        pass
    try:
        sys.stderr.flush()
    except OSError:
        pass
