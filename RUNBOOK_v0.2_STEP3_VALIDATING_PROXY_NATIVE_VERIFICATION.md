# v0.2 Step 3 — Validating Proxy + Host Firewall — Native Verification Runbook

> **Status: COMPLETE (2026-08-23)**
>
> This runbook documents the exact commands, expected results, and
> pass/fail criteria for natively verifying the v0.2 Step 3 validating
> forward proxy and the host-side destination firewall. Verification was
> executed in a **privileged Linux container** (python:3.11-slim +
> `iproute2` + `iptables`, run with `--privileged` so the veth, iptables
> and user-namespace operations have the required privileges).

---

## 1. What this step delivers

| Item | Where | Status |
|---|---|---|
| Host-side **validating proxy** (CONNECT protocol, destination allowlist, SSRF gate, host-side DNS resolution, DNS-rebinding safe) | `agent_sandbox/isolation/proxy.py` | IMPLEMENTED |
| Host-side **iptables destination firewall** (INPUT: only the proxy port accepted from the veth; FORWARD: all veth traffic dropped) | `agent_sandbox/isolation/network.py::install_host_firewall` | IMPLEMENTED |
| `network_allowlist` configuration (strict validation; dead entries — loopback/metadata/private-without-opt-in — rejected; deny-mode consistency) | `agent_sandbox/config.py::NetworkAllow` | IMPLEMENTED |
| Supervisor wiring: spawn proxy AFTER the veth exists, PROBE it listening, release the sandbox only on success; terminate proxy + remove firewall + delete veth on teardown | `agent_sandbox/isolation/setup.py` | IMPLEMENTED |
| IPv4-only allowlist path: IPv6 disabled on the sandbox-side veth (a moved veth is auto-assigned a link-local IPv6, which the netns verification refuses) | `agent_sandbox/isolation/network.py::_disable_ipv6` | IMPLEMENTED |
| Seccomp count unchanged | 69 = tier0 29 + tier1 40 | UNCHANGED |
| AF_UNIX / AF_NETLINK / AF_PACKET remain denied (BPF argument filter) | `agent_sandbox/isolation/seccomp.py` | UNCHANGED |

### The protocol (documented in `proxy.py`)

```
workload -> 10.255.254.0:8080 :  CONNECT <host> <port>\r\n
proxy    -> workload          :  OK\n            (then a byte tunnel)
proxy    -> workload          :  DENIED <reason>\n
```

The proxy binds ONLY to the host-side veth IP (`10.255.254.0`), never a
wildcard. Hostnames are resolved HOST-SIDE at connect time; every
resolved address must pass the SSRF gate (loopback, link-local incl.
`169.254.169.254`, multicast, unspecified, reserved, RFC 1918/6598
denied; private ranges forwardable only via an explicit `allow_private`
entry, which never relaxes loopback/link-local/metadata).

### Known limitations (explicit)

- **IPv4-only upstream**: IPv6 destinations are denied (`is_blocked_ip`);
  the /31 link is IPv4 and the allowlist netns verification refuses IPv6.
- **Host firewall requires `iptables` + CAP_NET_ADMIN** in the host netns;
  without it `install_host_firewall` fails closed (the allowlist network
  is NOT established — the sandbox cannot be released on an unenforced
  path).
- **One concurrent allowlist session per host** (fixed veth interface
  names + firewall rules keyed on `veth-sbx-h`).
- The workload needs a CONNECT-protocol client (documented above); no
  client ships in the minimal rootfs (out of TCB scope).

---

## 2. Root/privilege requirements (documented, preserved)

- `tests/unit/test_proxy.py::ProxyProcessIntegrationTests` requires
  **Linux + os.fork** (proxy process tests); the sandbox e2e
  additionally requires **root + the `ip` and `iptables` binaries**
  (`FullSandboxProxyTests`). The pre-existing root-premise failures
  (`test_host_caller_remains_unprivileged`, `test_host_process_invisibility`)
  remain classified as environment-premise results — do not convert them.

---

## 3. Unit + host-side verification (no root needed)

```bash
python3 -m unittest tests.unit.test_proxy -v
```

Expected: `OK` — 59 tests (parsing, SSRF classification, allowlist
matching, DNS-rebinding denial, config dead-entry rejection, registry
round-trip; Linux-gated process tests skipped on non-Linux).

```bash
python3 -m unittest tests.unit.test_network_veth -v
```

Expected: `OK` — including the host-firewall fail-closed rows
(`iptables` missing / non-zero / timeout → `NamespaceSetupError`;
`setup_allowlist_veth` installs the three rules).

## 4. Proxy process integration (Linux, no root needed)

```bash
python3 -m unittest tests.unit.test_proxy.ProxyProcessIntegrationTests -v
```

Expected: 9/9 `ok` — allowed destination echoed through a real TCP
tunnel; disallowed destination / unauthorized port / private-without-
`allow_private` / malformed request / empty allowlist → `DENIED
<reason>`; proxy-down probe → False (fail closed); termination reaps the
listener AND its per-connection handlers (no leaked processes — verified
by a /proc process-group scan); spawn fails closed without `os.fork`.

## 5. Full-sandbox end-to-end (Linux + root + `ip` + `iptables`)

```bash
python3 -m unittest tests.unit.test_proxy.FullSandboxProxyTests -v
```

The workload runs INSIDE the real HARDENED sandbox with
`network_mode="allowlist"` and one allowlisted destination (a host-side
echo server, `allow_private=True`):

| Probe (from inside the sandbox) | Expected | Result (2026-08-23) |
|---|---|---|
| `CONNECT <echo-ip> <port>` through the proxy | `OK` + echoed payload | PASS (`"OK"`, `"ping-from-sandbox"`) |
| Direct TCP connect to the echo service (bypassing the proxy) | blocked (host firewall DROPs the SYN) | PASS (TimeoutError — the sandbox cannot bypass the proxy) |
| `socket(AF_UNIX)` creation | EPERM (BPF argument filter) | PASS (errno 1) |

Teardown evidence: after the run, `iptables -S` contains no `veth-sbx-h`
rules and `/sys/class/net` contains no `veth-sbx-*` interface.

## 6. Surrounding suites (regression)

```bash
python3 -m unittest tests.unit.test_network tests.unit.test_seccomp \
  tests.unit.test_credentials tests.unit.test_failclosed_matrix
python3 tools/seccomp-derivation/test_derivation.py
```

Expected: all OK (32 seccomp tests incl. the aarch64 socket-NR
regression), `RESULT: ALL PASS` for the derivation.

## 7. Static gates

```bash
ruff check agent_sandbox tests tools
mypy agent_sandbox
bandit -q -r agent_sandbox -x tests,tools --skip B101,B108,B606,B110,B603,B607 -ll
git diff --check
```

Expected: all clean.
