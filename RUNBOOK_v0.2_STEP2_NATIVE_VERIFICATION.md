# v0.2 Step 2 — Allowlist Network Plumbing + Socket Domain Filtering — Native Verification Runbook

> **Status: PLUMBING COMPLETE, PROXY/FIREWALL OUTSTANDING**
>
> This runbook documents the exact commands, expected results, and
> pass/fail criteria for natively verifying the v0.2 Step 2 allowlist
> network plumbing (veth pair + socket domain argument filtering) on the
> Ubuntu 24.04 / kernel 6.8 / x86_64 QEMU VM, plus the explicitly
> outstanding work (validating proxy, host-side iptables/nftables) that
> must land before `network_mode="allowlist"` provides real outbound
> networking.

---

## 1. What this step delivers (and what it does NOT)

### Delivered

| Item | Where | Status |
|---|---|---|
| `network_mode` config accepts `deny` (default) and `allowlist` | `config.py` | IMPLEMENTED |
| Veth pair plumbing: create / move-to-netns / configure host side / configure sandbox side / verify / cleanup | `isolation/network.py` | IMPLEMENTED |
| Supervisor↔PID-1 net-ready pipe wiring in `run_in_sandbox` | `isolation/setup.py` | IMPLEMENTED |
| Socket argument-level filtering: `socket` allowlisted but restricted to `AF_INET` (2) / `AF_INET6` (10); all other domains EPERM | `isolation/seccomp.py` | IMPLEMENTED |
| Enforcement spot check switched to `socketpair()` (denied) | `isolation/seccomp.py` | IMPLEMENTED |
| Seccomp count unchanged | 69 = tier0 29 + tier1 40 | UNCHANGED |

### NOT delivered (outstanding Step 2 substeps — explicit)

| Item | Status |
|---|---|
| Host-side **validating proxy** process (listens on the host veth endpoint, validates destinations, forwards) | **NOT IMPLEMENTED** |
| Host-side **iptables/nftables** destination restriction on the host endpoint | **NOT IMPLEMENTED** |

Consequence: with `network_mode="allowlist"` today, the sandbox has a
veth and a default route into a **dead** host endpoint — no workload can
reach any external destination. The mode exists so the plumbing and its
verification are in place and honest; it is NOT a working outbound
network mode. Do not describe it as one.

---

## 2. Root requirement (documented, preserved)

- `tests/unit/test_network_veth.py::VethIntegrationTests::test_create_and_cleanup_veth_pair`
  requires **root**: veth-pair creation needs `CAP_NET_ADMIN` in the
  initial user namespace. The test explicitly skips (`os.geteuid() != 0`
  → `skipTest("veth operations require root")`) when unprivileged.
- Run it with `sudo` on the native VM:
  ```bash
  sudo python3 -m unittest tests.unit.test_network_veth -v
  ```
  Expected: `test_create_and_cleanup_veth_pair ... ok` (plus the
  host-side tests), `OK`.
- **Do NOT** convert the pre-existing root-premise failure
  (`test_host_caller_remains_unprivileged` — asserts a non-root caller,
  fails only because the run is root) into a pass. Its classification is
  preserved; it is an environment-premise result, not a sandbox
  boundary failure.

---

## 3. Socket domain filtering verification (native VM, root not required)

Under the installed HARDENED filter, verify the domain matrix:

```bash
python3 -c "
import socket, os
def probe(dom, kind):
    try:
        s = socket.socket(dom, kind); s.close(); return 'ALLOWED'
    except OSError as e:
        return f'EPERM' if e.errno == 1 else f'errno:{e.errno}'
print('AF_UNIX   ', probe(socket.AF_UNIX, socket.SOCK_STREAM))
print('AF_INET   ', probe(socket.AF_INET, socket.SOCK_STREAM))
print('AF_INET6  ', probe(getattr(socket, 'AF_INET6', 10), socket.SOCK_STREAM))
print('AF_NETLINK', probe(getattr(socket, 'AF_NETLINK', 16), socket.SOCK_RAW))
print('AF_PACKET ', probe(getattr(socket, 'AF_PACKET', 17), socket.SOCK_RAW))
try:
    s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM); print('socketpair ALLOWED'); s1.close(); s2.close()
except OSError as e:
    print('socketpair', 'EPERM' if e.errno == 1 else f'errno:{e.errno}')
"
```

Expected (run INSIDE the sandbox under the filter):

| Probe | Expected |
|---|---|
| AF_UNIX | EPERM (denied by domain filter — S-003/S-004 preserved) |
| AF_INET | ALLOWED (proxy path) |
| AF_INET6 | ALLOWED if the kernel/glibc supports it (denied filter path otherwise) |
| AF_NETLINK | EPERM |
| AF_PACKET | EPERM |
| socketpair | EPERM (denied syscall in both modes) |

---

## 4. Allowlist-network end-to-end checks (native VM, root)

With `network_mode="allowlist"` and a running sandbox:

1. **Sandbox netns state** (verified in PID 1 by
   `verify_allowlist_network`):
   - interfaces exactly `{lo, veth-sbx-s}`; lo DOWN; veth UP
   - sandbox IP `10.255.254.1/31` assigned to the veth
   - default route via `10.255.254.0`
   - netns distinct from host
2. **Host-side state** (supervisor): `veth-sbx-h` exists with
   `10.255.254.0/31`, UP.
3. **Cleanup**: after session destroy, host-side `veth-sbx-h` is gone
   (`cleanup_veth_pair`); the sandbox-side veth disappears with the
   netns. No interface residue remains.

```bash
# host side, before/after a run
ip link show veth-sbx-h    # exists during run, gone after destroy
ip addr show veth-sbx-h    # 10.255.254.0/31
```

---

## 5. Failure-path verification (fail closed)

| Failure | Expected |
|---|---|
| `ip` command missing | `NamespaceSetupError` "ip command not found" — workload not executed |
| `ip link add` non-zero | `NamespaceSetupError` "veth pair creation failed" — fail closed |
| move-to-netns fails (bad PID) | `NamespaceSetupError` "moving … failed" — fail closed |
| sandbox PID 1 unknown at veth time | `NamespaceSetupError` "sandbox PID 1 unknown" — fail closed, `net_ready` written `0` |
| no net-ready signal to PID 1 | `NamespaceSetupError` "veth setup did not complete" — fail closed |
| unexpected interface in allowlist netns | `verify_allowlist_network` refuses |

All covered by `test_network_veth.py` host-side fail-closed tests (PASS)
plus the `run_in_sandbox` wiring in `setup.py`.

---

## 6. Full verification checklist

| # | Check | Command | Expected | PASS/FAIL |
|---|---|---|---|---|
| 1 | Seccomp count unchanged | `len(allowlist)==69`, tier0 29 + tier1 40 | 69 | |
| 2 | BPF layout (domain sub-chain) | `python3 -m unittest tests.unit.test_seccomp -v` | PASS | |
| 3 | Veth host-side suite | `python3 -m unittest tests.unit.test_network_veth -v` | PASS (root test skipped unprivileged) | |
| 4 | Veth root integration | `sudo python3 -m unittest tests.unit.test_network_veth.VethIntegrationTests -v` | PASS | |
| 5 | Socket domain matrix | §3 probe inside sandbox | AF_UNIX/NETLINK/PACKET/socketpair EPERM; AF_INET allowed | |
| 6 | Deny-mode regression | `python3 -m unittest tests.unit.test_network -v` | PASS (connect fails, no usable path) | |
| 7 | Credential isolation | `python3 -m unittest tests.unit.test_credentials -v` | PASS (S-003/S-004) | |
| 8 | N1 fail-closed matrix | `python3 -m unittest tests.unit.test_failclosed_matrix -v` | PASS | |
| 9 | Fuzz suite | `python3 -m unittest discover -s tests/fuzz -t . -v` | PASS | |
| 10 | Adversarial suite | `python3 -m unittest discover -s tests/adversarial -t . -v` | PASS | |
| 11 | Full unit discover | `python3 -m unittest discover -s tests -t . -v` | 0 failures; documented skips only | |
| 12 | HARDENED e2e | `python3 -m unittest tests.native.test_hardened_e2e -v` | PASS (24/24) | |
| 13 | Allowlist e2e (proxy pending) | §4 | plumbing state verified; no outbound traffic expected (proxy NOT implemented) | |

---

## 7. Outstanding work (next Step 2 substeps — must be recorded, not hidden)

1. **Validating proxy** — a host-side process listening on the host veth
   endpoint that validates each outbound destination against the
   allowlist (S-005/S-006/S-007, SSRF/DNS-rebinding-aware per ADR-006
   and design §12–13) before forwarding. Until it exists,
   `network_mode="allowlist"` cannot provide outbound networking.
2. **Host-side iptables/nftables** destination restriction on the host
   endpoint (defense-in-depth; the proxy must not be bypassable by
   routing tricks inside the sandbox).
3. Update this runbook + README + THREAT_MODEL to "proxy VERIFIED" once
   the proxy lands, with native destination-enforcement evidence.

---

## 8. Post-verification steps

1. Record the exact native VM environment (uname, kernel, Python).
2. Record pass/fail per the checklist above.
3. Record the socket-domain matrix output (§3) verbatim as evidence.
4. Update `docs/seccomp-derivation/verification.md` with the native
   results (this runbook is the checklist; the verification record is
   the evidence).
5. Report to the workspace owner for commit authorization.
6. **Do NOT commit until explicitly authorized.**
