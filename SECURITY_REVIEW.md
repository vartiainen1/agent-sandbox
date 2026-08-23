# agent-sandbox — Independent Security Review Package

> **Status: NOT YET PERFORMED**
>
> This document is a **review-readiness evidence package** prepared for an
> independent external reviewer. It does NOT constitute a completed review.
> The independent security review required by implementation.md section 25
> has NOT been performed.
>
> The reviewer must be **independent of the primary author** (Vartiainen).

---

## 1. Repository State Under Review

| Item | Value |
|---|---|
| HEAD commit | `4944800` |
| v0.1.0 tag | `bb73386` (annotated, unsigned) |
| Working tree at preparation | CLEAN |
| Seccomp allowlist | 70 syscalls (tier0=29, tier1=41) |
| Runtime dependencies | zero (`dependencies = []`) |
| Architecture | x86_64 |
| Primary platform | Ubuntu 24.04 / kernel 6.8 |
| Python | >=3.11 |

---

## 2. Purpose and Scope

This review package covers the security-critical implementation of
`agent-sandbox`, a hardened execution environment for autonomous AI agents.
The review should assess whether the implementation correctly enforces the
security properties documented in:

- `SECURITY_SPEC.md` (S-001..S-040)
- `THREAT_MODEL.md` (T-001..T-056)
- `ARCHITECTURE.md` (trust boundaries, process model, Linux mechanisms)
- `ADRs/` (14 architecture decision records)

The review is specifically required by implementation.md section 25:

> "Before calling the sandbox production-ready, perform an independent
> security review. The reviewer should not be the primary author of the
> security-critical implementation."

---

## 3. Review Areas (implementation.md section 25)

Each area below lists the relevant source files, tests, invariants,
threat-model entries, verification status, and specific items for
reviewer inspection.

---

### 3.1 Trust Boundaries

**What to review:** Where does the trust boundary lie? What is trusted vs
untrusted? Are there any unintended trust escalations?

**Relevant source files:**
- `ARCHITECTURE.md` — trust boundaries, process model, security boundary definition
- `SECURITY_SPEC.md` — invariant definitions
- `ADRs/ADR-002-trusted-computing-base.md` — TCB definition
- `ADRs/ADR-013-control-surface.md` — CLI/MCP/API over single enforcement core

**Relevant tests:**
- `tests/unit/test_skeleton.py` — initialization, config immutability
- `tests/unit/test_workload.py` — end-to-end workload execution through the boundary

**Security invariants:** S-015 (single authorization path), S-026 (policy immutability)

**Threat model entries:** T-040, T-041, T-042 (CLI/MCP/API policy bypass)

**Verification classification:** HOST-SIDE VERIFIED (unit/integration) + NATIVE VERIFIED (P3, commit 7c1c30e)

**Specific reviewer inspection:**
- Confirm RuntimeSession.execute() is the sole enforcement path
- Confirm no alternate authorization path exists in CLI, MCP, or API
- Confirm the policy gate occurs before any boundary work
- Confirm the audit system is observational, not enforcement

---

### 3.2 Privileged Code

**What to review:** Which components run with elevated privilege? Is the
TCB as small as possible? Are there unnecessary privileged operations?

**Relevant source files:**
- `agent_sandbox/runtime/session.py` — RuntimeSession, the core execution path
- `agent_sandbox/isolation/setup.py` — sandbox initialization orchestration
- `agent_sandbox/isolation/namespaces.py` — namespace creation
- `agent_sandbox/isolation/rootfs.py` — pivot_root, filesystem setup
- `agent_sandbox/isolation/seccomp.py` — seccomp filter installation
- `agent_sandbox/isolation/privileges.py` — capability drop, no_new_privs
- `agent_sandbox/isolation/cgroups.py` — cgroup v2 setup
- `agent_sandbox/isolation/credentials.py` — credential isolation
- `agent_sandbox/isolation/environment.py` — environment sanitization
- `agent_sandbox/isolation/lifecycle.py` — process-tree containment, cleanup
- `agent_sandbox/isolation/output.py` — bounded output pipe
- `agent_sandbox/isolation/timeout.py` — external timeout
- `agent_sandbox/isolation/network.py` — network namespace
- `agent_sandbox/isolation/resources.py` — rlimits
- `agent_sandbox/isolation/userns.py` — user namespace mapping

**Relevant tests:**
- All `tests/unit/test_*.py` modules
- `tests/unit/test_failclosed_matrix.py` — 145 fail-closed tests

**Security invariants:** S-008, S-009, S-010, S-011, S-013, S-019, S-020

**Verification classification:** HOST-SIDE VERIFIED + NATIVE VERIFIED (P3)

**Specific reviewer inspection:**
- Confirm the supervisor process runs outside the sandbox
- Confirm the sandbox workload holds zero capabilities
- Confirm no_new_privs is established before exec
- Confirm seccomp is installed as the LAST setup operation
- Confirm no unnecessary code runs as root or with elevated caps

---

### 3.3 Namespace Setup

**What to review:** Are all required namespaces correctly created? Is the
namespace configuration sufficient for the claimed isolation?

**Relevant source files:**
- `agent_sandbox/isolation/namespaces.py` — CLONE_NEWUSER/MOUNT/PID/NET/UTS/IPC
- `agent_sandbox/isolation/userns.py` — uid 0→caller mapping
- `agent_sandbox/isolation/setup.py` — orchestration order

**Relevant tests:**
- `tests/unit/test_namespaces.py` — namespace creation, private propagation
- `tests/adversarial/test_filesystem_attacks.py::TOCTOURaceTests` — path races
- `tests/unit/test_race_concurrency.py::WorkspaceConcurrentModificationTests`

**Security invariants:** S-001, S-002, S-008, S-013, S-025, S-030

**Threat model entries:** T-001..T-011 (filesystem), T-026 (namespace escape)

**Verification classification:** DOCKER VERIFIED (real boundary) + NATIVE VERIFIED (P3)

**Specific reviewer inspection:**
- Confirm all six namespace types are created
- Confirm mount namespace uses MS_REC|MS_PRIVATE propagation
- Confirm user namespace mapping is correct
- Confirm PID namespace hides host processes
- Confirm network namespace has no interfaces (deny-by-construction)

---

### 3.4 Filesystem Handling

**What to review:** Is the filesystem isolation complete? Can the workload
access host files? Is the rootfs minimal and read-only where required?

**Relevant source files:**
- `agent_sandbox/isolation/rootfs.py` — pivot_root, rootfs construction
- `agent_sandbox/isolation/filesystem.py` — workspace copy, mount operations
- `ADRs/ADR-005-filesystem-isolation.md`
- `ADRs/ADR-015-dev-bind-mount.md`

**Relevant tests:**
- `tests/unit/test_rootfs.py` — workspace copy isolation, host source unreachable
- `tests/unit/test_procdev.py` — /proc hidepid=2, /dev minimal, /sys absent
- `tests/adversarial/test_filesystem_attacks.py` — path traversal, symlink, hardlink, workspace escape

**Security invariants:** S-001, S-002, S-025, S-028, S-029, S-030

**Threat model entries:** T-001..T-011

**Verification classification:** HOST-SIDE VERIFIED (rootfs tree) + DOCKER VERIFIED (real boundary) + NATIVE VERIFIED (P3)

**Specific reviewer inspection:**
- Confirm pivot_root is used (not chroot)
- Confirm workspace is a copy inside the rootfs, not a bind mount of the host
- Confirm host paths are absent from the rootfs
- Confirm /proc is mounted with hidepid=2
- Confirm /sys is not mounted
- Confirm /dev is minimal (null/zero/random/urandom/full/tty only)
- Confirm device nodes are identity-verified bind-mounts (ADR-015)

---

### 3.5 Network Enforcement

**What to review:** Is network isolation complete? Can the workload reach
any network resource?

**Relevant source files:**
- `agent_sandbox/isolation/network.py` — network namespace, loopback DOWN, veth plumbing, host firewall (iptables INPUT/FORWARD)
- `agent_sandbox/isolation/proxy.py` — host-side validating proxy (v0.2 Step 3): CONNECT protocol, SSRF gate, allowlist matching, host-side resolution, spawn/terminate
- `agent_sandbox/config.py` — `NetworkAllow` + `network_allowlist` validation
- `ADRs/ADR-006-network-isolation.md`

**Relevant tests:**
- `tests/unit/test_network.py` — deny-by-construction, metadata probe, private-range probes
- `tests/unit/test_network_veth.py` — veth plumbing + host firewall fail-closed
- `tests/unit/test_proxy.py` — CONNECT parsing, SSRF classification, DNS-rebinding denial, allowlist matching, config dead-entry rejection, proxy process integration (real echo server), full-sandbox e2e (workload reaches ONLY the proxy; direct host access DROPPED; AF_UNIX EPERM)
- `tests/adversarial/test_resource_attacks.py` — resource exhaustion

**Security invariants:** S-005, S-006, S-007

**Threat model entries:** T-012..T-017

**Verification classification:** DOCKER/NATIVE VERIFIED (real netns + socket deny; v0.2 Step 3 proxy + firewall + sandbox e2e verified natively in a privileged Linux container 2026-08-23)

**Specific reviewer inspection:**
- Confirm no network interfaces exist in the sandbox in deny mode (except loopback DOWN)
- Confirm the allowlist netns is IPv4-only (veth only; IPv6 disabled on the sandbox-side veth; IPv6 addresses/routes refused by verification)
- Confirm loopback is DOWN
- Confirm no DNS resolver is configured in the sandbox (resolution happens host-side in the trusted proxy)
- Confirm socket syscall is denied by seccomp (all domains except AF_INET/AF_INET6 via the BPF argument filter; AF_UNIX/AF_NETLINK/AF_PACKET EPERM)
- Confirm 169.254.169.254 (metadata) is unreachable
- Confirm RFC1918 ranges are unreachable
- **v0.2 Step 3:** confirm the proxy binds ONLY to the host-side veth IP (never a wildcard); confirm the host firewall makes the proxy port the ONLY destination accepted from the veth interface (no direct host access); confirm destination validation is AT CONNECT (hostname resolution + per-address SSRF checks in the proxy, DNS-rebinding safe); confirm `allow_private` relaxes only the private-range class (loopback/link-local/metadata never relaxable); confirm config-time rejection of dead allowlist entries; confirm proxy setup/probe/teardown failures fail closed and leave no leaked processes/interfaces/rules

---

### 3.6 Capability Configuration

**What to review:** Are capabilities correctly dropped? Can the workload
escalate privileges?

**Relevant source files:**
- `agent_sandbox/isolation/privileges.py` — bounding-set drop, effective/permitted/inheritable/ambient cleared
- `ADRs/ADR-008-capabilities-seccomp.md`

**Relevant tests:**
- `tests/unit/test_privileges.py` — drop_bounding_set, verify_capability_reduction, ambient CLEAR_ALL

**Security invariants:** S-009, S-010

**Threat model entries:** T-023, T-024, T-025

**Verification classification:** DOCKER VERIFIED (real cap-drop + readback)

**Specific reviewer inspection:**
- Confirm bounding set is fully dropped
- Confirm effective, permitted, inheritable, and ambient sets are empty
- Confirm no capability is granted to the workload
- Confirm workload cannot regain capabilities

---

### 3.7 Seccomp

**What to review:** Is the seccomp filter correctly derived, installed,
and enforced? Is the allowlist minimal and complete?

**Relevant source files:**
- `agent_sandbox/isolation/seccomp.py` — filter installation
- `agent_sandbox/isolation/syscalls.py` — syscall constants
- `tools/seccomp-derivation/allowlist.json` — the 70-syscall allowlist
- `tools/seccomp-derivation/allowlist_aarch64.json` — aarch64 allowlist (67 syscalls)
- `tools/seccomp-derivation/check_trace_regression.py` — regression gate
- `tools/seccomp-derivation/probe_policy.py` — behavioral probe
- `tools/seccomp-derivation/trace_workloads.py` — workload tracing
- `tools/seccomp-derivation/test_derivation.py` — derivation tests
- `docs/seccomp-derivation/policy.md` — change control, §5 change record
- `docs/seccomp-derivation/methodology.md` — derivation methodology
- `docs/seccomp-derivation/syscall-classification.md` — tier classification
- `docs/seccomp-derivation/verification.md` — verification results
- `ADRs/ADR-008-capabilities-seccomp.md`

**Relevant tests:**
- `tests/unit/test_seccomp.py` — filter installation, forbidden-syscall EPERM
- `tools/seccomp-derivation/test_derivation.py` — derivation integrity
- `tools/seccomp-derivation/probe_policy.py` — behavioral enforcement
- `tools/seccomp-derivation/check_trace_regression.py` — no undocumented expansion

**Security invariants:** S-011

**Threat model entries:** T-027

**Verification classification:** HOST-SIDE VERIFIED (derivation, regression, behavioral) + NATIVE VERIFIED (P3)

**Specific reviewer inspection:**
- Confirm the allowlist is derived empirically (not hardcoded)
- Confirm the regression gate prevents undocumented syscall expansion
- Confirm the behavioral probe verifies both allowed and denied syscalls
- Confirm the filter is installed AFTER all other setup
- Confirm the filter inherits to child processes via fork/exec
- Confirm the default action is EPERM (deny)
- Confirm ptrace/mount/chroot/unshare/clone/socketpair are denied, and that `socket` is argument-filtered to AF_INET/AF_INET6 (all other domains EPERM — v0.2 Step 2)
- Review the 70-syscall allowlist for completeness and minimality (69 baseline + fsync — the single Phase 10 dependency-installation syscall; see policy.md §5 change record for the necessity evidence)
- Review the aarch64 allowlist (67 syscalls) — note: filter installation/enforcement is NOT VERIFIED on aarch64

---

### 3.8 Resource Controls

**What to review:** Are resource limits correctly enforced? Can the workload
exhaust host resources?

**Relevant source files:**
- `agent_sandbox/isolation/resources.py` — rlimits (RLIMIT_CPU/AS/NPROC/NOFILE/FSIZE, CORE=0)
- `agent_sandbox/isolation/cgroups.py` — cgroup v2 (pids.max, memory.max, cpu.max, io.max)
- `ADRs/ADR-007-resource-limits.md`

**Relevant tests:**
- `tests/unit/test_resources.py` — six limits, read-back, seccomp interaction, inheritance
- `tests/unit/test_cgroups.py` — delegation probe, four controllers, io device, fail-closed
- `tests/unit/test_output.py` — bounded output pipe, truncation notice
- `tests/unit/test_timeout.py` — supervisor deadline, session termination
- `tests/adversarial/test_resource_attacks.py` — fork bomb, memory, disk, FD, limit-raise

**Security invariants:** S-012, S-027, S-036, S-037

**Threat model entries:** T-029..T-035

**Verification classification:** HOST-SIDE VERIFIED (unit) + NATIVE VERIFIED (P3 cgroup enforcement) + DOCKER VERIFIED (real boundary)

**Specific reviewer inspection:**
- Confirm rlimits are set AFTER seccomp install (so workload cannot change them)
- Confirm cgroup v2 delegation is required for HARDENED mode
- Confirm HARDENED refuses when delegation is absent (fail-closed)
- Confirm io.max uses a real resolvable block device
- Confirm output pipe is bounded and truncation is reported
- Confirm external timeout cannot be disabled by the workload

---

### 3.9 Policy Enforcement

**What to review:** Is the policy engine correct? Can policy be bypassed?
Are CLI, MCP, and API decision-equivalent?

**Relevant source files:**
- `agent_sandbox/policy.py` — capability-based policy, versioned, deny-by-default
- `agent_sandbox/config.py` — RuntimeConfig
- `agent_sandbox/runtime/session.py` — policy gate in RuntimeSession.execute()
- `ADRs/ADR-010-policy-model.md`
- `ADRs/ADR-013-control-surface.md`

**Relevant tests:**
- `tests/unit/test_policy.py` — validation, decision, immutability, session gate, CLI, interface
- `tests/unit/test_cli.py` — CLI routes through policy gate
- `tests/unit/test_mcp.py` — MCP routes through policy gate
- `tests/unit/test_api.py` — API routes through policy gate
- `tests/unit/test_cli_sessions.py` — Phase B command surface, create/exec route through policy
- `tests/unit/test_failclosed_matrix.py` — N1 policy fail-closed rows

**Security invariants:** S-015, S-016, S-017, S-021, S-022, S-026, S-027

**Threat model entries:** T-040..T-046, T-050

**Verification classification:** HOST-SIDE VERIFIED (unit/integration) + three-way equivalence tested

**Specific reviewer inspection:**
- Confirm policy is evaluated BEFORE any boundary work
- Confirm policy cannot be modified from inside the sandbox
- Confirm unknown security-critical fields are rejected (not warned)
- Confirm deny-by-default behavior
- Confirm CLI, MCP, and API produce identical decisions for identical requests
- Confirm the policy file is host-side only, never mounted into the sandbox

---

### 3.10 Lifecycle Cleanup

**What to review:** Are sandbox processes fully terminated after execution?
Can orphaned processes survive? Is cleanup verified?

**Relevant source files:**
- `agent_sandbox/isolation/lifecycle.py` — child subreaper, terminate_tree, absence verification, cgroup.kill
- `agent_sandbox/runtime/session.py` — session lifecycle management

**Relevant tests:**
- `tests/unit/test_lifecycle.py` — 21 tests: subreaper, terminate_tree, absence verification, cgroup cleanup, output truncation, fork-buffer, FD leak
- `tests/adversarial/test_lifecycle_attacks.py` — IncompleteCleanupTests, DestroyRaceTests, PolicyTamperingTests
- `tests/unit/test_race_concurrency.py::CleanupRaceTests` — concurrent destroy idempotent

**Security invariants:** S-014, S-038

**Threat model entries:** T-036, T-037, T-038, T-039

**Verification classification:** HOST-SIDE VERIFIED (unit) + NATIVE VERIFIED (P3)

**Specific reviewer inspection:**
- Confirm the supervisor is a child subreaper (PID 1 reaps strays)
- Confirm PID-1 SIGKILL + cgroup.kill is used
- Confirm absence verification occurs (not just assumed)
- Confirm incomplete cleanup is reported, never claimed successful
- Confirm cleanup handles: normal exit, command failure, timeout, parent crash

---

### 3.11 Race Conditions

**What to review:** Are there TOCTOU vulnerabilities? Can concurrent attacks
bypass security invariants?

**Relevant source files:**
- `agent_sandbox/runtime/session.py` — session state machine
- `agent_sandbox/registry.py` — session manifest read/write

**Relevant tests:**
- `tests/unit/test_race_concurrency.py` — 13 tests across 5 classes:
  - `RegistryAtomicityTests` — concurrent writers, read-during-write, create/destroy
  - `SessionStateRaceTests` — concurrent execute+destroy, execute-twice, destroy-during-init
  - `CleanupRaceTests` — concurrent destroy, destroy-during-output
  - `WorkspaceConcurrentModificationTests` — concurrent file creation, symlink-replacement-during-read
  - `PolicyAccessRaceTests` — concurrent decide()/require()
- `tests/adversarial/test_filesystem_attacks.py::TOCTOURaceTests` — serial symlink-replace + read

**Security invariants:** S-031

**Threat model entries:** T-009

**Verification classification:** HOST-SIDE VERIFIED (concurrency, unit-level)

**Specific reviewer inspection:**
- Confirm tests assert security/state invariants, not merely "didn't crash"
- Confirm the supervisor operates on host-side copies before the boundary exists
- Confirm workspace mutations are sandbox-internal (contained)
- Note: in-sandbox race surface is inherently limited (clone/threading denied by seccomp)

---

### 3.12 MCP/API Authorization

**What to review:** Can MCP or API bypass the policy engine? Are all three
interfaces (CLI, MCP, API) decision-equivalent?

**Relevant source files:**
- `agent_sandbox/mcp.py` — stdio JSON-RPC 2.0
- `agent_sandbox/api.py` — stdlib HTTP
- `agent_sandbox/cli.py` — CLI command surface
- `agent_sandbox/interface.py` — shared initialize/execute code
- `ADRs/ADR-013-control-surface.md`

**Relevant tests:**
- `tests/unit/test_mcp.py` — MCP protocol, decision equivalence, no-leak, fail-closed
- `tests/unit/test_api.py` — API protocol, three-way decision equivalence, no-leak, fail-closed
- `tests/unit/test_cli.py` — CLI protocol, no-shell guard, fail-closed
- `tests/unit/test_cli_sessions.py` — CLI session management

**Security invariants:** S-015, S-016, S-017

**Threat model entries:** T-040, T-041, T-042, T-043

**Verification classification:** HOST-SIDE VERIFIED (three-way equivalence)

**Specific reviewer inspection:**
- Confirm MCP tools map 1:1 to policy-gated capabilities
- Confirm API uses the same RuntimeSession.execute() path
- Confirm no alternate authorization path exists in any interface
- Confirm malformed MCP/API input fails closed (never executes)
- Confirm no host details leak through error messages

---

### 3.13 Audit Integrity

**What to review:** Is the audit system correctly observational? Can the
workload tamper with audit records? Are audit events session-correlated?

**Relevant source files:**
- `agent_sandbox/interface.py` — ADR-012 JSONL audit recorder (open-per-record)
- `ADRs/ADR-012-audit.md`

**Relevant tests:**
- `tests/unit/test_cli.py` — audit JSONL output
- `tests/unit/test_mcp.py` — no host exception/environment leakage
- `tests/unit/test_api.py` — internal error does not leak
- `tests/adversarial/test_info_leakage.py::AuditTamperingTests` — audit tampering
- `tests/adversarial/test_info_leakage.py::AuditEnvironmentLeakageTests` — env/audit leakage
- `tests/fuzz/test_fuzz_parsers.py` — audit write/read-back fuzzing

**Security invariants:** S-022, S-023, S-024, S-039

**Threat model entries:** T-053, T-054

**Verification classification:** HOST-SIDE VERIFIED (unit) + NATIVE VERIFIED (real boundary)

**Specific reviewer inspection:**
- Confirm audit recorder is host-side, outside sandbox filesystem
- Confirm audit is open-per-record (no audit fd crosses fork boundary)
- Confirm audit failure does not block execution (S-024)
- Confirm audit events include session_id, timestamp, event type
- Confirm workload cannot write to the audit file
- Confirm malformed/undecodable audit data is observationally skipped

---

## 4. Verification Status Summary

| Area | NATIVE VERIFIED | DOCKER VERIFIED | HOST-SIDE VERIFIED | UNIT-LEVEL | PARTIALLY VERIFIED | SUBSTRATE-LIMITED | DEFERRED |
|---|---|---|---|---|---|---|---|
| Trust boundaries | ✓ | | ✓ | | | | |
| Privileged code | ✓ | | ✓ | | | | |
| Namespace setup | ✓ | ✓ | ✓ | | | | |
| Filesystem handling | ✓ | ✓ | ✓ | | | | |
| Network enforcement | | ✓ | ✓ | | | | |
| Capability configuration | | ✓ | ✓ | | | | |
| Seccomp | ✓ | | ✓ | | | aarch64 | |
| Resource controls | ✓ | ✓ | ✓ | | | | |
| Policy enforcement | | | ✓ | ✓ | | | |
| Lifecycle cleanup | ✓ | | ✓ | | | | |
| Race conditions | | | | ✓ | | | |
| MCP/API authorization | | | ✓ | ✓ | | | |
| Audit integrity | ✓ | | ✓ | ✓ | | | |

---

## 5. Reproducibility

### 5.1 Full unit test suite

```bash
cd agent-sandbox
python -m unittest discover -s tests -t . -v
```

Expected: 761 run, 0 failures, 0 errors, 272 documented Linux-gated skips.

### 5.2 Adversarial suite

```bash
cd agent-sandbox
python -m unittest discover -s tests/adversarial -t . -v
```

Expected: 70 run, 0 failures, 52 documented Linux-gated skips.

### 5.3 Fuzz suite

```bash
cd agent-sandbox
python -m unittest discover -s tests/fuzz -t . -v
```

Expected: 21/21 PASS (seed 0xC0FFEE, deterministic).

### 5.4 Fail-closed matrix (N1)

```bash
cd agent-sandbox
python -m unittest tests.unit.test_failclosed_matrix -v
```

Expected: 42 run, 0 failures, 10 documented skips.

### 5.5 Race/concurrency suite

```bash
cd agent-sandbox
python -m unittest tests.unit.test_race_concurrency -v
```

Expected: 13/13 PASS.

### 5.6 Phase 17 S-invariant coverage regression suite

```bash
cd agent-sandbox
python -m unittest tests.regression.test_s_invariant_coverage -v
```

Expected: 44 run, 0 failures, 13 documented Windows-substrate skips. All 40 S-invariants (S-001..S-040) mapped to real test classes.

### 5.7 Seccomp derivation tests

```bash
cd agent-sandbox
python tools/seccomp-derivation/test_derivation.py
```

Expected: ALL PASS.

### 5.7 Seccomp regression gate (requires Linux)

```bash
cd agent-sandbox
python tools/seccomp-derivation/trace_workloads.py --out /tmp/trace.json
python tools/seccomp-derivation/check_trace_regression.py /tmp/trace.json
```

Expected: PASS — allowlist exactly 70 (tier0 29 + tier1 41), no undocumented expansion.

### 5.8 Seccomp behavioral probe (requires Linux)

```bash
cd agent-sandbox
python tools/seccomp-derivation/probe_policy.py
```

Expected: allowed syscalls pass; denied syscalls (socketpair, ptrace, mount, etc.) return EPERM; `socket` is allowed only for AF_INET/AF_INET6 (other domains EPERM — v0.2 Step 2 domain filter).

### 5.9 Static analysis

```bash
cd agent-sandbox
ruff check .                    # Expected: All checks passed
mypy agent_sandbox --ignore-missing-imports  # Expected: Success, no issues
bandit -r agent_sandbox --skip B101,B108,B606,B110,B603,B607 -ll  # Expected: 0 HIGH, 0 MEDIUM
pip-audit -r /dev/null --desc   # Expected: No known vulnerabilities
```

### 5.10 Native HARDENED e2e (requires Ubuntu 24.04 / kernel 6.8 / x86_64 QEMU VM with delegated cgroup)

```bash
cd agent-sandbox
python -m unittest tests.native.test_hardened_e2e -v
```

Expected: 24/24 PASS (on the documented substrate).

### 5.11 CLI/API/MCP equivalence

```bash
cd agent-sandbox
python -m unittest tests.unit.test_cli tests.unit.test_mcp tests.unit.test_api -v
```

Expected: three-way decision equivalence verified.

---

## 6. Known Limitations

1. **aarch64 native enforcement NOT VERIFIED** — the aarch64 seccomp allowlist (67 syscalls) is derived and regression-gated, but filter installation and enforcement have not been tested on a native aarch64 host. SUBSTRATE-LIMITED.

2. **Full SECURITY_SPEC.md coverage NOT ESTABLISHED** — while every S-invariant maps to at least one test (THREAT_MODEL section 10), the evidence is a mix of NATIVE VERIFIED, DOCKER VERIFIED, and HOST-SIDE VERIFIED. Not every invariant has native kernel-boundary evidence.

3. **Phase 10 dependency workflows — pip COMPLETE, npm/cargo intentionally unsupported** — the Python/pip dependency-installation workflow is implemented and verified (v0.2 Step 4, `pip install --proxy http://10.255.254.0:8080` inside the sandbox through the validating proxy, seccomp 69 → 70 +`fsync` only). Node/Rust (npm/cargo) are MEASURED and INTENTIONALLY UNSUPPORTED — real-filter measurement proves both unconditionally require `clone3` (the S-014 single-process containment boundary), so no syscall expansion. npm/cargo fail closed cleanly in-sandbox.

4. **Phase 13 ecosystem integrations DEFERRED** — not core security.

5. **Phase 14 snapshots DEFERRED** — not core security.

6. **Release artifact reproducibility VERIFIED (2026-08-23)** — `tools/release/build_release.py`: deterministic sdist+wheel (SOURCE_DATE_EPOCH pinned, sdist header normalization, clean-copy builds), two-clean-build byte-identity gate, GNU `SHA256SUMS` + per-artifact `.sha256`; `tools/release/test_release.py` (17/17 PASS) + CI Phase 20 step.

7. **Release signing/integrity PARTIALLY CONFIGURED** — checksums + tamper detection mechanized and tested; cryptographic signing mechanism prepared (`sign` → detached-armor GPG) but requires a maintainer-held key (`AGENT_SANDBOX_GPG_KEY`) — external, human-controlled, fails closed (exit 2) without it. GPG/SSH commit/tag signing remains unconfigured (external key).

8. **In-sandbox race surface inherently limited** — clone/threading denied by seccomp; serial TOCTOU is the maximum achievable inside the sandbox.

9. **Windows file-locking** — concurrent registry writes may fail transiently on Windows due to file locking (documented, not a security defect; production CLI is single-process).

10. **GitHub Actions AppArmor restriction** — the ubuntu-latest runner permits unprivileged user namespaces but AppArmor denies the setgroups-write, so the uid 0→caller mapping cannot be established there. The namespace and filesystem-boundary real-path tests skip on native CI with a recorded reason.

---

## 7. Residual Risks (documented, not claimed away)

1. **Host kernel compromise** — a kernel vulnerability exploitable from inside the sandbox defeats every control.
2. **Trusted-component vulnerabilities** — a bug in the supervisor, security init, policy validator, or audit recorder is in the TCB.
3. **seccomp allowlist completeness** — a missing syscall breaks workloads; an over-permissive entry widens the kernel surface.
4. **Host configuration** — cgroup delegation, user-namespace enablement, and systemd configuration are host decisions.
5. **The agent's own mistakes** — the sandbox contains them in the workspace; it does not prevent the agent from breaking its own project copy.

---

## 8. Reviewer Checklist

The independent reviewer should independently assess:

- [ ] **Trust boundaries** — Is the trust boundary correctly identified and enforced?
- [ ] **Fail-closed behavior** — Does every mandatory control refuse when unavailable?
- [ ] **Authorization paths** — Is there exactly one enforcement path? Can CLI/MCP/API bypass it?
- [ ] **Attack resistance** — Do the adversarial tests meaningfully test the real boundary?
- [ ] **Race safety** — Are security-sensitive operations safe under concurrency?
- [ ] **Audit integrity** — Is audit observational? Can the workload tamper with it?
- [ ] **Seccomp derivation** — Is the allowlist minimal, derived, and regression-protected?
- [ ] **Namespace/capability restrictions** — Are all namespaces created? Are capabilities fully dropped?
- [ ] **Resource enforcement** — Can the workload exhaust host resources?
- [ ] **Lifecycle cleanup** — Are orphaned processes reliably terminated?
- [ ] **MCP/API equivalence** — Do all three interfaces produce identical security decisions?
- [ ] **Known limitations** — Are the limitations honestly documented?
- [ ] **Claims vs evidence** — Do README/THREAT_MODEL/SECURITY_SPEC claims match the actual evidence?

---

## 9. Reviewer Sign-Off

> **This section must be completed by the independent reviewer.**
> It must NOT be filled in by the primary author or the coding agent.

| Field | Value |
|---|---|
| Reviewer name/identity | |
| Reviewer independence confirmed | |
| Date of review | |
| Commit reviewed | `4944800` |
| Repository state | HEAD `4944800`, v0.1.0 tag `bb73386`, seccomp 70 syscalls |
| Review scope | All 13 areas from implementation.md section 25 |
| Findings | |
| Severity of findings | |
| Required remediation | |
| Reviewer conclusion | |
| Approved for production use | |
| Signature | |

---

## 10. Documents Referenced

| Document | Path | Purpose |
|---|---|---|
| Security Specification | `dont touch/03_SECURITY_SPEC.md` | S-001..S-040 invariants |
| Threat Model | `THREAT_MODEL.md` | T-001..T-056 threats, evidence mapping |
| Architecture | `dont touch/02_DESIGN.md` | Trust boundaries, Linux mechanisms |
| Implementation Plan | `dont touch/implementation.md` | Phase definitions, acceptance criteria |
| Idea | `dont touch/01_IDEA.md` | Project vision |
| ADRs | `ADRs/` | 14 architecture decision records |
| Seccomp Policy | `docs/seccomp-derivation/policy.md` | Allowlist change control |
| Seccomp Methodology | `docs/seccomp-derivation/methodology.md` | Derivation process |
| Seccomp Classification | `docs/seccomp-derivation/syscall-classification.md` | Tier 0/1 classification |
| Seccomp Verification | `docs/seccomp-derivation/verification.md` | Verification results |
| Release Checklist | `RELEASE_CHECKLIST.md` | v0.1 release criteria status |
| CI Pipeline | `.github/workflows/ci.yml` | CI security gates |
| Tooling Config | `pyproject.toml` | ruff, mypy, bandit configuration |
