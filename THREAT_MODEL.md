# agent-sandbox — Threat Model

| | |
|---|---|
| Status | ACCEPTED (Phase 0) |
| Date | 2026-08-19 |
| Phase | 0 — Architecture and Threat Model |
| Companion docs | `ARCHITECTURE.md` (structure), `SECURITY_SPEC.md` (invariants S-001…S-040) |

The security objective (security spec §2): *prevent an untrusted sandbox
workload from obtaining unauthorized access to the host or resources
outside the explicitly authorized sandbox policy.* This document enumerates
what that means concretely: who attacks, what they want, how they could get
it, and what we do about it.

---

## 1. Methodology

- Threats are enumerated from the attack categories in the implementation
  plan (Phase 2 list, security spec §12) plus the invariants in
  `SECURITY_SPEC.md`.
- Each threat is mapped to the invariant(s) it targets and the mitigation
  that blocks it.
- Mitigations are *enforced properties*, not aspirations — every mitigation
  maps to a test (adversarial suite, Phase 2+; failure suite, Phase 3+) or a
  structural property.
- Residual risks are stated explicitly. A threat with no residual risk
  listed is assumed to be fully mitigated by the stated controls **and**
  tested; anything weaker is called out.
- The model is a living document: every confirmed vulnerability becomes a
  regression test (security spec §14) and a review entry here.

---

## 2. Trust Model Summary

See `ARCHITECTURE.md` §3 for the full trust model. In one sentence: the
kernel, the supervisor, security init, the policy validator, security
config and the audit recorder are trusted; **everything that enters the
sandbox is untrusted** — the LLM, the repository, its instructions, Git
hooks, dependencies, build scripts, tests, downloaded content, network
responses, generated code, and every sandboxed process.

The AI agent is not part of the security boundary. Interfaces (CLI/MCP/API)
are not the boundary. The audit system is not the boundary. The kernel
enforces the boundary; the supervisor creates it.

---

## 3. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Host filesystem (projects, home, configs) | Integrity + confidentiality |
| A2 | Host credentials (SSH, cloud, API keys, GitHub tokens, K8s) | Direct compromise value |
| A3 | Host processes and kernel interfaces | Observation, tampering, escalation |
| A4 | Host network and internal services | Pivot point for further attacks |
| A5 | Host control sockets (Docker, SSH agent, credential managers) | Often equivalent to full host access |
| A6 | Host resources (CPU, memory, disk, bandwidth, FDs) | Availability |
| A7 | Audit trail integrity | Accountability |
| A8 | Sibling `agent-*` repos and their data | Ecosystem value; sandbox is its foundation brick |
| A9 | The supervisor process itself | Escalating from sandbox to host control |

---

## 4. Threat Actors

| ID | Actor | Assumed capability | Primary goal |
|---|---|---|---|
| ADV-1 | Malicious or compromised AI agent | Can issue arbitrary CLI/MCP/API requests; may be prompt-injected | Reach host resources; steal credentials; exfiltrate |
| ADV-2 | Malicious repository author | Controls repo files, instructions, hooks, scripts | Trick the agent/sandbox into host access; inject prompts |
| ADV-3 | Malicious dependency author | Controls dependency install scripts / code | Same, via `pip`/`npm`/cargo install inside the sandbox |
| ADV-4 | Malicious network endpoint | Can respond to any sandbox network request (v0.2+) | Deliver exploit content; drive the agent |
| ADV-5 | Intentional escape payload | One or more sandboxed processes executing hostile code | Break the boundary itself |

Out of scope by design (documented residual, security spec §18): a
compromised host kernel, malicious hypervisor, hardware compromise, a host
administrator intentionally disabling security, unknown kernel
vulnerabilities, and vulnerabilities in trusted host components. The host
user is the owner, not an adversary.

---

## 5. Attack Surface

| Surface | Description | Phase it appears |
|---|---|---|
| CLI / MCP / API | Request interfaces; policy-bypass attempts | CLI Phase 8, MCP 11, API 12 (architecture decided now, ADR-013) |
| Repository content | Executed as build scripts, tests, hooks | Phase 1+ |
| Dependency installers | `pip`/`npm`/cargo scripts inside the sandbox | Phase 10 (design) |
| Sandboxed processes | Kernel attack surface (syscalls, namespaces, cgroups) | Phase 1+ |
| Filesystem view | `/proc`, `/sys`, `/dev`, symlinks, hardlinks, mounts | Phase 1+ |
| Policy parser | Malformed/ambiguous policy input | Phase 4 (policy engine) |
| Output / audit channels | Exhaustion, tampering, information leakage | Phase 1+ |
| Environment | Inherited variables, locale, TMPDIR tricks | Phase 1+ |

---

## 6. Threats

Columns: **ID** — threat — attack vector — targeted invariant(s) —
mitigation — residual risk — evidence (test class).

### 6.1 Filesystem

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-001 | Path traversal (`../`, encoded forms) to host paths | S-001, S-030 | `pivot_root`; no host paths exist in rootfs; path validation at supervisor boundary | None expected | adversarial: traversal suite |
| T-002 | Absolute-path escape (`/etc/passwd`, `/home/...`) | S-001, S-002 | Same; host paths absent from rootfs | None expected | adversarial: absolute-path suite |
| T-003 | Symlink escape (symlink → host path) | S-001, S-029 | Target path resolves inside rootfs where host path does not exist; supervisor refuses workspace symlinks pointing outside the workspace copy | Symlink to a *sandbox-visible* path is allowed by design (workspace-internal links) | adversarial: symlink suite (`test_ssh_key_symlink_denied`…) |
| T-004 | Hard-link attack on host files | S-001 | Hard links cannot cross filesystems/mount namespaces; host files are never visible to link against | None expected | adversarial: hardlink suite |
| T-005 | Mount / bind-mount attack | S-001, S-025 | No `CAP_SYS_ADMIN`; `mount(2)` denied by seccomp; private propagation | Kernel bug (residual) | adversarial: mount suite |
| T-006 | `/proc` access (host processes, `environ`, `cmdline`, `fd`) | S-002, S-008 | Rootfs `/proc` mounted with `hidepid=2`; PID namespace hides host PIDs; seccomp restricts `openat` on proc | Kernel info leaks via syscalls not covered by `hidepid` | adversarial: proc suite |
| T-007 | `/sys` access (devices, firmware, kernel config) | S-002 | `/sys` not mounted in v0.1 rootfs | None in v0.1 (no mount); revisit if a tool needs `/sys` | adversarial: sys suite |
| T-008 | `/dev` access (raw devices) | S-002 | Minimal `/dev` (null/zero/full/random/urandom/tty only); no device nodes for host disks | Kernel device-mapper tricks are kernel-bug territory (residual) | adversarial: dev suite |
| T-009 | TOCTOU / path race (replace file between check and use) | S-031 | Supervisor operates on its own host-side copies before the boundary exists; inside the sandbox no host path is reachable so there is no privileged check-then-use on host paths; workspace mutations are sandbox-internal | Races *inside* the workspace can corrupt the workspace (agent's own problem, contained) | adversarial: race suite |
| T-010 | Rootfs tampering (workload rewrites system layers) | S-001, S-025 | System layers read-only; no caps; seccomp denies `mount`/`chattr`-adjacent paths | None expected | security: RO-layer tests |
| T-011 | Workspace boundary escape (project copy links/mounts out) | S-028 | Workspace is a copy inside the rootfs; no host path to link to; size-checked | A workspace that ships its own tools can do anything *inside* — by design | adversarial: workspace suite |

### 6.2 Network

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-012 | Direct outbound network access | S-005 | Network namespace, no interfaces, loopback down — deny by construction (v0.1) | None (no network exists) | adversarial: net suite |
| T-013 | Metadata endpoint (`169.254.169.254`) | S-007 | Unreachable — no network in v0.1 | None | adversarial: metadata suite |
| T-014 | Private / link-local ranges | S-006 | Unreachable — no network in v0.1 | None | adversarial: private-range suite |
| T-015 | SSRF via redirects / DNS rebinding / alternate address forms | S-006 | v0.1: unreachable (no network). v0.2 Step 3: host-side validating proxy enforces destination validation AT CONNECT (never hostname allowlists alone): every resolved address must pass the SSRF gate (loopback, link-local incl. 169.254.169.254, multicast, unspecified, reserved, RFC 1918/6598 denied; private ranges forwardable only via an explicit allow_private entry); hostname resolution happens host-side in the trusted proxy, so rebinding cannot reach a denied address | None for the allowlist path; deny mode has no network at all | v0.2: `test_proxy.py` (SSRF + DNS-rebinding + config dead-entry rejection) |
| T-017 | DNS abuse / rebinding | S-005, S-006 | v0.1: no resolver, no network. v0.2 Step 3: the proxy resolves hostnames HOST-SIDE at connect time and refuses any resolution that fails or yields a denied address (fail closed); the sandbox has no resolver and only one route (the proxy) | None for the allowlist path | v0.2: `test_proxy.py` (rebinding-to-private/loopback denied, unresolvable denied) |
| T-016 | Unix socket access (Docker, SSH agent, K8s, credential managers) | S-004 | Sockets never mounted; socket paths absent from rootfs; no network namespace exposure | None expected | adversarial: socket suite (`test_docker_socket_denied`, `test_ssh_agent_socket_denied`) |
| T-017 | DNS abuse / rebinding | S-005, S-006 | No resolver configured; no network in v0.1 | None until v0.2 allowlists | v0.2: DNS suite |

### 6.3 Credentials and secrets

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-018 | Env inheritance leaks secrets | S-003, S-034 | Explicit environment allowlist; host env never inherited | A policy-declared variable is exposed by explicit user choice (documented) | security: env isolation suite |
| T-019 | Credential files mounted/readable | S-003 | No host mounts (`.ssh`, `.aws`, `.config`, K8s); workspace is a copy | A project that *contains* a credential in its source ships it into its own copy — user responsibility | adversarial: ssh/aws suite |
| T-020 | SSH-agent / credential sockets | S-004 | Never mounted; absent from rootfs | None expected | adversarial: socket suite |
| T-021 | Core dumps / crash artifacts leak in-memory secrets | S-003 | `RLIMIT_CORE=0`; tmpfs/workspace wiped on destroy | None expected | lifecycle: cleanup suite |
| T-022 | Audit/`environ` leakage of secrets into output | S-003, S-039 | Secrets absent by construction; output sanitization is not the boundary (defense in depth) | Policy-injected secrets could appear in logs — documented, user-gated | security: secret-scan suite |

### 6.4 Privilege and process

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-023 | setuid/setgid privilege escalation | S-008, S-010 | `no_new_privs` before exec; no setuid binaries in rootfs (RO layers vetted) | Kernel bug (residual) | adversarial: setuid suite |
| T-024 | Capability abuse | S-009 | Full bounding-set drop; empty inheritable/ambient; effective set empty | None expected | security: caps suite (`test_caps_effective_empty`) |
| T-025 | ptrace of host or supervisor processes | S-008, S-013 | PID namespace hides host PIDs; no caps; seccomp denies `ptrace`; supervisor is a separate process outside the namespace | None expected | adversarial: ptrace suite |
| T-026 | Namespace escape (`unshare`, `setns`, `clone(CLONE_NEW*)`) | S-013 | No caps; seccomp denies these syscalls/flags in HARDENED; nested user namespaces blocked by bounding-set drop | Kernel bug (residual) | adversarial: namespace suite |
| T-027 | Seccomp bypass | S-011 | Filter installed last, after all other setup, with no way to remove; default-deny action | Filter bugs are reviewed + fuzzed (Phase 15) | security: seccomp enforcement tests (behavioral, not config-presence) |
| T-028 | Process inspection of host (`ps`, `/proc/*/cmdline`) | S-008, S-013 | PID namespace + `hidepid=2`; host PIDs invisible | None expected | adversarial: proc suite |

### 6.5 Resources

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-029 | Fork bomb / process explosion | S-012, S-013 | `RLIMIT_NPROC` + cgroup `pids.max`; both unraisable | None expected | adversarial: fork-bomb suite |
| T-030 | Memory exhaustion | S-012 | `RLIMIT_AS` + cgroup `memory.max` (HARDENED); OOM-kill inside the session cgroup, host untouched | RESTRICTED (no cgroup) limits memory per-process only | adversarial: memory suite |
| T-031 | Disk exhaustion | S-012 | `RLIMIT_FSIZE` + cgroup `io.max` (HARDENED); workspace size pre-check; tmpfs size-limited | RESTRICTED without cgroup cannot cap total disk — documented gap (ADR-007) | adversarial: disk suite |
| T-032 | FD exhaustion | S-012 | `RLIMIT_NOFILE` | None expected | adversarial: fd suite |
| T-033 | Output exhaustion (stdout/stderr/audit/API) | S-037 | Bounded supervisor pipe → terminate + truncation notice; audit/API separately bounded | A hostile workload can still consume its own limit (by design) | adversarial: output suite |
| T-034 | Infinite execution / timeout bypass | S-036 | External supervisor timeout; workload cannot disable it (seccomp/no caps + timer outside) | None expected | lifecycle: timeout suite |
| T-035 | Resource-limit increase | S-012, S-027 | Lowered rlimits cannot be raised (kernel rule); cgroup files outside the sandbox | None expected | security: limit-raise suite |

### 6.6 Lifecycle and cleanup

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-036 | Child persistence after destroy (daemonized grandchildren) | S-014 | PID-1 SIGKILL + `cgroup.kill`; subreaper supervisor reaps strays; absence verification | A process that escapes the cgroup (host config bug) is a host problem | lifecycle: persistence suite |
| T-037 | Partial cleanup (mounts, sockets, tmp left behind) | S-038 | Namespace teardown; tmpfs unmount; workspace copy removal; verification step | None expected | lifecycle: cleanup suite |
| T-038 | Cleanup reported successful when incomplete | S-038, S-024 | Verification is part of destroy; incomplete state is reported explicitly, never claimed complete | None expected | lifecycle: verification suite |
| T-039 | Repeated destroy / destroy during exec | S-038 | Session state machine; idempotent destroy; lock per session | None expected | lifecycle: race suite |

### 6.7 Policy and interfaces

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-040 | CLI bypass of policy | S-015 | CLI is a thin front-end over the single enforcement core; no alternate path | A bug in the core affects all interfaces equally (single point of review) | policy: CLI suite |
| T-041 | MCP bypass of policy | S-016 | Same core; MCP tools map 1:1 to policy-gated capabilities | None expected | policy: MCP authorization suite |
| T-042 | API bypass of policy | S-017 | Same core; no separate security logic in the API | None expected | policy: API equivalence suite |
| T-043 | Policy tampering from inside the sandbox | S-025, S-026 | Policy file host-side, never mounted; session policy immutable | None expected | adversarial: policy-tamper suite |
| T-044 | Malformed/unknown policy fields change behavior | S-021 | Strict validator rejects unknown security-critical fields; no warn-and-continue | A *known* field with a surprising value is caught by tests + review | policy: validation suite |
| T-045 | Ambiguous policy → wrong decision | S-021 | Deterministic evaluation; conflicts rejected at parse | None expected | policy: conflict suite |
| T-046 | Mode misrepresentation (COMPATIBILITY presented as HARDENED) | S-019, S-020 | Mode is explicit per session, machine-readable, and derived from what actually initialized | A bug in mode reporting is caught by tests | security: mode suite |

### 6.8 Content and supply chain

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-047 | Malicious Git hooks gain host privileges | S-032 | Git runs only inside the sandbox; hooks execute inside the boundary; no host creds reachable | Hooks can act *inside* the sandbox (contained) | adversarial: git-hook suite |
| T-048 | Malicious dependencies escape the sandbox | S-033 | Install runs inside the boundary; dependencies can do anything *inside* — nothing outside | None expected (boundary holds) | adversarial: dependency suite |
| T-049 | Malicious build/test scripts attack the host | S-032 | Same containment | None expected | adversarial: build-script suite |
| T-050 | Prompt injection drives the agent to request host access | S-015 | The agent's requests are policy-gated; injected instructions cannot grant capabilities the policy denies | A policy that *allows* a dangerous action makes it reachable via injection — policy design is user-controlled | policy: injection suite |

### 6.9 Observation and information leakage

| ID | Threat / vector | Invariants | Mitigation | Residual | Evidence |
|---|---|---|---|---|---|
| T-051 | Host details leak via environment/locale | S-034 | Explicit env allowlist; minimal rootfs config | Hostname/OS version inside sandbox intentionally minimal | security: env suite |
| T-052 | Kernel information disclosure via `/proc`/`/sys`/syscalls | S-002 | `hidepid=2`; `/sys` absent; seccomp | Kernel metadata leaks are a residual kernel risk | adversarial: proc/sys suite |
| T-053 | Audit tampering or fabrication from inside | S-022, S-024 | Recorder host-side, outside the sandbox filesystem; workload cannot write it | Audit integrity vs. a compromised *supervisor* is out of scope (TCB compromise) | security: audit suite |
| T-054 | Audit failure misread as protection | S-024 | Documented: audit failure does not stop execution; enforcement is kernel-side; failure is itself reported | None expected | security: audit-failure suite |
| T-055 | Git configuration selects executables / invokes helpers (hostile repo config) | S-015, S-032 | Closed read-only git op set (status/diff/changed/untracked/deleted/base/current) + sanitized argv (highest-precedence `-c` overrides neutralize `core.fsmonitor`, `diff.external`/textconv, aliases, credential helpers, hooks, ssh, pager/editor, submodule recursion, protocol) + `git.read` policy gate; git runs inside the boundary so any residual execution is contained | A git bug could over-execute — contained by the boundary | adversarial: git-config suite (sandbox-boundary containment NATIVE VERIFIED 2026-08-22, see §10) |

---

## 7. Adversarial Test Mapping (Phase 2 `tests/adversarial/`)

Every attack category in the implementation plan Phase 2 list maps to
threats above; each mandatory invariant (S-001…S-040) maps to at least one
meaningful adversarial test that attacks the **actual runtime** (no mocks
for the boundary). Phase 2 P1 (commit 5408ce3) and P2 (commit dc1590a)
implemented the in-sandbox adversarial suite — 58 tests, plus the
fork-buffer regression added with the P3 exec-bridge work (59 total), all
exercising the real `RuntimeSession.execute()` → `run_in_sandbox()`
boundary:

| Attack category | Threats | Committed test module |
|---|---|---|
| Malicious Git hooks | T-047 | `tests/adversarial/test_content_attacks.py::HookAttackTests` |
| Hostile Git config (fsmonitor/ext-diff/textconv/aliases/credential/submodule/escape) | T-055 | `tests/adversarial/test_git_attacks.py::HostileConfigContainmentTests` (host-git control + sanitized-argv containment), `SandboxGitContainmentTests` (real boundary) |
| Malicious deps / install | T-048 | `tests/adversarial/test_content_attacks.py::DependencyAttackTests` |
| Malicious build/test scripts | T-049 | `tests/adversarial/test_content_attacks.py::BuildScriptAttackTests` |
| Path traversal | T-001, T-002 | `tests/adversarial/test_filesystem_attacks.py::PathTraversalTests`, `AbsolutePathEscapeTests` |
| Symlink escape | T-003 | `tests/adversarial/test_filesystem_attacks.py::SymlinkEscapeTests` |
| Hard-link attacks | T-004 | `tests/adversarial/test_filesystem_attacks.py::HardLinkAttackTests` |
| TOCTOU / path race | T-009 | `tests/adversarial/test_filesystem_attacks.py::TOCTOURaceTests` |
| Workspace boundary escape | T-011 | `tests/adversarial/test_filesystem_attacks.py::WorkspaceEscapeTests` |
| Fork bomb / process explosion | T-029 | `tests/adversarial/test_resource_attacks.py::ForkBombTests` |
| Memory exhaustion | T-030 | `tests/adversarial/test_resource_attacks.py::MemoryExhaustionTests` |
| Disk exhaustion | T-031 | `tests/adversarial/test_resource_attacks.py::DiskExhaustionTests` |
| FD exhaustion | T-032 | `tests/adversarial/test_resource_attacks.py::FDExhaustionTests` |
| Resource-limit increase | T-035 | `tests/adversarial/test_resource_attacks.py::ResourceLimitIncreaseTests` |
| Core dump leak | T-021 | `tests/adversarial/test_info_leakage.py::CoreDumpLeakTests` |
| Audit/environ leakage | T-022 | `tests/adversarial/test_info_leakage.py::AuditEnvironmentLeakageTests` |
| Audit tampering | T-053 | `tests/adversarial/test_info_leakage.py::AuditTamperingTests` |
| Incomplete cleanup | T-038 | `tests/adversarial/test_lifecycle_attacks.py::IncompleteCleanupTests` |
| Destroy race | T-039 | `tests/adversarial/test_lifecycle_attacks.py::DestroyRaceTests` |
| Policy tampering from inside | T-043 | `tests/adversarial/test_lifecycle_attacks.py::PolicyTamperingTests` |
| Prompt injection | T-050 | `tests/adversarial/test_lifecycle_attacks.py::PromptInjectionTests` |
| Mount attempts | T-005, T-010 | `tests/unit/test_namespaces.py`, `test_seccomp.py` (mount denied) |
| `/proc` | T-006, T-028 | `tests/unit/test_procdev.py::ProcMountTests` |
| `/sys` | T-007 | `tests/unit/test_procdev.py::SysAbsenceTests` |
| `/dev` | T-008 | `tests/unit/test_procdev.py::RootfsHostSideTests` |
| Namespace attacks | T-026 | `tests/unit/test_namespaces.py`, `test_seccomp.py` |
| Capability abuse | T-024 | `tests/unit/test_privileges.py::CapabilityTests` |
| Privilege escalation / setuid | T-023 | `tests/unit/test_privileges.py::NoNewPrivsTests` |
| ptrace | T-025 | `tests/unit/test_namespaces.py`, `test_seccomp.py` |
| Output exhaustion | T-033 | `tests/unit/test_output.py::BoundedOutputTests` |
| Network access | T-012, T-013, T-014 | `tests/unit/test_network.py` (socket denied; metadata 169.254.169.254 and private-range 192.168.1.1/172.16.0.1 probes) |
| DNS abuse | T-017 | v0.2 (no resolver in v0.1 — DESIGN INTENT) |
| Unix socket access | T-016, T-020 | `tests/unit/test_credentials.py` (socket deny) |
| Credential access | T-018, T-019, T-022 | `tests/unit/test_credentials.py`, `test_environment.py` |
| Environment leakage | T-018, T-051 | `tests/unit/test_environment.py` |
| Timeout / infinite run | T-034 | `tests/unit/test_timeout.py::DeadlineCollectionTests` |
| Child persistence / cleanup | T-036, T-037, T-038 | `tests/unit/test_lifecycle.py` |
| Policy bypass (CLI/MCP/API) | T-040, T-041, T-042 | `tests/unit/test_cli.py`, `test_mcp.py`, `test_api.py` (three-way equivalence); `tests/unit/test_cli_sessions.py` (Phase B command surface — create/exec/diff route through the sole policy gate; CLI/API refusal identical for a denied policy) |

Failure-mode tests (Phase 3) cover every row of the §14 fail-closed table:
namespace unavailable, network isolation failure, capability failure, seccomp
failure, resource-config failure, invalid filesystem config, invalid policy —
each must refuse execution with a specific reason, never "continue anyway".

---

## 8. Out of Scope and Residual Risks

Documented residual risks (security spec §18; kept honest, never claimed
away):

1. **Host kernel compromise** — a kernel vulnerability exploitable from
   inside the sandbox defeats every control. Mitigated by seccomp + minimal
   surface + no caps, but not eliminated.
2. **Trusted-component vulnerabilities** — a bug in the supervisor, security
   init, policy validator, or audit recorder is in the TCB and can break the
   boundary. Mitigated by small TCB, review, tests.
3. **seccomp allowlist completeness** — a syscall needed by the toolchain
   that is missing from the allowlist breaks workloads (availability), while
   an over-permissive entry widens the kernel surface. The list is derived
   empirically and reviewed in Phase 1 (ADR-008).
4. **Host configuration** — cgroup delegation, user-namespace enablement,
   and systemd configuration are host decisions. A misconfigured host either
   fails closed (HARDENED refused) or runs RESTRICTED with documented gaps —
   never silently.
5. **Container-vs-native divergence** — Docker Desktop runs (local dev) are
   *container-validated*, not native-Linux-validated; native CI is
   authoritative (ADR-014).
6. **The agent's own mistakes** — the sandbox contains them; it does not
   prevent the agent from breaking the *workspace* (e.g. deleting its own
   project copy). That is the product's intent, not a bug.
7. **Host admin / physical access / hypervisor / hardware** — explicitly
   out of scope.

---

## 9. Maintenance

- Every confirmed vulnerability ⇒ regression test (security spec §14) +
   this file updated with the threat, its vector, and the new mitigation.
- The threat list is re-reviewed whenever: a new interface is added (MCP,
   API, Git, snapshots), a new mechanism enters the boundary (v0.2 network
   allowlists, secret injection), or a security mode changes.
- The adversarial suite grows with the threat list; a threat without a test
   is an open item, not a claim.
---

## 10. Evidence Reconciliation (Phase 1 Steps 1-16 + Interface Phase + Phase 2 P1-P4)

**Date:** 2026-08-20
**Scope:** Every threat (T-001..T-054) and invariant (S-001..S-040)
**Classification key:**

- **DESIGN INTENT** -- Architecture/spec defines the control; no runtime test yet (or deferred to v0.2+)
- **HOST-SIDE VERIFIED** -- Tested on native Linux (CI ubuntu) or verified host-side on Windows
- **DOCKER VERIFIED** -- Tested inside Docker container (local dev validation)
- **NATIVE VERIFIED (real boundary)** -- In-sandbox attack executed through the real `RuntimeSession.execute()` → `run_in_sandbox()` boundary inside a Linux container (Phase 2 P1/P2 adversarial suite)
- **NOT VERIFIED / substrate limitation** -- Cannot be verified on current platform

**Substrate limitations (documented, preserved):**
- Windows: AppArmor restricts unprivileged user namespaces; `setgroups` denies `EACCES`; sandbox init refuses at `platform_linux` stage
- rootless cgroup v2: HARDENED mode requires cgroup delegation; if absent, HARDENED is refused (fail closed, verified)
- HARDENED end-to-end: **VERIFIED (NATIVE)** on Ubuntu 24.04 / kernel 6.8 / x86_64 (native QEMU VM) with a caller-owned delegated cgroup subtree (commit 7c1c30e); still refused where delegation is absent; GitHub-hosted runners run RESTRICTED (AppArmor userns restriction, unchanged)

### 10.1 Filesystem threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-001 Path traversal | S-001, S-030 | `test_rootfs.py` (workspace copy is fresh, host source unreachable); `test_skeleton.py` (config immutability); `test_filesystem_attacks.py::PathTraversalTests` (../, encoded forms through real boundary) | HOST-SIDE: rootfs build verified; NATIVE VERIFIED (real boundary): in-sandbox traversal suite |
| T-002 Absolute-path escape | S-001, S-002 | `test_rootfs.py` (workspace copy isolation); `test_procdev.py::RootfsHostSideTests` (no device nodes, no /sys); `test_filesystem_attacks.py::AbsolutePathEscapeTests` | HOST-SIDE: rootfs tree verified; NATIVE VERIFIED (real boundary): in-sandbox absolute-path suite |
| T-003 Symlink escape | S-001, S-029 | `test_rootfs.py::WorkspaceIsolationTests` (symlink escapes blocked, sandbox changes invisible on host); `test_filesystem_attacks.py::SymlinkEscapeTests` | HOST-SIDE: host-side isolation verified; NATIVE VERIFIED (real boundary): in-sandbox symlink suite |
| T-004 Hard-link attack | S-001 | `test_rootfs.py` (copytree preserves symlinks, workspace is a copy); `test_filesystem_attacks.py::HardLinkAttackTests` | HOST-SIDE: filesystem boundary exists; NATIVE VERIFIED (real boundary): in-sandbox hard-link suite |
| T-005 Mount/bind-mount attack | S-001, S-025 | `test_namespaces.py` (mount namespace private propagation); `test_seccomp.py` (mount syscall denied) | HOST-SIDE: mount flags + seccomp verified; DOCKER: real mount-denied test |
| T-006 /proc access | S-002, S-008 | `test_procdev.py::ProcMountTests` (hidepid=2, proc 1 is sandbox self); `test_procdev.py::RootfsHostSideTests` (no device nodes in rootfs) | DOCKER: real hidepid + proc isolation; HOST-SIDE: rootfs tree verified |
| T-007 /sys access | S-002 | `test_procdev.py::SysAbsenceTests` (/sys absent, host paths unreachable); `test_procdev.py::RootfsHostSideTests` (sys not in rootfs tree) | DOCKER: real /sys absence; HOST-SIDE: rootfs tree verified |
| T-008 /dev access | S-002 | `test_procdev.py::RootfsHostSideTests` (no device nodes in rootfs); `test_skeleton.py` (minimal /dev policy) | HOST-SIDE: rootfs verified; DOCKER: real /dev minimal (null/zero/random/urandom/full/tty only) |
| T-009 TOCTOU / path race | S-031 | `test_rootfs.py` (host source unreachable from sandbox); `test_filesystem_attacks.py::TOCTOURaceTests` (deterministic race attempt contained); `test_race_concurrency.py` (Phase 16: host-side concurrent registry writes/reads, concurrent session create/destroy, concurrent workspace file creation, symlink-replacement-during-read, concurrent policy decide/require — all security/state invariants preserved) | HOST-SIDE: boundary + concurrency verified (Phase 16); NATIVE VERIFIED (real boundary): in-sandbox race suite |
| T-010 Rootfs tampering | S-001, S-025 | `test_namespaces.py` (mount must fail after Step 7 capability drop); `test_seccomp.py` (mount denied) | DOCKER: real mount-denied under caps+seccomp |
| T-011 Workspace boundary escape | S-028 | `test_rootfs.py::WorkspaceIsolationTests` (workspace available inside, sandbox changes invisible on host, symlink escapes blocked); `test_filesystem_attacks.py::WorkspaceEscapeTests` | HOST-SIDE: workspace copy isolation; NATIVE VERIFIED (real boundary): in-sandbox workspace suite |

### 10.2 Network threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-012 Direct outbound access | S-005 | `test_network.py::NetworkDenyTests` (deny mode: no usable network path, connect fails; v0.2 Step 2: socket(AF_INET) allowed for the proxy path but every connect fails in the deny-by-construction netns); `test_network.py::NetworkPolicyTests` (loopback down) | DOCKER: real netns + connect-time denial; HOST-SIDE: policy + BPF domain filtering verified |
| T-013 Metadata endpoint | S-007 | `test_network.py` (169.254.169.254 unreachable by construction -- no network); `test_network.py::NetworkPolicyTests` (explicit connect_metadata probe 169.254.169.254:80 from inside) | DOCKER: real unreachable + explicit metadata probe verified |
| T-014 Private/link-local ranges | S-006 | `test_network.py` (no usable network path, RFC1918 unreachable); `test_network.py::NetworkPolicyTests` (explicit connect_host_gw 192.168.1.1:80 and host_gw 172.16.0.1:80 probes) | DOCKER: real unreachable + explicit private-range probes verified |
| T-015 SSRF via redirects | S-006 | **v0.2 Step 3 VERIFIED (NATIVE, container 2026-08-23):** `test_proxy.py::DestinationGateTests` (public allowed; private/loopback/link-local/metadata/multicast/unspecified/reserved denied; DNS-rebinding-to-private/loopback denied; allow_private relaxes ONLY the private-range class); `test_proxy.py::ConfigAllowlistTests` (dead allowlist entries — loopback/metadata/private-without-opt-in — rejected at configuration time); `test_proxy.py::ProxyProcessIntegrationTests` (real echo server: allowed destination forwarded, disallowed/private-without-opt-in/malformed/unauthorized-port DENIED with a deterministic reason); `test_proxy.py::FullSandboxProxyTests` (end-to-end through the real sandbox: workload reaches ONLY the proxy; a direct connection to a host service is DROPPED by the host firewall) | DOCKER/NATIVE: real proxy + firewall + sandbox verified; HOST-SIDE: pure validation unit-tested |
| T-016 Unix socket access | S-004 | `test_credentials.py::CredentialSandboxTests` (socket creation denied); `test_credentials.py::SocketCreationTests` (denial verified); v0.2 Step 2: AF_UNIX denied by BPF domain filter even though `socket` is allowlisted; v0.2 Step 3 e2e re-verifies AF_UNIX -> EPERM from inside the sandbox with the proxy live | DOCKER: real socket-denied; HOST-SIDE: policy + BPF domain filtering verified |
| T-017 DNS abuse/rebinding | S-005, S-006 | **v0.2 Step 3 VERIFIED:** host-side resolution in the trusted proxy (`resolve_host`); any failed resolution or any resolved address failing the SSRF gate is DENIED (fail closed) — `test_proxy.py::DestinationGateTests` (unresolvable denied, rebinding-to-private/loopback denied, any-private-among-multiple denied); the sandbox has no resolver and only the proxy route | DOCKER/NATIVE: real proxy resolution path verified; HOST-SIDE: unit-tested with mocked getaddrinfo |

### 10.3 Credential and secret threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-018 Env inheritance leaks secrets | S-003, S-034 | `test_environment.py::EnvConstructionTests` (6-variable construction, host values never read, sanitize+verify roundtrip); `test_environment.py::EnvSandboxTests` (host variable never reaches workload) | DOCKER: real env isolation; HOST-SIDE: construction verified |
| T-019 Credential files mounted | S-003 | `test_credentials.py::CredentialPathTests` (host paths absent, reachable paths reported); `test_credentials.py::CredentialSandboxTests` (credential paths unreachable in workload) | DOCKER: real credential-path isolation; HOST-SIDE: path policy verified |
| T-020 SSH-agent/credential sockets | S-004 | `test_credentials.py::CredentialSandboxTests` (socket creation denied, steps 6-11 invariants preserved) | DOCKER: real socket deny; HOST-SIDE: policy verified |
| T-021 Core dumps leak secrets | S-003 | `test_resources.py::ResourcePolicyTests` (RLIMIT_AS set, policy core is zero); `test_skeleton.py` (config validated); `test_info_leakage.py::CoreDumpLeakTests` (crash produces no core file) | HOST-SIDE: rlimit policy verified; NATIVE VERIFIED (real boundary): core-dump suite |
| T-022 Audit/environ leakage | S-003, S-039 | `test_api.py::ApiProtocolTests` (internal error does not leak); `test_mcp.py` (no host exception/environment leakage); `test_info_leakage.py::AuditEnvironmentLeakageTests` (six approved env vars only, no audit data in workload) | HOST-SIDE: interface no-leak verified; NATIVE VERIFIED (real boundary): env/audit leakage suite |

### 10.4 Privilege and process threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-023 setuid/setgid escalation | S-008, S-010 | `test_privileges.py::NoNewPrivsTests` (PR_GET_NO_NEW_PRIVS readback, establish_and_verify); `test_namespaces.py` (mount must fail after cap drop) | DOCKER: real nnp + cap-drop; HOST-SIDE: establish verified |
| T-024 Capability abuse | S-009 | `test_privileges.py::CapabilityTests` (drop_bounding_set, verify_capability_reduction, ambient CLEAR_ALL) | DOCKER: real cap-drop + readback; HOST-SIDE: policy verified |
| T-025 ptrace host processes | S-008, S-013 | `test_namespaces.py` (host processes not visible, PID namespace hides host); `test_seccomp.py` (ptrace denied by filter) | DOCKER: real PID isolation + seccomp; HOST-SIDE: namespace verified |
| T-026 Namespace escape | S-013 | `test_namespaces.py::NamespaceCreationTests` (user/mount/PID/network/UTS/IPC created); `test_seccomp.py` (unshare/clone denied) | DOCKER: real namespace creation + seccomp deny; HOST-SIDE: creation verified |
| T-027 Seccomp bypass | S-011 | `test_seccomp.py::SeccompBoundaryTests` (filter installed, forbidden syscall denied, fork denied under filter); `test_seccomp.py::SeccompHostTests` (allowlist loaded, BPF layout, enforcement EPERM) | DOCKER: real seccomp enforcement; HOST-SIDE: BPF + allowlist verified |
| T-028 Process inspection of host | S-008, S-013 | `test_procdev.py::ProcMountTests` (host processes not visible, proc 1 is sandbox self, hidepid enabled) | DOCKER: real proc isolation; HOST-SIDE: rootfs verified |

### 10.5 Resource threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-029 Fork bomb | S-012, S-013 | `test_resources.py::ResourcePolicyTests` (RLIMIT_NPROC set, all six soft+hard); `test_cgroups.py::CgroupPolicyTests` (pids.max); `test_resource_attacks.py::ForkBombTests` (fork loop contained, no survivors) | HOST-SIDE: rlimit + cgroup policy verified; NATIVE VERIFIED (real boundary): fork-bomb suite |
| T-030 Memory exhaustion | S-012 | `test_resources.py::ResourcePolicyTests` (RLIMIT_AS set, all limits); `test_cgroups.py::CgroupPolicyTests` (memory.max); `test_resource_attacks.py::MemoryExhaustionTests` (bounded exhaustion contained) | HOST-SIDE: policy verified; NATIVE VERIFIED (real boundary): memory suite (RESTRICTED per-process limit; cgroup memory.max = HARDENED, substrate-gated) |
| T-031 Disk exhaustion | S-012 | `test_resources.py::ResourcePolicyTests` (RLIMIT_FSIZE set); `test_cgroups.py::CgroupPolicyTests` (io.max); `test_resource_attacks.py::DiskExhaustionTests` (bounded disk write contained) | HOST-SIDE: policy verified; NATIVE VERIFIED (real boundary): disk suite (RESTRICTED per-process limit; cgroup io.max = HARDENED, substrate-gated) |
| T-032 FD exhaustion | S-012 | `test_resources.py::ResourcePolicyTests` (RLIMIT_NOFILE set); `test_resource_attacks.py::FDExhaustionTests` (fd loop contained) | HOST-SIDE: policy verified; NATIVE VERIFIED (real boundary): fd suite |
| T-033 Output exhaustion | S-037 | `test_output.py::BoundedOutputTests` (read_bounded, collect_bounded, truncation_notice, no bypass) | DOCKER: real bounded pipe + truncation; HOST-SIDE: policy verified |
| T-034 Timeout bypass | S-036 | `test_timeout.py::DeadlineCollectionTests` (deadline expiry terminates, no false success, timeout_notice) | DOCKER: real timeout enforcement; HOST-SIDE: deadline verified |
| T-035 Resource-limit increase | S-012, S-027 | `test_resources.py::ResourcePolicyTests` (verify hard/soft mismatch refuses, readback ok, apply before verify order); `test_resource_attacks.py::ResourceLimitIncreaseTests` (raise attempt blocked, limits immutable after drop) | HOST-SIDE: rlimit immutability verified; NATIVE VERIFIED (real boundary): in-sandbox raise suite |

### 10.6 Lifecycle and cleanup threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-036 Child persistence | S-014 | `test_lifecycle.py::ProcessContainmentTests` (establish_subreaper, terminate_tree, verify_no_workload_remains) | DOCKER: real subreaper + tree-kill + absence verify; HOST-SIDE: policy verified |
| T-037 Partial cleanup | S-038 | `test_lifecycle.py::CleanupTests` (namespace teardown, tmp removal, workspace removal) | DOCKER: real cleanup; HOST-SIDE: verification verified |
| T-038 Cleanup reported successful when incomplete | S-038, S-024 | `test_lifecycle.py::VerificationTests` (incomplete state reported, never claimed complete); `test_lifecycle_attacks.py::IncompleteCleanupTests` (cleanup after normal/error/output-exhaustion/timeout exits) | HOST-SIDE: verification logic verified; NATIVE VERIFIED (real boundary): cleanup suite |
| T-039 Repeated destroy / destroy during exec | S-038 | `test_lifecycle_attacks.py::DestroyRaceTests` (rapid exit with children, refusal prevents execution); `test_race_concurrency.py::CleanupRaceTests` (concurrent destroy idempotency, destroy-during-output-collection — host-side concurrency); `test_race_concurrency.py::SessionStateRaceTests` (concurrent execute+destroy, concurrent execute-twice, destroy-during-init — host-side state machine concurrency) | HOST-SIDE: state machine + concurrency verified; NATIVE VERIFIED (real boundary): destroy-race suite |

### 10.7 Policy and interface threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-040 CLI bypass of policy | S-015 | `test_policy.py::SessionPolicyGateTests` (denied capability refuses execution with deterministic reason before any boundary work); `test_cli.py::SessionExecuteTests` (refused session never reaches run_in_sandbox); `test_cli_sessions.py::ExecTests` / `DiffTests` / `EquivalenceTests` (Phase B: exec/diff re-open persisted sessions with strict manifest re-validation (S-021) and route through the same `RuntimeSession.execute()` policy gate; a denied capability refuses before the boundary; `git.read` gates diff; CLI/API refusal payload identical for the same denied policy); `test_api.py::ApiEquivalenceTests` / `test_mcp.py` (three-way CLI/MCP/API equivalence) | HOST-SIDE: policy gate + shared decision path verified (Phase B surface); NATIVE (real sandbox): diff/git ops execute inside the boundary (verified 2026-08-22 on the documented Ubuntu 24.04 / kernel 6.8 substrate after the documented `+chdir` expansion) |
| T-041 MCP bypass of policy | S-016 | `test_mcp.py` (no subprocess/os.system/os.popen; decision equivalence with CLI) | HOST-SIDE: MCP gate verified; three-way equivalence demo confirmed shared path |
| T-042 API bypass of policy | S-017 | `test_api.py::ApiEquivalenceTests` (success/refusal/malformed/invalid equivalent across all three); `test_api.py::ApiStructuralGuardTests` (no execution primitives, no framework) | HOST-SIDE: API gate verified; three-way equivalence demo confirmed shared path |
| T-043 Policy tampering from inside | S-025, S-026 | `test_policy.py::PolicyImmutabilityTests` (frozen Policy, read-only capability map, policy never enters the rootfs tree via the real `build_rootfs`); `test_lifecycle_attacks.py::PolicyTamperingTests` (in-sandbox tamper attempt contained) | HOST-SIDE: immutability + rootfs-absence verified; NATIVE VERIFIED (real boundary): in-sandbox tamper suite |
| T-044 Malformed/unknown policy fields | S-021 | `test_policy.py::PolicyValidationTests` (unknown top-level field / unknown capability / unsupported version / non-bool value rejected with deterministic message); `test_failclosed_matrix.py::PolicyFailClosedTests` (invalid policy never initializes) | HOST-SIDE: strict policy validator verified |
| T-045 Ambiguous policy | S-021 | `test_policy.py::PolicyValidationTests` (policy/config resource conflict rejected — never a silent second source); `test_skeleton.py::ConfigValidationTests` (unsupported mode rejected) | HOST-SIDE: deterministic evaluation + conflict rejection verified |
| T-046 Mode misrepresentation | S-019, S-020 | `test_skeleton.py::InitializationTests` (platform_fail_closed_on_non_linux, no_silent_downgrade); `test_api.py` (mode in every response) | HOST-SIDE: mode reporting verified across all interfaces |

### 10.8 Content and supply chain threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-047 Malicious Git hooks | S-032 | `test_content_attacks.py::HookAttackTests` (hook executes inside sandbox, shell + outbound attempt contained, no host file modification, cleanup complete) | NATIVE VERIFIED (real boundary): git-hook suite |
| T-048 Malicious dependencies | S-033 | `test_content_attacks.py::DependencyAttackTests` (install payload executes inside, privileged fs modification attempt contained, no host modification, cleanup complete); **Phase 10 (v0.2 Step 4) now provides the INSTALL workflow itself** — `pip install --proxy http://10.255.254.0:8080` inside the real sandbox: destination validated by the proxy (disallowed source DENIED — `test_proxy.py::Phase10DependencyInstallTests`), direct networking blocked by the host firewall, AF_UNIX/NETLINK/PACKET denied by the BPF domain filter, clone/clone3/bind still denied, teardown clean (no veth/firewall/proxy leaks). The allowlist grew 69 → 70 (+fsync only, the single genuinely-required syscall; see policy.md §5). The v0.1 deferral by ADR-006 (network) is lifted for the pip path; **Node/Rust (npm/cargo) workflows: MEASURED and INTENTIONALLY UNSUPPORTED (2026-08-23)** — real-filter measurement proves both unconditionally require clone3 (Node's platform scheduler thread at startup; cargo spawning rustc even for fetch); clone/clone3 are the S-014 single-process boundary, so no expansion — npm/cargo fail closed cleanly in-sandbox (node rc=139, cargo rc=101, no hang/leak; `test_proxy.py::Phase10NpmCargoDecisionTests` + `Phase10NpmCargoFailClosedTests`) | NATIVE VERIFIED (real boundary): dependency suite + Phase 10 install e2e (2026-08-23) — containment AND install workflow both verified |
| T-049 Malicious build/test scripts | S-032 | `test_content_attacks.py::BuildScriptAttackTests` (script executes inside, protected host data read + write-outside-workspace attempt contained, no credential leak, cleanup complete) | NATIVE VERIFIED (real boundary): build-script suite |
| T-050 Prompt injection | S-015 | `test_policy.py::SessionPolicyGateTests` (requests gated on required capabilities — injected instructions cannot grant capabilities the policy denies); `test_lifecycle_attacks.py::PromptInjectionTests` (injected instructions contained, no host effect) | HOST-SIDE: policy-gated decision path verified; NATIVE VERIFIED (real boundary): injection suite |
| T-055 Hostile Git config | S-015, S-032 | `test_git_attacks.py::HostileConfigContainmentTests` (control proves plain `git diff` executes hostile external-diff + fsmonitor scripts; sanitized argv runs status/diff with ZERO hostile execution — aliases, diff.external, textconv, fsmonitor incl. include.path-amplified, credential helpers, hooks all neutralized — empirically verified against the fixture); `test_git_workflow.py` (closed op set — commit/push/fetch/checkout/submodule refused; git.read denial refuses before the boundary; `git` CLI routing through the sole execution path); `SandboxGitContainmentTests` (real boundary: hostile repo status/diff/hook payloads/symlink+gitfile escapes contained — no host file ever created, cleanup verified) | HOST-SIDE VERIFIED: config-control layer (control + sanitized containment); **NATIVE VERIFIED (real boundary, 2026-08-22): SandboxGitContainmentTests 4/4 PASS on the documented Ubuntu 24.04 / kernel 6.8 substrate** — after the documented `+chdir` allowlist expansion (45→46, policy.md §5) the hostile repo status/diff/hook/symlink-gitfile operations execute through the real HARDENED boundary with zero host markers; the git closed set was previously blocked inside the sandbox by the missing `chdir` syscall (F-1, native finding, NOT substrate-limited) |
| T-056 Malformed parser/interface input | S-021, S-024, S-015 | Phase 15 fuzz harness (implementation.md Phase 15): `tests/fuzz/test_fuzz_parsers.py` + `tests/fuzz/test_fuzz_interfaces.py` — deterministic (seed `0xC0FFEE`), bounded, stdlib-only mutation fuzzing of the policy parser (no capability amplification, no policy-state corruption), config parser (network_mode can never escape `deny`), environment allowlist construction, registry manifest/id gates, git argv builder (hostile args stay literal argv elements), MCP `parse_message` (deterministic JSON-RPC errors), audit write/read-back (never raises, observational); CLI argv fuzz against an empty state dir (never raises, never mutates session state). **Caught + fixed in scope (2026-08-22): F-1** `network_mode` unhashable-value `TypeError` → deterministic `ConfigError`; **F-3** `logs` `UnicodeDecodeError` on non-UTF-8 audit bytes → `errors="replace"`; **F-4** `logs` `AttributeError` on non-dict JSON audit lines → `isinstance(ev, dict)` skip. 21/21 fuzz tests + N1 harness-hygiene rows PASS; CI fuzz step added. **HOST-SIDE / unit-level evidence only** — validates the trusted-side seams; does NOT replace native kernel-boundary verification (T-027 seccomp fuzzing remains Phase 15-mapped; the kernel boundary evidence stays the native/adversarial suites) |

### 10.9 Observation and information leakage threats

| Threat | Invariant | Evidence | Classification |
|---|---|---|---|
| T-051 Host details via environment | S-034 | `test_environment.py::EnvConstructionTests` (host values never read, explicit allowlist) | HOST-SIDE: env construction verified; DOCKER: real env isolation |
| T-052 Kernel info via /proc//sys | S-002 | `test_procdev.py::ProcMountTests` (hidepid=2, kernel interfaces not readable); `test_procdev.py::SysAbsenceTests` (/sys absent) | DOCKER: real proc/sys isolation |
| T-053 Audit tampering from inside | S-022, S-024 | `test_cli.py::AuditTests` (recorder writes JSONL, failure is observational, open-per-record no persistent fd); `test_info_leakage.py::AuditTamperingTests` (in-sandbox tamper attempt contained, audit path unreachable) | HOST-SIDE: recorder verified; NATIVE VERIFIED (real boundary): in-sandbox tamper suite |
| T-054 Audit failure misread as protection | S-024 | `test_cli.py::AuditTests` (recorder failure is observational, does not block execution) | HOST-SIDE: failure-mode verified |

### 10.10 Security-mode evidence (HARDENED vs RESTRICTED)

| Property | Evidence | Classification |
|---|---|---|
| RESTRICTED mode runs on all platforms | `test_skeleton.py` (real_non_linux_host_refuses_any_mode); CI passes on ubuntu + Windows | HOST-SIDE + CI verified |
| HARDENED requires cgroup delegation | `test_cgroups.py::CgroupProbeTests` (hardened blocks without delegation); `test_skeleton.py` (hardened refuses when probe fails) | HOST-SIDE: probe + refusal verified; DOCKER: real cgroup probe |
| HARDENED end-to-end on native Linux | P3 (commit 7c1c30e): `tests/native/test_hardened_e2e.py` — 24/24 PASS, 0 fail, 0 error, 0 skip on Ubuntu 24.04 / kernel 6.8 / x86_64 native QEMU VM, caller-owned delegated cgroup subtree (controllers enabled: cpu io memory pids), real io.max backing device, toolchain `/opt/agent-sandbox-toolchain`. HARDENED reaches READY; workload executes; seccomp active + socket() denied; capabilities zero; no_new_privs=1; PID/network namespaces isolated; six approved env vars only; timeout + cleanup verified; audit session identity correct. Earlier substrate run (commit e3b9873, Docker Desktop/WSL2: controllers available but NOT enabled in subtree_control; io.max unresolvable on overlay) correctly refused at RESOURCES — preserved as historical evidence | HARDENED END-TO-END VERIFIED (NATIVE) on the documented Ubuntu 24.04 / kernel 6.8 / x86_64 substrate only; NOT generalized to other kernels/distros, aarch64, CI runners, or proof of the entire SECURITY_SPEC.md. HARDENED still refuses execution when mandatory cgroup delegation/resources cannot be established (fail closed, verified) |

### 10.11 Interface-phase evidence

| Property | Evidence | Classification |
|---|---|---|
| CLI/MCP/API share single enforcement core | `interface.py` (SessionManager); `test_api.py::ApiEquivalenceTests` (three-way decision equivalence); integration demo (2026-08-20) | HOST-SIDE VERIFIED |
| CLI cannot bypass policy | `test_cli.py::SessionExecuteTests` (refused session blocked, no shell); `test_cli.py::RequestValidationTests`; `test_cli_sessions.py` (create/exec/run/status/diff/logs/destroy all route through `RuntimeSession.execute()` — no alternate path; unknown/destroyed/tampered sessions fail closed exit 5; destroy never claims success on incomplete cleanup) | HOST-SIDE VERIFIED |
| MCP cannot bypass policy | `test_mcp.py` (no subprocess/os.system; decision equivalence with CLI) | HOST-SIDE VERIFIED |
| API cannot bypass policy | `test_api.py::ApiStructuralGuardTests` (no execution primitives, no framework); three-way equivalence | HOST-SIDE VERIFIED |
| Refusal semantics equivalent | Integration demo: CLI exit 3/4, MCP -32602, API HTTP 400 -- all deterministic | HOST-SIDE VERIFIED |
| Audit events session-correlated | `test_cli.py::AuditTests` (session_correlates_events, JSONL output); integration demo | HOST-SIDE VERIFIED |
| No host fallback or bypass exists | `test_cli.py::RequestValidationTests` (interface_modules_have_no_shell_or_subprocess); `test_api.py::ApiStructuralGuardTests` | HOST-SIDE VERIFIED |

### 10.12 Summary statistics

| Classification | Count | Notes |
|---|---|---|
| NATIVE VERIFIED (real boundary) | 22 | Phase 2 P1/P2 in-sandbox adversarial suites (58 tests) through the real boundary + P3 HARDENED e2e suite (24 tests, commit 7c1c30e) on the documented native substrate |
| DOCKER VERIFIED | 24 | Real sandbox execution inside Docker container |
| HOST-SIDE VERIFIED | 7 | Policy/interface/mode gate verified host-side or on CI (no runtime attack test) |
| DESIGN INTENT | 2 | T-015 (SSRF), T-017 (DNS) -- deferred to v0.2 (no network in v0.1) |

**Phase 18 CI/tooling evidence (2026-08-22):** Static analysis, type checking, dependency auditing, secret scanning, and security scanning are now integrated into CI. Tools: ruff (F/S/B rules, justified exclusions), mypy (platform-specific Linux-attr ignores), bandit (B101/B108/B606/B110/B603/B607 exclusions — all justified), pip-audit (zero runtime deps verified), detect-secrets (baseline with 7 documented false positives: cache files + test fixtures). Security-scan failures block CI. **CI/tooling-level evidence** — proves the gates exist; does NOT replace native kernel-boundary verification, adversarial testing, or seccomp verification.

**Phase 20 release hardening (2026-08-22):** A release checklist (`RELEASE_CHECKLIST.md`) documents the verification status of every v0.1 criterion. All v0.1 acceptance criteria (implementation.md section 26) are verified: runtime, filesystem/process/network isolation, privilege reduction, resource controls, environment sanitization, fail-closed init, session lifecycle, structured audit, CLI, regression tests, adversarial tests. Not claimed: production-ready, fully verified, signed release, independently reviewed. Independent Security Review: REQUIRED / NOT YET PERFORMED. Release artifact reproducibility: VERIFIED (2026-08-23, `tools/release/` — deterministic sdist/wheel, byte-identity gate, SHA-256 manifest + tamper detection; signing mechanism prepared, credential external). aarch64: SUBSTRATE-LIMITED / NOT VERIFIED. Full SECURITY_SPEC.md: PARTIALLY VERIFIED.

**Substrate-gated (see 10.10):** aarch64 filter install/enforcement (P4) remains NOT VERIFIED / substrate limitation. HARDENED end-to-end (P3) is now VERIFIED (NATIVE) on the documented Ubuntu 24.04 / kernel 6.8 / x86_64 substrate (commit 7c1c30e).

**Key gaps (by design, documented):**
1. **HARDENED end-to-end (P3)** -- now HARDENED END-TO-END VERIFIED (NATIVE) on the documented Ubuntu 24.04 / kernel 6.8 / x86_64 QEMU VM with a caller-owned delegated cgroup subtree (commit 7c1c30e, 24/24 PASS). The fail-closed refusal at RESOURCES when delegation is absent remains correct and verified on substrates without it (earlier e3b9873 Docker/WSL2 run preserved as historical evidence)
2. **aarch64 runtime (P4)** -- allowlist derivation (67 syscalls), BPF construction, AUDIT_ARCH_AARCH64 guard, syscall-number validity all HOST-VERIFIED; filter installation/enforcement NOT VERIFIED (Docker Desktop's runtime seccomp blocks PR_SET_SECCOMP; requires native aarch64)
3. **T-015 / T-017 (network)** -- v0.1: no network exists (deny by construction) and SSRF/DNS were DESIGN INTENT. v0.2 Step 3 (2026-08-23) implements + verifies the SSRF/DNS protection in the validating proxy: destination validation at connect, host-side resolution, DNS-rebinding denial, config-time dead-entry rejection (see 10.2 rows). Remaining documented limitation: the proxy is IPv4-only (IPv6 destinations are denied) and the iptables rules require the `iptables` binary + CAP_NET_ADMIN (fail closed otherwise)
4. **rootless cgroup v2** -- HARDENED refused when delegation absent; documented gap, not silently degraded

**No false claims detected:** The updated evidence table does not claim "fully verified" where only Docker or host-side evidence exists; every Phase 2 adversarial result is labeled NATIVE VERIFIED (real boundary) with the exact committed test module. P3 HARDENED end-to-end is labeled VERIFIED (NATIVE) only for the documented Ubuntu 24.04 / kernel 6.8 / x86_64 substrate (commit 7c1c30e, 24/24 PASS); P4 aarch64 runtime enforcement remains honestly classified as SUBSTRATE-LIMITED / NOT VERIFIED.
