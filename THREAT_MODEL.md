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
| T-015 | SSRF via redirects / DNS rebinding / alternate address forms | S-006 | Deferred to v0.2 (no network in v0.1); v0.2 must enforce destination validation at connect, not hostname allowlists | Open until v0.2 (documented gap, not silently present) | v0.2: proxy suite |
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

---

## 7. Adversarial Test Mapping (Phase 2 `tests/adversarial/`)

Every attack category in the implementation plan Phase 2 list maps to
threats above; each mandatory invariant (S-001…S-040) maps to at least one
meaningful adversarial test that attacks the **actual runtime** (no mocks
for the boundary):

| Attack category | Threats | Planned test module |
|---|---|---|
| Path traversal | T-001, T-002 | `test_traversal.py` |
| Symlink escape | T-003, T-011 | `test_symlink.py` |
| Hard-link attacks | T-004 | `test_hardlink.py` |
| `/proc` | T-006, T-028 | `test_proc.py` |
| `/sys` | T-007 | `test_sys.py` |
| `/dev` | T-008 | `test_dev.py` |
| Mount attempts | T-005, T-010 | `test_mount.py` |
| Namespace attacks | T-026 | `test_namespace.py` |
| Capability abuse | T-024 | `test_capabilities.py` |
| Privilege escalation / setuid | T-023 | `test_privilege.py` |
| ptrace | T-025 | `test_ptrace.py` |
| Process explosion | T-029 | `test_forkbomb.py` |
| Memory exhaustion | T-030 | `test_memory.py` |
| Disk exhaustion | T-031 | `test_disk.py` |
| Output exhaustion | T-033 | `test_output.py` |
| Network access | T-012, T-014 | `test_network.py` |
| Private network | T-014 | `test_private_net.py` |
| Metadata access | T-013 | `test_metadata.py` |
| DNS abuse | T-017 | `test_dns.py` (v0.2) |
| Unix socket access | T-016, T-020 | `test_sockets.py` |
| Docker socket access | T-016 | `test_docker_socket.py` |
| Credential access | T-018, T-019, T-022 | `test_credentials.py` |
| Environment leakage | T-018, T-051 | `test_environment.py` |
| Timeout / infinite run | T-034 | `test_timeout.py` |
| Child persistence / cleanup | T-036, T-037, T-038 | `test_lifecycle.py` |
| Policy bypass (CLI/MCP/API) | T-040, T-041, T-042 | `test_policy_bypass.py` |
| Malicious Git hooks | T-047 | `test_git_hooks.py` |
| Malicious deps / scripts | T-048, T-049 | `test_supply_chain.py` |

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
