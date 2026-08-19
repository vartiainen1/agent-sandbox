# agent-sandbox - SECURITY SPECIFICATION (in-repo copy)
# Source of truth: "dont touch/security-spec.md" (kept out of this repo).
# This copy is canonical for the repository; keep in sync with the source.

# agent-sandbox

# Security Specification

## 1. Purpose

This document defines the security properties that `agent-sandbox` must maintain.

`DESIGN.md` describes how the system is intended to be structured.

This document defines what the system must guarantee.

The implementation must not be considered complete merely because the architecture described in `DESIGN.md` exists.

The security properties in this document must be demonstrated through tests, verification, and documented evidence.

---

# 2. Security Objective

The primary security objective is:

> Prevent an untrusted sandbox workload from obtaining unauthorized access to the host or resources outside the explicitly authorized sandbox policy.

The sandbox must remain secure even if:

- the AI agent is malicious
- the AI agent is compromised
- the repository is malicious
- repository instructions contain prompt injection
- dependencies are malicious
- build scripts are malicious
- tests are malicious
- executed programs are malicious
- network responses are malicious

---

# 3. Security Boundary

The sandbox security boundary is the combination of:

- host-side sandbox initialization
- operating-system isolation
- filesystem isolation
- process isolation
- network isolation
- capability restrictions
- seccomp
- resource controls
- policy enforcement

The AI agent is NOT part of the security boundary.

MCP is NOT the security boundary.

The API is NOT the security boundary.

The audit system is NOT the security boundary.

The operating system must enforce the actual containment boundary.

---

# 4. Trust Model

## Trusted

The trusted computing base should be minimized.

Potentially trusted:

- Linux kernel
- minimal host-side runtime
- security initialization code
- policy validator
- required privileged helper, if one exists
- security-critical configuration

## Untrusted

The following must be treated as untrusted:

- LLM
- MCP client
- API client
- repository
- repository files
- repository instructions
- Git hooks
- dependencies
- build scripts
- test programs
- downloaded content
- network responses
- generated code

---

# 5. Security Invariants

The following invariants must always hold in HARDENED mode.

## S-001: Filesystem Isolation

A sandbox workload must not access host filesystem paths outside explicitly authorized resources.

Expected behavior:

    unauthorized access -> DENIED

---

## S-002: No Implicit Host Filesystem Access

The host root filesystem must not be exposed to the sandbox by default.

The host home directory must not be exposed by default.

Sensitive directories must not be implicitly available.

---

## S-003: Credential Isolation

Host credentials must not be inherited by default.

This includes:

- SSH credentials
- cloud credentials
- API keys
- GitHub credentials
- Kubernetes credentials
- application secrets

---

## S-004: Unix Socket Isolation

Host control sockets must not be exposed by default.

Examples:

- Docker socket
- container runtime sockets
- SSH agent sockets
- Kubernetes sockets
- credential-manager sockets

---

## S-005: Network Default Deny

Network access must be denied unless explicitly authorized by policy.

---

## S-006: Private Network Protection

Private and internal network ranges must not be reachable by default.

This includes protection against SSRF.

---

## S-007: Metadata Protection

Cloud metadata services must be inaccessible unless explicitly authorized.

---

## S-008: Privilege Restriction

The sandbox workload must not be able to arbitrarily acquire additional privileges.

---

## S-009: Capability Restriction

Unnecessary Linux capabilities must be removed.

Dangerous capabilities must not be granted without explicit architectural justification.

---

## S-010: no_new_privs

`no_new_privs` must be enabled before untrusted workload execution in hardened Linux mode.

---

## S-011: Syscall Restriction

A hardened workload must be subject to an appropriate syscall restriction policy.

---

## S-012: Resource Limits

The sandbox workload must not be able to increase its own resource limits.

This includes:

- CPU
- memory
- processes
- file descriptors
- disk
- output
- wall-clock execution time

---

## S-013: Process Containment

Processes spawned by the workload must remain within the sandbox process boundary.

---

## S-014: Process Cleanup

Destroying a sandbox must terminate the sandbox's process tree.

The implementation must not only terminate the original parent process.

---

## S-015: Policy Enforcement

All privileged or security-sensitive operations must pass through policy enforcement.

---

## S-016: MCP Cannot Bypass Security

MCP requests must pass through the same security controls as CLI/API requests.

---

## S-017: API Cannot Bypass Security

The API must not provide an alternate path around policy enforcement.

---

## S-018: Fail Closed

If a mandatory security control cannot be established, hardened execution must not begin.

---

## S-019: No Silent Security Downgrade

The implementation must never silently disable a security control to improve compatibility.

---

## S-020: Explicit Security Mode

Every session must expose its security mode.

Possible modes:

    HARDENED
    RESTRICTED
    COMPATIBILITY

The user must be able to determine which mode is active.

---

## S-021: Policy Validation

Invalid or ambiguous security policy must be rejected.

Security-critical unknown fields must not silently change behavior.

---

## S-022: Auditability

Security-sensitive decisions must generate structured audit events.

---

## S-023: Session Correlation

Security events must be associated with a sandbox session ID.

---

## S-024: Audit Is Not Enforcement

The audit system must not be required to enforce security.

If audit recording fails, the implementation must follow the documented failure policy rather than assuming logging equals protection.

---

## S-025: Host Control

The sandbox workload must not be able to modify the host's sandbox security configuration.

---

## S-026: Policy Immutability

Once a session begins, security-critical policy must not be modifiable from inside the sandbox.

---

## S-027: Resource Policy Immutability

The sandbox workload must not increase CPU, memory, process, disk or other enforced resource limits.

---

## S-028: Workspace Boundary

The workspace must remain inside the authorized filesystem boundary.

---

## S-029: Symlink Safety

Symlinks must not allow access outside authorized paths.

---

## S-030: Path Traversal Protection

Relative or encoded path traversal must not allow unauthorized filesystem access.

---

## S-031: Race Safety

Security-sensitive filesystem checks must not rely on unsafe check-then-use behavior where a race can bypass the intended restriction.

---

## S-032: Malicious Repository Safety

A repository containing malicious build scripts, tests or hooks must not automatically gain host privileges.

---

## S-033: Dependency Safety

Dependencies installed inside the sandbox must remain sandboxed.

---

## S-034: Environment Isolation

The host environment must not be blindly inherited.

---

## S-035: Controlled Execution

The workload must execute only through the configured sandbox runtime.

---

## S-036: Timeout Enforcement

Timeouts must be enforced externally and cannot be disabled by the workload.

---

## S-037: Output Limits

The workload must not be able to generate unlimited output that exhausts host resources.

---

## S-038: Cleanup Failure Visibility

Incomplete cleanup must be detectable and reported.

---

## S-039: Security Errors Are Explicit

Security violations must produce structured, actionable errors.

---

## S-040: Security Configuration Is Observable

The active security configuration must be inspectable without exposing sensitive host information.

---

# 6. Failure Behavior

The sandbox must fail safely.

## Policy Failure

If policy parsing or validation fails:

    reject policy
    do not execute workload

---

## Namespace Failure

If required namespace isolation cannot be established:

    abort hardened execution

---

## Filesystem Isolation Failure

If required filesystem isolation cannot be established:

    abort hardened execution

---

## Network Isolation Failure

If network isolation is required but cannot be established:

    abort hardened execution

---

## Capability Configuration Failure

If required capability restrictions cannot be established:

    abort hardened execution

---

## Seccomp Failure

If seccomp is mandatory for the selected security mode and cannot be established:

    abort hardened execution

---

## Resource Limit Failure

If mandatory resource controls cannot be established:

    abort hardened execution

---

## Environment Sanitization Failure

If the runtime cannot guarantee the required environment isolation:

    abort hardened execution

---

## Cleanup Failure

If sandbox cleanup is incomplete:

    attempt recovery
    record failure
    expose incomplete cleanup state
    never report cleanup as successful when it was not

---

# 7. Security Downgrade Rules

Security downgrades must be explicit.

Forbidden:

    seccomp unavailable
    WARNING
    continuing anyway

Allowed:

    HARDENED execution unavailable.

    Reason:
    seccomp could not be configured.

    The sandbox refused to execute the workload.

If a weaker mode exists, the user must explicitly select it or explicitly approve its use according to the project's policy model.

---

# 8. Network Security Requirements

Network security must account for:

- DNS
- redirects
- IPv4
- IPv6
- private address ranges
- loopback
- link-local addresses
- metadata endpoints
- DNS rebinding
- alternate address representations

A hostname allowlist alone is not sufficient.

---

# 9. Filesystem Security Requirements

The implementation must defend against:

- `../`
- absolute path escapes
- symlink escapes
- hard-link attacks
- mount points
- bind mounts
- `/proc`
- `/sys`
- `/dev`
- race conditions
- TOCTOU

---

# 10. Process Security Requirements

The implementation must defend against:

- fork bombs
- process-tree abuse
- ptrace
- unauthorized process inspection
- privilege escalation
- setuid behavior
- uncontrolled child processes

---

# 11. Credential Security Requirements

The implementation must prevent accidental exposure of:

- environment credentials
- SSH keys
- cloud credentials
- API keys
- authentication sockets
- host configuration files containing secrets

---

# 12. Adversarial Security Requirements

The test suite must actively attempt:

- filesystem escape
- namespace escape
- network escape
- credential theft
- privilege escalation
- resource exhaustion
- process escape
- policy bypass
- MCP authorization bypass
- API authorization bypass
- cleanup bypass

---

# 13. Evidence Requirements

A security claim is not considered proven merely because the code appears correct.

Each important claim should have evidence.

Example:

    Claim:
    Sandbox cannot access host SSH credentials.

    Evidence:
    test_ssh_directory_denied
    test_ssh_key_symlink_denied
    test_environment_ssh_isolation
    test_ssh_agent_socket_denied

    Result:
    PASS

---

# 14. Regression Requirements

Every confirmed security vulnerability should become a regression test where practical.

A vulnerability must not simply be patched and forgotten.

The test suite should permanently protect against recurrence.

---

# 15. Fuzzing Requirements

Security-sensitive parsers and interfaces should be fuzzed.

At minimum:

- policy parser
- configuration parser
- MCP messages
- path processing
- network policies
- audit serialization

Malformed input must fail safely.

---

# 16. Security Test Mapping

Security requirements should map to tests.

Example:

    S-001 -> filesystem isolation tests
    S-005 -> network isolation tests
    S-008 -> privilege tests
    S-012 -> resource tests
    S-014 -> lifecycle tests
    S-016 -> MCP authorization tests
    S-018 -> failure-mode tests
    S-029 -> symlink tests
    S-031 -> race-condition tests

The project should maintain this mapping as it grows.

---

# 17. Security Modes

## HARDENED

All mandatory security controls for the platform are active.

Failure of a mandatory control prevents execution.

## RESTRICTED

Some guarantees are weaker.

The exact differences must be documented.

## COMPATIBILITY

Functionality is prioritized over strong isolation.

This mode must never be represented as equivalent to hardened execution.

---

# 18. Residual Risk

The sandbox does not guarantee protection against:

- a compromised host kernel
- a malicious hypervisor
- hardware compromise
- host administrator intentionally disabling security
- previously unknown kernel vulnerabilities
- vulnerabilities in trusted host components

These limitations must be documented.

---

# 19. Security Principle

The most important rule is:

> If the system cannot guarantee the required security property, it must refuse to claim that the property exists.

The project must prefer:

    safe failure

over:

    unsafe compatibility

---

# 20. Security Completion Criteria

Security work is not complete when the sandbox starts commands.

It is complete only when:

- invariants are implemented
- security controls are enforced
- adversarial tests exist
- failure behavior is tested
- regression tests exist
- security configuration is observable
- limitations are documented
- security claims have supporting evidence
- independent review is possible

---

# 21. Final Security Principle

The sandbox must assume that eventually something inside it will try to escape.

The system must be designed so that:

    malicious workload
          |
          v
    attempts attack
          |
          v
    OS enforcement
          |
          v
    attack blocked
          |
          v
    event recorded
          |
          v
    sandbox remains contained

Security is not a warning.

Security is not a README claim.

Security is an enforced property that must be tested.
