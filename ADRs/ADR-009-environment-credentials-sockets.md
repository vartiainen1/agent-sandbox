# ADR-009 — Environment, Credentials, and Sockets: Explicit Allowlist, No Host Mounts

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-003 (credential isolation), S-004 (socket isolation), S-034 (no blind
environment inheritance). The host environment routinely contains tokens
(`GITHUB_TOKEN`, `AWS_*`, `SSH_AUTH_SOCK`, …) and the host has control
sockets (Docker, SSH agent, K8s) whose exposure is equivalent to host
access (design §14, §16).

## Decision

- The host environment is **never inherited** (S-034). The supervisor
  builds an explicit environment from an allowlist: `PATH`, `HOME`, `LANG`,
  `LC_ALL`, `TERM`, `TMPDIR` (all pointing inside the sandbox) plus
  policy-declared variables. Everything else is dropped.
- **No host sockets** are ever exposed (S-004): Docker socket, SSH agent,
  K8s, credential managers are absent from the rootfs (ADR-005) and the
  network namespace (ADR-006).
- **No credential files** are reachable (S-003): no `.ssh`, `.aws`,
  `.config`, K8s mounts; the workspace is a copy (a project that *contains*
  a secret in its source ships it into its own copy — user responsibility).
- `RLIMIT_CORE=0` prevents secret spill into core dumps (T-021).
- Secret injection (design §16) is a future, narrowly scoped capability,
  gated by explicit policy; it is **not** in v0.1.

## Consequences

- Positive: credentials are absent by construction — nothing to leak, steal,
  or exfiltrate.
- Negative: any legitimately needed variable must be declared in policy
  (explicit, auditable); workflows needing host credentials do not exist in
  v0.1.

## References

ARCHITECTURE §7, §11; THREAT_MODEL T-018…T-022; security spec §11.
