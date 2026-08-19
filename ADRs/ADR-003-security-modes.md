# ADR-003 — Security Modes: HARDENED / RESTRICTED / COMPATIBILITY

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

Security spec S-019 (no silent downgrade), S-020 (explicit security mode)
and the design §34 require three explicit modes and forbid pretending a
weaker mode is hardened. Hosts will differ in what they can provide
(cgroup delegation, user namespaces), so the system needs an honest way to
run with documented weaker guarantees.

## Decision

- **HARDENED** — every mandatory control active: all namespaces, capability
  bounding drop, `no_new_privs`, seccomp, cgroups v2 + rlimits, `pivot_root`
  isolation, env sanitization, network deny-by-construction. Any mandatory
  control that cannot be established ⇒ execution refused with the specific
  reason (S-018). This is the only mode in which security claims are made.
- **RESTRICTED** — documented weaker set for hosts that cannot delegate
  cgroups or provide a control. The exact differences are recorded per
  deployment (e.g. rlimits only, no `io.max`/`memory.max`). Selection is an
  explicit user action (`--mode restricted`), never automatic.
- **COMPATIBILITY** — functionality over isolation; for functional testing
  only; never represented as secure.
- Every session reports its mode and the controls actually established,
  machine-readable (S-020).

## Consequences

- Positive: honest failure instead of silent weakening; users can see what
  they are getting.
- Negative: on constrained hosts, HARDENED is unavailable — by design.

## References

ARCHITECTURE §17, §19; security spec §6, §7, §17; THREAT_MODEL T-046.
