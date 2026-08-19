# ADR-002 — Trusted Computing Base: Minimal Supervisor, No Privileged Helper in v0.1

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

Implementation rule 3: keep the TCB as small as practical. The trust model
(ARCHITECTURE §3.1) must be concrete about which components are trusted and
whether any privileged (setuid/root) component exists. A privileged helper
is a large, high-value attack surface and contradicts rootless execution.

## Decision

- TCB = Linux kernel + host-side supervisor + security-init code + policy
  validator + security-critical configuration + audit recorder.
- **v0.1 has no privileged (setuid/root) helper.** All selected mechanisms
  are unprivileged on a stock kernel with user namespaces enabled
  (ADR-001).
- If a later phase requires a privileged component (e.g. cgroup delegation
  or network setup that cannot be done unprivileged), it must: be a
  separate minimal binary/script with a narrow documented interface;
  validate all input; drop privileges as early as possible; and be added to
  the TCB explicitly — this is the implementation plan §32 stop condition,
  triggered deliberately, never silently.

## Consequences

- Positive: no setuid binary to attack; every mechanism is exercised
  unprivileged; boundary setup is visible in our own code.
- Negative: some hosts cannot provide the needed unprivileged mechanisms
  (cgroup delegation, userns) → HARDENED refused (fail closed), RESTRICTED
  is the explicit fallback.
- The supervisor remains the single component that can touch the boundary;
  its compromise is a TCB compromise (documented residual, THREAT_MODEL §8).

## References

ARCHITECTURE §3.1, §5.1; implementation plan §5, §32; THREAT_MODEL §8.
