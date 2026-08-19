# ADR-010 — Policy Model: Versioned Strict-Schema YAML, Validated, Immutable, Host-Side

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-015 (policy enforcement), S-021 (validation, unknown fields rejected),
S-025/S-026 (immutable, host-side). The design (§25) specifies
capability-based YAML policy. Policy parsing runs host-side in the TCB, so
the parser choice is a TCB decision — this is the one deliberate TCB
dependency, recorded here per implementation plan §32 (stop condition must
be triggered deliberately, not silently).

## Decision

- **Format**: YAML, `version: 1`, strict-schema validated. Parsed host-side
  with **PyYAML** (pinned, reviewed) — deliberately accepted into the TCB
  because (a) the design specifies YAML policy with comments for human
  authors, and (b) a hand-rolled YAML subset parser is itself a security
  risk. This decision is re-confirmed at Phase 4 (policy engine); a
  zero-dependency JSON alternative remains the fallback if PyYAML is
  rejected.
- **Validation** (before any session starts): unknown security-critical
  fields ⇒ **reject policy** (S-021); conflicting capabilities ⇒ reject;
  deterministic evaluation; no warn-and-continue for security-critical
  fields.
- **Immutability**: policy is parsed and fixed at session start; the file
  lives host-side and is never mounted into the sandbox (S-025, S-026).
- **Capability model**: `filesystem.*`, `network.*`, `process.*`,
  `git.*` (push denied by default), `secrets.*` (deny by default),
  `privileged.*` (deny by default), `resources.*` (limits).
- The policy engine is the single decision point for CLI/MCP/API requests
  (ADR-013); the OS boundary remains the backstop.

## Consequences

- Positive: explicit, auditable, versioned security intent; malformed
  policy cannot silently change behavior.
- Negative: PyYAML enters the TCB (documented, pinned, re-confirmed at
  Phase 4); policy authoring is a new skill for users (mitigated by
  examples + validation errors that name the offending field).

## References

ARCHITECTURE §12, §16; THREAT_MODEL T-040…T-045; design §25; security spec
§6 (policy failure), §15 (fuzzing).
