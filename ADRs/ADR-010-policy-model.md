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

## Phase 4 implementation note (2026-08-22)

The policy engine is implemented (implementation.md Phase 4):
`agent_sandbox/policy.py` with the documented capability model, strict
validation (unknown fields/capabilities rejected, version required),
deny-by-default decisions, frozen/immutable Policy, host-side only.
The single decision path (S-015) is enforced in
`RuntimeSession.execute()` — the gate CLI/MCP/API all share (ADR-013) —
before any boundary work, with policy_loaded/policy_decision audit events.
CLI `--policy PATH` and the interface `policy` param expose it.

**Parser decision — re-confirmed at Phase 4 as this ADR required**: the
project carries zero runtime dependencies (`pyproject.toml` `dependencies
= []`) and the TCB rule forbids adding one for convenience, so the
documented zero-dependency fallback was taken: policy documents are
strict-schema **JSON** parsed with the stdlib `json` module. PyYAML is
**not** added to the TCB. Resource limits declared in a policy must be
consistent with the config's limits (ADR-007 single source); a conflict
rejects the policy (S-021/S-027) — never a silent second enforcement
source.

## References

ARCHITECTURE §12, §16; THREAT_MODEL T-040…T-045; design §25; security spec
§6 (policy failure), §15 (fuzzing).
