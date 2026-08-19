# ADR-013 — Control Surface: One Enforcement Core for CLI / MCP / API

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-015 (all privileged/security-sensitive ops pass policy), S-016 (MCP
cannot bypass), S-017 (API cannot bypass), implementation plan §12 (CLI),
§15 (MCP), §16 (API): *"Do not create a separate implementation of security
logic for the API."* Three interfaces must produce equivalent decisions for
equivalent requests.

## Decision

- CLI, MCP and API are **thin front-ends over a single enforcement core**:
  validated request → policy decision → security-init → execution. Exactly
  one code path touches the boundary (ARCHITECTURE §16).
- Interfaces are added in the mandated order — CLI (Phase 8) before MCP
  (Phase 11) before API (Phase 12) — and each is tested for decision
  equivalence and for bypass attempts (S-016, S-017).
- No interface carries its own copy of security logic; no interface can
  request a capability the active policy denies; security mode and session
  identity are exposed by every interface (S-020, S-023), machine-readable
  (`--json`).

## Consequences

- Positive: one review surface for security decisions; bypass requires
  breaking the core, which is tested from every interface.
- Negative: interface features are gated on the core's capabilities;
  interface-specific convenience must not leak into the core.

## References

ARCHITECTURE §16; THREAT_MODEL T-040…T-042; implementation plan §12, §15,
§16; security spec §5 (S-015…S-017).
