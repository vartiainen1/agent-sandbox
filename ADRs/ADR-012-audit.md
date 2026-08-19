# ADR-012 — Audit: Host-Side JSONL Recorder, Session Correlation, Audit Is Not Enforcement

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-022 (structured events), S-023 (session correlation), S-024 (audit is
not enforcement — a failure to log must not be conflated with protection).
Design §29 lists the event classes. The recorder must be outside the
sandbox so the workload cannot tamper with or read the audit stream.

## Decision

- The **audit recorder runs host-side, outside the sandbox filesystem**
  (ARCHITECTURE §15). The workload cannot write, truncate, or read it.
- Events are **structured JSONL**, each carrying: session ID, timestamp,
  event type, resource, decision, reason (S-022, S-023). Classes per design
  §29: session creation, policy load, process start/exit, filesystem op,
  network op, denied capability, secret access, policy decision, resource
  violation, sandbox violation, Git op, session termination.
- **Audit is observation, not enforcement** (S-024): enforcement lives in
  the kernel. Documented failure policy: if recording fails, execution
  continues (logging failure never equals protection failure), and the
  recording failure is itself reported where possible.
- Audit output is bounded (S-037) and session-correlated to memory,
  decisions, diffs, and MCP requests via the session ID (S-023).

## Consequences

- Positive: strong accountability without coupling protection to logging.
- Negative: audit data is sensitive host-side output — must be stored
  carefully (permissions, no secrets), a Phase 7 implementation concern.

## References

ARCHITECTURE §15; THREAT_MODEL T-053, T-054; design §29–30; security spec
§5 (S-022…S-024).
