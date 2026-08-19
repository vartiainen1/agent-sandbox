# ADR-011 — Lifecycle: Session-Owner Supervisor, cgroup.kill + PID-1 SIGKILL, Mandatory Verification

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-014 (kill the whole tree), S-036 (external timeout), S-038 (cleanup
failure visibility), design §33 (cleanup across every failure class:
parent death, agent crash, terminal disconnect, OOM, timeout, network
failure, repeated destroy, child persistence). Killing only the parent
process is explicitly forbidden.

## Decision

- The **supervisor owns the session** and its lifecycle state machine:
  create → exec → status → destroy; destroy is idempotent; each session has
  a unique ID (`sbx_<ts>_<rand>`) used to correlate everything (S-023).
- **Destroy** = SIGKILL to the namespace's PID 1 **plus** `cgroup.kill` on
  the session cgroup (catches every process regardless of parentage), then
  teardown of the sandbox mount namespace, removal of the workspace copy and
  tmpfs, and an **absence check** that no workload process remains (S-014,
  S-038).
- **Cleanup verification is mandatory**: incomplete cleanup is detected,
  recorded, and reported as incomplete — never reported as successful
  (S-038, S-024).
- Timeouts (command, session, cleanup grace) are enforced by the supervisor
  outside the sandbox and cannot be disabled by the workload (S-036).
- Failure classes are each tested: normal exit, command failure, parent
  death, agent crash, terminal disconnect, timeout, OOM, repeated destroy,
  partial cleanup, child persistence (implementation plan §10).

## Consequences

- Positive: reliable, verifiable teardown; no uncontrolled processes or
  resources survive a session.
- Negative: the supervisor must survive the workload (it is a separate
  process outside the namespace); supervisor crash during a session leaves
  state that the next boot must detect and clean (startup sweep).

## References

ARCHITECTURE §6, §13, §14; THREAT_MODEL T-036…T-039; design §33.
