# ADR-004 — Process Isolation: User + PID + UTS + IPC Namespaces, Subreaper, PID-1-in-Namespace

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-013 (process containment), S-014 (process cleanup), S-008 (no privilege
gain) require that every workload process stays inside the sandbox, cannot
see host processes, and can all be killed reliably. A naive "kill the
parent" model leaks grandchildren.

## Decision

- The supervisor forks one controlled child; that child performs
  `unshare(CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWIPC|…)` and
  becomes **PID 1 of a new PID namespace**, then applies the remaining
  security restrictions and execs the workload (ARCHITECTURE §6).
- The supervisor sets `PR_SET_CHILD_SUBREAPER` so orphans reparent to it.
- **Destroy** = SIGKILL to namespace PID 1 **plus** `cgroup.kill` on the
  session cgroup, then an absence check (S-014, S-038). Parent-only killing
  is forbidden.
- UTS/IPC namespaces isolate hostname and SysV IPC (hygiene).

## Consequences

- Positive: every workload process is a descendant of sandbox PID 1; host
  PIDs are invisible (S-008); cleanup is tree-complete.
- Negative: PID 1 semantics in the namespace must be handled (signal
  forwarding, zombie reaping by the init process itself).

## References

ARCHITECTURE §6, §10; THREAT_MODEL T-025, T-028, T-036.
