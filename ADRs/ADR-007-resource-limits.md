# ADR-007 — Resource Limits: rlimits Always + cgroups v2 When Delegated

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-012/S-027 (limits exist and cannot be raised), S-037 (output limits),
S-036 (external timeout), fork-bomb/memory/disk protection (design §17–21).
On an unprivileged system, rlimits can be lowered but never raised — a
strong primitive — but they are per-process: RLIMIT_AS bounds address space,
RLIMIT_FSIZE bounds single files, RLIMIT_NPROC bounds processes. Total
memory and total disk for a *tree* need cgroups v2, which require host
delegation.

## Decision

- **Always applied** (unprivileged, irreversible): `RLIMIT_CPU`,
  `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`,
  `RLIMIT_CORE=0`.
- **Applied when the host delegates cgroups v2** (systemd `Delegate=yes`
  or admin grant): `pids.max`, `memory.max`, `cpu.max`, `io.max` on the
  session subtree.
- **HARDENED requires cgroup v2 delegation** for memory/pids/io. Without
  it, HARDENED is refused with the specific reason (S-018); the user may
  explicitly select RESTRICTED, which documents that only rlimits apply.
- **Disk total** without cgroup delegation cannot be enforced
  unprivileged — this is a **flagged limitation**: HARDENED enforces total
  disk via `io.max` + workspace size pre-check + tmpfs size limit;
  RESTRICTED documents the gap. It is never silently claimed.
- Output is bounded by the supervisor's read pipe (terminate + truncation
  notice, S-037); timeouts are enforced externally (S-036).

## Consequences

- Positive: robust, unraisable limits with a clean fail-closed path.
- Negative: HARDENED depends on host configuration (delegation); some hosts
  can only run RESTRICTED. Documented, not hidden.

## References

ARCHITECTURE §9, §14, §19; THREAT_MODEL T-029…T-035; design §17–22.
