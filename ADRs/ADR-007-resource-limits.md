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

## Approved cgroup policy values (Phase 1 Step 10, READING A, 2026-08-19)

HARDENED requires ALL FOUR controllers, each established and verified by
kernel-state read-back — no partial success:

- `pids.max` = `ResourceLimits.processes` (default 256)
- `memory.max` = `ResourceLimits.memory_mb * 1024 * 1024` (default 4096 MiB)
- `cpu.max` = `"{cpu_quota_percent * 1000} 100000"` — fixed 100000 µs
  period; `cpu_quota_percent` is a new config field (default 100 = one
  full core; 50% = 50000/100000, 200% = 200000/100000), validated in
  [1, 10000].
- `io.max` = `"{major}:{minor} rbps={io_mbps * MiB} wbps={io_mbps * MiB}"`
  — `io_mbps` is a new config field (default 1024 MiB/s), validated in
  [1, 1048576]; the device is resolved from KERNEL STATE (st_dev →
  /sys/dev/block → /sys/class/block, then /proc/self/mountinfo) — never
  a guessed major:minor. An unresolvable backing device (tmpfs/overlay/
  pseudo) is a HARDENED refusal, never a silent skip of io.max.

Delegation model (no privileged helper, ADR-002): cgroup config inside a
delegated subtree is filesystem-permission work; the supervisor creates
the session cgroup as a child of the caller's cgroup (the delegation
root, whose subtree_control must enable the four controllers) and PID 1
migrates into it via `cgroup.procs`. No capability, no syscall beyond the
existing 45-syscall allowlist (mkdir/openat/write/read).
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
