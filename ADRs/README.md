# agent-sandbox — Architecture Decision Records

Each ADR records one decision: the context that forced it, the decision,
the consequences, and what it supersedes. Status values: PROPOSED,
ACCEPTED, SUPERSEDED, REJECTED.

| ID | Decision | Status | Date |
|---|---|---|---|
| [ADR-001](ADR-001-runtime-substrate.md) | Runtime substrate: native Linux syscalls via Python ctypes, rootless | ACCEPTED | 2026-08-19 |
| [ADR-002](ADR-002-trusted-computing-base.md) | Minimal TCB; no privileged helper in v0.1 | ACCEPTED | 2026-08-19 |
| [ADR-003](ADR-003-security-modes.md) | HARDENED / RESTRICTED / COMPATIBILITY with explicit control matrix | ACCEPTED | 2026-08-19 |
| [ADR-004](ADR-004-process-isolation.md) | User + PID + UTS + IPC namespaces; subreaper supervisor; PID-1-in-ns model | ACCEPTED | 2026-08-19 |
| [ADR-005](ADR-005-filesystem-isolation.md) | Mount namespace + pivot_root minimal rootfs; workspace copy; RO system layers | ACCEPTED | 2026-08-19 |
| [ADR-006](ADR-006-network-isolation.md) | Network namespace, no interfaces — deny by construction in v0.1 | ACCEPTED | 2026-08-19 |
| [ADR-007](ADR-007-resource-limits.md) | rlimits always + cgroup v2 when delegated; HARDENED requires delegation | ACCEPTED | 2026-08-19 |
| [ADR-008](ADR-008-capabilities-seccomp.md) | Full bounding-set drop + no_new_privs + seccomp BPF default-deny | ACCEPTED | 2026-08-19 |
| [ADR-009](ADR-009-environment-credentials-sockets.md) | Explicit env allowlist; no host mounts or sockets | ACCEPTED | 2026-08-19 |
| [ADR-010](ADR-010-policy-model.md) | Versioned strict-schema YAML policy, validated, immutable, host-side | ACCEPTED | 2026-08-19 |
| [ADR-011](ADR-011-lifecycle.md) | Session-owner supervisor; cgroup.kill + PID-1 SIGKILL; mandatory cleanup verification | ACCEPTED | 2026-08-19 |
| [ADR-012](ADR-012-audit.md) | Host-side JSONL recorder; session correlation; audit is not enforcement | ACCEPTED | 2026-08-19 |
| [ADR-013](ADR-013-control-surface.md) | Single enforcement core for CLI / MCP / API | ACCEPTED | 2026-08-19 |
| [ADR-014](ADR-014-validation-substrate.md) | Docker Desktop = container validation only; native CI is authoritative | ACCEPTED | 2026-08-19 |
| [ADR-015](ADR-015-dev-bind-mount.md) | Minimal /dev via six identity-verified host bind-mounts (mknod is kernel-impossible in the rootless userns) | ACCEPTED | 2026-08-19 |
