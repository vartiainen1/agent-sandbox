# ADR-005 — Filesystem Isolation: Mount Namespace + pivot_root Minimal Rootfs

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-001/S-002 (no host filesystem by default), S-028 (workspace boundary),
S-029 (symlink safety), S-030 (traversal), S-032/S-033 (malicious repo and
dependencies) demand isolation *by construction*: it must be structurally
impossible for the workload to reach a host path, not merely filtered.

## Decision

- The sandbox runs in a private mount namespace; the supervisor builds a
  **minimal rootfs** and `pivot_root`s into it (mount propagation = private):
  workspace (RW copy of the project), size-limited tmpfs `/tmp`, minimal
  `/home`, **read-only** bind-mounted system layers (`/usr`, `/bin`,
  `/lib`, minimal sanitized `/etc`), `/proc` with `hidepid=2`, minimal
  `/dev` (null/zero/full/random/urandom/tty), **no `/sys`** in v0.1.
- No host path is ever mounted: no host `/`, home, `.ssh`, `.aws`,
  `.config`, `/run`, `/var/run`, Docker/K8s sockets (S-002, S-004).
- The workspace is a **copy** of the project, not a bind mount — a
  malicious repo can only damage its own copy (S-028, S-032).
- Symlink/hardlink/traversal safety follows structurally: the target path
  resolves inside the rootfs where host paths do not exist (S-029, S-030).
- `mount(2)`/`pivot_root(2)` are denied by seccomp inside the sandbox.

## Consequences

- Positive: filesystem escape requires breaking the kernel, not outsmarting
  a filter; hostile repos are contained to their copy.
- Negative: workspace copy cost (size/time) per session; system layers must
  be curated (a minimal toolchain image) — a Phase 1 build artifact.

## References

ARCHITECTURE §7; THREAT_MODEL T-001…T-011; security spec §9.
