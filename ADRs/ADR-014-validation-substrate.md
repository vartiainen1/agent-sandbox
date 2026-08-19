# ADR-014 — Validation Substrate: Docker Desktop Is Container Validation Only; Native CI Is Authoritative

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

The dev machine is Windows; the product is a Linux runtime (user
namespaces, cgroups v2, seccomp, pivot_root). We need a local loop for
Linux development, but the product must never be validated only inside a
container runtime whose own isolation differs from the target.

## Decision

- **Native Linux is the security target** and the authoritative validation
  platform: GitHub Actions **ubuntu** runners run the unit, integration,
  security, adversarial and regression suites (family CI pattern —
  agent-blame precedent, 6-cell matrix incl. ubuntu/windows).
- **Docker Desktop is a local *container* validation substrate only**: used
  on this Windows machine to run Linux workloads for development iteration.
  Docker Desktop's isolation is **not** the product's boundary, and results
  from Docker runs are labeled **container-validated**, never
  **native-Linux-validated** (ADR naming, test reports, session notes).
- Where a mechanism behaves differently under Docker (nested namespaces,
  seccomp inheritance, cgroup delegation through the Docker VM), the native
  CI result is authoritative; divergences are documented, not papered over.
- Platform-skip reasons in CI are explicit, never silent (implementation
  plan §19, §23).

## Consequences

- Positive: fast local Linux iteration without a Linux box; honest labeling
  of what each result proves.
- Negative: some behaviors cannot be observed locally at all (native
  cgroup delegation details); those wait for CI — acceptable, by design.

## References

ARCHITECTURE §18, §19; implementation plan §19, §23; THREAT_MODEL §8.
