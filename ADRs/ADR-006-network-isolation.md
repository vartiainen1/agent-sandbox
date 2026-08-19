# ADR-006 — Network Isolation: Deny by Construction in v0.1

Status: ACCEPTED · Date: 2026-08-19 · Phase 0

## Context

S-005 (default deny), S-006 (private ranges), S-007 (metadata endpoints)
plus SSRF concerns (design §13, security spec §8) require network
isolation that cannot be argued with. Hostname allowlists are explicitly
insufficient (security spec §8). The design defers allowlists to a later
phase.

## Decision

- v0.1 workloads run in a **dedicated network namespace with no interfaces
  configured and loopback down**. There is no network to connect to —
  deny by construction, not by rules the workload could inspect or alter.
- Consequences of "no network": metadata endpoints (`169.254.169.254`),
  private ranges, link-local, DNS, and host sockets are all unreachable
  (S-004, S-005, S-006, S-007 hold structurally).
- **Allowlists are deferred to v0.2** and will be enforced inside the
  network namespace (interface + routing + host-side validating proxy),
  accounting for DNS resolution, redirects, alternate address forms and
  DNS rebinding — never hostname matching alone.
- A workload that legitimately needs network must wait for v0.2; v0.1
  sessions are offline by contract.

## Consequences

- Positive: the strongest possible network posture with zero enforcement
  code; metadata/SSRF classes are structurally eliminated.
- Negative: no package installs, git fetch, or any network workflow in v0.1;
  v0.2 must design the proxy carefully (flagged as the main v0.2 security
  work item).

## References

ARCHITECTURE §8; THREAT_MODEL T-012…T-017; security spec §8; design §12–13.
