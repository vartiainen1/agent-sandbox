# ADR-015 — Minimal /dev via Identity-Verified Bind-Mounts (mknod is kernel-impossible in the rootless userns)

Status: ACCEPTED · Date: 2026-08-19 · Phase 1, Step 4

## Context

ADR-005 specifies a minimal `/dev` (null/zero/full/random/urandom/tty) in
the pivot_root'd rootfs. Step 4 of the implementation plan requires
provisioning those device nodes. The architecture (ADR-001, ADR-002) also
requires **rootless** execution: the host supervisor must not need any
host privilege, and no privileged helper/setuid binary/CAP_MKNOD-on-host
may be introduced.

Empirical + authoritative finding (a charter stop-condition fired — "mknod
requires unexpected host privileges"): **`mknod(2)` of device nodes is
impossible inside a non-initial user namespace on Linux.** Verified
empirically in the container (uid 1001, full namespace boundary, ns-root
with `CapEff` including CAP_MKNOD): `mknod("/dev/null", S_IFCHR|0666,
1:3)` → EPERM. The authoritative rule (man 7 user_namespaces): creating a
device (governed by CAP_MKNOD) is among the operations for which **only a
process with privileges in the initial user namespace** has the necessary
capability. The kernel's capability check for device creation resolves
against the initial userns, not the caller's userns — so no amount of
in-userns capability grants it.

Therefore the Step 4 plan to `mknod` the nodes inside the sandbox was not
achievable by any mechanism, and doing it host-side would have required
host CAP_MKNOD — violating ADR-002.

## Decision

Provision `/dev` with the standard rootless pattern (podman/bubblewrap):

1. Mount a small, sandbox-private tmpfs at `/dev` (size-limited,
   mode 0755) inside the sandbox's own mount namespace, **before**
   `pivot_root` (the host `/dev` source paths are only resolvable pre-pivot).
2. Bind-mount **exactly six** host device nodes into that tmpfs:
   `/dev/null` (1,3), `/dev/zero` (1,5), `/dev/full` (1,7),
   `/dev/random` (1,8), `/dev/urandom` (1,9), `/dev/tty` (5,0).
3. **Identity-verify each source before the bind** (fail closed):
   character-device type (`S_ISCHR`), exact `st_rdev` major/minor, and
   the expected source path. Any mismatch, missing device, or failed
   bind raises and the initializer refuses — nothing is ever bound
   unverified.
4. **Verify post-operation** (never trust `mount(2)` success): `/dev` is
   the sandbox-private tmpfs (not a bind of the host `/dev` tree), the
   inventory is byte-exact (six nodes, nothing else), and each node is a
   character device with the exact major/minor/mode.
5. No host-side mknod, no privileged helper, no CAP_MKNOD on the host —
   the rootless constraint (ADR-002) is preserved, and in fact the
   sandbox **cannot create device nodes at all** (mknod EPERM in the
   userns — kernel-enforced), which is an additional security property.

## Security claim (narrow and accurate)

> The sandbox receives an explicitly allowlisted set of six
> identity-verified character devices through a private mount namespace.
> No host /dev tree is exposed.

The six inodes originate from the host; they are **not** "sandbox-created
devices" and the sandbox does not own the underlying device inodes. Their
host-side ownership maps to the overflow uid inside the sandbox (cosmetic:
mode 0666 makes access identical). The sandbox could `chmod`/`chown` the
six host inodes — negligible impact on the six standard nodes; the later
seccomp stage further bounds device access. Device access remains
constrained by the later capability/no_new_privs/seccomp stages; the
final device-security boundary is not claimed complete until those stages
are implemented and tested.

## Consequences

- Positive: rootless device provisioning without any privileged
  component; identity verification means a hostile/wrong host node is a
  refusal, never a passthrough; exact-inventory verification means no
  host /dev exposure; the sandbox provably cannot fabricate device nodes.
- Negative: the six device inodes originate from the host (documented
  limitation); bind sources are resolved at build time before pivot_root,
  so provisioning order matters (documented in the implementation);
  the /dev tmpfs adds a small mount to the namespace.

## References

ARCHITECTURE §7 (device inventory unchanged); ADR-005 (filesystem
isolation); ADR-002 (no privileged component); man 7 user_namespaces
(device creation requires initial-userns privileges); empirical probe in
the container (uid 1001): mknod → EPERM, six binds verified.
