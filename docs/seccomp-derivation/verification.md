# Seccomp Derivation — Verification Record

Date: 2026-08-19 · Platform: Docker Desktop (WSL2), ubuntu:24.04 image,
x86_64. **Container-validated.** Native Linux re-run is a CI job
(GitHub Actions ubuntu) — results from this record are not claimed as
native validation.

## What "verified" means here

The anti-claim rule (user directive): *do not claim "seccomp is secure
because the BPF filter loaded successfully".* The security question is
whether the policy **restricts the workload to the intended syscall
surface while still allowing required functionality**. Both halves are
tested behaviorally, with a real BPF filter built and loaded through the
same prctl/ctypes path the Phase 1 runtime will use.

## Container-validated results (2026-08-19, all PASS)

### Trace (observation, step 3)

| Workload | Exit | Unique syscalls |
|---|---|---|
| t0_sh_echo | 0 | 27 |
| t0_sh_exit | 0 | 26 |
| t1_sh_fileops | 0 | 34 |
| t1_python_hello | 0 | 32 |
| t1_python_agentish | 0 | 42 |
| t1_git_basics | 0 | 34 |
| **Union** | — | **45** |

Arg captures: `clone`/`clone3`/`unshare`/`socket`/`socketpair`/`setns` —
**zero occurrences** across all workloads (evidence for the denial
rationales). Evidence: `tools/seccomp-derivation/trace-results.json`.

### Probe (behavioral verification, steps 10-11)

`probe_policy.py` loads the derived filter in a child (mirroring the real
architecture: sandbox init loads filter → execs workload), then:

| Check | Result |
|---|---|
| allowed `getpid` under filter | PASS |
| denied `socket` → EPERM | PASS |
| denied `ptrace` → EPERM | PASS |
| denied `mount` → EPERM | PASS |
| denied `chroot` → EPERM | PASS |
| denied `unshare` → EPERM | PASS |
| denied `clone` → EPERM | PASS |
| Tier 0 workload `sh -c 'echo hello'` under filter | PASS (exit 0, output `hello`) |
| `python3 -c "import socket; socket.socket()"` blocked | PASS (`PermissionError: [Errno 1]`) |
| `threading.Thread(...).start()` blocked (clone) | PASS (`RuntimeError: can't start new thread`) |
| `sh -c 'mount ...'` blocked | PASS (`MOUNT_BLOCKED`) |

Exit code 0 = all checks pass; the probe fails the run on any single
check. Re-run: `python3 probe_policy.py` in the derivation image or on
native Linux.

## Container vs native (honest labeling)

| Claim | Status |
|---|---|
| The derived allowlist covers the Tier 0/1 surface (legit workloads pass) | **Container-validated**; native CI pending |
| Prohibited syscalls are blocked (EPERM) | **Container-validated**; native CI pending |
| Filter installs after no_new_privs, before exec (architectural) | Architecture decision (Phase 0/1), not yet exercised end-to-end |
| Syscall surface on a real uid-mapped rootless runtime | **VERIFIED DOCKER** (Step 2: full mapping exercised, uid 1001) — **NOT VERIFIED NATIVE** (24.04 runner blocks setgroups deny, EACCES) |
| Behavioral equivalence on native ubuntu | **VERIFIED** — native trace + probe + gate green |

Docker caveats recorded: container ran as uid 0 without a user namespace;
Docker's own seccomp/capability stack is not the product's boundary and
is not claimed as such; `mount`-listing output in the probe reflects
container mounts only.

## Native CI (authoritative — `.github/workflows/ci.yml`)

Published as github.com/vartiainen1/agent-sandbox; GitHub Actions ubuntu
runs on every push (Python 3.11 + 3.12):

1. Compile check + unit/regression suite (`test_derivation.py`).
2. Native syscall observation (`trace_workloads.py`).
3. **Seccomp regression gate** (`check_trace_regression.py`): any syscall
   observed natively but missing from `allowlist.json` FAILS the job —
   the allowlist must cover the real native surface or be updated
   deliberately through change control (policy.md §5).
4. Behavioral probe (`probe_policy.py`) — runs as the non-root runner
   user, so it exercises the unprivileged seccomp-install path.
5. Rootless capability detection (`check_rootless_capabilities.py`) —
   records VERIFIED/BLOCKED per mechanism with the reason; an unavailable
   mechanism is never converted into a false PASS.

## Native Linux results (first run, 2026-08-19 — run 32242402621)

Both matrix cells (ubuntu-latest, Python 3.11 + 3.12) **GREEN**.

| Check | 3.11 | 3.12 |
|---|---|---|
| Compile check | PASS | PASS |
| Unit + regression suite (18 checks) | PASS | PASS |
| Native trace | 44 unique syscalls, all workloads exit 0 | 44 |
| Seccomp regression gate (no expansion) | PASS (44 ⊆ 45) | PASS |
| Behavioral probe (non-root) | ALL PASS | ALL PASS |
| Rootless capability detection | userns VERIFIED, seccomp-as-nonroot VERIFIED, no_new_privs VERIFIED (uid 1001) | same |

**Docker-vs-native difference observed**: the native non-root surface is
44 syscalls vs 45 in the root container run. The difference is exactly one
syscall — `poll`, observed only under root. A non-root re-run of the trace
in the same container also yields 44, and the non-root container surface
**matches the native surface exactly** (44 = 44). The allowlist (45) is a
strict superset of all three observed surfaces; the gate passed everywhere.

**Rootless status (honest, corrected 2026-08-19)**: the earlier
"userns VERIFIED" line probed only `unshare(CLONE_NEWUSER)` — creation,
not the mapping. The Phase 1 Step 2 namespace tests exercised the FULL
rootless path (unshare → setgroups deny → uid_map/gid_map write →
read-back verify) and exposed that the GitHub-hosted ubuntu-24.04 runner
**cannot establish the uid 0→caller mapping**: `setgroups deny` fails with
EACCES (AppArmor userns restriction, default on 24.04). The probe was
upgraded to exercise the full path and now reports per-mechanism truth.
No mechanism is reported VERIFIED that was not actually exercised.

## Phase 1 Step 2 — namespace isolation results (2026-08-19)

Mechanism implemented: user/mount/PID/network/UTS/IPC namespaces with
verified uid/gid mapping, rootless PID-1 double-fork, NAMESPACES stage
guard (fail-closed; `agent_sandbox/isolation/`). The evidence below is
**real Linux execution**, labeled exactly as it was obtained.

### Container-validated (Docker Desktop, WSL2 kernel, uid 1001)

- 21 namespace tests PASS (user ns, uid/gid mapping, setgroups deny, host
  caller unprivileged + sandbox-side uid 0, PID-1 semantics with raw
  pid 1, host-process invisibility, mount ns + host mount namespace
  unchanged, network ns + no host interfaces/routes, combined setup,
  failure-mode refusals).
- Command: `docker run -u 1001 --security-opt seccomp=unconfined ...
  python3 -B -m unittest tests.unit.test_namespaces`.
- **Substrate caveat**: Docker Desktop's DEFAULT seccomp profile blocks
  `unshare(CLONE_NEWUSER)` (EPERM) — the container's seccomp is Docker's,
  not ours, so `seccomp=unconfined` was used to exercise OUR namespace
  code. Under the default profile the probe refuses honestly (BLOCKED:
  unshare EPERM) — the same fail-closed path the runtime uses. The product
  applies its own seccomp filter later (Phase 1 Step 13), inside its own
  sandbox.

### Native ubuntu CI (run 32246741335, authoritative) — substrate limitation

| Check | 3.11 | 3.12 |
|---|---|---|
| Namespace real-path tests | SKIPPED (substrate unavailable, reason recorded) | same |
| Fail-closed refusal (guard refuses when mechanism unavailable) | **PASS** (real EACCES path) | **PASS** |
| Failure-mode tests (patched EPERM/mapping/state seams) | **PASS** | **PASS** |
| Skeleton + wiring tests | **PASS** | **PASS** |
| Rootless capability probe | `userns-mapping: BLOCKED (setgroups deny errno=13 EACCES)` | same |

**Finding (documented, not papered over)**: the GitHub-hosted
ubuntu-24.04 runner permits unprivileged `unshare(CLONE_NEWUSER)` but the
AppArmor userns restriction (`kernel.apparmor_restrict_unprivileged_userns`)
denies the setgroups-deny write (EACCES), so the uid 0→caller mapping
cannot be established unprivileged there. Consequences, per the user
directive (detect, record, never false-PASS, never weaken):

- The real-path namespace tests SKIP on that substrate with the recorded
  reason; they are NOT claimed as native-verified.
- The **fail-closed behavior is itself verified natively**: the guard
  refuses with the exact EACCES reason and no workload executes.
- The namespace boundary execution evidence is VERIFIED DOCKER only until
  a native host that can provide the mechanism exists (self-hosted runner
  or VM with userns enabled is the open question).
- The rootless capability probe now exercises the full mapping and reports
  BLOCKED with the reason instead of the earlier creation-only VERIFIED.

## Phase 1 Step 4 — /proc + /dev + /sys boundary results (2026-08-19)

Mechanism implemented: `/proc` mounted in sandbox PID 1 with
`MS_NOSUID|MS_NODEV|MS_NOEXEC` + `hidepid=2` (mount state VERIFIED from
mountinfo, never assumed from mount() success); minimal `/dev` as a
sandbox-private tmpfs with EXACTLY six identity-verified host
bind-mounts (ADR-015); `/sys` absent (no mount, no dir — absence is the
mechanism). FILESYSTEM stage now completes the proc/dev/sys items (7-9)
of the Phase 1 order; HARDENED refusal point advances to NETWORK.

### mknod discovery + bind-mount decision (stop-condition fired, then approved)

`mknod(2)` of device nodes is **kernel-impossible inside a non-initial
user namespace** — a Linux rule, not a container artifact. Empirically
(container, uid 1001, full namespace boundary, ns-root with
`CapEff: 000001ffffffffff` incl. CAP_MKNOD): `mknod("/dev/null",
S_IFCHR|0666, 1:3)` → EPERM. Authoritative (man 7 user_namespaces):
device creation is one of the operations for which **only a process with
privileges in the initial user namespace** has the capability. The
charter stop-condition fired; the approved resolution (ADR-015) is the
standard rootless pattern: bind-mount exactly the six identity-verified
host nodes into a sandbox-private /dev tmpfs, with pre-bind identity
verification (type + exact major/minor) and post-bind exact-inventory
verification. No host mknod, no privileged helper; the sandbox cannot
create device nodes at all (additional property).

### Kernel difference observed (not a sandbox defect)

The container kernel (Docker Desktop/WSL2, a newer 6.x) prints the
hidepid=2 mount option in mountinfo super options as `hidepid=invisible`
— the symbolic alias for mode value 2 added in newer kernels (the older
spelling was `hidepid=2`, and a historical kernel typo printed
`hidpid=2`). The verification parses the hidepid MODE VALUE semantically
(0/1/2 vs off/ptraceable/invisible) and requires exactly value 2; the
first run's spelling-only matcher refused a correct mount, which is
precisely the kind of environment difference the gate exists to catch.

### Container-validated results (Docker Desktop, WSL2 kernel, uid 1001, seccomp=unconfined)

- **37/37 Step 4 tests PASS** (real Linux execution): /dev tmpfs private
  (separate device, tmpfs fstype), exact 6-node inventory, per-node
  identity (char type + exact major/minor + mode 0666), behavior
  (null writable, zero readable, full ENOSPC + zero reads, random/
  urandom readable, tty ENXIO-without-ctty), host /dev tree not exposed,
  13 forbidden device paths absent, sandbox mknod → EPERM + inventory
  unchanged, hostile workspace symlinks cannot influence /dev
  construction, proc mount present/procfs/hidepid=2/nosuid-nodev-noexec,
  host processes invisible (real host helper pid absent; only PID 1 in
  the sandbox proc view), kernel-metadata files blocked or sanitized
  (iomem zeroed addresses), /sys absent + sysfs-host symlink blocked,
  mount propagation private (host mountinfo unchanged), failure
  injections (dev mount, proc mount, wrong major/minor, unexpected
  device, extra device, verification failure, /sys mounted) all REFUSE.
- Command: `docker run -u 1001 --security-opt seccomp=unconfined ...
  python3 -B -m unittest tests.unit.test_procdev`.
- Same substrate caveat as Step 2: Docker's default seccomp profile
  blocks CLONE_NEWUSER; `seccomp=unconfined` exercises OUR code. The
  product's own filter is installed later (Step 13), inside its own
  sandbox.

### Native ubuntu CI (authoritative) — substrate limitation unchanged

| Check | 3.11 | 3.12 |
|---|---|---|
| proc/dev/sys real-path tests | SKIPPED (substrate unavailable, recorded reason: setgroups deny EACCES — rootless mapping cannot be established on the runner) | same |
| Host-side + fail-closed + failure-injection tests | PASS | PASS |
| Skeleton / namespace / rootfs regression | PASS | PASS |
| Seccomp regression gate + behavioral probe | PASS | PASS |

Status preserved: rootless UID/GID mapping + filesystem boundary
VERIFIED DOCKER; NOT VERIFIED NATIVE (recorded reason, never a false
PASS); native fail-closed behavior VERIFIED.
