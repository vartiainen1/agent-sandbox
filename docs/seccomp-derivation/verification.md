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

## Phase 1 Step 5 — network namespace deny-by-construction results (2026-08-19)

Mechanism implemented: the netns created in Step 2 is configured into
its final v0.1 state (ensure lo DOWN) and the resulting state is
VERIFIED (only lo, lo DOWN, no addresses, no usable routes, distinct
from host netns — `agent_sandbox/isolation/network.py`). Any unexpected
interface/route/address is a REFUSAL (fail closed). HARDENED refusal
point advances to PRIVILEGES.

### Empirical findings (Step 5 probe, container uid 1001 — the charter's required investigation)

1. **The workload CAN toggle lo** (ioctl SIOCSIFFLAGS succeeds): the
   userns-owned netns grants ns-local CAP_NET_ADMIN, so the sandbox can
   bring lo UP. Result: localhost-only connectivity (127.0.0.1/::1
   appear; connect to a local listener reaches it) and ZERO external
   path (connect to 8.8.8.8/169.254.169.254/host-gw still ENETUNREACH;
   no route to any non-lo device). Full prevention of even the lo toggle
   lands with Step 12 (capability drop removes CAP_NET_ADMIN) + Step 13
   (seccomp) — documented residual, NOT claimed at Step 5.
2. **Netlink dumps are NOT a reliable verification source inside the
   userns-owned netns** on the validation kernel: RTM_GETLINK dump
   returns zero messages, RTM_GETADDR dump returns EOPNOTSUPP, while
   /proc/net/* is complete. Verification therefore uses /proc/self/net/*
   (per-netns via the reader's netns) + ioctl — substrate-independent.
3. **Netlink mutations (RTM_NEWROUTE/RTM_NEWLINK) return EOPNOTSUPP** in
   the validation environment even as root with CAP_NET_ADMIN outside
   the sandbox — a Docker-Desktop/WSL2 environment artifact, NOT the
   security mechanism and NOT relied upon. On a native kernel they may
   succeed; the island netns makes them harmless (no host-side peer
   device exists; moving an interface to the host netns and
   setns(CLONE_NEWNET) require initial-userns CAP_NET_ADMIN/CAP_SYS_ADMIN
   and fail; no host pid is visible so no host netns fd path exists).
4. The fresh netns is deny-by-construction BY DEFAULT: only lo (DOWN, no
   addresses), no IPv4 routes; some kernels show inert IPv6 `::/0 dev
   lo` entries which are unusable (lo DOWN, address-less). The
   implementation verifies this state and REFUSES on any deviation.

### Container-validated results (Docker Desktop, WSL2 kernel, uid 1001, seccomp=unconfined)

- **27/27 Step 5 tests PASS** (real Linux execution): lo DOWN, only lo
  in /proc/net/dev, no IPv4/IPv6 addresses, no IPv4 routes, IPv6 routes
  reference only the DOWN lo, no default route usable, connect to
  public/metadata/host-gw all ENETUNREACH, bind+listen unreachable,
  host network state unchanged before/after, workload lo-up attempt
  creates no external path (connect still fails), route-add/iface-create
  attempts leave the boundary intact, no host-netns fd path exists
  (only PID 1 visible, own netns), failure injections (lo cannot be
  brought down, unexpected interface, unexpected route, unexpected
  address, lo UP at verify time, unreadable state) all REFUSE.
- Same substrate caveat as Steps 2-4 (Docker seccomp=unconfined to
  exercise OUR code; the product filter is Step 13).

### Native ubuntu CI (authoritative) — substrate limitation unchanged

| Check | 3.11 | 3.12 |
|---|---|---|
| network real-path tests | SKIPPED (recorded reason: setgroups deny EACCES — rootless mapping cannot be established on the runner) | same |
| host-side parsing + fail-closed + failure-injection tests | PASS | PASS |
| Skeleton / namespace / rootfs / procdev regression | PASS | PASS |
| Seccomp regression gate + behavioral probe | PASS | PASS |

### Step 5 labels

- **DESIGN INTENT** (ADR-006): dedicated netns, no interfaces, loopback
  down, deny by construction; allowlists deferred to v0.2.
- **DOCKER VERIFIED**: the complete deny-by-construction state and its
  verification, plus the structural adversarial properties (no usable
  path, no host escape, host netns unchanged).
- **NATIVE VERIFIED**: fail-closed behavior and host-side logic only;
  the full rootless path remains NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION (RESOLVED in Step 7)**: at Step 5 the workload
  could still toggle its own lo (ns-local CAP_NET_ADMIN) — localhost-
  only, no external path (verified). Step 7 (capability reduction)
  removes CAP_NET_ADMIN, so the toggle now FAILS (EPERM) and lo stays
  DOWN; the corresponding test_network tests were updated to assert the
  stronger behavior (see the Step 7 record below). Seccomp (Step 13)
  remains outstanding for the syscall layer. Netlink EOPNOTSUPP
  behavior is environment-specific and not the security mechanism.

## Phase 1 Step 7 — capability reduction (bounding-set drop) results (2026-08-19)

Mechanism implemented (ARCHITECTURE.md Q11, ADR-008, S-009): the ENTIRE
capability bounding set is dropped (prctl(PR_CAPBSET_DROP) for every
capability 0..63; EINVAL = beyond CAP_LAST_CAP on this kernel, skipped),
the ambient set is cleared (prctl(PR_CAP_AMBIENT_CLEAR_ALL)), and
effective/permitted/inheritable are cleared via capset(2)
(_LINUX_CAPABILITY_VERSION_3, all-zero) — `agent_sandbox/isolation/
privileges.py` + `syscalls.py` capset wrapper (x86_64 126 / aarch64 91).
The workload therefore holds NO capabilities, including inside its own
user namespace. Verification is the kernel-state READ-BACK of
/proc/self/status: CapBnd/CapEff/CapPrm/CapInh/CapAmb must ALL be zero;
any residual capability is a refusal. Applied in PID 1 AFTER no_new_privs
(mandated order) and BEFORE the workload fn; a failed or unverified
reduction refuses with the workload never executed.

### Why the mechanism is rootless-safe

- PR_CAPBSET_DROP needs CAP_SETPCAP in the caller's user namespace —
  sandbox PID 1 holds it before the reduction (verified, never assumed);
  the drop loop runs BEFORE capset removes the sets.
- Clearing one's own sets (capset to zero) and PR_CAP_AMBIENT_CLEAR_ALL
  require no privilege.
- No host/root privileges, no privileged helper, no setuid component
  (ADR-002): every step is reachable unprivileged inside the userns.

### Empirical findings (container uid 1001 — the gate catching real interactions)

1. **The Step 5 lo-toggle residual is RESOLVED**: without CAP_NET_ADMIN
   the ioctl lo-up attempt inside the sandbox now FAILS (EPERM) and lo
   stays DOWN — test_network's WorkloadReenableTests assert the stronger
   behavior (attempt != OK, lo down, connects still ENETUNREACH).
2. **Two Step 2/3 mount-isolation tests were updated**: their workload
   fns mounted a tmpfs to demonstrate the mount-namespace boundary;
   after the drop, mount(2) inside the workload fails EPERM (CAP_SYS_ADMIN
   gone) — an intended, stronger property. Both tests now assert the
   attempt fails, nothing is mounted, and the host mountinfo is
   byte-identical before/after (no propagation, no leak). The mount-ns
   distinctness property remains verified by ns identity.
3. Seccomp derivation unchanged: capset/prctl happen during Stage-A
   initialization (before any filter — ADR-008), never in workload
   traces; the regression gate still shows 45 syscalls, no expansion.

### Container-validated results (Docker Desktop, WSL2 kernel, uid 1001, seccomp=unconfined)

- **31/31 Step 7 tests PASS** (new capability tests: 12 host-side, 4
  sandbox-internal, 3 probe + 2 updated Step 2/3 mount tests in the
  regression). Full container suite: 173 tests OK (2 pre-existing
  substrate skips). Key evidence: capability sets all-zero at workload
  time with no_new_privs still set; CAP_SYS_ADMIN/CAP_SYS_PTRACE/
  CAP_NET_ADMIN/CAP_SYS_MODULE/CAP_SYS_RAWIO/CAP_DAC_OVERRIDE absent
  bit-by-bit; workload not executed when the reduction fails (marker
  absent); unexpected residual capability -> refusal; probe ok + capset/
  verify failure refusals.
- Same substrate caveat as Steps 2-6 (Docker seccomp=unconfined to
  exercise OUR code; the product filter is Step 13).

### Native ubuntu CI (authoritative) — substrate limitation unchanged

| Check | 3.11 | 3.12 |
|---|---|---|
| capability-reduction real-path tests | SKIPPED (recorded reason: setgroups deny EACCES — rootless mapping cannot be established on the runner) | same |
| host-side wrapper/fail-closed/failure-injection tests | PASS | PASS |
| Skeleton / namespace / rootfs / procdev / network / no_new_privs regression | PASS | PASS |
| Seccomp regression gate + behavioral probe | PASS | PASS |

### Step 7 labels

- **DESIGN INTENT** (ADR-008, S-009): full bounding-set drop + cleared
  sets before the workload; no capability may remain, namespace-local
  included.
- **DOCKER VERIFIED**: reduction + read-back (all sets zero), per-cap
  absence of the named forbidden capabilities, ordering after
  no_new_privs, workload-never-executed on failure, unexpected-state
  refusal, lo-toggle resolution, mount-EPERM resolution.
- **NATIVE VERIFIED**: fail-closed behavior and host-side logic only;
the full rootless path remains NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION (RESOLVED in Step 8)**: seccomp is now installed
  and enforced (see the Step 8 record below); rlimits now landed too
  (Step 9 record below); cgroups v2 (Step 10), environment
  sanitization, output limits, timeout/cleanup remain outstanding.

## Phase 1 Step 8 — seccomp filter installation results (2026-08-19)

Mechanism implemented (`agent_sandbox/isolation/seccomp.py`, per
policy.md - the sanctioned Phase-1 implementation): the derived
45-syscall default-deny filter is BUILT from the regression-protected
artifact `tools/seccomp-derivation/allowlist.json` (single source of
truth - no embedded copy, no parallel policy) host-side in the setup
child BEFORE entering the boundary (the artifact is unreachable inside
the pivoted rootfs), then INSTALLED in PID 1 as the LAST Stage-A
operation - after no_new_privs (Step 6) and the capability reduction
(Step 7), immediately before the workload fn (methodology.md section 9:
install after every Stage-A op, never before no_new_privs). The BPF is
the identical default-deny layout the derivation probe uses: arch guard
(KILL on AUDIT_ARCH mismatch), linear JEQ allow chain, trailing RET
ALLOW, default RET_ERRNO|EPERM. Architecture guard: the runtime refuses
to build/install on anything but x86_64 (the allowlist is x86_64-
derived).

### Kernel-state verification (never "prctl returned success")

- /proc/self/status read-back at workload time: Seccomp mode == 2
  (SECCOMP_MODE_FILTER) and Seccomp_filters >= 1 (0 = our install
  missing = refusal).
- Behavioral spot check after install: socket(2) must fail EPERM; if it
  succeeds the state is unexpected and the workload is refused.
- Empirical finding: Docker Desktop's WSL2 runtime applies its own outer
  seccomp filter even with seccomp=unconfined (the container process
  itself shows Seccomp: 2, Seccomp_filters: 1 - verified). Filters are
  inherited across fork, so sandbox PID 1 reports 2 after our install on
  Docker (outer + ours) and 1 on a clean native host. The MODE is the
  state signal; the count must be >= 1.

### Enforcement evidence (DOCKER VERIFIED, uid 1001, real sandbox)

- Workload runs under SECCOMP_MODE_FILTER (read-back at workload time).
- Allowed syscalls work: a legitimate file read/write/list/stat workload
  runs under the filter.
- Forbidden: socket and prctl fail EPERM; the workload cannot load a
  different filter or alter the bounding set (prctl denied); fork(2) is
  denied (process creation restricted to the vfork/execve path);
  exec'd descendants inherit the filter (a fresh interpreter exec'd via
  execve still gets EPERM on socket - SOCKET_EPERM:1 evidence).
- no_new_privs (NoNewPrivs: 1) and the empty capability sets are
  preserved at workload time under the filter.
- Failure paths: install failure, verification failure (mode 0), and
  unexpected state (mode 1) all REFUSE with the workload never executed
  (marker-absent evidence).
- 31/31 Step 8 tests + full suite 204 tests OK (2 pre-existing substrate
  skips) container-validated.

### Interaction updates (gate-caught, logged before fixing)

- The socket class is now syscall-denied at workload time: the Step 5
  network tests were updated to assert the syscall-level denial (socket
  -> EPERM) over the netns state (which remains verified pre-filter in
  PID 1); the ioctl flag reads at workload time are no longer possible
  (they need a socket fd).
- kill(2) (PID-visibility probe) and prctl(2) (nnp read-back) are denied
  at workload time: test_host_process_invisibility now probes via
  /proc/<pid> existence; the nnp read-back uses the NoNewPrivs status
  field (the prctl read-back remains verified by the probes, which run
  before the filter).

### Native ubuntu CI (authoritative) — substrate limitation unchanged

| Check | 3.11 | 3.12 |
|---|---|---|
| seccomp real-path tests | SKIPPED (recorded reason: setgroups deny EACCES — rootless mapping cannot be established on the runner) | same |
| host-side BPF/allowlist/fail-closed tests | PASS | PASS |
| Skeleton / namespace / rootfs / procdev / network / privileges regression | PASS | PASS |
| Seccomp regression gate (45, no expansion) + behavioral probe | PASS | PASS |

### Step 8 labels

- **DESIGN INTENT** (ADR-008, S-011, policy.md): last-Stage-A install,
  default-deny EPERM, x86_64-only, allowlist as regression-protected
  artifact.
- **DOCKER VERIFIED**: install + mode read-back + allowed/forbidden
  syscalls + fork/exec inheritance + nnp/cap preservation + all refusal
  paths, under the actual runtime filter.
- **NATIVE VERIFIED**: host-side logic (BPF layout, allowlist pin,
  verification semantics) and fail-closed behavior; the full rootless
  path remains NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: rlimits/cgroups (Step 9), environment
  sanitization, output limits, timeout/cleanup are not yet implemented;
  ioctl remains broad (bounded by minimal /dev + dropped caps); the
  allowlist is x86_64/glibc-specific.

## Phase 1 Step 6 — no_new_privs results (2026-08-19)

Mechanism implemented: `prctl(PR_SET_NO_NEW_PRIVS, 1)` established in
sandbox PID 1 immediately before the workload function runs, with the
KERNEL STATE read back and verified (`prctl(PR_GET_NO_NEW_PRIVS) == 1`)
— never "the prctl set call returned success"
(`agent_sandbox/isolation/privileges.py`, syscall wrapper in
`isolation/syscalls.py`, x86_64 157 / aarch64 167). Placement per
ADR-008: no_new_privs precedes the Step 13 seccomp filter install (an
unprivileged process may only load a filter after no_new_privs is set)
and precedes any untrusted exec. Any failure or unexpected read-back is
REFUSAL (fail closed) — the workload fn never runs on an unverified
privilege state. HARDENED refusal point advances to SECCOMP.

### Mechanism semantics

- The bit is inherited across fork and exec: setting it in PID 1 covers
the entire workload tree. setuid/setgid binaries and file capabilities
become inert from that point (S-010, THREAT_MODEL T-023).
- The kernel enforces it irrevocably — nothing inside the sandbox can
clear it.
- Verification is a kernel-state read-back of the calling thread's
current value (PR_GET_NO_NEW_PRIVS returns 0 or 1); value != 1 is a
refusal, never a warning-and-continue.

### Container-validated results (Docker Desktop, WSL2 kernel, uid 1001, seccomp=unconfined)

- **19/19 Step 6 tests PASS** (real Linux execution): raw read-back == 1
  inside sandbox PID 1 (uid 0, pid 1); ORDERING verified — with the
  prctl seam failing, the workload fn's host marker never appears (fn
  never executes) and the run fails with the explicit no_new_privs
  reason; setup failure refuses; verification failure (read-back 0)
  refuses; unexpected read-back (2) refuses; probe ok (read-back
  verified in PID 1); probe setup-failure and read-back-mismatch
  refusals; full real chain (namespaces + filesystem + network +
  privileges) then HARDENED refuses at SECCOMP (STAGE_UNAVAILABLE).
- Same substrate caveat as Steps 2-5 (Docker seccomp=unconfined to
  exercise OUR code; the product filter is Step 13).

### Native ubuntu CI (authoritative) — substrate limitation unchanged

| Check | 3.11 | 3.12 |
|---|---|---|
| no_new_privs real-path tests | SKIPPED (recorded reason: setgroups deny EACCES — rootless mapping cannot be established on the runner) | same |
| host-side wrapper/fail-closed/failure-injection tests | PASS | PASS |
| Skeleton / namespace / rootfs / procdev / network regression | PASS | PASS |
| Seccomp regression gate + behavioral probe | PASS | PASS |

### Step 6 labels

- **DESIGN INTENT** (ADR-008, S-010): no_new_privs before any untrusted
exec and before the seccomp install; never bypassed, never downgraded.
- **DOCKER VERIFIED**: establishment + kernel-state read-back + ordering
  (workload never executes before the invariant) + all failure/refusal
  paths, in the real sandbox.
- **NATIVE VERIFIED**: fail-closed behavior and host-side logic only;
the full rootless path remains NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: capability reduction (Step 12) and seccomp
  (Step 13) are not yet implemented — no_new_privs alone is the
  privilege-gain blocker today, and the complete privilege-reduction
  surface is not claimed until those land.

## Phase 1 Step 9 — rlimits results (2026-08-19)

Mechanism implemented (`agent_sandbox/isolation/resources.py`, per
ADR-007 / ARCHITECTURE.md §9, S-012/S-027): the six mandated rlimits are
lowered in sandbox PID 1 with soft == hard — RLIMIT_CPU (cpu_seconds),
RLIMIT_AS (memory_mb bytes), RLIMIT_NPROC (processes), RLIMIT_NOFILE
(open_files), RLIMIT_FSIZE (disk_mb bytes), RLIMIT_CORE=0 — and the
KERNEL STATE is read back (getrlimit) and verified: every limit must
read back (soft == hard == policy value). Never "the syscall returned
success"; any set failure, unreadable limit, or unexpected value is
REFUSAL (fail closed) — the workload fn never runs on an unverified
resource state. Lowered hard limits can never be raised (S-027).

### Ordering constraint (charter): seccomp is already installed

Seccomp (Step 8) is installed BEFORE the rlimits in PID 1 — the mandated
item order (13 then 14). glibc's setrlimit(2)/getrlimit(2) map to the
prlimit64 syscall, which IS in the derived 45-syscall allowlist
(syscall-classification.md) — so NO filter change and NO syscall
addition was required. This is proven empirically: the sandbox-internal
tests establish the rlimits under the ACTUAL runtime filter (DOCKER
VERIFIED), and the workload-time read-back shows the limits in force
alongside Seccomp: 2 and NoNewPrivs: 1 in one view. The seccomp
regression gate still reports 45 (no expansion).

### RESOURCES-stage shape (ADR-007)

- rlimits are the always-applied half of the RESOURCES stage.
- HARDENED additionally mandates cgroup v2 delegation (Step 10): until
  that half is implemented, the RESOURCES probe establishes + verifies
  the rlimits (proving the mechanism works) and then REFUSES HARDENED AT
  the RESOURCES stage with the explicit reason — the refusal point does
  not advance beyond RESOURCES while the stage is incomplete.
- RESTRICTED's RESOURCES stage is rlimits only (ADR-007): the probe
  returns OK and RESTRICTED advances to refuse at ENVIRONMENT.

### Kernel-state/read-back evidence (DOCKER VERIFIED, uid 1001, real sandbox)

- Workload-time read-back in PID 1 (one view): RLIMIT_CPU [300, 300],
  RLIMIT_AS [4294967296, 4294967296], RLIMIT_NPROC [256, 256],
  RLIMIT_NOFILE [4096, 4096], RLIMIT_FSIZE [10737418240, 10737418240],
  RLIMIT_CORE [0, 0], Seccomp: 2, NoNewPrivs: 1.
- Inheritance: the workload (a descendant of PID 1) reads back exactly
  the applied limits.
- S-027 / T-035 adversarial: an attempt to RAISE RLIMIT_NOFILE inside
  the workload is DENIED (kernel rule — no CAP_SYS_RESOURCE, Step 7).
- Failure paths: set-limit failure and read-back mismatch both REFUSE
  with the workload never executed (marker-absent evidence).
- Real chain: HARDENED refuses AT RESOURCES with the cgroup reason;
  RESTRICTED completes RESOURCES and refuses at ENVIRONMENT.
- 20/20 Step 9 tests + full suite 224 tests OK (2 pre-existing substrate
  skips) container-validated.

### Import-safety finding (logged before fixing, freebuff-errors.txt)

CPython on Windows does NOT ship the `resource` module: an unguarded
module-level `import resource` broke import-safety (8 ImportErrors in
test discovery). Fixed with a guarded import (`_HAS_RESOURCE` flag;
RLIMIT constants None; seams raise NamespaceSetupError) so the module
stays import-safe on every platform and fails closed at call time. The
host-side policy tests patch the constants with sentinels on non-Unix so
the logic is tested identically everywhere.

### Native ubuntu CI (authoritative) — substrate limitation unchanged

| Check | 3.11 | 3.12 |
|---|---|---|
| rlimits real-path tests | SKIPPED (recorded reason: setgroups deny EACCES — rootless mapping cannot be established on the runner) | same |
| host-side policy/apply/verify/fail-closed tests | PASS | PASS |
| Skeleton / namespace / rootfs / procdev / network / privileges / seccomp regression | PASS | PASS |
| Seccomp regression gate (45, no expansion) + behavioral probe | PASS | PASS |

### Step 9 labels

- **DESIGN INTENT** (ADR-007, S-012/S-027): six always-applied,
  unprivileged, irreversible limits; HARDENED also mandates cgroup v2
  (Step 10); RESTRICTED is rlimits only.
- **DOCKER VERIFIED**: establishment under the installed filter +
  read-back + inheritance + cannot-raise + all refusal paths, in the
  real sandbox.
- **NATIVE VERIFIED**: host-side logic (policy mapping, apply/verify
  semantics, failure injection) and fail-closed behavior; the full
  rootless path remains NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: cgroups v2 (Step 10) is the remaining half of
  the RESOURCES stage — HARDENED still refuses AT RESOURCES until it
  lands; RLIMIT_AS is per-process (total-tree memory needs the cgroup
  memory.max); RLIMIT_FSIZE bounds single files (total disk needs
  io.max + workspace pre-check) — both documented gaps per ADR-007.
