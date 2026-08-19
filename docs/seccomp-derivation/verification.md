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

## Phase 1 Step 10 — cgroup v2 enforcement results (2026-08-19)

### Policy (READING A — approved policy definition, ADR-007)

The four architecture-named controllers on the session subtree (a child
the supervisor creates in the delegated subtree):

| Controller | Exact value | Source |
|---|---|---|
| `pids.max` | `ResourceLimits.processes` (default 256) | config |
| `memory.max` | `ResourceLimits.memory_mb * 1024 * 1024` (default 4096 MiB) | config |
| `cpu.max` | `"{cpu_quota_percent * 1000} 100000"` — period fixed 100000 µs; 100% = 100000/100000 (one full core) | `cpu_quota_percent` (default 100) |
| `io.max` | `"{major}:{minor} rbps={io_mbps*1024*1024} wbps={io_mbps*1024*1024}"` on the kernel-resolved backing device of the workspace/rootfs | `io_mbps` (default 1024) |

HARDENED requires ALL FOUR controllers: no partial success — any
controller unavailable, not delegated, unwritable, unconfigureable, or
unverifiable → STAGE_FAILED → explicit reason → workload not executed →
refused AT RESOURCES. RESTRICTED retains rlimits-only (ADR-007), no
cgroup requirement. The io device is resolved from kernel state
(`/proc/self/mountinfo` + `/sys/dev/block`), never a guessed major:minor;
if the device cannot be resolved, HARDENED refuses. `memory.swap.max` is
not required (not in the architecture).

### Mechanism (isolation/cgroups.py)

- cgroup v2 filesystem identity verification (cgroup.controllers present,
  cgroup2 fstype in mountinfo)
- required-controller discovery (pids, memory, cpu, io)
- delegation/writability probe: create + remove a child cgroup in the
  caller's cgroup — the mkdir/rmdir test is the delegation signal, never
  "the probe file exists"; precise BLOCKED reason (read-only / not
  delegated / controller-unavailable) returned on failure
- session cgroup creation; enable the four controllers in subtree_control
  (atomic four-controller requirement)
- limit writes; migrate sandbox PID 1 via cgroup.procs
- read every configured limit back from kernel state (never a successful
  write as evidence); verify PID 1 membership; verify workload
  inheritance across fork/exec
- deterministic NamespaceSetupError on every unexpected state; Windows
  import-safe (all filesystem ops behind seams)

### Ordering

proc → network → no_new_privs → capability reduction → seccomp → rlimits
→ cgroup enforcement → workload. Seccomp untouched; cgroup setup uses
only already-allowlisted operations (open/write/read/close on the
delegated cgroupfs — no syscall expansion; gate still 45).

### Substrate evidence (labels kept strictly separate)

- **DOCKER ROOTLESS BLOCKED (uid 1001)**: cgroupfs is mounted
  READ-ONLY (cgroup2 ro,nosuid,nodev,noexec) — mkdir fails with
  "Read-only file system". The delegation probe returns the precise
  reason `cgroup v2 delegation unavailable: read-only filesystem
  (no writable delegated subtree)`, HARDENED refuses with the workload
  marker absent. This is the fail-closed path — NOT an enforcement PASS.
- **PRIVILEGED SUBSTRATE VERIFIED (WSL2 root container)**: delegation
  probe writable (mkdir/rmdir OK — the earlier false negative from the
  cgroup.type EINVAL write was fixed: that write is value semantics, not
  a delegation signal); io device resolved from kernel state (7,3);
  HARDENED then refuses with the precise controller-availability reason
  because WSL2 cannot enable `memory`/`io` at the root — even with
  pids/cpu individually enableable, the atomic four-controller
  requirement refuses, exactly READING A. Mechanism behavior proven;
  full enforcement NOT achieved on this substrate either.
- **NATIVE GITHUB RUNNER**: delegation detection/fail-closed path runs;
  no writable delegated subtree for uid 1001 (cgroupfs root-owned) →
  **NATIVE ROOTLESS ENFORCEMENT NOT VERIFIED** — never relabeled PASS.

### Step 10 labels

- **POLICY VERIFIED**: cpu.max / io.max formatting + exact mapping +
  validation, host-side (254-test Windows suite green).
- **ROOTLESS DELEGATION BLOCKED**: Docker rootless read-only cgroupfs —
  fail-closed refusal with precise reason (workload marker absent).
- **PRIVILEGED SUBSTRATE VERIFIED**: delegation probe + device
  resolution on the privileged container; controller-enablement refusal
  per READING A. Proves mechanism behavior only — NOT rootless proof.
- **NATIVE ROOTLESS NOT VERIFIED**: recorded reason (no delegated
  subtree on the runner); native skips never converted to PASS.
- **KNOWN LIMITATION**: genuine rootless HARDENED cgroup enforcement
  remains unverified until a systemd `Delegate=yes` (or equivalent)
  writable delegated subtree exists; io.max requires a resolvable
  backing device in the enforcement substrate.

## Phase 1 Step 11 — environment sanitization results (2026-08-19)

### Policy (approved Step 11 policy, ADR-009, S-034, T-018, T-051)

The host environment is NEVER inherited. PID 1 constructs exactly these
six deterministic sandbox-local variables and drops everything else:

    PATH=/usr/local/bin:/usr/bin:/bin
    HOME=/home
    TMPDIR=/tmp
    LANG=C.UTF-8
    LC_ALL=C.UTF-8
    TERM=dumb

env_allowlist semantics: the six are the COMPLETE v0.1 supported set;
config.py REJECTS any env_allowlist entry beyond them with an explicit
ConfigError (no value source in v0.1 — secret/environment-value injection
is explicitly deferred, ARCHITECTURE §11). Host values are never copied,
merged, or selectively inherited.

### Mechanism (isolation/environment.py)

- `construct_environment(allowlist)` — exactly {name: approved-value} for
  the allowlisted names; anything else fails closed (no guessed values).
- `apply_environment(environment)` — replaces the process environment
  entirely (clear + set); any failure is a refusal.
- `verify_environment(allowlist)` — reads the LIVE process environment
  back and requires exactly the allowlisted variables with exactly the
  approved values; any unexpected variable, missing variable, or
  incorrect value is a refusal with the precise reason.
- `sanitize_and_verify(allowlist)` — construct → apply → verify, applied
  in PID 1 AFTER the resource stage (cgroup join) and BEFORE the workload
  fn. Pure process state: no syscalls — seccomp untouched (gate 45).
- All mutation behind seams for deterministic failure injection; Windows
  import-safe.

### Ordering

proc → network → no_new_privs → capability reduction → seccomp → rlimits
→ cgroup → **environment sanitization** → workload. ENVIRONMENT stage
guard registers; HARDENED/RESTRICTED now advance past ENVIRONMENT and
refuse at EXECUTION (the next unimplemented stage) — never a silent pass.

### Verification evidence (labels kept separate)

- **HOST-SIDE VERIFIED (Windows 284 OK)**: construction, apply/verify
  semantics, unexpected/missing/incorrect-variable refusals, config
  rejection of entries beyond the six (GITHUB_TOKEN / AWS_* /
  SSH_AUTH_SOCK rejected), substitution-failure refusals, no-host-value
  reads (hostile PATH/HOME/TMPDIR injected → constructed env ignores
  them).
- **DOCKER VERIFIED (uid 1001 container, real sandbox under the ACTUAL
  runtime filter)**: workload sees exactly the approved six
  (PATH=/usr/local/bin:/usr/bin:/bin, HOME=/home, TMPDIR=/tmp,
  LANG=LC_ALL=C.UTF-8, TERM=dumb); host variables (PATH=/evil,
  GITHUB_TOKEN, AWS_ACCESS_KEY_ID, SSH_AUTH_SOCK) NEVER reach the
  workload; sanitization failure refuses with the workload marker absent;
  one workload-time view confirms NoNewPrivs=1, Seccomp=2, all capability
  sets zero, and the approved environment together — Steps 6-10
  invariants preserved. 30/30 Step 11 tests + full suite 284 OK.
- **NATIVE**: host-side policy/config/failure tests PASS; sandbox-internal
  tests SKIP with the recorded setgroups/AppArmor reason (never PASS).

### Step 11 labels

- **DESIGN INTENT** (ADR-009, S-034): six constructed variables; host env
  never inherited; value injection deferred.
- **DOCKER VERIFIED**: construction + leakage prevention + refusal paths
  in the real sandbox under the installed filter.
- **NATIVE VERIFIED**: host-side logic and fail-closed behavior; full
  rootless sandbox path NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: the ENVIRONMENT stage is complete, but EXECUTION
  (bounded output, timeout, process-tree cleanup) is the next
  unimplemented stage — isolated modes still refuse there; rootless
  cgroup enforcement remains the Step 10 open item.
## Phase 1 Step 12 — credential/socket isolation results (2026-08-19)

Policy (ADR-009, S-003/S-004, T-016/T-019/T-020): the sandbox must not be
able to reach host credentials, credential stores, agent/SSH/cloud
credential paths, or Docker/container/control Unix sockets. Absence by
boundary is the preferred property. Enforcement is by construction
(fresh rootfs + workspace copy, sanitized env, socket syscall class
denied by the Step 8 filter) — Step 12 verifies the boundary and fails
closed on any exposure.

Mechanism (`isolation/credentials.py`): `CREDENTIAL_PATHS` canonical
list (host home, .ssh, .aws, .kube, /root, /run, docker/containerd
sockets, etc.) checked for reachability from the workload view;
`SOCKET_ENV_NAMES` (SSH_AUTH_SOCK, DOCKER_HOST, etc.) verified absent
after sanitization; socket-creation denial verified inside the sandbox.
Wired: PID-1 verification after env sanitization, ENVIRONMENT probe half
verifies the constructed env carries no socket/credential variable.

### Step 12 evidence

- **HOST-SIDE VERIFIED** (Windows 307 OK / 146 substrate skips): path
  reachability semantics, env verification, socket-denial seam, failure
  injection, config rejection, workload-not-executed refusals.
- **DOCKER VERIFIED** (uid 1001, real sandbox under the ACTUAL filter):
  full suite 307 OK (3 honest skips); credential/socket tests exercise
  the real boundary — reachability checks against the sandbox view,
  socket-creation denial (EPERM from the filter), env isolation
  preserved.
- **NATIVE VERIFIED**: host-side logic and fail-closed behavior; full
  rootless sandbox path NOT VERIFIED NATIVE (recorded AppArmor/setgroups
  substrate reason).
- **SEPARATION**: no syscall added — the socket class was already denied
  by the 45-syscall allowlist; gate remains exactly 45.
- **INVARIANTS PRESERVED**: NoNewPrivs=1, cap sets zero, filter
  installed, rlimits enforced, cgroup controls preserved where delegated,
  six-variable sanitized env intact.

### Step 12 labels

- **DESIGN INTENT** (ADR-009, S-003/S-004): absence-by-boundary for all
  named credential/control surfaces.
- **DOCKER VERIFIED**: reachability absence, env cleanliness, and
  socket-creation denial demonstrated in the real sandbox under the
  filter.
- **NATIVE VERIFIED**: host-side logic + fail-closed; sandbox-internal
  path NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: ENVIRONMENT stage now complete; EXECUTION
  (bounded output, timeout, process-tree cleanup) remains the next
  unimplemented stage; rootless cgroup enforcement remains the Step 10
  open item.
## Phase 1 Step 13 — bounded stdout/stderr results (2026-08-19)

Policy (S-037, ARCHITECTURE section 9, ADR-007): the workload must not
be able to generate unlimited output that exhausts host resources. The
supervisor reads stdout/stderr through a bounded pipe; past the limit it
terminates the session with a truncation notice. The bound is ENFORCED,
not observed: the pipe is the only output channel into the supervisor,
and once the read end is closed past the limit the workload's further
writes hit EPIPE/SIGPIPE (kernel-enforced) - the workload cannot bypass
the bound. The limit value is the validated config `output_mb` (default
50 MiB, ResourceLimits, >= 1).

Mechanism (`isolation/output.py`): `read_bounded` reads at most
limit_bytes (plus a one-byte EOF probe so exactly-at-limit with EOF is a
COMPLETE run, not a false truncation); `collect_bounded` (supervisor
side) terminates the session on truncation (closes the read end + kills
the controlled child). Wired into `run_in_sandbox` supervisor-side:
`SandboxRun.truncated` + a deterministic truncation notice in the
output. The EXECUTION stage guard still does NOT register (items 19-20 -
timeout, process-tree cleanup - are outstanding), so the isolated modes
keep refusing at EXECUTION (fail closed).

### Step 13 evidence

- **HOST-SIDE VERIFIED** (Windows 322 OK / 150 substrate skips):
  under/at/over-limit reads, EOF probe semantics, zero/negative-limit
  fail-closed, read-failure fail-closed, chunking, deterministic notice,
  session-termination seam tests (kill invoked with SIGKILL, missing
  child tolerated).
- **DOCKER VERIFIED** (uid 1001, real sandbox under the ACTUAL filter):
  small output complete (truncated=False); 2 MiB against 1 MiB bound ->
  truncated=True, notice present, output length bounded, session
  terminated; 4 MiB hostile output -> never more than the bound captured
  (workload cannot bypass).
- **NATIVE VERIFIED**: host-side logic and fail-closed behavior; full
  rootless sandbox path NOT VERIFIED NATIVE (recorded AppArmor/setgroups
  substrate reason).
- **SEPARATION**: no syscall added - the bounded pipe uses only the
  already-allowlisted read/write/close on the supervisor side; gate
  remains exactly 45.
- **INVARIANTS PRESERVED**: NoNewPrivs=1, cap sets zero, filter
  installed, rlimits enforced, cgroup controls preserved where delegated,
  six-variable sanitized env intact, credential/socket boundary intact.

### Step 13 labels

- **DESIGN INTENT** (S-037): bounded supervisor pipe -> terminate +
  truncation notice; output cannot exhaust host resources.
- **DOCKER VERIFIED**: real bounded read under the actual filter,
  truncation + termination + no-bypass demonstrated.
- **NATIVE VERIFIED**: host-side logic + fail-closed; sandbox-internal
  path NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: EXECUTION stage guard still unregistered (items
  19-20 - external timeout, process-tree cleanup - outstanding), so
  isolated modes keep refusing at EXECUTION; rootless cgroup enforcement
  remains the Step 10 open item.
## Phase 1 Step 14 — external timeout enforcement results (2026-08-19)

Policy (S-036, ADR-011, ARCHITECTURE section 13, T-034): timeouts are
enforced EXTERNALLY by the supervisor and cannot be disabled by the
workload. The deadline value is the validated config `wall_time_seconds`
(default 900, ResourceLimits, >= 1) - no guessed value was introduced.

Mechanism (`isolation/timeout.py`): the supervisor enforces the deadline
while collecting the bounded output pipe: each wait is bounded by the
remaining time (select + time.monotonic, both supervisor-side); on
expiry the supervisor terminates the session (closes the read end +
kills the controlled child - further workload writes fail with
EPIPE/SIGPIPE) and marks `SandboxRun.timed_out` with a deterministic
timeout notice. The deadline lives entirely in the supervisor process -
the workload cannot disable, evade, or reset it (no shared clock, no
capabilities, no channel). The EXECUTION stage guard still does NOT
register (item 20 - process-tree containment - is outstanding), so the
isolated modes keep refusing at EXECUTION (fail closed).

Note: the workload cannot sleep (nanosleep is NOT in the derived
45-syscall allowlist - no expansion), so the sandbox-internal timeout
tests hang the workload on an ALLOWLISTED blocking read of a pipe it
creates itself, or stall mid-output - the hang is legal under the filter.

### Step 14 evidence

- **HOST-SIDE VERIFIED** (Windows 337 OK / 155 substrate skips):
  completes-within-deadline, deadline-expiry termination (SIGKILL),
  partial-output-then-expiry (never false success), output-bound still
  truncates before a long deadline, zero-bound, invalid-timeout and
  invalid-bound fail-closed, select-failure and read-failure fail-closed,
  deterministic notice.
- **DOCKER VERIFIED** (uid 1001, real sandbox under the ACTUAL filter):
  normal completion before the deadline succeeds (timed_out=False);
  hanging workload -> deadline fires, session terminated, timed_out=True,
  "NEVER REACHED" absent; output flows then stalls -> expiry terminates
  (no false success); output bound + deadline coexist (truncation, not
  timeout).
- **NATIVE VERIFIED**: host-side logic and fail-closed behavior; full
  rootless sandbox path NOT VERIFIED NATIVE (recorded AppArmor/setgroups
  substrate reason).
- **SEPARATION**: no syscall added - select/read/close are supervisor-
  side (outside the filter); gate remains exactly 45.
- **INVARIANTS PRESERVED**: NoNewPrivs=1, cap sets zero, filter
  installed, rlimits enforced, cgroup controls preserved where delegated,
  six-variable env intact, credential/socket boundary intact, bounded
  output intact.

### Step 14 labels

- **DESIGN INTENT** (S-036): external supervisor deadline; workload
  cannot disable/evade/reset it.
- **DOCKER VERIFIED**: real expiry under the actual filter - session
  terminated, timed_out reported, no false success.
- **NATIVE VERIFIED**: host-side logic + fail-closed; sandbox-internal
  path NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: EXECUTION stage guard still unregistered (item
  20 - process-tree containment/cleanup - outstanding), so isolated
  modes keep refusing at EXECUTION; rootless cgroup enforcement remains
  the Step 10 open item.

## Phase 1 Step 15 — process-tree containment and cleanup (2026-08-19)

Mechanism implemented (S-014, S-038, ADR-011, ARCHITECTURE section 6/13,
item 20): the supervisor is a CHILD SUBREAPER (PR_SET_CHILD_SUBREAPER,
verified by kernel-state read-back); termination targets SANDBOX PID 1 —
the namespace init, so the kernel terminates the WHOLE workload tree
(vfork/exec descendants included) — plus `cgroup.kill` where delegated;
after EVERY run path the supervisor performs MANDATORY absence
verification (S-038: no workload process may remain; a survivor is
recorded in `SandboxRun.cleanup_failure`, never reported as success,
S-024). Killing only the immediate child is explicitly forbidden
(ADR-011). Completes the EXECUTION stage (items 18–21: bounded output,
timeout, process-tree containment, cleanup verification); the EXECUTION
guard registers and the isolated modes initialize to READY on a capable
substrate.

### Step 15 evidence

- **HOST-SIDE VERIFIED (Windows 357 OK / 159 substrate skips):**
  subreaper set + kernel-state read-back; set failure and read-back
  mismatch fail closed; namespace-inode parsing; /proc membership scan
  (exact-entry matching); tree termination targets sandbox PID 1 (never
  just the immediate child); already-gone PID 1 tolerated; cgroup.kill
  belt-and-braces; absence verification (no survivors OK; survivors
  detected and reported with S-038 reason; namespace init gone == nothing
  remains; non-empty cgroup.procs reported).
- **DOCKER VERIFIED (uid 1001, real sandbox under the ACTUAL filter,
  real subreaper + real namespace-init kill):** supervisor is a real
  child subreaper after a run; normal completion leaves no workload
  process (cleanup_failure == ""); a hanging workload with a live vfork
  descendant (spin child — no syscalls, survives the filter) times out
  and the WHOLE tree is killed with no survivors; a flooding workload
  with a live vfork descendant hits the output bound and the whole tree
  is terminated with no survivors — the kernel namespace-init kill
  catches the descendant even though the supervisor never saw its PID.
- **NATIVE VERIFIED**: host-side logic + fail-closed behavior; the
  real sandbox path remains NOT VERIFIED NATIVE (recorded
  AppArmor/setgroups substrate reason).
- **EXECUTION GUARD**: registered (items 18–21 complete). The real-path
  probe exercises the supervisor machinery (subreaper set + read-back;
  flooding child truncated + terminated; silent child terminated on
  deadline expiry; both reaped). On a capable substrate HARDENED/
  RESTRICTED initialize to READY (asserted by the real-chain tests);
  on substrates where an earlier mandatory mechanism cannot be
  established they refuse at the first unavailable one — never a
  silent downgrade.
- **SEPARATION**: no syscall added — prctl/setpgid-free supervisor-side
  machinery; `vfork`/`write`/`read` were already allowlisted; gate
  remains exactly 45.
- **INVARIANTS PRESERVED**: NoNewPrivs=1, cap sets zero, filter
  installed, rlimits enforced, cgroup controls preserved where delegated,
  six-variable env intact, credential/socket boundary intact, bounded
  output + timeout intact.

### Step 15 labels

- **DESIGN INTENT** (S-014/S-038, ADR-011): namespace-init kill +
  subreaper + cgroup.kill + mandatory absence verification; killing only
  the parent is forbidden.
- **DOCKER VERIFIED**: whole-tree termination and absence verification
  under the actual filter with live vfork descendants.
- **NATIVE VERIFIED**: host-side logic + fail-closed; sandbox-internal
  path NOT VERIFIED NATIVE (recorded reason).
- **KNOWN LIMITATION**: native rootless sandbox-internal execution
  remains NOT VERIFIED (Step 2/10 open items, unchanged); the minimal
  successful workload demonstration (item 22) and CLI/MCP integration
  remain later steps.
