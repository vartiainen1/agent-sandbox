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
| Syscall surface on a real uid-mapped rootless runtime | **NOT YET VERIFIED** — the container trace ran as root without a user namespace; a native run with the real uid mapping is required |
| Behavioral equivalence on native ubuntu | **NOT YET VERIFIED** — needs CI |

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

Results are recorded in this file after the first native run; container
results remain labeled container-validated regardless.
