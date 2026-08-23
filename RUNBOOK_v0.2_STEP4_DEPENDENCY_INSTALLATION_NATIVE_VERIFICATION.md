# v0.2 Step 4 / Phase 10 — Dependency-Installation Workflow — Native Verification Runbook

> **Status: COMPLETE (2026-08-23)**
>
> This runbook documents the exact measurement, the toolchain decision,
> and the native verification of the dependency-installation workflow
> (pip through the validating proxy inside the real sandbox). Verified
> in a **privileged Linux container** (Debian 13, run with
> `--privileged` for veth/iptables/userns operations), WSL2 kernel
> 6.18.33.2-microsoft-standard, Python 3.11 (slim base) / 3.13
> (Debian dist-packages for pip), pip 24.x/25.1.1, strace 6.13.

---

## 1. What this step delivers

| Item | Where | Status |
|---|---|---|
| **Toolchain decision (A/B/C)**: the curated toolchain is extended with `python3-pip` (Option B) AND exactly one syscall is added to the seccomp allowlist (Option C, minimally scoped) | `tools/toolchain/build_toolchain.py` (+`PIP_PACKAGE = "python3-pip"`), `tools/seccomp-derivation/allowlist.json` (+`fsync`) | IMPLEMENTED |
| `pip install --proxy http://10.255.254.0:8080 ...` works inside the real sandbox through the validating proxy | `agent_sandbox/isolation/proxy.py` (Step 3, unchanged) + toolchain pip + 70-syscall filter | IMPLEMENTED + VERIFIED |
| Seccomp: 69 → **70** (+`fsync` only — tier0 29 + tier1 41; aarch64 66 → 67) | `allowlist.json` v4, `allowlist_aarch64.json` v3, `seccomp.py::_X86_64`, `probe_policy.py::SYS`, `check_trace_regression.py` counts | IMPLEMENTED |
| **getsockname/getpeername x86_64 number correction** (50/51 → 51/52 — the wrong numbers made getpeername always-EPERM in the sandbox; latent since Step 1, surfaced by pip's CONNECT tunnel) | artifact `syscall_numbers`, `seccomp.py`, `probe_policy.py`; regression test `test_seccomp.py::test_x86_64_socket_syscall_numbers` | IMPLEMENTED |
| Evidence record: `t1_pip_install` in `trace-results.json` (successful surface under the real filter, 56 syscalls, all inside the allowlist) | `tools/seccomp-derivation/trace-results.json` | RECORDED |
| Tests: allowed source succeeds / disallowed source DENIED / fail-closed + clean teardown | `tests/unit/test_proxy.py::Phase10DependencyInstallTests` | IMPLEMENTED + VERIFIED (3/3) |

### The decision (documented, evidence-backed)

**Not Option A** (operate within the 69-syscall policy): the real-filter
measurement below proves pip install fails without `fsync`.

**Option B (curated installer)**: the toolchain includes `python3-pip`.
Debian/Ubuntu's python3-pip is self-contained — `pip/_vendor` carries
requests/urllib3/certifi (incl. the CA bundle), verified by importing
pip with only the package's own files on the PYTHONPATH.

**Option C (narrowly scoped syscall change)**: exactly **`fsync`** added.
The other five candidates observed in the raw trace are proven tolerated:

| syscall | who uses it | under real-seccomp EPERM |
|---|---|---|
| `bind` | urllib3 IPv6-availability probe (`connection.py:139`, binds `::1` port 0) | probe fails → IPv4 fallback, install OK |
| `clock_nanosleep` | asyncio loop sleep | fallback, install OK |
| `mremap` | glibc malloc growth | fallback, install OK |
| `readlinkat` | dynamic loader `/proc/self/exe` resolution | tolerated, install OK |
| `rmdir` | pip temp-dir cleanup | warnings only, install OK |
| **`fsync`** | pip `adjacent_tmp_file` — `os.fsync` on the downloaded wheel BEFORE the atomic rename | **install ABORTS with `PermissionError`** |

`clone`/`clone3`: **not used by pip at all** (thread count 0 — pip uses
vfork/posix_spawn), remain denied. `bind` remains denied.

---

## 2. Measurement evidence (real seccomp, not LD_PRELOAD)

LD_PRELOAD cannot intercept glibc-internal calls (mremap from malloc,
readlinkat from dl) — so necessity was measured with the **project's own
filter**: `build_program()` + `install_filter()` (no_new_privs +
PR_SET_SECCOMP), exec'ing pip under strace.

```
POLICY=70 (project filter): INSTALLED (rc=0)
POLICY=69 (project filter): FAILED (rc=1) --
  ERROR: Could not install packages due to an OSError:
  [Errno 1] Operation not permitted        <- fsync EPERM
```

Successful surface from the pip execve onward under POLICY=70: **56
syscalls, ALL inside the 70-syscall allowlist** (`successful-but-not-
allowed: []`); `clone` count = 0. Recorded in `trace-results.json`
`t1_pip_install` (successful calls only; the attempted-but-tolerated
bind/clock_nanosleep/mremap/readlinkat/rmdir are documented in the
allowlist changelog and are intentionally NOT part of the recorded
surface).

### Root/privilege requirements (documented, preserved)

`tests/unit/test_proxy.py::Phase10DependencyInstallTests` requires
Linux + root + `ip` + `iptables` + `openssl` + a curated toolchain
containing pip3 (`AGENT_SANDBOX_TOOLCHAIN`); skips otherwise. The
pre-existing root-premise failures (`test_host_caller_remains_
unprivileged`, `test_host_process_invisibility`) remain classified as
environment-premise results — do not convert them.

---

## 3. Reproduce (container, root)

```bash
# 1. Build the curated toolchain (container substrate: python3.13;
#    on the native VM substrate the default python3.12 constant applies)
sed -i 's#"/usr/lib/python3.12",#"/usr/lib/python3.13",#' \
  tools/toolchain/build_toolchain.py
python3 tools/toolchain/build_toolchain.py --out /opt/as-toolchain

# 2. Run the Phase 10 e2e tests
AGENT_SANDBOX_TOOLCHAIN=/opt/as-toolchain \
  python3 -m unittest tests.unit.test_proxy.Phase10DependencyInstallTests -v
# Expected: 3/3 ok
#   - test_pip_install_allowed_source_succeeds
#   - test_pip_install_disallowed_source_denied
#   - test_pip_install_proxy_down_fails_closed

# 3. Derivation gates
python3 tools/seccomp-derivation/test_derivation.py      # ALL PASS
python3 tools/seccomp-derivation/check_trace_regression.py  # PASS (70)
```

Observed e2e output signature (allowed source): `Successfully installed
demo-pkg`, `exit_code: 0`, `cleanup_failure: ''`, no `veth-sbx-h` after
teardown, zero iptables rules referencing the veth. The `WARNING:
Failed to remove contents in a temporary directory ...` lines are the
DOCUMENTED tolerated `rmdir` EPERM behavior (rmdir stays denied).

### npm/cargo measurement (Phase 10 remainder, 2026-08-23)

```bash
# Node under the REAL 70-syscall filter (project build_program + install_filter)
strace -f -e trace=syscall node -e 'console.log(42)'
# => fatal abort at startup: uv_loop_init (eventfd2 EPERM), then
#    WorkerThreadsTaskRunner::DelayedTaskScheduler::Start (clone3 EPERM)
# => node CANNOT start ANY workload without clone3 (platform scheduler thread)
#    + eventfd2, epoll_ctl, epoll_pwait, madvise, exit

# Cargo under the REAL 70-syscall filter
cargo fetch
# => 'Operation not permitted' at clone3 (CLONE_VFORK spawning rustc)
#    even cargo fetch (download-only) needs it; rc=101

# Full-sandbox e2e with a REAL node binary present in a scratch toolchain:
# node aborts at uv_loop_init (eventfd2 EPERM), exit 245 (SIGABRT),
# prompt (0.07s), no hang, no survivor, clean teardown
```

**Decision: NO syscall-policy expansion.** clone/clone3 are the S-014
single-process containment boundary; a dependency installer wanting
threads is not a security-reviewed justification for process creation
inside the sandbox. npm/cargo remain unsupported in-sandbox, fail
closed cleanly, and are absent from the curated toolchain. pip remains
the supported dependency-installation workflow.

---

## 4. Known limitations (explicit)

- **IPv4-only upstream** (unchanged from Step 3): IPv6 destinations are
  denied; the /31 link is IPv4.
- **Host firewall requires `iptables` + CAP_NET_ADMIN** (unchanged);
  fail closed otherwise.
- **One concurrent allowlist session per host** (fixed veth names).
- **HTTPS indexes only**: pip does not CONNECT for plain-`http://`
  URLs (it sends `GET http://...`), which the proxy correctly rejects.
  Use `https://` indexes (self-signed OK with `--trusted-host`).
- **Node/Rust dependency workflows (npm/cargo): MEASURED and
  INTENTIONALLY UNSUPPORTED** — this is a documented DECISION, not
  outstanding work. Real-filter measurement (project's own
  `build_program` + `install_filter`, strace, Debian 13 / node
  20.19.2 / cargo 1.85.0) proves both tools GENUINELY and
  UNCONDITIONALLY require `clone3` (Node's platform scheduler thread
  at startup for EVERY workload — no flag avoids it; cargo spawns
  rustc children even for `cargo fetch`; Node also needs eventfd2,
  epoll_ctl/epoll_pwait, madvise, exit). clone/clone3 are the S-014
  single-process containment boundary (the sandbox is a single-process
  execve bridge; process-tree cleanup + PID-1 model depend on it), so
  NO policy expansion was made — the 70-syscall allowlist is
  unchanged. npm/cargo are not shipped in the curated toolchain and
  fail closed cleanly inside the sandbox (node rc=139 abort at
  eventfd2, cargo rc=101 at clone3 — prompt, no hang, no leak;
  verified native full-sandbox e2e with a real node binary present,
  exit 245/SIGABRT, clean teardown). Pinned by
  `test_proxy.py::Phase10NpmCargoDecisionTests` (clone/clone3 absent
  from allowlist + runtime table, Node's extra syscalls absent,
  toolchain MANIFEST has no node/npm/cargo/rustc) and
  `Phase10NpmCargoFailClosedTests` (in-sandbox exec attempts fail
  cleanly). See policy.md §5 decision record.
- **aarch64**: number mappings updated (fsync=82); native aarch64
  filter verification remains SUBSTRATE-LIMITED (unchanged).

---

## 5. Phase 10 hardening findings (2026-08-23, all FIXED + pinned)

While running the complete adversarial/unit battery in the container
several LATENT defects surfaced; all are pre-existing on pristine HEAD
(verified by `git show HEAD` comparison), none are Phase 10 regressions.
Each was logged in freebuff-errors.txt BEFORE fixing (log-before-fix)
and carries a re-runnable VERIFY pin.

### 5.1 Sandbox output capture broke under pytest 9 fd capture

- Symptom: under `pytest --capture=fd` (default), `run_in_sandbox`
  returned `run.output == ''` while the workload's JSON appeared in
  pytest's captured stdout — adversarial tests failed with
  `json.loads(run.output)` on empty string. unittest/CLI were fine.
- Root cause: the sandbox child redirected raw fd 1/2 via
  `os.dup2(out_w, 1/2)` but never rebound Python's `sys.stdout`/
  `sys.stderr` objects. Under pytest 9's fd capture,
  `sys.stdout.fileno()` is a HIGH fd (6) pointing at pytest's capture;
  the workload's `print()` wrote through the inherited object to
  pytest's capture and the supervisor read EOF. Older pytest dup2'd its
  capture onto fd 1, so the bug was latent.
- Fix: after the dup2 in sandbox PID 1, rebind
  `sys.stdout = os.fdopen(1, ...)` / `sys.stderr = os.fdopen(2, ...)`
  (`closefd=False`). Output capture is now harness-independent.

### 5.2 Adversarial content-attack payloads leaked sockets on the error path

- The hook/buildscript exfil attempts created `socket(AF_INET)` (allowed
  in v0.2) and only closed it on the success path; when `connect()`
  raised, the `except` handlers recorded BLOCKED but leaked the socket,
  producing a ResourceWarning that polluted captured output. Fixed with
  try/finally around the socket use.

### 5.3 T-048 setuid assertion was a filesystem-dependent heuristic

- The payload asserted the setuid BIT must not be settable — true only
  on filesystems that clear it. On tmpfs the bit sticks (even with the
  new nosuid mount, which neutralizes exec-time elevation, not chmod).
- The REAL invariant is exec-elevation: `no_new_privs=1` + `CapEff=0`
  (verified live inside the sandbox: `NoNewPrivs: 1`,
  `CapEff/Prm/Bnd: 0000000000000000`) make the bit inert. The payload
  now verifies that invariant.
- Defense-in-depth also added: `/tmp` tmpfs is now mounted
  `MS_NOSUID|MS_NODEV` (consistent with /dev and /proc; not noexec —
  /tmp stays executable for pip), verified by test_rootfs.py.

### 5.4 Symlink/TOCTOU tests asserted 'must be BLOCKED' (minimal-rootfs premise)

- With the curated toolchain the sandbox rootfs CONTAINS its own
  `/etc/passwd` (root+nobody, 89 bytes), so symlink reads resolve
  INSIDE the sandbox — contained, not a host leak. The tests now
  compare the read content against the HOST file content
  (`_host_file_content`) and assert no HOST content leaked; BLOCKED is
  still accepted for the minimal rootfs.

### 5.5 Pytest-9 exposure of the FULL adversarial suite (container results)

With the output-capture fix in place, the complete container battery
(AGENT_SANDBOX_TOOLCHAIN=/opt/as-toolchain, pytest 9.1.1):

| Suite | Result |
|---|---|
| tests/adversarial (all) | **70 passed** (incl. 13 content-attack + 13 filesystem) |
| tests/unit (full) | **724 passed, 12 skipped** — 2 fails are the DOCUMENTED root-premise pair (test_host_caller_remains_unprivileged, test_host_process_invisibility: container runs as root; identical on pristine HEAD) |
| fuzz + seccomp + network + veth + credentials + proxy + toolchain | **204 passed, 3 skipped, 250 subtests** |
| N1 fail-closed matrix | **42 passed** |
| derivation (test_derivation.py) | **ALL PASS** |
| trace regression | **PASS (70)** |
| ruff / mypy / bandit (CI flags) / git diff --check | clean |
| Freebuff | log 285 entries / 0 errors; audit **263 PASS / 0 FAIL**; boot + read green; _test_errors 119 / _test_readcheck 19 / _test_cfgcheck 29 |
