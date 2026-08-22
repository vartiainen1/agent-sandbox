# Seccomp Derivation Exercise

Phase 1 pre-task (approved 2026-08-19): determine, deliberately and
reproducibly, the smallest practical syscall allowlist required for the
agent-sandbox HARDENED runtime — and prove it works.

**Status: COMPLETE (container-validated).** Native Linux re-verification
is a CI job pending repo publish (user decision) — see
`verification.md` for the exact labeling.

## Result in one paragraph

The workload set (Tier 0: `echo hello`-class; Tier 1: coreutils + CPython
+ git) makes exactly **46 syscalls** under `strace -f` (45 derived + the
documented 2026-08-22 `+chdir` for the Phase C git closed set — see
policy.md §5 change record), and **zero** occurrences of the dangerous
classes (`clone`/`socket`/`unshare`/`setns`/
`mount`/`ptrace` were never called). The derived HARDENED policy allows
exactly those 46 (default-deny EPERM otherwise), is installed after all
initialization and immediately before the workload exec, and was verified
behaviorally: legit workloads pass, and `socket`/`ptrace`/`mount`/`chroot`/
`unshare`/`clone` all return EPERM. Documented limitations: no threads
(no `clone`), no networking syscalls, x86_64/glibc-specific.

## Documents

| Document | Contents |
|---|---|
| [methodology.md](methodology.md) | The 12-step reproducible process |
| [syscall-classification.md](syscall-classification.md) | Per-syscall rationale for all 45 allowed + the denied table |
| [policy.md](policy.md) | The derived HARDENED allowlist, filter placement, change control |
| [verification.md](verification.md) | Behavioral verification record, container-vs-native labeling |

## Tooling (reproducible)

| Tool | Purpose |
|---|---|
| `tools/seccomp-derivation/workloads.py` | The workload set |
| `tools/seccomp-derivation/trace_workloads.py` | strace-based observation |
| `tools/seccomp-derivation/probe_policy.py` | Behavioral verification (reference BPF implementation) |
| `tools/seccomp-derivation/allowlist.json` | **The canonical allowlist security artifact** (single source of truth) |
| `tools/seccomp-derivation/check_trace_regression.py` | Regression gate: fails any observed syscall outside the allowlist |
| `tools/seccomp-derivation/check_rootless_capabilities.py` | Rootless capability detection (VERIFIED/BLOCKED with reason) |
| `tools/seccomp-derivation/test_derivation.py` | Unit + regression suite (artifact integrity, gate, BPF layout, fail-closed guard) |
| `tools/seccomp-derivation/Dockerfile` | Toolchain image (ubuntu 24.04 + strace + python3 + git) |
| `tools/seccomp-derivation/trace-results.json` | Evidence record (container-validated) |

CI (`.github/workflows/ci.yml`) re-runs trace → regression gate → probe on
native ubuntu (authoritative); the gate makes undocumented syscall
expansion a CI failure.

## Reproduce

    docker build -t seccomp-derivation -f tools/seccomp-derivation/Dockerfile tools/seccomp-derivation
    docker run --rm -v "$PWD/tools/seccomp-derivation:/work" -w /work \
        seccomp-derivation python3 trace_workloads.py --out /work/trace-results.json
    docker run --rm -v "$PWD/tools/seccomp-derivation:/work" -w /work \
        seccomp-derivation python3 probe_policy.py

Native Linux: the same two scripts on an ubuntu host with strace
installed (authoritative; CI job pending).

## Next step

Phase 1 step 13 consumes this: `agent_sandbox/security/seccomp.py`
implements the BPF generator + install path, using the `ALLOWED` list
from `probe_policy.py` as the machine-readable source of truth.
