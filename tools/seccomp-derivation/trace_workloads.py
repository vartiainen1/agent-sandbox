"""Reproducible syscall observation for the seccomp derivation exercise.

Runs every workload in workloads.py under `strace -f`, parses the trace,
and emits a JSON summary:

    {
      "workload": {...syscall-name -> count...},
      "args":     {workload: {syscall: [{flags: "...", count: N}, ...]}},
      "summary":  {"union": {...}, "per_tier": {"Tier 0": {...}, "Tier 1": {...}}}
    }

Usage:
    python3 trace_workloads.py [--workload NAME] [--out PATH]

The trace itself must run on Linux (container or native). strace must be
installed. This script parses strace's `-f` output; it does not run strace
itself (strace runs the workload with argv as given, so strace must be
invoked by the caller, e.g. `strace -f -qq -o trace.log <workload argv>`).

Design notes (deliberate, per the derivation rules):
- We record *names* plus argument summaries for the high-risk syscalls
  (clone/clone3, unshare, socket/socketpair) so the arg-level seccomp rules
  (e.g. deny CLONE_NEW* flags) can be derived from evidence, not guessing.
- A syscall appearing in the trace is a *candidate* for the allowlist, not
  an automatic inclusion: classification happens in
  docs/seccomp-derivation/syscall-classification.md (per-syscall rationale,
  can-it-be-removed, dangerous-class analysis).
"""

import argparse
import json
import re
import subprocess
import sys
from collections import Counter

from workloads import WORKLOADS, tier_of

# syscall line:  openat(AT_FDCWD, "/tmp/x", O_RDONLY...) = 3
# With -f, strace prefixes every FORKED-CHILD line with "[pid NNNN] "
# (e.g. "[pid 97779] execve(...)"); without handling that prefix the
# child's syscalls are silently dropped from the record. Fixed
# 2026-08-22 during the native Phase C verification: the container-era
# trace under-recorded git's surface (chdir etc.) for exactly this
# reason, which is why git's closed-set chdir requirement was absent
# from the derived allowlist.
SYSCALL_RE = re.compile(r"^\s*(?:\[pid\s+\d+\]\s*)?([a-z0-9_]+)\(")
# lines that are NOT syscall calls (checked AFTER any [pid NNNN] strip,
# so child "--- SIGCHLD" / "+++ exited" / "<unfinished>" lines are
# still dropped)
SKIP_PREFIXES = ("---", "+++", "strace:", " <", "(", "= ?", "unfinished", "resumed")
# syscalls we capture argument summaries for (arg-level seccomp rules)
ARGCAPTURE = {"clone", "clone3", "unshare", "socket", "socketpair", "setns"}


def parse_trace(text: str) -> tuple[Counter, dict]:
    """Return (syscall counts, {syscall: [{"args":..., "count": N}]})."""
    counts: Counter = Counter()
    argsum: dict[str, Counter] = {s: Counter() for s in ARGCAPTURE}
    for line in text.splitlines():
        if line.startswith(SKIP_PREFIXES):
            continue
        m = SYSCALL_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        counts[name] += 1
        if name in ARGCAPTURE:
            argsum[name][line.strip()] += 1
    argdetail = {}
    for name, c in argsum.items():
        argdetail[name] = [{"call": call, "count": n} for call, n in c.most_common()]
    return counts, argdetail


def run_workload(name: str, argv: list[str]) -> tuple[int, Counter, dict]:
    """Run argv under strace -f; return (exitcode, counts, argdetail)."""
    cmd = ["strace", "-f", "-qq", "-e", "trace=all"] + argv
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    counts, argdetail = parse_trace(proc.stderr)
    return proc.returncode, counts, argdetail


def _platform_is_windows() -> bool:
    """Patchable by tests; kept separate from argparse so a fail-closed
    check never triggers platform-dependent imports (see the 3.12 _winapi
    incident in freebuff-errors.txt)."""
    return sys.platform.startswith("win")


def main() -> int:
    # Fail closed FIRST: refuse non-Linux before any argparse construction
    # (argparse lazily imports shutil, which on 3.12 imports _winapi when
    # sys.platform looks like Windows).
    if _platform_is_windows():
        print("ERROR: tracing requires Linux (strace). Run inside the derivation "
              "container (see Dockerfile) or natively on Linux/CI.",
              file=sys.stderr)
        return 2

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workload", help="run only this workload name")
    ap.add_argument("--out", default="trace-results.json", help="output JSON path")
    args = ap.parse_args()

    for name in ("strace",):
        if subprocess.run(["which", name], capture_output=True).returncode != 0:
            print(f"ERROR: {name} not found - install it or run in the derivation image.",
                  file=sys.stderr)
            return 2

    selected = {k: v for k, v in WORKLOADS.items() if not args.workload or k == args.workload}
    if not selected:
        print(f"ERROR: unknown workload '{args.workload}'.", file=sys.stderr)
        return 2

    results: dict[str, dict] = {}
    union: Counter = Counter()
    tier_union: dict[str, Counter] = {"Tier 0": Counter(), "Tier 1": Counter()}
    for name, argv in selected.items():
        rc, counts, argdetail = run_workload(name, argv)
        results[name] = {
            "exit": rc,
            "argv": argv,
            "tier": tier_of(name),
            "syscalls": dict(counts),
            "args": argdetail,
        }
        union.update(counts)
        tier_union[tier_of(name)].update(counts)
        print(f"{name:20s} exit={rc} unique_syscalls={len(counts):3d} "
              f"total_calls={sum(counts.values()):6d}")

    out = {
        "generated": __file__,
        "workloads": results,
        "summary": {
            "union": dict(union),
            "per_tier": {t: dict(c) for t, c in tier_union.items()},
            "union_size": len(union),
        },
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(f"wrote {args.out}: {len(union)} unique syscalls across {len(selected)} workload(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
