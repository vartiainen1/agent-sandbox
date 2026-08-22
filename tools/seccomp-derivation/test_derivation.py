"""Tests for the seccomp derivation tooling. stdlib-only (asserts).

Run: python3 test_derivation.py   (exit 0 = all pass)

Covers:
- trace parser (parse_trace) on sample strace output
- allowlist.json artifact integrity (46, sorted, unique, tiers, default action)
- trace regression gate: detects undocumented expansion; passes on the
  committed evidence record
- BPF builder structure (instruction layout, default-deny before allow)
- fail-closed guard: the tracer refuses to run on non-Linux (exit 2)
"""

import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

fails = []


def check(label, cond):
    print(("[PASS] " if cond else "[FAIL] ") + label)
    if not cond:
        fails.append(label)


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- trace parser ---
trace_workloads = load("trace_workloads")

sample = (
    "openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = 3\n"
    "fstat(3, {st_mode=S_IFREG}) = 0\n"
    "--- SIGCHLD {si_signo=SIGCHLD} ---\n"
    "+++ exited with 0 +++\n"
    "write(1, \"hi\\n\", 3) = 3\n"
    "<unfinished ...>\n"
    "getpid() = 42\n"
    # forked-child lines carry a [pid N] prefix under strace -f; these
    # must be counted (2026-08-22 fix - the container-era trace dropped
    # them, which hid git's chdir) and child status lines must not leak
    "[pid 97779] chdir(\"/tmp/gc\") = 0\n"
    "[pid 97779] --- SIGCHLD {si_signo=SIGCHLD} ---\n"
    "[pid 97779] +++ exited with 0 +++\n"
    "[pid 97779] openat(AT_FDCWD, \"/tmp/g/f\", O_WRONLY) = 4\n"
)
counts, argdetail = trace_workloads.parse_trace(sample)
check("parse_trace counts syscall calls", counts["openat"] == 2 and counts["write"] == 1)
check("parse_trace counts forked-child syscalls", counts["chdir"] == 1)
check("parse_trace skips SIG/exited/unfinished lines", "SIGCHLD" not in counts and "exited" not in counts)
check("parse_trace captures getpid", counts["getpid"] == 1)

# --- artifact integrity ---
artifact = json.loads((HERE / "allowlist.json").read_text(encoding="utf-8"))
allow = artifact["allowlist"]
check("allowlist has exactly 46 syscalls", len(allow) == 46)
check("allowlist is sorted", allow == sorted(allow))
check("allowlist has no duplicates", len(set(allow)) == len(allow))
check("tier0 + tier1 == allowlist", set(artifact["tier0"]) | set(artifact["tier1"]) == set(allow))
check("tier0 and tier1 disjoint", not (set(artifact["tier0"]) & set(artifact["tier1"])))
check("default action is EPERM deny", artifact["default_action"] == "SECCOMP_RET_ERRNO | EPERM (deny)")

# --- regression gate ---
check_reg = load("check_trace_regression")
problems = check_reg.validate_artifact(artifact)
check("artifact validation clean", not problems)

missing, problems = check_reg.check_trace(HERE / "trace-results.json", artifact)
check("committed trace: no syscall outside allowlist", not missing and not problems)

# expansion detection: inject a fake observed syscall
import copy
bad_trace = copy.deepcopy(json.loads((HERE / "trace-results.json").read_text(encoding="utf-8")))
bad_trace["summary"]["union"]["totally_new_syscall"] = 1
tmp = pathlib.Path(str(HERE / "trace-results.json") + ".expansion-probe")
tmp.write_text(json.dumps(bad_trace), encoding="utf-8")
try:
    missing, problems = check_reg.check_trace(tmp, artifact)
    check("expansion detected (new syscall flagged)", "totally_new_syscall" in missing)
finally:
    tmp.unlink(missing_ok=True)

# --- BPF builder structure ---
probe = load("probe_policy")
prog = probe.build_filter(allow)
N = len(allow)
# layout: ld-arch, jeq-arch, ret-kill, ld-nr, N x jeq, ret-errno, ret-allow
check("BPF instruction count = 4 + N + 2", prog.len == 4 + N + 2)
codes = [prog.filter[i].code for i in range(prog.len)]
check("BPF ends with default-deny then allow", codes[-2] == 0x06 and codes[-1] == 0x06)
check("BPF default action is EPERM", prog.filter[prog.len - 2].k == (0x00050000 | 1))
check("probe ALLOWED matches artifact", set(probe.ALLOWED) == set(allow))

# --- fail-closed guard (tracer refuses non-Linux) ---
# NOTE: patch the helper, never sys.platform globally - patching sys.platform
# makes CPython 3.12's argparse lazily import shutil, which then imports
# _winapi on Linux (logged in freebuff-errors.txt, 2026-08-19).
import unittest.mock
old_argv = sys.argv
sys.argv = ["trace_workloads.py"]
with unittest.mock.patch.object(trace_workloads, "_platform_is_windows", return_value=True):
    rc = trace_workloads.main()
sys.argv = old_argv
check("tracer fails closed on non-Linux (exit 2)", rc == 2)

print()
if fails:
    print(f"RESULT: {len(fails)} FAILED: {fails}")
    return_code = 1
else:
    print("RESULT: ALL PASS")
    return_code = 0
sys.exit(return_code)
