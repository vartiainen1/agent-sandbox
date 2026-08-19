"""Seccomp allowlist regression gate.

The derived 45-syscall HARDENED allowlist is a security artifact
(allowlist.json). This tool FAILS any trace whose observed syscall set
contains a syscall NOT in the allowlist - i.e. an accidental or
undocumented syscall expansion is detected.

Usage:
    python3 check_trace_regression.py [trace-results.json]

Default input: the committed evidence record (trace-results.json).
In CI it is pointed at the freshly generated native trace. Also validates
the allowlist artifact itself (sorted, unique, expected count).

This enforces policy.md section 5 (NO UNDOCUMENTED SYSCALL EXPANSION).
It does not prevent deliberate, documented changes - those flow through
the change-control process (diff + reason + security impact + tests +
docs update) and update allowlist.json itself.

Exit codes: 0 = pass, 1 = expansion detected / artifact invalid, 2 = usage.
"""

import json
import pathlib
import sys

EXPECTED_COUNT = 45  # must match docs/seccomp-derivation/syscall-classification.md

HERE = pathlib.Path(__file__).resolve().parent
ARTIFACT = HERE / "allowlist.json"


def load_artifact(path: pathlib.Path = ARTIFACT) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate_artifact(artifact: dict) -> list[str]:
    """Return a list of problems with the artifact (empty = valid)."""
    problems = []
    allow = artifact.get("allowlist")
    if not isinstance(allow, list) or not allow:
        problems.append("allowlist missing or empty")
        return problems
    if len(allow) != EXPECTED_COUNT:
        problems.append(f"allowlist has {len(allow)} entries, expected {EXPECTED_COUNT}")
    if allow != sorted(allow):
        problems.append("allowlist is not sorted")
    if len(set(allow)) != len(allow):
        problems.append("allowlist contains duplicates")
    for name in ("tier0", "tier1"):
        tier = artifact.get(name)
        if not isinstance(tier, list):
            problems.append(f"{name} missing")
        elif set(tier) - set(allow):
            problems.append(f"{name} contains syscalls not in allowlist")
    if artifact.get("default_action") != "SECCOMP_RET_ERRNO | EPERM (deny)":
        problems.append("default_action must be EPERM deny")
    return problems


def check_trace(trace_path: pathlib.Path, artifact: dict) -> tuple[list[str], list[str]]:
    """Return (missing-from-artifact, artifact-integrity-problems)."""
    with open(trace_path, encoding="utf-8") as f:
        trace = json.load(f)
    allow = set(artifact["allowlist"])
    observed = set(trace["summary"]["union"])
    return sorted(observed - allow), validate_artifact(artifact)


def main() -> int:
    if len(sys.argv) > 2:
        print("usage: check_trace_regression.py [trace-results.json]", file=sys.stderr)
        return 2
    trace_path = pathlib.Path(sys.argv[1]) if len(sys.argv) == 2 else HERE / "trace-results.json"
    if not trace_path.exists():
        print(f"ERROR: trace file not found: {trace_path}", file=sys.stderr)
        return 2
    artifact = load_artifact()
    missing, problems = check_trace(trace_path, artifact)
    print(f"artifact: {ARTIFACT}")
    print(f"trace   : {trace_path}")
    print(f"allowlist size: {len(artifact['allowlist'])} (expected {EXPECTED_COUNT})")
    if problems:
        print("ARTIFACT INVALID:")
        for p in problems:
            print(f"  - {p}")
        return 1
    if missing:
        print("REGRESSION DETECTED - syscalls observed but NOT in the allowlist:")
        for s in missing:
            print(f"  - {s}")
        print("No undocumented syscall expansion is allowed (policy.md section 5).")
        print("If this is a deliberate workload addition, update allowlist.json through")
        print("the change-control process (diff + reason + security impact + tests + docs).")
        return 1
    print("PASS: every observed syscall is inside the allowlist. No undocumented expansion.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
