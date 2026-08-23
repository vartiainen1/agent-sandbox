"""Seccomp allowlist regression gate.

The derived 46-syscall HARDENED allowlist is a security artifact
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

EXPECTED_COUNT_X86_64 = 70
EXPECTED_COUNT_AARCH64 = 67

HERE = pathlib.Path(__file__).resolve().parent
ARTIFACT_X86_64 = HERE / "allowlist.json"
ARTIFACT_AARCH64 = HERE / "allowlist_aarch64.json"


def validate_artifact(artifact: dict) -> list[str]:
    """Return a list of problems with the artifact (empty = valid)."""
    problems = []
    allow = artifact.get("allowlist")
    if not isinstance(allow, list) or not allow:
        problems.append("allowlist missing or empty")
        return problems
    arch = artifact.get("arch", "x86_64")
    expected = EXPECTED_COUNT_AARCH64 if arch == "aarch64" else EXPECTED_COUNT_X86_64
    if len(allow) != expected:
        problems.append(f"allowlist has {len(allow)} entries, expected {expected} (arch={arch})")
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
    # aarch64-specific checks
    if arch == "aarch64":
        numbers = artifact.get("syscall_numbers")
        if not isinstance(numbers, dict):
            problems.append("syscall_numbers missing for aarch64")
        else:
            for name in allow:
                if name not in numbers:
                    problems.append(f"{name} missing from syscall_numbers")
                elif not isinstance(numbers[name], int) or numbers[name] < 0:
                    problems.append(f"{name} has invalid syscall number: {numbers[name]}")
    return problems


def check_trace(trace_path: pathlib.Path, artifact: dict) -> tuple[list[str], list[str]]:
    """Return (missing-from-artifact, artifact-integrity-problems)."""
    with open(trace_path, encoding="utf-8") as f:
        trace = json.load(f)
    allow = set(artifact["allowlist"])
    observed = set(trace["summary"]["union"])
    return sorted(observed - allow), validate_artifact(artifact)


def load_artifact(path: pathlib.Path | None = None) -> dict:
    p = path or ARTIFACT_X86_64
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    if len(sys.argv) > 3:
        print("usage: check_trace_regression.py [--aarch64] [trace-results.json]",
              file=sys.stderr)
        return 2
    aarch64 = "--aarch64" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--aarch64"]
    trace_path = pathlib.Path(args[0]) if args else None
    artifact_path = ARTIFACT_AARCH64 if aarch64 else ARTIFACT_X86_64
    if trace_path is None:
        trace_name = "trace-results-aarch64.json" if aarch64 else "trace-results.json"
        trace_path = HERE / trace_name
    if not trace_path.exists():
        print(f"ERROR: trace file not found: {trace_path}", file=sys.stderr)
        return 2
    artifact = load_artifact(artifact_path)
    missing, problems = check_trace(trace_path, artifact)
    expected = EXPECTED_COUNT_AARCH64 if aarch64 else EXPECTED_COUNT_X86_64
    print(f"artifact: {artifact_path}")
    print(f"trace   : {trace_path}")
    print(f"allowlist size: {len(artifact['allowlist'])} (expected {expected})")
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
