"""Thin CLI front-end (ADR-013, interface phase sub-phase A).

The CLI carries NO security policy or enforcement logic. It builds a
validated ``RuntimeConfig``, creates a ``RuntimeSession``, initializes
(fail closed), and calls the SOLE execution entry point
``RuntimeSession.execute(ExecutionRequest)``. There is exactly one code
path that touches the boundary; the CLI cannot bypass it.

Command syntax (v0.1 - NO shell strings, argv only):

    python -m agent_sandbox --workspace DIR [--mode MODE] [--json]
        [--audit PATH] -- command arg1 arg2 ...

- ``command`` is the in-sandbox argv: an absolute path to an executable
  that exists INSIDE the sandbox (the minimal rootfs has no system
  binaries, so commands must be workspace-provided, typically
  ``/workspace/...``). argv is passed verbatim - shell metacharacters
  are never interpreted.
- ``--mode``: hardened | restricted (default) | compatibility. The mode
  is always reported (S-020), including in ``--json``.
- ``--json``: machine-readable result (S-023 session identity + mode).
- ``--audit PATH``: append ADR-012 JSONL events (host-side,
  observational).

Exit codes (deterministic):
- 0            workload exit 0 (success)
- 1..255       the workload's own exit code (it ran and failed)
- 2            usage / configuration error
- 3            initialization refused (fail closed - workload never ran)
- 4            execution refused (invalid request / setup failure /
               unsupported platform - workload never ran)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from agent_sandbox.audit import AuditRecorder
from agent_sandbox.config import RuntimeConfig
from agent_sandbox.models import (
    ConfigError,
    ExecutionRefused,
    ExecutionRequest,
)
from agent_sandbox.policy import PolicyError, load_policy_file
from agent_sandbox.runtime.session import RuntimeSession

EXIT_USAGE = 2
EXIT_INIT_REFUSED = 3
EXIT_EXEC_REFUSED = 4


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Run a command inside the agent-sandbox isolation "
                    "boundary (v0.1 - argv only, no shell).")
    parser.add_argument("--mode", choices=("hardened", "restricted",
                                           "compatibility"),
                        default="restricted",
                        help="security mode (default: restricted)")
    parser.add_argument("--workspace", required=True,
                        help="host directory copied into the sandbox as "
                             "/workspace (the command must live inside "
                             "the sandbox, e.g. /workspace/tool)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable result (includes mode and "
                             "session identity)")
    parser.add_argument("--audit", default=None, metavar="PATH",
                        help="append ADR-012 JSONL audit events to PATH "
                             "(host-side, observational)")
    parser.add_argument("--policy", default=None, metavar="PATH",
                        help="capability policy JSON document (version 1, "
                             "ADR-010); validated host-side before the "
                             "session starts - a malformed policy refuses "
                             "to start (S-021)")
    # The command argv is split manually (see main): argparse's
    # REMAINDER keeps the '--' separator, which must never reach the
    # in-sandbox argv.
    return parser


def _split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split the raw argv into (option tokens, command argv).

    ``--`` separates options from the command argv VERBATIM (the
    documented v0.1 form). Without ``--`` there is no command (a usage
    error) - option VALUES would be ambiguous with the command start,
    so the separator is mandatory. Never a shell string; argv is data
    passed unchanged into the sandbox."""
    if "--" in argv:
        sep = argv.index("--")
        return argv[:sep], argv[sep + 1:]
    return argv, []


def _refusal_payload(session: RuntimeSession, refusal: ExecutionRefused,
                     ) -> dict:
    return {
        "session_id": session.session_id,
        "mode": session.config.mode.value,
        "state": refusal.state,
        "refused": True,
        "reason": refusal.reason,
    }


def _result_payload(session: RuntimeSession, result) -> dict:
    return {
        "session_id": session.session_id,
        "mode": session.config.mode.value,
        "state": "ready",
        "refused": False,
        "exit_code": result.exit_code,
        "output": result.output,
        "truncated": result.truncated,
        "timed_out": result.timed_out,
        "cleanup_failure": result.cleanup_failure,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the deterministic process exit code."""
    raw = list(sys.argv[1:] if argv is None else argv)
    opt_argv, command = _split_command(raw)
    parser = _build_parser()
    try:
        args = parser.parse_args(opt_argv)
    except SystemExit:
        # argparse calls sys.exit(2) on usage errors - normalize to the
        # deterministic CLI exit code (never a raw exception upward).
        return EXIT_USAGE

    if not command:
        print("agent-sandbox: error: no command given - use the '--' "
              "separator: agent-sandbox --workspace DIR -- command arg ...",
              file=sys.stderr)
        return EXIT_USAGE

    # Validated, immutable configuration (never mutated after this).
    # A supplied policy document is loaded + strictly validated BEFORE
    # the session starts (fail closed, S-021): an unreadable or malformed
    # policy is a usage error, never a session that silently ignores it.
    try:
        policy = load_policy_file(args.policy) if args.policy else None
        config = RuntimeConfig.from_dict({
            "mode": args.mode,
            "workspace": args.workspace,
            **({"policy": policy} if policy is not None else {}),
        })
    except (ConfigError, PolicyError) as e:
        print(f"agent-sandbox: configuration error: {e}", file=sys.stderr)
        return EXIT_USAGE

    recorder = AuditRecorder(args.audit) if args.audit else None
    session = RuntimeSession(config, audit=recorder)

    result = session.initialize()
    if not result.ok:
        payload = {
            "session_id": session.session_id,
            "mode": config.mode.value,
            "state": "refused",
            "refused": True,
            "reason": result.failure.describe() if result.failure
                      else "initialization failed",
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"agent-sandbox: initialization refused "
                  f"({config.mode.value}): {payload['reason']}",
                  file=sys.stderr)
        return EXIT_INIT_REFUSED

    request = ExecutionRequest(command=tuple(command))
    outcome = session.execute(request)

    if isinstance(outcome, ExecutionRefused):
        payload = _refusal_payload(session, outcome)
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"agent-sandbox: execution refused: {outcome.reason}",
                  file=sys.stderr)
        return EXIT_EXEC_REFUSED

    payload = _result_payload(session, outcome)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        if outcome.output:
            sys.stdout.write(outcome.output)
            if not outcome.output.endswith("\n"):
                sys.stdout.write("\n")
        flags = []
        if outcome.truncated:
            flags.append("output truncated")
        if outcome.timed_out:
            flags.append("timed out")
        if outcome.cleanup_failure:
            flags.append(f"cleanup failure: {outcome.cleanup_failure}")
        summary = (f"[agent-sandbox mode={config.mode.value} "
                   f"session={session.session_id} exit={outcome.exit_code}")
        if flags:
            summary += " (" + "; ".join(flags) + ")"
        print(summary + "]")
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
