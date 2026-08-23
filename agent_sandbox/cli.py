"""Thin CLI front-end (ADR-013, interface phase sub-phase A + Phase B).

The CLI carries NO security policy or enforcement logic. Every command
builds a validated ``RuntimeConfig``, creates a ``RuntimeSession``,
initializes (fail closed), and calls the SOLE execution entry point
``RuntimeSession.execute(ExecutionRequest)``. There is exactly one code
path that touches the boundary; the CLI cannot bypass it.

Command surface (Phase B - all commands use the existing security-
critical runtime; no alternate security path exists):

    agent-sandbox run      --workspace DIR [--mode MODE] [--policy PATH]
                           [--audit PATH] [--json] -- command arg ...
        One-shot create + execute + cleanup (the v0.1 legacy form; also
        spelled ``run``). The session is transient - nothing is
        persisted, cleanup is verified inside execute() (S-038).
    agent-sandbox create   --workspace DIR [--mode MODE] [--policy PATH]
                           [--json]
        Create + initialize a PERSISTED session. Validates policy before
        anything runs; refuses (fail closed) on invalid config or
        failed initialization. Never executes a workload. Exposes the
        session identity (S-023) + mode (S-020) for later exec/status/
        diff/logs/destroy. Persisted under the caller-owned state dir
        (AGENT_SANDBOX_STATE_DIR or ~/.agent-sandbox).
    agent-sandbox exec     <session-id> [--json] -- command arg ...
        Execute through the existing RuntimeSession path against a
        created session (re-validated from its stored manifest - a
        malformed/tampered manifest fails closed). Policy, resource,
        output, timeout and cleanup controls are exactly the runtime's.
    agent-sandbox status   <session-id> [--json]
        Session state, security mode, configured resource limits and
        policy version/capabilities. No host secrets are exposed.
    agent-sandbox diff     <session-id> [--json] [-- git args ...]
        Runs ``git diff`` (with optional git args after ``--``) INSIDE
        the sandbox on /workspace - repository contents are treated as
        untrusted and never read host-side. Gated on the ``git.read``
        policy capability through the shared decision path (S-015).
    agent-sandbox logs     <session-id> [--json]
        The session's ADR-012 audit events (host-side, observational,
        session-correlated). Missing/malformed audit data is reported as
        empty - never an execution blocker (S-024).
    agent-sandbox destroy  <session-id> [--json]
        Terminates any live sandbox of the session via the existing
        lifecycle mechanism, VERIFIES absence (S-038), and removes the
        session state. Incomplete cleanup is reported explicitly and the
        session is NOT marked destroyed (retryable).
    agent-sandbox git      <session-id> <operation> [--json]
                           [-- git args ...]
        Safe Git workflow (implementation.md Phase 9, Phase C): the
        operation set is CLOSED and READ-ONLY - status | diff | changed
        | untracked | deleted | base | current - mapped to the builtin
        git commands status/ls-files/merge-base/rev-parse, executed
        INSIDE the sandbox against /workspace with a sanitized argv that
        neutralizes hostile repository configuration (see
        agent_sandbox/git.py: core.fsmonitor, diff.external/textconv,
        aliases, credential helpers, hooks, ssh, pager/editor, submodule
        recursion - all overridden via highest-precedence -c flags and
        diff --no-ext-diff/--no-textconv). The repository is hostile
        input: it can never select executables, invoke helpers, reach
        host credentials, use the network, or escape /workspace - the
        sandbox boundary is the enforcement layer. Every operation is
        gated on the git.read policy capability through the shared
        decision path (S-015) BEFORE the sandbox runs. `base` requires a
        ref: agent-sandbox git <id> base -- <ref> (merge-base HEAD ref);
        `current` is rev-parse HEAD. Anything outside the set is a usage
        error (fail closed), never a passthrough.

Commands are ARGV VECTORS (never shell strings); shell metacharacters
are data, never interpreted. The execve bridge runs the command INSIDE
the sandbox (S-016/S-017).

Exit codes (deterministic):
- 0            success (workload exit 0 / create / status / destroy /
               logs)
- 1..255       the workload's own exit code (it ran and failed)
- 2            usage / configuration error
- 3            initialization refused (fail closed - workload never ran)
- 4            execution refused (policy denial / invalid request /
               setup failure / unsupported platform - workload never
               ran)
- 5            session error (unknown / destroyed / invalid session id,
               malformed session state - fail closed)
- 6            destroy incomplete (survivors detected - the session is
               NOT marked destroyed)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from agent_sandbox import git as git_mod
from agent_sandbox import registry
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
EXIT_SESSION_ERROR = 5
EXIT_DESTROY_INCOMPLETE = 6

COMMANDS = ("create", "exec", "run", "status", "diff", "logs",
            "destroy", "git")
_MODE_CHOICES = ("hardened", "restricted", "compatibility")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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


def _usage_error(message: str) -> int:
    print(f"agent-sandbox: error: {message}", file=sys.stderr)
    return EXIT_USAGE


def _config_error(e: Exception) -> int:
    print(f"agent-sandbox: configuration error: {e}", file=sys.stderr)
    return EXIT_USAGE


def _session_error(message: str, json_mode: bool,
                   session_id: str | None = None) -> int:
    """Deterministic session error (unknown/destroyed/invalid id,
    malformed state, registry I/O) - fail closed, never executed."""
    if json_mode:
        print(json.dumps({
            "session_id": session_id,
            "refused": True,
            "reason": message,
        }, sort_keys=True))
    else:
        print(f"agent-sandbox: session error: {message}", file=sys.stderr)
    return EXIT_SESSION_ERROR


def _emit(payload: dict, json_mode: bool, exit_code: int,
          text: str | None = None, text_err: str | None = None) -> int:
    if json_mode:
        print(json.dumps(payload, sort_keys=True))
    else:
        if text_err is not None:
            print(text_err, file=sys.stderr)
        elif text is not None:
            print(text)
    return exit_code


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


def _print_result_text(payload: dict) -> None:
    """Human-mode result output (output to stdout, summary line) - the
    documented v0.1 form shared by run/exec/diff."""
    if payload.get("output"):
        sys.stdout.write(payload["output"])
        if not payload["output"].endswith("\n"):
            sys.stdout.write("\n")
    flags = []
    if payload.get("truncated"):
        flags.append("output truncated")
    if payload.get("timed_out"):
        flags.append("timed out")
    if payload.get("cleanup_failure"):
        flags.append(f"cleanup failure: {payload['cleanup_failure']}")
    summary = (f"[agent-sandbox mode={payload['mode']} "
               f"session={payload['session_id']} "
               f"exit={payload['exit_code']}")
    if flags:
        summary += " (" + "; ".join(flags) + ")"
    print(summary + "]")


def _init_refused_payload(session_id: str, mode: str,
                          result) -> dict:
    return {
        "session_id": session_id,
        "mode": mode,
        "state": "refused",
        "refused": True,
        "reason": result.failure.describe() if result.failure
                  else "initialization failed",
    }


def _build_policy_config(mode: str, workspace: str,
                         policy_path: str | None) -> RuntimeConfig:
    """Load + strictly validate policy (if any) and build the immutable
    config. Any failure raises ConfigError/PolicyError (fail closed)."""
    policy = load_policy_file(policy_path) if policy_path else None
    data: dict = {"mode": mode, "workspace": workspace}
    if policy is not None:
        data["policy"] = policy
    return RuntimeConfig.from_dict(data)


def _reopen_session(base: str, session_id: str):
    """Load + strictly re-validate a persisted session. Returns
    (config, manifest) or raises/returns an error tuple the caller maps
    to a deterministic outcome. Never returns a session for a malformed
    manifest (fail closed, S-021)."""
    try:
        manifest = registry.load_manifest(base, session_id)
    except registry.RegistryError as e:
        return None, str(e)
    if manifest is None:
        return None, f"unknown session {session_id!r} (not found or " \
                     "already destroyed)"
    try:
        config = registry.config_from_manifest(manifest)
    except ConfigError as e:
        return None, (f"session state for {session_id} is invalid: {e} - "
                      "fail closed, never executed")
    return (config, manifest), None


def _run_session_command(base: str, session_id: str, command: list[str],
                         json_mode: bool, label: str,
                         extra_policy: tuple[str, ...] = ()) -> int:
    """Shared exec/diff path: strict session re-open -> READY gate ->
    optional command-specific policy gate -> the SOLE execution entry
    point. Every failure is deterministic and fail closed."""
    opened = _reopen_session(base, session_id)
    if opened[1] is not None:
        return _session_error(f"{label}: {opened[1]}", json_mode,
                              session_id)
    config, _manifest = opened[0]

    rec = AuditRecorder(registry.session_audit_path(base, session_id))
    session = RuntimeSession(config, audit=rec, session_id=session_id)

    result = session.initialize()
    if not result.ok:
        payload = _init_refused_payload(session_id, config.mode.value,
                                        result)
        return _emit(payload, json_mode, EXIT_INIT_REFUSED,
                     text_err=(f"agent-sandbox: initialization refused "
                               f"({config.mode.value}): "
                               f"{payload['reason']}"))

    # Command-specific policy gate (S-015 shared decision path). The
    # generic command gate (filesystem + process capabilities) is
    # enforced inside execute() for every command; commands with their
    # own capability (e.g. diff -> git.read) decide it here, BEFORE the
    # boundary, with the same policy engine.
    if extra_policy:
        decision = config.policy.require(*extra_policy)
        if not decision.allowed:
            reason = ("execution blocked by policy: "
                      f"{decision.describe()} - fail closed, workload "
                      "not executed")
            rec.record(session_id, "policy_decision",
                       capability=decision.capability, allowed=False,
                       reason=decision.reason)
            rec.record(session_id, "execution_refused", reason=reason,
                       state="ready")
            payload = {
                "session_id": session_id,
                "mode": config.mode.value,
                "state": "ready",
                "refused": True,
                "reason": reason,
            }
            return _emit(payload, json_mode, EXIT_EXEC_REFUSED,
                         text_err=f"agent-sandbox: execution refused: "
                                  f"{reason}")

    outcome = session.execute(ExecutionRequest(command=tuple(command)))
    registry.update_last_execution(base, session_id,
                                   session.last_sandbox_pid1,
                                   session.last_cgroup_path)
    if isinstance(outcome, ExecutionRefused):
        payload = _refusal_payload(session, outcome)
        return _emit(payload, json_mode, EXIT_EXEC_REFUSED,
                     text_err=f"agent-sandbox: execution refused: "
                              f"{outcome.reason}")

    payload = _result_payload(session, outcome)
    if json_mode:
        print(json.dumps(payload, sort_keys=True))
        return outcome.exit_code
    _print_result_text(payload)
    return outcome.exit_code


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _cmd_run(argv: list[str]) -> int:
    """One-shot create + execute + cleanup (legacy v0.1 form and the
    ``run`` subcommand). Transient session - nothing persisted; cleanup
    is verified inside execute() (S-038)."""
    opt_argv, command = _split_command(argv)
    parser = argparse.ArgumentParser(
        prog="agent-sandbox run",
        description="Run a command inside the agent-sandbox isolation "
                    "boundary (v0.1 - argv only, no shell).")
    parser.add_argument("--mode", choices=_MODE_CHOICES,
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
    try:
        args = parser.parse_args(opt_argv)
    except SystemExit:
        return EXIT_USAGE

    if not command:
        return _usage_error(
            "no command given - use the '--' separator: "
            "agent-sandbox run --workspace DIR -- command arg ...")

    try:
        config = _build_policy_config(args.mode, args.workspace,
                                      args.policy)
    except (ConfigError, PolicyError) as e:
        return _config_error(e)

    recorder = AuditRecorder(args.audit) if args.audit else None
    session = RuntimeSession(config, audit=recorder)

    result = session.initialize()
    if not result.ok:
        payload = _init_refused_payload(session.session_id,
                                        config.mode.value, result)
        return _emit(payload, args.json, EXIT_INIT_REFUSED,
                     text_err=(f"agent-sandbox: initialization refused "
                               f"({config.mode.value}): "
                               f"{payload['reason']}"))

    outcome = session.execute(ExecutionRequest(command=tuple(command)))

    if isinstance(outcome, ExecutionRefused):
        payload = _refusal_payload(session, outcome)
        return _emit(payload, args.json, EXIT_EXEC_REFUSED,
                     text_err=f"agent-sandbox: execution refused: "
                              f"{outcome.reason}")

    payload = _result_payload(session, outcome)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
        return outcome.exit_code
    _print_result_text(payload)
    return outcome.exit_code


def _cmd_create(argv: list[str], base: str) -> int:
    """Create + initialize a PERSISTED session. Never executes a
    workload. Policy is validated before anything starts (S-021); a
    refused session is never persisted and never reported as ready."""
    parser = argparse.ArgumentParser(
        prog="agent-sandbox create",
        description="Create + initialize an isolated session (validates "
                    "policy and the security boundary; does NOT execute "
                    "a workload).")
    parser.add_argument("--workspace", required=True,
                        help="host directory copied into the sandbox as "
                             "/workspace")
    parser.add_argument("--mode", choices=_MODE_CHOICES,
                        default="restricted",
                        help="security mode (default: restricted)")
    parser.add_argument("--policy", default=None, metavar="PATH",
                        help="capability policy JSON document (version 1, "
                             "ADR-010); validated host-side before the "
                             "session starts (S-021)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable result")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT_USAGE

    try:
        config = _build_policy_config(args.mode, args.workspace,
                                      args.policy)
    except (ConfigError, PolicyError) as e:
        return _config_error(e)

    session_id = uuid.uuid4().hex
    try:
        registry.ensure_session_dir(base, session_id)
    except registry.RegistryError as e:
        return _session_error(f"create: {e}", args.json, session_id)

    rec = AuditRecorder(registry.session_audit_path(base, session_id))
    session = RuntimeSession(config, audit=rec, session_id=session_id)
    result = session.initialize()

    if not result.ok:
        # A refused session is never persisted (nothing to exec) - remove
        # the empty state dir (best-effort hygiene).
        try:
            registry.remove_session(base, session_id)
        except Exception:
            pass
        payload = _init_refused_payload(session_id, config.mode.value,
                                        result)
        return _emit(payload, args.json, EXIT_INIT_REFUSED,
                     text_err=(f"agent-sandbox: initialization refused "
                               f"({config.mode.value}): "
                               f"{payload['reason']}"))

    created = datetime.now(UTC).isoformat()
    try:
        registry.save_session(base, session_id, config, created)
    except registry.RegistryError as e:
        return _session_error(f"create: {e}", args.json, session_id)

    payload = {
        "session_id": session_id,
        "mode": config.mode.value,
        "state": "ready",
        "refused": False,
        "reason": "",
    }
    return _emit(payload, args.json, 0,
                 text=f"created session {session_id} "
                      f"(mode {config.mode.value}) - ready")


def _cmd_exec(argv: list[str], base: str) -> int:
    """Execute through the existing RuntimeSession path against a
    created session (strict re-validation of its manifest)."""
    opt_argv, command = _split_command(argv)
    parser = argparse.ArgumentParser(
        prog="agent-sandbox exec",
        description="Execute a command inside an existing session.")
    parser.add_argument("session_id",
                        help="the session id returned by create")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable result")
    try:
        args = parser.parse_args(opt_argv)
    except SystemExit:
        return EXIT_USAGE
    if not command:
        return _usage_error(
            "exec: no command given - use the '--' separator: "
            "agent-sandbox exec <session-id> -- command arg ...")
    return _run_session_command(base, args.session_id, command,
                                args.json, "exec")


def _cmd_status(argv: list[str], base: str) -> int:
    """Session state, mode, configured resources + policy view. No host
    secrets are exposed."""
    parser = argparse.ArgumentParser(
        prog="agent-sandbox status",
        description="Show session state, mode and configured limits.")
    parser.add_argument("session_id",
                        help="the session id returned by create")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT_USAGE
    try:
        manifest = registry.load_manifest(base, args.session_id)
    except registry.RegistryError as e:
        return _session_error(f"status: {e}", args.json, args.session_id)
    if manifest is None:
        return _session_error(
            f"status: unknown session {args.session_id!r} (not found or "
            "already destroyed)", args.json, args.session_id)

    policy = manifest.get("policy") or {}
    payload = {
        "session_id": manifest["session_id"],
        "state": "ready",
        "mode": manifest["mode"],
        "created": manifest.get("created", ""),
        "workspace": manifest["workspace"],
        "network_mode": manifest["network_mode"],
        "network_allowlist": manifest.get("network_allowlist", []),
        "policy_version": policy.get("version"),
        "capabilities": policy.get("capabilities", {}),
        "resources": manifest.get("resources", {}),
        "last_execution": manifest.get("last_execution"),
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
        return 0
    print(f"session: {payload['session_id']}")
    print(f"state: {payload['state']}")
    print(f"mode: {payload['mode']}")
    if payload["created"]:
        print(f"created: {payload['created']}")
    print(f"workspace: {payload['workspace']}")
    print(f"network: {payload['network_mode']}")
    allow = payload["network_allowlist"]
    if allow:
        print("network allowlist:")
        for entry in allow:
            priv = " (allow_private)" if entry.get("allow_private") else ""
            print(f"  - {entry['host']}:{entry['port']}{priv}")
    print(f"policy: version {payload['policy_version']} "
          f"({len(payload['capabilities'])} capabilities)")
    res = payload["resources"]
    print("resources: "
          + " ".join(f"{k}={v}" for k, v in sorted(res.items())))
    last = payload["last_execution"]
    if last:
        print(f"last execution: sandbox_pid1={last.get('sandbox_pid1')} "
              f"cgroup={last.get('cgroup_path')}")
    else:
        print("last execution: none")
    return 0


def _cmd_diff(argv: list[str], base: str) -> int:
    """``git diff`` INSIDE the sandbox on /workspace (repository
    contents treated as untrusted - never read host-side), gated on the
    ``git.read`` policy capability through the shared decision path.
    Uses the Phase C sanitized git argv (hostile-config neutralization)."""
    opt_argv, git_args = _split_command(argv)
    parser = argparse.ArgumentParser(
        prog="agent-sandbox diff",
        description="git diff INSIDE the sandbox on /workspace "
                    "(gated on the git.read policy capability).")
    parser.add_argument("session_id",
                        help="the session id returned by create")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable result")
    try:
        args = parser.parse_args(opt_argv)
    except SystemExit:
        return EXIT_USAGE
    command = list(git_mod.sanitized_git_argv("diff", git_args))
    return _run_session_command(base, args.session_id, command,
                                args.json, "diff",
                                extra_policy=("git.read",))


def _cmd_git(argv: list[str], base: str) -> int:
    """Safe Git workflow (Phase C): a CLOSED read-only operation set
    (status/diff/changed/untracked/deleted/base/current) executed INSIDE
    the sandbox with the sanitized argv (hostile repository = untrusted
    input). Every operation is gated on ``git.read`` through the shared
    decision path (S-015) BEFORE the sandbox runs; anything outside the
    set is a usage error (fail closed), never a passthrough."""
    opt_argv, git_args = _split_command(argv)
    parser = argparse.ArgumentParser(
        prog="agent-sandbox git",
        description="Safe Git workflow INSIDE the sandbox (Phase C): "
                    "status/diff/changed/untracked/deleted/base/current "
                    "- a closed read-only set, gated on git.read.")
    parser.add_argument("session_id",
                        help="the session id returned by create")
    parser.add_argument("operation",
                        choices=git_mod.GIT_OPERATIONS,
                        help="the closed read-only git operation "
                             f"({', '.join(git_mod.GIT_OPERATIONS)})")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable result")
    try:
        args = parser.parse_args(opt_argv)
    except SystemExit:
        return EXIT_USAGE
    command = list(git_mod.sanitized_git_argv(args.operation, git_args))
    return _run_session_command(base, args.session_id, command,
                                args.json, "git",
                                extra_policy=("git.read",))


def _cmd_logs(argv: list[str], base: str) -> int:
    """The session's ADR-012 audit events (host-side, observational,
    session-correlated). Audit problems are reported as empty - never an
    execution blocker (S-024)."""
    parser = argparse.ArgumentParser(
        prog="agent-sandbox logs",
        description="Show the session's audit events (observational).")
    parser.add_argument("session_id",
                        help="the session id returned by create")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT_USAGE
    try:
        manifest = registry.load_manifest(base, args.session_id)
    except registry.RegistryError as e:
        return _session_error(f"logs: {e}", args.json, args.session_id)
    if manifest is None:
        return _session_error(
            f"logs: unknown session {args.session_id!r} (not found or "
            "already destroyed)", args.json, args.session_id)

    path = registry.session_audit_path(base, args.session_id)
    events: list[dict] = []
    try:
        # errors="replace" (F-3): undecodable bytes in a corrupted audit
        # file surface as replacement characters and hit the per-line
        # observational skip below - the logs command never crashes and
        # audit parsing never becomes an authorization decision (S-024).
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue  # observational - malformed audit lines
                if not isinstance(ev, dict):
                    # F-4: valid JSON but not an event object (null, [] ,
                    # string, number) - same observational skip; audit
                    # parsing never crashes the host (S-024).
                    continue
                if ev.get("session_id") == args.session_id:
                    events.append(ev)
    except OSError:
        pass  # missing audit file -> empty events (observational, S-024)

    if args.json:
        print(json.dumps({"session_id": args.session_id,
                          "events": events}, sort_keys=True))
    else:
        for ev in events:
            print(json.dumps(ev, sort_keys=True))
    return 0


def _cmd_destroy(argv: list[str], base: str) -> int:
    """Terminate any live sandbox via the existing lifecycle mechanism,
    VERIFY absence (S-038), then remove the session state. Incomplete
    cleanup is reported explicitly and the session is NOT marked
    destroyed (retryable) - never claim successful destruction."""
    parser = argparse.ArgumentParser(
        prog="agent-sandbox destroy",
        description="Terminate + verify + remove a session.")
    parser.add_argument("session_id",
                        help="the session id returned by create")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT_USAGE
    try:
        manifest = registry.load_manifest(base, args.session_id)
    except registry.RegistryError as e:
        return _session_error(f"destroy: {e}", args.json, args.session_id)
    if manifest is None:
        return _session_error(
            f"destroy: unknown session {args.session_id!r} (not found "
            "or already destroyed)", args.json, args.session_id)

    # Live-sandbox termination + mandatory absence verification using the
    # EXISTING lifecycle mechanism (S-014/S-038). The recorded identity
    # is the last run's sandbox PID 1 (the namespace init) + HARDENED
    # cgroup path; between commands the sandbox is already cleaned up, so
    # this is normally a fast no-op - its purpose is a caller interrupted
    # mid-run (orphaned sandbox).
    survivors: list[int] = []
    reason: str | None = None
    last = manifest.get("last_execution")
    if isinstance(last, dict):
        pid1 = last.get("sandbox_pid1")
        cg_path = last.get("cgroup_path")
        if isinstance(pid1, int) and pid1 >= 1:
            from types import SimpleNamespace

            from agent_sandbox.isolation import lifecycle as lifecycle_mod
            cg = None
            if isinstance(cg_path, str) and cg_path:
                cg = SimpleNamespace(path=cg_path)
                # The recorded session cgroup is removed when execute()
                # finishes - if it is gone the sandbox already terminated
                # (nothing to do; the recorded pid1 is a dead init).
                if not os.path.isdir(cg_path):
                    cg = None
                    pid1 = None
            if pid1 is not None:
                lifecycle_mod.terminate_tree(pid1, cg)
                survivors, reason = lifecycle_mod.verify_no_workload_remains(
                    pid1, cg)

    if survivors or reason:
        payload = {
            "session_id": args.session_id,
            "destroyed": False,
            "cleanup_incomplete": True,
            "survivors": survivors,
            "reason": reason or ("cleanup incomplete: workload "
                                 "process(es) survive - S-038, never "
                                 "reported as successful"),
        }
        return _emit(
            payload, args.json, EXIT_DESTROY_INCOMPLETE,
            text_err=(f"agent-sandbox: destroy: cleanup incomplete for "
                      f"session {args.session_id}: "
                      f"{payload['reason']} - session NOT destroyed "
                      "(retry destroy)"))

    try:
        registry.remove_session(base, args.session_id)
    except registry.RegistryError as e:
        return _session_error(f"destroy: {e}", args.json,
                              args.session_id)

    payload = {
        "session_id": args.session_id,
        "destroyed": True,
        "cleanup_incomplete": False,
    }
    return _emit(payload, args.json, 0,
                 text=f"destroyed session {args.session_id}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _print_usage() -> None:
    """Top-level help showing all available commands."""
    print("usage: agent-sandbox <command> [options]", file=sys.stderr)
    print("", file=sys.stderr)
    print("commands:", file=sys.stderr)
    print("  run       One-shot create + execute + cleanup", file=sys.stderr)
    print("  create    Create + initialize an isolated session", file=sys.stderr)
    print("  exec      Execute a command inside an existing session", file=sys.stderr)
    print("  status    Show session state, mode and configured limits", file=sys.stderr)
    print("  diff      git diff INSIDE the sandbox on /workspace", file=sys.stderr)
    print("  logs      Show session audit events (observational)", file=sys.stderr)
    print("  destroy   Terminate + clean up a session", file=sys.stderr)
    print("  git       Safe read-only git workflow inside the sandbox", file=sys.stderr)
    print("", file=sys.stderr)
    print("Run 'agent-sandbox <command> --help' for command-specific help.",
          file=sys.stderr)


def main(argv: Sequence[str] | None = None,
         state_dir: str | None = None) -> int:
    """CLI entry point. Returns the deterministic process exit code.
    ``state_dir`` overrides the session state directory (tests); the
    default is AGENT_SANDBOX_STATE_DIR or ~/.agent-sandbox."""
    raw = list(sys.argv[1:] if argv is None else argv)
    base = state_dir or registry.state_base_dir()
    if raw and raw[0] in COMMANDS:
        cmd = raw[0]
        rest = raw[1:]
        if cmd == "run":
            return _cmd_run(rest)
        if cmd == "create":
            return _cmd_create(rest, base)
        if cmd == "exec":
            return _cmd_exec(rest, base)
        if cmd == "status":
            return _cmd_status(rest, base)
        if cmd == "diff":
            return _cmd_diff(rest, base)
        if cmd == "logs":
            return _cmd_logs(rest, base)
        if cmd == "destroy":
            return _cmd_destroy(rest, base)
        if cmd == "git":
            return _cmd_git(rest, base)
    # Unknown command or no arguments: show top-level usage.
    # Legacy one-shot form (no subcommand, starts with options like
    # --workspace) falls through to _cmd_run for backward compatibility.
    if raw and not raw[0].startswith("-"):
        print(f"agent-sandbox: unknown command {raw[0]!r}", file=sys.stderr)
        _print_usage()
        return EXIT_USAGE
    if not raw:
        _print_usage()
        return EXIT_USAGE
    # Legacy one-shot form: no subcommand, options go to run.
    return _cmd_run(raw)


if __name__ == "__main__":
    sys.exit(main())
